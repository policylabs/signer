// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

package bundle

import (
	"errors"
	"fmt"
	"time"

	intoto "github.com/in-toto/attestation/go/v1"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/policylabs/signer/internal/httpretry"
	"github.com/policylabs/signer/options"
	"github.com/policylabs/signer/sigstore"
)

// BundleSigner abstracts the signer implementation to make it easy to mock
//
//counterfeiter:generate . Signer
type Signer interface {
	VerifyAttestationContent(*options.Signer, []byte) error
	WrapData(payloadType string, data []byte) *sign.DSSEData
	BuildMessage(data []byte) *sign.PlainData
	BuildBundleOptions(*options.Signer, CredentialProvider) (*sign.BundleOptions, error)
	SignBundle(content sign.Content, keypair sign.Keypair, opts *sign.BundleOptions) (*protobundle.Bundle, error)
}

func NewSigner() Signer {
	return &DefaultSigner{}
}

// DefaultSigner implements the BundleSigner interface for the signer
type DefaultSigner struct{}

func (bs *DefaultSigner) WrapData(payloadType string, data []byte) *sign.DSSEData {
	content := &sign.DSSEData{
		Data:        data,
		PayloadType: payloadType,
	}
	return content
}

// BuildMessage is the alternative to WrapData.
func (bs *DefaultSigner) BuildMessage(data []byte) *sign.PlainData {
	return &sign.PlainData{
		Data: data,
	}
}

// VerifyContent checka that the attestation is in good shape to sign
func (bs *DefaultSigner) VerifyAttestationContent(_ *options.Signer, data []byte) error {
	if data == nil {
		return errors.New("payload is empty")
	}
	st := &intoto.Statement{}
	if err := protojson.Unmarshal(data, st); err != nil {
		return errors.New("unable to unmarshal intoto statement from payload")
	}
	return nil
}

// BuildBundleOptions assembles the sign.BundleOptions used by SignBundle. The
// certificate provider is supplied by the given CredentialProvider. TSA and
// Rekor endpoints, when requested, come from the sigstore signing config —
// SigningConfig is only required when those features are turned on, so SPIFFE
// (which carries no sigstore config and never wants TSA/Rekor today) flows
// through with no sigstore data leaking into the bundle.
func (bs *DefaultSigner) BuildBundleOptions(opts *options.Signer, cp CredentialProvider) (*sign.BundleOptions, error) {
	if cp == nil {
		return nil, errors.New("credential provider not set")
	}

	bundleOptions := sign.BundleOptions{}
	certProvider, cpOpts := cp.CertificateProvider()
	bundleOptions.CertificateProvider = certProvider
	bundleOptions.CertificateProviderOptions = cpOpts

	if opts.Timestamp {
		signingConfig := opts.SigningConfig
		if signingConfig == nil {
			// Backends that don't carry a sigstore SigningConfig (notably
			// SPIFFE) still need TSA URLs to satisfy the Timestamp toggle.
			// Fall back to a TSA-only config synthesized from the embedded
			// sigstore-roots. Fulcio / OIDC / Rekor URL slices are
			// intentionally left empty so this fallback only contributes
			// timestamping, never other sigstore endpoints.
			sc, err := tsaOnlySigningConfig(opts.SigstoreRootsData)
			if err != nil {
				return nil, fmt.Errorf("synthesizing TSA-only signing config: %w", err)
			}
			signingConfig = sc
		}
		tsaURLs, err := root.SelectServices(
			signingConfig.TimestampAuthorityURLs(),
			signingConfig.TimestampAuthorityURLsConfig(), []uint32{1}, time.Now(),
		)
		if err != nil {
			return nil, fmt.Errorf("fetching time stamp authority URLs: %w", err)
		}

		if len(tsaURLs) == 0 {
			return nil, fmt.Errorf("no timestamp authority found in signing config")
		}

		for _, tsaURL := range tsaURLs {
			bundleOptions.TimestampAuthorities = append(
				bundleOptions.TimestampAuthorities, newTimestampAuthority(tsaURL.URL),
			)
		}
	}

	if opts.AppendToRekor {
		if opts.SigningConfig == nil {
			return nil, fmt.Errorf("signing config not set; required when AppendToRekor is enabled")
		}
		for _, rekorURL := range opts.SigningConfig.RekorLogURLs() {
			// The Rekor client retries failed connections as well as
			// the answers that say to try again.
			rekorOpts := &sign.RekorOptions{
				BaseURL: rekorURL.URL,
				Timeout: 90 * time.Second,
				Retries: httpretry.Retries,
			}
			bundleOptions.TransparencyLogs = append(bundleOptions.TransparencyLogs, sign.NewRekor(rekorOpts))
		}
	}

	return &bundleOptions, nil
}

// newTimestampAuthority returns a client of the timestamp authority at
// url that rides out its passing failures: answers that say to try again
// (5xx and 429) are retried by the client itself, connections that fail
// by the transport.
func newTimestampAuthority(url string) *sign.TimestampAuthority {
	return sign.NewTimestampAuthority(&sign.TimestampAuthorityOptions{
		URL:       url,
		Timeout:   30 * time.Second,
		Retries:   httpretry.Retries,
		Transport: httpretry.NewTransport(),
	})
}

// tsaOnlySigningConfig builds a sigstore SigningConfig containing
// only the TSA URLs from the first parsed instance in rootsData.
// Fulcio, OIDC, and Rekor URL slices are intentionally left empty so
// the TSA-only fallback can't accidentally pull in non-TSA sigstore
// endpoints (e.g. for a SPIFFE-backed signature). Used by
// BuildBundleOptions when Timestamp is requested but the caller
// supplied no sigstore SigningConfig of its own.
func tsaOnlySigningConfig(rootsData []byte) (*root.SigningConfig, error) {
	parsed, err := sigstore.ParseRoots(rootsData)
	if err != nil {
		return nil, fmt.Errorf("parsing sigstore roots: %w", err)
	}
	if len(parsed.Roots) == 0 || parsed.Roots[0].SigningConfig == nil {
		return nil, errors.New("no signing config in sigstore roots")
	}
	src := parsed.Roots[0].SigningConfig
	tsaURLs := src.TimestampAuthorityURLs()
	if len(tsaURLs) == 0 {
		return nil, errors.New("no TSA URLs in sigstore roots")
	}
	return root.NewSigningConfig(
		root.SigningConfigMediaType02,
		nil, // no Fulcio
		nil, // no OIDC
		nil, // no Rekor
		root.ServiceConfiguration{},
		tsaURLs,
		src.TimestampAuthorityURLsConfig(),
	)
}

// SignBundle signs the DSSE envelop and returns the new bundle
func (bs *DefaultSigner) SignBundle(content sign.Content, keypair sign.Keypair, opts *sign.BundleOptions) (*protobundle.Bundle, error) {
	bndl, err := sign.Bundle(content, keypair, *opts)
	if err != nil {
		return nil, fmt.Errorf("signing DSSE wrapper: %w", err)
	}

	return bndl, nil
}
