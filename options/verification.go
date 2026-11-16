// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"regexp"
	"slices"

	"github.com/policylabs/signer/key"
)

type VerificationOptFunc func(*Verification) error

// Verification options are generic options that all the Verify* functions take
type Verification struct {
	SigstoreVerification
	KeyVerification
	SpiffeVerification

	// Rekor gates the online verification of keyless DSSE envelopes
	// against a transparency log.
	Rekor RekorVerification
}

// DefaultRekorURL is the transparency log queried when Rekor
// verification is enabled and no URL is configured.
const DefaultRekorURL = "https://rekor.sigstore.dev"

// RekorVerification configures the verification of keyless DSSE
// envelopes: legacy envelopes signed with a short-lived Sigstore
// certificate whose proof of timeliness lives in the Rekor transparency
// log rather than in the document (the pre-bundle cosign flow). Because
// checking one means querying the log over the network, the feature is
// off by default: without it such envelopes conclude UNVERIFIABLE.
type RekorVerification struct {
	// Enabled turns the transparency log lookup on.
	Enabled bool

	// URL is the Rekor instance to query. Empty means DefaultRekorURL.
	URL string

	// HTTPClient, when set, carries the requests to the log in place of
	// the default client, which dials its own connections and retries
	// failed requests. Timeouts and retries are then the caller's to
	// configure. Inject one where connections cannot be dialed, such as
	// js/wasm in a browser, where a client using http.DefaultTransport
	// goes through the Fetch API.
	HTTPClient *http.Client
}

// GetURL returns the configured Rekor URL or the default.
func (r *RekorVerification) GetURL() string {
	if r.URL == "" {
		return DefaultRekorURL
	}
	return r.URL
}

// WithRekorVerification enables or disables verifying keyless DSSE
// envelopes against the Rekor transparency log. See RekorVerification.
func WithRekorVerification(enabled bool) VerificationOptFunc {
	return func(v *Verification) error {
		v.Rekor.Enabled = enabled
		return nil
	}
}

// WithRekorURL sets the transparency log instance queried when Rekor
// verification is enabled.
func WithRekorURL(url string) VerificationOptFunc {
	return func(v *Verification) error {
		v.Rekor.URL = url
		return nil
	}
}

// WithRekorHTTPClient sets the HTTP client used to query the
// transparency log when Rekor verification is enabled. A nil client
// restores the default one. See RekorVerification.HTTPClient.
func WithRekorHTTPClient(client *http.Client) VerificationOptFunc {
	return func(v *Verification) error {
		v.Rekor.HTTPClient = client
		return nil
	}
}

var DefaultVerification = Verification{}

// SpiffeVerification carries the trust material and identity matchers used
// when verifying a bundle signed against a SPIFFE/SPIRE trust domain.
type SpiffeVerification struct {
	// TrustRootsPEM is the inline PEM-encoded set of trust anchors used to
	// validate the SVID chain. At least one of TrustRootsPEM or
	// TrustRootsPath must be set for SPIFFE verification to be enabled.
	TrustRootsPEM []byte

	// TrustRootsPath is a filesystem path to a PEM-encoded trust anchor file.
	TrustRootsPath string

	// ExpectedTrustDomain, when non-empty, asserts the leaf SVID's trust
	// domain matches this string (e.g. "prod.example.org").
	ExpectedTrustDomain string

	// ExpectedPath, when non-empty, requires an exact match on the SVID's
	// SPIFFE path component (e.g. "/workload/api").
	ExpectedPath string

	// ExpectedPathRegex, when non-empty, requires a regex match on the SVID's
	// SPIFFE path component. Mutually exclusive with ExpectedPath.
	ExpectedPathRegex string

	// SkipSVIDValidity disables enforcement of the leaf SVID's
	// NotBefore/NotAfter dates during chain validation. Default
	// (false) is the safe behavior: the verifier checks the leaf is
	// time-valid against either an RFC 3161 timestamp from the bundle
	// or time.Now(). Set true to validate the chain using the leaf's
	// NotBefore as the reference time, so the chain is checked purely
	// on its cryptographic shape — useful for archival verification
	// of bundles whose SVIDs have rotated.
	SkipSVIDValidity bool
}

// WithExpectedIdentity serts the ExpectedIssuer and ExptectedSan options
// and unsets the regex alternatives
func WithExpectedIdentity(issuer, san string) VerificationOptFunc {
	return func(v *Verification) error {
		if issuer != "" {
			v.ExpectedIssuerRegex = ""
			v.ExpectedIssuer = issuer
		}

		if san != "" {
			v.ExpectedSanRegex = ""
			v.ExpectedSan = san
		}
		return nil
	}
}

// WithExpectedIdentityRegex sets the ExpectedIssuerRegex and ExptectedSanRegex
// options and unsets the non-regex alternatives.
func WithExpectedIdentityRegex(issuer, san string) VerificationOptFunc {
	return func(v *Verification) error {
		if issuer != "" {
			if _, err := regexp.Compile(issuer); err != nil {
				return fmt.Errorf("compiling issuer regex: %w", err)
			}
			v.ExpectedIssuerRegex = issuer
			v.ExpectedIssuer = ""
		}

		if san != "" {
			if _, err := regexp.Compile(san); err != nil {
				return fmt.Errorf("compiling SAN regex: %w", err)
			}
			v.ExpectedSanRegex = san
			v.ExpectedSan = ""
		}
		return nil
	}
}

// WithSkipIdentityCheck instructs the verifier to not check the signature
// identities, only the signed payload will be checked.
func WithSkipIdentityCheck(yesno bool) VerificationOptFunc {
	return func(v *Verification) error {
		v.SkipIdentityCheck = yesno
		return nil
	}
}

// WithSpiffeTrustRootsPEM sets the inline PEM-encoded SPIFFE trust anchors.
func WithSpiffeTrustRootsPEM(pem []byte) VerificationOptFunc {
	return func(v *Verification) error {
		v.TrustRootsPEM = pem
		return nil
	}
}

// WithSpiffeTrustRootsFile sets the filesystem path to a PEM-encoded SPIFFE
// trust anchor file.
func WithSpiffeTrustRootsFile(path string) VerificationOptFunc {
	return func(v *Verification) error {
		v.TrustRootsPath = path
		return nil
	}
}

// WithExpectedSpiffeID sets the expected trust domain and path for the SVID
// leaf. Either can be empty to skip that check; both together form an exact
// match (use WithExpectedSpiffeIDRegex for pattern matching on the path).
func WithExpectedSpiffeID(trustDomain, path string) VerificationOptFunc {
	return func(v *Verification) error {
		v.ExpectedTrustDomain = trustDomain
		v.ExpectedPath = path
		v.ExpectedPathRegex = ""
		return nil
	}
}

// WithExpectedSpiffeIDRegex sets the expected trust domain and a regex that
// must match the SVID path. Unsets any exact ExpectedPath.
func WithExpectedSpiffeIDRegex(trustDomain, pathRegex string) VerificationOptFunc {
	return func(v *Verification) error {
		if pathRegex != "" {
			if _, err := regexp.Compile(pathRegex); err != nil {
				return fmt.Errorf("compiling spiffe path regex: %w", err)
			}
		}
		v.ExpectedTrustDomain = trustDomain
		v.ExpectedPathRegex = pathRegex
		v.ExpectedPath = ""
		return nil
	}
}

// WithPublicKeys sets the public keys used to verify DSSE signatures for
// this call, replacing any keys configured on the verifier. The slice is
// copied so later changes by the caller do not affect the verification.
// Passing no keys clears the set, in which case DSSE signatures cannot be
// checked and are reported as unverifiable.
func WithPublicKeys(keys ...key.PublicKeyProvider) VerificationOptFunc {
	return func(v *Verification) error {
		v.PubKeys = slices.Clone(keys)
		return nil
	}
}

// WithArtifactData hashes the artifact data to verify along the signature.
// This is required for message verifications
func WithArtifactData(data []byte) VerificationOptFunc {
	return func(opts *Verification) error {
		s256 := sha256.New()
		s256.Write(data)
		hashedBytes := s256.Sum(nil)

		opts.ArtifactDigest = fmt.Sprintf("%x", hashedBytes)
		opts.ArtifactDigestAlgo = "sha256"
		return nil
	}
}
