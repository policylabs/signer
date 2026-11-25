// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sigstore

import (
	"errors"
	"fmt"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/policylabs/signer/internal/tuf"
)

// Instance captures the configuration required to talk to a sigstore instance.
type Instance struct {
	// Embed the tuf options struct
	tuf.TufOptions

	// ID is the stable identifier for the instance. We ship with "sigstore" and
	// "github"). It selects the embedded TUF bootstrap and trusted roots from
	// (roots/<id>.json and roots/<id>.trusted_root.json).
	ID string `json:"id"`

	// TrustedRootSnapshot records when the embedded trusted_root.json for
	// this instance was captured. TrustedRoot uses it to decide whether the
	// embedded copy is still fresh (see DefaultTrustedRootMaxAge) or should
	// be refreshed from TUF.
	TrustedRootSnapshot time.Time `json:"trusted-root-snapshot"`

	// SigningConfig holds the official sigstore signing configuration
	// (application/vnd.dev.sigstore.signingconfig.v0.2+json).
	SigningConfig *root.SigningConfig `json:"-"`

	Timestamp bool

	// AppendToRekor controls if the signing operation is recorded into the
	// transparency log.
	AppendToRekor bool `json:"rekor-append"`
	DisableSTS    bool

	// STSProviders names the STS providers to look for ambient
	// credentials in, in the order they are tried. No other provider is
	// consulted. When empty, all the registered providers are tried in
	// their default order (see sts.Ordered).
	STSProviders []string `json:"-"`

	// Hide the OIDC options in the CLI --help
	HideOIDCOptions bool
	// FlagPrefix adds a prefix to the CLI strings, these help grouping them
	FlagPrefix string

	// OIDCConfig holds the client-side OIDC configuration.
	OIDCConfig OIDCConfig `json:"oidc-config"`

	// VerifierConfig holds the verification policy options.
	VerifierConfig VerifierConfig `json:"verifier-config"`
}

// OIDCConfig captures the client-side OIDC configuration for a sigstore instance.
type OIDCConfig struct {
	// RedirectURL defines the URL that the browser will redirect to.
	// If the port is set to 0, it will be randomized to a high number
	// port before starting the OIDC flow.
	RedirectURL string `json:"redirect-url"`

	// ClientID is the OIDC client ID to stamp on the tokens.
	ClientID string `json:"client-id"`

	// ClientSecret is the OIDC client secret.
	ClientSecret string `json:"client-secret"`
}

// Validate checks that the required OIDC client fields are set.
func (oc *OIDCConfig) Validate() error {
	errs := []error{}
	if oc.ClientID == "" {
		errs = append(errs, errors.New("OIDC client ID is missing"))
	}
	if oc.RedirectURL == "" {
		errs = append(errs, errors.New("OIDC redirect URL missing"))
	}
	return errors.Join(errs...)
}

// VerifierConfig captures the verification policy for a sigstore instance.
type VerifierConfig struct {
	// Look for a signed timestamp in the cert and verify with the CTLog Auth
	RequireCTlog bool `json:"require-ct-log"`
	// Verify the cert validity in the transparency log
	RequireTlog bool `json:"require-tlog"`
	// Verify the certificate validity time with a signed timestamp
	RequireSignedTimestamps bool `json:"require-signed-timestamps"`
	// Require an observer timestamp for verification
	RequireObserverTimestamp bool `json:"require-observer-timestamp"`
}

// Validate checks that at least one timestamp verification method is set.
func (vc *VerifierConfig) Validate() error {
	if !vc.RequireCTlog && !vc.RequireTlog && !vc.RequireObserverTimestamp && !vc.RequireSignedTimestamps {
		return errors.New("at least one method to check timestamps must be set")
	}
	return nil
}

// OidcIssuerURL returns the OIDC issuer URL from the signing config.
func (i *Instance) OidcIssuerURL() string {
	if i.SigningConfig == nil {
		return ""
	}
	if urls := i.SigningConfig.OIDCProviderURLs(); len(urls) > 0 {
		return urls[0].URL
	}
	return ""
}

// FulcioURL returns the Fulcio CA URL from the signing config.
func (i *Instance) FulcioURL() string {
	if i.SigningConfig == nil {
		return ""
	}
	if urls := i.SigningConfig.FulcioCertificateAuthorityURLs(); len(urls) > 0 {
		return urls[0].URL
	}
	return ""
}

// RekorURL returns the Rekor transparency log URL from the signing config.
func (i *Instance) RekorURL() string {
	if i.SigningConfig == nil {
		return ""
	}
	if urls := i.SigningConfig.RekorLogURLs(); len(urls) > 0 {
		return urls[0].URL
	}
	return ""
}

// ValidateOIDC checks that the OIDC properties are correct
func (i *Instance) ValidateOIDC() error {
	errs := []error{
		i.OIDCConfig.Validate(),
	}

	if i.OidcIssuerURL() == "" {
		errs = append(errs, errors.New("OIDC issuer URL missing"))
	}

	return errors.Join(errs...)
}

// ValidateTimestamps checks that at least one timestamp verification method is set.
func (i *Instance) ValidateTimestamps() error {
	return i.VerifierConfig.Validate()
}

func (i *Instance) ValidateVerifier() error {
	errs := []error{
		i.ValidateTimestamps(),
	}

	if i.SigningConfig == nil {
		errs = append(errs, errors.New("signing config not set"))
	} else if i.FulcioURL() == "" {
		errs = append(errs, errors.New("fulcio url not set in signing config"))
	}

	return errors.Join(errs...)
}

func (i *Instance) ValidateSigner() error {
	errs := []error{
		i.ValidateOIDC(),
	}

	if i.SigningConfig == nil {
		errs = append(errs, errors.New("signing config not set"))
		return errors.Join(errs...)
	}

	if i.AppendToRekor && i.RekorURL() == "" {
		errs = append(errs, errors.New("rekor url not set in signing config (and append to rekor is set)"))
	}

	if i.FulcioURL() == "" {
		errs = append(errs, errors.New("fulcio url not set in signing config"))
	}

	return errors.Join(errs...)
}

// ValidateSigningConfig checks that the instance has a valid signing config.
func (i *Instance) ValidateSigningConfig() error {
	if i.SigningConfig == nil {
		return fmt.Errorf("signing config not set")
	}
	return nil
}
