// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"errors"
	"fmt"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"

	"github.com/policylabs/signer/spiffe"
)

// SignerSet is the top-level sign-side OptionsSet that bundles every
// backend-specific child set behind a single --signing-backend discriminator
// flag. AddFlags registers --signing-backend plus every child's flags so the
// CLI's --help shows the full surface; Validate and BuildSigner act
// only on the child selected by --signing-backend, so non-selected children
// are inert.
//
// Typical use:
//
//	set := DefaultSignerSet()
//	set.AddFlags(cmd)
//	// ... after cobra parses ...
//	if err := set.Validate(); err != nil { ... }
//	opts, err := set.BuildSigner()
//	creds, err := set.BuildCredentialProvider()
//	runtime := signer.NewSigner()
//	runtime.Options = *opts
//	if creds != nil {
//	    runtime.Credentials = creds
//	}
//
// SPIFFE is the only backend that needs a separate credential
// provider; for sigstore and key BuildCredentialProvider returns
// (nil, nil) and the runtime signer's auto-build / unused-credentials
// behavior takes over.
type SignerSet struct {
	// Backend selects which child set Validate/BuildSigner consult.
	// Bound to --signing-backend. Empty resolves to BackendSigstore, matching
	// the runtime signer's default.
	Backend string

	// Timestamp controls whether the resulting bundle carries an RFC
	// 3161 timestamp. Bound to --signing-timestamp; the flag is the
	// single user-facing knob across backends so each per-backend
	// child has its own --<prefix>-timestamp suppressed (via
	// ManagedTimestamp on the child) when bundled here. BuildSigner
	// propagates this value into the dispatched child's
	// *options.Signer.Timestamp, overriding any per-backend default.
	// Applies to sigstore and SPIFFE (whose BuildSigner attaches a
	// TSA-only SigningConfig); the key backend ignores it because
	// DSSE envelopes carry no timestamps.
	Timestamp bool

	Keys     *KeysSign
	Sigstore *SigstoreSignSet
	Spiffe   *SpiffeSignSet

	config *command.OptionsSetConfig
}

var _ command.OptionsSet = (*SignerSet)(nil)

const (
	flagSigningBackend   = "signing-backend"
	flagSigningTimestamp = "signing-timestamp"
)

// DefaultSignerSet builds a SignerSet with every child constructed
// under its conventional flag prefix ("sigstore", "spiffe"; KeysSign
// uses its own --signing-key namespace). Backend is left empty so
// resolveBackend can auto-detect from the populated child flags;
// users who want a specific backend can override --signing-backend.
func DefaultSignerSet() *SignerSet {
	sigstoreSet := DefaultSigstoreSignSet("sigstore")
	spiffeSet := DefaultSpiffeSignSet("spiffe")
	// Suppress the per-backend --sigstore-timestamp / --spiffe-timestamp
	// flags when bundled; the single --signing-timestamp at this level
	// is the user-facing knob.
	sigstoreSet.Sign.ManagedTimestamp = true
	spiffeSet.Sign.ManagedTimestamp = true
	return &SignerSet{
		Timestamp: true,
		Keys:      DefaultKeysSign(),
		Sigstore:  sigstoreSet,
		Spiffe:    spiffeSet,
	}
}

// Config returns the flag config for the --signing-backend flag
// itself. Children expose their own Config() and remain the
// authoritative source for their flag namespaces.
func (s *SignerSet) Config() *command.OptionsSetConfig {
	if s.config == nil {
		s.config = &command.OptionsSetConfig{
			Flags: map[string]command.FlagConfig{
				flagSigningBackend: {
					Long: flagSigningBackend,
					Help: fmt.Sprintf("signing backend (%s | %s | %s) default %s",
						BackendKey, BackendSigstore, BackendSpiffe, BackendSigstore),
				},
				flagSigningTimestamp: {
					Long: flagSigningTimestamp,
					Help: "Add an RFC 3161 TSA-signed timestamp (sigstore/SPIFFE)",
				},
			},
		}
	}
	return s.config
}

// AddFlags registers --signing-backend and every non-nil child's
// flags. Order is fixed (signing-backend → keys → sigstore → spiffe)
// so --help output is stable across runs.
func (s *SignerSet) AddFlags(cmd *cobra.Command) {
	cfg := s.Config()
	pf := cmd.PersistentFlags()
	pf.StringVar(
		&s.Backend,
		cfg.LongFlag(flagSigningBackend),
		s.Backend,
		cfg.HelpText(flagSigningBackend),
	)
	pf.BoolVar(
		&s.Timestamp,
		cfg.LongFlag(flagSigningTimestamp),
		s.Timestamp,
		cfg.HelpText(flagSigningTimestamp),
	)
	if s.Keys != nil {
		s.Keys.AddFlags(cmd)
	}
	if s.Sigstore != nil {
		s.Sigstore.AddFlags(cmd)
	}
	if s.Spiffe != nil {
		s.Spiffe.AddFlags(cmd)
	}
}

// resolveBackend returns the Backend value to dispatch on. Explicit
// --signing-backend wins; otherwise auto-detect from the populated
// child flags. Env-var fallbacks (e.g. SPIFFE_ENDPOINT_SOCKET) do
// NOT trigger auto-detect — only explicit flag values do — so users
// don't get surprise SPIFFE-signed bundles on hosts where SPIRE
// happens to be installed. Set --signing-backend explicitly to opt
// into env-driven configuration.
func (s *SignerSet) resolveBackend() (Backend, error) {
	if s.Backend != "" {
		switch Backend(s.Backend) {
		case BackendKey, BackendSigstore, BackendSpiffe:
			return Backend(s.Backend), nil
		default:
			return "", fmt.Errorf("SignerSet: unknown --signing-backend %q (valid: %s, %s, %s)",
				s.Backend, BackendKey, BackendSigstore, BackendSpiffe)
		}
	}

	keyConfigured := s.Keys != nil && s.Keys.configured()
	spiffeConfigured := s.Spiffe != nil && s.Spiffe.Sign != nil && s.Spiffe.Sign.SocketPath != ""

	switch {
	case keyConfigured && spiffeConfigured:
		return "", errors.New("SignerSet: both a signing key (--signing-key or --signing-ssh-agent-key) and --spiffe-socket are set; pass --signing-backend explicitly to disambiguate")
	case keyConfigured:
		return BackendKey, nil
	case spiffeConfigured:
		return BackendSpiffe, nil
	default:
		return BackendSigstore, nil
	}
}

// Validate checks --signing-backend is recognized and validates the selected
// child only. Non-selected children are not consulted, so their flags
// can be left unset without failing validation. Nil-safe.
func (s *SignerSet) Validate() error {
	if s == nil {
		return errors.New("SignerSet: nil; construct via DefaultSignerSet")
	}
	backend, err := s.resolveBackend()
	if err != nil {
		return err
	}
	switch backend {
	case BackendKey:
		if s.Keys == nil {
			return errors.New("SignerSet: --signing-backend=key but Keys is nil")
		}
		return s.Keys.Validate()
	case BackendSigstore:
		if s.Sigstore == nil {
			return errors.New("SignerSet: --signing-backend=sigstore but Sigstore is nil")
		}
		return s.Sigstore.Validate()
	case BackendSpiffe:
		if s.Spiffe == nil {
			return errors.New("SignerSet: --signing-backend=spiffe but Spiffe is nil")
		}
		return s.Spiffe.Validate()
	default:
		return fmt.Errorf("SignerSet: unhandled backend %q", backend)
	}
}

// BuildSigner dispatches on --signing-backend and returns the populated
// *Signer for that backend. SPIFFE callers must additionally call
// BuildCredentialProvider and assign the result to
// signer.Signer.Credentials before any Sign* call.
func (s *SignerSet) BuildSigner() (*Signer, error) {
	if s == nil {
		return nil, errors.New("SignerSet: nil; construct via DefaultSignerSet")
	}
	backend, err := s.resolveBackend()
	if err != nil {
		return nil, err
	}
	var target *Signer
	switch backend {
	case BackendKey:
		if s.Keys == nil {
			return nil, errors.New("SignerSet: --signing-backend=key but Keys is nil")
		}
		target, err = s.Keys.BuildSigner()
	case BackendSigstore:
		if s.Sigstore == nil {
			return nil, errors.New("SignerSet: --signing-backend=sigstore but Sigstore is nil")
		}
		target, err = s.Sigstore.BuildSigner()
	case BackendSpiffe:
		if s.Spiffe == nil {
			return nil, errors.New("SignerSet: --signing-backend=spiffe but Spiffe is nil")
		}
		target, err = s.Spiffe.BuildSigner()
	default:
		return nil, fmt.Errorf("SignerSet: unhandled backend %q", backend)
	}
	if err != nil {
		return nil, err
	}
	// The bundled --signing-timestamp wins over per-backend defaults.
	// For BackendKey this is a no-op (DSSE envelopes carry no
	// timestamp); for BackendSpiffe it lights up once TSA-for-SPIFFE
	// wiring lands.
	target.Timestamp = s.Timestamp
	return target, nil
}

// BuildCredentialProvider returns the *spiffe.CredentialProvider
// needed to arm signer.Signer.Credentials for the SPIFFE backend.
// Returns (nil, nil) for backends that don't need an externally-
// supplied provider — sigstore lazy-builds from Options on first
// signing call; key has no credentials concept.
func (s *SignerSet) BuildCredentialProvider() (*spiffe.CredentialProvider, error) {
	if s == nil {
		return nil, errors.New("SignerSet: nil; construct via DefaultSignerSet")
	}
	backend, err := s.resolveBackend()
	if err != nil {
		return nil, err
	}
	if backend != BackendSpiffe {
		return nil, nil
	}
	if s.Spiffe == nil {
		return nil, errors.New("SignerSet: --signing-backend=spiffe but Spiffe is nil")
	}
	return s.Spiffe.BuildCredentialProvider()
}
