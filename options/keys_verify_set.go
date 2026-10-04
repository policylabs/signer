// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"errors"
	"fmt"

	"github.com/carabiner-dev/command"
	"github.com/carabiner-dev/command/keys"
)

// KeysVerify is a command.OptionsSet for verify-side public-key
// configuration. It composes the upstream
// github.com/carabiner-dev/command/keys.Options (which supplies the
// --key flag, repeatable, plus AddKeys and ParseKeys) with this
// package's verifier-side ApplyToVerifier / BuildVerifier so the set
// fits the same shape as SigstoreVerifySet and SpiffeVerifySet.
//
// Composition over duplication: the upstream package owns --key, we
// own the wiring into options.Verifier so the keys flow into
// Verification.PubKeys and VerifyParsedDSSE picks them up via the
// fallback added when the per-call keys argument is empty.
type KeysVerify struct {
	*keys.Options
}

var _ command.OptionsSet = (*KeysVerify)(nil)

// DefaultKeysVerify constructs a KeysVerify wrapping a fresh upstream
// keys.Options ready to bind flags.
func DefaultKeysVerify() *KeysVerify {
	return &KeysVerify{Options: &keys.Options{}}
}

// ApplyToVerifier parses every configured public-key file (and any
// programmatic providers added via AddKeys on the embedded Options)
// and stores them on target.Verification.PubKeys. VerifyParsedDSSE
// reads PubKeys as a fallback when its keys argument is empty, so a
// CLI can wire --key once and call VerifyDSSE without re-passing.
func (k *KeysVerify) ApplyToVerifier(target *Verifier) error {
	if target == nil {
		return errors.New("KeysVerify.ApplyToVerifier: target is nil")
	}
	if k == nil || k.Options == nil {
		return errors.New("KeysVerify: nil; construct via DefaultKeysVerify")
	}
	parsed, err := k.ParseKeys()
	if err != nil {
		return fmt.Errorf("KeysVerify.ApplyToVerifier: %w", err)
	}
	target.PubKeys = parsed
	return nil
}

// Active reports whether the user has configured this set with any
// public keys via the --key flag. Active=false means the bundled
// VerifierSet skips this child during Validate / ApplyToVerifier so
// a CLI verifying a sigstore- or SPIFFE-only bundle isn't forced to
// pass --key.
//
// Programmatically-added keys (via the embedded keys.Options.AddKeys)
// are not visible here because the upstream extraKeys field is
// unexported. Callers who only use AddKeys should construct the
// verifier directly via BuildVerifier rather than relying on the
// bundled VerifierSet's active-child filtering.
func (k *KeysVerify) Active() bool {
	if k == nil || k.Options == nil {
		return false
	}
	return len(k.PublicKeyPaths) > 0
}

// BuildVerifier returns a *Verifier populated from the resolved
// public-key configuration. Empty key configuration is allowed and
// yields a Verifier whose PubKeys slice is empty — callers that
// require keys must check before calling VerifyDSSE.
func (k *KeysVerify) BuildVerifier() (*Verifier, error) {
	target := DefaultVerifier
	if err := k.ApplyToVerifier(&target); err != nil {
		return nil, err
	}
	return &target, nil
}
