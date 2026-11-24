// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestSignerSetAddFlags(t *testing.T) {
	t.Parallel()

	set := DefaultSignerSet()
	cmd := &cobra.Command{Use: "test"}
	set.AddFlags(cmd)

	for _, name := range []string{
		"signing-backend",
		"signing-timestamp",
		"signing-key",
		"signing-key-passphrase-env",
		"sigstore-roots",
		"spiffe-trust-domain",
		"spiffe-socket",
	} {
		require.NotNil(t, cmd.PersistentFlags().Lookup(name), "flag %q must be registered", name)
	}

	// Per-backend timestamp flags are suppressed when bundled — the
	// shared --signing-timestamp is the single user-facing knob.
	for _, name := range []string{"sigstore-timestamp", "spiffe-timestamp"} {
		require.Nil(t, cmd.PersistentFlags().Lookup(name),
			"--%s must NOT be registered when bundled (ManagedTimestamp set by SignerSet)", name)
	}
}

// TestSignerSetTimestampPropagates asserts the bundled
// --signing-timestamp value flows into the resolved *options.Signer
// regardless of backend.
func TestSignerSetTimestampPropagates(t *testing.T) {
	t.Parallel()

	t.Run("sigstore-true", func(t *testing.T) {
		t.Parallel()
		set := DefaultSignerSet()
		set.Backend = string(BackendSigstore)
		set.Timestamp = true

		opts, err := set.BuildSigner()
		require.NoError(t, err)
		require.True(t, opts.Timestamp)
	})

	t.Run("sigstore-false", func(t *testing.T) {
		t.Parallel()
		set := DefaultSignerSet()
		set.Backend = string(BackendSigstore)
		set.Timestamp = false

		opts, err := set.BuildSigner()
		require.NoError(t, err)
		require.False(t, opts.Timestamp,
			"SignerSet.Timestamp=false must override the per-instance default")
	})

	t.Run("key-noop", func(t *testing.T) {
		t.Parallel()
		set := DefaultSignerSet()
		set.Backend = string(BackendKey)
		set.Timestamp = true
		set.Keys.PrivateKeyPaths = []string{writeECPrivateKey(t)}

		opts, err := set.BuildSigner()
		require.NoError(t, err)
		require.True(t, opts.Timestamp,
			"key backend ignores Timestamp at runtime but the field is still set")
	})

	t.Run("spiffe-true-propagates", func(t *testing.T) {
		t.Parallel()
		set := DefaultSignerSet()
		set.Backend = string(BackendSpiffe)
		set.Timestamp = true
		// Set socket via field to avoid t.Setenv (incompatible with the
		// parent t.Parallel chain).
		set.Spiffe.Sign.SocketPath = testSpiffeSocket

		opts, err := set.BuildSigner()
		require.NoError(t, err)
		require.True(t, opts.Timestamp)
		require.Nil(t, opts.SigningConfig,
			"options layer should not carry SigningConfig; bundle layer fills it in lazily")
	})

	t.Run("spiffe-false-overrides-per-set-default", func(t *testing.T) {
		t.Parallel()
		set := DefaultSignerSet()
		set.Backend = string(BackendSpiffe)
		set.Timestamp = false
		set.Spiffe.Sign.SocketPath = testSpiffeSocket

		opts, err := set.BuildSigner()
		require.NoError(t, err)
		require.False(t, opts.Timestamp,
			"SignerSet.Timestamp=false must override SPIFFE per-set default")
	})
}

func TestSignerSetValidateUnknownBackend(t *testing.T) {
	t.Parallel()

	set := DefaultSignerSet()
	set.Backend = "carrier-pigeon"
	err := set.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown --signing-backend")
}

func TestSignerSetValidateKeyBackend(t *testing.T) {
	t.Parallel()

	t.Run("missing-keys-fails", func(t *testing.T) {
		t.Parallel()
		set := DefaultSignerSet()
		set.Backend = string(BackendKey)
		// Validate passes (paths empty → no os.Stat). BuildSigner is the
		// place that errors out for "no keys configured".
		require.NoError(t, set.Validate())
		_, err := set.BuildSigner()
		require.Error(t, err)
		require.Contains(t, err.Error(), "no signing keys")
	})

	t.Run("with-key-builds", func(t *testing.T) {
		t.Parallel()
		set := DefaultSignerSet()
		set.Backend = string(BackendKey)
		set.Keys.PrivateKeyPaths = []string{writeECPrivateKey(t)}
		require.NoError(t, set.Validate())

		opts, err := set.BuildSigner()
		require.NoError(t, err)
		require.Equal(t, BackendKey, opts.Backend)
		require.Len(t, opts.Keys, 1)
	})

	t.Run("nil-keys-child-fails", func(t *testing.T) {
		t.Parallel()
		set := DefaultSignerSet()
		set.Backend = string(BackendKey)
		set.Keys = nil
		err := set.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "Keys is nil")
	})
}

func TestSignerSetValidateSpiffeBackend(t *testing.T) {
	// No t.Parallel — t.Setenv conflicts with parallel chains.
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")

	t.Run("missing-socket-fails", func(t *testing.T) {
		t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")
		set := DefaultSignerSet()
		set.Backend = string(BackendSpiffe)
		err := set.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "SPIFFE_ENDPOINT_SOCKET")
	})

	t.Run("env-satisfies", func(t *testing.T) {
		t.Setenv("SPIFFE_ENDPOINT_SOCKET", testSpiffeSocket)
		set := DefaultSignerSet()
		set.Backend = string(BackendSpiffe)
		require.NoError(t, set.Validate())

		opts, err := set.BuildSigner()
		require.NoError(t, err)
		require.Equal(t, BackendSpiffe, opts.Backend)

		creds, err := set.BuildCredentialProvider()
		require.NoError(t, err)
		require.NotNil(t, creds)
	})

	t.Run("nil-spiffe-child-fails", func(t *testing.T) {
		t.Setenv("SPIFFE_ENDPOINT_SOCKET", testSpiffeSocket)
		set := DefaultSignerSet()
		set.Backend = string(BackendSpiffe)
		set.Spiffe = nil
		err := set.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "Spiffe is nil")
	})
}

func TestSignerSetSigstoreBackendDefault(t *testing.T) {
	t.Parallel()

	t.Run("explicit-sigstore", func(t *testing.T) {
		t.Parallel()
		set := DefaultSignerSet()
		set.Backend = string(BackendSigstore)
		require.NoError(t, set.Validate())

		opts, err := set.BuildSigner()
		require.NoError(t, err)
		require.NotNil(t, opts)

		// Sigstore doesn't need an external credential provider.
		creds, err := set.BuildCredentialProvider()
		require.NoError(t, err)
		require.Nil(t, creds)
	})

	t.Run("empty-backend-defaults-to-sigstore", func(t *testing.T) {
		t.Parallel()
		set := DefaultSignerSet()
		set.Backend = ""
		require.NoError(t, set.Validate())

		opts, err := set.BuildSigner()
		require.NoError(t, err)
		require.NotNil(t, opts)
	})
}

// TestSignerSetAutoDetect verifies the empty-backend hybrid: explicit
// --signing-backend wins; otherwise the populated child flags decide,
// with sigstore as the no-flags fallback. Env vars (e.g.
// SPIFFE_ENDPOINT_SOCKET) intentionally do not trigger auto-detect.
func TestSignerSetAutoDetect(t *testing.T) {
	// No t.Parallel — t.Setenv conflicts with parallel chains.

	t.Run("no-flags-falls-back-to-sigstore", func(t *testing.T) {
		t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")
		set := DefaultSignerSet()
		require.Empty(t, set.Backend)

		backend, err := set.resolveBackend()
		require.NoError(t, err)
		require.Equal(t, BackendSigstore, backend)
	})

	t.Run("signing-key-flag-selects-key", func(t *testing.T) {
		t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")
		set := DefaultSignerSet()
		set.Keys.PrivateKeyPaths = []string{writeECPrivateKey(t)}

		backend, err := set.resolveBackend()
		require.NoError(t, err)
		require.Equal(t, BackendKey, backend)
	})

	t.Run("ssh-agent-key-flag-selects-key", func(t *testing.T) {
		t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")
		set := DefaultSignerSet()
		set.Keys.SSHAgentKeys = []string{"SHA256:nzPv/9uwC5nIic8SUw3EYVUOPycf1vDtFcpSar/D7QU"}

		backend, err := set.resolveBackend()
		require.NoError(t, err)
		require.Equal(t, BackendKey, backend)

		set.Spiffe.Sign.SocketPath = testSpiffeSocket
		_, err = set.resolveBackend()
		require.ErrorContains(t, err, "--signing-backend")
	})

	t.Run("spiffe-socket-flag-selects-spiffe", func(t *testing.T) {
		t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")
		set := DefaultSignerSet()
		set.Spiffe.Sign.SocketPath = testSpiffeSocket

		backend, err := set.resolveBackend()
		require.NoError(t, err)
		require.Equal(t, BackendSpiffe, backend)
	})

	t.Run("env-only-spiffe-does-not-auto-detect", func(t *testing.T) {
		// SPIFFE_ENDPOINT_SOCKET set, but --spiffe-socket flag empty.
		// The flag is the auto-detect signal; env vars require an
		// explicit --signing-backend=spiffe.
		t.Setenv("SPIFFE_ENDPOINT_SOCKET", testSpiffeSocket)
		set := DefaultSignerSet()

		backend, err := set.resolveBackend()
		require.NoError(t, err)
		require.Equal(t, BackendSigstore, backend)
	})

	t.Run("both-flags-set-is-ambiguous", func(t *testing.T) {
		t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")
		set := DefaultSignerSet()
		set.Keys.PrivateKeyPaths = []string{writeECPrivateKey(t)}
		set.Spiffe.Sign.SocketPath = testSpiffeSocket

		_, err := set.resolveBackend()
		require.Error(t, err)
		require.Contains(t, err.Error(), "pass --signing-backend explicitly")
	})

	t.Run("explicit-overrides-auto-detect", func(t *testing.T) {
		t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")
		// Both set, but explicit --signing-backend disambiguates and
		// dispatches without complaint.
		set := DefaultSignerSet()
		set.Backend = string(BackendKey)
		set.Keys.PrivateKeyPaths = []string{writeECPrivateKey(t)}
		set.Spiffe.Sign.SocketPath = testSpiffeSocket

		backend, err := set.resolveBackend()
		require.NoError(t, err)
		require.Equal(t, BackendKey, backend)
	})
}

// TestSignerSetBuildCredentialProviderSkipsNonSpiffe asserts the
// (nil, nil) contract for non-SPIFFE backends — callers can call this
// uniformly without checking the Backend first.
func TestSignerSetBuildCredentialProviderSkipsNonSpiffe(t *testing.T) {
	t.Parallel()

	for _, backend := range []Backend{BackendKey, BackendSigstore} {
		set := DefaultSignerSet()
		set.Backend = string(backend)
		creds, err := set.BuildCredentialProvider()
		require.NoError(t, err, "backend %q", backend)
		require.Nil(t, creds, "backend %q must yield (nil, nil)", backend)
	}
}
