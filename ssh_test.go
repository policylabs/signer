// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	api "github.com/policylabs/signer/api/v1"
	"github.com/policylabs/signer/internal/sshsig"
	"github.com/policylabs/signer/key"
	"github.com/policylabs/signer/options"
)

// newSSHKey generates an SSH key pair, the way ssh-keygen would write it.
func newSSHKey(t *testing.T) (*key.SSHPrivate, *key.SSHPublic) {
	t.Helper()
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(edKey, "")
	require.NoError(t, err)
	priv, err := key.ParseSSHPrivateKey(pem.EncodeToMemory(block), nil)
	require.NoError(t, err)
	return priv, priv.SSHPublicKey()
}

// A statement signed with an SSH key verifies, and the signer is
// reported as a key identified by its SSH fingerprint.
func TestSSHSignVerifyStatement(t *testing.T) {
	t.Parallel()
	priv, pub := newSSHKey(t)
	_, otherPub := newSSHKey(t)

	art, err := keySigner().SignStatement([]byte(keyBundleStatement), options.WithKey(priv))
	require.NoError(t, err)
	require.Equal(t, ArtifactKindEnvelope, art.Kind())

	// Verify what a consumer would read back from disk.
	var buf bytes.Buffer
	_, err = art.WriteTo(&buf)
	require.NoError(t, err)

	res, err := NewVerifier().VerifyStatementBytes(buf.Bytes(), options.WithPublicKeys(pub))
	require.NoError(t, err)
	require.Equal(t, api.VerificationStatus_VERIFIED, res.GetSignature().GetStatus())

	ids := res.GetSignature().GetIdentities()
	require.Len(t, ids, 1)
	require.Equal(t, pub.Fingerprint(), ids[0].GetKey().GetId())
	require.Equal(t, "ed25519", ids[0].GetKey().GetType())
	require.Equal(t, "key::ed25519::"+pub.Fingerprint(), ids[0].Principal())

	// A policy names the signer by fingerprint, or carries the key as the
	// line of an authorized_keys file.
	require.True(t, res.MatchesIdentity(&api.Identity{Key: &api.IdentityKey{Id: pub.Fingerprint()}}))
	require.True(t, res.MatchesIdentity(&api.Identity{Key: &api.IdentityKey{Data: pub.GetData()}}))
	require.False(t, res.MatchesIdentity(&api.Identity{Key: &api.IdentityKey{Id: otherPub.Fingerprint()}}))
	require.False(t, res.MatchesIdentity(&api.Identity{Key: &api.IdentityKey{Data: otherPub.GetData()}}))

	// Another key does not verify the statement.
	res, err = NewVerifier().VerifyStatementBytes(buf.Bytes(), options.WithPublicKeys(otherPub))
	require.NoError(t, err)
	require.Equal(t, api.VerificationStatus_FAILED, res.GetSignature().GetStatus())
}

// The namespace an SSH key signs under is the signer's choice. The
// verifier takes whatever namespace the signature declares.
func TestSSHSignStatementNamespace(t *testing.T) {
	t.Parallel()
	priv, pub := newSSHKey(t)
	priv.Namespace = "git"

	art, err := keySigner().SignStatement([]byte(keyBundleStatement), options.WithKey(priv))
	require.NoError(t, err)
	env, ok := art.(*EnvelopeArtifact)
	require.True(t, ok)
	require.Len(t, env.Envelope.GetSignatures(), 1)

	sig, err := sshsig.Parse(env.Envelope.GetSignatures()[0].GetSig())
	require.NoError(t, err)
	require.Equal(t, "git", sig.Namespace)

	res, err := NewVerifier().VerifyStatement(art, options.WithPublicKeys(pub))
	require.NoError(t, err)
	require.Equal(t, api.VerificationStatus_VERIFIED, res.GetSignature().GetStatus())
}

// An SSH key signs into a bundle like any other key.
func TestSSHSignBundle(t *testing.T) {
	t.Parallel()
	priv, pub := newSSHKey(t)

	art, err := keySigner().SignStatement([]byte(keyBundleStatement), options.WithKey(priv), options.WithBundle())
	require.NoError(t, err)
	require.Equal(t, ArtifactKindBundle, art.Kind())

	b := roundTrip(t, art)
	require.Equal(t, expectedHint(t, pub.GetKey()), b.GetVerificationMaterial().GetPublicKey().GetHint())

	res, err := NewVerifier().VerifyParsedDSSE(b.GetDsseEnvelope(), []key.PublicKeyProvider{pub})
	require.NoError(t, err)
	require.True(t, res.Verified)
	require.Len(t, res.Keys, 1)
	require.Equal(t, pub.Fingerprint(), res.Keys[0].ID())
}

// A key held by an SSH agent signs envelopes and bundles like one read
// from a file, even though its private key material cannot be reached.
func TestSSHAgentSignStatement(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("SSH agents are not supported on Windows")
	}

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyring := agent.NewKeyring()
	require.NoError(t, keyring.Add(agent.AddedKey{PrivateKey: edKey}))

	// Socket paths are limited to about a hundred bytes, which t.TempDir
	// can exceed.
	dir, err := os.MkdirTemp("", "agent") //nolint:usetesting // t.TempDir is too long for a socket
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) }) //nolint:errcheck,gosec // best effort
	socket := filepath.Join(dir, "s")

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socket)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() }) //nolint:errcheck,gosec // best effort
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()              //nolint:errcheck // best effort
				agent.ServeAgent(keyring, conn) //nolint:errcheck,gosec // ends when the client hangs up
			}()
		}
	}()

	held, err := key.SSHAgentKeys(socket)
	require.NoError(t, err)
	require.Len(t, held, 1)
	pub := held[0]

	priv, err := key.SSHAgentKey(socket, pub.Fingerprint())
	require.NoError(t, err)
	_, err = priv.PrivateKey()
	require.Error(t, err)

	t.Run("envelope", func(t *testing.T) {
		t.Parallel()
		art, err := keySigner().SignStatement([]byte(keyBundleStatement), options.WithKey(priv))
		require.NoError(t, err)
		require.Equal(t, ArtifactKindEnvelope, art.Kind())

		res, err := NewVerifier().VerifyStatement(art, options.WithPublicKeys(pub))
		require.NoError(t, err)
		require.Equal(t, api.VerificationStatus_VERIFIED, res.GetSignature().GetStatus())
		require.Len(t, res.GetSignature().GetIdentities(), 1)
		require.Equal(t,
			"key::ed25519::"+pub.Fingerprint(), res.GetSignature().GetIdentities()[0].Principal(),
		)
	})

	t.Run("bundle", func(t *testing.T) {
		t.Parallel()
		art, err := keySigner().SignStatement(
			[]byte(keyBundleStatement), options.WithKey(priv), options.WithBundle(),
		)
		require.NoError(t, err)
		require.Equal(t, ArtifactKindBundle, art.Kind())

		b := roundTrip(t, art)
		require.Equal(t, expectedHint(t, pub.GetKey()), b.GetVerificationMaterial().GetPublicKey().GetHint())

		res, err := NewVerifier().VerifyParsedDSSE(b.GetDsseEnvelope(), []key.PublicKeyProvider{pub})
		require.NoError(t, err)
		require.True(t, res.Verified)
	})
}

// The envelopes signed with SSH keys by other tools verify as statements.
// See dsse/ssh_test.go for where the fixtures come from.
func TestSSHVerifyStatementFixtures(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		envelope, key, principal string
	}{
		{
			"ssh-ed25519.dsse.json", "ssh-ed25519.pub",
			"key::ed25519::SHA256:LxeZc9rei//QDUFrAk6FxUG5vMTxXQ2p02uMxIjJzPY",
		},
		{
			"gittuf-approval.dsse.json", "gittuf-app.pub",
			"key::rsassa-pkcs1v15::SHA256:KTrCAHHGUSCkNjanR0t4ojOiHQ4qZIQM6mkwX64b2KY",
		},
	} {
		t.Run(tc.envelope, func(t *testing.T) {
			t.Parallel()
			envelope, err := os.ReadFile(filepath.Join("dsse", "testdata", tc.envelope))
			require.NoError(t, err)
			keyData, err := os.ReadFile(filepath.Join("dsse", "testdata", tc.key))
			require.NoError(t, err)
			pub, err := key.NewParser().ParsePublicKeyProvider(keyData)
			require.NoError(t, err)

			res, err := NewVerifier().VerifyStatementBytes(envelope, options.WithPublicKeys(pub))
			require.NoError(t, err)
			require.Equal(t, api.VerificationStatus_VERIFIED, res.GetSignature().GetStatus())
			require.Len(t, res.GetSignature().GetIdentities(), 1)
			require.Equal(t, tc.principal, res.GetSignature().GetIdentities()[0].Principal())

			expected, err := api.NewIdentityFromPrincipal(tc.principal)
			require.NoError(t, err)
			require.True(t, res.MatchesIdentity(expected))
		})
	}
}
