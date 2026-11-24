// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dsse

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

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

func readKey(t *testing.T, name string) key.PublicKeyProvider {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	provider, err := key.NewParser().ParsePublicKeyProvider(data)
	require.NoError(t, err)
	return provider
}

// Envelopes signed with SSH keys by other tools verify. Neither fixture
// was made by this repository's code:
//
//   - ssh-ed25519.dsse.json is an in-toto statement signed by hand with
//     ssh-keygen (OpenSSH 10.2) over the DSSE PAE of the payload, under
//     the "file" namespace:
//
//     ssh-keygen -Y sign -n file -f key pae.bin
//
//   - gittuf-approval.dsse.json is a pull request approval from the
//     gittuf project's own repository, signed by the gittuf GitHub app
//     with an RSA key under the "git" namespace. Its provenance is
//     recorded in internal/sshsig/testdata/README.md.
//
// Both carry the signature armored, as ssh-keygen writes it.
func TestRunVerificationSSHFixtures(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		envelope, key, fingerprint string
		scheme                     key.Scheme
		namespace                  string
	}{
		{
			"ssh-ed25519.dsse.json", "ssh-ed25519.pub",
			"SHA256:LxeZc9rei//QDUFrAk6FxUG5vMTxXQ2p02uMxIjJzPY", key.Ed25519, "file",
		},
		{
			"gittuf-approval.dsse.json", "gittuf-app.pub",
			"SHA256:KTrCAHHGUSCkNjanR0t4ojOiHQ4qZIQM6mkwX64b2KY", key.RsaPkcs1v15, "git",
		},
	} {
		t.Run(tc.envelope, func(t *testing.T) {
			t.Parallel()
			v := &DefaultVerifier{}
			env, err := v.OpenEnvelope(filepath.Join("testdata", tc.envelope))
			require.NoError(t, err)

			provider := readKey(t, tc.key)
			require.IsType(t, &key.SSHPublic{}, provider)

			res, err := v.RunVerification(&options.Verifier{}, key.NewVerifier(), env, []key.PublicKeyProvider{provider})
			require.NoError(t, err)
			require.True(t, res.Verified)
			require.Len(t, res.Keys, 1)

			// The key is reported by its SSH fingerprint and the scheme of
			// the underlying key. An SSH key has no subkeys, so there is
			// no separate signing fingerprint.
			require.Equal(t, tc.fingerprint, res.Keys[0].ID())
			require.Equal(t, tc.scheme, res.Keys[0].Scheme)
			require.Empty(t, res.Keys[0].SigningKeyFingerprint)

			// The namespace the signature was made under is reported.
			require.Equal(t, tc.namespace, res.Keys[0].SignatureNamespace)

			// A changed payload does not verify.
			env.Payload = append(env.Payload, ' ')
			res, err = v.RunVerification(&options.Verifier{}, key.NewVerifier(), env, []key.PublicKeyProvider{provider})
			require.NoError(t, err)
			require.False(t, res.Verified)
		})
	}
}

// The keys of one fixture do not verify the other, and keys of other
// formats do not get in the way.
func TestRunVerificationSSHWrongKeys(t *testing.T) {
	t.Parallel()
	v := &DefaultVerifier{}
	env, err := v.OpenEnvelope(filepath.Join("testdata", "ssh-ed25519.dsse.json"))
	require.NoError(t, err)

	wrong := []key.PublicKeyProvider{
		readKey(t, "gittuf-app.pub"), readKey(t, "rebuild.key"), readKey(t, "gpg-ed25519.pub.asc"),
	}
	res, err := v.RunVerification(&options.Verifier{}, key.NewVerifier(), env, wrong)
	require.NoError(t, err)
	require.False(t, res.Verified)
	require.Empty(t, res.Keys)

	res, err = v.RunVerification(
		&options.Verifier{}, key.NewVerifier(), env, append(wrong, readKey(t, "ssh-ed25519.pub")),
	)
	require.NoError(t, err)
	require.True(t, res.Verified)
	require.Len(t, res.Keys, 1)
}

// An envelope signed with an SSH key verifies against its public key.
func TestSignVerifySSH(t *testing.T) {
	t.Parallel()
	priv, pub := newSSHKey(t)
	_, otherPub := newSSHKey(t)

	signer := NewSigner()
	env, err := signer.WrapPayload("text/plain", []byte("some payload"))
	require.NoError(t, err)
	require.NoError(t, signer.Sign(env, []key.PrivateKeyProvider{priv}))
	require.Len(t, env.GetSignatures(), 1)

	v := &DefaultVerifier{}
	res, err := v.RunVerification(&options.Verifier{}, key.NewVerifier(), env, []key.PublicKeyProvider{pub})
	require.NoError(t, err)
	require.True(t, res.Verified)
	require.Len(t, res.Keys, 1)
	require.Equal(t, pub.Fingerprint(), res.Keys[0].ID())

	res, err = v.RunVerification(&options.Verifier{}, key.NewVerifier(), env, []key.PublicKeyProvider{otherPub})
	require.NoError(t, err)
	require.False(t, res.Verified)

	// The payload type is part of what is signed.
	env.PayloadType = "text/html"
	res, err = v.RunVerification(&options.Verifier{}, key.NewVerifier(), env, []key.PublicKeyProvider{pub})
	require.NoError(t, err)
	require.False(t, res.Verified)
}

// The namespace of each verified signature is reported with the key that
// verified it. The key the caller passed in is left untouched.
func TestRunVerificationSSHNamespace(t *testing.T) {
	t.Parallel()
	priv, pub := newSSHKey(t)

	signer := NewSigner()
	env, err := signer.WrapPayload("text/plain", []byte("some payload"))
	require.NoError(t, err)

	// The same key signs twice, under two namespaces.
	require.NoError(t, signer.Sign(env, []key.PrivateKeyProvider{priv}))
	priv.Namespace = "git"
	require.NoError(t, signer.Sign(env, []key.PrivateKeyProvider{priv}))
	require.Len(t, env.GetSignatures(), 2)

	res, err := (&DefaultVerifier{}).RunVerification(
		&options.Verifier{}, key.NewVerifier(), env, []key.PublicKeyProvider{pub},
	)
	require.NoError(t, err)
	require.True(t, res.Verified)
	require.Len(t, res.Keys, 2)

	namespaces := []string{res.Keys[0].SignatureNamespace, res.Keys[1].SignatureNamespace}
	require.ElementsMatch(t, []string{key.DefaultSSHNamespace, "git"}, namespaces)
	for _, k := range res.Keys {
		require.Equal(t, pub.Fingerprint(), k.ID())
	}

	// Keys without a namespace report none.
	plainPriv, err := key.NewGenerator().GenerateKeyPair()
	require.NoError(t, err)
	plainPub, err := plainPriv.PublicKey()
	require.NoError(t, err)
	plainEnv, err := signer.WrapPayload("text/plain", []byte("some payload"))
	require.NoError(t, err)
	require.NoError(t, signer.Sign(plainEnv, []key.PrivateKeyProvider{plainPriv}))
	res, err = (&DefaultVerifier{}).RunVerification(
		&options.Verifier{}, key.NewVerifier(), plainEnv, []key.PublicKeyProvider{plainPub},
	)
	require.NoError(t, err)
	require.Len(t, res.Keys, 1)
	require.Empty(t, res.Keys[0].SignatureNamespace)
}

// An envelope can carry the signatures of an SSH key and of a plain key.
// Each key verifies its own signature only.
func TestSignVerifySSHMixed(t *testing.T) {
	t.Parallel()
	sshPriv, sshPub := newSSHKey(t)
	plainPriv, err := key.NewGenerator().GenerateKeyPair()
	require.NoError(t, err)
	plainPub, err := plainPriv.PublicKey()
	require.NoError(t, err)

	signer := NewSigner()
	env, err := signer.WrapPayload("text/plain", []byte("some payload"))
	require.NoError(t, err)
	require.NoError(t, signer.Sign(env, []key.PrivateKeyProvider{plainPriv, sshPriv}))
	require.Len(t, env.GetSignatures(), 2)

	verify := func(keys ...key.PublicKeyProvider) *key.VerificationResult {
		res, err := (&DefaultVerifier{}).RunVerification(&options.Verifier{}, key.NewVerifier(), env, keys)
		require.NoError(t, err)
		return res
	}

	require.Len(t, verify(plainPub, sshPub).Keys, 2)

	res := verify(sshPub)
	require.Len(t, res.Keys, 1)
	require.Equal(t, sshPub.Fingerprint(), res.Keys[0].ID())

	res = verify(plainPub)
	require.Len(t, res.Keys, 1)
	require.Equal(t, plainPub.ID(), res.Keys[0].ID())

	// The key material of the SSH key, handled as a plain key, does not
	// verify the SSH signature: the two are different signature formats.
	underlying, err := sshPriv.PrivateKey()
	require.NoError(t, err)
	underlyingPub, err := underlying.PublicKey()
	require.NoError(t, err)
	require.False(t, verify(underlyingPub).Verified)
}
