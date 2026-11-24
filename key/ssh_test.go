// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/policylabs/signer/internal/sshsig"
)

// The SSH fixtures in testdata were made with ssh-keygen (OpenSSH 10.2):
//
//	ssh-keygen -t ed25519 -N '' -C test@example.com -f ssh-ed25519
//	ssh-keygen -p -N test -f ssh-ed25519-encrypted   (a copy of ssh-ed25519)
//	ssh-keygen -t ecdsa -b 256 -N '' -C '' -f ssh-ecdsa
//	ssh-keygen -t rsa -b 2048 -N '' -C '' -f ssh-rsa
//	ssh-keygen -Y sign -n file -f ssh-ed25519 message.txt   (ssh-message.sig)
const (
	sshEd25519Fingerprint = "SHA256:nzPv/9uwC5nIic8SUw3EYVUOPycf1vDtFcpSar/D7QU"
	sshFixturePassphrase  = "test"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return data
}

func TestParseSSHPublicKey(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		file    string
		keyType Type
		scheme  Scheme
		hash    crypto.Hash
		stdKey  any
	}{
		{"ssh-ed25519.pub", ED25519, Ed25519, 0, ed25519.PublicKey{}},
		{"ssh-ecdsa.pub", ECDSA, EcdsaSha2nistP256, crypto.SHA256, &ecdsa.PublicKey{}},
		{"ssh-rsa.pub", RSA, RsaPkcs1v15, crypto.SHA256, &rsa.PublicKey{}},
	} {
		t.Run(tc.file, func(t *testing.T) {
			t.Parallel()
			data := readTestdata(t, tc.file)
			k, err := ParseSSHPublicKey(data)
			require.NoError(t, err)

			// The wrapper reports itself as an SSH key and describes the
			// underlying key.
			require.Equal(t, SSH, k.GetType())
			require.Equal(t, tc.scheme, k.GetScheme())
			require.Equal(t, tc.hash, k.GetHashType())
			require.IsType(t, tc.stdKey, k.GetKey())
			require.Nil(t, k.GetNotBefore())
			require.Nil(t, k.GetNotAfter())
			require.Equal(t, strings.TrimSpace(string(data)), k.GetData())
			require.NotNil(t, k.SSHPublicKey())

			// The extracted key is identified by the SSH fingerprint.
			pub, err := k.PublicKey()
			require.NoError(t, err)
			require.Equal(t, tc.keyType, pub.Type)
			require.Equal(t, tc.scheme, pub.Scheme)
			require.Equal(t, tc.hash, pub.HashType)
			require.IsType(t, tc.stdKey, pub.Key)
			require.Equal(t, k.Fingerprint(), pub.ID())
			require.True(t, strings.HasPrefix(pub.ID(), "SHA256:"))

			// The data of the extracted key is the PEM of the underlying
			// key, not the SSH encoding.
			block, _ := pem.Decode([]byte(pub.Data))
			require.NotNil(t, block)
		})
	}
}

func TestParseSSHPublicKey_FingerprintAndComment(t *testing.T) {
	t.Parallel()
	k, err := ParseSSHPublicKey(readTestdata(t, "ssh-ed25519.pub"))
	require.NoError(t, err)
	require.Equal(t, sshEd25519Fingerprint, k.Fingerprint())
	require.Equal(t, "test@example.com", k.Comment())

	// Without a comment the data is the bare key.
	bare, err := ParseSSHPublicKey(readTestdata(t, "ssh-ecdsa.pub"))
	require.NoError(t, err)
	require.Empty(t, bare.Comment())
	require.Len(t, strings.Fields(bare.GetData()), 2)
}

func TestParseSSHPublicKey_Errors(t *testing.T) {
	t.Parallel()

	_, err := ParseSSHPublicKey([]byte("not a key"))
	require.Error(t, err)

	_, err = ParseSSHPublicKey(readTestdata(t, "gpg-ecdsa-public.asc"))
	require.Error(t, err)

	// Certificates are not supported.
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ca, err := ssh.NewSignerFromKey(caKey)
	require.NoError(t, err)
	subject, err := ParseSSHPublicKey(readTestdata(t, "ssh-ed25519.pub"))
	require.NoError(t, err)
	cert := &ssh.Certificate{Key: subject.SSHPublicKey(), CertType: ssh.UserCert, ValidBefore: ssh.CertTimeInfinity}
	require.NoError(t, cert.SignCert(rand.Reader, ca))
	_, err = ParseSSHPublicKey(ssh.MarshalAuthorizedKey(cert))
	require.ErrorIs(t, err, sshsig.ErrCertificate)
}

func TestParseSSHPrivateKey(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		file       string
		passphrase string
		keyType    Type
		scheme     Scheme
		stdKey     any
	}{
		{"ssh-ed25519", "", ED25519, Ed25519, ed25519.PrivateKey{}},
		{"ssh-ed25519-encrypted", sshFixturePassphrase, ED25519, Ed25519, ed25519.PrivateKey{}},
		{"ssh-ecdsa", "", ECDSA, EcdsaSha2nistP256, &ecdsa.PrivateKey{}},
		{"ssh-rsa", "", RSA, RsaPkcs1v15, &rsa.PrivateKey{}},
	} {
		t.Run(tc.file, func(t *testing.T) {
			t.Parallel()
			k, err := ParseSSHPrivateKey(readTestdata(t, tc.file), []byte(tc.passphrase))
			require.NoError(t, err)
			require.Equal(t, SSH, k.GetType())
			require.Equal(t, tc.scheme, k.GetScheme())
			require.NotNil(t, k.GetKey())
			require.Nil(t, k.GetNotBefore())
			require.Nil(t, k.GetNotAfter())

			// The underlying key is available as a plain key.
			priv, err := k.PrivateKey()
			require.NoError(t, err)
			require.Equal(t, tc.keyType, priv.Type)
			require.Equal(t, tc.scheme, priv.Scheme)
			require.IsType(t, tc.stdKey, priv.Key)
			require.Equal(t, priv.Data, k.GetData())
			reparsed, err := parsePrivateKeyBytes([]byte(priv.Data))
			require.NoError(t, err)
			require.Equal(t, tc.keyType, reparsed.Type)

			// The public half is identified by the SSH fingerprint.
			pub, err := k.PublicKey()
			require.NoError(t, err)
			require.Equal(t, k.Fingerprint(), pub.ID())
			require.Equal(t, k.Fingerprint(), k.SSHPublicKey().Fingerprint())
		})
	}
}

// The private key fixtures match the public ones.
func TestParseSSHPrivateKey_MatchesPublic(t *testing.T) {
	t.Parallel()
	pub, err := ParseSSHPublicKey(readTestdata(t, "ssh-ed25519.pub"))
	require.NoError(t, err)

	plain, err := ParseSSHPrivateKey(readTestdata(t, "ssh-ed25519"), nil)
	require.NoError(t, err)
	require.Equal(t, pub.Fingerprint(), plain.Fingerprint())

	encrypted, err := ParseSSHPrivateKey(readTestdata(t, "ssh-ed25519-encrypted"), []byte(sshFixturePassphrase))
	require.NoError(t, err)
	require.Equal(t, pub.Fingerprint(), encrypted.Fingerprint())
}

func TestParseSSHPrivateKey_Errors(t *testing.T) {
	t.Parallel()

	_, err := ParseSSHPrivateKey(readTestdata(t, "ssh-ed25519-encrypted"), nil)
	require.ErrorContains(t, err, "passphrase is required")

	_, err = ParseSSHPrivateKey(readTestdata(t, "ssh-ed25519-encrypted"), []byte("wrong"))
	require.Error(t, err)

	_, err = ParseSSHPrivateKey([]byte("not a key"), nil)
	require.Error(t, err)

	// Private keys in other PEM formats are plain keys, even though the
	// ssh package can read them.
	plain, err := NewGenerator().GenerateKeyPair()
	require.NoError(t, err)
	_, err = ParseSSHPrivateKey([]byte(plain.Data), nil)
	require.ErrorContains(t, err, "OpenSSH format")
}

// The parser recognizes SSH keys next to the other formats.
func TestParser_SSH(t *testing.T) {
	t.Parallel()
	parser := NewParser()

	t.Run("public key provider", func(t *testing.T) {
		t.Parallel()
		prov, err := parser.ParsePublicKeyProvider(readTestdata(t, "ssh-ed25519.pub"))
		require.NoError(t, err)
		sshKey, ok := prov.(*SSHPublic)
		require.True(t, ok, "expected *SSHPublic, got %T", prov)
		require.Equal(t, sshEd25519Fingerprint, sshKey.Fingerprint())
	})

	t.Run("public key", func(t *testing.T) {
		t.Parallel()
		pub, err := parser.ParsePublicKey(readTestdata(t, "ssh-ed25519.pub"))
		require.NoError(t, err)
		require.Equal(t, ED25519, pub.Type)
		require.Equal(t, sshEd25519Fingerprint, pub.ID())
	})

	t.Run("private key provider", func(t *testing.T) {
		t.Parallel()
		prov, err := parser.ParsePrivateKeyProvider(readTestdata(t, "ssh-ed25519"))
		require.NoError(t, err)
		sshKey, ok := prov.(*SSHPrivate)
		require.True(t, ok, "expected *SSHPrivate, got %T", prov)
		require.Equal(t, sshEd25519Fingerprint, sshKey.Fingerprint())
	})

	t.Run("encrypted private key provider", func(t *testing.T) {
		t.Parallel()
		prov, err := parser.ParsePrivateKeyProvider(
			readTestdata(t, "ssh-ed25519-encrypted"), WithPassphrase(sshFixturePassphrase),
		)
		require.NoError(t, err)
		require.IsType(t, &SSHPrivate{}, prov)

		_, err = parser.ParsePrivateKeyProvider(readTestdata(t, "ssh-ed25519-encrypted"))
		require.ErrorContains(t, err, "passphrase is required")
	})

	// The other formats still parse as what they were.
	t.Run("other formats unchanged", func(t *testing.T) {
		t.Parallel()
		prov, err := parser.ParsePublicKeyProvider(readTestdata(t, "gpg-ecdsa-public.asc"))
		require.NoError(t, err)
		require.IsType(t, &GPGPublic{}, prov)

		plain, err := NewGenerator().GenerateKeyPair()
		require.NoError(t, err)
		privProv, err := parser.ParsePrivateKeyProvider([]byte(plain.Data))
		require.NoError(t, err)
		require.IsType(t, &Private{}, privProv)

		plainPub, err := plain.PublicKey()
		require.NoError(t, err)
		pubProv, err := parser.ParsePublicKeyProvider([]byte(plainPub.Data))
		require.NoError(t, err)
		require.IsType(t, &Public{}, pubProv)
	})
}

// An SSH key signs through the key signer and verifies through the key
// verifier, in the SSH signature format.
func TestSSH_SignVerify(t *testing.T) {
	t.Parallel()
	message := []byte("a message to sign")

	for _, file := range []string{"ssh-ed25519", "ssh-ecdsa", "ssh-rsa"} {
		t.Run(file, func(t *testing.T) {
			t.Parallel()
			priv, err := ParseSSHPrivateKey(readTestdata(t, file), nil)
			require.NoError(t, err)
			pub, err := ParseSSHPublicKey(readTestdata(t, file+".pub"))
			require.NoError(t, err)

			sigBytes, err := NewSigner().SignMessage(priv, message)
			require.NoError(t, err)

			// The signature is a binary SSH signature under the default
			// namespace.
			sig, err := sshsig.Parse(sigBytes)
			require.NoError(t, err)
			require.Equal(t, DefaultSSHNamespace, sig.Namespace)
			require.Equal(t, sig.Marshal(), sigBytes)

			ok, err := NewVerifier().VerifyMessage(pub, message, sigBytes)
			require.NoError(t, err)
			require.True(t, ok)

			// The armored form verifies too.
			ok, err = NewVerifier().VerifyMessage(pub, message, sig.Armor())
			require.NoError(t, err)
			require.True(t, ok)

			ok, err = NewVerifier().VerifyMessage(pub, []byte("another message"), sigBytes)
			require.NoError(t, err)
			require.False(t, ok)
		})
	}
}

// The namespace is the signer's choice, and the verifier takes whatever
// namespace the signature declares.
func TestSSH_Namespace(t *testing.T) {
	t.Parallel()
	message := []byte("a message to sign")
	priv, err := ParseSSHPrivateKey(readTestdata(t, "ssh-ed25519"), nil)
	require.NoError(t, err)
	priv.Namespace = "git"

	sigBytes, err := priv.SignMessage(message)
	require.NoError(t, err)
	sig, err := sshsig.Parse(sigBytes)
	require.NoError(t, err)
	require.Equal(t, "git", sig.Namespace)

	ok, err := priv.SSHPublicKey().VerifyMessage(message, sigBytes)
	require.NoError(t, err)
	require.True(t, ok)
}

// The parser sets the namespace SSH keys sign under. Other keys ignore
// it.
func TestParser_SSHNamespace(t *testing.T) {
	t.Parallel()
	parser := NewParser()
	message := []byte("a message to sign")

	namespaceOf := func(prov PrivateKeyProvider) string {
		sigBytes, err := NewSigner().SignMessage(prov, message)
		require.NoError(t, err)
		sig, err := sshsig.Parse(sigBytes)
		require.NoError(t, err)
		return sig.Namespace
	}

	prov, err := parser.ParsePrivateKeyProvider(readTestdata(t, "ssh-ed25519"))
	require.NoError(t, err)
	require.Equal(t, DefaultSSHNamespace, namespaceOf(prov))

	prov, err = parser.ParsePrivateKeyProvider(readTestdata(t, "ssh-ed25519"), WithSSHNamespace("git"))
	require.NoError(t, err)
	require.Equal(t, "git", namespaceOf(prov))

	// An empty namespace is the default one.
	prov, err = parser.ParsePrivateKeyProvider(readTestdata(t, "ssh-ed25519"), WithSSHNamespace(""))
	require.NoError(t, err)
	require.Equal(t, DefaultSSHNamespace, namespaceOf(prov))

	plain, err := NewGenerator().GenerateKeyPair()
	require.NoError(t, err)
	prov, err = parser.ParsePrivateKeyProvider([]byte(plain.Data), WithSSHNamespace("git"))
	require.NoError(t, err)
	require.IsType(t, &Private{}, prov)
}

// A signature made by ssh-keygen verifies through the parser and the key
// verifier.
func TestSSH_FixtureVerify(t *testing.T) {
	t.Parallel()
	prov, err := NewParser().ParsePublicKeyProvider(readTestdata(t, "ssh-ed25519.pub"))
	require.NoError(t, err)

	ok, err := NewVerifier().VerifyMessage(prov, readTestdata(t, "message.txt"), readTestdata(t, "ssh-message.sig"))
	require.NoError(t, err)
	require.True(t, ok)
}

// An SSH key only verifies SSH signatures made by itself. Anything else
// does not verify, and is not an error: an envelope can carry signatures
// from several keys in several formats.
func TestSSH_VerifyRejects(t *testing.T) {
	t.Parallel()
	message := []byte("a message to sign")
	priv, err := ParseSSHPrivateKey(readTestdata(t, "ssh-ed25519"), nil)
	require.NoError(t, err)
	pub := priv.SSHPublicKey()
	other, err := ParseSSHPublicKey(readTestdata(t, "ssh-ecdsa.pub"))
	require.NoError(t, err)

	sshSig, err := priv.SignMessage(message)
	require.NoError(t, err)

	// A bare signature made with the same key material, outside the SSH
	// signature format.
	plain, err := priv.PrivateKey()
	require.NoError(t, err)
	bareSig, err := NewSigner().SignMessage(plain, message)
	require.NoError(t, err)
	plainPub, err := plain.PublicKey()
	require.NoError(t, err)
	ok, err := NewVerifier().VerifyMessage(plainPub, message, bareSig)
	require.NoError(t, err)
	require.True(t, ok, "the bare signature is valid for the plain key")

	for name, tc := range map[string]struct {
		key *SSHPublic
		sig []byte
	}{
		"signature of another key": {other, sshSig},
		"bare signature":           {pub, bareSig},
		"GPG signature":            {pub, readTestdata(t, "message.sig")},
		"garbage":                  {pub, []byte("garbage")},
		"empty":                    {pub, nil},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ok, err := NewVerifier().VerifyMessage(tc.key, message, tc.sig)
			require.NoError(t, err)
			require.False(t, ok)
		})
	}

	// And the SSH signature does not verify as a bare signature of the
	// plain key.
	ok, err = NewVerifier().VerifyMessage(plainPub, message, sshSig)
	require.NoError(t, err)
	require.False(t, ok)
}

// Keys written by the ssh package (not ssh-keygen) parse too, encrypted
// or not.
func TestParseSSHPrivateKey_Generated(t *testing.T) {
	t.Parallel()
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	block, err := ssh.MarshalPrivateKey(edKey, "comment")
	require.NoError(t, err)
	k, err := ParseSSHPrivateKey(pem.EncodeToMemory(block), nil)
	require.NoError(t, err)
	require.Equal(t, Ed25519, k.GetScheme())

	block, err = ssh.MarshalPrivateKeyWithPassphrase(edKey, "comment", []byte("secret"))
	require.NoError(t, err)
	encrypted, err := ParseSSHPrivateKey(pem.EncodeToMemory(block), []byte("secret"))
	require.NoError(t, err)
	require.Equal(t, k.Fingerprint(), encrypted.Fingerprint())
}
