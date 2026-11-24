// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sshsig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

var testMessage = []byte("a message to sign")

// testSigners returns one freshly generated signer per supported kind of
// key.
func testSigners(t *testing.T) map[string]ssh.Signer {
	t.Helper()

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signers := map[string]ssh.Signer{}
	for name, k := range map[string]any{
		"ed25519": edKey, "ecdsa-p256": p256Key, "ecdsa-p384": p384Key, "rsa": rsaKey,
	} {
		signer, err := ssh.NewSignerFromKey(k)
		require.NoError(t, err)
		signers[name] = signer
	}
	return signers
}

func readPublicKey(t *testing.T, name string) ssh.PublicKey {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data) //nolint:dogsled // only the key matters
	require.NoError(t, err)
	return pub
}

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return data
}

// A signature verifies against the key that made it, and survives both
// encodings.
func TestSignVerify(t *testing.T) {
	t.Parallel()
	for name, signer := range testSigners(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			sig, err := Sign(signer, DefaultNamespace, testMessage)
			require.NoError(t, err)
			require.Equal(t, DefaultNamespace, sig.Namespace)
			require.Equal(t, SHA512, sig.HashAlgorithm)
			require.NoError(t, sig.Verify(signer.PublicKey(), testMessage))

			for encoding, data := range map[string][]byte{"binary": sig.Marshal(), "armored": sig.Armor()} {
				parsed, err := Parse(data)
				require.NoError(t, err, encoding)
				require.Equal(t, sig.Namespace, parsed.Namespace, encoding)
				require.Equal(t, sig.HashAlgorithm, parsed.HashAlgorithm, encoding)
				require.Equal(t, signer.PublicKey().Marshal(), parsed.PublicKey.Marshal(), encoding)
				require.NoError(t, parsed.Verify(signer.PublicKey(), testMessage), encoding)
				require.Equal(t, sig.Marshal(), parsed.Marshal(), encoding)
			}
		})
	}
}

// The namespace is the signer's choice and is verified as declared.
func TestSignNamespace(t *testing.T) {
	t.Parallel()
	signer := testSigners(t)["ed25519"]

	sig, err := Sign(signer, "git", testMessage)
	require.NoError(t, err)
	parsed, err := Parse(sig.Marshal())
	require.NoError(t, err)
	require.Equal(t, "git", parsed.Namespace)
	require.NoError(t, parsed.Verify(signer.PublicKey(), testMessage))

	_, err = Sign(signer, "", testMessage)
	require.Error(t, err)
}

func TestVerifyFailures(t *testing.T) {
	t.Parallel()
	signers := testSigners(t)
	signer := signers["ed25519"]
	sig, err := Sign(signer, DefaultNamespace, testMessage)
	require.NoError(t, err)

	t.Run("other message", func(t *testing.T) {
		t.Parallel()
		err := sig.Verify(signer.PublicKey(), []byte("another message"))
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrKeyMismatch)
	})

	t.Run("other key", func(t *testing.T) {
		t.Parallel()
		require.ErrorIs(t, sig.Verify(signers["ecdsa-p256"].PublicKey(), testMessage), ErrKeyMismatch)
	})

	t.Run("no key", func(t *testing.T) {
		t.Parallel()
		require.Error(t, sig.Verify(nil, testMessage))
	})

	// The namespace, the reserved field and the hash algorithm are part
	// of what the key signs: changing any of them breaks the signature.
	t.Run("changed namespace", func(t *testing.T) {
		t.Parallel()
		changed := *sig
		changed.Namespace = "git"
		require.Error(t, changed.Verify(signer.PublicKey(), testMessage))
	})

	t.Run("changed reserved", func(t *testing.T) {
		t.Parallel()
		changed := *sig
		changed.reserved = "x"
		require.Error(t, changed.Verify(signer.PublicKey(), testMessage))
	})

	t.Run("changed hash algorithm", func(t *testing.T) {
		t.Parallel()
		changed := *sig
		changed.HashAlgorithm = SHA256
		require.Error(t, changed.Verify(signer.PublicKey(), testMessage))
	})
}

// RSA keys sign with SHA-2. A SHA-1 signature (the ssh-rsa format) is
// rejected even though it is cryptographically valid.
func TestRSASHA1Rejected(t *testing.T) {
	t.Parallel()
	signer := testSigners(t)["rsa"]

	sig, err := Sign(signer, DefaultNamespace, testMessage)
	require.NoError(t, err)
	require.Equal(t, ssh.KeyAlgoRSASHA512, sig.signature.Format)

	data, err := sig.signedData(testMessage)
	require.NoError(t, err)
	sha1Sig, err := signer.Sign(rand.Reader, data)
	require.NoError(t, err)
	require.Equal(t, ssh.KeyAlgoRSA, sha1Sig.Format)
	require.NoError(t, signer.PublicKey().Verify(data, sha1Sig), "the SHA-1 signature itself is valid")

	weak := *sig
	weak.signature = sha1Sig
	require.ErrorContains(t, weak.Verify(signer.PublicKey(), testMessage), "not accepted")
}

// Certificates are refused when signing and when parsing.
func TestCertificatesRejected(t *testing.T) {
	t.Parallel()
	signers := testSigners(t)
	ca, signer := signers["ecdsa-p256"], signers["ed25519"]

	cert := &ssh.Certificate{
		Key:             signer.PublicKey(),
		CertType:        ssh.UserCert,
		KeyId:           "test",
		ValidPrincipals: []string{"someone"},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	require.NoError(t, cert.SignCert(rand.Reader, ca))
	certSigner, err := ssh.NewCertSigner(cert, signer)
	require.NoError(t, err)

	_, err = Sign(certSigner, DefaultNamespace, testMessage)
	require.ErrorIs(t, err, ErrCertificate)

	sig, err := Sign(signer, DefaultNamespace, testMessage)
	require.NoError(t, err)
	withCert := *sig
	withCert.PublicKey = cert
	_, err = Parse(withCert.Marshal())
	require.ErrorIs(t, err, ErrCertificate)

	require.ErrorIs(t, sig.Verify(cert, testMessage), ErrCertificate)
}

func TestParseErrors(t *testing.T) {
	t.Parallel()
	signer := testSigners(t)["ed25519"]
	sig, err := Sign(signer, DefaultNamespace, testMessage)
	require.NoError(t, err)

	// encode builds a binary signature from sig with some fields changed.
	encode := func(change func(*wireSignature)) []byte {
		wire := wireSignature{
			Version:       sigVersion,
			PublicKey:     sig.PublicKey.Marshal(),
			Namespace:     sig.Namespace,
			HashAlgorithm: string(sig.HashAlgorithm),
			Signature:     ssh.Marshal(sig.signature),
		}
		change(&wire)
		return append([]byte(magic), ssh.Marshal(wire)...)
	}

	for name, data := range map[string][]byte{
		"empty":            nil,
		"not a signature":  []byte("hello"),
		"magic only":       []byte(magic),
		"truncated":        sig.Marshal()[:40],
		"trailing data":    append(sig.Marshal(), 0),
		"version 2":        encode(func(w *wireSignature) { w.Version = 2 }),
		"no namespace":     encode(func(w *wireSignature) { w.Namespace = "" }),
		"unknown hash":     encode(func(w *wireSignature) { w.HashAlgorithm = "md5" }),
		"bad public key":   encode(func(w *wireSignature) { w.PublicKey = []byte("nope") }),
		"bad signature":    encode(func(w *wireSignature) { w.Signature = []byte{1} }),
		"other armor":      []byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"),
		"broken armor":     []byte(armorBegin + "\n!!!\n" + armorEnd + "\n"),
		"data after armor": append(sig.Armor(), []byte("more")...),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse(data)
			require.Error(t, err)
		})
	}

	// Whitespace around the armor is fine.
	_, err = Parse(append([]byte("\n  "), append(sig.Armor(), '\n', '\n')...))
	require.NoError(t, err)
}

// Signatures made by ssh-keygen verify. See testdata/README.md for how
// the fixtures were produced.
func TestVerifySSHKeygenFixtures(t *testing.T) {
	t.Parallel()
	message := readFile(t, "message.txt")

	for _, tc := range []struct {
		sig, key, namespace string
		hash                HashAlgorithm
	}{
		{"ed25519.sig", "ed25519.pub", "file", SHA512},
		{"ecdsa-p256.sig", "ecdsa-p256.pub", "file", SHA512},
		{"ecdsa-p384.sig", "ecdsa-p384.pub", "file", SHA512},
		{"rsa.sig", "rsa.pub", "file", SHA512},
		{"ed25519-sha256-custom.sig", "ed25519.pub", "custom@example.com", SHA256},
	} {
		t.Run(tc.sig, func(t *testing.T) {
			t.Parallel()
			sig, err := Parse(readFile(t, tc.sig))
			require.NoError(t, err)
			require.Equal(t, tc.namespace, sig.Namespace)
			require.Equal(t, tc.hash, sig.HashAlgorithm)
			require.NoError(t, sig.Verify(readPublicKey(t, tc.key), message))

			// The subtests share message: the altered one has to be a copy.
			altered := slices.Concat(message, []byte("!"))
			require.Error(t, sig.Verify(readPublicKey(t, tc.key), altered))
			require.ErrorIs(t, sig.Verify(readPublicKey(t, "gittuf-app.pub"), message), ErrKeyMismatch)

			// Our armor is byte for byte the one ssh-keygen wrote.
			require.Equal(t, string(readFile(t, tc.sig)), string(sig.Armor()))
		})
	}
}

// A DSSE envelope signed by a third party verifies: an approval recorded
// by the gittuf GitHub app, signed over the DSSE PAE under the "git"
// namespace.
func TestVerifyGittufFixture(t *testing.T) {
	t.Parallel()
	var envelope struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Signatures  []struct {
			Sig string `json:"sig"`
		} `json:"signatures"`
	}
	require.NoError(t, json.Unmarshal(readFile(t, "gittuf-approval.dsse.json"), &envelope))
	require.Len(t, envelope.Signatures, 1)

	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	require.NoError(t, err)
	pae := fmt.Appendf(nil, "DSSEv1 %d %s %d %s", len(envelope.PayloadType), envelope.PayloadType, len(payload), payload)

	rawSig, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
	require.NoError(t, err)
	sig, err := Parse(rawSig)
	require.NoError(t, err)
	require.Equal(t, "git", sig.Namespace)
	require.Equal(t, SHA512, sig.HashAlgorithm)

	key := readPublicKey(t, "gittuf-app.pub")
	require.Equal(t, "SHA256:KTrCAHHGUSCkNjanR0t4ojOiHQ4qZIQM6mkwX64b2KY", ssh.FingerprintSHA256(key))
	require.NoError(t, sig.Verify(key, pae))
	require.Error(t, sig.Verify(key, payload), "the signature covers the PAE, not the bare payload")
}

// ssh-keygen accepts the signatures we make, and applies its own
// namespace check to them.
func TestSSHKeygenVerifiesOurSignatures(t *testing.T) {
	t.Parallel()
	sshKeygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}

	for name, signer := range testSigners(t) {
		for _, namespace := range []string{DefaultNamespace, "git"} {
			t.Run(name+"/"+namespace, func(t *testing.T) {
				t.Parallel()
				sig, err := Sign(signer, namespace, testMessage)
				require.NoError(t, err)

				dir := t.TempDir()
				allowed := filepath.Join(dir, "allowed_signers")
				sigFile := filepath.Join(dir, "message.sig")
				line := append([]byte("signer "), ssh.MarshalAuthorizedKey(signer.PublicKey())...)
				require.NoError(t, os.WriteFile(allowed, line, 0o600))
				require.NoError(t, os.WriteFile(sigFile, sig.Armor(), 0o600))

				verify := func(ns string, message []byte) error {
					cmd := exec.CommandContext( //nolint:gosec // fixed binary, test-controlled arguments
						t.Context(), sshKeygen, "-Y", "verify", "-f", allowed, "-I", "signer", "-n", ns, "-s", sigFile,
					)
					cmd.Stdin = bytes.NewReader(message)
					out, err := cmd.CombinedOutput()
					if err != nil {
						return fmt.Errorf("%w: %s", err, out)
					}
					return nil
				}

				require.NoError(t, verify(namespace, testMessage))
				require.Error(t, verify(namespace, []byte("another message")))
				require.Error(t, verify("other", testMessage))
			})
		}
	}
}
