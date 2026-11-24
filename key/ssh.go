// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"crypto"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/policylabs/signer/internal/sshsig"
)

// SSH keys sign in the SSH signature format (the one `ssh-keygen -Y
// sign` produces), not with bare cryptographic signatures. An SSH
// signature carries a namespace, a label the signer chooses to say what
// the signature is for.
//
// Signatures are verified under whatever namespace they declare: the
// namespace is never compared to an expected value.

// DefaultSSHNamespace is the namespace of the signatures made with an
// SSH key when no other is set.
const DefaultSSHNamespace = sshsig.DefaultNamespace

// SSHPublic wraps an SSH public key. It implements the Key,
// PublicKeyProvider and MessageVerifier interfaces.
type SSHPublic struct {
	key     ssh.PublicKey
	comment string
}

// GetType returns the SSH key type.
func (s *SSHPublic) GetType() Type { return SSH }

// GetScheme returns the scheme of the underlying key.
func (s *SSHPublic) GetScheme() Scheme {
	_, scheme, _, _ := s.underlyingKeyInfo() //nolint:errcheck,dogsled // zero values acceptable on error
	return scheme
}

// GetHashType returns the hash type of the underlying key.
func (s *SSHPublic) GetHashType() crypto.Hash {
	_, _, hash, _ := s.underlyingKeyInfo() //nolint:errcheck,dogsled // zero values acceptable on error
	return hash
}

// GetData returns the key as an authorized_keys line: the key type, the
// base64-encoded key and the comment when there is one.
func (s *SSHPublic) GetData() string {
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.key)))
	if s.comment != "" {
		line += " " + s.comment
	}
	return line
}

// GetKey returns the underlying crypto.PublicKey.
func (s *SSHPublic) GetKey() crypto.PublicKey {
	pub, err := sshPublicKeyToStdlib(s.key)
	if err != nil {
		return nil
	}
	return pub
}

// GetNotBefore returns nil: SSH keys carry no validity period.
func (s *SSHPublic) GetNotBefore() *time.Time { return nil }

// GetNotAfter returns nil: SSH keys carry no validity period.
func (s *SSHPublic) GetNotAfter() *time.Time { return nil }

// PublicKey extracts the underlying crypto public key and returns it as
// a *Public. Its ID is the SSH fingerprint of the key.
func (s *SSHPublic) PublicKey() (*Public, error) {
	stdPub, err := sshPublicKeyToStdlib(s.key)
	if err != nil {
		return nil, err
	}

	keyType, scheme, hash, err := cryptoKeyToTypeSchemeHash(stdPub)
	if err != nil {
		return nil, fmt.Errorf("mapping SSH key to type/scheme: %w", err)
	}

	pubKeyData, err := marshalCryptoPublicKey(stdPub)
	if err != nil {
		return nil, fmt.Errorf("marshaling underlying public key: %w", err)
	}

	return &Public{
		Type:       keyType,
		Scheme:     scheme,
		HashType:   hash,
		Data:       string(pubKeyData),
		Key:        stdPub,
		overrideID: s.Fingerprint(),
	}, nil
}

// Fingerprint returns the SHA-256 fingerprint of the key the way OpenSSH
// prints it: "SHA256:" followed by the unpadded base64 of the hash. The
// fingerprint is case-sensitive.
func (s *SSHPublic) Fingerprint() string {
	return ssh.FingerprintSHA256(s.key)
}

// Comment returns the comment that came with the key, usually a name or
// an email address. Nothing vouches for it: it is not part of the key
// and must not be used to identify the signer.
func (s *SSHPublic) Comment() string {
	return s.comment
}

// SSHPublicKey returns the underlying ssh.PublicKey.
func (s *SSHPublic) SSHPublicKey() ssh.PublicKey {
	return s.key
}

// VerifyMessage reports whether signature is an SSH signature of message
// made by this key. The signature can be armored or binary. It
// implements MessageVerifier.
//
// A signature made by another key, or one that is not an SSH signature
// at all, is not an error: it simply does not verify.
func (s *SSHPublic) VerifyMessage(message, signature []byte) (bool, error) {
	sig, err := sshsig.Parse(signature)
	if err != nil {
		return false, nil //nolint:nilerr // not a signature this key can check
	}
	if err := sig.Verify(s.key, message); err != nil {
		return false, nil //nolint:nilerr // the signature does not verify
	}
	return true, nil
}

// SignatureNamespace returns the namespace an SSH signature declares. It
// implements SignatureNamespacer.
//
// The namespace is read from the signature as it is: it says nothing
// about the signature being valid, which VerifyMessage checks.
func (s *SSHPublic) SignatureNamespace(signature []byte) (string, error) {
	sig, err := sshsig.Parse(signature)
	if err != nil {
		return "", fmt.Errorf("parsing SSH signature: %w", err)
	}
	return sig.Namespace, nil
}

// underlyingKeyInfo returns the type, scheme and hash of the underlying key.
func (s *SSHPublic) underlyingKeyInfo() (Type, Scheme, crypto.Hash, error) {
	stdPub, err := sshPublicKeyToStdlib(s.key)
	if err != nil {
		return "", "", 0, err
	}
	return cryptoKeyToTypeSchemeHash(stdPub)
}

// SSHPrivate wraps an SSH private key. It implements the Key,
// PublicKeyProvider, PrivateKeyProvider and MessageSigner interfaces.
//
// The key material may not be at hand: keys held by an SSH agent (see
// SSHAgentKey) sign and tell their public half, but PrivateKey returns
// an error for them.
type SSHPrivate struct {
	// Namespace is the namespace of the signatures the key makes. When
	// empty, DefaultSSHNamespace is used.
	Namespace string

	signer ssh.Signer

	// raw is the underlying crypto private key. It is nil when the key
	// is held somewhere else, as the keys of an SSH agent are.
	raw crypto.PrivateKey
}

// GetType returns the SSH key type.
func (s *SSHPrivate) GetType() Type { return SSH }

// GetScheme returns the scheme of the underlying key.
func (s *SSHPrivate) GetScheme() Scheme { return s.SSHPublicKey().GetScheme() }

// GetHashType returns the hash type of the underlying key.
func (s *SSHPrivate) GetHashType() crypto.Hash { return s.SSHPublicKey().GetHashType() }

// GetData returns the underlying private key PEM-encoded as PKCS #8, or
// an empty string if it cannot be encoded.
func (s *SSHPrivate) GetData() string {
	priv, err := s.PrivateKey()
	if err != nil {
		return ""
	}
	return priv.Data
}

// GetKey returns the underlying crypto.PublicKey.
func (s *SSHPrivate) GetKey() crypto.PublicKey { return s.SSHPublicKey().GetKey() }

// GetNotBefore returns nil: SSH keys carry no validity period.
func (s *SSHPrivate) GetNotBefore() *time.Time { return nil }

// GetNotAfter returns nil: SSH keys carry no validity period.
func (s *SSHPrivate) GetNotAfter() *time.Time { return nil }

// PrivateKey extracts the underlying crypto private key and returns it
// as a *Private.
func (s *SSHPrivate) PrivateKey() (*Private, error) {
	if s.raw == nil {
		return nil, errors.New("the private key material of the SSH key is not available")
	}

	keyType, scheme, hash, err := s.SSHPublicKey().underlyingKeyInfo()
	if err != nil {
		return nil, fmt.Errorf("mapping SSH key to type/scheme: %w", err)
	}

	privKeyData, err := marshalPrivateKey(s.raw)
	if err != nil {
		return nil, fmt.Errorf("marshaling underlying private key: %w", err)
	}

	return &Private{
		Type:     keyType,
		Scheme:   scheme,
		HashType: hash,
		Data:     string(privKeyData),
		Key:      s.raw,
	}, nil
}

// PublicKey derives the public key. Its ID is the SSH fingerprint of the
// key.
func (s *SSHPrivate) PublicKey() (*Public, error) {
	return s.SSHPublicKey().PublicKey()
}

// SSHPublicKey returns the public half of the key.
func (s *SSHPrivate) SSHPublicKey() *SSHPublic {
	return &SSHPublic{key: s.signer.PublicKey()}
}

// Fingerprint returns the SHA-256 fingerprint of the key the way OpenSSH
// prints it.
func (s *SSHPrivate) Fingerprint() string {
	return ssh.FingerprintSHA256(s.signer.PublicKey())
}

// SignMessage signs message and returns a binary SSH signature made
// under the key's namespace. It implements MessageSigner.
func (s *SSHPrivate) SignMessage(message []byte) ([]byte, error) {
	namespace := s.Namespace
	if namespace == "" {
		namespace = DefaultSSHNamespace
	}
	sig, err := sshsig.Sign(s.signer, namespace, message)
	if err != nil {
		return nil, fmt.Errorf("signing with SSH key: %w", err)
	}
	return sig.Marshal(), nil
}

// sshPublicKeyToStdlib converts an SSH public key to a standard library
// crypto.PublicKey.
func sshPublicKeyToStdlib(pub ssh.PublicKey) (crypto.PublicKey, error) {
	cpk, ok := pub.(ssh.CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported SSH public key type: %s", pub.Type())
	}
	return cpk.CryptoPublicKey(), nil
}

// newSSHPublic creates an SSHPublic from an ssh.PublicKey, checking that
// the key is of a supported kind.
func newSSHPublic(pub ssh.PublicKey, comment string) (*SSHPublic, error) {
	if err := sshsig.CheckKey(pub); err != nil {
		return nil, err
	}
	return &SSHPublic{key: pub, comment: comment}, nil
}

// newSSHPrivate creates an SSHPrivate from a crypto private key.
func newSSHPrivate(raw crypto.PrivateKey) (*SSHPrivate, error) {
	// The ssh package hands out ed25519 keys as pointers, the rest of
	// this package handles them as values.
	if k, ok := raw.(*ed25519.PrivateKey); ok {
		raw = *k
	}
	signer, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return nil, fmt.Errorf("building SSH signer: %w", err)
	}
	if err := sshsig.CheckKey(signer.PublicKey()); err != nil {
		return nil, err
	}
	return &SSHPrivate{signer: signer, raw: raw}, nil
}

// The SSH providers sign and verify in their own signature format.
var (
	_ MessageSigner       = (*SSHPrivate)(nil)
	_ MessageVerifier     = (*SSHPublic)(nil)
	_ SignatureNamespacer = (*SSHPublic)(nil)
)
