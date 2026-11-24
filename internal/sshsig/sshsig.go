// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package sshsig reads, writes and verifies SSH signatures in the SSHSIG
// format, the one `ssh-keygen -Y sign` produces.
//
// An SSH signature is not a bare signature over the message. It is a
// small structure that carries the signer's public key, a namespace, the
// hash algorithm applied to the message and the signature itself. The
// key does not sign the message directly either: it signs a wrapper that
// repeats the namespace and the hash algorithm next to the hash of the
// message.
//
// The format is described in the PROTOCOL.sshsig document of OpenSSH.
package sshsig

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

const (
	// DefaultNamespace is the namespace given to signatures when the
	// caller does not choose one. It is the one ssh-keygen users reach
	// for when signing files.
	DefaultNamespace = "file"

	// magic opens both the signature structure and the data the key
	// signs.
	magic = "SSHSIG"

	// sigVersion is the only version of the format.
	sigVersion = 1

	armorType  = "SSH SIGNATURE"
	armorBegin = "-----BEGIN " + armorType + "-----"
	armorEnd   = "-----END " + armorType + "-----"

	// armorWidth is the line length ssh-keygen wraps the armor at.
	armorWidth = 70
)

// HashAlgorithm names the hash applied to the message before signing.
type HashAlgorithm string

const (
	SHA256 HashAlgorithm = "sha256"
	SHA512 HashAlgorithm = "sha512"
)

var (
	// ErrKeyMismatch is returned by Verify when the signature was made
	// by a key other than the one it is checked against.
	ErrKeyMismatch = errors.New("signature was made by a different key")

	// ErrCertificate is returned when a signature or a signer carries an
	// SSH certificate. Certificates are not supported.
	ErrCertificate = errors.New("SSH certificates are not supported")
)

// Signature is an SSH signature.
type Signature struct {
	// PublicKey is the key the signature claims to be made with. The
	// signature carries it, so it says nothing about who signed until
	// Verify checks it against a key the caller trusts.
	PublicKey ssh.PublicKey

	// Namespace is the purpose the signer declared for the signature.
	Namespace string

	// HashAlgorithm is the hash applied to the message.
	HashAlgorithm HashAlgorithm

	// reserved is a field the format keeps for future use. It is part
	// of the signed data, so it is kept as read.
	reserved string

	signature *ssh.Signature
}

// wireSignature is the signature structure as encoded, after the magic
// preamble.
type wireSignature struct {
	Version       uint32
	PublicKey     []byte
	Namespace     string
	Reserved      string
	HashAlgorithm string
	Signature     []byte
}

// wireSignedData is the data the key signs, after the magic preamble.
type wireSignedData struct {
	Namespace     string
	Reserved      string
	HashAlgorithm string
	Hash          []byte
}

// Sign signs message with signer under the given namespace. The message
// is hashed with SHA-512.
//
// RSA keys sign with rsa-sha2-512. The signer of an RSA key has to
// implement ssh.AlgorithmSigner, as the default RSA signature is made
// over SHA-1.
func Sign(signer ssh.Signer, namespace string, message []byte) (*Signature, error) {
	if signer == nil {
		return nil, errors.New("no signer")
	}
	if namespace == "" {
		return nil, errors.New("namespace is empty")
	}
	pub := signer.PublicKey()
	if err := CheckKey(pub); err != nil {
		return nil, err
	}

	sig := &Signature{
		PublicKey:     pub,
		Namespace:     namespace,
		HashAlgorithm: SHA512,
	}
	data, err := sig.signedData(message)
	if err != nil {
		return nil, err
	}

	if pub.Type() == ssh.KeyAlgoRSA {
		as, ok := signer.(ssh.AlgorithmSigner)
		if !ok {
			return nil, errors.New("RSA signer cannot sign with rsa-sha2-512")
		}
		sig.signature, err = as.SignWithAlgorithm(rand.Reader, data, ssh.KeyAlgoRSASHA512)
	} else {
		sig.signature, err = signer.Sign(rand.Reader, data)
	}
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	return sig, nil
}

// Parse reads a signature, armored or binary.
//
// Parse checks the structure of the signature, not its validity: use
// Verify for that.
func Parse(data []byte) (*Signature, error) {
	if trimmed := bytes.TrimSpace(data); bytes.HasPrefix(trimmed, []byte("-----BEGIN")) {
		block, rest := pem.Decode(trimmed)
		if block == nil || block.Type != armorType {
			return nil, errors.New("not an armored SSH signature")
		}
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, errors.New("data after the armored SSH signature")
		}
		data = block.Bytes
	}

	body, ok := bytes.CutPrefix(data, []byte(magic))
	if !ok {
		return nil, errors.New("not an SSH signature")
	}

	var wire wireSignature
	if err := ssh.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("decoding SSH signature: %w", err)
	}
	if wire.Version != sigVersion {
		return nil, fmt.Errorf("unsupported SSH signature version %d", wire.Version)
	}
	if wire.Namespace == "" {
		return nil, errors.New("SSH signature has no namespace")
	}

	sig := &Signature{
		Namespace:     wire.Namespace,
		HashAlgorithm: HashAlgorithm(wire.HashAlgorithm),
		reserved:      wire.Reserved,
		signature:     &ssh.Signature{},
	}
	if _, err := sig.HashAlgorithm.sum(nil); err != nil {
		return nil, err
	}

	pub, err := ssh.ParsePublicKey(wire.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parsing the public key of the SSH signature: %w", err)
	}
	if err := CheckKey(pub); err != nil {
		return nil, err
	}
	sig.PublicKey = pub

	if err := ssh.Unmarshal(wire.Signature, sig.signature); err != nil {
		return nil, fmt.Errorf("decoding the signature of the SSH signature: %w", err)
	}
	return sig, nil
}

// Marshal returns the signature in its binary form.
func (s *Signature) Marshal() []byte {
	wire := wireSignature{
		Version:       sigVersion,
		PublicKey:     s.PublicKey.Marshal(),
		Namespace:     s.Namespace,
		Reserved:      s.reserved,
		HashAlgorithm: string(s.HashAlgorithm),
		Signature:     ssh.Marshal(s.signature),
	}
	return append([]byte(magic), ssh.Marshal(wire)...)
}

// Armor returns the signature in its armored form, the one ssh-keygen
// writes to .sig files.
func (s *Signature) Armor() []byte {
	encoded := base64.StdEncoding.EncodeToString(s.Marshal())

	var buf bytes.Buffer
	buf.WriteString(armorBegin + "\n")
	for encoded != "" {
		n := min(armorWidth, len(encoded))
		buf.WriteString(encoded[:n] + "\n")
		encoded = encoded[n:]
	}
	buf.WriteString(armorEnd + "\n")
	return buf.Bytes()
}

// Verify checks that the signature is a valid signature of message made
// by key.
//
// The namespace is not checked: the signature is verified under the
// namespace it declares, which callers can read from Namespace.
//
// When the signature was made by another key Verify returns
// ErrKeyMismatch.
func (s *Signature) Verify(key ssh.PublicKey, message []byte) error {
	if key == nil {
		return errors.New("no public key to verify against")
	}
	if err := CheckKey(key); err != nil {
		return err
	}
	if !bytes.Equal(key.Marshal(), s.PublicKey.Marshal()) {
		return ErrKeyMismatch
	}

	// RSA keys can produce SHA-1 signatures (the ssh-rsa format), which
	// the ssh package still verifies.
	if key.Type() == ssh.KeyAlgoRSA {
		switch s.signature.Format {
		case ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512:
		default:
			return fmt.Errorf("RSA signature format %q is not accepted", s.signature.Format)
		}
	}

	data, err := s.signedData(message)
	if err != nil {
		return err
	}
	if err := key.Verify(data, s.signature); err != nil {
		return fmt.Errorf("verifying SSH signature: %w", err)
	}
	return nil
}

// signedData builds the data the key signs for message.
func (s *Signature) signedData(message []byte) ([]byte, error) {
	hash, err := s.HashAlgorithm.sum(message)
	if err != nil {
		return nil, err
	}
	wire := wireSignedData{
		Namespace:     s.Namespace,
		Reserved:      s.reserved,
		HashAlgorithm: string(s.HashAlgorithm),
		Hash:          hash,
	}
	return append([]byte(magic), ssh.Marshal(wire)...), nil
}

// sum hashes message.
func (h HashAlgorithm) sum(message []byte) ([]byte, error) {
	switch h {
	case SHA256:
		sum := sha256.Sum256(message)
		return sum[:], nil
	case SHA512:
		sum := sha512.Sum512(message)
		return sum[:], nil
	default:
		return nil, fmt.Errorf("unsupported SSH signature hash algorithm %q", string(h))
	}
}

// CheckKey reports whether key is of a kind whose signatures are supported.
// Certificates are not, and are reported with ErrCertificate.
func CheckKey(key ssh.PublicKey) error {
	if _, ok := key.(*ssh.Certificate); ok {
		return ErrCertificate
	}
	switch key.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoSKED25519,
		ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoSKECDSA256,
		ssh.KeyAlgoRSA:
		return nil
	default:
		return fmt.Errorf("unsupported SSH key type %q", key.Type())
	}
}
