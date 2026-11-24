// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func NewParser() *Parser {
	return &Parser{}
}

type Parser struct{}

type KeyParseOptions struct {
	Scheme Scheme
	// Passphrase decrypts encrypted GPG and SSH private keys. Plain-text
	// PEM private keys ignore this field. Empty + encrypted key + parser
	// invocation is an error.
	Passphrase string
	// SSHNamespace is the namespace of the signatures made with SSH
	// private keys. Keys of other formats ignore this field. When empty,
	// SSH keys sign under DefaultSSHNamespace.
	SSHNamespace string
}

type FnOpt func(*KeyParseOptions)

// WithScheme defines a scheme for a key.
func WithScheme(scheme Scheme) FnOpt {
	return func(kpo *KeyParseOptions) {
		kpo.Scheme = scheme
	}
}

// WithPassphrase supplies a passphrase used to decrypt encrypted
// private keys (GPG-armored and OpenSSH encrypted keys).
func WithPassphrase(passphrase string) FnOpt {
	return func(kpo *KeyParseOptions) {
		kpo.Passphrase = passphrase
	}
}

// WithSSHNamespace sets the namespace of the signatures made with SSH
// private keys. The namespace is a label the signer chooses to say what
// a signature is for; SSH keys sign under DefaultSSHNamespace unless
// told otherwise. Keys of other formats ignore it.
func WithSSHNamespace(namespace string) FnOpt {
	return func(kpo *KeyParseOptions) {
		kpo.SSHNamespace = namespace
	}
}

// ParsePublicKey parses a public key that can be used to verify.
// It supports PEM-encoded keys (RSA, ECDSA, ED25519), SSH keys in the
// authorized_keys format and GPG keys (ASCII-armored or binary). For SSH
// and GPG keys the underlying crypto public key is extracted and
// returned as a *Public.
func (p *Parser) ParsePublicKey(pubKeyData []byte, funcs ...FnOpt) (*Public, error) {
	opts := KeyParseOptions{}
	for _, f := range funcs {
		f(&opts)
	}

	// Try PEM first
	k, pemErr := parseKeyBytes(pubKeyData)
	if pemErr != nil {
		// Then SSH, then GPG (ASCII-armored or binary)
		var provider PublicKeyProvider
		if sshKey, sshErr := ParseSSHPublicKey(pubKeyData); sshErr == nil {
			provider = sshKey
		} else if gpgKeys, gpgErr := ParseGPGPublicKey(pubKeyData); gpgErr == nil && len(gpgKeys) > 0 {
			provider = gpgKeys[0]
		} else {
			return nil, fmt.Errorf("parsing public key: %w", pemErr)
		}
		var err error
		k, err = provider.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("extracting public key from key data: %w", err)
		}
	}

	if opts.Scheme != "" {
		if err := k.SetScheme(opts.Scheme); err != nil {
			return nil, fmt.Errorf("setting key scheme: %w", err)
		}
	}
	return k, nil
}

// ParsePublicKeyProvider parses public key data and returns a PublicKeyProvider.
// It supports PEM-encoded keys (RSA, ECDSA, ED25519), SSH keys in the
// authorized_keys format and GPG keys (ASCII-armored or binary). For PEM keys
// the returned provider is a *Public; for SSH keys it is an *SSHPublic, which
// verifies SSH signatures; for GPG keys it is a *GPGPublic which preserves the
// full OpenPGP metadata.
func (p *Parser) ParsePublicKeyProvider(pubKeyData []byte, funcs ...FnOpt) (PublicKeyProvider, error) {
	opts := KeyParseOptions{}
	for _, f := range funcs {
		f(&opts)
	}

	// Try PEM first
	k, pemErr := parseKeyBytes(pubKeyData)
	if pemErr == nil {
		if opts.Scheme != "" {
			if err := k.SetScheme(opts.Scheme); err != nil {
				return nil, fmt.Errorf("setting key scheme: %w", err)
			}
		}
		return k, nil
	}

	// Try SSH (an authorized_keys line)
	if sshKey, sshErr := ParseSSHPublicKey(pubKeyData); sshErr == nil {
		return sshKey, nil
	}

	// Try GPG (ASCII-armored or binary)
	gpgKeys, gpgErr := ParseGPGPublicKey(pubKeyData)
	if gpgErr == nil && len(gpgKeys) > 0 {
		return gpgKeys[0], nil
	}

	// None worked, return the PEM error as it's the most common format
	return nil, fmt.Errorf("parsing public key: %w", pemErr)
}

// ParsePrivateKeyProvider parses private key data and returns a
// PrivateKeyProvider. Supports:
//
//   - PEM-encoded PKCS#8, PKCS#1 (RSA), and SEC1 (EC) private keys.
//     Returned as *Private.
//   - OpenPGP private keys (ASCII-armored or binary), encrypted or
//     plain. Encrypted keys require WithPassphrase. Returned as
//     *GPGPrivate to preserve OpenPGP entity metadata.
//   - Private keys in the OpenSSH format (the one ssh-keygen writes),
//     encrypted or plain. Encrypted keys require WithPassphrase.
//     Returned as *SSHPrivate, which makes SSH signatures.
//
// Tries OpenPGP first because GPG armored data is also valid PEM in
// some sense; the GPG parser correctly rejects non-OpenPGP PEM input
// and we fall back to PEM parsing.
func (p *Parser) ParsePrivateKeyProvider(privKeyData []byte, funcs ...FnOpt) (PrivateKeyProvider, error) {
	opts := KeyParseOptions{}
	for _, f := range funcs {
		f(&opts)
	}

	// Try OpenPGP first.
	gpgKeys, gpgErr := ParseGPGPrivateKey(privKeyData, []byte(opts.Passphrase))
	if gpgErr == nil && len(gpgKeys) > 0 {
		return gpgKeys[0], nil
	}

	// Then the OpenSSH format. It is a PEM block the PEM parser below
	// does not read, so its errors are reported as they are.
	if isOpenSSHPrivateKey(privKeyData) {
		sshKey, err := ParseSSHPrivateKey(privKeyData, []byte(opts.Passphrase))
		if err != nil {
			return nil, fmt.Errorf("parsing private key: %w", err)
		}
		sshKey.Namespace = opts.SSHNamespace
		return sshKey, nil
	}

	// Fall back to PEM private-key formats.
	priv, pemErr := parsePrivateKeyBytes(privKeyData)
	if pemErr != nil {
		// Surface the PEM error as the primary diagnostic — that's
		// the dominant format. The GPG attempt is best-effort.
		return nil, fmt.Errorf("parsing private key: %w", pemErr)
	}

	if opts.Scheme != "" {
		priv.Scheme = opts.Scheme
	}
	return priv, nil
}

// parsePrivateKeyBytes parses a PEM-encoded private key. Supports
// PKCS#8 ("PRIVATE KEY" or "ENCRYPTED PRIVATE KEY"), PKCS#1
// ("RSA PRIVATE KEY"), and SEC1 ("EC PRIVATE KEY") blocks. Infers
// Type, Scheme, and HashType from the parsed crypto key, mirroring
// parseKeyBytes' public-key inference.
func parsePrivateKeyBytes(privKeyData []byte) (*Private, error) {
	blk, _ := pem.Decode(privKeyData)
	if blk == nil || blk.Bytes == nil {
		return nil, errors.New("unable to decode PEM block from private key data")
	}

	var (
		raw any
		err error
	)
	switch blk.Type {
	case "PRIVATE KEY":
		raw, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
	case "RSA PRIVATE KEY":
		raw, err = x509.ParsePKCS1PrivateKey(blk.Bytes)
	case "EC PRIVATE KEY":
		raw, err = x509.ParseECPrivateKey(blk.Bytes)
	default:
		// Best-effort: attempt PKCS#8 for unknown headers — a
		// caller-generated armoring with a non-canonical Type still
		// often contains PKCS#8 inside.
		raw, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unsupported PEM block type %q for private key", blk.Type)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("parsing PEM private key (%s): %w", blk.Type, err)
	}

	priv := &Private{
		Data: string(privKeyData),
		Key:  raw,
	}
	switch pk := raw.(type) {
	case *rsa.PrivateKey:
		priv.Type = RSA
		priv.HashType = crypto.SHA256
		priv.Scheme = RsaPkcs1v15
	case *ecdsa.PrivateKey:
		priv.Type = ECDSA
		switch pk.Curve.Params().Name {
		case elliptic.P224().Params().Name:
			priv.HashType = crypto.SHA224
			priv.Scheme = EcdsaSha2nistP224
		case elliptic.P256().Params().Name:
			priv.HashType = crypto.SHA256
			priv.Scheme = EcdsaSha2nistP256
		case elliptic.P384().Params().Name:
			priv.HashType = crypto.SHA384
			priv.Scheme = EcdsaSha2nistP384
		case elliptic.P521().Params().Name:
			priv.HashType = crypto.SHA512
			priv.Scheme = EcdsaSha2nistP521
		}
	case ed25519.PrivateKey:
		priv.Type = ED25519
		priv.Scheme = Ed25519
	default:
		return nil, fmt.Errorf("unsupported private key type %T", raw)
	}
	return priv, nil
}

// parseKeyBytes is the parser function. It's a helper to expose it to tests.
func parseKeyBytes(pubKeyData []byte) (*Public, error) {
	blk, _ := pem.Decode(pubKeyData)
	if blk == nil || blk.Bytes == nil {
		return nil, errors.New("unable to decode key from data")
	}

	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key from PEM data: %w", err)
	}

	k := &Public{
		Data: string(pubKeyData),
		Key:  pub,
	}

	switch ik := pub.(type) {
	case *rsa.PublicKey:
		k.Type = RSA
		// Default to PKCS1v15 with SHA-256 for RSA keys. Without a HashType
		// the verifier panics when computing the message digest. We use
		// PKCS1v15 rather than PSS as the default because cosign and most
		// tooling sign with PKCS1v15. The verifier tries PKCS1v15 first
		// for non-PSS schemes, then falls back to PSS.
		k.HashType = crypto.SHA256
		k.Scheme = RsaPkcs1v15
	case *ecdsa.PublicKey:
		k.Type = ECDSA
		// We can infer the hash type from the elliptic curve in use. If it does
		// not match, verifications will not match but they would be insecure anyway
		switch ik.Curve.Params().Name {
		case elliptic.P224().Params().Name: // "P-256"
			k.HashType = crypto.SHA224
			k.Scheme = EcdsaSha2nistP224
		case elliptic.P256().Params().Name: // "P-256"
			k.HashType = crypto.SHA256
			k.Scheme = EcdsaSha2nistP256
		case elliptic.P384().Params().Name: // "P-384"
			k.HashType = crypto.SHA384
			k.Scheme = EcdsaSha2nistP384
		case elliptic.P521().Params().Name: // P-521
			k.HashType = crypto.SHA512
			k.Scheme = EcdsaSha2nistP521
		}
	case ed25519.PublicKey:
		k.Type = ED25519

	default:
		return nil, fmt.Errorf("unsupported key type: %T", pub)
	}

	return k, nil
}
