// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

var (
	ErrUnknownScheme          = errors.New("unknown key scheme")
	ErrIncorrectKeySchema     = errors.New("unable to set key scheme, incorrect key type")
	ErrIncorrectEllipticCurve = errors.New("schema curve does not match key")
	ErrUnknownEllipticCurve   = errors.New("unsupported elliptic curve")
)

type (
	Scheme            string
	Type              string
	PublicKeyProvider interface {
		PublicKey() (*Public, error)
	}
)

const (
	RSA     Type = "rsa"
	ECDSA   Type = "ecdsa"
	ED25519 Type = "ed25519"
	GPG     Type = "gpg"
	SSH     Type = "ssh"

	RsaPkcs1v15         Scheme = "rsassa-pkcs1v15"
	RsaSsaPssSha256     Scheme = "rsassa-pss-sha256"
	RsaSsaPssSha384     Scheme = "rsassa-pss-sha384"
	RsaSsaPssSha512     Scheme = "rsassa-pss-sha512"
	EcdsaSha2nistP224   Scheme = "ecdsa-sha2-nistp224"
	EcdsaSha2nistP256   Scheme = "ecdsa-sha2-nistp256"
	EcdsaSha2nistP384   Scheme = "ecdsa-sha2-nistp384"
	EcdsaSha2nistP521   Scheme = "ecdsa-sha2-nistp521"
	EcdsaSha256nistP256 Scheme = "ecdsa-sha256-nistp256"
	EcdsaSha384nistP384 Scheme = "ecdsa-sha384-nistp384"
	Ed25519             Scheme = "ed25519"

	pemTypePublicKey = "PUBLIC KEY"
)

// Public key abstracts a public key data and all its features required to
// verify. After parsing, the original key data is preserved in the srtuct.
type Public struct {
	Type      Type
	Scheme    Scheme
	HashType  crypto.Hash
	Data      string
	Key       crypto.PublicKey
	NotBefore *time.Time `json:"not_before"`
	NotAfter  *time.Time `json:"not_after"`

	// SigningKeyFingerprint is the fingerprint of the specific key that
	// produced a verified signature.
	// This is meant for GPG entities as it may differ from ID(). When a
	// signature was made with a subkey:
	//
	//  - ID() returns the primary (identity) fingerprint
	//  - This field returns the actual signer key.
	//
	// Only populated on entries in VerificationResult.Keys after a
	// successful verification. It is emptu on general-purpose Public keys.
	SigningKeyFingerprint string `json:"signing_key_fingerprint,omitempty"`

	// overrideID, when set, is returned by ID() instead of computing
	// an identifier from the key material. This is used to preserve
	// the GPG fingerprint when converting from GPGPublic.
	overrideID string
}

// ID computes a key id by hashing the key data and triming it to the first bytes
func (p *Public) ID() string {
	if p.overrideID != "" {
		return p.overrideID
	}
	var hash [32]byte
	switch pubKey := p.Key.(type) {
	case *rsa.PublicKey:
		hash = sha256.Sum256(pubKey.N.Bytes())
	case *ecdsa.PublicKey:
		coords, err := ecdsaKeyIDBytes(pubKey)
		if err != nil {
			return ""
		}
		hash = sha256.Sum256(coords)
	case ed25519.PublicKey:
		hash = sha256.Sum256(pubKey)
	default:
		return ""
	}
	return hex.EncodeToString(hash[:8])
}

// ecdsaKeyIDBytes returns the bytes hashed to compute the ID of an ECDSA
// public key: the X and Y coordinates, each stripped of leading zero bytes,
// concatenated. This is the historical big.Int encoding of the coordinates
// and must not change, as key IDs are pinned in policies.
func ecdsaKeyIDBytes(pub *ecdsa.PublicKey) ([]byte, error) {
	// SEC 1 uncompressed point: 0x04 || X || Y, X and Y fixed-width.
	point, err := pub.Bytes()
	if err != nil {
		return nil, err
	}
	coords := point[1:]
	half := len(coords) / 2
	x := bytes.TrimLeft(coords[:half], "\x00")
	y := bytes.TrimLeft(coords[half:], "\x00")
	return slices.Concat(x, y), nil
}

// SetScheme sets the scheme string in the key, verifying consistency and defining
// some features of the key.
func (p *Public) SetScheme(scheme Scheme) error {
	if scheme == "" {
		return fmt.Errorf("scheme string is empty")
	}

	// Ed25519 has no hashes or curves
	if scheme == Ed25519 {
		return nil
	}

	switch {
	case scheme == RsaPkcs1v15:
		if p.Type != RSA {
			return ErrIncorrectKeySchema
		}
	case strings.HasPrefix(string(scheme), "rsassa-pss"):
		if p.Type != RSA {
			return ErrIncorrectKeySchema
		}

		switch strings.TrimPrefix(string(scheme), "rsassa-pss-") {
		case "sha256":
			p.HashType = crypto.SHA256
		case "sha384":
			p.HashType = crypto.SHA384
		case "sha512":
			p.HashType = crypto.SHA512
		default:
			return ErrUnknownScheme
		}
	case strings.HasPrefix(string(scheme), "ecdsa-sha2-"):
		if p.Type != ECDSA {
			return ErrIncorrectKeySchema
		}

		switch p.Curve() {
		case elliptic.P224().Params().Name: // "P-224"
			if scheme != EcdsaSha2nistP224 {
				return ErrIncorrectEllipticCurve
			}
			p.HashType = crypto.SHA224
		case elliptic.P256().Params().Name: // "P-256"
			if scheme != EcdsaSha2nistP256 {
				return ErrIncorrectEllipticCurve
			}
			p.HashType = crypto.SHA256
		case elliptic.P384().Params().Name: // "P-384"
			if scheme != EcdsaSha2nistP384 {
				return ErrIncorrectEllipticCurve
			}
			p.HashType = crypto.SHA384
		case elliptic.P521().Params().Name: // P-521
			if scheme != EcdsaSha2nistP521 {
				return ErrIncorrectEllipticCurve
			}
			p.HashType = crypto.SHA512
		default:
			return ErrUnknownEllipticCurve
		}
	default:
		return ErrUnknownScheme
	}

	p.Scheme = scheme
	return nil
}

// Curve returns the nist name of elliptic curve used in the key. If it cannot
// be read or the key is not an elliptic curve key then this function returns an
// empty string.
func (p *Public) Curve() string {
	if p.Type != ECDSA {
		return ""
	}

	if k, ok := p.Key.(*ecdsa.PublicKey); ok {
		return k.Curve.Params().Name
	}

	return ""
}

// Public is the most basic public key provider. It just returns itself
func (p *Public) PublicKey() (*Public, error) {
	return p, nil
}
