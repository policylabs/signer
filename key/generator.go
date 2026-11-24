// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func NewGenerator() *Generator {
	return &Generator{}
}

// Generator is a key generator that returns keys wrapped in our key wrappers.
// The key generator supports ECDSA, RSA and ED25519 and some basic options such
// as key length and defininig the elliptic curve to use.
type Generator struct{}

type GenerateOptions struct {
	Type         Type
	Curve        elliptic.Curve
	UseECMarshal bool
	RSAHashType  crypto.Hash
	KeyLength    int
}

// DefaultGenerateOptions default key generation options
var DefaultGenerateOptions = GenerateOptions{
	Type:        ECDSA,
	Curve:       elliptic.P256(),
	RSAHashType: crypto.SHA256,
	KeyLength:   4096,
}

type FnGenOpt func(*GenerateOptions) error

func WithKeyLength(l int) FnGenOpt {
	return func(o *GenerateOptions) error {
		if l < 1024 {
			return fmt.Errorf("invalid key length")
		}
		o.KeyLength = l
		return nil
	}
}

func WithEllipticCurve(cv elliptic.Curve) FnGenOpt {
	return func(o *GenerateOptions) error {
		o.Curve = cv
		return nil
	}
}

func WithKeyType(t Type) FnGenOpt {
	return func(o *GenerateOptions) error {
		o.Type = t
		return nil
	}
}

// GenerateKeyPair creates a new keypair
func (gen *Generator) GenerateKeyPair(funcs ...FnGenOpt) (*Private, error) {
	opts := DefaultGenerateOptions
	for _, f := range funcs {
		if err := f(&opts); err != nil {
			return nil, err
		}
	}

	switch opts.Type {
	case ECDSA:
		var hasher crypto.Hash
		var s Scheme
		switch opts.Curve.Params().Name {
		case elliptic.P224().Params().Name: // "P-256"
			hasher = crypto.SHA224
			s = EcdsaSha2nistP224
		case elliptic.P256().Params().Name: // "P-256"
			hasher = crypto.SHA256
			s = EcdsaSha2nistP256
		case elliptic.P384().Params().Name: // "P-384"
			hasher = crypto.SHA384
			s = EcdsaSha2nistP384
		case elliptic.P521().Params().Name: // P-521
			hasher = crypto.SHA512
			s = EcdsaSha2nistP521
		default:
			return nil, fmt.Errorf("unsupported elliptic curve")
		}

		privateKey, err := ecdsa.GenerateKey(opts.Curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating ECDSA key: %w", err)
		}
		var data []byte
		if opts.UseECMarshal {
			privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
			if err != nil {
				log.Fatal(err)
			}

			data = pem.EncodeToMemory(&pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: privateKeyBytes,
			})
		} else {
			data, err = marshalPrivateKey(privateKey)
			if err != nil {
				return nil, fmt.Errorf("marshaling provate key: %w ", err)
			}
		}

		return &Private{
			Type:     opts.Type,
			Scheme:   s,
			HashType: hasher,
			Data:     string(data),
			Key:      privateKey,
		}, nil

	case RSA:
		var s Scheme
		//nolint:exhaustive // We don't support just any hash
		switch opts.RSAHashType {
		case crypto.SHA256:
			s = RsaSsaPssSha256
		case crypto.SHA384:
			s = RsaSsaPssSha384
		case crypto.SHA512:
			s = RsaSsaPssSha512
		default:
			return nil, fmt.Errorf("unsupported hasher for RSA")
		}
		privateKey, err := rsa.GenerateKey(rand.Reader, opts.KeyLength)
		if err != nil {
			return nil, fmt.Errorf("generating RSA key pair: %w", err)
		}

		privateKeyPEM := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		}
		data := pem.EncodeToMemory(privateKeyPEM)

		return &Private{
			Type:     opts.Type,
			Scheme:   s,
			HashType: opts.RSAHashType,
			Data:     string(data),
			Key:      privateKey,
		}, nil

	case ED25519:
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating ed25519 key pair: %w", err)
		}

		data, err := marshalPrivateKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("marshaling ed25519 key: %w", err)
		}

		return &Private{
			Type:   ED25519,
			Scheme: Ed25519,
			Data:   string(data),
			Key:    privateKey,
		}, nil

	case GPG:
		return nil, fmt.Errorf("GPG key generation not supported, use GenerateGPGKeyPair")

	case SSH:
		return nil, fmt.Errorf("SSH key generation not supported")

	default:
		return nil, fmt.Errorf("key type not supported")
	}
}

// GPGGenerateOptions configures GPG key generation.
type GPGGenerateOptions struct {
	Name    string
	Comment string
	Email   string
	packet.Config
}

// DefaultGPGGenerateOptions provides sensible defaults for GPG key generation.
var DefaultGPGGenerateOptions = GPGGenerateOptions{
	Config: packet.Config{
		Algorithm: packet.PubKeyAlgoEdDSA,
		Curve:     packet.Curve25519,
	},
}

// FnGPGGenOpt is a functional option for GPG key generation.
type FnGPGGenOpt func(*GPGGenerateOptions) error

// WithGPGName sets the user name for the GPG key.
func WithGPGName(name string) FnGPGGenOpt {
	return func(o *GPGGenerateOptions) error {
		o.Name = name
		return nil
	}
}

// WithGPGComment sets the comment for the GPG key.
func WithGPGComment(comment string) FnGPGGenOpt {
	return func(o *GPGGenerateOptions) error {
		o.Comment = comment
		return nil
	}
}

// WithGPGEmail sets the email for the GPG key.
func WithGPGEmail(email string) FnGPGGenOpt {
	return func(o *GPGGenerateOptions) error {
		o.Email = email
		return nil
	}
}

// WithGPGAlgorithm sets the key algorithm (e.g. packet.PubKeyAlgoRSA,
// packet.PubKeyAlgoECDSA, packet.PubKeyAlgoEdDSA).
func WithGPGAlgorithm(algo packet.PublicKeyAlgorithm) FnGPGGenOpt {
	return func(o *GPGGenerateOptions) error {
		o.Algorithm = algo
		return nil
	}
}

// WithGPGCurve sets the elliptic curve for ECDSA/EdDSA keys.
func WithGPGCurve(curve packet.Curve) FnGPGGenOpt {
	return func(o *GPGGenerateOptions) error {
		o.Curve = curve
		return nil
	}
}

// WithGPGRSABits sets the RSA key size in bits.
func WithGPGRSABits(bits int) FnGPGGenOpt {
	return func(o *GPGGenerateOptions) error {
		if bits < 2048 {
			return fmt.Errorf("RSA key size must be at least 2048 bits")
		}
		o.RSABits = bits
		return nil
	}
}

// WithGPGKeyLifetime sets the key expiration in seconds (0 = no expiration).
func WithGPGKeyLifetime(seconds uint32) FnGPGGenOpt {
	return func(o *GPGGenerateOptions) error {
		o.KeyLifetimeSecs = seconds
		return nil
	}
}

// GenerateGPGKeyPair creates a new GPG key pair with the full OpenPGP entity,
// preserving user IDs, self-signatures, and subkeys.
func (gen *Generator) GenerateGPGKeyPair(funcs ...FnGPGGenOpt) (*GPGPrivate, error) {
	opts := DefaultGPGGenerateOptions
	for _, f := range funcs {
		if err := f(&opts); err != nil {
			return nil, err
		}
	}

	entity, err := openpgp.NewEntity(opts.Name, opts.Comment, opts.Email, &opts.Config)
	if err != nil {
		return nil, fmt.Errorf("generating GPG key pair: %w", err)
	}

	return newGPGPrivate(entity)
}
