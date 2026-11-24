// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

func NewSigner() *Signer {
	return &Signer{}
}

type Signer struct{}

// SignMessage signs a supplied message
func (s *Signer) SignMessage(keyProvider PrivateKeyProvider, message []byte) ([]byte, error) {
	// Providers with a signature format of their own (OpenPGP entities,
	// for example) sign the message themselves. This dispatches before
	// extracting the raw key material so the provider keeps its full
	// context.
	if ms, ok := keyProvider.(MessageSigner); ok {
		return ms.SignMessage(message)
	}

	key, err := keyProvider.PrivateKey()
	if err != nil {
		return nil, fmt.Errorf("getting private key: %w", err)
	}

	if key.Type == ED25519 {
		edk, ok := key.Key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("unable to cast crypto crypto key to ED25519")
		}
		return ed25519.Sign(edk, message), nil
	}

	if key.HashType == 0 && key.Type != ED25519 {
		return nil, fmt.Errorf("unable to hash message, no hasher defined in key")
	}

	hasher := key.HashType.New()
	if _, err := hasher.Write(message); err != nil {
		return nil, fmt.Errorf("writing to hasher: %w", err)
	}

	return s.SignDigest(key, hasher.Sum(nil))
}

// SignDigestString signs a digest in hex string representation
func (s *Signer) SignDigestString(keyProvider PrivateKeyProvider, digestString string) ([]byte, error) {
	digest, err := hex.DecodeString(digestString)
	if err != nil {
		return nil, fmt.Errorf("decoding digest string: %w", err)
	}
	return s.SignDigest(keyProvider, digest)
}

// SignDigest signs the digest byte sequence using the key obtained from a key provider
func (s *Signer) SignDigest(keyProvider PrivateKeyProvider, digest []byte) ([]byte, error) {
	pkey, err := keyProvider.PrivateKey()
	if err != nil {
		return nil, fmt.Errorf("getting provate key: %w", err)
	}

	var sig []byte
	switch k := pkey.Key.(type) {
	case *ecdsa.PrivateKey:
		sig, err = ecdsa.SignASN1(rand.Reader, k, digest)
		if err != nil {
			return nil, fmt.Errorf("error signing with ECDSA key: %w", err)
		}
	case *rsa.PrivateKey:
		// Perhaps we should force PSS on shorter keys
		if strings.HasPrefix(string(pkey.Scheme), "rsassa-pss") {
			sig, err = rsa.SignPSS(rand.Reader, k, pkey.HashType, digest, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash, // for fips 140
				Hash:       pkey.HashType,
			})
		} else {
			sig, err = rsa.SignPKCS1v15(rand.Reader, k, pkey.HashType, digest)
		}
		if err != nil {
			return nil, fmt.Errorf("error signing with %s key: %w", pkey.Scheme, err)
		}
	case ed25519.PrivateKey:
		return nil, errors.New("digest signing not supported in ed25519")
	default:
		return nil, errors.New("unsupported key for signing")
	}
	return sig, nil
}
