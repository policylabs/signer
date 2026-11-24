// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

type Verifier struct{}

func NewVerifier() *Verifier {
	return &Verifier{}
}

// VerificationResult captures the key verification result
type VerificationResult struct {
	Keys     []*Public
	Time     time.Time
	Digest   map[string]string
	Verified bool
}

// VerifyMessage verifies the signature by getting the whole message
func (v *Verifier) VerifyMessage(pkeyProv PublicKeyProvider, message, signature []byte) (bool, error) {
	// Providers with a signature format of their own (OpenPGP entities,
	// for example) are verified exclusively by the provider. We
	// intentionally do not fall through to raw crypto verification on
	// the underlying key material, as that would skip the rules the
	// format enforces.
	if mv, ok := pkeyProv.(MessageVerifier); ok {
		return mv.VerifyMessage(message, signature)
	}

	pubKey, err := pkeyProv.PublicKey()
	if err != nil {
		return false, fmt.Errorf("getting public key: %w", err)
	}
	switch pubKey.Type {
	case ECDSA:
		h := pubKey.HashType.New()
		if _, err := h.Write(message); err != nil {
			return false, fmt.Errorf("writing message to hasher: %w", err)
		}
		return verifyECDSA(pubKey, h.Sum(nil), signature)
	case RSA:
		h := pubKey.HashType.New()
		if _, err := h.Write(message); err != nil {
			return false, fmt.Errorf("writing message to hasher: %w", err)
		}
		return verifyRSA(pubKey, h.Sum(nil), signature)
	case ED25519:
		return verifyEd25519Message(pubKey, message, signature)
	case GPG, SSH:
		return false, fmt.Errorf("%s keys must be extracted to their underlying type before verification", pubKey.Type)
	default:
		// *dsa.PublicKey is deprectated, we don't support it.
		return false, fmt.Errorf("unsupported key type: %T", pubKey)
	}
}

// VerifyDigestString verifies the signature from a digest string. The
// provided string must be a hex encoded string of a hash produced by
// algorithm defined in the public key abstraction.
func (v *Verifier) VerifyDigestString(pkeyProv PublicKeyProvider, digestString string, signature []byte) (bool, error) {
	pubKey, err := pkeyProv.PublicKey()
	if err != nil {
		return false, fmt.Errorf("getting public key: %w", err)
	}
	digest, err := hex.DecodeString(digestString)
	if err != nil {
		return false, fmt.Errorf("decoding digest: %w", err)
	}

	return v.VerifyDigest(pubKey, digest, signature)
}

// VerifyDigest checks a sigest signature against a digest byte slice
func (v *Verifier) VerifyDigest(pkeyProv PublicKeyProvider, digest, signature []byte) (bool, error) {
	pubKey, err := pkeyProv.PublicKey()
	if err != nil {
		return false, fmt.Errorf("getting public key: %w", err)
	}
	switch pubKey.Type {
	case ECDSA:
		return verifyECDSA(pubKey, digest, signature)
	case RSA:
		return verifyRSA(pubKey, digest, signature)
	case ED25519:
		return false, errors.New("cannot verify ed25519 signatures from hash")
	case GPG, SSH:
		return false, fmt.Errorf("%s keys must be extracted to their underlying type before verification", pubKey.Type)
	default:
		// *dsa.PublicKey is deprectated, we don't support it. Also ecdh keys
		return false, fmt.Errorf("unsupported key type: %T", pubKey)
	}
}

type signatureValues struct {
	R, S *big.Int
}

// verifyRSA verifies RSA using PSS
func verifyRSA(pubKey *Public, digest, signature []byte) (bool, error) {
	rsaKey, ok := pubKey.Key.(*rsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("unable to verify, key is not an RSA key")
	}

	// If it's not a PSS key, try PKCS1v15 first
	if !strings.HasPrefix(string(pubKey.Scheme), "rsassa-pss") {
		if err := rsa.VerifyPKCS1v15(rsaKey, pubKey.HashType, digest, signature); err == nil {
			return true, nil
		}
	}

	// Try PSS verification
	pssOptions := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       pubKey.HashType,
	}

	if err := rsa.VerifyPSS(rsaKey, pubKey.HashType, digest, signature, pssOptions); err != nil {
		if errors.Is(err, rsa.ErrVerification) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// verifyECDSA verifies a digest signed with an ECDSA key.
func verifyECDSA(pubKey *Public, digest, signature []byte) (bool, error) {
	ecdsaKey, ok := pubKey.Key.(*ecdsa.PublicKey)
	if !ok {
		return false, errors.New("unable to verify, key is not an ECDSA public key")
	}

	// Ensure the curves match the algorithms as per FIPS 186-4
	curveErr := errors.New("invalid curve in public key")
	//nolint:exhaustive // Not all hashes in the world apply :)
	switch pubKey.HashType {
	case crypto.SHA224:
		if pubKey.Curve() != elliptic.P224().Params().Name { // "P-224"
			return false, curveErr
		}
	case crypto.SHA256:
		if pubKey.Curve() != elliptic.P256().Params().Name { // "P-256"
			return false, curveErr
		}
	case crypto.SHA384:
		if pubKey.Curve() != elliptic.P384().Params().Name { // "P-384"
			return false, curveErr
		}
	case crypto.SHA512:
		if pubKey.Curve() != elliptic.P521().Params().Name { // "P-521"
			return false, curveErr
		}
	default:
		return false, fmt.Errorf("unsupported ECDSA configuration: curve %s with hash %v", pubKey.Curve(), pubKey.HashType)
	}

	// Try DER/ASN.1 encoding first, fall back to raw/IEEE P1363 (R||S).
	var sig signatureValues
	if _, err := asn1.Unmarshal(signature, &sig); err != nil {
		// Raw P1363: R and S are zero-padded to equal length and concatenated.
		n := len(signature)
		if n == 0 || n%2 != 0 {
			// Neither encoding: the signature is malformed. That is a
			// property of the signature under verification, not of the
			// key, so it is a negative result rather than an error.
			return false, nil
		}
		half := n / 2
		sig.R = new(big.Int).SetBytes(signature[:half])
		sig.S = new(big.Int).SetBytes(signature[half:])
	}

	// Verify the signature
	return ecdsa.Verify(ecdsaKey, digest, sig.R, sig.S), nil
}

// verifyEd25519 verifies an Ed25519 signature
func verifyEd25519Message(pubKey *Public, message, signature []byte) (bool, error) {
	edKey, ok := pubKey.Key.(ed25519.PublicKey)
	if !ok {
		return false, fmt.Errorf("unable to verify, key is not an ed25519 public key")
	}
	// A signature of the wrong size cannot be an ed25519 signature over
	// anything: a negative result, not an error.
	if len(signature) != ed25519.SignatureSize {
		return false, nil
	}

	// Key must be 32 bytes, always
	if len(edKey) != ed25519.PublicKeySize {
		return false, errors.New("invalid ed25519 key length")
	}

	// Verify the signature (Ed25519 doesn't require separate hashing)
	return ed25519.Verify(edKey, message, signature), nil
}
