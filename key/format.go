// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

// Some keys do not produce bare cryptographic signatures: they wrap the
// signature in a format of their own that carries more than the raw
// bytes (an OpenPGP signature packet, for example). Providers of those
// keys implement the interfaces below, and the Signer, the Verifier and
// the DSSE code hand the whole message to them instead of working on the
// underlying key material.

// MessageSigner is implemented by private key providers that sign a
// message in their own signature format.
type MessageSigner interface {
	// SignMessage signs message and returns the signature encoded in
	// the provider's format.
	SignMessage(message []byte) ([]byte, error)
}

// MessageVerifier is implemented by public key providers that verify
// signatures in their own signature format.
//
// Signatures of these providers are only ever checked through
// VerifyMessage, never against the underlying key material, as the
// format can carry rules the raw key knows nothing about.
type MessageVerifier interface {
	// VerifyMessage reports whether signature is a valid signature of
	// message in the provider's format.
	VerifyMessage(message, signature []byte) (bool, error)
}

// SigningKeyFingerprinter is implemented by public key providers that
// can tell which of their keys produced a signature. This matters when
// the provider groups more than one key, as an OpenPGP entity does with
// its subkeys.
type SigningKeyFingerprinter interface {
	// SigningKeyFingerprint returns the fingerprint of the key that
	// produced signature.
	SigningKeyFingerprint(signature []byte) (string, error)
}
