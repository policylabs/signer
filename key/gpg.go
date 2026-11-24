// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	gpgecdsa "github.com/ProtonMail/go-crypto/openpgp/ecdsa"
	gpgeddsa "github.com/ProtonMail/go-crypto/openpgp/eddsa"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// GPGPublic wraps an OpenPGP entity and provides access to its public key material.
// It implements the Key and PublicKeyProvider interfaces.
type GPGPublic struct {
	entity *openpgp.Entity
}

// GetType returns the GPG key type.
func (g *GPGPublic) GetType() Type { return GPG }

// GetScheme returns the scheme of the underlying signing key.
func (g *GPGPublic) GetScheme() Scheme {
	scheme, _, _ := g.underlyingKeyInfo() //nolint:errcheck // zero values acceptable on error
	return scheme
}

// GetHashType returns the hash type of the underlying signing key.
func (g *GPGPublic) GetHashType() crypto.Hash {
	_, hash, _ := g.underlyingKeyInfo() //nolint:errcheck // zero values acceptable on error
	return hash
}

// GetData returns the ASCII-armored representation of the public key.
func (g *GPGPublic) GetData() string {
	var buf bytes.Buffer
	if err := g.Serialize(&buf); err != nil {
		return ""
	}
	return buf.String()
}

// GetKey returns the underlying crypto.PublicKey from the primary signing key.
func (g *GPGPublic) GetKey() crypto.PublicKey {
	sk := signingKey(g.entity)
	stdPub, err := gpgPublicKeyToStdlib(sk.PublicKey.PublicKey)
	if err != nil {
		return nil
	}
	return stdPub
}

// GetNotBefore returns the creation time of the primary key.
func (g *GPGPublic) GetNotBefore() *time.Time {
	t := g.entity.PrimaryKey.CreationTime
	return &t
}

// GetNotAfter returns the expiration time of the primary key, or nil if it doesn't expire.
func (g *GPGPublic) GetNotAfter() *time.Time {
	for _, id := range g.entity.Identities {
		if id.SelfSignature != nil && id.SelfSignature.KeyLifetimeSecs != nil && *id.SelfSignature.KeyLifetimeSecs > 0 {
			exp := g.entity.PrimaryKey.CreationTime.Add(
				time.Duration(*id.SelfSignature.KeyLifetimeSecs) * time.Second,
			)
			return &exp
		}
	}
	return nil
}

// PublicKey extracts the underlying crypto public key and returns it as a *Public.
func (g *GPGPublic) PublicKey() (*Public, error) {
	sk := signingKey(g.entity)

	stdPub, err := gpgPublicKeyToStdlib(sk.PublicKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("converting GPG public key: %w", err)
	}

	keyType, scheme, hash, err := cryptoKeyToTypeSchemeHash(stdPub)
	if err != nil {
		return nil, fmt.Errorf("mapping GPG key to type/scheme: %w", err)
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
		NotBefore:  g.GetNotBefore(),
		NotAfter:   g.GetNotAfter(),
		overrideID: g.Fingerprint(),
	}, nil
}

// Fingerprint returns the hex-encoded fingerprint of the primary key.
func (g *GPGPublic) Fingerprint() string {
	return strings.ToUpper(hex.EncodeToString(g.entity.PrimaryKey.Fingerprint))
}

// KeyID returns the hex-encoded key ID of the primary key.
func (g *GPGPublic) KeyID() string {
	return fmt.Sprintf("%X", g.entity.PrimaryKey.KeyId)
}

// UserIDs returns the user ID strings from the entity.
func (g *GPGPublic) UserIDs() []string {
	ids := make([]string, 0, len(g.entity.Identities))
	for name := range g.entity.Identities {
		ids = append(ids, name)
	}
	return ids
}

// CreationTime returns the creation time of the primary key.
func (g *GPGPublic) CreationTime() time.Time {
	return g.entity.PrimaryKey.CreationTime
}

// Serialize writes the public key in ASCII-armored format.
func (g *GPGPublic) Serialize(w io.Writer) error {
	aw, err := armor.Encode(w, openpgp.PublicKeyType, nil)
	if err != nil {
		return fmt.Errorf("creating armor encoder: %w", err)
	}
	if err := g.entity.Serialize(aw); err != nil {
		aw.Close() //nolint:errcheck,gosec // best effort close
		return fmt.Errorf("serializing entity: %w", err)
	}
	return aw.Close()
}

// SerializeBinary writes the public key in binary OpenPGP format.
func (g *GPGPublic) SerializeBinary(w io.Writer) error {
	return g.entity.Serialize(w)
}

// Entity returns the underlying openpgp.Entity.
func (g *GPGPublic) Entity() *openpgp.Entity {
	return g.entity
}

// SigningKeyFingerprint parses the OpenPGP signature packet and returns the
// hex-encoded fingerprint of the key within this entity that produced the
// signature.
//
// When the signature was made by a subkey, this method returns the subkey's
// fingerprint, which is different from Fingerprint() which always returns the
// primary key's fingerprint.
func (g *GPGPublic) SigningKeyFingerprint(signature []byte) (string, error) {
	// Parse the signature packet
	sig, err := parseSignaturePacket(signature)
	if err != nil {
		return "", fmt.Errorf("parsing signature packet: %w", err)
	}

	if len(sig.IssuerFingerprint) > 0 {
		if bytes.Equal(sig.IssuerFingerprint, g.entity.PrimaryKey.Fingerprint) {
			return strings.ToUpper(hex.EncodeToString(g.entity.PrimaryKey.Fingerprint)), nil
		}
		for _, sk := range g.entity.Subkeys {
			if sk.PublicKey != nil && bytes.Equal(sig.IssuerFingerprint, sk.PublicKey.Fingerprint) {
				return strings.ToUpper(hex.EncodeToString(sk.PublicKey.Fingerprint)), nil
			}
		}
		return "", fmt.Errorf("signature issuer fingerprint %x not found in entity", sig.IssuerFingerprint)
	}

	if sig.IssuerKeyId != nil {
		if g.entity.PrimaryKey.KeyId == *sig.IssuerKeyId {
			return strings.ToUpper(hex.EncodeToString(g.entity.PrimaryKey.Fingerprint)), nil
		}
		for _, sk := range g.entity.Subkeys {
			if sk.PublicKey != nil && sk.PublicKey.KeyId == *sig.IssuerKeyId {
				return strings.ToUpper(hex.EncodeToString(sk.PublicKey.Fingerprint)), nil
			}
		}
		return "", fmt.Errorf("signature issuer key id %016X not found in entity", *sig.IssuerKeyId)
	}

	return "", errors.New("signature has no issuer identifier")
}

// VerifyMessage verifies an OpenPGP detached signature (armored or binary)
// of message against the entity. It implements MessageVerifier.
//
// Verification goes through the openpgp library so that subkey binding
// signatures, key-usage flags and revocation are enforced. Checking the
// signature against the raw primary key material instead would accept
// signatures the entity's self-signatures forbid (a primary-key signature
// on an entity that restricts signing to a subkey, or a signature from a
// revoked or expired subkey).
func (g *GPGPublic) VerifyMessage(message, signature []byte) (bool, error) {
	keyring := openpgp.EntityList{g.entity}

	// Try armored signature first, then binary
	signer, err := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(message), bytes.NewReader(signature), nil)
	if err == nil && signer != nil {
		return true, nil
	}
	signer, err = openpgp.CheckDetachedSignature(keyring, bytes.NewReader(message), bytes.NewReader(signature), nil)
	if err == nil && signer != nil {
		return true, nil
	}

	return false, nil
}

// parseSignaturePacket extracts the first Signature packet from raw bytes,
// handling both ASCII-armored and binary OpenPGP encodings.
func parseSignaturePacket(data []byte) (*packet.Signature, error) {
	var r io.Reader = bytes.NewReader(data)
	if isOpenPGPArmored(data) {
		block, err := armor.Decode(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("decoding ASCII armor: %w", err)
		}
		r = block.Body
	}

	pr := packet.NewReader(r)
	for {
		p, err := pr.Next()
		if errors.Is(err, io.EOF) {
			return nil, errors.New("no signature packet found")
		}
		if err != nil {
			return nil, fmt.Errorf("reading packet: %w", err)
		}
		if sig, ok := p.(*packet.Signature); ok {
			return sig, nil
		}
	}
}

// underlyingKeyInfo returns the scheme and hash for the signing key.
func (g *GPGPublic) underlyingKeyInfo() (Scheme, crypto.Hash, error) {
	sk := signingKey(g.entity)
	stdPub, err := gpgPublicKeyToStdlib(sk.PublicKey.PublicKey)
	if err != nil {
		return "", 0, err
	}
	_, scheme, hash, err := cryptoKeyToTypeSchemeHash(stdPub)
	return scheme, hash, err
}

// GPGPrivate wraps an OpenPGP entity with private key material.
// It implements the Key, PublicKeyProvider, and PrivateKeyProvider interfaces.
type GPGPrivate struct {
	entity *openpgp.Entity
}

// GetType returns the GPG key type.
func (g *GPGPrivate) GetType() Type { return GPG }

// GetScheme returns the scheme of the underlying signing key.
func (g *GPGPrivate) GetScheme() Scheme {
	scheme, _, _ := g.underlyingKeyInfo() //nolint:errcheck // zero values acceptable on error
	return scheme
}

// GetHashType returns the hash type of the underlying signing key.
func (g *GPGPrivate) GetHashType() crypto.Hash {
	_, hash, _ := g.underlyingKeyInfo() //nolint:errcheck // zero values acceptable on error
	return hash
}

// GetData returns the ASCII-armored representation of the private key.
func (g *GPGPrivate) GetData() string {
	var buf bytes.Buffer
	if err := g.Serialize(&buf); err != nil {
		return ""
	}
	return buf.String()
}

// GetKey returns the underlying crypto.PublicKey from the primary signing key.
func (g *GPGPrivate) GetKey() crypto.PublicKey {
	sk := signingKey(g.entity)
	stdPub, err := gpgPublicKeyToStdlib(sk.PublicKey.PublicKey)
	if err != nil {
		return nil
	}
	return stdPub
}

// GetNotBefore returns the creation time of the primary key.
func (g *GPGPrivate) GetNotBefore() *time.Time {
	t := g.entity.PrimaryKey.CreationTime
	return &t
}

// GetNotAfter returns the expiration time of the primary key, or nil if it doesn't expire.
func (g *GPGPrivate) GetNotAfter() *time.Time {
	for _, id := range g.entity.Identities {
		if id.SelfSignature != nil && id.SelfSignature.KeyLifetimeSecs != nil && *id.SelfSignature.KeyLifetimeSecs > 0 {
			exp := g.entity.PrimaryKey.CreationTime.Add(
				time.Duration(*id.SelfSignature.KeyLifetimeSecs) * time.Second,
			)
			return &exp
		}
	}
	return nil
}

// PrivateKey extracts the underlying crypto private key and returns it as a *Private.
func (g *GPGPrivate) PrivateKey() (*Private, error) {
	sk := signingKey(g.entity)

	if sk.PrivateKey == nil {
		return nil, fmt.Errorf("no private key material available")
	}

	if sk.PrivateKey.Encrypted {
		return nil, fmt.Errorf("private key is encrypted, decrypt first")
	}

	stdPriv, err := gpgPrivateKeyToStdlib(sk.PrivateKey.PrivateKey, sk.PublicKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("converting GPG private key: %w", err)
	}

	stdPub, err := gpgPublicKeyToStdlib(sk.PublicKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("converting GPG public key: %w", err)
	}

	keyType, scheme, hash, err := cryptoKeyToTypeSchemeHash(stdPub)
	if err != nil {
		return nil, fmt.Errorf("mapping GPG key to type/scheme: %w", err)
	}

	privKeyData, err := marshalPrivateKey(stdPriv)
	if err != nil {
		return nil, fmt.Errorf("marshaling underlying private key: %w", err)
	}

	return &Private{
		Type:      keyType,
		Scheme:    scheme,
		HashType:  hash,
		Data:      string(privKeyData),
		Key:       stdPriv,
		NotBefore: g.GetNotBefore(),
		NotAfter:  g.GetNotAfter(),
	}, nil
}

// PublicKey derives the public key from the private key entity.
func (g *GPGPrivate) PublicKey() (*Public, error) {
	return g.GPGPublicKey().PublicKey()
}

// GPGPublicKey returns a GPGPublic view of this private key (stripping private material reference).
func (g *GPGPrivate) GPGPublicKey() *GPGPublic {
	return &GPGPublic{entity: g.entity}
}

// SignMessage signs message and returns a binary OpenPGP detached
// signature packet. It implements MessageSigner.
//
// Signing goes through the entity, not the extracted key material, so
// the signing subkey is selected by the openpgp library and the packet
// records which key issued the signature.
func (g *GPGPrivate) SignMessage(message []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := openpgp.DetachSign(&buf, g.entity, bytes.NewReader(message), nil); err != nil {
		return nil, fmt.Errorf("signing with GPG entity: %w", err)
	}
	return buf.Bytes(), nil
}

// Fingerprint returns the hex-encoded fingerprint of the primary key.
func (g *GPGPrivate) Fingerprint() string {
	return strings.ToUpper(hex.EncodeToString(g.entity.PrimaryKey.Fingerprint))
}

// KeyID returns the hex-encoded key ID of the primary key.
func (g *GPGPrivate) KeyID() string {
	return fmt.Sprintf("%X", g.entity.PrimaryKey.KeyId)
}

// UserIDs returns the user ID strings from the entity.
func (g *GPGPrivate) UserIDs() []string {
	ids := make([]string, 0, len(g.entity.Identities))
	for name := range g.entity.Identities {
		ids = append(ids, name)
	}
	return ids
}

// CreationTime returns the creation time of the primary key.
func (g *GPGPrivate) CreationTime() time.Time {
	return g.entity.PrimaryKey.CreationTime
}

// Serialize writes the private key in ASCII-armored format.
func (g *GPGPrivate) Serialize(w io.Writer) error {
	aw, err := armor.Encode(w, openpgp.PrivateKeyType, nil)
	if err != nil {
		return fmt.Errorf("creating armor encoder: %w", err)
	}
	if err := g.entity.SerializePrivate(aw, nil); err != nil {
		aw.Close() //nolint:errcheck,gosec // best effort close
		return fmt.Errorf("serializing private entity: %w", err)
	}
	return aw.Close()
}

// SerializeBinary writes the private key in binary OpenPGP format.
func (g *GPGPrivate) SerializeBinary(w io.Writer) error {
	return g.entity.SerializePrivate(w, nil)
}

// Entity returns the underlying openpgp.Entity.
func (g *GPGPrivate) Entity() *openpgp.Entity {
	return g.entity
}

// underlyingKeyInfo returns the scheme and hash for the signing key.
func (g *GPGPrivate) underlyingKeyInfo() (Scheme, crypto.Hash, error) {
	sk := signingKey(g.entity)
	stdPub, err := gpgPublicKeyToStdlib(sk.PublicKey.PublicKey)
	if err != nil {
		return "", 0, err
	}
	_, scheme, hash, err := cryptoKeyToTypeSchemeHash(stdPub)
	return scheme, hash, err
}

// signingKey selects the best signing key from an OpenPGP entity.
func signingKey(entity *openpgp.Entity) *openpgp.Key {
	sk, ok := entity.SigningKey(time.Now())
	if !ok || sk.PublicKey == nil {
		// Fallback to the primary key
		k := openpgp.Key{
			Entity:    entity,
			PublicKey: entity.PrimaryKey,
		}
		if entity.PrivateKey != nil {
			k.PrivateKey = entity.PrivateKey
		}
		return &k
	}
	return &sk
}

// gpgPublicKeyToStdlib converts a go-crypto public key to a standard library crypto.PublicKey.
// RSA keys are already stdlib types. ECDSA and EdDSA keys need conversion.
func gpgPublicKeyToStdlib(pub any) (crypto.PublicKey, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return k, nil
	case *gpgecdsa.PublicKey:
		curve, err := gpgCurveNameToElliptic(k.GetCurve().GetCurveName())
		if err != nil {
			return nil, err
		}
		// MarshalPoint returns the SEC 1 uncompressed point for NIST curves.
		stdPub, err := ecdsa.ParseUncompressedPublicKey(curve, k.MarshalPoint())
		if err != nil {
			return nil, fmt.Errorf("parsing ECDSA public key: %w", err)
		}
		return stdPub, nil
	case *gpgeddsa.PublicKey:
		if len(k.X) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid ed25519 public key length: %d", len(k.X))
		}
		return ed25519.PublicKey(k.X), nil
	default:
		return nil, fmt.Errorf("unsupported GPG public key type: %T", pub)
	}
}

// gpgPrivateKeyToStdlib converts a go-crypto private key to a standard library crypto.PrivateKey.
func gpgPrivateKeyToStdlib(priv, pub any) (crypto.PrivateKey, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return k, nil
	case *gpgecdsa.PrivateKey:
		stdPub, err := gpgPublicKeyToStdlib(pub)
		if err != nil {
			return nil, err
		}
		ecdsaPub, ok := stdPub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected *ecdsa.PublicKey, got %T", stdPub)
		}
		// ParseRawPrivateKey wants the scalar at the curve's byte length,
		// but go-crypto encodes it without leading zeros. Left-pad it.
		byteLen := (ecdsaPub.Curve.Params().BitSize + 7) / 8
		d := k.MarshalIntegerSecret()
		if len(d) > byteLen {
			return nil, fmt.Errorf("ECDSA private scalar is %d bytes, longer than the curve's %d", len(d), byteLen)
		}
		padded := make([]byte, byteLen)
		copy(padded[byteLen-len(d):], d)
		stdPriv, err := ecdsa.ParseRawPrivateKey(ecdsaPub.Curve, padded)
		if err != nil {
			return nil, fmt.Errorf("parsing ECDSA private key: %w", err)
		}
		if !stdPriv.PublicKey.Equal(ecdsaPub) {
			return nil, errors.New("ECDSA private key does not match its public key")
		}
		return stdPriv, nil
	case *gpgeddsa.PrivateKey:
		if len(k.D) != ed25519.SeedSize {
			return nil, fmt.Errorf("invalid ed25519 seed length: %d", len(k.D))
		}
		return ed25519.NewKeyFromSeed(k.D), nil
	default:
		return nil, fmt.Errorf("unsupported GPG private key type: %T", priv)
	}
}

// gpgCurveNameToElliptic maps a go-crypto curve name to a standard library elliptic.Curve.
func gpgCurveNameToElliptic(name string) (elliptic.Curve, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported ECDSA curve: %s", name)
	}
}

// cryptoKeyToTypeSchemeHash maps a standard library crypto.PublicKey to the corresponding Type, Scheme, and Hash.
func cryptoKeyToTypeSchemeHash(pub crypto.PublicKey) (Type, Scheme, crypto.Hash, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return RSA, RsaPkcs1v15, crypto.SHA256, nil
	case *ecdsa.PublicKey:
		switch k.Curve.Params().Name {
		case elliptic.P224().Params().Name:
			return ECDSA, EcdsaSha2nistP224, crypto.SHA224, nil
		case elliptic.P256().Params().Name:
			return ECDSA, EcdsaSha2nistP256, crypto.SHA256, nil
		case elliptic.P384().Params().Name:
			return ECDSA, EcdsaSha2nistP384, crypto.SHA384, nil
		case elliptic.P521().Params().Name:
			return ECDSA, EcdsaSha2nistP521, crypto.SHA512, nil
		default:
			return "", "", 0, fmt.Errorf("unsupported ECDSA curve: %s", k.Curve.Params().Name)
		}
	case ed25519.PublicKey:
		return ED25519, Ed25519, 0, nil
	case *ed25519.PublicKey:
		return ED25519, Ed25519, 0, nil
	default:
		return "", "", 0, fmt.Errorf("unsupported key type: %T", pub)
	}
}

// marshalCryptoPublicKey marshals a standard library crypto.PublicKey to PEM-encoded bytes.
func marshalCryptoPublicKey(pub crypto.PublicKey) ([]byte, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		der := x509.MarshalPKCS1PublicKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: der}), nil
	case *ecdsa.PublicKey:
		der, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: pemTypePublicKey, Bytes: der}), nil
	case ed25519.PublicKey:
		der, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: pemTypePublicKey, Bytes: der}), nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// newGPGPublic creates a new GPGPublic from an openpgp.Entity.
func newGPGPublic(entity *openpgp.Entity) *GPGPublic {
	return &GPGPublic{entity: entity}
}

// newGPGPrivate creates a new GPGPrivate from an openpgp.Entity with private key material.
func newGPGPrivate(entity *openpgp.Entity) (*GPGPrivate, error) {
	if entity.PrivateKey == nil {
		return nil, fmt.Errorf("entity has no private key material")
	}
	return &GPGPrivate{entity: entity}, nil
}

// The OpenPGP providers sign and verify in their own signature format.
var (
	_ MessageSigner           = (*GPGPrivate)(nil)
	_ MessageVerifier         = (*GPGPublic)(nil)
	_ SigningKeyFingerprinter = (*GPGPublic)(nil)
)
