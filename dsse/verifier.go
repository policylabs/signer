// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dsse

import (
	"crypto"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/nozzle/throttler"
	sdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/policylabs/signer/key"
	"github.com/policylabs/signer/options"
)

type Verifier interface {
	RunVerification(*options.Verifier, *key.Verifier, *sdsse.Envelope, []key.PublicKeyProvider) (*key.VerificationResult, error)
	BuildKeyVerifier(*options.Verifier) (*key.Verifier, error)
	OpenEnvelope(string) (*sdsse.Envelope, error)
}

type DefaultVerifier struct{}

// RunVerification verifies the DSSE envelope
func (dv *DefaultVerifier) RunVerification(
	opts *options.Verifier, kv *key.Verifier, env *sdsse.Envelope, keys []key.PublicKeyProvider,
) (*key.VerificationResult, error) {
	if env == nil {
		return nil, fmt.Errorf("")
	}

	if kv == nil {
		return nil, errors.New("did not get a key verifier to check signatures")
	}

	// Extract the public keys up front for efficiency. We keep both the
	// extracted *Public and the original provider so that GPG providers can
	// be routed through the OpenPGP detached-signature path.
	publicKeys := []*key.Public{}
	providers := []key.PublicKeyProvider{}
	for _, provider := range keys {
		pk, err := provider.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("unable to read public key: %w", err)
		}
		publicKeys = append(publicKeys, pk)
		providers = append(providers, provider)
	}

	// Precompute PAE digests for keys that verify via prehash. ED25519 and
	// GPG-wrapped signatures operate on the raw PAE message, so skip them.
	paeMessage := PAEEncode(env)
	digests := map[crypto.Hash][]byte{}
	digestStrs := map[string]string{}
	for _, k := range publicKeys {
		if k.HashType == 0 {
			continue
		}
		if _, ok := digests[k.HashType]; ok {
			continue
		}
		digest, err := hashPayload(env, k.HashType)
		if err != nil {
			return nil, fmt.Errorf("error hashing with %s: %w", k.HashType, err)
		}
		digests[k.HashType] = digest
		digestStrs[k.HashType.String()] = fmt.Sprintf("%x", digest)
	}

	// Build a slice to collect the keys that can verify the
	// signatures, keys that don't match are not reported.
	matchedKeys := []*key.Public{}

	// Got all required data, now verify the sigs in parallel
	var mutex sync.Mutex
	t := throttler.New(4, len(env.GetSignatures())*len(keys))
	for _, sig := range env.GetSignatures() {
		for i, k := range publicKeys {
			provider := providers[i]
			_, ownFormat := provider.(key.MessageVerifier)
			fingerprinter, canFingerprint := provider.(key.SigningKeyFingerprinter)
			go func() {
				var (
					pass bool
					err  error
				)
				// Providers with a signature format of their own (OpenPGP
				// packets, for example) verify the whole PAE message
				// themselves. ED25519 signs the message directly (no
				// prehash).
				if ownFormat || k.HashType == 0 {
					pass, err = kv.VerifyMessage(provider, paeMessage, sig.GetSig())
				} else {
					pass, err = kv.VerifyDigest(k, digests[k.HashType], sig.GetSig())
				}
				if err == nil && pass {
					matched := k
					if canFingerprint {
						if fp, ferr := fingerprinter.SigningKeyFingerprint(sig.GetSig()); ferr == nil {
							clone := *k
							clone.SigningKeyFingerprint = fp
							matched = &clone
						}
					}
					mutex.Lock()
					matchedKeys = append(matchedKeys, matched)
					mutex.Unlock()
				}
				t.Done(err)
			}()
			t.Throttle()
		}
	}

	if err := errors.Join(t.Errs()...); err != nil {
		return nil, fmt.Errorf("running sig verification: %w", err)
	}

	return &key.VerificationResult{
		Keys:     matchedKeys,
		Time:     time.Now(),
		Digest:   digestStrs,
		Verified: len(matchedKeys) > 0,
	}, nil
}

// BuildKeyVerifier builds a key verifier used to check the DSSE signatures
func (dv *DefaultVerifier) BuildKeyVerifier(opts *options.Verifier) (*key.Verifier, error) {
	v := key.NewVerifier()
	return v, nil
}

// OpenEnvelope parses a DSSE envelope
func (dv *DefaultVerifier) OpenEnvelope(path string) (*sdsse.Envelope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening DSSE envelope file: %w", err)
	}

	env := &sdsse.Envelope{}
	if err := protojson.Unmarshal(data, env); err != nil {
		return nil, fmt.Errorf("unmarshaling DSSE envelope: %w", err)
	}
	return env, nil
}

// hashPayload generates the payload hash using the supplied hasher. Note that
// this function is not a normal hasher, it implements the DSSE PAE encoding
// and the returned digest is from the PAE message constructed according to the
// DSSE specification.
func hashPayload(env *sdsse.Envelope, hasher crypto.Hash) ([]byte, error) {
	if env == nil {
		return nil, errors.New("no envelope supplied")
	}

	if env.Payload == nil {
		return nil, errors.New("DSEE envelope has no payload")
	}

	if env.GetPayloadType() == "" {
		return nil, errors.New("unset payload type in DSSE envelope")
	}

	PAEEncoded := PAEEncode(env)

	h := hasher.New()
	if _, err := h.Write(PAEEncoded); err != nil {
		return nil, fmt.Errorf("writing to hasher: %w", err)
	}
	return h.Sum(nil), nil
}

// PAEEncode implements the DSSE signing protocol:
// https://github.com/secure-systems-lab/dsse/blob/master/protocol.md#signature-definition
// This function was stolen from the Secure System Labs dsse packager.
func PAEEncode(env *sdsse.Envelope) []byte {
	// payloadType string, payload []byte) []byte {
	return fmt.Appendf(nil, "DSSEv1 %d %s %d %s",
		len(env.GetPayloadType()), env.GetPayloadType(),
		len(env.GetPayload()), env.GetPayload())
}
