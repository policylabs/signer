// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"errors"
	"fmt"

	sbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"google.golang.org/protobuf/types/known/timestamppb"

	api "github.com/policylabs/signer/api/v1"
	"github.com/policylabs/signer/options"
)

// VerifyStatement is the inverse of Signer.SignStatement. It takes a
// signed statement in any supported format and returns the verification
// conclusion as an api.Verification carrying the three signals a
// consumer can read: whether the statement is signed (status UNSIGNED),
// whether the signatures could be checked (UNVERIFIABLE), and whether
// they verified against the content (FAILED or VERIFIED, in which case
// Identities names the signers).
//
// A non-nil error means nothing was concluded: the options, key or
// trust material could not be used, or the artifact is not a statement.
// A negative conclusion is not an error; it is returned as a
// Verification with the corresponding status and the reason in Error.
// Bundle verifiers report their conclusions by wrapping
// api.ErrVerificationFailed or api.ErrUnverifiable, which this method
// translates into the FAILED and UNVERIFIABLE statuses.
//
// Keys for DSSE envelopes come from options.WithPublicKeys or from the
// keys configured on the verifier. Bundles verify against the sigstore
// or SPIFFE trust material configured on the verifier.
func (v *Verifier) VerifyStatement(art SignedArtifact, fnOpts ...options.VerificationOptFunc) (*api.Verification, error) {
	if art == nil {
		return nil, errors.New("no signed artifact to verify")
	}
	switch a := art.(type) {
	case *EnvelopeArtifact:
		return v.verifyEnvelopeStatement(a, fnOpts...)
	case *BundleArtifact:
		return v.verifyBundleStatement(a.Bundle, fnOpts...)
	default:
		return nil, fmt.Errorf("unsupported signed artifact kind %q", art.Kind())
	}
}

// VerifyStatementBytes parses the serialized form of a signed statement
// (a sigstore bundle or a DSSE envelope) and verifies it with
// VerifyStatement.
func (v *Verifier) VerifyStatementBytes(data []byte, fnOpts ...options.VerificationOptFunc) (*api.Verification, error) {
	art, err := ParseArtifact(data)
	if err != nil {
		return nil, err
	}
	return v.VerifyStatement(art, fnOpts...)
}

// verifyEnvelopeStatement verifies a bare DSSE envelope. Envelopes are
// checked against the configured public keys when there are any; a
// keyless envelope carrying a Sigstore certificate in its signatures is
// verified against the Rekor transparency log when that is enabled
// (options.WithRekorVerification) and is UNVERIFIABLE otherwise.
func (v *Verifier) verifyEnvelopeStatement(art *EnvelopeArtifact, fnOpts ...options.VerificationOptFunc) (*api.Verification, error) {
	if art == nil || art.Envelope == nil {
		return nil, errors.New("envelope artifact has no DSSE envelope")
	}
	env := art.Envelope
	if len(env.GetSignatures()) == 0 {
		return conclude(api.VerificationStatus_UNSIGNED, "DSSE envelope has no signatures"), nil
	}

	opts := v.Options.Verification
	for _, fn := range fnOpts {
		if err := fn(&opts); err != nil {
			return nil, err
		}
	}
	if len(opts.PubKeys) == 0 {
		// No keys to check against. A certificate attached to a
		// signature means the envelope is keyless-signed and the
		// transparency log can vouch for it.
		if cert := firstSignatureCert(art); cert != nil {
			if opts.Rekor.Enabled {
				return v.verifyKeylessDSSE(art, cert, &opts)
			}
			return conclude(api.VerificationStatus_UNVERIFIABLE, fmt.Sprintf(
				"the envelope is signed with a Sigstore certificate (%s); verifying it needs a "+
					"transparency log lookup, which is disabled — enable it with options.WithRekorVerification",
				certIdentityHint(cert),
			)), nil
		}
		if opts.Rekor.Enabled {
			return conclude(api.VerificationStatus_UNVERIFIABLE,
				"no public keys to verify the DSSE signatures against, and the envelope carries no "+
					"certificate to find in the transparency log"), nil
		}
		return conclude(api.VerificationStatus_UNVERIFIABLE, "no public keys to verify the DSSE signatures against"), nil
	}

	res, err := v.VerifyParsedDSSE(env, opts.PubKeys, fnOpts...)
	if err != nil {
		return nil, err
	}
	if !res.Verified {
		return conclude(api.VerificationStatus_FAILED, fmt.Sprintf(
			"none of the %d signatures verified against the %d supplied public keys",
			len(env.GetSignatures()), len(opts.PubKeys),
		)), nil
	}

	ids := make([]*api.Identity, 0, len(res.Keys))
	for _, k := range res.Keys {
		ids = append(ids, &api.Identity{
			Key: &api.IdentityKey{
				Id:                 k.ID(),
				Type:               string(k.Scheme),
				Data:               k.Data,
				SigningFingerprint: k.SigningKeyFingerprint,
			},
		})
	}
	return verified(ids), nil
}

// verifyBundleStatement verifies a sigstore bundle against the configured
// sigstore or SPIFFE trust material, translating the bundle verifier's
// typed errors into conclusions. The bundle wraps a DSSE envelope, or a
// message signature over a digest the bundle carries: that is how a cosign
// image signature travels once a collector has turned it into an
// attestation, and the signature is verified against that digest.
func (v *Verifier) verifyBundleStatement(bndl *sbundle.Bundle, fnOpts ...options.VerificationOptFunc) (*api.Verification, error) {
	if bndl == nil || bndl.Bundle == nil {
		return nil, errors.New("bundle artifact has no bundle")
	}
	switch {
	case bndl.GetDsseEnvelope() != nil:
		if len(bndl.GetDsseEnvelope().GetSignatures()) == 0 {
			return conclude(api.VerificationStatus_UNSIGNED, "bundle DSSE envelope has no signatures"), nil
		}
	case bndl.GetMessageSignature() != nil:
		msg := bndl.GetMessageSignature()
		if len(msg.GetSignature()) == 0 {
			return conclude(api.VerificationStatus_UNSIGNED, "bundle message signature has no signature"), nil
		}
		if len(msg.GetMessageDigest().GetDigest()) == 0 {
			return nil, errors.New("bundle message signature carries no digest to verify against")
		}
	default:
		return nil, errors.New("bundle wraps neither a DSSE envelope nor a message signature")
	}

	res, err := v.VerifyParsedBundle(bndl, fnOpts...)
	switch {
	case errors.Is(err, api.ErrUnverifiable):
		return conclude(api.VerificationStatus_UNVERIFIABLE, err.Error()), nil
	case errors.Is(err, api.ErrVerificationFailed):
		return conclude(api.VerificationStatus_FAILED, err.Error()), nil
	case err != nil:
		return nil, err
	case res == nil:
		return nil, errors.New("bundle verifier returned no result and no error")
	}

	sv := api.SignatureVerificationFromResult(res)
	sv.Date = timestamppb.Now()
	sv.Verified = true
	sv.Status = api.VerificationStatus_VERIFIED
	return &api.Verification{Signature: sv}, nil
}

// conclude builds a Verification for an outcome other than VERIFIED.
func conclude(status api.VerificationStatus, reason string) *api.Verification {
	return &api.Verification{
		Signature: &api.SignatureVerification{
			Date:     timestamppb.Now(),
			Status:   status,
			Verified: false,
			Error:    reason,
		},
	}
}

// verified builds a VERIFIED Verification naming the signers.
func verified(ids []*api.Identity) *api.Verification {
	return &api.Verification{
		Signature: &api.SignatureVerification{
			Date:       timestamppb.Now(),
			Status:     api.VerificationStatus_VERIFIED,
			Verified:   true,
			Identities: ids,
		},
	}
}
