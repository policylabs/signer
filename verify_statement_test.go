// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	sdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	sbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/policylabs/signer/api/v1"
	"github.com/policylabs/signer/bundle/bundlefakes"
	"github.com/policylabs/signer/key"
	"github.com/policylabs/signer/options"
)

func loadTestKey(t *testing.T, name string) *key.Public {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("dsse", "testdata", name))
	require.NoError(t, err)
	k, err := key.NewParser().ParsePublicKey(data)
	require.NoError(t, err)
	return k
}

// loadTestEnvelope returns the rebuild.dsse.json testdata envelope, which
// verifies against rebuild.key.
func loadTestEnvelope(t *testing.T) *EnvelopeArtifact {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("dsse", "testdata", "rebuild.dsse.json"))
	require.NoError(t, err)
	art, err := ParseArtifact(data)
	require.NoError(t, err)
	env, ok := art.(*EnvelopeArtifact)
	require.True(t, ok)
	return env
}

func TestVerifyStatementDSSE(t *testing.T) {
	t.Parallel()

	rightKey := loadTestKey(t, "rebuild.key")
	wrongKey := loadTestKey(t, "sigstore.dsse.key")

	for _, tc := range []struct {
		name       string
		envelope   func(t *testing.T) *EnvelopeArtifact
		verifier   func() *Verifier
		opts       []options.VerificationOptFunc
		wantStatus api.VerificationStatus
		wantIDs    int
	}{
		{
			name: "unsigned",
			envelope: func(t *testing.T) *EnvelopeArtifact {
				t.Helper()
				return &EnvelopeArtifact{Envelope: &sdsse.Envelope{PayloadType: "x", Payload: []byte("y")}}
			},
			verifier:   func() *Verifier { return NewVerifier() },
			opts:       []options.VerificationOptFunc{options.WithPublicKeys(rightKey)},
			wantStatus: api.VerificationStatus_UNSIGNED,
		},
		{
			name:       "signed, no keys anywhere",
			envelope:   func(t *testing.T) *EnvelopeArtifact { t.Helper(); return loadTestEnvelope(t) },
			verifier:   func() *Verifier { return NewVerifier() },
			wantStatus: api.VerificationStatus_UNVERIFIABLE,
		},
		{
			name:       "signed, wrong key",
			envelope:   func(t *testing.T) *EnvelopeArtifact { t.Helper(); return loadTestEnvelope(t) },
			verifier:   func() *Verifier { return NewVerifier() },
			opts:       []options.VerificationOptFunc{options.WithPublicKeys(wrongKey)},
			wantStatus: api.VerificationStatus_FAILED,
		},
		{
			// Malformed signature bytes are a conclusion about the envelope,
			// not an error: the key was supplied and the check ran.
			name: "signed with garbage bytes, right key",
			envelope: func(t *testing.T) *EnvelopeArtifact {
				t.Helper()
				env := loadTestEnvelope(t)
				env.Envelope.Signatures[0].Sig = []byte("garbage")
				return env
			},
			verifier:   func() *Verifier { return NewVerifier() },
			opts:       []options.VerificationOptFunc{options.WithPublicKeys(rightKey)},
			wantStatus: api.VerificationStatus_FAILED,
		},
		{
			name:       "signed, right key via option",
			envelope:   func(t *testing.T) *EnvelopeArtifact { t.Helper(); return loadTestEnvelope(t) },
			verifier:   func() *Verifier { return NewVerifier() },
			opts:       []options.VerificationOptFunc{options.WithPublicKeys(wrongKey, rightKey)},
			wantStatus: api.VerificationStatus_VERIFIED,
			wantIDs:    1,
		},
		{
			name:     "signed, right key configured on verifier",
			envelope: func(t *testing.T) *EnvelopeArtifact { t.Helper(); return loadTestEnvelope(t) },
			verifier: func() *Verifier {
				return NewVerifier(func(o *options.Verifier) { o.PubKeys = []key.PublicKeyProvider{rightKey} })
			},
			wantStatus: api.VerificationStatus_VERIFIED,
			wantIDs:    1,
		},
		{
			name:     "per-call keys replace configured keys",
			envelope: func(t *testing.T) *EnvelopeArtifact { t.Helper(); return loadTestEnvelope(t) },
			verifier: func() *Verifier {
				return NewVerifier(func(o *options.Verifier) { o.PubKeys = []key.PublicKeyProvider{rightKey} })
			},
			opts:       []options.VerificationOptFunc{options.WithPublicKeys(wrongKey)},
			wantStatus: api.VerificationStatus_FAILED,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ver, err := tc.verifier().VerifyStatement(tc.envelope(t), tc.opts...)
			require.NoError(t, err)
			require.NotNil(t, ver)
			require.NotNil(t, ver.GetSignature())

			sig := ver.GetSignature()
			assert.Equal(t, tc.wantStatus, sig.GetStatus())
			assert.Equal(t, tc.wantStatus == api.VerificationStatus_VERIFIED, sig.GetVerified())
			assert.Equal(t, tc.wantStatus == api.VerificationStatus_VERIFIED, ver.GetVerified())
			assert.NotNil(t, sig.GetDate())
			assert.Len(t, sig.GetIdentities(), tc.wantIDs)
			if tc.wantStatus == api.VerificationStatus_VERIFIED {
				assert.Empty(t, sig.GetError())
				assert.Equal(t, rightKey.ID(), sig.GetIdentities()[0].GetKey().GetId())
				assert.True(t, ver.MatchesIdentity(&api.Identity{Key: &api.IdentityKey{Id: rightKey.ID()}}))
			} else {
				assert.NotEmpty(t, sig.GetError())
				assert.NotEmpty(t, ver.Error())
			}
		})
	}
}

func TestVerifyStatementBytes(t *testing.T) {
	t.Parallel()

	rightKey := loadTestKey(t, "rebuild.key")
	data, err := os.ReadFile(filepath.Join("dsse", "testdata", "rebuild.dsse.json"))
	require.NoError(t, err)

	ver, err := NewVerifier().VerifyStatementBytes(data, options.WithPublicKeys(rightKey))
	require.NoError(t, err)
	assert.Equal(t, api.VerificationStatus_VERIFIED, ver.GetSignature().GetStatus())

	ver, err = NewVerifier().VerifyStatementBytes([]byte(`{"foo": 1}`))
	require.ErrorIs(t, err, ErrUnknownArtifact)
	assert.Nil(t, ver)
}

func TestVerifyStatementErrors(t *testing.T) {
	t.Parallel()

	env := loadTestEnvelope(t)
	// A bundle that signs a message without saying what was signed is not
	// something VerifyStatement can conclude about.
	msg := &BundleArtifact{Bundle: &sbundle.Bundle{Bundle: &protobundle.Bundle{
		Content: &protobundle.Bundle_MessageSignature{MessageSignature: &protocommon.MessageSignature{
			Signature: []byte("sig"),
		}},
	}}}
	// A bundle with no content at all.
	empty := &BundleArtifact{Bundle: &sbundle.Bundle{Bundle: &protobundle.Bundle{}}}

	for _, tc := range []struct {
		name string
		art  SignedArtifact
		opts []options.VerificationOptFunc
	}{
		{name: "nil artifact", art: nil},
		{name: "envelope artifact without envelope", art: &EnvelopeArtifact{}},
		{name: "bundle artifact without bundle", art: &BundleArtifact{}},
		{name: "bundle signing a message without a digest", art: msg},
		{name: "bundle with no content", art: empty},
		// An option that fails to apply is an error, not a conclusion.
		{name: "bad option", art: env, opts: []options.VerificationOptFunc{options.WithExpectedSpiffeIDRegex("td", "(")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ver, err := NewVerifier().VerifyStatement(tc.art, tc.opts...)
			require.Error(t, err)
			assert.Nil(t, ver)
		})
	}
}

// bundleWithSigs builds a minimal bundle wrapping a DSSE envelope with n
// signatures, enough for the statement checks that run before the bundle
// verifier is consulted.
func bundleWithSigs(n int) *BundleArtifact {
	sigs := make([]*sdsse.Signature, n)
	for i := range sigs {
		sigs[i] = &sdsse.Signature{Sig: []byte("sig")}
	}
	return &BundleArtifact{Bundle: &sbundle.Bundle{Bundle: &protobundle.Bundle{
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: &sdsse.Envelope{
			PayloadType: "application/vnd.in-toto+json", Payload: []byte("{}"), Signatures: sigs,
		}},
	}}}
}

func TestVerifyStatementBundle(t *testing.T) {
	t.Parallel()

	sigstoreResult := verify.NewVerificationResult()
	sigstoreResult.VerifiedIdentity = &verify.CertificateIdentity{
		SubjectAlternativeName: verify.SubjectAlternativeNameMatcher{SubjectAlternativeName: "https://github.com/org/repo/.github/workflows/release.yaml@refs/tags/v1"},
		Issuer:                 verify.IssuerMatcher{Issuer: "https://token.actions.githubusercontent.com"},
	}
	spiffeResult := verify.NewVerificationResult()
	spiffeResult.VerifiedIdentity = &verify.CertificateIdentity{
		SubjectAlternativeName: verify.SubjectAlternativeNameMatcher{SubjectAlternativeName: "spiffe://example.org/workload"},
	}

	for _, tc := range []struct {
		name       string
		art        *BundleArtifact
		result     *verify.VerificationResult
		err        error
		wantStatus api.VerificationStatus
		wantErr    bool
		check      func(t *testing.T, ver *api.Verification)
	}{
		{
			name: "unsigned envelope short-circuits before the verifier",
			art:  bundleWithSigs(0), err: errors.New("must not be called"),
			wantStatus: api.VerificationStatus_UNSIGNED,
		},
		{
			name: "verified, sigstore identity",
			art:  bundleWithSigs(1), result: sigstoreResult,
			wantStatus: api.VerificationStatus_VERIFIED,
			check: func(t *testing.T, ver *api.Verification) {
				t.Helper()
				require.Len(t, ver.GetSignature().GetIdentities(), 1)
				ss := ver.GetSignature().GetIdentities()[0].GetSigstore()
				require.NotNil(t, ss)
				assert.Equal(t, "https://token.actions.githubusercontent.com", ss.GetIssuer())
				assert.True(t, ver.MatchesIdentity(&api.Identity{Sigstore: &api.IdentitySigstore{
					Issuer: ss.GetIssuer(), Identity: ss.GetIdentity(),
				}}))
			},
		},
		{
			name: "verified, spiffe identity",
			art:  bundleWithSigs(1), result: spiffeResult,
			wantStatus: api.VerificationStatus_VERIFIED,
			check: func(t *testing.T, ver *api.Verification) {
				t.Helper()
				require.Len(t, ver.GetSignature().GetIdentities(), 1)
				assert.Equal(t, "spiffe://example.org/workload", ver.GetSignature().GetIdentities()[0].GetSpiffe().GetSvid())
			},
		},
		{
			name: "failed conclusion",
			art:  bundleWithSigs(1), err: fmt.Errorf("chain verification failed: x509: unknown authority: %w", api.ErrVerificationFailed),
			wantStatus: api.VerificationStatus_FAILED,
			check: func(t *testing.T, ver *api.Verification) {
				t.Helper()
				assert.Contains(t, ver.GetSignature().GetError(), "unknown authority")
				assert.Empty(t, ver.GetSignature().GetIdentities())
			},
		},
		{
			name: "unverifiable conclusion",
			art:  bundleWithSigs(1), err: fmt.Errorf("no spiffe verifier configured: %w", api.ErrUnverifiable),
			wantStatus: api.VerificationStatus_UNVERIFIABLE,
		},
		{
			name: "operational error propagates",
			art:  bundleWithSigs(1), err: errors.New("fetching trusted root: connection refused"),
			wantErr: true,
		},
		{
			name:    "nil result without error is an error",
			art:     bundleWithSigs(1),
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fake := &bundlefakes.FakeVerifier{}
			fake.VerifyReturns(tc.result, tc.err)
			v := &Verifier{Options: options.DefaultVerifier, bundleVerifier: fake}

			ver, err := v.VerifyStatement(tc.art)
			if tc.wantErr {
				require.Error(t, err)
				assert.Nil(t, ver)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, ver.GetSignature())
			assert.Equal(t, tc.wantStatus, ver.GetSignature().GetStatus())
			assert.Equal(t, tc.wantStatus == api.VerificationStatus_VERIFIED, ver.GetVerified())
			assert.NotNil(t, ver.GetSignature().GetDate())
			if tc.wantStatus != api.VerificationStatus_VERIFIED {
				assert.NotEmpty(t, ver.GetSignature().GetError())
			}
			if tc.check != nil {
				tc.check(t, ver)
			}
		})
	}
}

// TestVerifyStatementSigstoreIntegration runs real sigstore bundles from
// the bundle testdata through VerifyStatement. Not parallel: the subtests
// share the global TUF cache.
func TestVerifyStatementSigstoreIntegration(t *testing.T) {
	for _, tc := range []struct {
		name       string
		rootsPath  string
		bundlePath string
		wantStatus api.VerificationStatus
	}{
		{"verifies against its instance", "bundle/testdata/sigstore-roots.json", "bundle/testdata/public-good.sigstore.json", api.VerificationStatus_VERIFIED},
		{"fails against the wrong instance", "bundle/testdata/github.json", "bundle/testdata/public-good.sigstore.json", api.VerificationStatus_FAILED},
	} {
		t.Run(tc.name, func(t *testing.T) {
			roots, err := os.ReadFile(tc.rootsPath)
			require.NoError(t, err)
			data, err := os.ReadFile(tc.bundlePath)
			require.NoError(t, err)

			v := NewVerifier(func(o *options.Verifier) { o.SigstoreRootsData = roots })
			ver, err := v.VerifyStatementBytes(data, options.WithSkipIdentityCheck(true))
			require.NoError(t, err)
			require.NotNil(t, ver.GetSignature())
			assert.Equal(t, tc.wantStatus, ver.GetSignature().GetStatus())
			assert.Equal(t, tc.wantStatus == api.VerificationStatus_VERIFIED, ver.GetVerified())
			if tc.wantStatus == api.VerificationStatus_VERIFIED {
				// Identity checks were skipped, so the signer must come
				// from the verified certificate itself.
				require.Len(t, ver.GetSignature().GetIdentities(), 1)
				ss := ver.GetSignature().GetIdentities()[0].GetSigstore()
				require.NotNil(t, ss)
				assert.NotEmpty(t, ss.GetIssuer())
				assert.NotEmpty(t, ss.GetIdentity())
			} else {
				assert.NotEmpty(t, ver.GetSignature().GetError())
			}
		})
	}
}
