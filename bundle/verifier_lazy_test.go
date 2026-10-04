// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"errors"
	"os"
	"sync/atomic"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/policylabs/signer/api/v1"
	"github.com/policylabs/signer/sigstore"
)

// buildCounter stands in for BuildSigstoreVerifier, recording how many
// times it ran and returning a canned instance.
type buildCounter struct {
	calls atomic.Int32
	inst  VerifyCapable
	err   error
}

func (b *buildCounter) build(*sigstore.InstanceConfig) (VerifyCapable, error) {
	b.calls.Add(1)
	return b.inst, b.err
}

func TestWithSigstoreRootsDataDefersBuild(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("testdata/sigstore-roots.json")
	require.NoError(t, err)

	v, err := NewWithError(WithSigstoreRootsData(data))
	require.NoError(t, err)
	dv, ok := v.(*DefaultVerifier)
	require.True(t, ok)
	require.Len(t, dv.Verifiers, 2)

	// Construction must not have touched any trusted root: every entry
	// is still an unbuilt lazy verifier.
	for _, ver := range dv.Verifiers {
		lazy, ok := ver.(*lazyVerifier)
		require.True(t, ok)
		assert.Nil(t, lazy.verifier)
		require.NoError(t, lazy.err)
	}
}

func TestLazyVerifierBuildsOnce(t *testing.T) {
	t.Parallel()
	good := &verify.VerificationResult{}
	counter := &buildCounter{inst: &fakeInstance{res: good}}
	lazy := &lazyVerifier{conf: &sigstore.InstanceConfig{}, build: counter.build}
	v := &DefaultVerifier{Verifiers: []VerifyCapable{lazy}}

	assert.Equal(t, int32(0), counter.calls.Load())
	for range 3 {
		res, err := v.Verify(skipIdentity(), testBundle(t))
		require.NoError(t, err)
		assert.Same(t, good, res)
	}
	assert.Equal(t, int32(1), counter.calls.Load())
}

func TestLazyVerifierBuildErrorIsNotAConclusion(t *testing.T) {
	t.Parallel()
	boom := errors.New("tuf unreachable")
	counter := &buildCounter{err: boom}
	lazy := &lazyVerifier{
		conf:  &sigstore.InstanceConfig{Instance: sigstore.Instance{ID: "sigstore"}},
		build: counter.build,
	}
	v := &DefaultVerifier{Verifiers: []VerifyCapable{lazy}}

	res, err := v.Verify(skipIdentity(), testBundle(t))
	require.Error(t, err)
	assert.Nil(t, res)
	// Failing to build the verifier means nothing was concluded about the
	// bundle, so neither conclusion sentinel may be in the chain.
	require.ErrorIs(t, err, boom)
	require.ErrorContains(t, err, `instance "sigstore"`)
	require.NotErrorIs(t, err, api.ErrVerificationFailed)
	require.NotErrorIs(t, err, api.ErrUnverifiable)

	// The failed build is cached; a second verification does not retry it.
	_, err = v.Verify(skipIdentity(), testBundle(t))
	require.ErrorIs(t, err, boom)
	assert.Equal(t, int32(1), counter.calls.Load())
}
