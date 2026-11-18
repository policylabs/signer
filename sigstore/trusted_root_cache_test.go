// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sigstore

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/policylabs/signer/internal/tuf"
)

// fakeTUF stands in for the TUF fetch: it counts the calls it gets and
// answers with the embedded sigstore trusted root, or with err when set.
type fakeTUF struct {
	t     *testing.T
	calls atomic.Int32
	err   atomic.Pointer[error]
}

func (f *fakeTUF) fetch(*tuf.TufOptions) ([]byte, error) {
	f.calls.Add(1)
	if err := f.err.Load(); err != nil {
		return nil, *err
	}
	data, err := readEmbeddedTrustedRoot("sigstore")
	require.NoError(f.t, err)
	return data, nil
}

func (f *fakeTUF) fail(err error) {
	if err == nil {
		f.err.Store(nil)
		return
	}
	f.err.Store(&err)
}

// fakeClock is a clock tests move by hand.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newTestCache(t *testing.T) (*tufTrustedRootCache, *fakeTUF, *fakeClock) {
	t.Helper()
	source := &fakeTUF{t: t}
	clock := &fakeClock{now: time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)}
	return newTUFTrustedRootCache(source.fetch, clock.Now), source, clock
}

func TestTUFTrustedRootCache(t *testing.T) {
	t.Parallel()
	opts := &tuf.TufOptions{TufRootURL: "https://tuf.example", RootData: []byte("bootstrap")}

	t.Run("fetches-once-until-it-expires", func(t *testing.T) {
		t.Parallel()
		cache, source, clock := newTestCache(t)

		first, fetched, err := cache.get(opts)
		require.NoError(t, err)
		require.True(t, fetched)
		require.NotEmpty(t, first.FulcioCertificateAuthorities())

		clock.Advance(tufTrustedRootTTL - time.Second)
		again, fetched, err := cache.get(opts)
		require.NoError(t, err)
		require.False(t, fetched)
		require.Same(t, first, again)
		require.EqualValues(t, 1, source.calls.Load())

		clock.Advance(time.Second)
		_, fetched, err = cache.get(opts)
		require.NoError(t, err)
		require.True(t, fetched)
		require.EqualValues(t, 2, source.calls.Load())
	})

	t.Run("remembers-a-failure-for-a-shorter-time", func(t *testing.T) {
		t.Parallel()
		cache, source, clock := newTestCache(t)
		errDown := errors.New("tuf is down")
		source.fail(errDown)

		_, fetched, err := cache.get(opts)
		require.ErrorIs(t, err, errDown)
		require.True(t, fetched)

		clock.Advance(tufTrustedRootFailureTTL - time.Second)
		_, fetched, err = cache.get(opts)
		require.ErrorIs(t, err, errDown)
		require.False(t, fetched, "a remembered failure must not go back to TUF")
		require.EqualValues(t, 1, source.calls.Load())

		// Once the failure expires the fetch is tried again, and a
		// success replaces it.
		source.fail(nil)
		clock.Advance(time.Second)
		tr, fetched, err := cache.get(opts)
		require.NoError(t, err)
		require.True(t, fetched)
		require.NotNil(t, tr)
		require.EqualValues(t, 2, source.calls.Load())
	})

	t.Run("unparseable-root-is-a-failure", func(t *testing.T) {
		t.Parallel()
		clock := &fakeClock{now: time.Now()}
		cache := newTUFTrustedRootCache(func(*tuf.TufOptions) ([]byte, error) {
			return []byte("{not-json"), nil
		}, clock.Now)

		tr, fetched, err := cache.get(opts)
		require.ErrorContains(t, err, "parsing trusted root fetched via TUF")
		require.True(t, fetched)
		require.Nil(t, tr)
	})

	t.Run("repositories-do-not-share-an-outcome", func(t *testing.T) {
		t.Parallel()
		cache, source, _ := newTestCache(t)

		for _, o := range []*tuf.TufOptions{
			opts,
			{TufRootURL: "https://other.example", RootData: opts.RootData},
			{TufRootURL: opts.TufRootURL, RootData: []byte("another bootstrap")},
			{TufRootURL: opts.TufRootURL, RootData: opts.RootData, TufRootPath: "/elsewhere"},
		} {
			_, fetched, err := cache.get(o)
			require.NoError(t, err)
			require.True(t, fetched)
		}
		require.EqualValues(t, 4, source.calls.Load())
	})

	t.Run("concurrent-callers-share-one-fetch", func(t *testing.T) {
		t.Parallel()
		cache, source, _ := newTestCache(t)

		var wg sync.WaitGroup
		for range 32 {
			wg.Go(func() {
				tr, _, err := cache.get(opts)
				if err != nil || tr == nil {
					t.Errorf("getting the trusted root: %v", err)
				}
			})
		}
		wg.Wait()
		require.EqualValues(t, 1, source.calls.Load())
	})
}

// TestTrustedRootStaleRemembersTUFFailure checks the resolution end to end:
// with a stale embed and an unreachable TUF repository every call returns
// the embed, and only the first one pays for the attempt.
func TestTrustedRootStaleRemembersTUFFailure(t *testing.T) {
	t.Parallel()
	roots, err := ParseRoots(DefaultRoots)
	require.NoError(t, err)
	ic := roots.Roots[0]
	// A repository of its own, so no other test has fetched it.
	ic.TufRootURL = "http://127.0.0.1:1/remembers-failure"

	_, err = ic.TrustedRoot(WithMaxAge(0))
	require.NoError(t, err)

	start := time.Now()
	for range 20 {
		tr, err := ic.TrustedRoot(WithMaxAge(0))
		require.NoError(t, err)
		require.NotEmpty(t, tr.FulcioCertificateAuthorities())
	}
	// One attempt takes its retries' backoff, 750ms; twenty remembered
	// ones only parse the embed.
	require.Less(t, time.Since(start), 500*time.Millisecond)
}
