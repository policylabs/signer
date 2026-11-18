// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sigstore

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/policylabs/signer/internal/tuf"
)

const (
	// tufTrustedRootTTL is how long a trusted root fetched from TUF serves
	// the process before it is fetched again. It bounds how long a running
	// process keeps verifying against trust material upstream has replaced.
	tufTrustedRootTTL = time.Hour

	// tufTrustedRootFailureTTL is how long a failed TUF fetch is remembered
	// before the next attempt. A fetch that cannot work (no network, a
	// cache directory that cannot be written) costs its retries and
	// timeouts once per window instead of once per call.
	tufTrustedRootFailureTTL = 5 * time.Minute
)

// tufTrustedRoots holds the trusted roots the process has fetched from TUF.
var tufTrustedRoots = newTUFTrustedRootCache(tuf.GetRoot, time.Now)

// tufTrustedRootCache remembers the outcome of fetching a trusted root from
// TUF. Resolving one builds a TUF client, which reads and verifies the
// repository metadata and may go to the network; a process that builds many
// verifiers (one per signature, in the worst callers) would otherwise pay
// that every time its embedded root is stale.
//
// Outcomes are kept per TUF repository and bootstrap root, so two instances
// never share one. Concurrent callers of the same repository wait for a
// single fetch.
type tufTrustedRootCache struct {
	fetch func(*tuf.TufOptions) ([]byte, error)
	now   func() time.Time

	mu      sync.Mutex
	entries map[tufTrustedRootKey]*tufTrustedRootEntry
}

// tufTrustedRootKey identifies what a fetch depends on: where the repository
// is and the root its metadata is verified from.
type tufTrustedRootKey struct {
	url       string
	path      string
	bootstrap [sha256.Size]byte
}

type tufTrustedRootEntry struct {
	mu      sync.Mutex
	root    *root.TrustedRoot
	err     error
	expires time.Time
}

func newTUFTrustedRootCache(fetch func(*tuf.TufOptions) ([]byte, error), now func() time.Time) *tufTrustedRootCache {
	return &tufTrustedRootCache{
		fetch:   fetch,
		now:     now,
		entries: map[tufTrustedRootKey]*tufTrustedRootEntry{},
	}
}

// get returns the trusted root of the TUF repository in opts, fetching it
// when no outcome is remembered or the remembered one has expired. fetched
// reports whether this call went to TUF: a remembered failure returns its
// error with fetched false, so the caller can tell a new failure from one
// it has already reported.
func (c *tufTrustedRootCache) get(opts *tuf.TufOptions) (tr *root.TrustedRoot, fetched bool, err error) {
	key := tufTrustedRootKey{
		url:       opts.TufRootURL,
		path:      opts.TufRootPath,
		bootstrap: sha256.Sum256(opts.RootData),
	}

	c.mu.Lock()
	entry, ok := c.entries[key]
	if !ok {
		entry = &tufTrustedRootEntry{}
		c.entries[key] = entry
	}
	c.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if c.now().Before(entry.expires) {
		return entry.root, false, entry.err
	}

	entry.root, entry.err = c.fetchTrustedRoot(opts)
	ttl := tufTrustedRootTTL
	if entry.err != nil {
		ttl = tufTrustedRootFailureTTL
	}
	entry.expires = c.now().Add(ttl)
	return entry.root, true, entry.err
}

func (c *tufTrustedRootCache) fetchTrustedRoot(opts *tuf.TufOptions) (*root.TrustedRoot, error) {
	data, err := c.fetch(opts)
	if err != nil {
		return nil, err
	}
	tr, err := root.NewTrustedRootFromJSON(data)
	if err != nil {
		return nil, fmt.Errorf("parsing trusted root fetched via TUF: %w", err)
	}
	return tr, nil
}
