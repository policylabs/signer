// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package tuf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// The fixtures are the public good sigstore root chain: version 12 is the
// bootstrap root the signer shipped with until October 2026 and 13-15 are
// its successors, each signed by the keys of the one before.
const (
	testRepoURL = "https://tuf.example.test/repo"
	fixtureDir  = "testdata"
)

func fixture(t *testing.T, version int) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureDir, fmt.Sprintf("%d.root.json", version)))
	require.NoError(t, err)
	return data
}

func rootVersion(t *testing.T, data []byte) int64 {
	t.Helper()
	root, err := metadata.Root().FromBytes(data)
	require.NoError(t, err)
	return root.Signed.Version
}

// writeCache lays out a cache directory with root.json at version
// cachedRoot and the given versioned roots next to it.
func writeCache(t *testing.T, cachedRoot int, versioned ...int) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "root.json"), fixture(t, cachedRoot), 0o600))
	for _, v := range versioned {
		require.NoError(t, os.WriteFile(versionedRootPath(dir, int64(v)), fixture(t, v), 0o600))
	}
	return dir
}

// mapFetcher serves versioned roots from memory and records what was asked.
type mapFetcher struct {
	files map[string][]byte
	asked []string
}

func (m *mapFetcher) DownloadFile(urlPath string, _ int64, _ time.Duration) ([]byte, error) {
	m.asked = append(m.asked, urlPath)
	name := urlPath[strings.LastIndex(urlPath, "/")+1:]
	data, ok := m.files[name]
	if !ok {
		return nil, errors.New("not found: " + urlPath)
	}
	return data, nil
}

func TestBootstrapRoot(t *testing.T) {
	t.Parallel()
	embed := fixture(t, 12)

	t.Run("no-cache-returns-embed", func(t *testing.T) {
		t.Parallel()
		got := bootstrapRoot(t.TempDir(), embed, nil, testRepoURL)
		assert.Equal(t, embed, got)
	})

	t.Run("cache-not-newer-returns-embed", func(t *testing.T) {
		t.Parallel()
		got := bootstrapRoot(writeCache(t, 12), embed, nil, testRepoURL)
		assert.Equal(t, embed, got)
	})

	t.Run("full-chain-in-cache-returns-newest", func(t *testing.T) {
		t.Parallel()
		got := bootstrapRoot(writeCache(t, 15, 13, 14, 15), embed, nil, testRepoURL)
		assert.Equal(t, int64(15), rootVersion(t, got))
	})

	t.Run("partial-chain-returns-last-verified", func(t *testing.T) {
		t.Parallel()
		got := bootstrapRoot(writeCache(t, 15, 13), embed, nil, testRepoURL)
		assert.Equal(t, int64(13), rootVersion(t, got))
	})

	t.Run("bad-link-stops-walk-and-is-removed", func(t *testing.T) {
		t.Parallel()
		dir := writeCache(t, 15, 13, 15)
		// Version 15 standing in for 14 is correctly signed but has the
		// wrong version number, so it must not chain from 13.
		require.NoError(t, os.WriteFile(versionedRootPath(dir, 14), fixture(t, 15), 0o600))

		got := bootstrapRoot(dir, embed, nil, testRepoURL)
		assert.Equal(t, int64(13), rootVersion(t, got))
		_, err := os.Stat(versionedRootPath(dir, 14))
		require.ErrorIs(t, err, os.ErrNotExist)
		// The link after the bad one is untouched: the walk stopped.
		_, err = os.Stat(versionedRootPath(dir, 15))
		require.NoError(t, err)
	})

	t.Run("corrupt-embed-is-returned-as-is", func(t *testing.T) {
		t.Parallel()
		bad := []byte("not json")
		got := bootstrapRoot(writeCache(t, 15, 13, 14, 15), bad, nil, testRepoURL)
		assert.Equal(t, bad, got)
	})

	t.Run("missing-versions-are-fetched-and-cached", func(t *testing.T) {
		t.Parallel()
		dir := writeCache(t, 15)
		f := &mapFetcher{files: map[string][]byte{
			"13.root.json": fixture(t, 13),
			"14.root.json": fixture(t, 14),
			"15.root.json": fixture(t, 15),
		}}

		got := bootstrapRoot(dir, embed, f, testRepoURL)
		assert.Equal(t, int64(15), rootVersion(t, got))
		assert.Equal(t, []string{
			testRepoURL + "/13.root.json",
			testRepoURL + "/14.root.json",
			testRepoURL + "/15.root.json",
		}, f.asked)
		for _, v := range []int64{13, 14, 15} {
			data, err := os.ReadFile(versionedRootPath(dir, v))
			require.NoError(t, err)
			assert.Equal(t, v, rootVersion(t, data))
		}

		// Once cached, the walk never asks the network again.
		f.asked = nil
		got = bootstrapRoot(dir, embed, f, testRepoURL)
		assert.Equal(t, int64(15), rootVersion(t, got))
		assert.Empty(t, f.asked)
	})

	t.Run("fetch-failure-returns-last-verified", func(t *testing.T) {
		t.Parallel()
		dir := writeCache(t, 15, 13)
		f := &mapFetcher{files: map[string][]byte{}}

		got := bootstrapRoot(dir, embed, f, testRepoURL)
		assert.Equal(t, int64(13), rootVersion(t, got))
		assert.Equal(t, []string{testRepoURL + "/14.root.json"}, f.asked)
	})

	t.Run("fetched-root-that-does-not-chain-is-not-kept", func(t *testing.T) {
		t.Parallel()
		dir := writeCache(t, 15, 13)
		f := &mapFetcher{files: map[string][]byte{"14.root.json": fixture(t, 15)}}

		got := bootstrapRoot(dir, embed, f, testRepoURL)
		assert.Equal(t, int64(13), rootVersion(t, got))
		_, err := os.Stat(versionedRootPath(dir, 14))
		require.ErrorIs(t, err, os.ErrNotExist)
	})
}
