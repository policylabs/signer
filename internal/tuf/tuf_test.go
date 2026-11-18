// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package tuf

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// readOnlyHome points the TUF cache at a home directory nothing can be
// created in. Not parallel: it changes the environment.
func readOnlyHome(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("directory permissions do not keep files out on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root writes to read-only directories")
	}
	home := filepath.Join(t.TempDir(), "home")
	require.NoError(t, os.Mkdir(home, 0o500))
	t.Setenv("HOME", home)
}

func TestCacheWritable(t *testing.T) {
	t.Run("creates-the-directory", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "a", "b")
		require.True(t, cacheWritable(dir))

		// The probe is not left behind.
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Empty(t, entries)
	})

	t.Run("read-only-parent", func(t *testing.T) {
		readOnlyHome(t)
		require.False(t, cacheWritable(filepath.Join(os.Getenv("HOME"), ".sigstore", "root")))
	})

	t.Run("read-only-directory", func(t *testing.T) {
		readOnlyHome(t)
		require.False(t, cacheWritable(os.Getenv("HOME")))
	})
}

// TestGetClientUnwritableCacheIsNotRetried checks that a cache directory
// that cannot be written fails the client at once, instead of after the
// backoff of every retry.
func TestGetClientUnwritableCacheIsNotRetried(t *testing.T) {
	readOnlyHome(t)
	rootData, err := os.ReadFile(filepath.Join(fixtureDir, "12.root.json"))
	require.NoError(t, err)

	start := time.Now()
	_, err = GetClient(&TufOptions{
		TufRootURL: "http://127.0.0.1:1",
		RootData:   rootData,
	})
	require.ErrorContains(t, err, "cannot be written")
	require.Less(t, time.Since(start), tufInitInitialDelay)
}
