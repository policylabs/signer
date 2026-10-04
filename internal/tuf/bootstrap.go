// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package tuf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/sirupsen/logrus"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

// rootMaxLength bounds a downloaded root metadata file. Same value go-tuf
// uses for its own root downloads.
const rootMaxLength = 512000

// bootstrapRoot returns the root metadata the TUF client should be seeded
// with: the newest root that chains, signature by signature, from the
// embedded bootstrap root.
//
// go-tuf persists whatever root it is seeded with over the cached
// root.json. Seeding it with an old embed therefore replaces a newer
// cached root with an older, possibly expired, one, after which the
// cached metadata can no longer be loaded locally and every client
// creation goes back to the network. Seeding it with the newest verified
// root instead makes that persist a no-op, so a populated cache keeps
// working offline for as long as its metadata is valid.
//
// The chain is walked through versioned roots (<N>.root.json) kept next to
// the cached metadata. Versions missing from the cache are fetched only
// while the cached root.json is newer than what was verified so far; a
// cache that is already verified costs no network. Any failure along the
// way returns the embed, which is what the client was seeded with before.
func bootstrapRoot(cacheDir string, embedded []byte, f fetcher.Fetcher, repoURL string) []byte {
	trusted, err := trustedmetadata.New(embedded)
	if err != nil {
		// The embed is handed to go-tuf unchanged; it reports the problem.
		return embedded
	}

	cached, err := cachedRootVersion(cacheDir)
	if err != nil || cached <= trusted.Root.Signed.Version {
		return embedded
	}

	newest := embedded
	for next := trusted.Root.Signed.Version + 1; next <= cached; next++ {
		data, err := versionedRoot(cacheDir, next, f, repoURL)
		if err != nil {
			logrus.Debugf("tuf: stopping root chain walk at version %d: %v", next, err)
			break
		}
		if _, err := trusted.UpdateRoot(data); err != nil {
			logrus.Warnf("tuf: cached root version %d does not verify against version %d: %v", next, next-1, err)
			// Drop the bad file so the next walk fetches it again instead
			// of failing on the same bytes forever.
			if rerr := os.Remove(versionedRootPath(cacheDir, next)); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
				logrus.Debugf("tuf: removing unverifiable root version %d: %v", next, rerr)
			}
			break
		}
		newest = data
	}
	return newest
}

// cachedRootVersion reads the version of the root.json go-tuf keeps in the
// cache directory.
func cachedRootVersion(cacheDir string) (int64, error) {
	data, err := os.ReadFile(filepath.Join(cacheDir, "root.json"))
	if err != nil {
		return 0, err
	}
	root, err := metadata.Root().FromBytes(data)
	if err != nil {
		return 0, err
	}
	return root.Signed.Version, nil
}

// versionedRoot returns root metadata version v from the cache, fetching
// and caching it from the repository when it is not there yet. The file
// is returned unverified; the caller verifies it against the chain.
func versionedRoot(cacheDir string, v int64, f fetcher.Fetcher, repoURL string) ([]byte, error) {
	path := versionedRootPath(cacheDir, v)
	if data, err := os.ReadFile(path); err == nil {
		return data, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if f == nil || repoURL == "" {
		return nil, fmt.Errorf("root version %d is not cached and no fetcher is configured", v)
	}
	data, err := f.DownloadFile(ensureTrailingSlash(repoURL)+filepath.Base(path), rootMaxLength, 0)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, err
	}
	// Verification happens in the caller, which removes the file again if
	// it does not chain.
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return nil, err
	}
	return data, nil
}

// versionedRootPath is where root metadata version v is cached.
func versionedRootPath(cacheDir string, v int64) string {
	return filepath.Join(cacheDir, strconv.FormatInt(v, 10)+".root.json")
}

func ensureTrailingSlash(url string) string {
	if url == "" || url[len(url)-1] == '/' {
		return url
	}
	return url + "/"
}
