// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package tuf

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"sigs.k8s.io/release-utils/version"
)

// TUF metadata initialization is brittle on transient filesystem
// contention: on Windows the atomic rename of the freshly-created
// temp metadata file fails when antivirus / indexer briefly locks it
// ("Access is denied"), and on slow disks any platform can hit a
// short window where the rename or initial fetch fails. The
// failure mode is recoverable on retry, so we bound a few attempts
// here rather than blow up the verifier on a sub-second I/O blip.
const (
	tufInitMaxAttempts  = 3
	tufInitInitialDelay = 250 * time.Millisecond
)

// TufOptions captures the TUF options handled by bind
type TufOptions struct {
	Fetcher     fetcher.Fetcher
	TufRootPath string `json:"tuf-root-path"`
	TufRootURL  string `json:"tuf-root-url"`
	RootData    []byte `json:"root-data"`
}

// GetClient returns a TUF client configured with the options. The
// underlying tuf.New call is retried with exponential backoff on
// transient errors (see the tufInit* constants for rationale); the
// last error is returned after exhausting attempts so legitimate
// configuration problems still surface.
//
// When a valid TUF cache is already present on disk (e.g. pre-baked
// into an air-gapped image), ForceCache is enabled so sigstore-go
// uses the local copy and never makes a network call. ForceCache only
// disables proactive refresh — sigstore-go still re-fetches on its
// own when metadata has actually expired, so this is safe by default.
func GetClient(opts *TufOptions) (*tuf.Client, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		// Fall back to using a TUF repository in the temp location
		home = os.TempDir()
	}

	cachePath := filepath.Join(home, ".sigstore", "root")
	cacheDir := filepath.Join(cachePath, tuf.URLToPath(opts.TufRootURL))
	f := Defaultfetcher()
	tufOpts := &tuf.Options{
		CacheValidity:             0,
		ForceCache:                cacheHasMetadata(cachePath, opts.TufRootURL),
		Root:                      bootstrapRoot(cacheDir, opts.RootData, f, opts.TufRootURL),
		CachePath:                 cachePath,
		RepositoryBaseURL:         opts.TufRootURL,
		DisableLocalCache:         false,
		DisableConsistentSnapshot: false,
		Fetcher:                   f,
	}

	var (
		client  *tuf.Client
		lastErr error
		delay   = tufInitInitialDelay
	)
	for attempt := 1; attempt <= tufInitMaxAttempts; attempt++ {
		client, lastErr = tuf.New(tufOpts)
		if lastErr == nil {
			// The client may have just rotated the cached root.json past
			// what was verified above. Walk the chain again now, while the
			// repository is known to be reachable, so the versioned roots
			// are on disk and the next client creation can verify the
			// cached root without the network.
			bootstrapRoot(cacheDir, opts.RootData, f, opts.TufRootURL)
			return client, nil
		}
		if attempt < tufInitMaxAttempts {
			time.Sleep(delay)
			delay *= 2
		}
	}
	return nil, fmt.Errorf("creating TUF client (after %d attempts): %w", tufInitMaxAttempts, lastErr)
}

// GetRoot fetches the trusted root from the configured URL or from
// the sigstore public instance.
func GetRoot(opts *TufOptions) ([]byte, error) {
	client, err := GetClient(opts)
	if err != nil {
		return nil, fmt.Errorf("creating TUF client: %w", err)
	}

	data, err := client.GetTarget("trusted_root.json")
	if err != nil {
		return nil, fmt.Errorf("fetching TUF root data: %w", err)
	}
	return data, nil
}

// cacheHasMetadata reports whether the TUF cache at cachePath/<URL-derived
// subdir> already contains the root.json metadata file. If so, the caller
// can safely enable ForceCache to keep sigstore-go from re-fetching over
// the network. A missing root.json means there's nothing to honor, and
// the default refresh-on-load behavior is correct.
//
// repoURL is the same value passed as Options.RepositoryBaseURL; the
// per-repo subdirectory inside cachePath is derived by sigstore-go's
// own URLToPath, which we call to stay byte-identical with the path
// the TUF client will look at.
func cacheHasMetadata(cachePath, repoURL string) bool {
	if cachePath == "" || repoURL == "" {
		return false
	}
	rootJSON := filepath.Join(cachePath, tuf.URLToPath(repoURL), "root.json")
	info, err := os.Stat(rootJSON)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular() && info.Size() > 0
}

// fetchTimeout bounds every HTTP request the TUF client makes. go-tuf's
// default fetcher uses http.DefaultClient, which has no timeout, so a
// black-holed proxy would otherwise hang a verification indefinitely.
const fetchTimeout = 30 * time.Second

// Defaultfetcher returns a default TUF fetcher configured with the bind UA
func Defaultfetcher() fetcher.Fetcher {
	f := fetcher.NewDefaultFetcher()
	agentString := fmt.Sprintf(
		"Carabiner Signer/%s (%s; %s; Carabiner Systems; https://github.com/policylabs/signer)",
		version.GetVersionInfo().GitVersion, runtime.GOOS, runtime.GOARCH,
	)
	f.SetHTTPUserAgent(agentString)
	f.SetHTTPClient(&http.Client{Timeout: fetchTimeout})
	return f
}
