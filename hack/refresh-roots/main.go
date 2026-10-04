// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Command refresh-roots keeps the embedded sigstore trusted roots as fresh as
// possible.
//
// For every instance declared in sigstore/sigstore-roots.json it fetches the
// current trusted_root.json over TUF (the very same path the runtime accessor
// uses, internal/tuf.GetRoot), validates that it parses, writes it to
// sigstore/roots/<id>.trusted_root.json and stamps that instance's
// "trusted-root-snapshot" with the current date.
//
// It also advances the instance's embedded TUF bootstrap root,
// sigstore/roots/<id>.json, to the newest root metadata that verifies from
// the current embed. A bootstrap root is only good until it expires; past
// that, a client seeded with it cannot use its local cache and must go to
// the network on every run.
//
// It is idempotent: run twice on the same day against unchanged upstreams it
// produces byte-identical output. Run it from the repository root:
//
//	go run ./hack/refresh-roots
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/policylabs/signer/internal/tuf"
	"github.com/policylabs/signer/sigstore"
)

// defaultRootsFile is the roots config relative to the repository root.
const defaultRootsFile = "sigstore/sigstore-roots.json"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	rootsFile := defaultRootsFile
	if len(args) > 0 {
		rootsFile = args[0]
	}
	rootsDir := filepath.Join(filepath.Dir(rootsFile), "roots")

	data, err := os.ReadFile(rootsFile)
	if err != nil {
		return fmt.Errorf("reading roots file: %w", err)
	}

	roots, err := sigstore.ParseRoots(data)
	if err != nil {
		return fmt.Errorf("parsing roots file: %w", err)
	}

	// Truncate to the day so re-running within the same day is a no-op.
	snapshot := time.Now().UTC().Truncate(24 * time.Hour).Format(time.RFC3339)

	updated := data
	var errs []error
	for i := range roots.Roots {
		inst := &roots.Roots[i]
		fmt.Printf("refreshing trusted root for %q via TUF (%s)...\n", inst.ID, inst.TufRootURL)

		trData, gerr := tuf.GetRoot(&inst.TufOptions)
		if gerr != nil {
			errs = append(errs, fmt.Errorf("%s: fetching trusted root via TUF: %w", inst.ID, gerr))
			continue
		}

		// Validate the fetched material parses before writing it.
		if _, perr := root.NewTrustedRootFromJSON(trData); perr != nil {
			errs = append(errs, fmt.Errorf("%s: fetched trusted root does not parse: %w", inst.ID, perr))
			continue
		}

		formatted, ferr := indentJSON(trData)
		if ferr != nil {
			errs = append(errs, fmt.Errorf("%s: formatting trusted root: %w", inst.ID, ferr))
			continue
		}

		outPath := filepath.Join(rootsDir, inst.ID+".trusted_root.json")
		if werr := os.WriteFile(outPath, formatted, 0o600); werr != nil {
			errs = append(errs, fmt.Errorf("%s: writing %s: %w", inst.ID, outPath, werr))
			continue
		}

		next, serr := setSnapshot(updated, inst.ID, snapshot)
		if serr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", inst.ID, serr))
			continue
		}
		updated = next
		fmt.Printf("  wrote %s (snapshot %s)\n", outPath, snapshot)

		if err := refreshBootstrapRoot(rootsDir, inst); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", inst.ID, err))
		}
	}

	if !bytes.Equal(updated, data) {
		if err := os.WriteFile(rootsFile, updated, 0o600); err != nil {
			return fmt.Errorf("writing roots file: %w", err)
		}
	}

	return errors.Join(errs...)
}

// refreshBootstrapRoot writes the newest verified root metadata of the
// instance's TUF repository to sigstore/roots/<id>.json, the embed the
// runtime seeds its TUF client with. The bytes are kept as served, since
// that is what the signatures cover.
func refreshBootstrapRoot(rootsDir string, inst *sigstore.InstanceConfig) error {
	data, err := tuf.LatestRoot(&inst.TufOptions)
	if err != nil {
		return fmt.Errorf("fetching latest TUF root: %w", err)
	}
	latest, err := metadata.Root().FromBytes(data)
	if err != nil {
		return fmt.Errorf("latest TUF root does not parse: %w", err)
	}
	current, err := metadata.Root().FromBytes(inst.RootData)
	if err != nil {
		return fmt.Errorf("embedded TUF root does not parse: %w", err)
	}
	if latest.Signed.Version < current.Signed.Version {
		return fmt.Errorf("latest verified TUF root (v%d) is older than the embed (v%d)",
			latest.Signed.Version, current.Signed.Version)
	}

	outPath := filepath.Join(rootsDir, inst.ID+".json")
	if err := os.WriteFile(outPath, data, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", outPath, err)
	}
	fmt.Printf("  wrote %s (root v%d, expires %s)\n",
		outPath, latest.Signed.Version, latest.Signed.Expires.UTC().Format(time.RFC3339))
	return nil
}

// setSnapshot rewrites the "trusted-root-snapshot" value of the instance with
// the given id in the raw roots JSON, leaving the rest of the file (key order,
// indentation, other instances) untouched. Anchoring the match on the "id"
// key keeps the rewrite scoped to the right instance.
func setSnapshot(data []byte, id, snapshot string) ([]byte, error) {
	re := regexp.MustCompile(
		`("id"\s*:\s*"` + regexp.QuoteMeta(id) + `"[\s\S]*?"trusted-root-snapshot"\s*:\s*")[^"]*(")`,
	)
	if !re.Match(data) {
		return nil, fmt.Errorf("could not locate trusted-root-snapshot for instance %q", id)
	}
	return re.ReplaceAll(data, []byte("${1}"+snapshot+"${2}")), nil
}

// indentJSON normalizes JSON to the embed's on-disk style: 2-space indentation
// (preserving key order via json.Indent) and exactly one trailing newline.
func indentJSON(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.Indent(&buf, data, "", "  "); err != nil {
		return nil, fmt.Errorf("indenting trusted root JSON: %w", err)
	}
	return append(bytes.TrimRight(buf.Bytes(), "\n"), '\n'), nil
}
