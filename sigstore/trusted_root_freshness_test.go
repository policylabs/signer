// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sigstore

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/stretchr/testify/require"

	"github.com/policylabs/signer/internal/tuf"
)

// rootFreshnessEnv gates the freshness guard. The default `go test` run stays
// offline and green because the guard skips unless this is set.
const rootFreshnessEnv = "SIGNER_CHECK_ROOT_FRESHNESS"

// ciTrustedRootMaxAge is a CI-only freshness floor for the embedded trusted
// roots. It is deliberately tighter than the runtime DefaultTrustedRootMaxAge
// (90 days) so a refresh is forced well before an embed could go stale enough
// to make the runtime fall back to a live TUF fetch during verification.
const ciTrustedRootMaxAge = 21 * 24 * time.Hour

// TestTrustedRootFreshness backstops the weekly auto-refresh: it fails when an
// embedded trusted root has drifted from upstream. It is env-gated so the
// normal offline suite skips it; enable it with SIGNER_CHECK_ROOT_FRESHNESS=1.
//
// Per instance it checks two things:
//
//   - Offline floor: the recorded snapshot is younger than ciTrustedRootMaxAge.
//   - Upstream diff (network): the embed is not missing any trust anchor the
//     live upstream trusted root now advertises.
func TestTrustedRootFreshness(t *testing.T) {
	if os.Getenv(rootFreshnessEnv) == "" {
		t.Skipf("set %s=1 to run the trusted-root freshness guard (it makes network calls)", rootFreshnessEnv)
	}

	roots, err := ParseRoots(DefaultRoots)
	require.NoError(t, err)
	require.NotEmpty(t, roots.Roots)

	for i := range roots.Roots {
		inst := &roots.Roots[i]
		t.Run(inst.ID, func(t *testing.T) {
			// Offline floor: a fast, deterministic signal with no network.
			require.Falsef(
				t, inst.TrustedRootSnapshot.IsZero(),
				"instance %q has no trusted-root-snapshot; run `go run ./hack/refresh-roots`", inst.ID,
			)
			age := time.Since(inst.TrustedRootSnapshot)
			require.LessOrEqualf(
				t, age, ciTrustedRootMaxAge,
				"embedded trusted root for %q is %s old (CI floor is %s); run `go run ./hack/refresh-roots`",
				inst.ID, age.Round(time.Hour), ciTrustedRootMaxAge,
			)

			// Upstream diff: the embed must carry every anchor upstream has.
			embedData, err := readEmbeddedTrustedRoot(inst.ID)
			require.NoError(t, err)
			embed, err := root.NewTrustedRootFromJSON(embedData)
			require.NoError(t, err)

			upstreamData, err := tuf.GetRoot(&inst.TufOptions)
			require.NoErrorf(t, err, "fetching upstream trusted root for %q", inst.ID)
			upstream, err := root.NewTrustedRootFromJSON(upstreamData)
			require.NoError(t, err)

			missing := missingAnchors(embed, upstream)
			require.Emptyf(
				t, missing,
				"embedded trusted root for %q is missing anchors present upstream: %v; run `go run ./hack/refresh-roots`",
				inst.ID, missing,
			)
		})
	}
}

// anchorKeys returns the set of stable identities for every trust anchor in a
// trusted root. Fulcio CAs and timestamping authorities are keyed by the
// SHA-256 fingerprint of their root certificate; Rekor and CT logs are keyed
// by their log key ID (the stable map key sigstore-go derives from the log
// ID). These keys survive the volatile ordering and metadata of the serialized
// trusted_root.json, so the anchors can be compared as sets rather than by
// byte-comparing the whole file.
func anchorKeys(tr *root.TrustedRoot) map[string]struct{} {
	keys := map[string]struct{}{}
	for _, ca := range tr.FulcioCertificateAuthorities() {
		if fca, ok := ca.(*root.FulcioCertificateAuthority); ok && fca.Root != nil {
			keys["fulcio:"+certFingerprint(fca.Root)] = struct{}{}
		}
	}
	for id := range tr.RekorLogs() {
		keys["rekor:"+id] = struct{}{}
	}
	for id := range tr.CTLogs() {
		keys["ctlog:"+id] = struct{}{}
	}
	for _, tsa := range tr.TimestampingAuthorities() {
		if sta, ok := tsa.(*root.SigstoreTimestampingAuthority); ok && sta.Root != nil {
			keys["tsa:"+certFingerprint(sta.Root)] = struct{}{}
		}
	}
	return keys
}

// missingAnchors returns the sorted anchor identities present upstream but
// absent from embed. A non-empty result means the embed is stale.
func missingAnchors(embed, upstream *root.TrustedRoot) []string {
	have := anchorKeys(embed)
	var missing []string
	for k := range anchorKeys(upstream) {
		if _, ok := have[k]; !ok {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	return missing
}

func certFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}
