// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sigstore

import (
	"errors"
	"fmt"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sirupsen/logrus"

	"github.com/policylabs/signer/internal/tuf"
)

// DefaultTrustedRootMaxAge is the staleness window for an embedded trusted
// root. Once the instance's snapshot date is older than this, TrustedRoot
// refreshes the trust material from TUF instead of using the embed.
//
// The window is sized for binaries that pin a signer release and never get
// a fresher embed: upstream trusted roots publish new anchors well before
// they are used, so an embed stays usable for months. A shorter window
// only sends every such binary to the network sooner.
const DefaultTrustedRootMaxAge = 90 * 24 * time.Hour

// trustedRootOptions is the resolved option set for a TrustedRoot call.
type trustedRootOptions struct {
	roots           *SigstoreRoots
	instanceID      string
	forceTUF        bool
	trustedRootJSON []byte
	trustedRootPath string
	maxAge          time.Duration
}

// TrustedRootOptFn configures a TrustedRoot lookup.
type TrustedRootOptFn func(*trustedRootOptions)

// WithInstance indicates the sigstore instance (by ID) for which we will resolve
// its roots. Only meaningful for the package level TrustedRoot method, it is
// ignored by the  (*Instance).TrustedRoot method which returns its own root.
func WithInstance(id string) TrustedRootOptFn {
	return func(o *trustedRootOptions) { o.instanceID = id }
}

// WithRoots supplies the parsed sigstore roots to resolve the instance from.
// When unset, we use the embedded DefaultRoots. Only meaningful for the
// package level TrustedRoot.
func WithRoots(roots *SigstoreRoots) TrustedRootOptFn {
	return func(o *trustedRootOptions) { o.roots = roots }
}

// WithForceTUF skips the embedded trusted root entirely and always fetches
// from TUF. Because the embed is bypassed, it is not available as a resilient
// fallback if the TUF fetch fails.
func WithForceTUF() TrustedRootOptFn {
	return func(o *trustedRootOptions) { o.forceTUF = true }
}

// WithoutEmbedded is an alias of WithForceTUF: it opts out of the embedded
// trusted root and forces a TUF fetch.
func WithoutEmbedded() TrustedRootOptFn { return WithForceTUF() }

// WithTrustedRootJSON provides to the solver the trusted root material directly.
// It short circuits instance resolution and the embeds, in favor of the supplied bytes
func WithTrustedRootJSON(b []byte) TrustedRootOptFn {
	return func(o *trustedRootOptions) { o.trustedRootJSON = b }
}

// WithTrustedRootPath loads trusted root material from a file. Like
// WithTrustedRootJSON it wins over any instance embed or TUF fetch.
func WithTrustedRootPath(p string) TrustedRootOptFn {
	return func(o *trustedRootOptions) { o.trustedRootPath = p }
}

// WithMaxAge overrides the staleness window for the embedded trusted root.
// A zero (or negative) duration forces the embed to be treated as stale so
// the TUF path is taken (falling back to the embed only if TUF fails).
func WithMaxAge(d time.Duration) TrustedRootOptFn {
	return func(o *trustedRootOptions) { o.maxAge = d }
}

func defaultTrustedRootOptions() trustedRootOptions {
	return trustedRootOptions{maxAge: DefaultTrustedRootMaxAge}
}

// TrustedRoot resolves the sigstore trusted root for the default instance
// (Roots[0], which is the public good sigstore instance) or the one selected
// if selected with WithInstance().
//
// It is the single source of sigstore trust material for the signer and its
// consumers. See (*Instance).TrustedRoot for the resolution order.
func TrustedRoot(opts ...TrustedRootOptFn) (*root.TrustedRoot, error) {
	o := defaultTrustedRootOptions()
	for _, fn := range opts {
		fn(&o)
	}

	// Any supplied root wins over any instance resolution.
	if tr, ok, err := loadTrustedRootOverride(&o); ok || err != nil {
		return tr, err
	}

	ic, err := resolveInstance(&o)
	if err != nil {
		return nil, err
	}
	return ic.resolveTrustedRoot(&o)
}

// TrustedRoot resolves the trusted root for the current sigstore instance. The
// resolution order is:
//
//  1. First, any supplied override (WithTrustedRootJSON/WithTrustedRootPath) wins
//  2. If there is an embedded roots/instance-id.trusted_root.json and its fresh
//     (snapshot is within MaxAge and its Fulcio anchors are not expired) and
//     TUF is not forced, the the embeds are used. Here we make no network calls.
//  3. Otherwise a TUF fetch of the live trusted root as defined in the roots.
//  4. If the TUF fetch fails but a stale embed exists, the embed is used and
//     a warning is logged so verification works.
func (i *Instance) TrustedRoot(opts ...TrustedRootOptFn) (*root.TrustedRoot, error) {
	o := defaultTrustedRootOptions()
	for _, fn := range opts {
		fn(&o)
	}
	if tr, ok, err := loadTrustedRootOverride(&o); ok || err != nil {
		return tr, err
	}
	return i.resolveTrustedRoot(&o)
}

// resolveTrustedRoot implements steps 2-4 of the resolution order for an instance.
func (i *Instance) resolveTrustedRoot(o *trustedRootOptions) (*root.TrustedRoot, error) {
	// Load and keep the parsed embedded root so it can serve both as the
	// trust root when fresh and as fallback when TUF fails.
	var embedded *root.TrustedRoot
	if !o.forceTUF {
		if data, err := readEmbeddedTrustedRoot(i.ID); err == nil {
			tr, perr := root.NewTrustedRootFromJSON(data)
			if perr != nil {
				logrus.Warnf("ignoring corrupt embedded trusted root for %q: %v", i.ID, perr)
			} else {
				embedded = tr
				if i.embeddedTrustedRootFresh(tr, o.maxAge) {
					return tr, nil
				}
			}
		}
	}

	// Fetch the live trusted root via TUF (when forced)
	data, tufErr := tuf.GetRoot(&i.TufOptions)
	if tufErr == nil {
		tr, perr := root.NewTrustedRootFromJSON(data)
		if perr == nil {
			return tr, nil
		}
		tufErr = fmt.Errorf("parsing trusted root fetched via TUF: %w", perr)
	}

	// If TUF fails then fall back to the stale embed if we have one.
	if embedded != nil {
		logrus.Warnf(
			"fetching trusted root for %q via TUF failed (%v); using embedded copy captured %s",
			i.ID, tufErr, i.trustedRootSnapshotLabel(),
		)
		return embedded, nil
	}

	return nil, fmt.Errorf("resolving trusted root for %q: %w", i.ID, tufErr)
}

// embeddedTrustedRootFresh reports whether the embedded trusted root can be
// trusted without a TUF refresh (its snapshot is within maxAge and at least
// one valid Fulcio anchor)
func (i *Instance) embeddedTrustedRootFresh(tr *root.TrustedRoot, maxAge time.Duration) bool {
	// No snapshot means we can't vouch for its age
	if i.TrustedRootSnapshot.IsZero() {
		return false
	}
	if time.Since(i.TrustedRootSnapshot) > maxAge {
		return false
	}
	// Even within maxAge, treat the embed as stale if all its Fulcio anchors are
	// expired, the trust anchors are dead and only a TUF refresh can do.
	if allFulcioAuthoritiesExpired(tr) {
		return false
	}
	return true
}

func (i *Instance) trustedRootSnapshotLabel() string {
	if i.TrustedRootSnapshot.IsZero() {
		return "(unknown date)"
	}
	return i.TrustedRootSnapshot.Format(time.RFC3339)
}

// allFulcioAuthoritiesExpired reports if all the Fulcio certificate
// authorities in the trusted root are expired. A CA with an unset end
// date never expires, so a root that contains one is considered live.
// If no anchors are set we report as expired.
func allFulcioAuthoritiesExpired(tr *root.TrustedRoot) bool {
	cas := tr.FulcioCertificateAuthorities()
	if len(cas) == 0 {
		return true
	}
	now := time.Now()
	for _, ca := range cas {
		fca, ok := ca.(*root.FulcioCertificateAuthority)
		if !ok {
			return false
		}
		if fca.ValidityPeriodEnd.IsZero() || now.Before(fca.ValidityPeriodEnd) {
			return false
		}
	}
	return true
}

// loadTrustedRootOverride returns a trusted root when one of the override
// options is set by the caller. The bool reports whether an override applied.
func loadTrustedRootOverride(o *trustedRootOptions) (*root.TrustedRoot, bool, error) {
	switch {
	case len(o.trustedRootJSON) > 0:
		tr, err := root.NewTrustedRootFromJSON(o.trustedRootJSON)
		if err != nil {
			return nil, true, fmt.Errorf("parsing supplied trusted root JSON: %w", err)
		}
		return tr, true, nil
	case o.trustedRootPath != "":
		tr, err := root.NewTrustedRootFromPath(o.trustedRootPath)
		if err != nil {
			return nil, true, fmt.Errorf("reading trusted root from %q: %w", o.trustedRootPath, err)
		}
		return tr, true, nil
	}
	return nil, false, nil
}

// resolveInstance selects the InstanceConfig for which we will resolve the roots
// ehich is the one whose ID matches WithInstance(), or Roots[0] when no ID was
// specified in the options.
func resolveInstance(o *trustedRootOptions) (*InstanceConfig, error) {
	roots := o.roots
	if roots == nil {
		parsed, err := ParseRoots(DefaultRoots)
		if err != nil {
			return nil, fmt.Errorf("parsing default sigstore roots: %w", err)
		}
		roots = parsed
	}
	if len(roots.Roots) == 0 {
		return nil, errors.New("no sigstore instances configured")
	}
	if o.instanceID == "" {
		return &roots.Roots[0], nil
	}
	for i := range roots.Roots {
		if roots.Roots[i].ID == o.instanceID {
			return &roots.Roots[i], nil
		}
	}
	return nil, fmt.Errorf("no sigstore instance with id %q", o.instanceID)
}
