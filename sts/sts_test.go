// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sts

import (
	"context"
	"maps"
	"slices"
	"testing"

	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/stretchr/testify/require"
)

// The tests here change the registry, which is global: they do not run in
// parallel and put it back as it was.

// restoreRegistry puts the registry back as it is now when the test ends.
func restoreRegistry(t *testing.T) {
	t.Helper()
	mtx.Lock()
	providers, names := maps.Clone(DefaultProviders), slices.Clone(order)
	mtx.Unlock()

	t.Cleanup(func() {
		mtx.Lock()
		DefaultProviders, order = providers, names
		mtx.Unlock()
	})
}

type fakeProvider struct{ id string }

func (*fakeProvider) Provide(context.Context, string) (*oauthflow.OIDCIDToken, error) {
	return nil, nil //nolint:nilnil // no token, as a provider out of its environment
}

// names returns the names of the registered providers, in order.
func names() []string {
	ordered := Ordered()
	out := make([]string, 0, len(ordered))
	for _, named := range ordered {
		out = append(out, named.Name)
	}
	return out
}

func TestOrderedDefault(t *testing.T) { //nolint:paralleltest // global registry
	expected := []string{"actions", "gitlab", "gcp"}

	// Ranging over a map starts at a random place: ask often enough to
	// catch an order that depends on it.
	for range 200 {
		require.Equal(t, expected, names())
	}

	// Each name comes with its own provider.
	for _, named := range Ordered() {
		require.Same(t, DefaultProviders[named.Name], named.Provider)
	}
}

func TestOrderedRegister(t *testing.T) { //nolint:paralleltest // global registry
	restoreRegistry(t)

	// New providers go last, in the order they are registered. The names
	// are chosen to sort the other way around.
	RegisterProvider("zzz", &fakeProvider{})
	RegisterProvider("aaa", &fakeProvider{})
	for range 200 {
		require.Equal(t, []string{"actions", "gitlab", "gcp", "zzz", "aaa"}, names())
	}

	// Registering under a taken name replaces the provider where it is.
	replacement := &fakeProvider{id: "replacement"}
	RegisterProvider("gitlab", replacement)
	require.Equal(t, []string{"actions", "gitlab", "gcp", "zzz", "aaa"}, names())
	require.Same(t, replacement, Ordered()[1].Provider)
}

func TestOrderedUnregister(t *testing.T) { //nolint:paralleltest // global registry
	restoreRegistry(t)

	UnregisterProvider("gitlab", nil)
	require.Equal(t, []string{"actions", "gcp"}, names())

	// Unregistering what is not there changes nothing.
	UnregisterProvider("nope", nil)
	require.Equal(t, []string{"actions", "gcp"}, names())

	// A provider that comes back is new: it goes last.
	RegisterProvider("gitlab", &fakeProvider{})
	require.Equal(t, []string{"actions", "gcp", "gitlab"}, names())

	UnregisterProvider("actions", nil)
	UnregisterProvider("gcp", nil)
	UnregisterProvider("gitlab", nil)
	require.Empty(t, Ordered())
}

// Providers written to the map directly still get a fixed place.
func TestOrderedDirectMapWrites(t *testing.T) { //nolint:paralleltest // global registry
	restoreRegistry(t)

	mtx.Lock()
	DefaultProviders["zeta"] = &fakeProvider{}
	DefaultProviders["alpha"] = &fakeProvider{}
	DefaultProviders["mid"] = &fakeProvider{}
	delete(DefaultProviders, "gitlab")
	mtx.Unlock()

	for range 200 {
		require.Equal(t, []string{"actions", "gcp", "alpha", "mid", "zeta"}, names())
	}

	// Registered ones keep coming before them.
	RegisterProvider("registered", &fakeProvider{})
	require.Equal(t, []string{"actions", "gcp", "registered", "alpha", "mid", "zeta"}, names())
}

func TestProvidersSnapshot(t *testing.T) { //nolint:paralleltest // global registry
	restoreRegistry(t)

	snapshot := Providers()
	ordered := Ordered()
	RegisterProvider("later", &fakeProvider{})

	require.NotContains(t, snapshot, "later")
	require.Len(t, ordered, 3)
	require.Contains(t, Providers(), "later")
	require.Len(t, Ordered(), 4)
}
