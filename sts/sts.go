// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sts

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/sigstore/sigstore/pkg/oauthflow"

	"github.com/policylabs/signer/sts/providers/gcp"
	"github.com/policylabs/signer/sts/providers/github"
	"github.com/policylabs/signer/sts/providers/gitlab"
)

// Ensure the provider implement
var (
	_ Provider = &github.Actions{}
	_ Provider = &gitlab.CI{}
	_ Provider = &gcp.Metadata{}
	_ Provider = &gcp.Provider{}
)

// These are the default STS providers, the signer project has additional
// providers in https://github.com/policylabs/signer-extras which have a
// heavier dependency footprint. gcp mints a service-account identity token
// from $GOOGLE_APPLICATION_CREDENTIALS or the Google Cloud metadata server
// and, like the others, reports no token when its environment is absent.
// Build it with gcp.New to pin a service account key explicitly. When
// $GOOGLE_SERVICE_ACCOUNT_NAME names a service account, gcp impersonates it
// through the IAM Credentials API instead (see docs/gcp-identity.md) and
// fails rather than falling back to another identity.
//
// Access the map through Ordered/Providers/RegisterProvider/
// UnregisterProvider: iterating it directly is not synchronized with
// concurrent registration, and a map has no order. Use Ordered to try the
// providers one after the other.
var DefaultProviders = map[string]Provider{
	"gitlab":  &gitlab.CI{},
	"actions": &github.Actions{},
	"gcp":     &gcp.Provider{},
}

// order lists the names of the providers in the order they are tried.
//
// The providers of CI systems come first: their tokens are scoped to a
// job and are only there when the job was granted one. gcp comes last, as
// the metadata server it falls back to speaks for the machine the process
// runs on, whatever is running there.
var order = []string{"actions", "gitlab", "gcp"}

var mtx sync.RWMutex

// Named is a provider and the name it is registered under.
type Named struct {
	Name     string
	Provider Provider
}

// Ordered returns the registered STS providers in the order they are to
// be tried. The order is always the same: the default providers (actions,
// gitlab, gcp), then the ones added with RegisterProvider in the order
// they were registered.
//
// Providers written to DefaultProviders directly, without RegisterProvider,
// come after all of those, sorted by name.
//
// The result is a snapshot, safe to iterate while other goroutines
// register or unregister providers.
func Ordered() []Named {
	mtx.RLock()
	defer mtx.RUnlock()

	out := make([]Named, 0, len(DefaultProviders))
	for _, name := range order {
		if p, ok := DefaultProviders[name]; ok {
			out = append(out, Named{Name: name, Provider: p})
		}
	}

	if len(out) == len(DefaultProviders) {
		return out
	}

	unordered := make([]string, 0, len(DefaultProviders)-len(out))
	for name := range DefaultProviders {
		if !slices.Contains(order, name) {
			unordered = append(unordered, name)
		}
	}
	slices.Sort(unordered)
	for _, name := range unordered {
		out = append(out, Named{Name: name, Provider: DefaultProviders[name]})
	}
	return out
}

// Select returns the registered providers with the given names, in the
// order the names are given. It is how a caller limits the ambient
// credentials to the providers it expects, or tries them in an order of
// its own.
//
// Without names, Select returns all the providers in the default order,
// as Ordered does. A name that is not registered, or that is given more
// than once, is an error.
func Select(names ...string) ([]Named, error) {
	if len(names) == 0 {
		return Ordered(), nil
	}

	mtx.RLock()
	defer mtx.RUnlock()

	out := make([]Named, 0, len(names))
	for i, name := range names {
		if slices.Contains(names[:i], name) {
			return nil, fmt.Errorf("STS provider %q is listed more than once", name)
		}
		p, ok := DefaultProviders[name]
		if !ok {
			registered := slices.Sorted(maps.Keys(DefaultProviders))
			return nil, fmt.Errorf(
				"unknown STS provider %q (registered: %s)", name, strings.Join(registered, ", "),
			)
		}
		out = append(out, Named{Name: name, Provider: p})
	}
	return out, nil
}

// Providers returns a snapshot of the registered STS providers, safe to
// iterate while other goroutines register or unregister providers.
//
// A map has no order: use Ordered to try the providers one after the
// other.
func Providers() map[string]Provider {
	mtx.RLock()
	defer mtx.RUnlock()

	snapshot := make(map[string]Provider, len(DefaultProviders))
	for k, p := range DefaultProviders {
		snapshot[k] = p
	}
	return snapshot
}

// RegisterProvider registers a provider. A new name is tried after all
// the providers registered before it. Registering under a name that is
// already taken replaces that provider and keeps its place in the order.
func RegisterProvider(key string, p Provider) {
	mtx.Lock()
	defer mtx.Unlock()

	DefaultProviders[key] = p
	if !slices.Contains(order, key) {
		order = append(order, key)
	}
}

// UnregisterProvider removes a registered provider.
func UnregisterProvider(key string, _ Provider) {
	mtx.Lock()
	defer mtx.Unlock()

	delete(DefaultProviders, key)
	if i := slices.Index(order, key); i >= 0 {
		order = slices.Delete(order, i, i+1)
	}
}

type Provider interface {
	Provide(context.Context, string) (*oauthflow.OIDCIDToken, error)
}
