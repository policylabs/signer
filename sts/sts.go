// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sts

import (
	"context"
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
// Access the map through Providers/RegisterProvider/UnregisterProvider:
// iterating it directly is not synchronized with concurrent registration.
var DefaultProviders = map[string]Provider{
	"gitlab":  &gitlab.CI{},
	"actions": &github.Actions{},
	"gcp":     &gcp.Provider{},
}

var mtx sync.RWMutex

// Providers returns a snapshot of the registered STS providers, safe to
// iterate while other goroutines register or unregister providers.
func Providers() map[string]Provider {
	mtx.RLock()
	defer mtx.RUnlock()

	snapshot := make(map[string]Provider, len(DefaultProviders))
	for k, p := range DefaultProviders {
		snapshot[k] = p
	}
	return snapshot
}

// RegisterProvider registers a new provider
func RegisterProvider(key string, p Provider) {
	mtx.Lock()
	DefaultProviders[key] = p
	mtx.Unlock()
}

// UnregisterProvider removes a registered provider
func UnregisterProvider(key string, _ Provider) {
	mtx.Lock()
	delete(DefaultProviders, key)
	mtx.Unlock()
}

type Provider interface {
	Provide(context.Context, string) (*oauthflow.OIDCIDToken, error)
}
