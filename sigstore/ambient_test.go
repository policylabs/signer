// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sigstore

import (
	"context"
	"errors"
	"testing"

	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"

	"github.com/policylabs/signer/sts"
)

// recordingProvider answers with a fixed token or error and records that
// it was asked, in calls.
type recordingProvider struct {
	name  string
	token *oauthflow.OIDCIDToken
	err   error
	calls *[]string
}

func (r *recordingProvider) Provide(_ context.Context, audience string) (*oauthflow.OIDCIDToken, error) {
	*r.calls = append(*r.calls, r.name+"/"+audience)
	return r.token, r.err
}

func TestFirstAmbientToken(t *testing.T) {
	t.Parallel()
	tokenB := &oauthflow.OIDCIDToken{RawString: "b"}
	tokenC := &oauthflow.OIDCIDToken{RawString: "c"}
	errBroken := errors.New("broken")

	for _, tc := range []struct {
		name string
		// what each of the providers a, b and c answers, in that order
		tokens []*oauthflow.OIDCIDToken
		errs   []error

		expect    *oauthflow.OIDCIDToken
		expectErr string
		asked     []string
	}{
		{
			name:   "first-token-wins",
			tokens: []*oauthflow.OIDCIDToken{nil, tokenB, tokenC},
			errs:   []error{nil, nil, nil},
			expect: tokenB,
			asked:  []string{"a/aud", "b/aud"},
		},
		{
			name:   "nobody-has-credentials",
			tokens: []*oauthflow.OIDCIDToken{nil, nil, nil},
			errs:   []error{nil, nil, nil},
			asked:  []string{"a/aud", "b/aud", "c/aud"},
		},
		{
			name:      "an-error-ends-the-search",
			tokens:    []*oauthflow.OIDCIDToken{nil, nil, tokenC},
			errs:      []error{nil, errBroken, nil},
			expectErr: "trying ambient credentials from b: broken",
			asked:     []string{"a/aud", "b/aud"},
		},
		{
			name:   "a-failing-provider-after-the-token-is-not-asked",
			tokens: []*oauthflow.OIDCIDToken{nil, tokenB, nil},
			errs:   []error{nil, nil, errBroken},
			expect: tokenB,
			asked:  []string{"a/aud", "b/aud"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			calls := []string{}
			providers := make([]sts.Named, 0, 3)
			for i, name := range []string{"a", "b", "c"} {
				providers = append(providers, sts.Named{
					Name: name,
					Provider: &recordingProvider{
						name: name, token: tc.tokens[i], err: tc.errs[i], calls: &calls,
					},
				})
			}

			token, err := firstAmbientToken(t.Context(), providers, "aud")
			if tc.expectErr != "" {
				require.EqualError(t, err, tc.expectErr)
				require.ErrorIs(t, err, errBroken)
			} else {
				require.NoError(t, err)
			}
			require.Same(t, tc.expect, token)
			require.Equal(t, tc.asked, calls)
		})
	}

	t.Run("no-providers", func(t *testing.T) {
		t.Parallel()
		token, err := firstAmbientToken(t.Context(), nil, "aud")
		require.NoError(t, err)
		require.Nil(t, token)
	})
}

// TestRunAmbientSTSProviders checks that the providers named in
// STSProviders are the only ones asked, in the order they are named.
//
// It registers providers in the registry, which is global: it does not
// run in parallel, so no other test sees them.
func TestRunAmbientSTSProviders(t *testing.T) { //nolint:paralleltest // global registry
	calls := []string{}
	register := func(name string, token *oauthflow.OIDCIDToken) {
		sts.RegisterProvider(name, &recordingProvider{name: name, token: token, calls: &calls})
		t.Cleanup(func() { sts.UnregisterProvider(name, nil) })
	}
	tokenB := &oauthflow.OIDCIDToken{RawString: "b"}
	tokenC := &oauthflow.OIDCIDToken{RawString: "c"}
	register("test-a", nil)
	register("test-b", tokenB)
	register("test-c", tokenC)

	newProvider := func(names ...string) *CredentialProvider {
		return &CredentialProvider{
			Instance:     &Instance{OIDCConfig: OIDCConfig{ClientID: "aud"}},
			STSProviders: names,
		}
	}

	for _, tc := range []struct {
		name   string
		names  []string
		expect *oauthflow.OIDCIDToken
		asked  []string
	}{
		{"one", []string{"test-c"}, tokenC, []string{"test-c/aud"}},
		{"in-the-order-given", []string{"test-c", "test-b"}, tokenC, []string{"test-c/aud"}},
		{"reversed", []string{"test-a", "test-b", "test-c"}, tokenB, []string{"test-a/aud", "test-b/aud"}},
		{"none-has-credentials", []string{"test-a"}, nil, []string{"test-a/aud"}},
	} {
		t.Run(tc.name, func(t *testing.T) { //nolint:paralleltest // global registry
			calls = calls[:0]
			token, err := newProvider(tc.names...).runAmbientSTS(t.Context())
			require.NoError(t, err)
			require.Same(t, tc.expect, token)
			require.Equal(t, tc.asked, calls)
		})
	}

	t.Run("unknown-provider", func(t *testing.T) { //nolint:paralleltest // global registry
		calls = calls[:0]
		_, err := newProvider("test-a", "test-nope").runAmbientSTS(t.Context())
		require.ErrorContains(t, err, `unknown STS provider "test-nope"`)
		// Nobody is asked when the list is wrong.
		require.Empty(t, calls)
	})
}

// TestFirstAmbientTokenLogs checks that the provider the token came from
// is logged, and the token is not.
//
// It hooks into the global logger: it does not run in parallel.
func TestFirstAmbientTokenLogs(t *testing.T) { //nolint:paralleltest // global logger
	hook := logrustest.NewGlobal()
	level := logrus.GetLevel()
	logrus.SetLevel(logrus.DebugLevel)
	t.Cleanup(func() {
		logrus.SetLevel(level)
		logrus.StandardLogger().ReplaceHooks(logrus.LevelHooks{})
	})

	calls := []string{}
	providers := []sts.Named{
		{Name: "first", Provider: &recordingProvider{name: "first", calls: &calls}},
		{Name: "second", Provider: &recordingProvider{
			name: "second", token: &oauthflow.OIDCIDToken{RawString: "secret-token"}, calls: &calls,
		}},
	}

	messages := func() []string {
		entries := hook.AllEntries()
		out := make([]string, 0, len(entries))
		for _, entry := range entries {
			require.Equal(t, logrus.DebugLevel, entry.Level)
			require.NotContains(t, entry.Message, "secret-token")
			out = append(out, entry.Message)
		}
		hook.Reset()
		return out
	}

	_, err := firstAmbientToken(t.Context(), providers, "aud")
	require.NoError(t, err)
	require.Equal(t, []string{"using ambient credentials from the second STS provider"}, messages())

	_, err = firstAmbientToken(t.Context(), providers[:1], "aud")
	require.NoError(t, err)
	require.Equal(t, []string{"no ambient credentials found (1 STS providers tried)"}, messages())
}
