// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sigstore

import (
	"context"
	"errors"
	"testing"

	"github.com/sigstore/sigstore/pkg/oauthflow"
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
