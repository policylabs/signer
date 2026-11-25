// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The provider reads its configuration from the environment, so these
// tests set it and do not run in parallel.

// reply is what the fake token service answers to one request.
type reply struct {
	status int
	body   string
}

// tokenService serves replies in order, repeating the last one, and
// points the provider at itself. It returns the count of requests made.
func tokenService(t *testing.T, replies ...reply) *atomic.Int32 {
	t.Helper()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(requests.Add(1))
		if r.Header.Get("Authorization") != "bearer request-token" || len(r.Header.Values("Authorization")) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("bad credentials")) //nolint:errcheck // test server
			return
		}
		if r.URL.Query().Get("audience") != "sigstore" || r.URL.Query().Get("api-version") != "2.0" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		rep := replies[min(n, len(replies))-1]
		w.WriteHeader(rep.status)
		_, _ = w.Write([]byte(rep.body)) //nolint:errcheck // test server
	}))
	t.Cleanup(server.Close)

	t.Setenv(VariableGitHubRequestURL, server.URL+"/token?api-version=2.0")
	t.Setenv(VariableGitHubRequestToken, "request-token")
	return &requests
}

// testActions returns a provider that does not wait between attempts.
func testActions() *Actions {
	return &Actions{retryDelay: time.Millisecond}
}

var (
	replyToken    = reply{http.StatusOK, `{"value":"the-token"}`}
	replyNotJSON  = reply{http.StatusOK, "upstream request timeout"}
	replyNoToken  = reply{http.StatusOK, `{"value":""}`}
	replyBusy     = reply{http.StatusServiceUnavailable, "try later"}
	replySlowDown = reply{http.StatusTooManyRequests, "slow down"}
	replyDenied   = reply{http.StatusForbidden, "not allowed"}
)

func TestActionsNotInActions(t *testing.T) {
	t.Setenv(VariableGitHubRequestURL, "")
	token, err := testActions().Provide(t.Context(), "sigstore")
	require.NoError(t, err)
	require.Nil(t, token)
}

func TestActionsProvide(t *testing.T) {
	for _, tc := range []struct {
		name     string
		replies  []reply
		requests int32
		// errs are fragments expected in the error. No fragments, no error.
		errs []string
	}{
		{"first-try", []reply{replyToken}, 1, nil},
		{"after-a-response-that-is-not-json", []reply{replyNotJSON, replyToken}, 2, nil},
		{"after-a-server-error", []reply{replyBusy, replyToken}, 2, nil},
		{"after-being-told-to-slow-down", []reply{replySlowDown, replyToken}, 2, nil},
		{"after-a-response-without-a-token", []reply{replyNoToken, replyToken}, 2, nil},
		{"on-the-last-attempt", []reply{replyBusy, replyNotJSON, replySlowDown, replyToken}, 4, nil},
		{
			"gives-up",
			[]reply{replyBusy},
			4,
			[]string{"fetching GitHub OIDC token", "503 Service Unavailable", `"try later"`},
		},
		{
			"gives-up-on-what-is-not-json",
			[]reply{replyNotJSON},
			4,
			[]string{"decoding response", `"upstream request timeout"`},
		},
		{
			"a-refused-request-is-not-retried",
			[]reply{replyDenied, replyToken},
			1,
			[]string{"403 Forbidden", `"not allowed"`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := tokenService(t, tc.replies...)

			token, err := testActions().Provide(t.Context(), "sigstore")
			require.Equal(t, tc.requests, requests.Load())
			if len(tc.errs) == 0 {
				require.NoError(t, err)
				require.Equal(t, "the-token", token.RawString)
				return
			}
			require.Nil(t, token)
			for _, fragment := range tc.errs {
				require.ErrorContains(t, err, fragment)
			}
		})
	}
}

// A response cut short may hold part of a token, which must not end up
// in an error message.
func TestActionsTruncatedTokenNotQuoted(t *testing.T) {
	tokenService(t, reply{http.StatusOK, `{"value":"secret-part-of-a-tok`})
	_, err := testActions().Provide(t.Context(), "sigstore")
	require.ErrorContains(t, err, "decoding response")
	require.NotContains(t, err.Error(), "secret-part")
}

func TestActionsLongErrorBodyIsCut(t *testing.T) {
	long := make([]byte, 5000)
	for i := range long {
		long[i] = 'x'
	}
	tokenService(t, reply{http.StatusForbidden, string(long)})
	_, err := testActions().Provide(t.Context(), "sigstore")
	require.Error(t, err)
	require.Less(t, len(err.Error()), 400)
}

func TestActionsNetworkError(t *testing.T) {
	// Nothing listens here: the server is closed right away.
	server := httptest.NewServer(http.NotFoundHandler())
	server.Close()
	t.Setenv(VariableGitHubRequestURL, server.URL+"/token?api-version=2.0")
	t.Setenv(VariableGitHubRequestToken, "request-token")

	_, err := testActions().Provide(t.Context(), "sigstore")
	require.ErrorContains(t, err, "fetching GitHub OIDC token")
}

// The wait between attempts ends when the context does.
func TestActionsContextCanceled(t *testing.T) {
	requests := tokenService(t, replyBusy)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := (&Actions{retryDelay: time.Hour}).Provide(ctx, "sigstore")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), 10*time.Second)
	require.Equal(t, int32(1), requests.Load())
}

func TestActionsBadInput(t *testing.T) {
	requests := tokenService(t, replyToken)

	for _, audience := range []string{"", "  ", "a b", "a&b", "a?b", "a#b"} {
		_, err := testActions().Provide(t.Context(), audience)
		require.Error(t, err, "audience %q", audience)
	}

	t.Setenv(VariableGitHubRequestToken, "")
	_, err := testActions().Provide(t.Context(), "sigstore")
	require.ErrorContains(t, err, VariableGitHubRequestToken)

	t.Setenv(VariableGitHubRequestToken, "with space")
	_, err = testActions().Provide(t.Context(), "sigstore")
	require.ErrorContains(t, err, "invalid characters")

	require.Zero(t, requests.Load(), "bad input must not reach the token service")
}

func TestPermanentErrorUnwraps(t *testing.T) {
	t.Parallel()
	inner := errors.New("inner")
	require.ErrorIs(t, permanentError{inner}, inner)
}

func TestHTTP1Client(t *testing.T) {
	t.Parallel()
	client, err := http1Client(http.DefaultClient)
	require.NoError(t, err)
	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	require.False(t, transport.ForceAttemptHTTP2)
	require.Empty(t, transport.TLSNextProto)
	require.NotSame(t, http.DefaultTransport, client.Transport)

	// A transport that is not the standard one cannot be changed.
	_, err = http1Client(&http.Client{Transport: roundTripper(nil)})
	require.Error(t, err)
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
