// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package httpretry

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var errConnection = errors.New("connection reset by peer")

// flaky fails the first failures requests before they reach next, and
// records the bodies it was handed.
type flaky struct {
	next     http.RoundTripper
	failures int32
	calls    atomic.Int32
	bodies   []string
}

func (f *flaky) RoundTrip(req *http.Request) (*http.Response, error) {
	n := f.calls.Add(1)
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body.Close() //nolint:errcheck,gosec // test
		f.bodies = append(f.bodies, string(body))
		req = req.Clone(req.Context())
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	if n <= f.failures {
		return nil, errConnection
	}
	return f.next.RoundTrip(req)
}

// echoServer answers with the status asked for in the path and the body
// it received.
func echoServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body) //nolint:errcheck // test server
		if r.URL.Path == "/busy" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_, _ = w.Write(body) //nolint:errcheck // test server
	}))
	t.Cleanup(server.Close)
	return server
}

func newClient(f *flaky) *http.Client {
	return &http.Client{Transport: &Transport{Base: f, Retries: 3, Delay: time.Millisecond}}
}

func post(t *testing.T, client *http.Client, url, body string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, strings.NewReader(body))
	require.NoError(t, err)
	return client.Do(req)
}

func TestTransportRetriesConnectionErrors(t *testing.T) {
	t.Parallel()
	server := echoServer(t)

	for _, tc := range []struct {
		name     string
		failures int32
		calls    int32
		fails    bool
	}{
		{"no-failure", 0, 1, false},
		{"one-failure", 1, 2, false},
		{"as-many-failures-as-retries", 3, 4, false},
		{"one-failure-too-many", 4, 4, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &flaky{next: http.DefaultTransport, failures: tc.failures}
			resp, err := post(t, newClient(f), server.URL, "the body")
			require.Equal(t, tc.calls, f.calls.Load())
			if tc.fails {
				require.ErrorIs(t, err, errConnection)
				return
			}
			require.NoError(t, err)
			defer resp.Body.Close() //nolint:errcheck // test

			// Every attempt carried the whole body.
			got, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equal(t, "the body", string(got))
			for _, body := range f.bodies {
				require.Equal(t, "the body", body)
			}
		})
	}
}

// An answer is not retried, whatever its status.
func TestTransportLeavesAnswersAlone(t *testing.T) {
	t.Parallel()
	server := echoServer(t)
	f := &flaky{next: http.DefaultTransport}

	resp, err := post(t, newClient(f), server.URL+"/busy", "x")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // test
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	require.Equal(t, int32(1), f.calls.Load())
}

func TestTransportGet(t *testing.T) {
	t.Parallel()
	server := echoServer(t)
	f := &flaky{next: http.DefaultTransport, failures: 2}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, http.NoBody)
	require.NoError(t, err)
	resp, err := newClient(f).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // test
	require.Equal(t, int32(3), f.calls.Load())
}

// A body that cannot be read again is sent once.
func TestTransportBodyThatCannotBeReplayed(t *testing.T) {
	t.Parallel()
	server := echoServer(t)
	f := &flaky{next: http.DefaultTransport, failures: 1}

	// A reader of a type the http package cannot rewind.
	body := io.NopCloser(strings.NewReader("once"))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL, body)
	require.NoError(t, err)
	require.Nil(t, req.GetBody)

	_, err = newClient(f).Do(req) //nolint:bodyclose // no response
	require.ErrorIs(t, err, errConnection)
	require.Equal(t, int32(1), f.calls.Load())
}

// The timeout of the client ends the retries.
func TestTransportStopsWhenTheContextIsDone(t *testing.T) {
	t.Parallel()
	f := &flaky{next: http.DefaultTransport, failures: 100}

	t.Run("while-waiting", func(t *testing.T) {
		t.Parallel()
		client := &http.Client{
			Transport: &Transport{Base: f, Retries: 3, Delay: time.Hour},
			Timeout:   50 * time.Millisecond,
		}
		start := time.Now()
		_, err := post(t, client, "http://signer.invalid", "x") //nolint:bodyclose // no response
		require.Error(t, err)
		require.Less(t, time.Since(start), 10*time.Second)
	})

	t.Run("already-done", func(t *testing.T) {
		t.Parallel()
		calls := &flaky{next: http.DefaultTransport, failures: 100}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://signer.invalid", http.NoBody)
		require.NoError(t, err)
		_, err = (&Transport{Base: calls, Delay: time.Millisecond}).RoundTrip(req) //nolint:bodyclose // no response
		require.ErrorIs(t, err, errConnection)
		require.Equal(t, int32(1), calls.calls.Load())
	})
}

func TestTransportDefaults(t *testing.T) {
	t.Parallel()
	// The zero value retries the default number of times.
	f := &flaky{next: http.DefaultTransport, failures: 100}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://signer.invalid", http.NoBody)
	require.NoError(t, err)
	_, err = (&Transport{Base: f, Delay: time.Millisecond}).RoundTrip(req) //nolint:bodyclose // no response
	require.ErrorIs(t, err, errConnection)
	require.Equal(t, int32(Retries+1), f.calls.Load())

	require.Nil(t, NewTransport().Base)
}
