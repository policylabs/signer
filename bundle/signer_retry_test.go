// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// A timestamp authority that drops a connection is asked again.
func TestTimestampAuthorityRetriesDroppedConnections(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			// Hang up without answering.
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Error("cannot hijack the connection")
				return
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			conn.Close() //nolint:errcheck,gosec // test server
			return
		}
		// Not a timestamp: what matters is that the request came again.
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(server.Close)

	_, err := newTimestampAuthority(server.URL).GetTimestamp(t.Context(), []byte("signature"))
	require.Error(t, err, "the server never answers with a timestamp")
	require.Equal(t, int32(2), requests.Load())
}
