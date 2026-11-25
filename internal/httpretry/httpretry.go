// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package httpretry holds what the signer uses to ride out the passing
// failures of the services it talks to when signing.
package httpretry

import (
	"net/http"
	"time"
)

const (
	// Retries is how many times a request to a signing service is made
	// again after it fails in a way that may pass: four attempts in all.
	Retries = 3

	// delay is the wait before the first retry. It doubles after each
	// attempt.
	delay = time.Second
)

// Transport is an http.RoundTripper that makes a request again when it
// fails before an answer comes back: a refused or reset connection, a
// failed name lookup or TLS handshake.
//
// It leaves answers alone, whatever their status: retrying on a status is
// up to the caller. It does not retry once the context of the request is
// done, which is how the timeout of an http.Client shows up here, and it
// does not retry a request whose body cannot be read again.
//
// The request may reach the server more than once, so Transport is only
// for requests that are safe to repeat.
type Transport struct {
	// Base makes the requests. When nil, http.DefaultTransport is used.
	Base http.RoundTripper

	// Retries is how many times a request is made again. When zero, the
	// Retries constant is used.
	Retries int

	// Delay is the wait before the first retry, doubled after each
	// attempt. When zero, one second is used.
	Delay time.Duration
}

// NewTransport returns a Transport with the defaults.
func NewTransport() *Transport {
	return &Transport{}
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	retries := t.Retries
	if retries == 0 {
		retries = Retries
	}
	wait := t.Delay
	if wait == 0 {
		wait = delay
	}

	// A body that was sent cannot be sent again unless the request says
	// how to get a new one.
	replayable := req.Body == nil || req.Body == http.NoBody || req.GetBody != nil

	attempt := req
	for retry := 0; ; retry++ {
		resp, err := base.RoundTrip(attempt)
		if err == nil {
			return resp, nil
		}
		if !replayable || retry == retries || req.Context().Err() != nil {
			return nil, err
		}

		timer := time.NewTimer(wait)
		select {
		case <-req.Context().Done():
			timer.Stop()
			return nil, err
		case <-timer.C:
		}
		wait *= 2

		// A RoundTripper must not change the request it is given, and
		// the body of the last attempt is spent.
		attempt = req.Clone(req.Context())
		if req.GetBody != nil {
			body, berr := req.GetBody()
			if berr != nil {
				return nil, err
			}
			attempt.Body = body
		}
	}
}
