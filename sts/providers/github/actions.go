// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package github implements a client to requesta short lived token
// from github actions.
//
// Shamelessly stolen from https://pkg.go.dev/github.com/sigstore/cosign/v2/pkg/providers/github
// but adapted here to avoid pulling down all sigstore/cosign and, thus, the world.
package github

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sirupsen/logrus"
)

const (
	VariableGitHubRequestURL   = "ACTIONS_ID_TOKEN_REQUEST_URL"
	VariableGitHubRequestToken = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
)

const (
	// maxAttempts is how many times the token is asked for before giving
	// up. The token service of GitHub fails now and then with errors that
	// go away when asked again.
	maxAttempts = 4

	// retryDelay is the wait before the second attempt. It doubles after
	// each attempt, so all the attempts take about seven seconds of
	// waiting.
	retryDelay = time.Second

	// attemptTimeout bounds each request: the default HTTP client has no
	// timeout of its own.
	attemptTimeout = 30 * time.Second

	// maxResponseSize bounds how much of a response is read. Tokens are a
	// few kilobytes.
	maxResponseSize = 1 << 20

	// maxErrorBody is how much of an unexpected response is quoted in an
	// error.
	maxErrorBody = 200
)

// Actions gets OIDC tokens from GitHub Actions. The zero value is ready
// to use.
type Actions struct {
	// Client makes the requests. When nil, http.DefaultClient is used.
	Client *http.Client

	// retryDelay replaces the wait before the second attempt, for tests.
	retryDelay time.Duration
}

// permanentError marks the failures that asking again will not fix.
type permanentError struct{ error }

func (e permanentError) Unwrap() error { return e.error }

// Provide requests a token from GitHub Actions. It returns no token when
// the process is not running in a job that can ask for one.
//
// Failures that are likely to go away are retried a few times, waiting
// longer after each attempt: network errors, responses with a 5xx or 429
// status, and responses that do not carry a token. Other failures, such
// as a rejected request token, are returned right away.
func (actions *Actions) Provide(ctx context.Context, audience string) (*oauthflow.OIDCIDToken, error) {
	// Get the request URL from the environment vars
	url := os.Getenv(VariableGitHubRequestURL)
	if url == "" {
		return nil, nil
	}

	audience = strings.TrimSpace(audience)
	if audience == "" {
		return nil, fmt.Errorf("audience string must not be empty")
	}
	if strings.ContainsAny(audience, " \t\n\r&?#") {
		return nil, fmt.Errorf("audience string contains invalid characters")
	}

	requestToken := os.Getenv(VariableGitHubRequestToken)
	if requestToken == "" {
		return nil, fmt.Errorf("GitHub actions request token (%s) not set", VariableGitHubRequestToken)
	}
	if strings.ContainsAny(requestToken, " \t\n\r") {
		return nil, fmt.Errorf("GitHub actions request token contains invalid characters")
	}

	// May be replaced by a different client if we hit HTTP_1_1_REQUIRED.
	client := actions.Client
	if client == nil {
		client = http.DefaultClient
	}

	delay := actions.retryDelay
	if delay == 0 {
		delay = retryDelay
	}

	endpoint := fmt.Sprintf("%s&audience=%s", url, audience)
	for attempt := 1; ; attempt++ {
		raw, err := fetchToken(ctx, client, endpoint, requestToken)
		if err == nil {
			return &oauthflow.OIDCIDToken{
				RawString: raw,
				Subject:   "", // TODO(puerco): Perhaps parse and populate here
			}, nil
		}

		var permanent permanentError
		if errors.As(err, &permanent) || attempt == maxAttempts || ctx.Err() != nil {
			return nil, fmt.Errorf("fetching GitHub OIDC token: %w", err)
		}

		// This error isn't exposed by net/http, and retrying this with the
		// same client will fail because it will just use HTTP2 again.
		// I don't know why go doesn't do this for us.
		if strings.Contains(err.Error(), "HTTP_1_1_REQUIRED") {
			http1, herr := http1Client(client)
			if herr != nil {
				// If the transport cannot be changed to HTTP/1.1 there is
				// no point in retrying.
				return nil, fmt.Errorf("fetching GitHub OIDC token: %w", err)
			}
			client = http1
		}

		logrus.Warnf("error fetching GitHub OIDC token (attempt %d of %d, will retry): %v", attempt, maxAttempts, err)

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, fmt.Errorf("fetching GitHub OIDC token: %w", ctx.Err())
		case <-timer.C:
		}
		delay *= 2
	}
}

// fetchToken asks for the token once. The errors that asking again
// will not fix are returned as permanentError.
func fetchToken(ctx context.Context, client *http.Client, endpoint, requestToken string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody) //nolint:gosec // G704: URL comes from trusted ACTIONS_ID_TOKEN_REQUEST_URL env var
	if err != nil {
		return "", permanentError{err}
	}
	req.Header.Set("Authorization", "bearer "+requestToken)

	//nolint:gosec // G704 The token is validated by the caller
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("unexpected status %s: %s", resp.Status, quoteBody(body))
		// The server failing or asking to slow down may pass. Anything
		// else is the request being refused.
		if resp.StatusCode >= http.StatusInternalServerError || resp.StatusCode == http.StatusTooManyRequests {
			return "", err
		}
		return "", permanentError{err}
	}

	var payload struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		// A response cut short can hold part of a token: quote it only
		// when it is clearly something else.
		if bytes.Contains(body, []byte(`"value"`)) {
			return "", fmt.Errorf("decoding response: %w", err)
		}
		return "", fmt.Errorf("decoding response: %w: %s", err, quoteBody(body))
	}
	if payload.Value == "" {
		return "", fmt.Errorf("response carries no token: %s", quoteBody(body))
	}
	return payload.Value, nil
}

// http1Client returns a copy of client that does not attempt HTTP/2.
func http1Client(client *http.Client) (*http.Client, error) {
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	t, ok := transport.(*http.Transport)
	if !ok {
		return nil, errors.New("HTTP transport cannot be changed to HTTP/1.1")
	}
	http1 := t.Clone()
	http1.ForceAttemptHTTP2 = false
	http1.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}

	clone := *client
	clone.Transport = http1
	return &clone, nil
}

// quoteBody returns the start of an unexpected response, to tell what
// answered in an error message.
func quoteBody(body []byte) string {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return "empty response"
	}
	if len(text) > maxErrorBody {
		text = text[:maxErrorBody] + "..."
	}
	return fmt.Sprintf("%q", text)
}
