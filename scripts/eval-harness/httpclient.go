// httpclient.go is this harness's thin, dependency-free wrapper over the
// hub's plain-REST API — deliberately not importing internal/api (this
// harness is meant to drive the hub exactly the way a real caller over the
// network would, the same posture scripts/smoke-test.sh's curl calls take,
// just in Go instead of bash).
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type apiClient struct {
	baseURL     string
	accessToken string
	http        *http.Client

	// email/password are kept so the client can re-authenticate itself
	// mid-run. An access token lives 15 minutes (internal/authz.
	// AccessTokenTTL) and a full real-model corpus pass takes longer than
	// that — the first run of this path died on a 401 twenty-three cases in,
	// having already paid for every one of them. Re-login on 401 is the fix
	// that keeps working however long the corpus grows, where refreshing on
	// a timer would only move the cliff.
	email, password string
	// reauthenticating guards the one retry against recursing: a 401 from
	// the login call itself must surface, not trigger another login.
	reauthenticating bool

	// analyzeWait bounds how long postAnalyze polls for one investigation
	// to land. POST /incidents/{id}/analyze answers 202 at once and the hub
	// investigates in the background (PROJECT.md M1), bounded by the resolved
	// analysis time limit (180s in the dev compose profile) plus a grace
	// margin — so every request here stays a normal short REST round trip,
	// and this is the one longer wait, on the incident rather than on a
	// socket. Too short a wait reports a failure the run did not have, on an
	// analysis it has already paid for.
	analyzeWait time.Duration
}

func newAPIClient(baseURL string, analyzeTimeout time.Duration) *apiClient {
	return &apiClient{
		baseURL:     baseURL,
		http:        &http.Client{Timeout: 30 * time.Second},
		analyzeWait: analyzeTimeout,
	}
}

// do sends one request and, on a non-2xx status, returns an error carrying
// the response body so a failure is diagnosable without a debugger.
func (c *apiClient) do(method, path string, body any, out any) (int, error) {
	return c.doWith(method, path, body, out)
}

func (c *apiClient) doWith(method, path string, body any, out any) (int, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, fmt.Errorf("marshal request body: %w", err)
		}
		reader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, c.baseURL+path, reader)
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	if reader != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, fmt.Errorf("%s %s: read response: %w", method, path, err)
	}

	// An expired access token is an expected condition on a run that lasts
	// longer than 15 minutes, not a failure — log in again and send the
	// request once more. Anything else, including a second 401, is reported.
	if resp.StatusCode == http.StatusUnauthorized && c.email != "" && !c.reauthenticating {
		c.reauthenticating = true
		loginErr := c.login(c.email, c.password)
		c.reauthenticating = false
		if loginErr != nil {
			return resp.StatusCode, fmt.Errorf("%s %s: access token rejected and re-login failed: %w", method, path, loginErr)
		}
		log.Printf("eval-harness: access token had expired; logged in again and retrying %s %s", method, path)
		return c.doWith(method, path, body, out)
	}

	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("%s %s: unexpected status %d: %s", method, path, resp.StatusCode, string(respBody))
	}

	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return resp.StatusCode, fmt.Errorf("%s %s: parse response: %w (body: %s)", method, path, err, string(respBody))
		}
	}
	return resp.StatusCode, nil
}

func (c *apiClient) post(path string, body, out any) (int, error) {
	return c.do(http.MethodPost, path, body, out)
}

func (c *apiClient) get(path string, out any) (int, error) {
	return c.do(http.MethodGet, path, nil, out)
}
func (c *apiClient) put(path string, body, out any) (int, error) {
	return c.do(http.MethodPut, path, body, out)
}
