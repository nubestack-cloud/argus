package llm

// Tests for probe.go's error classification — the part of the connection-test
// feature that has real logic in it. The classification IS the feature: a probe
// that reports "failed" would be worse than no probe, so every distinguishable
// failure mode gets a test that pins it to its own ProbeResult.Kind.
//
// **Nothing here makes a live call to a real provider.** Every case is either
// an httptest server on localhost, a deliberately-broken local address, or a
// synthesized Go error handed straight to the classifier. The one path this
// suite cannot cover is a genuine paid endpoint answering correctly — see the
// note on TestProbeAPISuccess for what stands in for it and why that is the
// right trade.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"

	"argus/internal/outbound"
)

// testLoopbackProbeClient is the test-only seam for the handful of cases
// below that need a REAL transport-level failure (connection refused, an
// untrusted TLS cert, a scheme mismatch) against an httptest server on
// 127.0.0.1. probeAPIClient's production default now shares
// aiProviderOutboundPolicy (default-deny) with the real completion path —
// see that policy's own comment on why probe and the real path must never
// silently disagree — so these tests pass an explicit, loopback-allowing
// client instead of relying on nil/the production default, exactly as the
// coordinator's fix instructions asked: point the test at the policy
// explicitly rather than weakening the production default to pass it. The
// client is otherwise a real hardened transport (real TLS verification,
// real dialing), so the failure mode under test is still genuine, not
// faked.
func testLoopbackProbeClient() *http.Client {
	return outbound.NewClient(outbound.Policy{AllowPrivate: true, Reason: "test: httptest servers bind to 127.0.0.1"}, 0)
}

// apiTarget is a ProbeTarget pointed at an httptest server, with a key long
// enough that redactSecret does not skip it.
func apiTarget(baseURL, model string) ProbeTarget {
	return ProbeTarget{Kind: "api", BaseURL: baseURL, Model: model, APIKey: "sk-test-secret-value-1234567890"}
}

// TestProbeAPIStatusClassification walks every HTTP outcome an
// OpenAI-compatible endpoint can produce and asserts the probe names the right
// one. The table is the requirement list: not configured, 401, 403, 404 (both
// meanings), 429, model-not-found across four statuses, and a 2xx that does
// not parse.
func TestProbeAPIStatusClassification(t *testing.T) {
	tests := []struct {
		name string
		// status/body/headers the fake provider returns.
		status  int
		body    string
		headers map[string]string
		model   string

		wantKind string
		// wantDetailContains is asserted so a case cannot pass with the right
		// classification and a message that fails to say what to do.
		wantDetailContains string
	}{
		{
			name:               "401 with a key configured blames the key",
			status:             401,
			body:               `{"error":{"message":"Incorrect API key provided","type":"invalid_request_error","code":"invalid_api_key"}}`,
			wantKind:           ProbeUnauthorized,
			wantDetailContains: "Incorrect API key provided",
		},
		{
			name:               "403 is a scope problem, not a bad key",
			status:             403,
			body:               `{"error":{"message":"Project does not have access to this resource"}}`,
			wantKind:           ProbeForbidden,
			wantDetailContains: "permissions or entitlement problem",
		},
		{
			name:               "403 carrying rate-limit markers is throttling, not permissions",
			status:             403,
			body:               `{"error":{"message":"Rate limit reached for this organisation"}}`,
			headers:            map[string]string{"X-RateLimit-Remaining": "0"},
			wantKind:           ProbeRateLimited,
			wantDetailContains: "Nothing is misconfigured",
		},
		{
			name:               "404 with no model hint blames the base URL",
			status:             404,
			body:               `{"detail":"Not Found"}`,
			wantKind:           ProbeEndpointNotFound,
			wantDetailContains: "part BEFORE /chat/completions",
		},
		{
			name:               "404 naming the model blames the model",
			status:             404,
			body:               `{"error":{"message":"The model ` + "`gpt-nope`" + ` does not exist","code":"model_not_found"}}`,
			model:              "gpt-nope",
			wantKind:           ProbeModelNotFound,
			wantDetailContains: "only the model name is wrong",
		},
		{
			name:               "400 naming the model blames the model, not the request",
			status:             400,
			body:               `{"error":{"message":"model 'llama3' not found, try pulling it first"}}`,
			model:              "llama3",
			wantKind:           ProbeModelNotFound,
			wantDetailContains: "case-sensitive and provider-specific",
		},
		{
			name:               "422 naming the model blames the model",
			status:             422,
			body:               `{"message":"unknown model: mistral-x"}`,
			model:              "mistral-x",
			wantKind:           ProbeModelNotFound,
			wantDetailContains: "the address is right",
		},
		{
			name:               "403 naming the model blames the model",
			status:             403,
			body:               `{"error":{"message":"You do not have access to model claude-x; model_not_available"}}`,
			model:              "claude-x",
			wantKind:           ProbeModelNotFound,
			wantDetailContains: "only the model name is wrong",
		},
		{
			name:               "429 says explicitly that nothing is misconfigured",
			status:             429,
			body:               `{"error":{"message":"Rate limit exceeded"}}`,
			headers:            map[string]string{"Retry-After": "30"},
			wantKind:           ProbeRateLimited,
			wantDetailContains: "30-second wait",
		},
		{
			name:               "400 that is not about the model passes the provider's words through",
			status:             400,
			body:               `{"error":{"message":"messages: at least one message is required"}}`,
			model:              "some-model",
			wantKind:           ProbeRejected,
			wantDetailContains: "at least one message is required",
		},
		{
			name:               "400 with no model configured says so",
			status:             400,
			body:               `{"error":{"message":"you must provide a model parameter"}}`,
			model:              "",
			wantKind:           ProbeRejected,
			wantDetailContains: "no model name configured",
		},
		{
			name:               "503 blames the endpoint, not the configuration",
			status:             503,
			body:               `upstream connect error`,
			wantKind:           ProbeProviderError,
			wantDetailContains: "Nothing on this side needs changing",
		},
		{
			name:               "200 with an HTML page is a malformed response",
			status:             200,
			body:               `<html><head><title>Sign in</title></head><body>Please log in</body></html>`,
			headers:            map[string]string{"Content-Type": "text/html; charset=utf-8"},
			wantKind:           ProbeMalformedResponse,
			wantDetailContains: "not a chat completion",
		},
		{
			name:               "200 with JSON that is not a completion is a malformed response",
			status:             200,
			body:               `{"status":"ok"}`,
			headers:            map[string]string{"Content-Type": "application/json"},
			wantKind:           ProbeMalformedResponse,
			wantDetailContains: "no `choices` array",
		},
		{
			name:               "302 is reported rather than followed",
			status:             302,
			body:               ``,
			headers:            map[string]string{"Location": "https://login.example.test/sso?token=abc"},
			wantKind:           ProbeRedirected,
			wantDetailContains: "would send the API key",
		},
		{
			name:               "405 means something is there and it is not this API",
			status:             405,
			body:               "Method Not Allowed",
			wantKind:           ProbeEndpointNotFound,
			wantDetailContains: "refused the POST",
		},
		{
			name:               "418 falls through to an honest unknown",
			status:             418,
			body:               `nope`,
			wantKind:           ProbeUnexpectedStatus,
			wantDetailContains: "not a status an OpenAI-compatible",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for k, v := range tc.headers {
					w.Header().Set(k, v)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			got := ProbeProvider(t.Context(), srv.Client(), apiTarget(srv.URL, tc.model))
			if got.OK {
				t.Fatalf("OK = true, want a classified failure (kind %q)", got.Kind)
			}
			if got.Kind != tc.wantKind {
				t.Errorf("Kind = %q, want %q\nsummary: %s\ndetail: %s", got.Kind, tc.wantKind, got.Summary, got.Detail)
			}
			if !strings.Contains(got.Detail, tc.wantDetailContains) {
				t.Errorf("Detail does not mention %q; got: %s", tc.wantDetailContains, got.Detail)
			}
			if strings.TrimSpace(got.Summary) == "" {
				t.Error("Summary is empty — every failure must name what happened")
			}
		})
	}
}

// TestProbeAPI401WithoutKeyBlamesTheMissingKey is the same status as the table
// case above with the opposite configuration, and it must say something
// different: "your key is wrong" and "you have no key" have different fixes.
func TestProbeAPI401WithoutKeyBlamesTheMissingKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
	}))
	defer srv.Close()

	got := ProbeProvider(t.Context(), srv.Client(), ProbeTarget{Kind: "api", BaseURL: srv.URL, Model: "m"})
	if got.Kind != ProbeUnauthorized {
		t.Fatalf("Kind = %q, want %q", got.Kind, ProbeUnauthorized)
	}
	if !strings.Contains(got.Detail, "No API key is configured") {
		t.Errorf("detail should say the provider has no key at all; got: %s", got.Detail)
	}
}

// TestProbeAPISuccess is the closest this suite can get to a real provider
// answering: the fake endpoint returns exactly the wire shape a real one does.
// It stands in for the paid call deliberately — the whole point of a
// cost-conscious probe is undermined by a test suite that spends money, and a
// live call would also make the suite depend on a working key in CI.
func TestProbeAPISuccess(t *testing.T) {
	var gotAuth, gotPath string
	var gotReq probeRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotReq)
		w.Header().Set("Content-Type", "application/json")
		// max_tokens=1 legitimately yields an empty or one-character content;
		// the empty string here is the realistic case and must still pass.
		_, _ = w.Write([]byte(`{"model":"served-model","choices":[{"message":{"role":"assistant","content":""}}],"usage":{"prompt_tokens":9,"completion_tokens":1}}`))
	}))
	defer srv.Close()

	got := ProbeProvider(t.Context(), srv.Client(), apiTarget(srv.URL, "served-model"))
	if !got.OK || got.Kind != ProbeOK {
		t.Fatalf("OK/Kind = %v/%q, want true/%q (detail: %s)", got.OK, got.Kind, ProbeOK, got.Detail)
	}
	if gotPath != "/chat/completions" {
		t.Errorf("posted to %q, want /chat/completions appended to the base URL", gotPath)
	}
	if gotAuth != "Bearer sk-test-secret-value-1234567890" {
		t.Errorf("Authorization = %q, want the configured key as a bearer token", gotAuth)
	}
	// The cost guarantees, asserted rather than trusted to a comment.
	if gotReq.MaxTokens != 1 {
		t.Errorf("max_tokens = %d, want 1 — the generation cap is the cost control", gotReq.MaxTokens)
	}
	if len(gotReq.Messages) != 1 || gotReq.Messages[0].Role != "user" {
		t.Errorf("messages = %+v, want exactly one user message and no system prompt", gotReq.Messages)
	}
	if len(gotReq.Messages[0].Content) > 8 {
		t.Errorf("prompt is %q — the probe prompt must stay tiny", gotReq.Messages[0].Content)
	}
	if got.TokensIn != 9 || got.TokensOut != 1 {
		t.Errorf("tokens = %d/%d, want the provider's reported 9/1", got.TokensIn, got.TokensOut)
	}
	if got.Caveat == "" {
		t.Error("a pass must state what it did not prove")
	}
}

// TestProbeAPISuccessFlagsModelSubstitution covers the silent misconfiguration
// nothing else would catch: the endpoint works, and is serving a different
// model than the one configured. A plain green tick here would hide it forever.
func TestProbeAPISuccessFlagsModelSubstitution(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"model":"whatever-is-loaded","choices":[{"message":{"content":"h"}}]}`))
	}))
	defer srv.Close()

	got := ProbeProvider(t.Context(), srv.Client(), apiTarget(srv.URL, "the-model-i-asked-for"))
	if !got.OK {
		t.Fatalf("want a pass, got %q: %s", got.Kind, got.Detail)
	}
	if !strings.Contains(got.Summary, "different model") {
		t.Errorf("summary should flag the substitution; got: %s", got.Summary)
	}
	if got.Model != "whatever-is-loaded" {
		t.Errorf("Model = %q, want the model the provider named", got.Model)
	}
}

// TestProbeNotConfigured covers both kinds' pre-flight refusal: no network call
// at all when the one indispensable field is empty.
func TestProbeNotConfigured(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target ProbeTarget
		want   string
	}{
		{"api with no base URL", ProbeTarget{Kind: "api", Model: "m", APIKey: "k"}, "no base URL"},
		{"cli with no runner URL", ProbeTarget{Kind: "cli", Agent: "claude"}, "no runner URL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ProbeProvider(t.Context(), nil, tc.target)
			if got.Kind != ProbeNotConfigured {
				t.Fatalf("Kind = %q, want %q", got.Kind, ProbeNotConfigured)
			}
			if !strings.Contains(got.Summary, tc.want) {
				t.Errorf("summary %q should mention %q", got.Summary, tc.want)
			}
		})
	}
}

// TestProbeRejectsUnusableURLs is the fix for a real misclassification found by
// testing against the live hub: http.NewRequest accepts a relative URL and only
// Do() fails, with "unsupported protocol scheme" — which was reported as a
// network failure. A missing "https://" is a configuration typo and must be
// named as one, since the two send an operator to completely different places.
func TestProbeRejectsUnusableURLs(t *testing.T) {
	for _, tc := range []struct {
		name, raw, wantReason string
		kind                  string
	}{
		{"bare hostname", "api.openai.com/v1", "no scheme", "api"},
		{"unsupported scheme", "ftp://api.example.test/v1", "only http and https", "api"},
		{"scheme with no host", "http:///v1", "no host", "api"},
		{"runner with a bare hostname", "argus-cli-runner:8090", "no scheme", "cli"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := ProbeTarget{Kind: tc.kind, Model: "m"}
			if tc.kind == "api" {
				target.BaseURL = tc.raw
			} else {
				target.RunnerURL = tc.raw
			}
			got := ProbeProvider(t.Context(), nil, target)
			if got.Kind != ProbeNotConfigured {
				t.Fatalf("Kind = %q, want %q (detail: %s)", got.Kind, ProbeNotConfigured, got.Detail)
			}
			if !strings.Contains(got.Detail, tc.wantReason) {
				t.Errorf("detail should say %q; got: %s", tc.wantReason, got.Detail)
			}
		})
	}
}

// TestProbeUnsupportedKind: the requirement is that the probe works for
// whichever kind is active OR says clearly it cannot test that kind. This is
// the second half.
func TestProbeUnsupportedKind(t *testing.T) {
	got := ProbeProvider(t.Context(), nil, ProbeTarget{Kind: "telepathy"})
	if got.Kind != ProbeUnsupportedKind {
		t.Fatalf("Kind = %q, want %q", got.Kind, ProbeUnsupportedKind)
	}
	if !strings.Contains(got.Summary, "telepathy") {
		t.Errorf("summary should name the kind it cannot test; got: %s", got.Summary)
	}
}

// TestProbeEmptyKindIsTreatedAsAPI pins the upgrade behaviour
// settings.NormalizeProviderKind established: a row predating migration 000033
// has no kind and means api.
func TestProbeEmptyKindIsTreatedAsAPI(t *testing.T) {
	got := ProbeProvider(t.Context(), nil, ProbeTarget{Kind: ""})
	if got.Kind != ProbeNotConfigured || !strings.Contains(got.Summary, "base URL") {
		t.Fatalf("an empty kind should be probed as api (and refused for a missing base URL); got %q: %s", got.Kind, got.Summary)
	}
}

// ---------------------------------------------------------------------------
// transport failures
// ---------------------------------------------------------------------------

// TestProbeConnectionRefused uses a real refused connection: an httptest server
// closed before the call, so its port is genuinely nobody's. Local, fast, and
// it exercises the actual syscall errno rather than a stand-in.
func TestProbeConnectionRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedURL := srv.URL
	srv.Close()

	got := ProbeProvider(t.Context(), testLoopbackProbeClient(), apiTarget(closedURL, "m"))
	if got.Kind != ProbeConnectionRefused {
		t.Fatalf("Kind = %q, want %q (detail: %s)", got.Kind, ProbeConnectionRefused, got.Detail)
	}
	if !strings.Contains(got.Detail, "nothing is listening") {
		t.Errorf("detail should point at the port; got: %s", got.Detail)
	}
}

// TestProbeTLSUntrustedCertificate uses a real TLS handshake failure: an
// httptest TLS server probed with the default client, which does not trust its
// self-signed certificate. This is the single most common real-world TLS
// failure for a self-hosted endpoint.
func TestProbeTLSUntrustedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()

	// Deliberately NOT srv.Client(): the point is a client that does not trust
	// the server's CA, which is what a hub without the private CA installed is.
	got := ProbeProvider(t.Context(), testLoopbackProbeClient(), apiTarget(srv.URL, "m"))
	if got.Kind != ProbeTLSFailure {
		t.Fatalf("Kind = %q, want %q (detail: %s)", got.Kind, ProbeTLSFailure, got.Detail)
	}
	if !strings.Contains(got.Detail, "not trusted") && !strings.Contains(got.Detail, "certificate authority") {
		t.Errorf("detail should explain the trust problem; got: %s", got.Detail)
	}
	if strings.Contains(got.Detail, "sk-test-secret") {
		t.Fatal("the API key leaked into the error detail")
	}
}

// TestProbeTLSSchemeMismatch covers the two wrong-scheme mix-ups, which are
// handshake failures rather than certificate problems and have a
// one-character fix. Both are produced for real here: an https:// URL against
// a plaintext httptest server, and an http:// URL against a TLS one.
func TestProbeTLSSchemeMismatch(t *testing.T) {
	t.Run("https to a plaintext port", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{}`))
		}))
		defer srv.Close()
		httpsURL := "https://" + strings.TrimPrefix(srv.URL, "http://")

		got := ProbeProvider(t.Context(), testLoopbackProbeClient(), apiTarget(httpsURL, "m"))
		if got.Kind != ProbeTLSFailure {
			t.Fatalf("Kind = %q, want %q (detail: %s)", got.Kind, ProbeTLSFailure, got.Detail)
		}
		if !strings.Contains(got.Detail, "http://") {
			t.Errorf("detail should suggest the other scheme; got: %s", got.Detail)
		}
	})

	t.Run("http to a TLS port", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		defer srv.Close()
		httpURL := "http://" + strings.TrimPrefix(srv.URL, "https://")

		got := ProbeProvider(t.Context(), testLoopbackProbeClient(), apiTarget(httpURL, "m"))
		if got.Kind != ProbeTLSFailure {
			t.Fatalf("Kind = %q, want %q (detail: %s)", got.Kind, ProbeTLSFailure, got.Detail)
		}
	})
}

// TestProbeTimeout uses a handler that never answers, so the probe's own
// deadline is what ends the call — the wedged-provider case the timeout exists
// for. The deadline is shortened by cancelling the parent context, since
// waiting ProbeTimeout in a unit test would be absurd.
func TestProbeTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer func() { close(release); srv.Close() }()

	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()

	got := ProbeProvider(ctx, srv.Client(), apiTarget(srv.URL, "m"))
	if got.Kind != ProbeTimedOut {
		t.Fatalf("Kind = %q, want %q (detail: %s)", got.Kind, ProbeTimedOut, got.Detail)
	}
	if !strings.Contains(got.Detail, "no response arrived in time") {
		t.Errorf("detail should describe a wedged endpoint; got: %s", got.Detail)
	}
}

// TestProbeTimeoutIsBounded proves the safety property directly: even with a
// context that never expires, a probe against a server that never answers
// cannot run longer than ProbeTimeout, because ProbeProvider imposes its own
// deadline. Asserted against the constant rather than a hardcoded number.
func TestProbeTimeoutIsBounded(t *testing.T) {
	if ProbeTimeout > 30*time.Second {
		t.Fatalf("ProbeTimeout is %s — this runs inside a synchronous request an operator is watching, and holds a DB transaction open", ProbeTimeout)
	}
}

// TestClassifyProbeTransportError covers the cases that cannot be produced
// locally without making a real outbound request — DNS in particular. The
// errors are synthesized exactly as net/http would wrap them, which is what
// makes this a fair test of the classifier rather than of the network.
func TestClassifyProbeTransportError(t *testing.T) {
	wrap := func(err error) error {
		// net/http always hands back a *url.Error carrying the request URL.
		// Wrapping the same way here also exercises probeErrorDetail's
		// URL-stripping, which is a redaction guarantee and not just cosmetics.
		return &url.Error{Op: "Post", URL: "https://host.test/v1/chat/completions?api-key=SUPERSECRETVALUE", Err: err}
	}
	pc := probeContext{endpoint: "https://host.test/v1/chat/completions", apiKey: "SUPERSECRETVALUE"}

	tests := []struct {
		name               string
		err                error
		wantKind           string
		wantSummaryContain string
	}{
		{
			name:               "NXDOMAIN",
			err:                wrap(&net.DNSError{Err: "no such host", Name: "typo.example.test", IsNotFound: true}),
			wantKind:           ProbeDNSFailure,
			wantSummaryContain: "does not resolve",
		},
		{
			name:               "DNS timeout is a resolver problem, not a wrong hostname",
			err:                wrap(&net.DNSError{Err: "i/o timeout", Name: "slow.example.test", IsTimeout: true}),
			wantKind:           ProbeDNSFailure,
			wantSummaryContain: "timed out",
		},
		{
			name:               "other DNS failure",
			err:                wrap(&net.DNSError{Err: "server misbehaving", Name: "odd.example.test"}),
			wantKind:           ProbeDNSFailure,
			wantSummaryContain: "could not be resolved",
		},
		{
			name:               "connection refused",
			err:                wrap(&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}),
			wantKind:           ProbeConnectionRefused,
			wantSummaryContain: "refused",
		},
		{
			name:               "connection reset",
			err:                wrap(&net.OpError{Op: "read", Err: syscall.ECONNRESET}),
			wantKind:           ProbeNetworkFailure,
			wantSummaryContain: "reset",
		},
		{
			name:               "no route to host",
			err:                wrap(&net.OpError{Op: "dial", Err: syscall.EHOSTUNREACH}),
			wantKind:           ProbeNetworkFailure,
			wantSummaryContain: "no route",
		},
		{
			name:               "hostname mismatch on the certificate",
			err:                wrap(&tls.CertificateVerificationError{Err: fmt.Errorf("x509: %w", &net.OpError{Op: "x", Err: errors.New("boom")})}),
			wantKind:           ProbeTLSFailure,
			wantSummaryContain: "TLS handshake",
		},
		{
			name:               "deadline exceeded",
			err:                wrap(context.DeadlineExceeded),
			wantKind:           ProbeTimedOut,
			wantSummaryContain: "did not answer",
		},
		{
			name:               "something else entirely",
			err:                wrap(errors.New("http2: unexpected frame")),
			wantKind:           ProbeNetworkFailure,
			wantSummaryContain: "could not be completed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyProbeTransportError(tc.err, pc)
			if got.Kind != tc.wantKind {
				t.Errorf("Kind = %q, want %q (summary: %s)", got.Kind, tc.wantKind, got.Summary)
			}
			if !strings.Contains(got.Summary, tc.wantSummaryContain) {
				t.Errorf("Summary = %q, want it to mention %q", got.Summary, tc.wantSummaryContain)
			}
			// The redaction guarantee, asserted on every single case rather
			// than once: the wrapped *url.Error carries both the credential
			// and a query string, and neither may survive into a result.
			for _, field := range []string{got.Summary, got.Detail, got.Caveat} {
				if strings.Contains(field, "SUPERSECRETVALUE") {
					t.Fatalf("credential leaked into a probe result: %s", field)
				}
				if strings.Contains(field, "api-key=") {
					t.Fatalf("query string leaked into a probe result: %s", field)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// cli providers
// ---------------------------------------------------------------------------

// runnerStub stands in for cmd/cli-runner. investigateStatus is what it
// returns from POST /investigate — 400 is what the real runner returns for the
// probe's empty body, AFTER checking the token and BEFORE doing any work.
type runnerStub struct {
	healthStatus     int
	healthBody       string
	investigateCalls int
	investigateBody  string
	investigateAuth  string
	investigateFunc  func(w http.ResponseWriter, r *http.Request)
}

func (rs *runnerStub) server() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rs.healthStatus)
		_, _ = w.Write([]byte(rs.healthBody))
	})
	mux.HandleFunc("POST /investigate", func(w http.ResponseWriter, r *http.Request) {
		rs.investigateCalls++
		rs.investigateAuth = r.Header.Get("Authorization")
		buf := make([]byte, 256)
		n, _ := r.Body.Read(buf)
		rs.investigateBody = string(buf[:n])
		rs.investigateFunc(w, r)
	})
	return httptest.NewServer(mux)
}

// TestProbeCLIRunnerSuccess is the important one for the cli half: a pass, and
// proof that the probe reached /investigate with an EMPTY body — the request
// the real runner rejects before spawning anything. If this body ever grew
// into something the runner would accept, the test button would start billing
// for full investigations.
func TestProbeCLIRunnerSuccess(t *testing.T) {
	rs := &runnerStub{
		healthStatus: 200,
		healthBody:   `{"agents":{"claude":"1.2.3","codex":"0.9"}}`,
		investigateFunc: func(w http.ResponseWriter, _ *http.Request) {
			// What cmd/cli-runner really does for this body.
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"mcpUrl and mcpToken are required"}`))
		},
	}
	srv := rs.server()
	defer srv.Close()

	got := ProbeProvider(t.Context(), srv.Client(), ProbeTarget{
		Kind: "cli", RunnerURL: srv.URL, RunnerToken: "runner-token-long-enough", Agent: "claude",
	})
	if !got.OK || got.Kind != ProbeOK {
		t.Fatalf("OK/Kind = %v/%q, want true/%q (detail: %s)", got.OK, got.Kind, ProbeOK, got.Detail)
	}
	if rs.investigateCalls != 1 {
		t.Fatalf("POST /investigate called %d times, want exactly 1", rs.investigateCalls)
	}
	if strings.TrimSpace(rs.investigateBody) != "{}" {
		t.Errorf("investigate body = %q, want exactly {} — anything a runner could act on would cost a real investigation", rs.investigateBody)
	}
	if rs.investigateAuth != "Bearer runner-token-long-enough" {
		t.Errorf("Authorization = %q, want the configured runner token", rs.investigateAuth)
	}
	if !strings.Contains(got.Detail, "1.2.3") {
		t.Errorf("detail should report the installed agent version; got: %s", got.Detail)
	}
	if !strings.Contains(got.Caveat, "model credential") {
		t.Errorf("caveat must say the runner's own model credential is untested; got: %s", got.Caveat)
	}
}

// TestProbeCLIRunnerBadToken: a 401 from /investigate is the only signal that
// the runner token is wrong, and it must not be reported as anything else.
func TestProbeCLIRunnerBadToken(t *testing.T) {
	rs := &runnerStub{
		healthStatus: 200,
		healthBody:   `{"agents":{"claude":"1.2.3"}}`,
		investigateFunc: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		},
	}
	srv := rs.server()
	defer srv.Close()

	got := ProbeProvider(t.Context(), srv.Client(), ProbeTarget{
		Kind: "cli", RunnerURL: srv.URL, RunnerToken: "wrong-token-value-here", Agent: "claude",
	})
	if got.Kind != ProbeUnauthorized {
		t.Fatalf("Kind = %q, want %q (detail: %s)", got.Kind, ProbeUnauthorized, got.Detail)
	}
	if !strings.Contains(got.Detail, "ARGUS_CLI_RUNNER_TOKEN") {
		t.Errorf("detail should name the runner's own env var; got: %s", got.Detail)
	}
	// The distinction that matters: this is the ARGUS->runner token, not the
	// model credential, and confusing the two sends someone to the wrong file.
	if !strings.Contains(got.Detail, "not the model credential") {
		t.Errorf("detail should distinguish the two credentials; got: %s", got.Detail)
	}
}

// TestProbeCLIRunnerAgentMissing: the runner is fine and the provider asks for
// a CLI it does not have. Two variants, because "no agents at all" is fixed in
// the runner's image and "not the one you asked for" can be fixed here.
func TestProbeCLIRunnerAgentMissing(t *testing.T) {
	t.Run("configured agent not installed", func(t *testing.T) {
		rs := &runnerStub{healthStatus: 200, healthBody: `{"agents":{"claude":"1.2.3"}}`}
		srv := rs.server()
		defer srv.Close()

		got := ProbeProvider(t.Context(), srv.Client(), ProbeTarget{
			Kind: "cli", RunnerURL: srv.URL, RunnerToken: "tok-long-enough-value", Agent: "codex",
		})
		if got.Kind != ProbeAgentMissing {
			t.Fatalf("Kind = %q, want %q (detail: %s)", got.Kind, ProbeAgentMissing, got.Detail)
		}
		if !strings.Contains(got.Detail, "claude") {
			t.Errorf("detail should list what IS installed; got: %s", got.Detail)
		}
		if rs.investigateCalls != 0 {
			t.Error("the auth check should not run once the agent is known to be missing")
		}
	})

	t.Run("runner has no agents at all", func(t *testing.T) {
		rs := &runnerStub{healthStatus: 503, healthBody: `{"agents":{}}`}
		srv := rs.server()
		defer srv.Close()

		got := ProbeProvider(t.Context(), srv.Client(), ProbeTarget{
			Kind: "cli", RunnerURL: srv.URL, RunnerToken: "tok-long-enough-value",
		})
		if got.Kind != ProbeAgentMissing {
			t.Fatalf("Kind = %q, want %q", got.Kind, ProbeAgentMissing)
		}
		if !strings.Contains(got.Detail, "runner's own image") {
			t.Errorf("detail should point at the runner image, not this provider; got: %s", got.Detail)
		}
	})
}

// TestProbeCLIRunnerNotARunner: something answers on that address and is not a
// runner. Both the 404 (no /healthz) and the non-JSON-body variants.
func TestProbeCLIRunnerNotARunner(t *testing.T) {
	t.Run("no healthz endpoint", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(404)
		}))
		defer srv.Close()

		got := ProbeProvider(t.Context(), srv.Client(), ProbeTarget{Kind: "cli", RunnerURL: srv.URL})
		if got.Kind != ProbeNotARunner {
			t.Fatalf("Kind = %q, want %q (detail: %s)", got.Kind, ProbeNotARunner, got.Detail)
		}
	})

	t.Run("healthz answers with something else", func(t *testing.T) {
		rs := &runnerStub{healthStatus: 200, healthBody: `<html>hello</html>`}
		srv := rs.server()
		defer srv.Close()

		got := ProbeProvider(t.Context(), srv.Client(), ProbeTarget{Kind: "cli", RunnerURL: srv.URL})
		if got.Kind != ProbeNotARunner {
			t.Fatalf("Kind = %q, want %q (detail: %s)", got.Kind, ProbeNotARunner, got.Detail)
		}
	})

	t.Run("investigate accepts an invalid request", func(t *testing.T) {
		rs := &runnerStub{
			healthStatus:    200,
			healthBody:      `{"agents":{"claude":"1"}}`,
			investigateFunc: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) },
		}
		srv := rs.server()
		defer srv.Close()

		got := ProbeProvider(t.Context(), srv.Client(), ProbeTarget{
			Kind: "cli", RunnerURL: srv.URL, RunnerToken: "tok-long-enough-value",
		})
		if got.Kind != ProbeNotARunner {
			t.Fatalf("Kind = %q, want %q (detail: %s)", got.Kind, ProbeNotARunner, got.Detail)
		}
	})
}

// TestProbeCLIRunnerTransportFailuresAreClassified confirms the cli half shares
// the api half's network classification rather than reporting a generic error.
func TestProbeCLIRunnerTransportFailuresAreClassified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedURL := srv.URL
	srv.Close()

	got := ProbeProvider(t.Context(), nil, ProbeTarget{Kind: "cli", RunnerURL: closedURL, RunnerToken: "tok-long-enough-value"})
	if got.Kind != ProbeConnectionRefused {
		t.Fatalf("Kind = %q, want %q (detail: %s)", got.Kind, ProbeConnectionRefused, got.Detail)
	}
}

// ---------------------------------------------------------------------------
// redaction and message handling
// ---------------------------------------------------------------------------

// TestProbeNeverEchoesTheCredential is the requirement-4 test, and it is
// deliberately adversarial: the fake provider echoes the whole Authorization
// header back in its error body, which a reflecting proxy or a debug endpoint
// genuinely does. Not one character of the key may reach the result.
func TestProbeNeverEchoesTheCredential(t *testing.T) {
	const key = "sk-live-DO-NOT-LEAK-THIS-0987654321"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{"message": "your request was: " + r.Header.Get("Authorization")},
		})
	}))
	defer srv.Close()

	got := ProbeProvider(t.Context(), srv.Client(), ProbeTarget{Kind: "api", BaseURL: srv.URL, Model: "m", APIKey: key})
	all := got.Summary + " " + got.Detail + " " + got.Caveat + " " + got.Model
	if strings.Contains(all, key) {
		t.Fatalf("the API key survived into the result: %s", all)
	}
	// A prefix is still key material, so a prefix must not survive either.
	if strings.Contains(all, key[:12]) {
		t.Fatalf("a prefix of the API key survived into the result: %s", all)
	}
	if !strings.Contains(all, "[redacted]") {
		t.Errorf("the echoed key should have been replaced, not silently dropped; got: %s", all)
	}
}

// TestRedactURL pins the query-string and userinfo stripping. Several real
// providers authenticate with a query parameter, so a probe message echoing a
// base URL verbatim would be a credential-disclosure path.
func TestRedactURL(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://api.example.test/v1/chat/completions?api-key=SECRET", "https://api.example.test/v1/chat/completions"},
		{"https://user:pass@api.example.test/v1", "https://api.example.test/v1"},
		{"https://api.example.test/v1#frag", "https://api.example.test/v1"},
		{"not a url at all", "the configured address"},
		{"", ""},
	} {
		if got := redactURL(tc.in); got != tc.want {
			t.Errorf("redactURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestRedactSecretSkipsShortStrings: blanking every occurrence of a two-letter
// "key" would mangle messages for no security benefit.
func TestRedactSecretSkipsShortStrings(t *testing.T) {
	if got := redactSecret("the model is not found", "no"); got != "the model is not found" {
		t.Errorf("a short secret should not be redacted out of prose; got %q", got)
	}
	if got := redactSecret("key is abcdefghij here", "abcdefghij"); !strings.Contains(got, "[redacted]") {
		t.Errorf("an 8+ character secret must be redacted; got %q", got)
	}
}

// TestProviderMessage covers every error envelope shape this package has to
// read, including the one that motivated json.RawMessage: `error` as a string
// rather than an object.
func TestProviderMessage(t *testing.T) {
	for _, tc := range []struct {
		name, body, wantContains string
	}{
		{"openai object", `{"error":{"message":"bad key","type":"invalid_request_error","code":"invalid_api_key"}}`, "bad key"},
		{"openai object keeps the code", `{"error":{"message":"nope","code":"model_not_found"}}`, "model_not_found"},
		{"error as a bare string", `{"error":"model 'x' not found"}`, "model 'x' not found"},
		{"message field", `{"message":"unknown model"}`, "unknown model"},
		{"detail field", `{"detail":"Not Found"}`, "Not Found"},
		{"non-JSON falls back to a snippet", `502 Bad Gateway`, "502 Bad Gateway"},
		{"numeric code does not break parsing", `{"error":{"message":"oops","code":400}}`, "oops"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := providerMessage([]byte(tc.body), ""); !strings.Contains(got, tc.wantContains) {
				t.Errorf("providerMessage(%s) = %q, want it to contain %q", tc.body, got, tc.wantContains)
			}
		})
	}
}

// TestProviderMessageIsSanitizedAndBounded: the body is untrusted remote text
// that ends up in a log line and a UI string, so it must not be able to carry
// newlines, control characters, or unbounded length.
func TestProviderMessageIsSanitizedAndBounded(t *testing.T) {
	got := providerMessage([]byte("{\"error\":\"line one\nline two\x1b[31mred\x00\"}"), "")
	if strings.ContainsAny(got, "\n\x1b\x00") {
		t.Errorf("control characters survived: %q", got)
	}
	long := providerMessage([]byte(`{"error":"`+strings.Repeat("x", 5000)+`"}`), "")
	if len([]rune(long)) > probeMessageMaxLen+1 {
		t.Errorf("message is %d runes, want it bounded to ~%d", len([]rune(long)), probeMessageMaxLen)
	}
}

// TestLooksLikeModelNotFoundIsConservative is the counterpart to the
// model-not-found table cases: a false positive tells someone their model name
// is wrong when their base URL is, which is worse than not detecting it. These
// must NOT match.
func TestLooksLikeModelNotFoundIsConservative(t *testing.T) {
	for _, msg := range []string{
		"Incorrect API key provided",
		"Not Found",
		"rate limit exceeded",
		"the model responded slowly", // mentions "model", no absence word
		"page not found",             // absence word, no model
		"",
	} {
		if looksLikeModelNotFound(msg, "some-model") {
			t.Errorf("looksLikeModelNotFound(%q) = true, want false — this would blame the wrong field", msg)
		}
	}
	for _, msg := range []string{
		"The model `x` does not exist",
		"model_not_found",
		"unknown model: y",
		"model 'z' not found, try pulling it first",
		"invalid_model",
	} {
		if !looksLikeModelNotFound(msg, "x") {
			t.Errorf("looksLikeModelNotFound(%q) = false, want true", msg)
		}
	}
}
