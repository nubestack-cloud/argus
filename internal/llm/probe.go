package llm

// Connection probes — the engine behind Settings' "Test connection" button
// (POST /api/v1/admin/ai-providers/{id}/test, internal/api/ai_providers.go).
//
// Why this file exists at all: every other way of finding out whether a
// provider is configured correctly costs a real investigation. An operator
// pastes a base URL, a model name and a key, saves, and learns nothing until
// an incident is analysed — at which point a wrong `/v1` suffix, an expired
// key and a rate limit all surface as the same unhelpful "analysis failed",
// during an outage, in a code path that has already spent money getting
// there. This turns that into one click that costs almost nothing and names
// the actual problem.
//
// The design rule for the whole file: **every failure must be distinguishable
// from every other failure that has a different fix.** A probe that reports
// "could not connect" is worse than no probe, because it looks like an answer.
// So the classification below is deliberately fine-grained, the messages name
// the specific misconfiguration that produces each one, and where two causes
// genuinely cannot be told apart (a 403 that might be a scope problem or
// might be a WAF) the message says so rather than picking one.
//
// The two provider kinds are probed completely differently, and neither
// probe pretends to prove more than it does — see ProbeAPIProvider and
// ProbeCLIRunner for what each one does and does not establish.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"argus/internal/outbound"
)

// ProbeTimeout bounds one probe end to end, including both HTTP calls the cli
// probe makes. Deliberately short: this runs synchronously inside an HTTP
// request an operator is watching, and a wedged endpoint that accepts a
// connection and then never answers must not be able to hold that request (or
// the database transaction it carries) open indefinitely. Long enough for a
// self-hosted server that has to page a model in before answering, short
// enough that a human does not conclude the button is broken.
const ProbeTimeout = 15 * time.Second

// Probe result classifications. These are the machine-readable half of a
// result — the API returns one as an RFC 9457 extension member so the UI can
// branch on the *kind* of failure without parsing prose out of the message.
//
// Each constant exists because it has a DIFFERENT FIX. Two causes that an
// operator would respond to identically are one constant; two that need
// different actions are never merged, however similar they look on the wire
// (ProbeEndpointNotFound and ProbeModelNotFound are both HTTP 404, and
// confusing them sends someone to edit the wrong field).
const (
	// ProbeOK: the provider answered correctly. See each probe's doc comment
	// for exactly what that does and does not establish.
	ProbeOK = "ok"
	// ProbeNotConfigured: there is nothing to test — the field this provider
	// kind cannot work without is empty. Reported before any network call.
	ProbeNotConfigured = "not_configured"
	// ProbeDNSFailure: the hostname did not resolve. Fix is the hostname (or
	// the hub's resolver), never the credential.
	ProbeDNSFailure = "dns_failure"
	// ProbeConnectionRefused: the host resolved and answered, and refused the
	// connection. Almost always the wrong port, or the service is not
	// running.
	ProbeConnectionRefused = "connection_refused"
	// ProbeNetworkFailure: reachable-in-principle but the connection failed
	// some other way (reset, unreachable network, no route). Kept separate
	// from ProbeConnectionRefused because "nothing is listening on that port"
	// and "this hub has no route to that network" are different problems with
	// different owners.
	ProbeNetworkFailure = "network_failure"
	// ProbeTLSFailure: the TCP connection succeeded and the TLS handshake did
	// not. Covers an untrusted CA, a hostname mismatch, an expired
	// certificate, and both scheme mix-ups (https:// to a plaintext port and
	// http:// to a TLS one) — all of which produce a handshake failure and
	// none of which are credential problems.
	ProbeTLSFailure = "tls_failure"
	// ProbeTimedOut: the endpoint accepted the connection and did not answer
	// within ProbeTimeout. The one failure that says nothing about
	// configuration and everything about the endpoint's health.
	ProbeTimedOut = "timeout"
	// ProbeUnauthorized: HTTP 401. The credential was rejected.
	ProbeUnauthorized = "unauthorized"
	// ProbeForbidden: HTTP 403. Distinct from 401 because the fix is usually
	// the key's *scope* or the account's entitlements, not the key itself.
	ProbeForbidden = "forbidden"
	// ProbeEndpointNotFound: HTTP 404 with nothing indicating the model. The
	// base URL is wrong — overwhelmingly a missing or doubled path segment.
	ProbeEndpointNotFound = "endpoint_not_found"
	// ProbeModelNotFound: the endpoint is right and the model name is not.
	// Detected from the error body rather than the status, because providers
	// signal it as 400, 403, 404 and 422 depending on who wrote them.
	ProbeModelNotFound = "model_not_found"
	// ProbeRateLimited: HTTP 429 (or a 403 carrying rate-limit markers). Not
	// a configuration fault at all, which the message says explicitly so
	// nobody goes looking for one.
	ProbeRateLimited = "rate_limited"
	// ProbeRedirected: the endpoint answered with a redirect. Reported rather
	// than followed — see probeHTTPClient for why following it would be a
	// credential leak.
	ProbeRedirected = "redirected"
	// ProbeRejected: HTTP 400/422 for some reason other than the model name.
	// The provider's own message is the useful part here.
	ProbeRejected = "rejected"
	// ProbeProviderError: HTTP 5xx. The endpoint (or a gateway in front of
	// it) is unhealthy; nothing on this side needs changing.
	ProbeProviderError = "provider_error"
	// ProbeUnexpectedStatus: a status none of the above covers.
	ProbeUnexpectedStatus = "unexpected_status"
	// ProbeMalformedResponse: HTTP 2xx whose body is not a chat completion.
	// Nearly always something other than the API answering — a login page, a
	// proxy's HTML error page, a static site.
	ProbeMalformedResponse = "malformed_response"
	// ProbeAgentMissing: cli kind only. The runner is reachable and
	// authenticated, and does not have the configured CLI installed.
	ProbeAgentMissing = "agent_missing"
	// ProbeNotARunner: cli kind only. Something is listening and answering,
	// and it is not an ARGUS CLI runner.
	ProbeNotARunner = "not_a_runner"
	// ProbeUnsupportedKind: the provider's kind is not one this file knows
	// how to test. Reported honestly instead of guessing at a probe.
	ProbeUnsupportedKind = "unsupported_kind"
)

// ProbeResult is one connection test's outcome.
//
// Summary is a single sentence naming what happened; Detail is the actionable
// part, and is where a provider's own error message is passed through (see
// providerMessage). Caveat states what the probe did NOT prove — mandatory
// rather than optional, because the most dangerous outcome of this feature
// would be an operator reading a green tick as "analysis will work", which
// neither probe can establish.
//
// No field of this struct ever holds a credential, or any part of one. Every
// string that could have come from outside this process is passed through
// redactSecret and length-bounded first.
type ProbeResult struct {
	OK      bool
	Kind    string
	Summary string
	Detail  string
	Caveat  string

	// Model is what the provider echoed back in its response, which is worth
	// showing: an endpoint that silently serves a different model than the one
	// requested (a gateway with a default, a self-hosted server with one model
	// loaded) is a real misconfiguration that otherwise stays invisible.
	Model string
	// TokensIn/TokensOut are what the provider reported billing for this
	// probe. Reported so the cost claim in this file's comments is verifiable
	// against a real endpoint rather than taken on trust.
	TokensIn  int
	TokensOut int
	LatencyMs int
}

// ProbeTarget is one provider's fully-resolved configuration — the same fields
// internal/settings resolves for the active provider, for whichever provider
// is being tested. Carries real secrets, so it is an input only: nothing in
// this file puts a field of it into a ProbeResult except BaseURL/RunnerURL,
// and those go through redactURL first.
type ProbeTarget struct {
	Kind string

	BaseURL string
	Model   string
	APIKey  string

	RunnerURL   string
	RunnerToken string
	Agent       string

	// PrivateDestinations is the operator allowlist source the "api" probe
	// consults — and it must be the SAME source internal/llm.NewProvider was
	// wired with (settings.PrivateDestinationSource over the hub's pool), for
	// exactly the reason probeAPIClient's own comment gives: a probe that
	// applies a different private-destination policy from the real
	// completion path can report "connection OK" for a destination the real
	// path then refuses, or the reverse.
	//
	// nil means plain default-deny, which is the correct answer for a caller
	// that has no database to read the allowlist from (tests), not a reason
	// to skip the check.
	PrivateDestinations outbound.AllowlistSource
}

// ProbeProvider dispatches on kind and applies the ProbeTimeout bound.
//
// The bound lives here rather than at the call site on purpose: it is a safety
// property (requirement: a wedged provider cannot hang the request), and a
// caller that forgets to set it would silently lose it. client may be nil, in
// which case probeHTTPClient is used; tests pass an httptest server's client.
func ProbeProvider(ctx context.Context, client *http.Client, t ProbeTarget) ProbeResult {
	ctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()

	switch t.Kind {
	case "", "api":
		// "" is treated as api for the same reason
		// settings.NormalizeProviderKind does: it is what a row predating
		// migration 000033 means.
		return ProbeAPIProvider(ctx, client, t)
	case "cli":
		return ProbeCLIRunner(ctx, client, t)
	default:
		return ProbeResult{
			Kind:    ProbeUnsupportedKind,
			Summary: fmt.Sprintf("ARGUS cannot test a provider of kind %q.", t.Kind),
			Detail: "Only \"api\" (an OpenAI-compatible endpoint ARGUS calls itself) and \"cli\" " +
				"(a runner service driving a coding-agent CLI) can be tested. This provider's kind is " +
				"neither, so there is no request to send. Edit the provider and pick a supported kind.",
		}
	}
}

// ---------------------------------------------------------------------------
// api providers
// ---------------------------------------------------------------------------

// probeMaxTokens caps what the provider is allowed to GENERATE. 1 is the
// floor every OpenAI-compatible endpoint accepts, and generation is the
// expensive half of a completion.
const probeMaxTokens = 1

// probePrompt is the entire prompt. One word, no system prompt.
const probePrompt = "hi"

// WHAT ONE PROBE COSTS, in tokens:
//
//   - Prompt: one user message containing the two characters "hi", plus
//     whatever chat-template and role framing the provider adds around it.
//     That framing is provider-specific and not something this code can
//     control, but it is small and fixed — on the OpenAI-compatible endpoints
//     this package targets it lands in the 5–15 token range, so **under ~20
//     prompt tokens** is the honest upper bound.
//   - Completion: **at most 1 token**, hard-capped by max_tokens above.
//
// So one click is on the order of twenty tokens. For scale, one real
// investigation is a multi-turn tool-calling loop over cluster evidence —
// thousands of prompt tokens per turn, for up to maxIterations turns. The
// probe is three to four orders of magnitude below that.
//
// Two deliberate omissions keep it there. There is **no system prompt**: it
// would be the largest single item on the bill for a request whose only
// purpose is to learn whether the endpoint answers, and it would prove nothing
// extra. And the probe is **never run automatically** — not on save, not on
// activate, not on a timer, not on page load. It is sent when, and only when,
// a human clicks the button, because it is the one code path in this package
// that spends money without an incident behind it.
//
// The provider's own reported usage comes back in ProbeResult.TokensIn/
// TokensOut, so the paragraph above is checkable against a real endpoint
// rather than taken on faith.

// probeRequest is a chat completion with a hard generation cap. A separate
// type from chatRequest rather than a field added to it, because a max_tokens
// cap is exactly the wrong thing to have available on the real analysis path —
// truncating a model's actual reasoning to save tokens is how an analysis
// becomes confidently wrong.
type probeRequest struct {
	Model     string        `json:"model"`
	Messages  []chatMessage `json:"messages"`
	MaxTokens int           `json:"max_tokens"`
}

// ProbeAPIProvider sends one minimal chat completion and classifies whatever
// comes back.
//
// What a pass proves: the base URL resolves, connects and completes a TLS
// handshake if applicable; the endpoint speaks the chat-completions protocol
// at that path; the credential (or the absence of one) is accepted; the model
// name is servable; and the response parses.
//
// What a pass does NOT prove: that a full investigation will succeed. This
// request has no system prompt, no tools, no multi-turn loop and a 1-token
// generation cap, so it cannot detect a context window too small for real
// evidence, a model that does not support tool calling, an account whose quota
// runs out on the second request, or a per-model entitlement that differs from
// the one this probe happened to exercise. The Caveat field says so.
func ProbeAPIProvider(ctx context.Context, client *http.Client, t ProbeTarget) ProbeResult {
	if strings.TrimSpace(t.BaseURL) == "" {
		return ProbeResult{
			Kind:    ProbeNotConfigured,
			Summary: "This provider has no base URL, so there is nothing to call.",
			Detail: "An api provider needs the base URL of an OpenAI-compatible endpoint — the part " +
				"BEFORE /chat/completions, e.g. https://api.openai.com/v1. Edit the provider and set it.",
		}
	}

	// Validated here rather than left to http.NewRequest, which happily builds
	// a request for a relative URL like "api.openai.com/v1" and only fails at
	// Do() with "unsupported protocol scheme" — reported as a network failure,
	// which sends someone to check their egress rules over a missing "https://".
	// Found by testing a bare hostname against the live hub.
	if reason, ok := unusableURL(t.BaseURL); !ok {
		return ProbeResult{
			Kind:    ProbeNotConfigured,
			Summary: "The base URL is not a usable URL.",
			Detail: fmt.Sprintf("%s It must be an absolute URL with a scheme and a host, e.g. "+
				"https://api.openai.com/v1 — and it should be the part BEFORE /chat/completions.", reason),
		}
	}

	endpoint := strings.TrimSuffix(strings.TrimSpace(t.BaseURL), "/") + "/chat/completions"
	pc := probeContext{endpoint: redactURL(endpoint), model: t.Model, apiKey: t.APIKey}

	body, err := json.Marshal(probeRequest{
		Model:     t.Model,
		Messages:  []chatMessage{{Role: "user", Content: probePrompt}},
		MaxTokens: probeMaxTokens,
	})
	if err != nil {
		// Unreachable in practice (the struct above always marshals), handled
		// rather than ignored.
		return ProbeResult{Kind: ProbeUnexpectedStatus, Summary: "Could not build the test request.", Detail: err.Error()}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		// This is where a base URL that is not a URL at all lands (a bare
		// hostname, a stray space, a scheme typo) — worth its own message,
		// since "unsupported protocol scheme" out of context reads like a
		// network fault rather than a typo in a text field.
		return ProbeResult{
			Kind:    ProbeNotConfigured,
			Summary: "The base URL is not a usable URL.",
			Detail: fmt.Sprintf("ARGUS could not even build a request for it: %s. It must be an absolute "+
				"http:// or https:// URL.", probeErrorDetail(err, t.APIKey)),
		}
	}
	req.Header.Set("Content-Type", "application/json")
	if t.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+t.APIKey)
	}

	start := time.Now()
	resp, err := httpClientOrDefault(client, probeAPIClient(t.PrivateDestinations)).Do(req)
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		out := classifyProbeTransportError(err, pc)
		out.LatencyMs = latency
		return out
	}
	defer resp.Body.Close()

	// Bounded read: an endpoint that is not the API at all (the common
	// malformed-response case) may be serving an arbitrarily large HTML page,
	// and none of it past the first few KB is diagnostically useful.
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))

	out := classifyProbeResponse(resp, respBody, pc)
	out.LatencyMs = latency
	return out
}

// probeContext is the small bundle of request facts every classifier needs:
// where the request went (already redacted, safe to put in a message), what
// model was asked for, and the API key — present for the sole purpose of
// scrubbing it back out of anything an endpoint echoes at us.
type probeContext struct {
	endpoint string
	model    string
	apiKey   string
}

func (pc probeContext) keySet() bool { return pc.apiKey != "" }

// classifyProbeResponse turns one HTTP response into a ProbeResult.
//
// Split out from ProbeAPIProvider with no I/O of its own so that every branch
// below is unit-testable — which matters more here than anywhere else in this
// file, since the classification IS the feature.
func classifyProbeResponse(resp *http.Response, body []byte, pc probeContext) ProbeResult {
	msg := providerMessage(body, pc.apiKey)
	status := resp.StatusCode

	switch {
	case status >= 200 && status < 300:
		return classifyProbeSuccessBody(resp, body, pc)

	case status >= 300 && status < 400:
		// Not followed — see probeHTTPClient. Only the redirect's
		// scheme/host/path is reported; its query string is dropped by
		// redactURL, since a redirect target is exactly the kind of URL that
		// carries a token.
		loc := redactURL(resp.Header.Get("Location"))
		if loc == "" {
			loc = "an unspecified location"
		}
		return ProbeResult{
			Kind:    ProbeRedirected,
			Summary: fmt.Sprintf("The endpoint redirected the request (HTTP %d).", status),
			Detail: fmt.Sprintf("It pointed at %s. ARGUS deliberately does not follow redirects on this "+
				"request, because doing so would send the API key to whatever host the redirect names. "+
				"Set the base URL to the final address instead. A redirect here usually means the base URL "+
				"is missing a path segment, or is hitting an SSO/login flow rather than the API.", loc),
		}

	case status == http.StatusUnauthorized:
		if !pc.keySet() {
			return ProbeResult{
				Kind:    ProbeUnauthorized,
				Summary: "The endpoint requires a credential and this provider has none (HTTP 401).",
				Detail: joinDetail("No API key is configured for this provider, so the request was sent "+
					"without an Authorization header and was refused. Add a key, or point the provider at an "+
					"endpoint that does not need one (a local Ollama or vLLM server, typically).", msg),
			}
		}
		return ProbeResult{
			Kind:    ProbeUnauthorized,
			Summary: "The provider rejected the API key (HTTP 401).",
			Detail: joinDetail("The key was sent and refused. It is wrong, expired, revoked, or belongs to "+
				"a different account, project or region than this endpoint serves. Re-paste the key — a "+
				"truncated copy/paste is the single most common cause, and ARGUS cannot detect one because it "+
				"never displays the stored key.", msg),
		}

	case status == http.StatusForbidden:
		// A 403 carrying rate-limit markers is not an authorization problem,
		// and telling someone to check their key's scopes when they are
		// actually throttled sends them to the wrong place entirely. Same
		// reasoning (and the same header check) as internal/scm/github.go.
		if isRateLimitResponse(resp, msg) {
			return rateLimitedResult(resp, msg, 403)
		}
		if looksLikeModelNotFound(msg, pc.model) {
			return modelNotFoundResult(msg, pc, 403)
		}
		return ProbeResult{
			Kind:    ProbeForbidden,
			Summary: "The provider accepted the credential but refused the request (HTTP 403).",
			Detail: joinDetail("This is a permissions or entitlement problem rather than a bad key. The "+
				"three causes worth checking, in order: the key is valid but has no access to this model; the "+
				"account or organisation has a policy or spend limit blocking it; or something in front of the "+
				"endpoint (a corporate proxy, a WAF, an API gateway) is rejecting the request before it "+
				"arrives. The provider's own message below usually says which.", msg),
		}

	case status == http.StatusNotFound:
		// The one genuinely ambiguous status, and the ambiguity matters: a
		// 404 is either "wrong URL" or "wrong model", and those are different
		// fields in the form. The body is the only thing that distinguishes
		// them, so it is checked first and the URL answer is the fallback.
		if looksLikeModelNotFound(msg, pc.model) {
			return modelNotFoundResult(msg, pc, 404)
		}
		return ProbeResult{
			Kind:    ProbeEndpointNotFound,
			Summary: "Nothing is served at that address (HTTP 404).",
			Detail: joinDetail(fmt.Sprintf("ARGUS posted to %s and the server had no such path. The base URL "+
				"is the part BEFORE /chat/completions, so the two mistakes that land here are a base URL that "+
				"already ends in /chat/completions (giving .../chat/completions/chat/completions) and one "+
				"missing the version segment the endpoint expects (usually /v1). Check the provider's own "+
				"documentation for the exact base URL.", pc.endpoint), msg),
		}

	case status == http.StatusMethodNotAllowed, status == http.StatusNotImplemented:
		// Its own case, added after live testing produced it: pointing a base
		// URL at a web server, a static file host or any API that is not this
		// one very often yields 405 rather than 404, and reporting that as an
		// "unrecognised status" buries the single most useful fact — something
		// IS listening there, and it is not a chat-completions endpoint.
		return ProbeResult{
			Kind:    ProbeEndpointNotFound,
			Summary: fmt.Sprintf("That address exists but does not accept this request (HTTP %d).", status),
			Detail: joinDetail(fmt.Sprintf("Something is listening at %s and refused the POST. A "+
				"chat-completions endpoint accepts POST, so this is almost certainly not one — a web server, a "+
				"static file host, or a different API. Check the base URL against the provider's own "+
				"documentation.", pc.endpoint), msg),
		}

	case status == http.StatusTooManyRequests:
		return rateLimitedResult(resp, msg, 429)

	case status == http.StatusBadRequest, status == http.StatusUnprocessableEntity:
		// Checked before anything else: a TLS listener asked to speak plain
		// HTTP does not always fail the handshake — Go's own http.Server and
		// nginx both answer with a perfectly valid HTTP 400 saying so, which
		// would otherwise be classified as "the provider rejected the
		// request" and send someone hunting through their prompt settings for
		// a missing "s" in a URL.
		if looksLikePlaintextToTLSPort(msg) {
			return ProbeResult{
				Kind:    ProbeTLSFailure,
				Summary: "The endpoint expects TLS, but the URL says http://.",
				Detail: joinDetail("It answered the plaintext request with an error saying so. Change the "+
					"base URL's scheme from http:// to https://.", msg),
			}
		}
		if looksLikeModelNotFound(msg, pc.model) {
			return modelNotFoundResult(msg, pc, status)
		}
		detail := fmt.Sprintf("The endpoint and credential are fine — it understood the request and "+
			"declined it. The provider's own message is the useful part: %s", orNoMessage(msg))
		if strings.TrimSpace(pc.model) == "" {
			// Worth calling out explicitly rather than leaving in the
			// provider's words: a blank model is legal in this codebase's
			// provider validation (only baseUrl is required for an api
			// provider, because some single-model self-hosted servers ignore
			// the field) but is rejected by almost everything else.
			detail += " This provider has no model name configured, which is the most likely cause: " +
				"an OpenAI-compatible endpoint normally requires one."
		}
		if strings.Contains(strings.ToLower(msg), "max_tokens") {
			// A real and confusing case: some newer endpoints reject
			// max_tokens in favour of max_completion_tokens. It would fail
			// only the probe, never a real analysis, so saying so prevents
			// someone "fixing" a provider that was never broken.
			detail += " Note that the message mentions max_tokens, which only this connection test sends " +
				"(to cap its cost at one generated token). If that is the whole complaint, real analysis " +
				"requests are unaffected and this provider is probably usable as-is."
		}
		return ProbeResult{
			Kind:    ProbeRejected,
			Summary: fmt.Sprintf("The provider rejected the request as invalid (HTTP %d).", status),
			Detail:  detail,
		}

	case status >= 500:
		return ProbeResult{
			Kind:    ProbeProviderError,
			Summary: fmt.Sprintf("The provider itself failed (HTTP %d).", status),
			Detail: joinDetail("Nothing on this side needs changing: the address and the credential got the "+
				"request through, and the endpoint (or a gateway in front of it) failed to serve it. A 502, 503 "+
				"or 504 here is usually transient — retry. A repeated 500 is worth raising with whoever runs "+
				"the endpoint.", msg),
		}

	default:
		return ProbeResult{
			Kind:    ProbeUnexpectedStatus,
			Summary: fmt.Sprintf("The provider answered HTTP %d, which ARGUS does not recognise.", status),
			Detail: joinDetail("This is not a status an OpenAI-compatible chat-completions endpoint is "+
				"expected to return, which usually means the base URL is pointing at something that is not "+
				"that API.", msg),
		}
	}
}

// classifyProbeSuccessBody handles the 2xx case: a status alone proves
// nothing, because a proxy, a login page and a static site all answer 200.
//
// The success bar is deliberately "the body parses as a chat completion with
// at least one choice" and NOT "the choice contains text". With max_tokens=1
// an empty or single-character content field is the expected, correct outcome,
// and requiring non-empty text would have failed every well-configured
// provider — the exact kind of false negative that makes a test button
// worthless.
func classifyProbeSuccessBody(resp *http.Response, body []byte, pc probeContext) ProbeResult {
	var parsed chatResponse
	if err := json.Unmarshal(body, &parsed); err != nil || len(parsed.Choices) == 0 {
		detail := fmt.Sprintf("Something at %s answered HTTP %d, but the body is not a chat completion "+
			"(no `choices` array). That normally means the base URL is not pointing at the API: a web UI, an "+
			"SSO login page, a proxy's error page and a static site all answer 200.",
			pc.endpoint, resp.StatusCode)
		if ct := resp.Header.Get("Content-Type"); ct != "" && !strings.Contains(strings.ToLower(ct), "json") {
			detail += fmt.Sprintf(" The response's Content-Type was %q rather than JSON, which supports that.",
				truncate(sanitizeForMessage(ct), 60))
		}
		if snippet := providerMessage(body, pc.apiKey); snippet != "" {
			detail += " It said: " + snippet
		}
		return ProbeResult{Kind: ProbeMalformedResponse, Summary: "The endpoint answered, but not with a chat completion.", Detail: detail}
	}

	served := parsed.Model
	summary := "The provider answered correctly."
	detail := "The base URL, the credential and the model all work: ARGUS sent a one-word prompt with a " +
		"one-token generation cap and got a well-formed chat completion back."
	// An endpoint quietly serving a different model than the one requested is
	// a real misconfiguration (a gateway with a default route, a self-hosted
	// server with one model loaded) that is otherwise completely invisible —
	// analysis would just run against the wrong model forever.
	if served != "" && pc.model != "" && !strings.EqualFold(served, pc.model) {
		summary = "The provider answered — but with a different model than the one configured."
		detail = fmt.Sprintf("ARGUS asked for %q and the endpoint answered as %q. The connection, "+
			"credential and endpoint are all fine, but analysis will run against %q, not the configured "+
			"model. That is normal for a gateway that routes to a default, or a self-hosted server with a "+
			"single model loaded; if it is not what you expect, the model name is being ignored.",
			truncate(sanitizeForMessage(pc.model), 80), truncate(sanitizeForMessage(served), 80),
			truncate(sanitizeForMessage(served), 80))
	}

	return ProbeResult{
		OK:      true,
		Kind:    ProbeOK,
		Summary: summary,
		Detail:  detail,
		Caveat: "This test sends one word with no system prompt, no tools and a one-token cap, so it cannot " +
			"prove a full investigation will succeed — it says nothing about the context window, tool-calling " +
			"support, or remaining quota.",
		Model:     truncate(sanitizeForMessage(served), 200),
		TokensIn:  parsed.Usage.PromptTokens,
		TokensOut: parsed.Usage.CompletionTokens,
	}
}

// modelNotFoundResult is shared by every status a provider might use to say
// "no such model" — the whole point of detecting it from the body is that the
// status is not a reliable signal.
func modelNotFoundResult(msg string, pc probeContext, status int) ProbeResult {
	model := strings.TrimSpace(pc.model)
	if model == "" {
		model = "(none configured)"
	}
	return ProbeResult{
		Kind:    ProbeModelNotFound,
		Summary: fmt.Sprintf("The endpoint is reachable, but does not serve the model %q (HTTP %d).", truncate(sanitizeForMessage(model), 80), status),
		Detail: joinDetail("This is good news as far as the connection goes: the address is right and the "+
			"credential was accepted — only the model name is wrong. Model identifiers are exact, "+
			"case-sensitive and provider-specific (they differ between a vendor's own API, Bedrock, Vertex and "+
			"a self-hosted server serving the same weights), so copy it from the endpoint's own model list "+
			"rather than from documentation.", msg),
	}
}

// rateLimitedResult is reported for both 429 and a 403 carrying rate-limit
// markers. OK stays false — the probe did not complete — but the message is
// emphatic that nothing is misconfigured, because a throttled operator
// otherwise starts editing settings that were already correct.
func rateLimitedResult(resp *http.Response, msg string, status int) ProbeResult {
	detail := "Nothing is misconfigured: the address and credential both worked, and the account simply " +
		"has no quota available at this moment. Wait and test again."
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		detail += fmt.Sprintf(" The provider asked for a %s-second wait.", truncate(sanitizeForMessage(ra), 20))
	}
	if reset := resp.Header.Get("X-RateLimit-Reset"); reset != "" {
		detail += fmt.Sprintf(" Its rate limit resets at %s.", truncate(sanitizeForMessage(reset), 40))
	}
	return ProbeResult{
		Kind:    ProbeRateLimited,
		Summary: fmt.Sprintf("The provider is rate-limiting this account (HTTP %d).", status),
		Detail:  joinDetail(detail, msg),
	}
}

// ---------------------------------------------------------------------------
// cli providers
// ---------------------------------------------------------------------------

// ProbeCLIRunner tests a cli provider WITHOUT running an investigation, which
// is the entire difficulty of this half.
//
// A cli provider's only real endpoint is POST /investigate, and calling that
// for real would spawn a coding-agent CLI, drive a multi-turn loop against the
// hub's MCP server and bill for all of it — the most expensive request in the
// system, and the one thing a "test connection" button must never do. It also
// needs a cluster-scoped MCP token, so there is no harmless well-formed
// request to send.
//
// So the probe is two cheap calls that between them cover everything except
// the model:
//
//  1. GET /healthz — unauthenticated by design (it is a liveness target), and
//     it reports which CLI agents are actually installed and executable. This
//     covers DNS, TCP, TLS, "is anything there at all", "is it an ARGUS
//     runner", and "is the configured agent installed".
//  2. POST /investigate with an empty JSON object — which the runner rejects
//     with 400 *after* checking the bearer token and *before* acquiring a
//     concurrency slot or spawning anything (see cmd/cli-runner/main.go's
//     handleInvestigate: authorized() first, then the mcpUrl/mcpToken
//     validation, then the semaphore). So a 401 proves the token is wrong and
//     a 400 proves it is right, and neither runs a CLI or costs a token.
//     **That ordering in the runner is what makes this safe** — if it ever
//     changes so that validation happens after work begins, this call must
//     change with it.
//
// What a pass proves: the runner URL is right, the runner is up, the runner
// token matches, and the configured CLI is installed there.
//
// What a pass does NOT prove: that the CLI's own model credential works. That
// credential lives in the runner's environment and never passes through ARGUS
// at all, so only a real investigation exercises it. The Caveat says so
// plainly, because a green tick that implied otherwise would be actively
// misleading.
func ProbeCLIRunner(ctx context.Context, client *http.Client, t ProbeTarget) ProbeResult {
	if strings.TrimSpace(t.RunnerURL) == "" {
		return ProbeResult{
			Kind:    ProbeNotConfigured,
			Summary: "This provider has no runner URL, so there is nothing to call.",
			Detail: "A cli provider needs the address of an ARGUS CLI runner service, e.g. " +
				"http://argus-cli-runner:8090. Edit the provider and set it.",
		}
	}

	if reason, ok := unusableURL(t.RunnerURL); !ok {
		return ProbeResult{
			Kind:    ProbeNotConfigured,
			Summary: "The runner URL is not a usable URL.",
			Detail: fmt.Sprintf("%s It must be an absolute URL with a scheme and a host, e.g. "+
				"http://argus-cli-runner:8090.", reason),
		}
	}

	base := strings.TrimSuffix(strings.TrimSpace(t.RunnerURL), "/")
	agent := strings.TrimSpace(t.Agent)
	if agent == "" {
		// Same default as CLIInvestigator.Investigate, so the probe tests
		// what an investigation would actually ask for.
		agent = "claude"
	}
	// The runner token is passed as the pc.apiKey so that it is scrubbed out
	// of any message the runner (or anything else answering on that address)
	// echoes back, exactly as an API key would be.
	pc := probeContext{endpoint: redactURL(base + "/healthz"), apiKey: t.RunnerToken}

	start := time.Now()
	health, healthResult := probeRunnerHealth(ctx, client, base, agent, pc)
	if healthResult != nil {
		healthResult.LatencyMs = int(time.Since(start).Milliseconds())
		return *healthResult
	}

	if authResult := probeRunnerAuth(ctx, client, base, t.RunnerToken, pc); authResult != nil {
		authResult.LatencyMs = int(time.Since(start).Milliseconds())
		return *authResult
	}

	detail := fmt.Sprintf("The runner is up, it accepted the runner token, and it has %s installed", agent)
	if v := health[agent]; v != "" {
		detail += fmt.Sprintf(" (%s)", truncate(sanitizeForMessage(v), 120))
	}
	detail += "."
	return ProbeResult{
		OK:      true,
		Kind:    ProbeOK,
		Summary: "The CLI runner is reachable and accepted the token.",
		Detail:  detail,
		Caveat: "This proves the runner URL, the runner token and the CLI installation. It does NOT prove " +
			"the CLI's own model credential works — that lives in the runner's environment, never passes " +
			"through ARGUS, and is only exercised by a real investigation. No model was called and nothing " +
			"was billed by this test.",
		LatencyMs: int(time.Since(start).Milliseconds()),
	}
}

// runnerHealth is cmd/cli-runner's /healthz body: agent name -> version
// string, listing only the agents it found installed and executable.
type runnerHealth struct {
	Agents map[string]string `json:"agents"`
}

// probeRunnerHealth returns the installed-agent map, or a non-nil failure
// result. Two return values rather than an error because a failure here is
// already a fully-formed, classified answer — wrapping it in an error and
// unwrapping it at the call site would lose the classification.
func probeRunnerHealth(ctx context.Context, client *http.Client, base, agent string, pc probeContext) (map[string]string, *ProbeResult) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/healthz", nil)
	if err != nil {
		return nil, &ProbeResult{
			Kind:    ProbeNotConfigured,
			Summary: "The runner URL is not a usable URL.",
			Detail: fmt.Sprintf("ARGUS could not build a request for it: %s. It must be an absolute http:// "+
				"or https:// URL.", probeErrorDetail(err, pc.apiKey)),
		}
	}
	resp, err := httpClientOrDefault(client, probeCLIHTTPClient).Do(req)
	if err != nil {
		out := classifyProbeTransportError(err, pc)
		return nil, &out
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))

	if resp.StatusCode == http.StatusNotFound {
		return nil, &ProbeResult{
			Kind:    ProbeNotARunner,
			Summary: "Something is listening there, but it is not an ARGUS CLI runner.",
			Detail: fmt.Sprintf("A GET to %s returned 404. Every ARGUS CLI runner serves /healthz, so this "+
				"address is almost certainly pointing at a different service — check the port, and check that "+
				"the runner URL has no extra path on the end.", pc.endpoint),
		}
	}

	var parsed runnerHealth
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, &ProbeResult{
			Kind:    ProbeNotARunner,
			Summary: "Something is listening there, but it is not an ARGUS CLI runner.",
			Detail: joinDetail(fmt.Sprintf("A GET to %s returned HTTP %d with a body that is not the runner's "+
				"health JSON. Check the port and the path.", pc.endpoint, resp.StatusCode),
				providerMessage(body, pc.apiKey)),
		}
	}

	// 503 with an empty agent map is the runner's own way of saying it has no
	// usable CLI — see cmd/cli-runner's handleHealthz. Reported as a missing
	// agent rather than a generic failure, because the fix is inside the
	// runner's image, not in ARGUS.
	if len(parsed.Agents) == 0 {
		return nil, &ProbeResult{
			Kind:    ProbeAgentMissing,
			Summary: "The runner is up but has no usable CLI agent installed.",
			Detail: "It answered its health check and reported zero installed agents, so every investigation " +
				"sent to it would fail. The runner's own image needs a working `claude` or `codex` binary on " +
				"its PATH; nothing about this provider's configuration will fix it.",
		}
	}
	if _, ok := parsed.Agents[agent]; !ok {
		return nil, &ProbeResult{
			Kind:    ProbeAgentMissing,
			Summary: fmt.Sprintf("The runner is up, but does not have %q installed.", agent),
			Detail: fmt.Sprintf("This provider is configured to drive %q, and the runner reports these agents "+
				"as installed instead: %s. Either change this provider's agent to one the runner has, or add "+
				"the missing CLI to the runner's image.", agent, strings.Join(sortedAgentNames(parsed.Agents), ", ")),
		}
	}
	return parsed.Agents, nil
}

// probeRunnerAuth returns nil when the runner accepted the token, or a
// classified failure. See ProbeCLIRunner's doc comment for why an
// intentionally-invalid POST is the correct — and free — way to test this.
func probeRunnerAuth(ctx context.Context, client *http.Client, base, token string, pc probeContext) *ProbeResult {
	// An empty object: it fails the runner's mcpUrl/mcpToken check, its
	// allowedTools check, and carries no prompt. There is no reading of this
	// body under which any work could begin.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/investigate", strings.NewReader("{}"))
	if err != nil {
		return &ProbeResult{Kind: ProbeUnexpectedStatus, Summary: "Could not build the runner auth check.", Detail: probeErrorDetail(err, token)}
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := httpClientOrDefault(client, probeCLIHTTPClient).Do(req)
	if err != nil {
		out := classifyProbeTransportError(err, pc)
		return &out
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))

	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		what := "The runner rejected the runner token"
		if token == "" {
			what = "No runner token is configured, and the runner requires one"
		}
		return &ProbeResult{
			Kind:    ProbeUnauthorized,
			Summary: fmt.Sprintf("%s (HTTP %d).", what, resp.StatusCode),
			Detail: "The value stored here must match the runner's own ARGUS_CLI_RUNNER_TOKEN exactly. The " +
				"runner refuses to serve without one at all, so an empty token here can never work. Note this " +
				"is the token that authenticates ARGUS to the runner — not the model credential, which lives " +
				"in the runner's environment.",
		}
	case resp.StatusCode == http.StatusBadRequest:
		// The expected, wanted outcome: past authentication, refused on
		// content. Nothing ran.
		return nil
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		// Should be impossible against a real runner, which requires mcpUrl
		// and mcpToken. Flagged rather than passed, because a 2xx here means
		// whatever is on that address is not enforcing the runner's contract
		// and may have accepted an unscoped request.
		return &ProbeResult{
			Kind:    ProbeNotARunner,
			Summary: "That address accepted an obviously invalid investigation request.",
			Detail: "An ARGUS CLI runner rejects a request with no MCP URL or token; this one returned " +
				"success. Whatever is listening is not behaving like a runner, and ARGUS will not treat it as " +
				"one. Check the runner URL.",
		}
	default:
		return &ProbeResult{
			Kind:    ProbeUnexpectedStatus,
			Summary: fmt.Sprintf("The runner answered its auth check with an unexpected HTTP %d.", resp.StatusCode),
			Detail: joinDetail("Its health check passed, so something is there, but it did not respond to the "+
				"token check the way a runner does.", providerMessage(body, pc.apiKey)),
		}
	}
}

func sortedAgentNames(agents map[string]string) []string {
	names := make([]string, 0, len(agents))
	for name := range agents {
		names = append(names, sanitizeForMessage(name))
	}
	// Sorted so the message is stable across calls (Go map iteration is not).
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	return names
}

// ---------------------------------------------------------------------------
// transport-error classification
// ---------------------------------------------------------------------------

// classifyProbeTransportError names the specific network-level cause of a
// failed request.
//
// Order matters and is not arbitrary. DNS is checked first because a DNS
// timeout is both a *net.DNSError and a timeout, and "the hostname does not
// resolve" is the more useful of the two answers. TLS comes next because a
// handshake failure surfaces as a plain connection error to anything that
// only looks at the outer type. Only then the connect-level errno cases, and
// finally the generic timeout — which is what a wedged-but-listening endpoint
// produces, and which must not be shadowed by any of the above.
//
// Nothing here embeds err.Error() directly: a *url.Error stringifies with the
// full request URL, which may carry a credential in its query string. See
// probeErrorDetail.
func classifyProbeTransportError(err error, pc probeContext) ProbeResult {
	inner := probeErrorDetail(err, pc.apiKey)

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsNotFound:
			return ProbeResult{
				Kind:    ProbeDNSFailure,
				Summary: fmt.Sprintf("The hostname %q does not resolve.", truncate(sanitizeForMessage(dnsErr.Name), 120)),
				Detail: "DNS returned no record for it, so nothing was contacted. Check the hostname for a " +
					"typo. If this is an in-cluster address, remember the hub resolves it from its own " +
					"namespace — a bare service name only works inside the same namespace, otherwise it needs " +
					"the service.namespace form.",
			}
		case dnsErr.IsTimeout:
			return ProbeResult{
				Kind:    ProbeDNSFailure,
				Summary: fmt.Sprintf("The DNS lookup for %q timed out.", truncate(sanitizeForMessage(dnsErr.Name), 120)),
				Detail: "The hostname may well be correct — the hub's own DNS resolver did not answer in time. " +
					"This is a problem with the hub's networking rather than with this provider's " +
					"configuration.",
			}
		default:
			return ProbeResult{
				Kind:    ProbeDNSFailure,
				Summary: fmt.Sprintf("The hostname %q could not be resolved.", truncate(sanitizeForMessage(dnsErr.Name), 120)),
				Detail:  joinDetail("DNS resolution failed, so nothing was contacted.", inner),
			}
		}
	}

	if kind, summary, detail, ok := classifyTLSError(err, inner); ok {
		return ProbeResult{Kind: kind, Summary: summary, Detail: detail}
	}

	if errors.Is(err, syscall.ECONNREFUSED) {
		return ProbeResult{
			Kind:    ProbeConnectionRefused,
			Summary: "The connection was refused.",
			Detail: fmt.Sprintf("The host is reachable and actively refused the connection to %s, which means "+
				"nothing is listening on that port. Check the port number first, then whether the service is "+
				"running.", pc.endpoint),
		}
	}

	// Checked before the generic timeout so that a wedged endpoint and an
	// unroutable one do not report the same thing.
	switch {
	case errors.Is(err, syscall.ECONNRESET):
		return ProbeResult{
			Kind:    ProbeNetworkFailure,
			Summary: "The connection was reset by the other end.",
			Detail: joinDetail("Something accepted the connection and then dropped it mid-request. A proxy, "+
				"load balancer or firewall between the hub and the endpoint is the usual cause; so is speaking "+
				"plain HTTP to a port that expects TLS.", inner),
		}
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return ProbeResult{
			Kind:    ProbeNetworkFailure,
			Summary: "There is no route from the hub to that address.",
			Detail: joinDetail("The hostname resolved but the network is unreachable from where the hub runs. "+
				"This is a networking/egress question (NetworkPolicy, routing, VPN) rather than anything about "+
				"the provider's configuration.", inner),
		}
	}

	if isTimeoutError(err) {
		return ProbeResult{
			Kind:    ProbeTimedOut,
			Summary: fmt.Sprintf("The endpoint did not answer within %s.", ProbeTimeout),
			Detail: fmt.Sprintf("The connection to %s was established (or at least not refused) and no "+
				"response arrived in time. A self-hosted server loading a model on first request can genuinely "+
				"take longer than this, so retrying once is worth doing; a consistent timeout points at an "+
				"overloaded or wedged endpoint, or at a firewall silently dropping the traffic rather than "+
				"refusing it.", pc.endpoint),
		}
	}

	return ProbeResult{
		Kind:    ProbeNetworkFailure,
		Summary: "The request could not be completed.",
		Detail:  joinDetail(fmt.Sprintf("ARGUS could not reach %s.", pc.endpoint), inner),
	}
}

// classifyTLSError recognises the handshake failures, including the two
// scheme mix-ups that are not certificate problems at all but land in the
// same place and have the same one-character fix.
//
// The two string matches are deliberate and commented: net/http reports both
// scheme mix-ups as plain errors with no exported sentinel to match on, and a
// wrong scheme is far too common a misconfiguration to leave in the generic
// bucket for want of a typed error.
func classifyTLSError(err error, inner string) (kind, summary, detail string, ok bool) {
	lower := strings.ToLower(err.Error())

	// https:// pointed at a plaintext listener.
	if strings.Contains(lower, "server gave http response to https client") {
		return ProbeTLSFailure,
			"The endpoint speaks plain HTTP, but the URL says https://.",
			"The TLS handshake failed because the server answered it with an unencrypted HTTP response. " +
				"Change the base URL's scheme from https:// to http://, or point it at the endpoint's TLS port.",
			true
	}
	// http:// pointed at a TLS listener: the "response" is a TLS record,
	// which net/http reports as a malformed HTTP response.
	if strings.Contains(lower, "malformed http response") || strings.Contains(lower, "first record does not look like a tls handshake") {
		return ProbeTLSFailure,
			"The scheme in the URL does not match what the endpoint speaks.",
			joinDetail("The server's reply was not valid HTTP, which almost always means the URL's scheme is "+
				"wrong — http:// against a TLS port, or https:// against a plaintext one. Try the other scheme.", inner),
			true
	}

	var certErr *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var invalidCert x509.CertificateInvalidError
	var recordHeader tls.RecordHeaderError

	switch {
	case errors.As(err, &hostnameErr):
		return ProbeTLSFailure,
			"The endpoint's TLS certificate is not valid for that hostname.",
			joinDetail("The certificate presented does not list the hostname in the base URL. Use the "+
				"hostname the certificate is actually issued for — an IP address or an in-cluster service name "+
				"often is not one.", inner),
			true
	case errors.As(err, &unknownAuthority):
		return ProbeTLSFailure,
			"The endpoint's TLS certificate is not trusted by the hub.",
			joinDetail("It is signed by a certificate authority the hub does not know — typical for a private "+
				"CA or a self-signed certificate on a self-hosted endpoint. The hub's trust store needs that CA "+
				"added; ARGUS will not skip verification, since that would make the credential it sends "+
				"interceptable.", inner),
			true
	case errors.As(err, &invalidCert):
		return ProbeTLSFailure,
			"The endpoint's TLS certificate was rejected.",
			joinDetail("The certificate itself is not acceptable — most often expired, or not valid for this "+
				"use. Check its validity dates at the endpoint.", inner),
			true
	case errors.As(err, &certErr), errors.As(err, &recordHeader):
		return ProbeTLSFailure,
			"The TLS handshake with the endpoint failed.",
			joinDetail("The TCP connection succeeded and the encrypted session could not be established. "+
				"This is not a credential problem: check the certificate, the scheme, and the port.", inner),
			true
	}
	return "", "", "", false
}

// looksLikePlaintextToTLSPort recognises the HTTP-level complaint a TLS
// listener returns when it is handed an unencrypted request. Matched on the
// message because it arrives as a well-formed HTTP 400 with nothing else to
// distinguish it — Go's net/http and nginx are the two implementations that do
// this, and between them they cover most of what a self-hosted endpoint sits
// behind.
func looksLikePlaintextToTLSPort(msg string) bool {
	lower := strings.ToLower(msg)
	return strings.Contains(lower, "http request to an https server") ||
		strings.Contains(lower, "http request was sent to https port")
}

func isTimeoutError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// ---------------------------------------------------------------------------
// message extraction and redaction
// ---------------------------------------------------------------------------

// probeMessageMaxLen bounds any string that came from outside this process
// before it reaches a ProbeResult. Long enough for a real provider error
// (they are usually one sentence), short enough that a proxy's HTML page
// cannot turn a UI error into a wall of markup.
const probeMessageMaxLen = 400

// providerMessage extracts the human-readable error out of a provider's
// response body, across the several shapes OpenAI-compatible servers actually
// use, and returns "" when it cannot find one.
//
// The shapes handled, all seen in the wild on endpoints this package targets:
//
//	{"error": {"message": "...", "type": "...", "code": "..."}}   OpenAI et al
//	{"error": "..."}                                             Ollama, gateways
//	{"message": "..."} / {"detail": "..."}                        vLLM, FastAPI fronts
//
// `error` is decoded as a json.RawMessage rather than a typed field because it
// is an object in the first shape and a string in the second — a single struct
// would fail to unmarshal on one of them and lose the other fields with it.
//
// Whatever comes back is untrusted text from a remote server, so it is
// scrubbed of the credential, stripped of control characters, collapsed onto
// one line and truncated before it is allowed anywhere near a result.
func providerMessage(body []byte, secret string) string {
	var envelope struct {
		Error   json.RawMessage `json:"error"`
		Message string          `json:"message"`
		Detail  string          `json:"detail"`
	}
	msg := ""
	if err := json.Unmarshal(body, &envelope); err == nil {
		var asObject struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			// Code is `any` because providers send it as both a string
			// ("model_not_found") and a number (400).
			Code any `json:"code"`
		}
		var asString string
		switch {
		case len(envelope.Error) > 0 && json.Unmarshal(envelope.Error, &asObject) == nil && asObject.Message != "":
			msg = asObject.Message
			// The type/code is often the only machine-precise part
			// (looksLikeModelNotFound reads it), so it is kept alongside the
			// prose rather than dropped.
			if asObject.Type != "" {
				msg += " (" + asObject.Type + ")"
			}
			if code, ok := asObject.Code.(string); ok && code != "" && code != asObject.Type {
				msg += " [" + code + "]"
			}
		case len(envelope.Error) > 0 && json.Unmarshal(envelope.Error, &asString) == nil && asString != "":
			msg = asString
		case envelope.Message != "":
			msg = envelope.Message
		case envelope.Detail != "":
			msg = envelope.Detail
		}
	}
	if msg == "" {
		// Not JSON, or JSON with no recognisable error field. A bounded
		// snippet of the raw body is still the most useful thing available —
		// an HTML title or a plaintext error line often names the real
		// problem.
		msg = string(body)
	}
	msg = sanitizeForMessage(msg)
	msg = redactSecret(msg, secret)
	return truncate(msg, probeMessageMaxLen)
}

// looksLikeModelNotFound decides whether a provider's error is about the model
// name rather than the address or the credential.
//
// Necessary because the status code does not settle it: the same condition
// arrives as 400 from some endpoints, 403 from others, 404 from most and 422
// from a few. Matched on the message and on OpenAI's `code`/`type` marker,
// both of which travel inside the string providerMessage builds.
//
// Deliberately conservative — it requires a "model" word AND an
// absence/invalidity word. A false positive here is worse than a false
// negative, because it would tell someone their model name is wrong when
// their base URL is.
func looksLikeModelNotFound(msg, model string) bool {
	if msg == "" {
		return false
	}
	lower := strings.ToLower(msg)
	for _, marker := range []string{"model_not_found", "model_not_available", "invalid_model", "unknown_model"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	mentionsModel := strings.Contains(lower, "model")
	if !mentionsModel && model != "" {
		mentionsModel = strings.Contains(lower, strings.ToLower(model))
	}
	if !mentionsModel {
		return false
	}
	for _, phrase := range []string{
		"not found", "does not exist", "doesn't exist", "not exist",
		"unknown model", "no such model", "invalid model", "unsupported model",
		"is not supported", "not available", "unavailable",
	} {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	return false
}

// redactSecret removes a credential from a string that is about to be shown
// to a caller.
//
// This is belt-and-braces: no provider echoes an API key back, and none of
// the messages this file constructs contain one. But a misconfigured base URL
// can point at an arbitrary host — including a debug endpoint or a proxy that
// reflects the request it received — and the requirement is absolute (never
// return the key, or any prefix or suffix of it). Replacing rather than
// truncating matters: showing even a prefix would leak key material, so the
// whole occurrence goes.
//
// Short secrets are skipped: a one- or two-character "key" is not a
// credential, and blanking every occurrence of a common substring would
// mangle the message for no benefit.
func redactSecret(s, secret string) string {
	if len(secret) < 8 {
		return s
	}
	return strings.ReplaceAll(s, secret, "[redacted]")
}

// unusableURL reports whether a configured address can be dialled at all,
// returning a human reason when it cannot.
//
// Only the two things that actually matter are required: an http/https scheme
// and a host. Deliberately not stricter than that — an operator may
// legitimately configure an IP, a port, a non-standard path, or an in-cluster
// service name, and a validator that second-guessed any of those would reject
// working configurations.
func unusableURL(raw string) (reason string, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "It is empty.", false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "It could not be parsed as a URL.", false
	}
	if u.Scheme == "" {
		return "It has no scheme — a bare hostname is not enough.", false
	}
	// "argus-cli-runner:8090" parses as scheme "argus-cli-runner" with opaque
	// "8090", not as a host and port — so a bare host:port must be reported as
	// a missing scheme rather than as an exotic one, which is what the reader
	// would otherwise be told about their own hostname.
	if u.Host == "" && u.Opaque != "" {
		return "It has no scheme — a bare host:port is not enough.", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Sprintf("Its scheme is %q; only http and https can be called.", truncate(sanitizeForMessage(u.Scheme), 20)), false
	}
	if u.Host == "" {
		return "It has no host.", false
	}
	return "", true
}

// redactURL renders a URL for display with its query string, fragment and any
// embedded userinfo removed.
//
// Not paranoia: several real providers authenticate with a query parameter
// (`?key=`, `?api-key=`, `?code=`), and this codebase's own repository
// bindings already refuse URLs with embedded credentials for the same reason
// (internal/scm). Since a provider's base URL is operator-supplied free text,
// a probe message that echoed it verbatim would be a credential-disclosure
// path. Only the parts needed to diagnose a wrong address are kept.
func redactURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		// Unparseable, or relative: return nothing rather than risk echoing
		// an unexamined string that may carry a token.
		return "the configured address"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return truncate(sanitizeForMessage(u.String()), 200)
}

// probeErrorDetail renders an error for an operator with both the credential
// and the request URL removed.
//
// The URL removal is the important half: net/url's *url.Error stringifies as
// `Post "https://host/path?key=SECRET": dial tcp: ...`, so embedding
// err.Error() would defeat redactURL entirely. Unwrapping to the inner error
// drops the URL at the source instead of trying to scrub it afterwards.
func probeErrorDetail(err error, secret string) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		msg = urlErr.Err.Error()
	}
	return truncate(redactSecret(sanitizeForMessage(msg), secret), probeMessageMaxLen)
}

// sanitizeForMessage collapses untrusted text onto one line and strips
// control characters, so a remote server cannot inject line breaks or
// terminal escapes into a message the hub logs or renders.
func sanitizeForMessage(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r == '\r' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(strings.Join(strings.Fields(s), " "))
}

func truncate(s string, max int) string {
	if runes := []rune(s); len(runes) > max {
		return string(runes[:max]) + "…"
	}
	return s
}

// joinDetail appends a provider's own words to ARGUS's explanation, clearly
// attributed. Attribution matters: an operator needs to know which half is
// ARGUS's diagnosis and which half is the endpoint's, because only the second
// is authoritative about that endpoint.
func joinDetail(ours, theirs string) string {
	if strings.TrimSpace(theirs) == "" {
		return ours
	}
	return ours + " The provider said: " + theirs
}

func orNoMessage(msg string) string {
	if strings.TrimSpace(msg) == "" {
		return "(it returned no message)"
	}
	return msg
}

// isRateLimitResponse recognises throttling that arrives dressed as a 403.
// The header check mirrors internal/scm/github.go's; the message check catches
// endpoints that only say so in prose.
func isRateLimitResponse(resp *http.Response, msg string) bool {
	if resp.Header.Get("X-RateLimit-Remaining") == "0" || resp.Header.Get("Retry-After") != "" {
		return true
	}
	lower := strings.ToLower(msg)
	return strings.Contains(lower, "rate limit") || strings.Contains(lower, "rate_limit") ||
		strings.Contains(lower, "too many requests") || strings.Contains(lower, "quota")
}

// probeAPIClient/probeCLIHTTPClient are the clients ProbeAPIProvider and
// the cli-probe helpers (probeRunnerHealth/probeRunnerAuth) use unless a test
// injects one. Split in two — rather than one shared probeHTTPClient, as this
// file had before — because the two probe kinds read two different
// admin-configured URLs (ai_providers.base_url vs. settings.CLIRunnerURL)
// that get two different, deliberately DIFFERENT outbound.Policy values from
// their real callers (aiProviderOutboundPolicy in provider.go is
// default-deny; cliRunnerOutboundPolicy in cli_investigator.go allows
// private, since the runner is a same-deployment sidecar/Service). Each
// probe client is built from the SAME policy VARIABLE its real caller uses,
// not a second copy of the literal, so the probe and the real path can never
// silently drift apart — see aiProviderOutboundPolicy's own comment for why
// that drift specifically (a probe reporting "connection OK" for a
// destination the real path then refuses) is a defect this codebase treats
// as seriously as a fabricated zero.
//
// Both share two other properties, unchanged from before this split:
//
// Redirects are NOT followed. This request carries a bearer credential, and
// following a redirect would hand that credential to whatever host the
// redirect names — a host chosen by whoever controls the endpoint, which is
// precisely the misconfiguration being tested for. The redirect is reported
// instead (ProbeRedirected), which is also the more useful answer.
//
// No client-level Timeout is set. The bound is the context deadline applied in
// ProbeProvider, and a second, independent timeout here would silently take
// precedence over it — the same reasoning as CLIInvestigator's client.
// probeAPIClient is built per probe rather than once at package init,
// because the policy it needs now carries a runtime allowlist source
// (ProbeTarget.PrivateDestinations) that package init has no way to obtain.
// Building an *http.Client here costs nothing on a path that already makes a
// network round-trip, and it is what keeps the probe and the real provider
// path reading the same operator allowlist.
func probeAPIClient(src outbound.AllowlistSource) *http.Client {
	return newProbeDefaultClient(aiProviderOutboundPolicy(src))
}

// probeCLIHTTPClient stays a package-level value: cliRunnerOutboundPolicy is
// a static compile-time allowance (AllowPrivate, because the runner is a
// same-deployment sidecar/Service) with no operator-configurable part, so
// there is nothing for it to resolve per call.
var probeCLIHTTPClient = newProbeDefaultClient(cliRunnerOutboundPolicy)

func newProbeDefaultClient(policy outbound.Policy) *http.Client {
	c := outbound.NewClient(policy, 0)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

// httpClientOrDefault returns c, redirect-suppressed, if a test injected one,
// otherwise def — the real default for whichever probe kind is calling
// (probeAPIClient's result or probeCLIHTTPClient).
func httpClientOrDefault(c, def *http.Client) *http.Client {
	if c == nil {
		return def
	}
	// A test's injected client (httptest's, which trusts that server's cert)
	// is used as given, except that redirect-following is suppressed the same
	// way — otherwise the ProbeRedirected path would be untestable.
	clone := *c
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &clone
}
