// Package outbound is ARGUS's one hardened HTTP transport for every
// operator- or provider-influenced destination the hub dials out to.
//
// lld/01-threat-model.md T15/SR-16 and T6/SR-9 both describe the same class
// of gap from two angles: an admin-supplied URL (a notification webhook, a
// self-hosted SCM API base, a model provider's base_url) can point at a
// cloud metadata endpoint or an internal-only address, and even a validated
// hostname can be made to resolve somewhere else by the time the dialer
// actually connects (DNS rebinding). Five packages build their own
// *http.Client today, each with none of this: internal/llm (AI providers,
// and the CLI-runner sidecar), internal/scm (repositories), internal/notify
// (webhooks), internal/idp (OIDC discovery) and internal/knowledge (Ollama
// embeddings). This package gives all of them one client constructor so the
// validation lives in exactly one place rather than five slightly different
// half-attempts at it.
//
// # The default is refuse, and the blanket allowance is per-caller code, not config
//
// Policy.AllowPrivate is false unless a caller sets it. THREE callers do,
// and this list was wrong here until 2026-09-19 — it named only the first
// two, which reads as "the webhook is default-deny" and is not true:
//
//   - internal/idp — a self-hosted broker such as Dex commonly runs on
//     localhost or an internal address;
//   - internal/knowledge — Ollama is a self-hosted model server, routinely
//     on localhost or a private LAN address;
//   - internal/notify — an internal alerting/chat receiver or corporate
//     proxy is the expected webhook target for a self-hosted ARGUS, not an
//     exception (see notifier.go's own Reason).
//
// All three set it as a Go literal at their own construction site — never
// read from a database row, a settings API value, or an environment
// variable — so there is no runtime knob anywhere that widens it wholesale,
// and in particular no admin-facing "disable SSRF protection" switch.
//
// The two callers that do NOT set it are the ones this package's narrow
// opt-in exists for: internal/llm's AI-provider client and internal/scm's
// repository clients.
//
// # The narrow, named, operator-visible exception (2026-09-19)
//
// Those two are NOT well served by an all-or-nothing compile-time decision:
// the AI provider's base_url (B5) and a repository's API base URL (B7) are
// normally public and occasionally private — a self-hosted vLLM, an internal
// GitHub Enterprise Server — and which one an installation has is an
// operator fact. The owner's decision was to keep default-deny and add an
// opt-in that names SPECIFIC destinations, rejecting both "allow private by
// default" and "no opt-in at all".
//
// Policy.PrivateDestinations is that opt-in, and allowlist.go is all of it.
// It is deliberately not a boolean: an operator names hosts/IPs/CIDRs, an
// entry can only ever permit an address that would otherwise be refused, and
// everything not named stays refused. It is read at dial time and matched
// against the RESOLVED address, so it does not weaken the rebinding defence
// below. Cloud metadata remains unreachable through it by three independent
// checks. internal/notify, internal/idp and internal/knowledge do not set it
// and their behaviour is unchanged — for those three the question does not
// arise, since each already holds the wholesale allowance.
//
// # The one exception with no allowance, ever
//
// Cloud metadata endpoints (169.254.169.254, fd00:ec2::254,
// metadata.google.internal) are refused unconditionally, before Policy is
// even consulted. This holds for every caller, including the two that set
// AllowPrivate — an Ollama or OIDC base URL pointed at the metadata service
// is refused exactly like it would be for a webhook.
//
// # DNS rebinding
//
// Validating a hostname and then letting the standard dialer resolve it
// again leaves a window: the name can resolve to an allowed address at
// validation time and a different, disallowed one at connect time. This
// package closes that by resolving the hostname itself, inside
// DialContext, validating the resolved address, and then dialing that
// literal IP — never handing the hostname to net.Dial a second time. The
// same validation runs again on every redirect (CheckRedirect), because a
// 302 is just as capable of pointing at a private address as the original
// URL was, and http.Client does not otherwise re-validate anything about a
// redirect target beyond letting the Transport dial it.
package outbound

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Policy describes what a specific caller's destination is allowed to be.
// The zero value is the safe default: refuse loopback, link-local and
// private-range destinations, in addition to the unconditional metadata
// refusal every Policy gets regardless of its fields.
type Policy struct {
	// AllowPrivate opts this caller's client into reaching loopback,
	// link-local and RFC1918/RFC4193 private destinations, in addition to
	// public ones. See the package doc comment for why this must only ever
	// be set as a literal at a caller's own construction site. It is the
	// WHOLESALE allowance; PrivateDestinations below is the narrow one, and
	// a caller sets at most one of the two.
	AllowPrivate bool

	// PrivateDestinations, when non-nil, is consulted at dial time for an
	// address that AllowPrivate would otherwise refuse: if the operator has
	// named that specific address, the dial proceeds; if not, it is refused
	// exactly as before, and the refusal says the allowlist is the lever.
	//
	// A function, not a value, because the clients that need it are built
	// once (at hub startup, or per repository operation) while the setting
	// is edited at runtime through the admin settings API — the same
	// resolve-fresh-per-use contract internal/settings applies to every
	// other org setting, so a change takes effect without a hub restart.
	// It is called only on the path to a refusal, so an ordinary public
	// destination never pays for it.
	//
	// Setting this does NOT relax anything else: metadata is still refused
	// unconditionally and before this is consulted, the resolved address is
	// still what gets checked, and an entry that does not name a
	// loopback/link-local/private address cannot be stored at all. See
	// allowlist.go.
	PrivateDestinations AllowlistSource

	// Reason is a short, operator-visible statement of why AllowPrivate is
	// set — surfaced in this package's own refusal-adjacent documentation
	// and required whenever AllowPrivate is true, so an exception always
	// carries its own justification rather than being an unexplained flag
	// some future reader has to reverse-engineer. NewClient panics if
	// AllowPrivate is true and Reason is empty.
	Reason string

	// DialTimeout bounds a single connection attempt (the TCP handshake,
	// not the whole request). Defaults to 10s when zero.
	DialTimeout time.Duration

	// MaxRedirects bounds how many redirects CheckRedirect will follow
	// before refusing. Defaults to 5 when zero; a negative value means
	// "follow none".
	MaxRedirects int
}

func (p Policy) dialTimeout() time.Duration {
	if p.DialTimeout > 0 {
		return p.DialTimeout
	}
	return 10 * time.Second
}

func (p Policy) maxRedirects() int {
	if p.MaxRedirects != 0 {
		return p.MaxRedirects
	}
	return 5
}

// RefusalError is returned (wrapped) whenever a request or a redirect is
// refused. Reason is a short, stable, human-readable statement of exactly
// what was refused and why — the acceptance criterion this package exists
// to satisfy is that a refusal states a reason, not just "connection
// failed".
type RefusalError struct {
	Target string // the host, or host:port, or URL that was refused
	Reason string
}

func (e *RefusalError) Error() string {
	return fmt.Sprintf("outbound: refused %s: %s", e.Target, e.Reason)
}

// metadataHosts is matched case-insensitively, with a trailing dot trimmed,
// against the hostname a caller asked to dial — BEFORE any DNS resolution,
// so a metadata hostname is refused even if resolving it were somehow to
// fail or be intercepted. This is the unconditional half of the metadata
// refusal; metadataIPs below is the other half, for callers that skip the
// hostname (a literal IP) or whose DNS resolves to one of these anyway.
var metadataHosts = map[string]bool{
	"metadata.google.internal": true,
	"metadata":                 true, // GCE's short form of the same host
}

// metadataIPs are cloud instance-metadata addresses. 169.254.169.254 is used
// by AWS, Azure, GCP, DigitalOcean, Oracle Cloud and Alibaba Cloud IMDS;
// fd00:ec2::254 is AWS's IPv6 equivalent. Neither Policy.AllowPrivate nor any
// other field ever overrides this list — see the package doc comment's "one
// exception with no allowance" section.
var metadataIPs = []net.IP{
	net.ParseIP("169.254.169.254"),
	net.ParseIP("fd00:ec2::254"),
}

func isMetadataHost(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	return metadataHosts[h]
}

func isMetadataIP(ip net.IP) bool {
	for _, m := range metadataIPs {
		if m != nil && m.Equal(ip) {
			return true
		}
	}
	return false
}

// lookupIP is the one resolver this package uses — for the destination
// hostname in safeDialContext and for a hostname ENTRY in
// Allowlist.permits, so both answer "what does this name resolve to right
// now" the same way. A package-level var solely so a test can substitute a
// fake resolver and prove the metadata refusal survives a name that
// resolves to 169.254.169.254; it is unexported and nothing in the product
// reassigns it.
var lookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
	resolved, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(resolved))
	for _, r := range resolved {
		ips = append(ips, r.IP)
	}
	return ips, nil
}

// classify reports whether ip is reachable under policy, and if not, why.
// Metadata is refused unconditionally, before anything else is consulted;
// loopback/link-local/private need either policy.AllowPrivate or an
// operator allowlist entry naming that address; anything else (an ordinary
// public address) is always allowed.
//
// allowlist is a lazy getter rather than a value so that the DB read behind
// it happens at most once per dial and only when an address is otherwise
// about to be refused. It is nil when the caller's policy has no allowlist
// source at all, and the refusal wording differs in that case: telling an
// operator to "add it to the allowlist" would be false advice for a client
// that does not consult one.
func classify(ctx context.Context, ip net.IP, policy Policy, allowlist func() (Allowlist, error)) error {
	if isMetadataIP(ip) {
		return &RefusalError{Target: ip.String(), Reason: "cloud metadata address — refused unconditionally, no allowance exists for this"}
	}
	if ip.IsUnspecified() {
		return &RefusalError{Target: ip.String(), Reason: "unspecified address"}
	}

	var class string
	switch {
	case ip.IsLoopback():
		class = "loopback address"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		class = "link-local address"
	case ip.IsPrivate():
		class = "private-range address"
	default:
		return nil // an ordinary public address
	}

	if policy.AllowPrivate {
		return nil
	}
	if allowlist == nil {
		return &RefusalError{Target: ip.String(), Reason: class + ", and this caller's policy does not allow private destinations"}
	}

	allowed, err := allowlist()
	if err != nil {
		// Fail closed, and say so: a guard that opens when it cannot read
		// its own policy is not a guard.
		return &RefusalError{Target: ip.String(), Reason: class + ", and the operator allowlist of permitted private destinations could not be read (" + err.Error() + ") — refusing rather than assuming it is allowed"}
	}
	if _, ok := allowed.permits(ctx, ip); ok {
		return nil
	}
	return &RefusalError{
		Target: ip.String(),
		Reason: class + ", and it is not one of the private destinations an operator has allowlisted — add it under the outbound settings section, with a reason, if this destination is intended",
	}
}

// validateScheme refuses anything that is not plain HTTP(S). file://,
// gopher://, and similar schemes reaching this far would mean a caller
// handed a fetch function a URL it never should have accepted.
func validateScheme(u *url.URL) error {
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return nil
	default:
		return &RefusalError{Target: u.String(), Reason: fmt.Sprintf("scheme %q is refused — only http and https are allowed", u.Scheme)}
	}
}

// validatePort refuses a malformed or out-of-range port. url.Parse already
// rejects most garbage here; this is a second, explicit check so the
// refusal reason is ours rather than net/url's generic parse error.
func validatePort(portStr string) error {
	if portStr == "" {
		return nil
	}
	n := 0
	for _, c := range portStr {
		if c < '0' || c > '9' {
			return &RefusalError{Target: portStr, Reason: "port is not numeric"}
		}
		n = n*10 + int(c-'0')
		if n > 65535 {
			return &RefusalError{Target: portStr, Reason: "port out of range"}
		}
	}
	if n == 0 {
		return &RefusalError{Target: portStr, Reason: "port 0 is refused"}
	}
	return nil
}

// safeDialContext returns a DialContext function that resolves host once,
// validates the resolved address(es) against policy (and unconditionally
// against the metadata list), and dials the validated IP literally — so the
// address that gets validated is the exact address that gets connected to,
// closing the DNS-rebinding window between a pre-flight check and the
// dialer's own, later resolution.
func safeDialContext(policy Policy) func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: policy.dialTimeout()}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("outbound: %w", err)
		}
		if err := validatePort(port); err != nil {
			return nil, err
		}
		if isMetadataHost(host) {
			return nil, &RefusalError{Target: host, Reason: "cloud metadata hostname — refused unconditionally, no allowance exists for this"}
		}

		var ips []net.IP
		if literal := net.ParseIP(host); literal != nil {
			ips = []net.IP{literal}
		} else {
			resolved, err := lookupIP(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("outbound: resolve %s: %w", host, err)
			}
			ips = resolved
		}
		if len(ips) == 0 {
			return nil, &RefusalError{Target: host, Reason: "no addresses resolved"}
		}

		// Resolved at most once per dial, and only if some address actually
		// reaches the allowlist branch of classify — see Policy
		// .PrivateDestinations. Memoised (including the error) so a dial
		// against a multi-address name does not re-query per address.
		var (
			allowlistOnce  bool
			allowlistValue Allowlist
			allowlistErr   error
		)
		var getAllowlist func() (Allowlist, error)
		if policy.PrivateDestinations != nil {
			getAllowlist = func() (Allowlist, error) {
				if !allowlistOnce {
					allowlistOnce = true
					allowlistValue, allowlistErr = policy.PrivateDestinations(ctx)
				}
				return allowlistValue, allowlistErr
			}
		}

		var lastErr error
		for _, ip := range ips {
			if err := classify(ctx, ip, policy, getAllowlist); err != nil {
				lastErr = err
				continue
			}
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err != nil {
				lastErr = err
				continue
			}
			return conn, nil
		}
		if lastErr == nil {
			lastErr = &RefusalError{Target: host, Reason: "no allowed address to dial"}
		}
		return nil, lastErr
	}
}

// validatingTransport wraps an *http.Transport and additionally validates
// scheme before every RoundTrip. The address-level validation (metadata,
// private-range, DNS rebinding) lives in DialContext, which this transport
// already carries; this layer catches a refused scheme before a connection
// is even attempted, and runs identically on the first request and on every
// followed redirect, since a redirect re-enters RoundTrip like any other
// request.
type validatingTransport struct {
	inner *http.Transport
}

func (t *validatingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := validateScheme(req.URL); err != nil {
		return nil, err
	}
	return t.inner.RoundTrip(req)
}

// checkRedirect returns an http.Client.CheckRedirect that re-validates the
// redirect target's scheme explicitly (defense in depth — DialContext will
// also re-validate the target address when the redirected request actually
// dials, since that is a fresh connection through the same Transport) and
// bounds the number of redirects followed.
func checkRedirect(policy Policy) func(req *http.Request, via []*http.Request) error {
	max := policy.maxRedirects()
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= max {
			return fmt.Errorf("outbound: stopped after %d redirects", max)
		}
		if err := validateScheme(req.URL); err != nil {
			return err
		}
		return nil
	}
}

// NewClient builds an *http.Client whose every connection — the first one
// and every redirect — is validated against policy before it is made:
// scheme must be http/https, the resolved address must not be a cloud
// metadata address (unconditionally), and must not be loopback/link-
// local/private unless policy.AllowPrivate is set. timeout bounds the whole
// request (connect + read + write); pass 0 to leave the client's Timeout
// unset when a caller needs the bound to come from the request's own
// context deadline instead (matching the reasoning already established for
// probe/CLI-runner clients elsewhere in this codebase — an unbounded
// client-level Timeout would silently race a context deadline).
func NewClient(policy Policy, timeout time.Duration) *http.Client {
	if policy.AllowPrivate && strings.TrimSpace(policy.Reason) == "" {
		panic("outbound: Policy.AllowPrivate is set with no Reason")
	}
	// A caller that sets both has expressed two different intentions: the
	// wholesale allowance wins, which would make every operator allowlist
	// entry dead configuration while the settings screen still displayed
	// it as the thing granting access. That is a lie an operator would have
	// no way to detect, so it is a programming error rather than a
	// precedence rule.
	if policy.AllowPrivate && policy.PrivateDestinations != nil {
		panic("outbound: Policy.AllowPrivate and Policy.PrivateDestinations are both set — pick the wholesale compile-time allowance or the narrow operator allowlist, never both")
	}
	transport := &validatingTransport{
		inner: &http.Transport{
			DialContext:           safeDialContext(policy),
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
	return &http.Client{
		Timeout:       timeout,
		Transport:     transport,
		CheckRedirect: checkRedirect(policy),
	}
}

// IsRefusal reports whether err is (or wraps) this package's own refusal —
// useful for a caller that wants to distinguish "the destination was
// refused by policy" from an ordinary network failure (DNS failure,
// connection refused, timeout).
func IsRefusal(err error) bool {
	var re *RefusalError
	return errors.As(err, &re)
}
