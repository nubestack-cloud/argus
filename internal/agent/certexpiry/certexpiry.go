// Package certexpiry rates TLS certificate expiry for a cluster without ever
// reading a Secret. Two sources feed it: cert-manager Certificate objects
// (status.notAfter is public metadata) and, when an operator opts in, the
// certificate a TLS endpoint actually serves (read from the handshake, not
// from the Secret that backs it).
//
// The same physical certificate can appear in both sources: a Certificate
// writes a Secret that an Ingress then serves. Aggregate is the one place
// that reconciles them so callers stay thin.
package certexpiry

import (
	"cmp"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"argus/internal/agent/health"
)

// Source identifies which input a certificate row came from.
type Source string

const (
	SourceCertManager Source = "cert-manager"
	SourceServed      Source = "served"
)

// Health is the expiry rating, in internal/agent/health's words: unknown
// when there is no expiry to judge (a Certificate not yet issued), otherwise
// by the days left on expiryLadder.
type Health string

const (
	HealthHealthy   = Health(health.LevelHealthy)
	HealthDegraded  = Health(health.LevelDegraded)
	HealthUnhealthy = Health(health.LevelUnhealthy)
	HealthUnknown   = Health(health.LevelUnknown)
)

// expiryLadder rates a known expiry by whole days left, first match wins:
// under a week (or already expired) is unhealthy, under a month degraded,
// anything longer healthy.
var expiryLadder = []struct {
	under  int
	rating Health
}{
	{7, HealthUnhealthy},
	{30, HealthDegraded},
}

// Input is one certificate normalized from either source. NotAfter == nil
// means expiry is unknown.
type Input struct {
	Name      string
	Namespace string
	Issuer    string
	Subject   string
	Domains   []string
	NotAfter  *time.Time
	Source    Source
	// SecretName is the Secret the certificate lives in: spec.secretName for
	// a cert-manager Certificate, the Ingress spec.tls[].secretName for a
	// served certificate when the caller knows it. Only the name is used —
	// the Secret itself is never read.
	SecretName string
	// Endpoint is the address:port a served certificate was read from.
	Endpoint string

	// ReadyReason/ReadyMessage/RenewalTime are cert-manager-source-only
	// (2026-10-13 parity review, PG5): the Certificate's own status.conditions
	// Ready entry and status.renewalTime, read straight from the object —
	// never a Secret. Empty for a served certificate, and for a Certificate
	// whose Ready condition is True (nothing to explain).
	ReadyReason  string
	ReadyMessage string
	RenewalTime  *time.Time
	// RequestChain is the newest CertificateRequest for this Certificate and,
	// when it is ACME-backed, the newest Order and Challenge beneath it —
	// nil when no request exists yet, or none could be correlated.
	RequestChain *RequestChain
}

// RequestChain is cert-manager's own explanation for why a renewal has not
// completed, read three objects deep: the newest CertificateRequest this
// Certificate owns, the newest Order that request owns (ACME only), and the
// newest Challenge that order owns. Any stage can be the dead end — a
// CertificateRequest denied by policy never reaches an Order; a non-ACME
// issuer (CA, Vault) never reaches one either.
type RequestChain struct {
	RequestName    string `json:"requestName"`
	RequestReady   bool   `json:"requestReady"`
	RequestReason  string `json:"requestReason,omitempty"`
	RequestMessage string `json:"requestMessage,omitempty"`
	OrderName      string `json:"orderName,omitempty"`
	// OrderState is the Order's own status.state (pending, valid, ready,
	// processing, invalid, errored, expired) — cert-manager's ACME order
	// lifecycle, not this package's Health ladder.
	OrderState    string `json:"orderState,omitempty"`
	OrderReason   string `json:"orderReason,omitempty"`
	ChallengeName string `json:"challengeName,omitempty"`
	// ChallengeState is the Challenge's own status.state (pending,
	// processing, valid, invalid).
	ChallengeState  string `json:"challengeState,omitempty"`
	ChallengeReason string `json:"challengeReason,omitempty"`
}

// Sources bundles a cluster's per-source inputs for one Aggregate call.
type Sources struct {
	CertManager []Input
	Served      []Input
	// Now anchors expiry math; the zero value means time.Now.
	Now time.Time
}

// Cert is one unified row, ready to serialize. DaysLeft is nil when expiry is
// unknown; Expiry is RFC 3339 and omitted in that case.
type Cert struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Issuer    string `json:"issuer"`
	Domains   string `json:"domains"`
	Expiry    string `json:"expiry,omitempty"`
	DaysLeft  *int   `json:"daysLeft,omitempty"`
	Health    Health `json:"health"`
	Source    Source `json:"source"`
	Endpoint  string `json:"endpoint,omitempty"`

	// ReadyReason/ReadyMessage/RenewalTime/RequestChain (PG5) carry through
	// from Input unchanged — see Input's own doc comments.
	ReadyReason  string        `json:"readyReason,omitempty"`
	ReadyMessage string        `json:"readyMessage,omitempty"`
	RenewalTime  string        `json:"renewalTime,omitempty"`
	RequestChain *RequestChain `json:"requestChain,omitempty"`
}

// Aggregate merges the sources into one list, most urgent first. A served
// certificate is dropped as a duplicate only when a cert-manager Certificate
// in its namespace writes the Secret it is served from and the two expiries
// agree to the second — then they are one physical certificate and the
// Certificate's row says more. When the expiries differ, the endpoint is
// serving something other than what cert-manager last issued (a stale copy,
// a reload that never happened), and both rows stay.
func Aggregate(s Sources) []Cert {
	now := cmp.Or(s.Now, time.Now())
	issued := map[string]*time.Time{}
	out := make([]Cert, 0, len(s.CertManager)+len(s.Served))
	for _, in := range s.CertManager {
		if in.SecretName != "" {
			issued[in.Namespace+"/"+in.SecretName] = in.NotAfter
		}
		out = append(out, row(in, now))
	}
	for _, in := range s.Served {
		if na, ok := issued[in.Namespace+"/"+in.SecretName]; ok && in.SecretName != "" && na != nil && in.NotAfter != nil &&
			na.Truncate(time.Second).Equal(in.NotAfter.Truncate(time.Second)) {
			continue
		}
		out = append(out, row(in, now))
	}
	slices.SortStableFunc(out, byUrgency)
	return out
}

// row renders one input. Days left are floored, so a certificate that
// expired an hour ago reads -1 (expired) rather than 0 (expires today).
func row(in Input, now time.Time) Cert {
	c := Cert{
		Name: in.Name, Namespace: in.Namespace, Issuer: in.Issuer,
		Domains: domainsCell(in.Domains),
		Health:  HealthUnknown,
		Source:  in.Source, Endpoint: in.Endpoint,
		ReadyReason: in.ReadyReason, ReadyMessage: in.ReadyMessage, RequestChain: in.RequestChain,
	}
	if t := in.RenewalTime; t != nil {
		c.RenewalTime = t.UTC().Format(time.RFC3339)
	}
	if t := in.NotAfter; t != nil {
		left := int(math.Floor(t.Sub(now).Hours() / 24))
		c.Expiry, c.DaysLeft, c.Health = t.UTC().Format(time.RFC3339), &left, HealthHealthy
		for _, step := range expiryLadder {
			if left < step.under {
				c.Health = step.rating
				break
			}
		}
	}
	return c
}

// byUrgency orders known expiries soonest first and unknown ones last, then
// by namespace, name and source so a repeated scan lists rows in the same
// order.
func byUrgency(a, b Cert) int {
	if (a.DaysLeft == nil) != (b.DaysLeft == nil) {
		if a.DaysLeft == nil {
			return 1
		}
		return -1
	}
	days := 0
	if a.DaysLeft != nil {
		days = cmp.Compare(*a.DaysLeft, *b.DaysLeft)
	}
	return cmp.Or(days, strings.Compare(a.Namespace, b.Namespace), strings.Compare(a.Name, b.Name), cmp.Compare(a.Source, b.Source))
}

// domainsCell lists at most two SANs and counts the rest ("a, b +3 more"),
// so a certificate for a wildcard and dozens of hosts stays one cell wide.
func domainsCell(d []string) string {
	if len(d) <= 2 {
		return strings.Join(d, ", ")
	}
	return strings.Join(d[:2], ", ") + " +" + strconv.Itoa(len(d)-2) + " more"
}
