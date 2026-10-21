package certexpiry

import (
	"fmt"
	"slices"
	"testing"
	"time"
)

var clock = time.Date(2026, 10, 1, 9, 30, 0, 0, time.UTC)

func inDays(d int) *time.Time {
	t := clock.AddDate(0, 0, d)
	return &t
}

func issued(ns, name, secret string, notAfter *time.Time) Input {
	return Input{Namespace: ns, Name: name, SecretName: secret, NotAfter: notAfter, Source: SourceCertManager}
}

func serving(ns, host, secret string, notAfter *time.Time) Input {
	return Input{Namespace: ns, Name: host, SecretName: secret, NotAfter: notAfter, Source: SourceServed}
}

// rows renders the result as "ns/name(source):health" in output order.
func rows(certs []Cert) []string {
	out := make([]string, len(certs))
	for i, c := range certs {
		out[i] = fmt.Sprintf("%s/%s(%s):%s", c.Namespace, c.Name, c.Source, c.Health)
	}
	return out
}

func TestExpiryLadder(t *testing.T) {
	for days, want := range map[int]Health{
		-3: HealthUnhealthy, 0: HealthUnhealthy, 6: HealthUnhealthy,
		7: HealthDegraded, 18: HealthDegraded, 29: HealthDegraded,
		30: HealthHealthy, 400: HealthHealthy,
	} {
		got := Aggregate(Sources{Now: clock, Served: []Input{serving("edge", "www.example.org", "", inDays(days))}})
		if got[0].Health != want || *got[0].DaysLeft != days {
			t.Errorf("%d days: %s (%d left), want %s", days, got[0].Health, *got[0].DaysLeft, want)
		}
	}
	// Not yet issued: nothing to judge.
	got := Aggregate(Sources{Now: clock, CertManager: []Input{issued("edge", "fresh", "fresh-tls", nil)}})
	if got[0].Health != HealthUnknown || got[0].DaysLeft != nil || got[0].Expiry != "" {
		t.Errorf("unissued = %+v", got[0])
	}
}

// An hour past expiry is expired (-1), not "expires today" (0).
func TestJustExpiredReadsMinusOne(t *testing.T) {
	gone := clock.Add(-time.Hour)
	got := Aggregate(Sources{Now: clock, CertManager: []Input{issued("edge", "api", "", &gone)}})
	if *got[0].DaysLeft != -1 || got[0].Health != HealthUnhealthy {
		t.Errorf("got %d / %s", *got[0].DaysLeft, got[0].Health)
	}
}

func TestServedCopiesOfIssuedCertificates(t *testing.T) {
	expiry := inDays(55)
	got := rows(Aggregate(Sources{
		Now: clock,
		CertManager: []Input{
			issued("payments", "gateway", "gateway-tls", expiry),
			issued("search", "frontend", "frontend-tls", inDays(70)),
		},
		Served: []Input{
			// The Certificate's own Secret, same expiry: one certificate, one row.
			serving("payments", "pay.example.org", "gateway-tls", expiry),
			// Same Secret name in another namespace is a different Secret.
			serving("ledger", "ledger.example.org", "gateway-tls", expiry),
			// Same Secret, different expiry: the endpoint serves a stale
			// copy, and that divergence is the point of showing both.
			serving("search", "search.example.org", "frontend-tls", inDays(3)),
			// No Secret known: nothing to match against.
			serving("payments", "hooks.example.org", "", expiry),
		},
	}))
	want := []string{
		"search/search.example.org(served):unhealthy",
		"ledger/ledger.example.org(served):healthy",
		"payments/gateway(cert-manager):healthy",
		"payments/hooks.example.org(served):healthy",
		"search/frontend(cert-manager):healthy",
	}
	if !slices.Equal(got, want) {
		t.Errorf("rows:\n got  %v\n want %v", got, want)
	}
}

// Soonest first, unknown last, and ties in a fixed order.
func TestUrgencyOrder(t *testing.T) {
	got := rows(Aggregate(Sources{
		Now:         clock,
		CertManager: []Input{issued("b", "pending", "", nil), issued("a", "same-day", "", inDays(12))},
		Served:      []Input{serving("b", "later", "", inDays(40)), serving("a", "same-day", "", inDays(12)), serving("a", "first", "", inDays(2))},
	}))
	want := []string{
		"a/first(served):unhealthy",
		"a/same-day(cert-manager):degraded",
		"a/same-day(served):degraded",
		"b/later(served):healthy",
		"b/pending(cert-manager):unknown",
	}
	if !slices.Equal(got, want) {
		t.Errorf("order:\n got  %v\n want %v", got, want)
	}
}

func TestDomainsCell(t *testing.T) {
	for want, sans := range map[string][]string{
		"":                                   nil,
		"api.example.org":                    {"api.example.org"},
		"api.example.org, www.example.org":   {"api.example.org", "www.example.org"},
		"*.example.org, example.org +3 more": {"*.example.org", "example.org", "a.example.net", "b.example.net", "c.example.net"},
	} {
		if got := domainsCell(sans); got != want {
			t.Errorf("%v: %q, want %q", sans, got, want)
		}
	}
}
