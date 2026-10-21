package certexpiry

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func certificate(obj map[string]any) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: obj}
	u.SetAPIVersion("cert-manager.io/v1")
	u.SetKind("Certificate")
	return u
}

// Everything a row needs comes off the Certificate itself: spec for the
// Secret name, issuer and SANs, status for the expiry.
func TestFromCertManager(t *testing.T) {
	expiry := time.Date(2026, 12, 24, 6, 0, 0, 0, time.UTC)
	in, ok := FromCertManager(certificate(map[string]any{
		"metadata": map[string]any{"namespace": "billing", "name": "invoices"},
		"spec": map[string]any{
			"secretName": "invoices-tls",
			"dnsNames":   []any{"invoices.example.net", "pay.example.net"},
			"issuerRef":  map[string]any{"kind": "ClusterIssuer", "name": "acme-prod"},
		},
		"status": map[string]any{"notAfter": expiry.Format(time.RFC3339)},
	}))
	if !ok {
		t.Fatal("a cert-manager Certificate was rejected")
	}
	got := fmt.Sprintf("%s/%s secret=%s issuer=%s sans=%v source=%s", in.Namespace, in.Name, in.SecretName, in.Issuer, in.Domains, in.Source)
	if want := "billing/invoices secret=invoices-tls issuer=acme-prod sans=[invoices.example.net pay.example.net] source=cert-manager"; got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	if in.NotAfter == nil || !in.NotAfter.Equal(expiry) {
		t.Errorf("notAfter = %v, want %v", in.NotAfter, expiry)
	}
}

func TestFromCertManager_NotYetIssued(t *testing.T) {
	u := certificate(map[string]any{
		"metadata": map[string]any{"name": "pending", "namespace": "default"},
		"spec":     map[string]any{"secretName": "pending-tls", "issuerRef": map[string]any{"name": "letsencrypt"}},
	})
	in, ok := FromCertManager(u)
	if !ok || in.Name != "pending" {
		t.Fatalf("FromCertManager = %+v, %v", in, ok)
	}
	if in.NotAfter != nil {
		t.Errorf("NotAfter = %v, want nil (no status.notAfter)", in.NotAfter)
	}
	if got := Aggregate(Sources{CertManager: []Input{in}}); got[0].Health != HealthUnknown {
		t.Errorf("unissued certificate health = %q, want unknown", got[0].Health)
	}
}

func TestFromCertManager_RejectsOtherKinds(t *testing.T) {
	if _, ok := FromCertManager(nil); ok {
		t.Error("nil accepted")
	}
	other := &unstructured.Unstructured{Object: map[string]any{}}
	other.SetAPIVersion("networking.k8s.io/v1")
	other.SetKind("Ingress")
	if _, ok := FromCertManager(other); ok {
		t.Error("Ingress accepted as a Certificate")
	}
	lookalike := &unstructured.Unstructured{Object: map[string]any{}}
	lookalike.SetAPIVersion("example.com/v1")
	lookalike.SetKind("Certificate")
	if _, ok := FromCertManager(lookalike); ok {
		t.Error("Certificate from another API group accepted")
	}
}

func TestProbeServedCertificate(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "https://")
	in, err := ProbeServedCertificate(context.Background(), addr, "example.com", 2*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	leaf := srv.Certificate()
	if in.NotAfter == nil || !in.NotAfter.Equal(leaf.NotAfter.UTC()) {
		t.Errorf("NotAfter = %v, want %v", in.NotAfter, leaf.NotAfter)
	}
	if in.Source != SourceServed || in.Endpoint != addr || in.Name != "example.com" {
		t.Errorf("unexpected identity fields: %+v", in)
	}
	if len(in.Domains) != len(leaf.DNSNames) {
		t.Errorf("domains = %v, want %v", in.Domains, leaf.DNSNames)
	}
	if in.Issuer == "" || in.Subject == "" {
		t.Errorf("issuer/subject not populated: %+v", in)
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("probe sent %d HTTP requests, want 0", n)
	}
}

func TestProbeServedCertificate_DialFailure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := strings.TrimPrefix(srv.URL, "https://")
	srv.Close()
	if _, err := ProbeServedCertificate(context.Background(), addr, "", 500*time.Millisecond); err == nil {
		t.Fatal("expected an error dialling a closed listener")
	}
	if _, err := ProbeServedCertificate(context.Background(), "", "", time.Second); err == nil {
		t.Fatal("expected an error for an empty address")
	}
}

func TestProbeServedCertificate_PlainTCPIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	if _, err := ProbeServedCertificate(context.Background(), addr, "", time.Second); err == nil {
		t.Fatal("expected a handshake error against a plain HTTP listener")
	}
}
