package outbound

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClient_RefusesMetadataIP(t *testing.T) {
	c := NewClient(Policy{}, 2*time.Second)
	_, err := c.Get("http://169.254.169.254/latest/meta-data/")
	if err == nil {
		t.Fatal("expected refusal, got nil error")
	}
	if !IsRefusal(err) {
		t.Fatalf("expected a RefusalError, got: %v", err)
	}
	if !strings.Contains(err.Error(), "metadata") {
		t.Fatalf("expected a stated metadata reason, got: %v", err)
	}
}

func TestNewClient_RefusesMetadataHostname(t *testing.T) {
	c := NewClient(Policy{}, 2*time.Second)
	_, err := c.Get("http://metadata.google.internal/computeMetadata/v1/")
	if err == nil || !IsRefusal(err) {
		t.Fatalf("expected refusal of metadata.google.internal, got: %v", err)
	}
}

func TestNewClient_MetadataRefusedEvenWithAllowPrivate(t *testing.T) {
	c := NewClient(Policy{AllowPrivate: true, Reason: "test"}, 2*time.Second)
	_, err := c.Get("http://169.254.169.254/latest/meta-data/")
	if err == nil || !IsRefusal(err) {
		t.Fatalf("expected metadata to be refused even for a private-allowing policy, got: %v", err)
	}
}

func TestNewClient_DefaultRefusesPrivateAndLoopback(t *testing.T) {
	c := NewClient(Policy{}, 2*time.Second)

	if _, err := c.Get("http://10.1.2.3/"); err == nil || !IsRefusal(err) {
		t.Fatalf("expected private-range refusal, got: %v", err)
	}
	if _, err := c.Get("http://127.0.0.1:1/"); err == nil || !IsRefusal(err) {
		t.Fatalf("expected loopback refusal, got: %v", err)
	}
}

func TestNewClient_AllowPrivateReachesLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewClient(Policy{AllowPrivate: true, Reason: "test"}, 2*time.Second)
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("expected loopback to be reachable under AllowPrivate, got: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestNewClient_RefusesNonHTTPScheme(t *testing.T) {
	c := NewClient(Policy{}, 2*time.Second)
	_, err := c.Get("file:///etc/passwd")
	if err == nil || !IsRefusal(err) {
		t.Fatalf("expected scheme refusal, got: %v", err)
	}
}

func TestNewClient_RedirectToPrivateIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()

	// This server is itself on loopback, so allow private to isolate the
	// behaviour under test to the redirect target, not the server's own
	// address.
	c := NewClient(Policy{AllowPrivate: true, Reason: "test"}, 2*time.Second)
	_, err := c.Get(srv.URL)
	if err == nil {
		t.Fatal("expected the redirect to a metadata address to be refused")
	}
}

func TestNewClient_PanicsWhenAllowPrivateHasNoReason(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic for AllowPrivate with no Reason")
		}
	}()
	NewClient(Policy{AllowPrivate: true}, time.Second)
}
