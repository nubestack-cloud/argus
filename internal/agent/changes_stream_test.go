package agent

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"argus/internal/redact"
	"argus/internal/tunnel"
)

func TestChangeStreamOverflowBecomesAGap(t *testing.T) {
	s := &changeStream{maxBuffer: 2, now: time.Now}
	t0 := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		s.push(tunnel.ResourceChange{ObservedAt: t0.Add(time.Duration(i) * time.Second), Kind: "Deployment", Name: "a", Op: "update"})
	}
	b := s.drain()
	if len(b.Changes) != 2 {
		t.Fatalf("changes = %d, want the 2 that fit", len(b.Changes))
	}
	// The overflow window is recorded when the buffer next accepts a change.
	s.push(tunnel.ResourceChange{ObservedAt: t0.Add(time.Minute), Kind: "Deployment", Name: "a", Op: "update"})
	b = s.drain()
	if len(b.Gaps) != 1 || !b.Gaps[0].From.Equal(t0.Add(2*time.Second)) || !b.Gaps[0].To.Equal(t0.Add(4*time.Second)) {
		t.Fatalf("gaps = %+v", b.Gaps)
	}
	if s.drain() != nil {
		t.Fatal("an empty stream must drain to nil")
	}
}

// The change stream's own egress chokepoint: whatever a differ emits, values
// on secret-bearing paths and credential-shaped strings never leave.
func TestChangeStreamRedactsAtEgress(t *testing.T) {
	s := &changeStream{maxBuffer: 10, now: time.Now}
	s.push(tunnel.ResourceChange{
		ObservedAt: time.Now(), Kind: "Deployment", Name: "a", Op: "update",
		Summary: "token rotated to bearer " + egressCanary,
		Fields: []tunnel.ChangeField{
			{Path: "spec.template.spec.containers[app].env.DB_PASSWORD", OldValue: egressCanary, NewValue: "modified"},
			{Path: "data.password", OldValue: nil, NewValue: egressCanary},
			{Path: "spec.template.spec.containers[app].args", OldValue: []any{"--token=" + egressCanary}, NewValue: "x"},
			{Path: "spec.replicas", OldValue: 2, NewValue: 3},
		},
	})
	b := s.drain()
	raw, _ := json.Marshal(b)
	if strings.Contains(string(raw), egressCanary) {
		t.Fatalf("canary escaped the change stream: %s", raw)
	}
	if !strings.Contains(string(raw), `"newValue":"modified"`) || !strings.Contains(string(raw), redact.Marker) {
		t.Errorf("expected the modified marker and a redaction marker: %s", raw)
	}
	if !strings.Contains(string(raw), `"newValue":3`) {
		t.Errorf("a non-sensitive value must survive: %s", raw)
	}
}
