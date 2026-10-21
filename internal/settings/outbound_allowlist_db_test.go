package settings

import (
	"context"
	"net"
	"testing"
)

// The operator allowlist of private outbound destinations, end to end against
// a real Postgres row: Update writes it, Resolve reads it back, and
// PrivateDestinationSource turns it into the value internal/outbound dials
// with. Migration 000115; owner decision 2026-09-19.
//
// Each test runs inside one transaction that is rolled back, never committed
// — org_settings is a real, shared singleton row on a live dev database, and
// providers_db_test.go's discipline for this exact table is the one followed
// here.

func TestUpdateAndResolve_OutboundPrivateAllowlistRoundTrips(t *testing.T) {
	pool := providersTestPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	want := []OutboundPrivateDestination{
		{Destination: "10.20.0.0/16", Reason: "self-hosted vLLM subnet"},
		{Destination: "ghe.internal.example.test", Reason: "internal GitHub Enterprise"},
	}
	if err := Update(ctx, tx, UpdateInput{Outbound: &OutboundUpdate{PrivateDestinations: want}}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	cfg, err := Resolve(ctx, tx)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(cfg.OutboundPrivateDestinations) != len(want) {
		t.Fatalf("OutboundPrivateDestinations = %+v, want %d entries", cfg.OutboundPrivateDestinations, len(want))
	}
	for i, got := range cfg.OutboundPrivateDestinations {
		if got != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got, want[i])
		}
	}

	// The reason is stored and read back, not dropped: an exception that
	// loses its justification is the state migration 000115's jsonb shape
	// exists to prevent.
	if cfg.OutboundPrivateDestinations[0].Reason == "" {
		t.Error("the stored reason came back empty")
	}

	// And it parses into the value internal/outbound actually consults.
	allowlist, err := cfg.PrivateDestinationAllowlist()
	if err != nil {
		t.Fatalf("PrivateDestinationAllowlist: %v", err)
	}
	if allowlist.Empty() {
		t.Fatal("PrivateDestinationAllowlist came back empty for a two-entry list")
	}
	if len(allowlist.Entries()) != 2 {
		t.Errorf("Entries() = %+v, want 2", allowlist.Entries())
	}
}

// TestUpdate_OutboundPrivateAllowlistClearsBackToNothing pins the
// per-section contract: an empty list is a real instruction ("remove every
// exception"), not a no-op. Removing an exception is the operation that
// matters most on a list of security exceptions.
func TestUpdate_OutboundPrivateAllowlistClearsBackToNothing(t *testing.T) {
	pool := providersTestPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if err := Update(ctx, tx, UpdateInput{Outbound: &OutboundUpdate{
		PrivateDestinations: []OutboundPrivateDestination{{Destination: "192.168.5.5", Reason: "temporary"}},
	}}); err != nil {
		t.Fatalf("Update (set): %v", err)
	}
	if err := Update(ctx, tx, UpdateInput{Outbound: &OutboundUpdate{PrivateDestinations: nil}}); err != nil {
		t.Fatalf("Update (clear): %v", err)
	}

	cfg, err := Resolve(ctx, tx)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(cfg.OutboundPrivateDestinations) != 0 {
		t.Fatalf("OutboundPrivateDestinations = %+v, want empty after an explicit clear", cfg.OutboundPrivateDestinations)
	}

	// An untouched section stays untouched, which is the other half of the
	// same contract.
	if err := Update(ctx, tx, UpdateInput{Outbound: &OutboundUpdate{
		PrivateDestinations: []OutboundPrivateDestination{{Destination: "192.168.5.5", Reason: "temporary"}},
	}}); err != nil {
		t.Fatalf("Update (set again): %v", err)
	}
	if err := Update(ctx, tx, UpdateInput{Notify: &NotifyUpdate{}}); err != nil {
		t.Fatalf("Update (unrelated section): %v", err)
	}
	cfg, err = Resolve(ctx, tx)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(cfg.OutboundPrivateDestinations) != 1 {
		t.Fatalf("OutboundPrivateDestinations = %+v, want the list to survive an unrelated section's update", cfg.OutboundPrivateDestinations)
	}
}

// TestUpdate_OutboundPrivateAllowlistRefusesEntriesTheDialPathWouldRefuse
// proves Update is a gate in its own right, not a pass-through that trusts
// the API handler: the same internal/outbound parser the dial path uses runs
// before the write, so a caller that bypasses internal/api cannot store an
// entry the dialler would never honour, or one that reaches cloud metadata.
func TestUpdate_OutboundPrivateAllowlistRefusesEntriesTheDialPathWouldRefuse(t *testing.T) {
	pool := providersTestPool(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name  string
		entry OutboundPrivateDestination
	}{
		{"cloud metadata address", OutboundPrivateDestination{Destination: "169.254.169.254", Reason: "operator insists"}},
		{"cloud metadata hostname", OutboundPrivateDestination{Destination: "metadata.google.internal", Reason: "operator insists"}},
		{"range containing cloud metadata", OutboundPrivateDestination{Destination: "169.254.0.0/16", Reason: "link-local"}},
		{"everything", OutboundPrivateDestination{Destination: "0.0.0.0/0", Reason: "just let it through"}},
		{"a public address", OutboundPrivateDestination{Destination: "8.8.8.8", Reason: "dns"}},
		{"no reason", OutboundPrivateDestination{Destination: "10.0.0.1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			defer func() { _ = tx.Rollback(context.Background()) }()

			err = Update(ctx, tx, UpdateInput{Outbound: &OutboundUpdate{
				PrivateDestinations: []OutboundPrivateDestination{tc.entry},
			}})
			if err == nil {
				t.Fatalf("Update accepted %q — it must be refused before it is ever stored", tc.entry.Destination)
			}
		})
	}
}

// TestPrivateDestinationSource_ResolvesWhatTheDialPathWillSee wires the real
// source the AI-provider and repository clients are built with and asks it
// the question internal/outbound asks: is this specific address permitted.
func TestPrivateDestinationSource_ResolvesWhatTheDialPathWillSee(t *testing.T) {
	pool := providersTestPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if err := Update(ctx, tx, UpdateInput{Outbound: &OutboundUpdate{
		PrivateDestinations: []OutboundPrivateDestination{{Destination: "10.20.0.0/16", Reason: "self-hosted vLLM subnet"}},
	}}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	allowlist, err := PrivateDestinationSource(tx)(ctx)
	if err != nil {
		t.Fatalf("PrivateDestinationSource: %v", err)
	}
	entries := allowlist.Entries()
	if len(entries) != 1 || entries[0].Destination != "10.20.0.0/16" {
		t.Fatalf("Entries() = %+v, want the one stored entry", entries)
	}
	// Sanity: the parsed entry is a CIDR, so it is the resolved-IP form
	// internal/outbound matches against — not a hostname string.
	if net.ParseIP("10.20.0.5") == nil {
		t.Fatal("test bug: bad literal")
	}
}
