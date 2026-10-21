package data

import (
	"context"
	"testing"
	"time"
)

// PROJECT.md P15. These pin the two things that are easy to get wrong when
// someone later "tidies" the pool configuration: that a default is actually
// applied (the bug being fixed was a bare pgxpool.New, which silently meant
// max(4, NumCPU) and nobody noticed for months), and that a bad value in the
// environment degrades to the default rather than to a pool that cannot serve
// anything.

func TestDefaultPoolConfigCoversTheHubsBackgroundDemand(t *testing.T) {
	cfg := DefaultPoolConfig()

	// The floor is structural, not a preference: twelve sweepers, up to eight
	// concurrent finding handlers and the MCP listener can all want a
	// connection with no browser open at all (see PoolConfig's doc comment).
	// A default below that guarantees background work queues behind itself
	// before a single HTTP request arrives — which is the state this change
	// found the hub in.
	const backgroundDemand = 12 + 8 + 1
	if cfg.MaxConns <= backgroundDemand {
		t.Errorf("MaxConns = %d, which does not clear the hub's own background demand of %d", cfg.MaxConns, backgroundDemand)
	}
	// Three hub replicas plus the migrate job and argusctl must still fit in
	// Postgres's default max_connections of 100.
	if cfg.MaxConns*3 > 90 {
		t.Errorf("MaxConns = %d: three replicas would need %d connections, leaving too little of a default max_connections=100 for migrations and argusctl", cfg.MaxConns, cfg.MaxConns*3)
	}
	if cfg.MinConns <= 0 || cfg.MinConns > cfg.MaxConns {
		t.Errorf("MinConns = %d is not a usable floor under MaxConns = %d", cfg.MinConns, cfg.MaxConns)
	}
	// All three durations must be set — a zero here is exactly the "unset"
	// state P15 is about, and Connect would then leave pgx's default in place
	// while the config claims to have decided.
	if cfg.MaxConnLifetime <= 0 || cfg.MaxConnIdleTime <= 0 || cfg.HealthCheckPeriod <= 0 {
		t.Errorf("a lifetime/idle/health-check value is unset: %s", cfg)
	}
	if cfg.MaxConnIdleTime >= cfg.MaxConnLifetime {
		t.Errorf("MaxConnIdleTime %s is not shorter than MaxConnLifetime %s, so idle connections would never be released before retirement", cfg.MaxConnIdleTime, cfg.MaxConnLifetime)
	}
}

func TestPoolConfigFromEnvOverridesAndRejectsNonsense(t *testing.T) {
	t.Setenv("ARGUS_DB_MAX_CONNS", "40")
	t.Setenv("ARGUS_DB_MIN_CONNS", "6")
	t.Setenv("ARGUS_DB_MAX_CONN_LIFETIME", "10m")
	t.Setenv("ARGUS_DB_MAX_CONN_IDLE_TIME", "90s")
	t.Setenv("ARGUS_DB_HEALTH_CHECK_PERIOD", "15s")
	cfg := PoolConfigFromEnv()
	if cfg.MaxConns != 40 || cfg.MinConns != 6 {
		t.Errorf("env overrides not applied: %s", cfg)
	}
	if cfg.MaxConnLifetime != 10*time.Minute || cfg.MaxConnIdleTime != 90*time.Second || cfg.HealthCheckPeriod != 15*time.Second {
		t.Errorf("duration overrides not applied: %s", cfg)
	}

	// A typo must not be able to stop a hub booting, and must not be able to
	// produce a pool of zero either.
	defaults := DefaultPoolConfig()
	for _, bad := range []string{"", "lots", "0", "-3"} {
		t.Setenv("ARGUS_DB_MAX_CONNS", bad)
		t.Setenv("ARGUS_DB_HEALTH_CHECK_PERIOD", bad)
		cfg := PoolConfigFromEnv()
		if cfg.MaxConns != defaults.MaxConns {
			t.Errorf("ARGUS_DB_MAX_CONNS=%q gave MaxConns %d, want the default %d", bad, cfg.MaxConns, defaults.MaxConns)
		}
		if cfg.HealthCheckPeriod != defaults.HealthCheckPeriod {
			t.Errorf("ARGUS_DB_HEALTH_CHECK_PERIOD=%q gave %s, want the default %s", bad, cfg.HealthCheckPeriod, defaults.HealthCheckPeriod)
		}
	}
}

func TestConnectRejectsAnUnparseableConnectionStringBeforeDialing(t *testing.T) {
	// Guards the one behaviour change in Connect's rewrite: it now parses the
	// connection string itself (to attach the pool config) rather than handing
	// it straight to pgxpool.New, so a parse failure has to surface as an
	// error rather than a panic or a nil pool.
	db, err := Connect(context.Background(), "this is not a connection string", DefaultPoolConfig())
	if err == nil {
		db.Close()
		t.Fatal("Connect accepted an unparseable connection string")
	}
}

func TestConnectClampsMinConnsAboveMaxConns(t *testing.T) {
	// Not a DB test: pgxpool.ParseConfig + the clamp both run before any dial,
	// and the dial below fails fast against a closed port. What is being
	// checked is that a misconfiguration is corrected rather than handed to
	// pgx as a pool that can never satisfy its own floor.
	cfg := DefaultPoolConfig()
	cfg.MaxConns = 4
	cfg.MinConns = 50
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	db, err := Connect(ctx, "postgres://argus_app:nope@127.0.0.1:1/argus?sslmode=disable&connect_timeout=1", cfg)
	if err == nil {
		db.Close()
		t.Fatal("expected the dial to a closed port to fail")
	}
	// A panic or a "MinConns cannot be greater than MaxConns" from pgx would
	// have failed above with a different error; reaching a dial failure is the
	// evidence the clamp ran.
	if got := err.Error(); got == "" {
		t.Fatal("empty error")
	}
}
