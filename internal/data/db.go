// Package data owns the Postgres connection pool and migration runner.
//
// lld/02-authz-spec.md §10.2 and lld/05-data-model.md §6 require the application to
// connect as a non-owner role (argus_app) with no BYPASSRLS, over a session-pooling
// connection so SET LOCAL actually persists for the request. This package's
// SetRequestScope is the ONLY place app.accessible_cluster_ids / app.tenant_id may be
// set — every other package must go through it rather than issuing SET LOCAL directly,
// so there is exactly one call site to audit for SR-2's parameterisation requirement.
package data

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/logging"
)

// logger is this package's structured logger (PROJECT.md T22).
var logger = logging.For("data")

type DB struct {
	Pool *pgxpool.Pool
}

// PoolConfig is the hub's Postgres connection-pool shape. PROJECT.md P15: this
// used to be a bare pgxpool.New, which means pgx's own default of
// max(4, runtime.NumCPU()) — four connections on a small node, eight on this
// project's dev box — for a process whose demand has nothing to do with how
// many CPUs it has.
//
// WHAT CONTENDS FOR THE POOL (count it before changing MaxConns; every one of
// these holds a connection for the length of a transaction, not an instant):
//
//   - One transaction per authenticated HTTP request. internal/api's
//     requireAuth opens it, so EVERY authenticated read is inside one — not
//     just writes.
//   - Twelve background sweepers (cmd/hub/main.go's startWorker calls): health
//     monitor, validation, merge, approval, execution reconciler, notifier,
//     auto-analysis poller, stale-object sweeper, knowledge backfill,
//     unattended executor, partition maintainer, orphan reaper.
//   - Up to eight concurrent finding handlers (internal/gateway's
//     maxConcurrentFindingProcessing), each doing correlation/promotion work
//     against the DB.
//   - The MCP listener, serving the cli investigation backend's tool calls.
//
// So the hub's background half alone can want ~21 connections with no browser
// open at all, against a pool of 8. Exhaustion does not surface as an error:
// pgxpool blocks in Acquire until one frees up, so it presents as unexplained
// latency and downstream timeouts, which is the worst possible failure shape
// to debug.
//
// DEFAULTS, AND THE MEASUREMENT BEHIND THEM. Measured on the dev stack
// (8 vCPU, one live agent, one browser tab) by running the hub with the cap
// raised far above demand and sampling pg_stat_activity for connections
// actually busy (state 'active' or 'idle in transaction'):
// see PROJECT.md P15 for the figures. The default below is that observed peak
// with room for the HTTP burst a page mount fires (four to eight queries at
// once, per open tab) on top of it. It is deliberately a flat number rather
// than a multiple of NumCPU: these connections spend their lives waiting on
// Postgres, not on this process's CPUs.
//
// It is also deliberately configurable, because the one number that cannot be
// picked here is how many hub processes share the database. At Postgres's
// default max_connections of 100, the default below leaves room for three hub
// replicas plus the migrate job and argusctl; anyone running more must set
// ARGUS_DB_MAX_CONNS down to match, which is why this is configuration and not
// a constant.
type PoolConfig struct {
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
}

// DefaultPoolConfig is what the hub uses when nothing is set in the
// environment. See PoolConfig's doc comment for where each number comes from.
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxConns: 25,
		// Enough that the sweepers do not pay a TCP+TLS+auth handshake on every
		// wake-up during a quiet period, few enough that an idle hub is not
		// holding a meaningful share of the server's connection slots.
		MinConns: 4,
		// A connection is retired after half an hour whatever its state. This is
		// what stops a long-lived hub pinning connections across a Postgres
		// failover, a pgbouncer restart, or a role/search_path change, and it
		// bounds the blast radius of any per-connection server-side state that
		// leaks past a transaction.
		MaxConnLifetime: 30 * time.Minute,
		// Idle connections above MinConns are released after five minutes, so a
		// burst does not permanently reserve the peak it needed.
		MaxConnIdleTime: 5 * time.Minute,
		// The sweep that enforces the two settings above and replaces
		// connections that died silently (a NAT/firewall idle timeout between
		// hub and database is the usual cause). pgx's own default is one minute;
		// thirty seconds halves how long a dead connection can sit in the pool
		// waiting to be handed to a request that will then fail.
		HealthCheckPeriod: 30 * time.Second,
	}
}

// PoolConfigFromEnv is DefaultPoolConfig with each field overridable by an
// environment variable. A set-but-unparseable value logs and falls back rather
// than failing startup, matching cmd/hub's envOrInt: the default is correct for
// every deployment this project has, so a typo in a tuning knob should not be
// the reason a hub will not boot.
func PoolConfigFromEnv() PoolConfig {
	cfg := DefaultPoolConfig()
	cfg.MaxConns = int32(envInt("ARGUS_DB_MAX_CONNS", int(cfg.MaxConns)))
	cfg.MinConns = int32(envInt("ARGUS_DB_MIN_CONNS", int(cfg.MinConns)))
	cfg.MaxConnLifetime = envDuration("ARGUS_DB_MAX_CONN_LIFETIME", cfg.MaxConnLifetime)
	cfg.MaxConnIdleTime = envDuration("ARGUS_DB_MAX_CONN_IDLE_TIME", cfg.MaxConnIdleTime)
	cfg.HealthCheckPeriod = envDuration("ARGUS_DB_HEALTH_CHECK_PERIOD", cfg.HealthCheckPeriod)
	return cfg
}

func envInt(name string, fallback int) int {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		logger.Warn("environment variable is not a positive integer; using the default",
			slog.String("variable", name), slog.String("value", v), slog.Int("default", fallback))
		return fallback
	}
	return n
}

func envDuration(name string, fallback time.Duration) time.Duration {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		logger.Warn("environment variable is not a positive Go duration (e.g. 30m); using the default",
			slog.String("variable", name), slog.String("value", v), slog.Duration("default", fallback))
		return fallback
	}
	return d
}

// String renders the pool shape for the one startup log line that states it —
// an operator debugging "the hub is slow" should be able to read what the pool
// was sized at without attaching anything.
func (c PoolConfig) String() string {
	return fmt.Sprintf("maxConns=%d minConns=%d maxConnLifetime=%s maxConnIdleTime=%s healthCheckPeriod=%s",
		c.MaxConns, c.MinConns, c.MaxConnLifetime, c.MaxConnIdleTime, c.HealthCheckPeriod)
}

// Connect opens the hub's pool with an explicit, tuned configuration —
// never pgxpool.New's CPU-derived default. See PoolConfig.
func Connect(ctx context.Context, connString string, cfg PoolConfig) (*DB, error) {
	poolCfg, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("parse postgres connection string: %w", err)
	}
	// Applied only where this config actually says something, so a knob left
	// at zero (a caller building PoolConfig by hand) keeps pgx's own default
	// rather than silently meaning "no connections" or "retire immediately".
	if cfg.MaxConns > 0 {
		poolCfg.MaxConns = cfg.MaxConns
	}
	if cfg.MinConns > 0 {
		// Clamped rather than rejected: MinConns above MaxConns is a
		// configuration mistake pgx would otherwise turn into a pool that
		// cannot satisfy its own floor.
		if cfg.MinConns > poolCfg.MaxConns {
			logger.Warn("minConns exceeds maxConns; clamping to maxConns",
				slog.Int("min_conns", int(cfg.MinConns)), slog.Int("max_conns", int(poolCfg.MaxConns)))
			cfg.MinConns = poolCfg.MaxConns
		}
		poolCfg.MinConns = cfg.MinConns
	}
	if cfg.MaxConnLifetime > 0 {
		poolCfg.MaxConnLifetime = cfg.MaxConnLifetime
	}
	if cfg.MaxConnIdleTime > 0 {
		poolCfg.MaxConnIdleTime = cfg.MaxConnIdleTime
	}
	if cfg.HealthCheckPeriod > 0 {
		poolCfg.HealthCheckPeriod = cfg.HealthCheckPeriod
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &DB{Pool: pool}, nil
}

// Stat reports the pool's live counters — total/idle/acquired connections,
// and the two that actually answer "is the pool the bottleneck?":
// EmptyAcquireCount (an Acquire that had to wait for a connection to come
// free) and AcquireDuration (how long acquires have spent waiting in total).
//
// Nothing consumes this yet. PROJECT.md T24 is where it becomes a metric;
// this exists so that when T24 is built it is a read of an already-reachable
// value rather than a change to this package. A non-zero and RISING
// EmptyAcquireCount is the signal that MaxConns is too low for the
// deployment — the symptom P15 exists to make diagnosable, since pool
// exhaustion otherwise presents only as unexplained latency.
func (db *DB) Stat() *pgxpool.Stat {
	return db.Pool.Stat()
}

func (db *DB) Close() {
	db.Pool.Close()
}

// CheckRLSPreconditions implements the startup health check lld/01-threat-model.md
// SR-2 requires: RLS silently does nothing if any precondition is missed, so this
// must run before the hub accepts traffic, not just at migration time.
func (db *DB) CheckRLSPreconditions(ctx context.Context) error {
	var currentRole string
	if err := db.Pool.QueryRow(ctx, "SELECT current_user").Scan(&currentRole); err != nil {
		return fmt.Errorf("check current role: %w", err)
	}
	if currentRole != "argus_app" {
		return fmt.Errorf("SR-2 violation: hub is connected as %q, not argus_app — RLS guarantees do not hold for any other role", currentRole)
	}

	var bypassRLS bool
	if err := db.Pool.QueryRow(ctx,
		"SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user").Scan(&bypassRLS); err != nil {
		return fmt.Errorf("check bypassrls: %w", err)
	}
	if bypassRLS {
		return fmt.Errorf("SR-2 violation: role %q has BYPASSRLS — every RLS policy in this schema is decoration until this is revoked", currentRole)
	}

	var forcedCount int
	if err := db.Pool.QueryRow(ctx, `
		SELECT count(*) FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relrowsecurity AND NOT c.relforcerowsecurity
	`).Scan(&forcedCount); err != nil {
		return fmt.Errorf("check force rls: %w", err)
	}
	if forcedCount > 0 {
		return fmt.Errorf("SR-2 violation: %d table(s) have row security enabled but not forced — the table owner can still bypass RLS on them", forcedCount)
	}

	return nil
}

// SetRequestScope sets the RLS session variables for one request's transaction.
// Takes a pgx.Tx, not the bare pool — calling this outside an explicit transaction
// (session-pooling mode, per §10.2) is a compile error, not a silent no-op.
func SetRequestScope(ctx context.Context, tx pgx.Tx, tenantID string, accessibleClusterIDs []string) error {
	// Deliberately parameterised — never string-interpolated (SR-2's other
	// precondition: an injection must not be able to set this directly).
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID); err != nil {
		return fmt.Errorf("set app.tenant_id: %w", err)
	}
	joined := strings.Join(accessibleClusterIDs, ",")
	if _, err := tx.Exec(ctx, "SELECT set_config('app.accessible_cluster_ids', $1, true)", joined); err != nil {
		return fmt.Errorf("set app.accessible_cluster_ids: %w", err)
	}
	return nil
}
