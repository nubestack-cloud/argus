package agent

// finding_ack_kill_db_test.go is PROJECT.md P21's acceptance criterion,
// carried out rather than argued: a tunnel killed between an agent's send
// and the hub's ack must lose nothing, "proven by doing exactly that and
// observing the finding arrive after reconnect".
//
// Everything on both sides of the wire here is production code. The hub is a
// real internal/gateway.Gateway on its real exported listener
// (ListenAndServeTLS -> handleConn -> serveClientMessages ->
// processFindingAsync -> handleFinding), backed by a real Postgres, with a
// real cluster row resolved from a real mTLS client certificate's serial.
// The agent is serveTunnelForever with a real findingQueue, including its
// real reconnect backoff. Nothing is stubbed and no timer is shortened.
//
// The kill is a real TCP kill, not an instrumented Conn. A byte-level proxy
// sits between the two (the TLS session runs end to end THROUGH it, so it
// can see lengths and nothing else), and when armed it drops the next chunk
// the agent writes and closes both sockets. That is precisely the failure
// this feature exists for: the agent has taken the finding off its queue and
// written it, and the hub never sees it and therefore never acks it.
//
// The falsification is the pair of assertions, not either one alone. Before
// this change the first would still have passed and the second would not:
// the finding was gone from the queue the moment the writer took it, and
// only a later sweep re-deriving the same condition would have produced it
// again — which is why the test enqueues the finding by hand exactly once
// and never again.

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
	"argus/internal/events"
	"argus/internal/gateway"
	"argus/internal/tunnel"
)

func ackKillTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connString := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if connString == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping the P21 kill-between-send-and-ack test (it needs a real hub, which needs a real Postgres)")
	}
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// killProxy forwards bytes between the agent and the hub until it is armed,
// at which point it swallows the next chunk the agent writes and closes both
// connections — the agent's write has "succeeded" into a socket whose
// contents will never be delivered, and the connection is gone before any
// ack could come back.
type killProxy struct {
	addr   string
	armed  atomic.Bool
	killed chan struct{}
	once   sync.Once
}

func newKillProxy(t *testing.T, upstream string) *killProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	p := &killProxy{addr: ln.Addr().String(), killed: make(chan struct{})}
	go func() {
		for {
			down, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", upstream)
			if err != nil {
				down.Close()
				continue
			}
			go p.pumpFromAgent(down, up)
			go func() {
				_, _ = io.Copy(down, up)
				down.Close()
				up.Close()
			}()
		}
	}()
	return p
}

func (p *killProxy) pumpFromAgent(down, up net.Conn) {
	defer down.Close()
	defer up.Close()
	buf := make([]byte, 32*1024)
	for {
		n, err := down.Read(buf)
		if n > 0 {
			if p.armed.Load() {
				// The kill. These bytes are dropped on the floor and both
				// halves of the connection go away with them.
				p.once.Do(func() { close(p.killed) })
				return
			}
			if _, werr := up.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// TestFindingSurvivesATunnelKilledBetweenSendAndAck is the acceptance test.
func TestFindingSurvivesATunnelKilledBetweenSendAndAck(t *testing.T) {
	pool := ackKillTestPool(t)
	ctx := context.Background()

	ca, err := gateway.NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}
	gw := gateway.NewGateway(&data.DB{Pool: pool}, ca, events.NewBus())

	clusterID := domain.NewID(domain.PrefixCluster)
	keyPEM, csrPEM, err := GenerateKeyAndCSR(clusterID)
	if err != nil {
		t.Fatalf("generate agent key/csr: %v", err)
	}
	certPEM, serial, err := ca.SignCSR(csrPEM, time.Hour)
	if err != nil {
		t.Fatalf("sign agent csr: %v", err)
	}

	tenantID := insertAckKillCluster(t, pool, clusterID, serial)

	// The real listener, on a port nothing else in this repo's dev stack
	// uses. Chosen by binding :0 and releasing it, because
	// ListenAndServeTLS takes an address rather than a listener.
	hubAddr := reserveLocalPort(t)
	go func() { _ = gw.ListenAndServeTLS(hubAddr, []string{"127.0.0.1"}) }()
	t.Cleanup(func() { gw.Shutdown(context.Background()) })
	waitForDial(t, hubAddr)

	proxy := newKillProxy(t, hubAddr)

	q := newFindingQueue(findingQueueCapacity)
	agentCtx, stopAgent := context.WithCancel(ctx)
	defer stopAgent()
	go q.Run(agentCtx)
	go func() {
		_ = serveTunnelForever(agentCtx, Config{AgentVersion: tunnel.AgentBuildVersion, TLSServerNameOverride: "127.0.0.1"},
			proxy.addr, []byte(certPEM), keyPEM, ca.RootCertPEM(), q, nil)
	}()

	// Session 1 is up once the hub has stored this cluster's facts — the
	// first thing runTunnelSession sends, and proof the whole prologue
	// (mTLS handshake, cert-serial lookup, message loop) worked.
	waitForFactsRow(t, pool, tenantID, clusterID)
	// Let the connection go quiet, so the armed cut lands on the finding's
	// own write and not on something still in flight behind it. The
	// heartbeat is 30s away and the facts refresh two minutes.
	time.Sleep(500 * time.Millisecond)

	finding := &tunnel.Finding{
		DetectorID: "k8s-sweep", DetectorVersion: "v1",
		Fingerprint: "p21-kill-" + clusterID,
		GVK:         "batch/v1/Job", Namespace: "default", ObjectName: "completed-job",
		Reason: "JobMissingActiveDeadlineSeconds", Message: "no deadline", Severity: "low",
		OccurrenceCount: 1, OccurredAt: time.Now(),
		// Risk-classed on purpose: it gets a findings row and opens no
		// incident, so this test asserts delivery without also asserting
		// promotion (which is promotion_db_test.go's job).
		Class: tunnel.FindingClassRisk, Confidence: tunnel.FindingConfidenceVerified, Impact: tunnel.FindingImpactPotential,
	}

	proxy.armed.Store(true)
	// Enqueued EXACTLY ONCE, here, and never again: no detector is running
	// in this process, so nothing can re-derive it. If it reaches the hub
	// after the kill, it is because the queue held it.
	q.In() <- *finding

	select {
	case <-proxy.killed:
	case <-time.After(20 * time.Second):
		t.Fatal("the proxy never saw the agent write the finding, so no kill happened — nothing has been proven either way")
	}

	// Half one: the hub genuinely did not get it. Give the hub a moment to
	// have written it if it somehow had.
	time.Sleep(500 * time.Millisecond)
	if n := countFindings(t, pool, tenantID, clusterID, finding.Fingerprint); n != 0 {
		t.Fatalf("findings rows before the reconnect = %d, want 0 — the kill did not actually prevent delivery, so the second half of this test would prove nothing", n)
	}

	// Half two: let the agent reconnect (its own real backoff ladder,
	// tunnelBackoffInitial plus jitter) and deliver what it was holding.
	proxy.armed.Store(false)
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if countFindings(t, pool, tenantID, clusterID, finding.Fingerprint) == 1 {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if n := countFindings(t, pool, tenantID, clusterID, finding.Fingerprint); n != 1 {
		t.Fatalf("findings rows after the reconnect = %d, want 1 — the finding was taken off the queue, never acked, and not redelivered: that is exactly the one-finding-per-disconnect loss P21 exists to end", n)
	}

	// And the agent agrees it is done with it: nothing pending, nothing
	// dropped. A queue that still held it would mean the ack path never
	// closed the loop, which would leak one entry per finding forever.
	pendingDeadline := time.Now().Add(10 * time.Second)
	var pending, dropped int
	for time.Now().Before(pendingDeadline) {
		pending, dropped = q.Stats()
		if pending == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if pending != 0 {
		t.Errorf("queue still holds %d finding(s) after the hub acked — the ack must release it, or the queue grows without bound", pending)
	}
	if dropped != 0 {
		t.Errorf("queue reports %d dropped, want 0 — nothing here is near the capacity bound", dropped)
	}
}

// insertAckKillCluster creates the throwaway cluster this test's certificate
// resolves to, and registers the residue-checked cleanup for everything the
// run produces: the cluster row, the cluster_facts row the agent's inventory
// message writes, and the one findings row that is the point of the test.
func insertAckKillCluster(t *testing.T, pool *pgxpool.Pool, clusterID, certSerial string) string {
	t.Helper()
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint, cert_serial)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4, $5)`,
		clusterID, tenantID, "p21-ack-kill-"+clusterID, "fp-"+clusterID, certSerial); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}

	fixture := dbtest.New(t)
	fixture.Created("clusters", 1)
	fixture.Created("cluster_facts", 1)
	fixture.Created("findings", 1)
	fixture.OwnsCluster(tenantID, clusterID)
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "findings", SQL: `DELETE FROM findings WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "cluster_facts", SQL: `DELETE FROM cluster_facts WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})
	return tenantID
}

func countFindings(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, fingerprint string) int {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin count: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM findings WHERE cluster_id = $1 AND fingerprint = $2`, clusterID, fingerprint).Scan(&n); err != nil {
		t.Fatalf("count findings: %v", err)
	}
	return n
}

func waitForFactsRow(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID string) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			tx.Rollback(ctx) //nolint:errcheck
			t.Fatalf("set request scope: %v", err)
		}
		var n int
		err = tx.QueryRow(ctx, `SELECT count(*) FROM cluster_facts WHERE cluster_id = $1`, clusterID).Scan(&n)
		tx.Rollback(ctx) //nolint:errcheck
		if err != nil {
			t.Fatalf("count cluster_facts: %v", err)
		}
		if n == 1 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("the agent never completed an inventory sync, so no tunnel session was ever established")
}

// reserveLocalPort returns a loopback address that was free a moment ago.
// Racy in principle, unavoidable given ListenAndServeTLS takes an address
// rather than a listener, and harmless here: the window is microseconds and
// a collision fails loudly rather than silently doing the wrong thing.
func reserveLocalPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func waitForDial(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("hub gateway never started listening on %s", addr)
}
