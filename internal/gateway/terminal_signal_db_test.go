package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/agent"
	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
	"argus/internal/events"
	"argus/internal/tunnel"
)

// This file proves the reconnect-storm fix end to end, through the REAL
// handleConn prologue (cert-serial-to-cluster-state Postgres lookup
// included) — deliberately NOT going through tunnel_roundtrip_test.go's
// newTestGateway/serveClientMessages shortcut, since the whole point here is
// the state check handleConn does BEFORE serveClientMessages ever starts
// (server.go: "cluster %s connected from %s while %s — closing"). That check
// reads clusters.state by cert_serial, so unlike this package's other
// gateway-side tests, this one genuinely needs Postgres — same
// ARGUS_TEST_DATABASE_URL gating as finding_db_test.go's testPool.

// newTerminalSignalTestListener starts a real TLS listener whose accept loop
// calls gw.handleConn(conn) directly — the unmodified, real production
// dispatch path (ListenAndServeTLS's own accept loop does exactly this),
// unlike newTestGateway's shortcut in tunnel_roundtrip_test.go, which calls
// serveClientMessages directly and so never exercises the Archived/Rejected
// state check at all. handleConn does its own TLS handshake internally, so
// this accept loop hands it the raw conn.
func newTerminalSignalTestListener(t *testing.T, gw *Gateway, ca *DevCA) string {
	t.Helper()

	certPEM, keyPEM, err := ca.IssueServerCert([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatalf("issue gateway server cert: %v", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load gateway server cert: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.ClientCAPool(),
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go gw.handleConn(conn)
		}
	}()

	return ln.Addr().String()
}

// issueAgentCertWithSerial mirrors tunnel_roundtrip_test.go's dialTestAgent
// cert-issuing half, but also returns the issued leaf's own serial number
// (the exact string SignCSR returns, matching clusters.cert_serial's stored
// format) so the caller can insert a clusters row this exact certificate
// will resolve to.
func issueAgentCertWithSerial(t *testing.T, ca *DevCA, commonName string) (cert tls.Certificate, rootPool *x509.CertPool, serial string) {
	t.Helper()

	keyPEM, csrPEM, err := agent.GenerateKeyAndCSR(commonName)
	if err != nil {
		t.Fatalf("generate agent key/csr: %v", err)
	}
	certPEM, serial, err := ca.SignCSR(csrPEM, time.Hour)
	if err != nil {
		t.Fatalf("sign agent csr: %v", err)
	}
	cert, err = tls.X509KeyPair([]byte(certPEM), keyPEM)
	if err != nil {
		t.Fatalf("load agent cert/key: %v", err)
	}

	rootPool = x509.NewCertPool()
	if !rootPool.AppendCertsFromPEM(ca.RootCertPEM()) {
		t.Fatal("failed to add dev CA root cert to pool")
	}
	return cert, rootPool, serial
}

// TestHandleConn_TerminalSignal is this feature's core proof: a cluster
// already in a terminal state (Archived or Rejected) gets
// tunnel.ServerMessage.Terminal on the wire, sent ALONE, immediately before
// the hub closes the connection — not a bare close, which is what an agent
// cannot tell apart from a hub restart.
func TestHandleConn_TerminalSignal(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name         string
		clusterState string
		wantReason   string
	}{
		{"archived cluster gets the archived reason", "Archived", tunnel.TerminalReasonArchived},
		{"rejected cluster gets the rejected reason", "Rejected", tunnel.TerminalReasonRejected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca, err := NewEphemeralDevCA()
			if err != nil {
				t.Fatalf("new dev CA: %v", err)
			}
			gw := NewGateway(&data.DB{Pool: pool}, ca, events.NewBus())
			addr := newTerminalSignalTestListener(t, gw, ca)

			clusterID := domain.NewID(domain.PrefixCluster)
			cert, rootPool, serial := issueAgentCertWithSerial(t, ca, clusterID)

			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin setup: %v", err)
			}
			tenantID, err := data.SingleOrganisationID(ctx, tx)
			if err != nil {
				tx.Rollback(ctx) //nolint:errcheck
				t.Fatalf("resolve organisation: %v", err)
			}
			if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
				tx.Rollback(ctx) //nolint:errcheck
				t.Fatalf("set request scope: %v", err)
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint, cert_serial)
				 VALUES ($1, $2, $3, $4, 'shard-test', $5, $6)`,
				clusterID, tenantID, "terminal-signal-test-"+clusterID, tc.clusterState, "fp-"+clusterID, serial); err != nil {
				tx.Rollback(ctx) //nolint:errcheck
				t.Fatalf("insert cluster: %v", err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatalf("commit setup: %v", err)
			}
			fixture := dbtest.New(t)
			fixture.OwnsCluster(tenantID, clusterID)
			fixture.Created("clusters", 1)
			fixture.Cleanup(pool,
				func(ctx context.Context, tx pgx.Tx) error {
					return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
				},
				[]dbtest.TableDelete{
					{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
				},
			)

			conn, err := tls.Dial("tcp", addr, &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      rootPool,
				ServerName:   "127.0.0.1",
				MinVersion:   tls.VersionTLS12,
			})
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()

			if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatalf("set read deadline: %v", err)
			}

			var msg tunnel.ServerMessage
			if err := json.NewDecoder(conn).Decode(&msg); err != nil {
				t.Fatalf("decode terminal signal: %v", err)
			}
			if msg.Terminal != tc.wantReason {
				t.Fatalf("ServerMessage.Terminal = %q, want %q (full message: %+v)", msg.Terminal, tc.wantReason, msg)
			}
			if msg.Ack || msg.Error != "" || msg.ToolRequest != nil {
				t.Fatalf("terminal ServerMessage carried something else too: %+v — it must be sent alone", msg)
			}

			// The hub must actually close the connection right after — not
			// leave it open expecting a ClientMessage that will never come.
			buf := make([]byte, 1)
			if _, err := conn.Read(buf); err == nil {
				t.Fatal("read after the terminal signal: want the hub to have closed the connection, got more data / no error")
			}
		})
	}
}
