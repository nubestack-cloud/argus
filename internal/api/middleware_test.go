package api

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/authz"
	"argus/internal/data"
)

// grantsFor builds the effective-grant slice a requestContext carries for a
// principal holding exactly these capabilities, all org-wide (the only scope
// shape this codebase's grants take today — see authz.ResolveEffectivePermissions).
// Shared by every capability-gating test in this package.
func grantsFor(capabilities ...string) []authz.EffectiveGrant {
	grants := make([]authz.EffectiveGrant, 0, len(capabilities))
	for _, capability := range capabilities {
		grants = append(grants, authz.EffectiveGrant{Capability: capability, Scope: authz.Scope{Type: "AllClusters"}})
	}
	return grants
}

// serverWithUnreachableAuditDB builds a Server whose only DB use on the code
// paths under test is recordCapabilityDenial's own best-effort audit
// transaction. It points at a closed local port so Begin fails immediately with
// no Postgres anywhere in sight — which is itself the behaviour that function's
// doc comment promises: a failed audit write is logged and must never change the
// 403 the caller receives.
func serverWithUnreachableAuditDB(t *testing.T) *Server {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://argus:argus@127.0.0.1:1/argus?connect_timeout=1&sslmode=disable")
	if err != nil {
		t.Fatalf("build unreachable pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return &Server{db: &data.DB{Pool: pool}}
}

// recordingWriter is a minimal http.ResponseWriter that appends every call it
// receives to a shared, ordered log — the point of these tests is WHEN the
// response reaches the client relative to the commit, not just what it says.
type recordingWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
	log    *[]string
}

func newRecordingWriter(log *[]string) *recordingWriter {
	return &recordingWriter{header: make(http.Header), log: log}
}

func (w *recordingWriter) Header() http.Header { return w.header }

func (w *recordingWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	*w.log = append(*w.log, "writeHeader")
}

func (w *recordingWriter) Write(b []byte) (int, error) {
	*w.log = append(*w.log, "write")
	return w.body.Write(b)
}

// fakeTxFinisher stands in for pgx.Tx's commit/rollback half (txFinisher).
type fakeTxFinisher struct {
	commitErr   error
	rollbackErr error
	commits     int
	rollbacks   int
	log         *[]string
}

func (f *fakeTxFinisher) Commit(context.Context) error {
	f.commits++
	if f.log != nil {
		*f.log = append(*f.log, "commit")
	}
	return f.commitErr
}

func (f *fakeTxFinisher) Rollback(context.Context) error {
	f.rollbacks++
	if f.log != nil {
		*f.log = append(*f.log, "rollback")
	}
	return f.rollbackErr
}

// TestBufferedResponseWriterCapturesEverything covers the writer half: nothing
// a handler writes may reach the real ResponseWriter until flushTo is called,
// and what does reach it must be byte-identical to what the handler wrote.
func TestBufferedResponseWriterCapturesEverything(t *testing.T) {
	buf := newBufferedResponseWriter()
	buf.Header().Set("Content-Type", "application/json")
	buf.WriteHeader(http.StatusCreated)
	// A header set after WriteHeader is ignored, exactly as net/http does.
	buf.Header().Set("X-Too-Late", "yes")
	if _, err := buf.Write([]byte(`{"ok":true}`)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if buf.status != http.StatusCreated {
		t.Errorf("buffered status = %d, want %d", buf.status, http.StatusCreated)
	}

	rec := httptest.NewRecorder()
	buf.flushTo(rec)

	if rec.Code != http.StatusCreated {
		t.Errorf("flushed status = %d, want %d", rec.Code, http.StatusCreated)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("flushed Content-Type = %q, want %q", got, "application/json")
	}
	if got := rec.Header().Get("X-Too-Late"); got != "" {
		t.Errorf("flushed X-Too-Late = %q, want it dropped (set after WriteHeader)", got)
	}
	if got := rec.Body.String(); got != `{"ok":true}` {
		t.Errorf("flushed body = %q, want %q", got, `{"ok":true}`)
	}
}

// TestBufferedResponseWriterImplicitStatus locks in net/http's own semantics
// for a handler that writes a body without ever calling WriteHeader (an
// implicit 200), and for one that calls WriteHeader twice (the second is
// ignored). Both matter because completeRequest branches on the captured
// status.
func TestBufferedResponseWriterImplicitStatus(t *testing.T) {
	buf := newBufferedResponseWriter()
	if _, err := buf.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if buf.status != http.StatusOK {
		t.Errorf("implicit status = %d, want %d", buf.status, http.StatusOK)
	}

	buf2 := newBufferedResponseWriter()
	buf2.WriteHeader(http.StatusConflict)
	buf2.WriteHeader(http.StatusOK)
	if buf2.status != http.StatusConflict {
		t.Errorf("status after a second WriteHeader = %d, want %d (first wins)", buf2.status, http.StatusConflict)
	}
}

// TestBufferedResponseWriterFlushesEmptyResponse covers a handler that writes
// neither a status nor a body (e.g. an implicit empty 200): flushTo must still
// send a status line, and any header the handler set must still go out.
func TestBufferedResponseWriterFlushesEmptyResponse(t *testing.T) {
	buf := newBufferedResponseWriter()
	buf.Header().Set("X-Set-Before-Anything", "yes")

	rec := httptest.NewRecorder()
	buf.flushTo(rec)

	if rec.Code != http.StatusOK {
		t.Errorf("flushed status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("X-Set-Before-Anything"); got != "yes" {
		t.Errorf("flushed header = %q, want %q", got, "yes")
	}
	if rec.Body.Len() != 0 {
		t.Errorf("flushed body = %q, want empty", rec.Body.String())
	}
}

// TestCompleteRequestCommitsBeforeSendingResponse is the ordering regression
// test for the bug this buffering exists to fix: requireAuth used to write the
// handler's status and body straight to the client and commit afterwards. The
// commit must now be the FIRST thing that happens.
func TestCompleteRequestCommitsBeforeSendingResponse(t *testing.T) {
	var log []string
	tx := &fakeTxFinisher{log: &log}
	dst := newRecordingWriter(&log)

	buf := newBufferedResponseWriter()
	buf.Header().Set("Content-Type", "application/json")
	buf.WriteHeader(http.StatusOK)
	_, _ = buf.Write([]byte(`{"clusterId":"cl_1","status":"Archived"}`))

	completeRequest(context.Background(), dst, buf, tx, nil)

	if want := []string{"commit", "writeHeader", "write"}; strings.Join(log, ",") != strings.Join(want, ",") {
		t.Fatalf("call order = %v, want %v", log, want)
	}
	if tx.commits != 1 || tx.rollbacks != 0 {
		t.Errorf("commits = %d, rollbacks = %d, want 1 and 0", tx.commits, tx.rollbacks)
	}
	if dst.status != http.StatusOK {
		t.Errorf("status = %d, want %d", dst.status, http.StatusOK)
	}
	if got := dst.body.String(); got != `{"clusterId":"cl_1","status":"Archived"}` {
		t.Errorf("body = %q, want the handler's own body", got)
	}
}

// TestCompleteRequestCommitFailureReplacesSuccessResponse is the core Bug 2
// regression test: a handler that wrote a 2xx whose transaction then fails to
// commit must NOT report success. Before the fix the commit error was only
// log.Printf'ed and the caller kept its 200 — cluster decommission's
// s.gw.Disconnect + failed commit being the concrete case (tunnel severed,
// cluster still Active, "Archived" reported).
func TestCompleteRequestCommitFailureReplacesSuccessResponse(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent} {
		tx := &fakeTxFinisher{commitErr: errors.New("could not serialize access due to concurrent update")}
		rec := httptest.NewRecorder()

		buf := newBufferedResponseWriter()
		buf.Header().Set("Content-Type", "application/json")
		buf.WriteHeader(status)
		_, _ = buf.Write([]byte(`{"status":"Archived"}`))

		completeRequest(context.Background(), rec, buf, tx, nil)

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("handler status %d + failed commit: response status = %d, want %d", status, rec.Code, http.StatusInternalServerError)
		}
		if strings.Contains(rec.Body.String(), "Archived") {
			t.Errorf("handler status %d + failed commit: body still contains the discarded success response: %s", status, rec.Body.String())
		}
		if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
			t.Errorf("handler status %d + failed commit: Content-Type = %q, want application/problem+json", status, got)
		}
		if tx.rollbacks != 0 {
			t.Errorf("handler status %d + failed commit: rollbacks = %d, want 0 (the commit already ended the transaction)", status, tx.rollbacks)
		}
	}
}

// TestCompleteRequestRollsBackErrorResponses locks in the pre-existing,
// deliberate behaviour the fix had to preserve: a handler response >= 400 rolls
// the transaction back and is never committed — which is exactly why
// recordCapabilityDenial uses its own separate transaction. The error response
// itself must still reach the client unchanged.
func TestCompleteRequestRollsBackErrorResponses(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusConflict, http.StatusInternalServerError} {
		var log []string
		tx := &fakeTxFinisher{log: &log}
		dst := newRecordingWriter(&log)

		buf := newBufferedResponseWriter()
		buf.Header().Set("Content-Type", "application/problem+json")
		buf.WriteHeader(status)
		_, _ = buf.Write([]byte(`{"title":"nope"}`))

		completeRequest(context.Background(), dst, buf, tx, nil)

		if tx.commits != 0 {
			t.Errorf("handler status %d: commits = %d, want 0", status, tx.commits)
		}
		if tx.rollbacks != 1 {
			t.Errorf("handler status %d: rollbacks = %d, want 1", status, tx.rollbacks)
		}
		if dst.status != status {
			t.Errorf("handler status %d: forwarded status = %d, want it unchanged", status, dst.status)
		}
		if got := dst.body.String(); got != `{"title":"nope"}` {
			t.Errorf("handler status %d: body = %q, want the handler's own body", status, got)
		}
		if want := []string{"rollback", "writeHeader", "write"}; strings.Join(log, ",") != strings.Join(want, ",") {
			t.Errorf("handler status %d: call order = %v, want %v", status, log, want)
		}
	}
}

// TestCompleteRequestCommitsSilentSuccess covers a handler that returned
// without writing anything at all (an implicit empty 200): that still has to
// commit, and still has to send a response.
func TestCompleteRequestCommitsSilentSuccess(t *testing.T) {
	tx := &fakeTxFinisher{}
	rec := httptest.NewRecorder()

	completeRequest(context.Background(), rec, newBufferedResponseWriter(), tx, nil)

	if tx.commits != 1 {
		t.Errorf("commits = %d, want 1", tx.commits)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// TestRequireAnyCapability covers the OR-shaped gate added for
// POST /api/v1/ws/ticket: holding either listed capability is enough, holding
// neither is a 403 that names both, and the wrapped handler must not run in the
// denied case.
func TestRequireAnyCapability(t *testing.T) {
	required := []string{authz.CapIncidentRead, authz.CapClusterRead}

	cases := []struct {
		name       string
		grants     []authz.EffectiveGrant
		wantStatus int
		wantCalled bool
	}{
		{"holds the first", grantsFor(authz.CapIncidentRead), http.StatusOK, true},
		{"holds the second", grantsFor(authz.CapClusterRead), http.StatusOK, true},
		{"holds both", grantsFor(authz.CapIncidentRead, authz.CapClusterRead), http.StatusOK, true},
		{"holds neither", grantsFor(authz.CapRemediationApprove), http.StatusForbidden, false},
		{"holds nothing at all", nil, http.StatusForbidden, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := serverWithUnreachableAuditDB(t)
			called := false
			handler := s.requireAnyCapability(required, func(w http.ResponseWriter, r *http.Request, rc *requestContext) {
				called = true
				writeJSON(w, http.StatusOK, map[string]string{"ok": "yes"})
			})

			rec := httptest.NewRecorder()
			handler(rec, httptest.NewRequest(http.MethodPost, "/api/v1/ws/ticket", nil), &requestContext{Grants: c.grants})

			if called != c.wantCalled {
				t.Errorf("inner handler called = %v, want %v", called, c.wantCalled)
			}
			if rec.Code != c.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, c.wantStatus, rec.Body.String())
			}
			if c.wantStatus == http.StatusForbidden {
				for _, capability := range required {
					if !strings.Contains(rec.Body.String(), capability) {
						t.Errorf("403 body does not name %q: %s", capability, rec.Body.String())
					}
				}
			}
		})
	}
}
