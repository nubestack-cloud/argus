package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/events"
	"argus/internal/logging"
	"argus/internal/remediation"
)

// pollTokenReplayGrace bounds how long after a cert is first issued the
// idempotent "issued" response (including the per-cluster plan signing key
// riding along with it, see enrollStatusResponse) keeps being served to
// repeat polls of the same pollToken. Not true single-use: a legitimate
// agent that received the response but crashed before finishing persisting
// it to disk must still be able to retry. 24h is generous relative to how
// fast that persist actually happens (sub-second) while still closing what
// would otherwise be an eternal replay window for fleet-sensitive material.
const pollTokenReplayGrace = 24 * time.Hour

// leafCertValidity is the lifetime of a cluster's issued leaf certificate —
// lld/03-agent-protocol.md §3's default (7 days would be the "real" two-tier
// PKI default; this MVP's single-tier dev CA uses the document's stated
// configurable ceiling instead, since there's no renewal-over-tunnel
// mechanism implemented yet to exercise the shorter default against).
const leafCertValidity = 90 * 24 * time.Hour

type enrollRequest struct {
	Token              string `json:"token"`
	CSRPem             string `json:"csrPem"`
	ClusterFingerprint string `json:"clusterFingerprint"`
	DisplayName        string `json:"displayName"`
}

type enrollResponse struct {
	ClusterID string `json:"clusterId"`
	Status    string `json:"status"`
	PollToken string `json:"pollToken"`
}

// handleEnroll is POST /api/v1/clusters/enroll (lld/03-agent-protocol.md §5's
// `Enroll` step, adapted to this increment's plain-REST MVP transport — see
// this document's addendum for why Enroll/EnrollStatus are REST, not RPC, at
// this stage). Unauthenticated by necessity, like the token-issuing routes:
// the caller is an agent presenting a bearer enrollment token, not a user with
// a session.
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}
	if req.Token == "" || req.CSRPem == "" || req.ClusterFingerprint == "" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-enroll-request",
			"token, csrPem, and clusterFingerprint are all required", "")
		return
	}
	if _, err := parseCSR(req.CSRPem); err != nil {
		logger.WarnContext(r.Context(), "rejecting an enrollment request: the CSR is invalid", logging.Err(err))
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-csr", "Submitted CSR could not be parsed", "")
		return
	}

	ctx := r.Context()
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "beginning the enrollment transaction failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not start transaction", "")
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// RedeemEnrollmentToken resolves + sets RLS scope itself (no prior session
	// exists yet to have done that already) and returns the token's tenant —
	// the new cluster row belongs to that tenant.
	redemption, err := s.enrollmentSigner.Redeem(ctx, tx, req.Token)
	tenantID := redemption.TenantID
	if err != nil {
		// Real reason already logged inside RedeemEnrollmentToken; this is
		// reachable from an unauthenticated caller, so no further detail here.
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-enrollment-token", "Enrollment token could not be redeemed", "")
		return
	}

	// §5: a duplicate fingerprint means the same physical cluster attempting to
	// enroll twice — reject outright rather than silently creating a second
	// record. This check gives a clean 409 in the common case; the DB's unique
	// index (clusters_fingerprint_active_idx, migration 000002) is the actual
	// backstop for the race with a concurrent enroll of the same fingerprint,
	// handled below when the INSERT itself is attempted.
	var existingID string
	err = tx.QueryRow(ctx,
		`SELECT id FROM clusters WHERE cluster_fingerprint = $1 AND archived_at IS NULL`,
		req.ClusterFingerprint).Scan(&existingID)
	if err == nil {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/already-enrolled", "A cluster with this fingerprint is already enrolled", "")
		return
	}
	if err != pgx.ErrNoRows {
		logger.ErrorContext(ctx, "checking for an existing CSR fingerprint failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not check existing enrollment", "")
		return
	}

	pollToken, pollTokenHash, err := newPollTokenAndHash()
	if err != nil {
		logger.ErrorContext(ctx, "generating the enrollment poll token failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not generate poll token", "")
		return
	}

	displayName := req.DisplayName
	if displayName == "" {
		displayName = "cluster-" + shortFingerprint(req.ClusterFingerprint)
	}

	clusterID := domain.NewID(domain.PrefixCluster)
	// A fleet token with auto-accept accepts the cluster here, on behalf of
	// the person who issued it (who held cluster:accept to do so): the
	// cluster starts Provisioning, exactly as an accept leaves it.
	state, acceptedBy, status := "PendingApproval", (*string)(nil), "pendingApproval"
	if redemption.AutoAccept {
		state, acceptedBy, status = "Provisioning", &redemption.Issuer, "accepted"
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint, csr_pem, poll_token_hash, accepted_by)
		 VALUES ($1, $2, $3, $7, 'default', $4, $5, $6, $8)`,
		clusterID, tenantID, displayName, req.ClusterFingerprint, req.CSRPem, pollTokenHash, state, acceptedBy)
	if err != nil {
		if isUniqueViolation(err) {
			// Lost the race against a concurrent enroll of the same fingerprint.
			writeProblem(w, http.StatusConflict, "https://argus.io/errors/already-enrolled", "A cluster with this fingerprint is already enrolled", "")
			return
		}
		logger.ErrorContext(ctx, "inserting the enrolling cluster failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not create cluster record", "")
		return
	}

	// The actor here is an unauthenticated agent that presented a bearer
	// enrollment token, not a logged-in user — ActorID stays nil (there is
	// no users.id to point to), and ActorAuthMethod records what WAS
	// presented instead. Recorded on the same transaction as the INSERT
	// above, before its Commit, so the audit row and the new cluster row
	// land atomically together.
	if err := audit.RecordEvent(ctx, tx, audit.Event{
		TenantID:        tenantID,
		ActorAuthMethod: "enrollment_token",
		SourceIP:        clientIP(r),
		ClusterID:       &clusterID,
		Outcome:         audit.OutcomeSuccess,
		Details:         map[string]any{"clusterFingerprint": req.ClusterFingerprint},
	}); err != nil {
		logger.ErrorContext(ctx, "recording an enrollment in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}
	if redemption.AutoAccept {
		capability := authz.CapClusterAccept
		if err := audit.RecordEvent(ctx, tx, audit.Event{
			TenantID: tenantID, ActorID: &redemption.Issuer, ActorAuthMethod: "fleet_token", SourceIP: clientIP(r),
			Capability: &capability, ClusterID: &clusterID, Outcome: audit.OutcomeSuccess,
			Details: map[string]any{"action": "auto_accept_cluster", "tokenId": redemption.TokenID},
		}); err != nil {
			logger.ErrorContext(ctx, "recording an automatic acceptance in the audit log failed", logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
			return
		}
	}

	if err := tx.Commit(ctx); err != nil {
		logger.ErrorContext(ctx, "committing an enrollment failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not commit enrollment", "")
		return
	}

	// A cluster APPEARING is a cluster update, and this was the one lifecycle
	// transition that published nothing — accept, decommission, health
	// demotion and heartbeat recovery all did. It did not show while every
	// screen polled /clusters every five seconds; PROJECT.md P16 made the
	// event the refresh mechanism and the poll a 60s safety net, at which
	// point the missing publish becomes an operator watching the onboarding
	// wizard on Overview for up to a minute after their agent has already
	// checked in. Published after Commit, so nothing is announced that a
	// rolled-back transaction would then unsay.
	if s.events != nil {
		s.events.Publish(events.ClusterUpdated(clusterID))
	}

	writeJSON(w, http.StatusCreated, enrollResponse{
		ClusterID: clusterID,
		Status:    status,
		PollToken: pollToken,
	})
}

type enrollStatusResponse struct {
	Status      string `json:"status"`
	CertPem     string `json:"certPem,omitempty"`
	CAPem       string `json:"caPem,omitempty"`
	HubEndpoint string `json:"hubEndpoint,omitempty"`
	// PlanSigningKey is this cluster's own derived remediation-plan signing
	// key (remediation.DeriveClusterSigningKey), base64-standard-encoded —
	// never the hub's root key. Reuses this same one-shot hub->agent
	// delivery path as CertPem/CAPem rather than a second push channel; the
	// agent persists it to disk alongside cert.pem/ca.pem
	// (internal/agent/client.go) and uses it to verify a signed
	// ScaleDeployment/RestartPod plan before ever calling Patch.
	PlanSigningKey string `json:"planSigningKey,omitempty"`
}

// buildIssuedEnrollStatusResponse is the one place that assembles the
// "issued" response shape — used by both call sites below (the idempotent
// replay branch and the first-issuance branch) so they can never drift on
// what an issued response actually contains.
func (s *Server) buildIssuedEnrollStatusResponse(clusterID, certPem string) enrollStatusResponse {
	perClusterKey, err := remediation.DeriveClusterSigningKey(s.planSigningRootKey, clusterID)
	if err != nil {
		// Only fails if crypto/rand-backed HKDF expansion itself fails —
		// not a real-world condition, but if it somehow did, the agent
		// simply won't be able to execute a remediation plan against this
		// cluster (it never received a key), not a reason to fail
		// enrollment/reconnection itself, which everything else in this
		// response still serves.
		logger.Error("deriving the plan signing key failed", logging.ClusterID(clusterID), logging.Err(err))
	}
	return enrollStatusResponse{
		Status:         "issued",
		CertPem:        certPem,
		CAPem:          string(s.ca.RootCertPEM()),
		HubEndpoint:    s.tunnelPublicEndpoint,
		PlanSigningKey: base64.StdEncoding.EncodeToString(perClusterKey),
	}
}

// handleEnrollStatus is GET /api/v1/clusters/enroll/status?pollToken=...
// (lld/03-agent-protocol.md §5's `EnrollStatus` poll, agent-initiated,
// jittered per §5's table). Unauthenticated, like handleEnroll.
func (s *Server) handleEnrollStatus(w http.ResponseWriter, r *http.Request) {
	pollToken := r.URL.Query().Get("pollToken")
	if pollToken == "" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "pollToken query parameter is required", "")
		return
	}
	pollTokenHash := hashPollToken(pollToken)

	ctx := r.Context()
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "beginning the enrollment-status transaction failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not start transaction", "")
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		logger.ErrorContext(ctx, "resolving the organisation for an enrollment status poll failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not resolve organisation", "")
		return
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		logger.ErrorContext(ctx, "setting the request scope for an enrollment status poll failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not set request scope", "")
		return
	}

	var clusterID, state, csrPem string
	var issuedCertPem *string
	var certIssuedAt *time.Time
	err = tx.QueryRow(ctx,
		`SELECT id, state, csr_pem, issued_cert_pem, cert_issued_at FROM clusters WHERE poll_token_hash = $1`,
		pollTokenHash).Scan(&clusterID, &state, &csrPem, &issuedCertPem, &certIssuedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "No cluster matches this poll token", "")
			return
		}
		logger.ErrorContext(ctx, "looking up the enrollment poll token failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up enrollment status", "")
		return
	}

	// Idempotent polling: once a cert has been issued, every subsequent poll
	// returns the same one, regardless of what state the cluster has moved to
	// since (Provisioning -> Active happens over the tunnel, not via this poll)
	// — but only within pollTokenReplayGrace of the original issuance (see its
	// own doc comment); a poll of a long-since-issued token past that window
	// is treated exactly like an unrecognized one, closing what would
	// otherwise be an eternal replay window for the plan signing key riding
	// along with this response.
	if issuedCertPem != nil && *issuedCertPem != "" {
		if certIssuedAt == nil || time.Since(*certIssuedAt) > pollTokenReplayGrace {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "No cluster matches this poll token", "")
			return
		}
		writeJSON(w, http.StatusOK, s.buildIssuedEnrollStatusResponse(clusterID, *issuedCertPem))
		return
	}

	switch state {
	case "Rejected":
		writeJSON(w, http.StatusOK, enrollStatusResponse{Status: "rejected"})
		return
	case "Provisioning":
		// §4's transition point: cluster:accept already moved this cluster to
		// Provisioning; this is the first poll since then, so sign the CSR now.
		certPem, serial, err := s.ca.SignCSR([]byte(csrPem), leafCertValidity)
		if err != nil {
			logger.ErrorContext(ctx, "signing the agent CSR failed", logging.ClusterID(clusterID), logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not issue certificate", "")
			return
		}
		if _, err := tx.Exec(ctx,
			`UPDATE clusters SET issued_cert_pem = $2, cert_serial = $3, cert_issued_at = now() WHERE id = $1`,
			clusterID, certPem, serial); err != nil {
			logger.ErrorContext(ctx, "storing the issued agent certificate failed", logging.ClusterID(clusterID), logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not store issued certificate", "")
			return
		}

		// This transition (issued_cert_pem set for the first time) happens
		// exactly once per cluster — every later poll takes the idempotent
		// early-return branch above instead — so this can't double-log on
		// repeated polling. Actor is the polling agent, not a user: it
		// authenticated this request by presenting the poll token, not a
		// user session, hence ActorID nil / ActorAuthMethod "poll_token".
		if err := audit.RecordEvent(ctx, tx, audit.Event{
			TenantID:        tenantID,
			ActorAuthMethod: "poll_token",
			SourceIP:        clientIP(r),
			ClusterID:       &clusterID,
			Outcome:         audit.OutcomeSuccess,
			Details:         map[string]any{"certSerial": serial},
		}); err != nil {
			logger.ErrorContext(ctx, "recording a certificate issue in the audit log failed", logging.ClusterID(clusterID), logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
			return
		}

		if err := tx.Commit(ctx); err != nil {
			logger.ErrorContext(ctx, "committing an enrollment certificate issue failed", logging.ClusterID(clusterID), logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not commit certificate issuance", "")
			return
		}
		writeJSON(w, http.StatusOK, s.buildIssuedEnrollStatusResponse(clusterID, certPem))
		return
	default:
		// PendingApproval, or (shouldn't normally happen without an issued cert
		// already set above) any later state — report pendingApproval rather
		// than guess.
		writeJSON(w, http.StatusOK, enrollStatusResponse{Status: "pendingApproval"})
		return
	}
}

// parseCSR validates that csrPEM is a well-formed, self-consistent PKCS#10
// CSR — the same check gateway.DevCA.SignCSR performs at accept time, run
// here too so a malformed submission fails fast with a clean 400 instead of
// being stored and only discovered as broken when accept-time signing fails.
func parseCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("not a PEM-encoded CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature invalid: %w", err)
	}
	return csr, nil
}

// newPollTokenAndHash mirrors authz's refresh-token shape exactly (32 random
// bytes, base64url for the bearer value, hex-SHA256 for what's actually
// stored) — see internal/authz/session.go's newOpaqueTokenAndHash. Only the
// hash is ever persisted (clusters.poll_token_hash); the raw value is
// returned to the caller once and never stored.
func newPollTokenAndHash() (token, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generate poll token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(buf)
	return token, hashPollToken(token), nil
}

func hashPollToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// shortFingerprint returns up to the first 8 characters of a fingerprint, for
// the display-name fallback ("cluster-" + shortFingerprint(...)) — safe even
// if the submitted fingerprint happens to be shorter than 8 characters.
func shortFingerprint(fingerprint string) string {
	if len(fingerprint) <= 8 {
		return fingerprint
	}
	return fingerprint[:8]
}

// isUniqueViolation reports whether err is a Postgres unique_violation
// (SQLSTATE 23505) — used to handle the enroll-time fingerprint race
// gracefully after the pre-check above already covers the common,
// non-racing case.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
