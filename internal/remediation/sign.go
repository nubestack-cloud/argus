// This file implements plan signing: turning a RemediationPlan the hub has
// decided to execute into a tamper-evident, expiring envelope
// (internal/agent/tools.go's four execution tools — scale_deployment,
// restart_pod, patch_resource_limits, revert_container_image — are the only
// consumers) — lld/08-remediation-contracts.md §7's HMAC scheme, plus the
// HKDF per-cluster key derivation from lld/08's key-management note.
//
// Deliberately still no DB access and no state of its own, matching this
// package's existing pure-function discipline (see plan.go/gate.go): the
// root signing key is loaded from Postgres elsewhere (internal/data's
// LoadOrCreateSigningKey, called from cmd/hub/main.go, same pattern as
// authz's signers) and handed to Sign/Verify here as plain bytes. This
// package only ever computes a hash/HMAC over bytes it's given — it never
// looks anything up.
package remediation

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

// GenerateRootSigningKeyMaterial generates a fresh 32-byte root signing
// key — the "generate" callback for internal/data.LoadOrCreateSigningKey's
// "plan_signing_key_root" purpose (cmd/hub/main.go), mirroring
// authz.generateEnrollmentKeyMaterial's exact shape and rationale: an HMAC
// key is just opaque random bytes, no serialization step needed.
func GenerateRootSigningKeyMaterial() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate root plan signing key: %w", err)
	}
	return key, nil
}

// CompensatingAction is the "undo" half of one plan: the typed action that
// restores the state the plan is about to change, captured from the LIVE
// object before the mutation and carried inside the signed envelope.
//
// Why it carries no target of its own: a compensating action always applies
// to the exact same object as the plan it undoes (PlanContent's TargetGVK/
// TargetNamespace/TargetName). A rollback naming a different target would
// not be an undo, it would be a second plan — and allowing one to be
// expressed here would mean the envelope contained a mutation the approver
// never saw described. So the shape makes that unrepresentable rather than
// merely discouraged.
//
// Why Params is raw JSON rather than the typed ActionParams interface: same
// reason PlanContent.Params is (see below) — this package must be able to
// carry marshaled params without importing internal/orchestrator, which owns
// the wire shape and already imports this package. The consumer re-decodes it
// into the typed params struct for its action type and re-validates before
// acting on it; nothing trusts these bytes because they arrived signed.
//
// Executing a rollback is a separate, deliberately unbuilt step: nothing in
// this codebase applies one yet (there is no undo endpoint and no automatic
// rollback trigger — DESIGN.md §10.5's automatic triggers and
// §12.2's outcome table both need the validation sweeper to be able to drive
// an execution, which it cannot). What this type buys today is that the undo
// is COMPUTED and RECORDED, from live state, before the change happens — so
// building the executor later is a matter of reading an audit record, not of
// re-running an analysis against a cluster that has since moved on. That is
// exactly the property §10.3 asks for, and the half of it that has to happen
// now, because the pre-change values are only knowable now.
type CompensatingAction struct {
	// ActionType is the action that undoes the plan — for
	// PatchResourceLimits, another PatchResourceLimits carrying the values
	// read off the live container; for RevertContainerImage, another
	// RevertContainerImage carrying the image the container is running RIGHT
	// NOW, so the undo of "go back one revision" is "come back forward to
	// where we were". Both are captured from the live object before the
	// mutation, which is the only moment either is knowable.
	ActionType ActionType `json:"actionType"`

	// Params is that action's params, in the same lowercase-keyed wire shape
	// PlanContent.Params uses.
	Params json.RawMessage `json:"params"`

	// Description is a one-line, human-readable statement of what the undo
	// would do, written at capture time. Present so the audit record is
	// readable by a human who is not going to decode Params (and so a future
	// approval UI can show "if this goes wrong, we can put it back to X"
	// without needing to understand every action type's params shape).
	Description string `json:"description,omitempty"`
}

// PlanContent is the exact set of fields a signature commits to — a
// concrete struct (not a map) so json.Marshal produces the same bytes every
// time regardless of Go map-iteration order, which is what makes planHash
// below deterministic. Params is carried as already-marshaled
// lowercase-keyed JSON (internal/orchestrator.MarshalPlanParams' shape)
// rather than the typed remediation.ActionParams interface, specifically so
// this package never needs to import internal/orchestrator (which already
// imports this package) to reproduce its marshaling — the caller marshals
// once and hands the bytes to both the DB row and this struct.
type PlanContent struct {
	RecommendationID string          `json:"recommendationId"`
	ActionType       ActionType      `json:"actionType"`
	TargetGVK        string          `json:"targetGvk"`
	TargetNamespace  string          `json:"targetNamespace"`
	TargetName       string          `json:"targetName"`
	Params           json.RawMessage `json:"params"`

	// Rollback is the compensating action captured BEFORE execution, per
	// DESIGN.md §10.3's plan schema ("explicit rollback per
	// action, captured before execution, so undo doesn't require
	// re-analysis") — the `"rollback": {...}` member of §10.3's own JSON
	// example. nil for an action type that has no representable compensating
	// action.
	//
	// Signed as part of PlanContent, not attached alongside it, for the same
	// reason ResourceVersion is: an unsigned rollback is one a compromised
	// hub could rewrite between signing and dispatch, which would turn the
	// undo path into a second, unreviewed mutation channel. Being inside the
	// signature also means the agent can refuse an action type whose contract
	// requires a rollback if one is absent — it can tell "the hub captured
	// nothing" from "someone stripped it", because stripping it changes the
	// hash. internal/agent/tools.go's patch_resource_limits and
	// revert_container_image both do exactly that, and both go further: each
	// also checks the rollback still describes the live object, since a
	// correctly-signed undo that is no longer true is worse than none.
	//
	// `omitempty` on a pointer matters more than it looks: it keeps the
	// marshaled bytes — and therefore planHash, and therefore every
	// signature — byte-identical to what they were before this field existed
	// for the two action types that don't populate it (ScaleDeployment,
	// RestartPod). Adding a rollback to those is a separate change with its
	// own execution-layer work, not something this field's existence
	// silently did.
	Rollback *CompensatingAction `json:"rollback,omitempty"`

	// ResourceVersion is the optimistic-concurrency precondition
	// (lld/08-remediation-contracts.md §5, SR-20) fetched fresh against
	// TargetGVK/TargetNamespace/TargetName at approval time — never the
	// possibly-stale value from whenever the plan was originally proposed.
	// Signed alongside everything else so it can't be swapped for a
	// different value after signing; the agent embeds it directly in its
	// strategic-merge patch body, which the API server itself then enforces
	// atomically (a bare Patch call fails outright against a mismatched
	// resourceVersion — no separate Get-then-Patch window to race).
	ResourceVersion string `json:"resourceVersion"`

	// DryRun asks the agent to send this exact patch to the API server with
	// `dryRun=All`: full authentication, authorization, admission control,
	// schema validation and defaulting, and then nothing persisted. It is
	// BACKLOG.md F12's gate — the layer that makes an approval-time assurance
	// the *cluster's* answer rather than the model's claim about itself.
	//
	// Inside the signature, for the same reason ResourceVersion and Rollback
	// are. If it were an unsigned argument travelling alongside the envelope,
	// a compromised hub — or, far more likely, a bug on the dispatch path —
	// could turn an intended dry run into a real mutation, and the agent would
	// have no way to tell that had happened. Signed, the two are different
	// plans with different hashes: the hub signs a dry-run twin and the real
	// plan separately, and neither can be rewritten into the other.
	//
	// `omitempty` is load-bearing, exactly as it is on Rollback: it keeps the
	// marshaled bytes — and therefore planHash, and therefore every existing
	// signature — byte-identical for every plan that does not set it. Adding
	// this field changed no existing plan's hash.
	//
	// VERSION SKEW IS THE DANGEROUS CASE, and it is handled at the other end
	// rather than here. An agent too old to know this field ignores it and
	// executes for real, which would mutate the cluster during what the hub
	// believed was a rehearsal and then mutate it again on the real call. So
	// the agent's result echoes back whether it actually ran a dry run, and
	// the hub REFUSES to proceed unless that echo is present and true —
	// fail-closed on silence, not trust-by-default. See
	// internal/agent/tools.go's executeResult and the gate in
	// internal/execution.
	DryRun bool `json:"dryRun,omitempty"`
}

// SignedPlan is the full envelope sent to an agent: PlanContent plus the
// cluster/expiry binding and the signature over all of it. This is exactly
// what internal/execution builds and signs at approve time, and
// what internal/agent/tools.go's execution tools receive as their
// tool-call args and independently re-verify before ever calling Patch.
type SignedPlan struct {
	PlanContent
	ClusterID string    `json:"clusterId"`
	ExpiresAt time.Time `json:"expiresAt"`
	Signature string    `json:"signature"` // base64url(HMAC-SHA256(...))
}

// planHash returns SHA-256(json.Marshal(content)), hex-encoded — a
// human-inspectable checkpoint (e.g. for remediation_executions' own audit
// row), but never itself trusted on its own: Verify below always
// recomputes it from the envelope's own content fields rather than
// accepting a transmitted hash value at face value, so there is no "bare
// hash + signature" pair anywhere that content hasn't been independently
// re-derived from.
func planHash(content PlanContent) (string, error) {
	b, err := json.Marshal(content)
	if err != nil {
		return "", fmt.Errorf("marshal plan content: %w", err)
	}
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum), nil
}

// signaturePayload builds the exact bytes the HMAC is computed over —
// planHash bound to the cluster and expiry it's only valid for, so neither
// can be swapped onto a signature minted for a different cluster or a
// longer lifetime without invalidating it.
func signaturePayload(hash, clusterID string, expiresAt time.Time) []byte {
	return []byte(hash + "|" + clusterID + "|" + expiresAt.UTC().Format(time.RFC3339Nano))
}

// Sign produces a SignedPlan for one cluster's per-cluster derived key
// (DeriveClusterSigningKey below) — never the raw root key, which this
// function has no parameter for at all.
func Sign(content PlanContent, clusterID string, expiresAt time.Time, perClusterKey []byte) (SignedPlan, error) {
	hash, err := planHash(content)
	if err != nil {
		return SignedPlan{}, err
	}
	mac := hmac.New(sha256.New, perClusterKey)
	mac.Write(signaturePayload(hash, clusterID, expiresAt))
	return SignedPlan{
		PlanContent: content,
		ClusterID:   clusterID,
		ExpiresAt:   expiresAt,
		Signature:   base64.RawURLEncoding.EncodeToString(mac.Sum(nil)),
	}, nil
}

// Verify checks a SignedPlan against the cluster it was received from, at
// the time it's about to be acted on: the envelope must be addressed to
// expectedClusterID, must not have expired, and its signature must verify
// against a hash Verify recomputes from the envelope's own content — never
// a hash the envelope merely claims. now is a parameter (not time.Now()
// internally) so expiry is unit-testable without waiting on a real clock.
//
// A mismatched clusterID and a bad signature both fail closed with the same
// class of error deliberately: the per-cluster key derivation already
// means a signature minted for cluster A will not verify under cluster B's
// key, so the explicit clusterID check here is defense in depth, not the
// only thing standing between clusters.
func Verify(signed SignedPlan, expectedClusterID string, perClusterKey []byte, now time.Time) error {
	if signed.ClusterID != expectedClusterID {
		return fmt.Errorf("remediation: signed plan is addressed to cluster %q, not %q", signed.ClusterID, expectedClusterID)
	}
	if !now.Before(signed.ExpiresAt) {
		return fmt.Errorf("remediation: signed plan expired at %s", signed.ExpiresAt.UTC().Format(time.RFC3339))
	}

	hash, err := planHash(signed.PlanContent)
	if err != nil {
		return err
	}
	wantMAC := hmac.New(sha256.New, perClusterKey)
	wantMAC.Write(signaturePayload(hash, signed.ClusterID, signed.ExpiresAt))
	gotSig, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil {
		return fmt.Errorf("remediation: malformed signature: %w", err)
	}
	if !hmac.Equal(wantMAC.Sum(nil), gotSig) {
		return fmt.Errorf("remediation: signature verification failed")
	}
	return nil
}

// clusterKeyDerivationInfo namespaces the HKDF derivation so this key can
// never collide with some future, differently-purposed derivation from the
// same root key.
const clusterKeyDerivationInfo = "argus-remediation-plan-signing-v1"

// DeriveClusterSigningKey derives a 32-byte per-cluster key from the org's
// single root key (internal/data.LoadOrCreateSigningKey, purpose
// "plan_signing_key_root") via HKDF-SHA256, salted with nothing (the root
// key itself is already high-entropy random material — HKDF's salt exists
// to strengthen a low-entropy input, which this isn't) and bound to
// clusterID as HKDF's "info" parameter. This is deliberately a one-way,
// non-invertible derivation: a leaked per-cluster key (the only kind ever
// written to an agent's disk, see internal/api/enroll.go) reveals nothing
// about the root key or any other cluster's derived key.
func DeriveClusterSigningKey(rootKey []byte, clusterID string) ([]byte, error) {
	h := hkdf.New(sha256.New, rootKey, nil, []byte(clusterKeyDerivationInfo+":"+clusterID))
	key := make([]byte, 32)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, fmt.Errorf("derive per-cluster plan signing key: %w", err)
	}
	return key, nil
}
