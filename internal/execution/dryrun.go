package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"argus/internal/remediation"
)

// dryRunAttestation is what the cluster said when asked to rehearse a change.
// It is ARGUS's own record of having checked, not a claim copied from a model.
type dryRunAttestation struct {
	// At is when the rehearsal ran. An attestation is a statement about the
	// cluster at a moment, and it goes stale: an admission policy or a quota
	// can change between the rehearsal and the execution seconds later. This
	// gate narrows that window to about as small as it can be made without
	// the API server offering a transaction, and the timestamp is what makes
	// the residual window visible rather than implied.
	At time.Time `json:"at"`
	// Object is the API server's own "after" state, post-defaulting and
	// post-mutating-admission. Retained for BACKLOG.md F13's diff.
	Object json.RawMessage `json:"object,omitempty"`
	// Patch is what the agent actually submitted. It lets the diff separate
	// "what this plan asked for" from "what the cluster also did" — the second
	// being the thing an approver could not have predicted for themselves.
	Patch json.RawMessage `json:"patch,omitempty"`
}

// attestByDryRun asks the cluster whether it would accept `content`, without
// changing anything.
//
// # A rehearsal is cheap, but it is not free, and the difference is DESIGN.md's
//
// DESIGN.md §8.3/§18.3 state the caveat this code must not paper over: a
// server-side dry run "traverses the full authorisation chain and therefore
// requires the *same* patch/update/create verb as a real write, and it
// executes mutating admission webhooks that do not declare
// `sideEffects: NoneOnDryRun`".
//
// The first half is why this gate needed no new RBAC or ServiceAccount — a
// dry-run patch is a `patch`, which argus-remediate already holds, which is
// what turned this from an item blocked on C4 into a shipped one.
//
// The second half is a real, if narrow, cost. Nothing ARGUS does is committed
// and the API server persists nothing, but a badly-behaved mutating webhook in
// the customer's cluster can still take an action when it sees the request. So
// "a refused rehearsal costs nothing" is true of ARGUS and of the API server's
// storage, and is NOT a claim about third-party webhooks. It is not worth
// avoiding — the alternative is discovering the same rejection after the
// approval is recorded, having sent the identical request anyway — but it
// should be stated where someone would otherwise assume a dry run is inert.
//
// It signs a dry-run TWIN of the plan rather than adding an unsigned flag to
// the real one. That costs one extra HMAC and buys the property that matters:
// the rehearsal and the execution are two distinct signed plans with distinct
// hashes, so neither can be rewritten into the other in flight, and the agent
// decides what to do from content it verified rather than from an argument it
// was handed. Everything else about the two — target, params, rollback,
// precondition — is identical by construction, because both are signed from
// the same `content` value.
func (s *Executor) attestByDryRun(
	ctx context.Context, clusterID, tool string,
	content remediation.PlanContent, expiresAt time.Time, perClusterKey []byte,
	mode PrepMode,
) (dryRunAttestation, error) {
	content.DryRun = true
	signed, err := remediation.Sign(content, clusterID, expiresAt, perClusterKey)
	if err != nil {
		return dryRunAttestation{}, fmt.Errorf("sign dry-run plan: %w", err)
	}
	argsJSON, err := json.Marshal(map[string]any{"plan": signed})
	if err != nil {
		return dryRunAttestation{}, fmt.Errorf("build dry-run tool args: %w", err)
	}

	raw, err := s.gw.CallTool(ctx, clusterID, tool, argsJSON)
	if err != nil {
		// The underlying words, surfaced verbatim rather than summarized. An
		// admission webhook's rejection is usually the single most useful
		// sentence available about why a change cannot be made — it names the
		// policy, the field and the bound — and it is also the text
		// BACKLOG.md F12b's retry loop feeds back to the model so it can
		// correct its own patch (see dryRunRejectedError below, and
		// retryDryRunWithCorrection which acts on it). Rewriting it into
		// ARGUS's voice would discard exactly the part with diagnostic value.
		//
		// Attributed to "the cluster or its ARGUS agent", not to the API
		// server, because the hub genuinely cannot tell which refused: the
		// error arrives as text over the tunnel, and the agent's own
		// pre-flight checks (signature, expiry, target narrowing, live-state
		// assertions) sit in front of the API server call. This was written
		// the confident way first and the first live run said "The API server
		// said: signature verification failed" — a sentence that sends an
		// operator to look at their admission policies for an agent-side
		// problem. Naming both is the honest shape, and cheap.
		//
		// Wrapped in dryRunRejectedError (rather than left as a bare
		// fmt.Errorf, which is all this was before F12b) because this is
		// specifically the ONE PreparePlan failure mode a corrected params
		// value could plausibly fix — see that type's own doc comment for
		// why every other PreparePlan failure is deliberately left as a
		// plain error the retry loop passes straight through.
		//
		// Worded per mode: on a preview nobody asked to execute anything, so
		// "nothing was executed" would answer a question that was not asked.
		return dryRunAttestation{}, fmt.Errorf("%s %w", dryRunRefusalLead(mode),
			&dryRunRejectedError{Rejection: err.Error(), cause: err})
	}

	return interpretDryRunResult(raw, time.Now().UTC())
}

// interpretDryRunResult decides whether an agent's successful response actually
// proves a rehearsal happened.
//
// Split out from attestByDryRun as a pure function purely so it can be tested:
// this is the fail-closed check the gate's safety rests on, s.gw is a concrete
// *gateway.Gateway rather than an interface, and a control this important
// should not be reachable only through a live tunnel.
func interpretDryRunResult(raw json.RawMessage, now time.Time) (dryRunAttestation, error) {
	var res struct {
		DryRun bool            `json:"dryRun"`
		Object json.RawMessage `json:"object"`
		Patch  json.RawMessage `json:"patch"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return dryRunAttestation{}, fmt.Errorf("the cluster accepted the rehearsal but its response could not be read, so ARGUS cannot confirm the change was only rehearsed: %w", err)
	}

	// FAIL CLOSED on an unconfirmed rehearsal. This is the version-skew guard,
	// and it is the reason the echo exists at all.
	//
	// Hub and agent upgrade independently — that is a property of the product,
	// not of this deployment, since the agent runs in the customer's cluster
	// and is upgraded on their schedule. An agent built before
	// SignedPlan.DryRun existed will unmarshal the field into nothing, ignore
	// it, and PATCH FOR REAL. Its response is indistinguishable from a
	// successful rehearsal — a 200 and a resourceVersion — so if the hub
	// trusted success alone it would mutate the cluster here and then mutate
	// it a second time below, having reported the first as a dry run.
	//
	// So silence is treated as failure. An old agent makes remediation refuse
	// with an actionable message; it does not make remediation dangerous. That
	// is the correct direction for this trade, and it is why the echo is
	// checked rather than assumed.
	if !res.DryRun {
		return dryRunAttestation{}, errors.New(
			"this agent did not confirm it ran the change as a dry run, so ARGUS cannot tell a rehearsal from a real mutation and refused to continue. This almost always means the agent predates the dry-run gate — upgrade the ARGUS agent in this cluster")
	}

	return dryRunAttestation{At: now, Object: res.Object, Patch: res.Patch}, nil
}

// dryRunRefusalLead is the sentence in front of the cluster's own words when
// the rehearsal is refused.
func dryRunRefusalLead(mode PrepMode) string {
	if mode == PrepForPreflight {
		return "the cluster refused the rehearsal of this change, so nothing was changed. The cluster or its ARGUS agent reported:"
	}
	return "this change did not pass the rehearsal ARGUS runs before executing, so nothing was executed and this incident was not moved to Executing. The cluster or its ARGUS agent reported:"
}
