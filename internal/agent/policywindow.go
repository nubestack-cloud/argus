package agent

// policywindow.go is the agent-side half of BACKLOG.md F14 — per-execution
// admission-policy scoping. See internal/api/executionwindow.go's header for
// the hub-side orchestration and
// deploy/helm/argus-agent/templates/validatingadmissionpolicy.yaml for the
// CEL that reads what this file writes.
//
// # Why one singleton object holding a list, not one object per window
//
// The alternative this feature could have taken is a separate
// ExecutionWindow object per open window, matched by a ValidatingAdmission
// PolicyBinding's paramRef.selector against a label. That was rejected: a
// selector-based paramRef's "match multiple param objects" semantics are not
// a documented, simple "permit if ANY matched object permits it" OR — and
// getting that wrong in the safety-critical direction (silently requiring
// ALL matched windows to agree, which would mean one unrelated open window
// on a different object could block or interact with another) is a risk this
// design avoids entirely by construction: there is exactly one param object,
// named directly in the binding's paramRef (no selector), so there is no
// multi-param evaluation semantics to get right or wrong. Concurrent windows
// for DIFFERENT targets are simply different entries in the one object's
// spec.windows list, and the CEL asks "does ANY entry in this list match
// THIS request" with a plain `.exists()` — an ordinary, unambiguous list
// comprehension.
//
// The cost of that choice is that two concurrent open/close calls (different
// targets, same cluster) race on updating the SAME Kubernetes object. That
// is handled entirely within this file, with an ordinary get-modify-update
// retry-on-conflict loop — it never blocks or serialises the HUB's two
// concurrent requests against each other (see internal/api/executionwindow.go's
// header for why that matters for G6/R3 composition); it only retries this
// agent's own small API call a bounded number of times.
//
// # TTL sweep — the independent half of the crash-safety guarantee
//
// runExecutionWindowSweeper runs for the lifetime of this agent process,
// entirely independent of the hub or the tunnel: it re-reads the singleton
// on its own timer, using its own clock, and drops any entry whose OpenedAt
// (stamped by THIS agent when the entry was created — never trusted from the
// hub, so a hub that lied about timing could not extend its own window) is
// older than policyWindowTTL. This is what bounds an execution window's
// lifetime when the hub crashes or the tunnel drops between opening a window
// and asking to close it — internal/api/executionwindow.go's `defer`-based
// close is the happy-path guarantee; this is what holds when the process
// running that defer never gets to.
import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"argus/internal/logging"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// policyWindowTTL bounds how long any single ExecutionWindow entry may
// survive without the hub explicitly closing it, enforced by this agent's own
// sweep regardless of hub liveness.
//
// Sized generously against the happy path it needs to outlast:
// signedPlanTTL (2 minutes, internal/api/remediation_exec.go) bounds how
// stale a signed plan may be, and the dry-run attestation plus the real
// patch both have to complete inside that window on an ordinary request —
// well under it in practice. Ten minutes is an order of magnitude of
// headroom over that, generous enough that no genuinely in-flight execution
// is ever swept out from under itself (a hub that is merely slow, not
// crashed, still closes its own window long before this fires), while still
// being a bounded number an operator can reason about rather than "forever".
const policyWindowTTL = 10 * time.Minute

// policyWindowSweepInterval is how often runExecutionWindowSweeper re-checks
// the singleton. Frequent enough that a stale window is never open much
// longer than policyWindowTTL itself, cheap enough (one GET, most ticks
// doing nothing) to run for the lifetime of every agent process regardless
// of whether this cluster ever opens a single window.
const policyWindowSweepInterval = 60 * time.Second

// executionWindowGroupVersionKind is stamped onto every object this file
// builds, matching deploy/helm/argus-agent/templates/executionwindow-crd.yaml.
const (
	executionWindowAPIVersion = "argus.io/v1"
	executionWindowKind       = "ExecutionWindow"
)

// windowRequestEntry is what internal/api/executionwindow.go's
// executionWindowEntry looks like on the wire — every field the hub sends,
// and nothing else. OpenedAt is deliberately NOT one of them: it is stamped
// by THIS agent, from this agent's own clock, the moment an entry is
// actually written (see this file's header for why that must never be a
// hub-supplied value).
type windowRequestEntry struct {
	PlanID          string `json:"planId"`
	TargetAPIGroup  string `json:"targetApiGroup"`
	TargetKind      string `json:"targetKind"`
	TargetNamespace string `json:"targetNamespace,omitempty"`
	TargetName      string `json:"targetName"`
	TargetUID       string `json:"targetUid"`
	FieldPath       string `json:"fieldPath"`
}

// validate refuses an entry missing anything the CEL widening clauses or
// this file's own bookkeeping actually key on. Fail closed: an entry with an
// empty TargetUID or FieldPath would either match nothing (harmless, but
// pointless — the tunnel round trip was wasted) or, worse, be a sign this
// agent decoded a malformed or truncated request it should not silently act
// on.
func (w windowRequestEntry) validate() error {
	if w.PlanID == "" {
		return fmt.Errorf("windows[].planId is required")
	}
	if w.TargetUID == "" {
		return fmt.Errorf("windows[].targetUid is required")
	}
	if w.FieldPath == "" {
		return fmt.Errorf("windows[].fieldPath is required")
	}
	if w.TargetName == "" {
		return fmt.Errorf("windows[].targetName is required")
	}
	return nil
}

// storedWindowEntry is windowRequestEntry plus the agent-stamped OpenedAt —
// the shape actually persisted on the ExecutionWindow singleton's
// spec.windows.
type storedWindowEntry struct {
	windowRequestEntry
	OpenedAt string `json:"openedAt"`
}

// isStale reports whether this entry is older than policyWindowTTL, relative
// to now. An unparseable OpenedAt (should never happen — this agent is the
// only writer) is treated as stale, on the fail-safe side: something this
// agent cannot make sense of is not something it should trust to still be a
// live execution.
func (w storedWindowEntry) isStale(now time.Time) bool {
	t, err := time.Parse(time.RFC3339, w.OpenedAt)
	if err != nil {
		return true
	}
	return now.Sub(t) > policyWindowTTL
}

// getExecutionWindowSpec fetches the singleton and decodes its
// spec.windows, or returns (nil, "", false, nil) when the object does not
// exist yet — an entirely ordinary state (no window has ever been opened on
// this cluster) rather than an error.
//
// exists is reported separately from resourceVersion rather than inferred
// from resourceVersion being "" — a real API server always assigns one on
// creation, but this codebase's own test fake does not, and putExecutionWindowSpec
// below must still choose Update (never Create) for an object that already
// exists with an empty resourceVersion, or it would loop forever mistaking
// "exists but unversioned" for "does not exist".
func (e *ToolExecutor) getExecutionWindowSpec(ctx context.Context) (entries []storedWindowEntry, resourceVersion string, exists bool, err error) {
	obj, err := e.executionWindowResource().Get(ctx, executionWindowSingletonName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, "", false, nil
	}
	if err != nil {
		return nil, "", false, fmt.Errorf("get ExecutionWindow/%s: %w", executionWindowSingletonName, err)
	}
	raw, found, err := unstructured.NestedSlice(obj.Object, "spec", "windows")
	if err != nil {
		return nil, "", false, fmt.Errorf("read spec.windows: %w", err)
	}
	rv := obj.GetResourceVersion()
	if !found {
		return nil, rv, true, nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, "", false, fmt.Errorf("re-marshal spec.windows: %w", err)
	}
	if err := json.Unmarshal(b, &entries); err != nil {
		return nil, "", false, fmt.Errorf("decode spec.windows: %w", err)
	}
	return entries, rv, true, nil
}

// putExecutionWindowSpec creates the singleton (exists == false) or updates
// it (exists == true, using resourceVersion from the matching Get), setting
// spec.windows to exactly entries. Returns apierrors.IsConflict(err) == true
// when a concurrent writer beat this call to it — callers retry from a
// fresh Get, per this file's header comment on why that races safely.
func (e *ToolExecutor) putExecutionWindowSpec(ctx context.Context, entries []storedWindowEntry, resourceVersion string, exists bool) error {
	if entries == nil {
		entries = []storedWindowEntry{}
	}
	b, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("marshal spec.windows: %w", err)
	}
	var windowsAny []any
	if err := json.Unmarshal(b, &windowsAny); err != nil {
		return fmt.Errorf("decode spec.windows back to unstructured: %w", err)
	}

	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": executionWindowAPIVersion,
		"kind":       executionWindowKind,
		"metadata": map[string]any{
			"name": executionWindowSingletonName,
		},
		"spec": map[string]any{
			"windows": windowsAny,
		},
	}}

	if !exists {
		_, err := e.executionWindowResource().Create(ctx, obj, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			return apierrors.NewConflict(executionWindowGVR.GroupResource(), executionWindowSingletonName, fmt.Errorf("created concurrently"))
		}
		return err
	}
	obj.SetResourceVersion(resourceVersion)
	_, err = e.executionWindowResource().Update(ctx, obj, metav1.UpdateOptions{})
	return err
}

// maxExecutionWindowCASAttempts bounds the get-modify-update retry loop both
// tool handlers and the sweeper share. Contention on this one shared object
// is expected to be rare and short-lived (a handful of concurrent
// executions on one cluster at once, at most — this codebase's own
// blast-radius caps keep unattended volume far below anything that would
// make this loop the bottleneck), so a small bounded retry count is a
// correctness backstop, not a throughput mechanism.
const maxExecutionWindowCASAttempts = 8

// mutateExecutionWindow runs mutate against the current spec.windows and
// writes the result back, retrying on a resourceVersion conflict up to
// maxExecutionWindowCASAttempts times. mutate returns the new entries list
// and whether anything actually changed — putExecutionWindowSpec is skipped
// entirely when it did not, so closing a window nobody opened (or opening one
// that already exists) costs no write at all.
func (e *ToolExecutor) mutateExecutionWindow(ctx context.Context, mutate func([]storedWindowEntry) (next []storedWindowEntry, changed bool)) (next []storedWindowEntry, err error) {
	for attempt := 0; attempt < maxExecutionWindowCASAttempts; attempt++ {
		current, rv, exists, err := e.getExecutionWindowSpec(ctx)
		if err != nil {
			return nil, err
		}
		updated, changed := mutate(current)
		if !changed {
			return updated, nil
		}
		if err := e.putExecutionWindowSpec(ctx, updated, rv, exists); err != nil {
			if apierrors.IsConflict(err) {
				continue
			}
			return nil, err
		}
		return updated, nil
	}
	return nil, fmt.Errorf("gave up after %d attempts contending for the ExecutionWindow object", maxExecutionWindowCASAttempts)
}

// openExecutionWindow is the "open_execution_window" tool: adds (or, for a
// re-sent planId+fieldPath pair, replaces — making the open call idempotent)
// one entry per requested window, each stamped with THIS agent's own current
// time as OpenedAt.
func (e *ToolExecutor) openExecutionWindow(ctx context.Context, rawArgs json.RawMessage) (json.RawMessage, bool, error) {
	if !e.policyControllerReachable() {
		return nil, false, errPolicyControllerNotConfigured
	}
	var args struct {
		Windows []windowRequestEntry `json:"windows"`
	}
	if err := json.Unmarshal(rawArgs, &args); err != nil {
		return nil, false, fmt.Errorf("decode open_execution_window args: %w", err)
	}
	if len(args.Windows) == 0 {
		return nil, false, fmt.Errorf("open_execution_window requires at least one entry in windows")
	}
	for i, w := range args.Windows {
		if err := w.validate(); err != nil {
			return nil, false, fmt.Errorf("windows[%d]: %w", i, err)
		}
	}

	now := time.Now().UTC().Format(time.RFC3339)
	result, err := e.mutateExecutionWindow(ctx, func(current []storedWindowEntry) ([]storedWindowEntry, bool) {
		byKey := make(map[string]int, len(current))
		for i, entry := range current {
			byKey[entry.PlanID+"\x00"+entry.FieldPath] = i
		}
		next := append([]storedWindowEntry{}, current...)
		for _, w := range args.Windows {
			entry := storedWindowEntry{windowRequestEntry: w, OpenedAt: now}
			if i, exists := byKey[w.PlanID+"\x00"+w.FieldPath]; exists {
				next[i] = entry // idempotent re-open: refresh, don't duplicate
			} else {
				next = append(next, entry)
			}
		}
		return next, true
	})
	if err != nil {
		return nil, false, fmt.Errorf("open execution window: %w", err)
	}
	out, err := json.Marshal(map[string]any{"opened": len(args.Windows), "totalOpen": len(result)})
	if err != nil {
		return nil, false, err
	}
	return out, false, nil
}

// closeExecutionWindow is the "close_execution_window" tool: removes every
// entry tagged with the given planId. Idempotent and safe against a planId
// that never had a window (or already had it closed, or swept by TTL) —
// reports zero closed rather than an error, so
// internal/api/executionwindow.go's unconditional `defer` never needs to
// track whether opening actually succeeded.
func (e *ToolExecutor) closeExecutionWindow(ctx context.Context, rawArgs json.RawMessage) (json.RawMessage, bool, error) {
	if !e.policyControllerReachable() {
		return nil, false, errPolicyControllerNotConfigured
	}
	var args struct {
		PlanID string `json:"planId"`
	}
	if err := json.Unmarshal(rawArgs, &args); err != nil {
		return nil, false, fmt.Errorf("decode close_execution_window args: %w", err)
	}
	if args.PlanID == "" {
		return nil, false, fmt.Errorf("close_execution_window requires planId")
	}

	closed := 0
	_, err := e.mutateExecutionWindow(ctx, func(current []storedWindowEntry) ([]storedWindowEntry, bool) {
		next := make([]storedWindowEntry, 0, len(current))
		for _, w := range current {
			if w.PlanID == args.PlanID {
				closed++
				continue
			}
			next = append(next, w)
		}
		return next, closed > 0
	})
	if err != nil {
		return nil, false, fmt.Errorf("close execution window: %w", err)
	}
	out, err := json.Marshal(map[string]any{"closed": closed})
	if err != nil {
		return nil, false, err
	}
	return out, false, nil
}

// sweepStaleExecutionWindows removes every entry older than policyWindowTTL,
// relative to now, in one CAS round. Exported for tests (client_test.go
// exercises the crash-safety property end to end against a fake dynamic
// client) as a pure-ish, directly callable step, separate from the ticker
// loop below.
func (e *ToolExecutor) sweepStaleExecutionWindows(ctx context.Context, now time.Time) (removed int, err error) {
	if !e.policyControllerReachable() {
		return 0, nil
	}
	_, err = e.mutateExecutionWindow(ctx, func(current []storedWindowEntry) ([]storedWindowEntry, bool) {
		next := make([]storedWindowEntry, 0, len(current))
		for _, w := range current {
			if w.isStale(now) {
				removed++
				continue
			}
			next = append(next, w)
		}
		return next, removed > 0
	})
	return removed, err
}

// ensureExecutionWindowBootstrap is a fix for a real defect found live
// against a real kind API server (BACKLOG.md E4/F14, 2026-08-31), not a
// theoretical hardening. This chart's own executionwindow-crd.yaml used to
// document (and this file's header above still explains the REST of) a
// design that assumed the ExecutionWindow singleton could safely not exist
// at all until this cluster's first-ever widened execution — reasoning that
// validatingadmissionpolicy.yaml's matchConditions (username +
// "did this request actually touch the widened field") would keep any
// OTHER request from ever reaching paramRef resolution.
//
// That assumption is false on a real API server: a
// ValidatingAdmissionPolicyBinding with paramKind set and
// paramRef.parameterNotFoundAction: Deny resolves (or fails to resolve) its
// params for EVERY request matching the policy's matchConstraints (apps/v1
// deployments/statefulsets, UPDATE) BEFORE matchConditions are consulted —
// confirmed live, repeatably, against a real kind 1.34 cluster: with no
// ExecutionWindow object present, a plain `kubectl annotate deployment
// <any-deployment>` by an ordinary cluster-admin user — not argus-remediate,
// and not touching spec.progressDeadlineSeconds/spec.revisionHistoryLimit at
// all — was denied with "failed to configure binding: no params found for
// policy binding with `Deny` parameterNotFoundAction". That is a collateral
// denial of every ordinary Deployment/StatefulSet UPDATE on the WHOLE
// cluster, by any user, for any reason, for as long as the object doesn't
// exist — worse than the standing policy F14 replaces, not a narrower
// version of it, and it would fire on every cluster that ever enables
// policyController.enabled until its first-ever widened execution.
//
// The fix is making the object's steady state "exists, spec.windows == []"
// rather than "does not exist" — verified live immediately after manually
// creating it: the same kubectl annotate above succeeded again, and a real
// spec.progressDeadlineSeconds change with no open window was STILL
// correctly denied, by the validation clause itself rather than by a
// params-not-found configuration error. Doing this from a Helm chart
// template was tried and rejected: Helm cannot create an instance of a CRD
// in the same install/upgrade that also registers the CRD ("no matches for
// kind \"ExecutionWindow\"... ensure CRDs are installed first" — a
// well-known Helm limitation, confirmed live here too), and moving the CRD
// into the chart's special crds/ directory to sidestep that would stop the
// CRD being installable via `helm upgrade` at all — breaking the "opt in
// later on an already-installed release" model every other toggle in this
// chart (remediate, dryRun, policyController itself) already has. Doing it
// here instead — once, idempotently, at agent startup — works uniformly
// regardless of whether policyController was enabled on day one or turned
// on later via upgrade, and never touches the object's contents once it
// exists (see the exists-check below), so a real open window already in
// progress across an agent restart is never at risk of being reset.
//
// Retries because the CRD may not be Established yet at the exact instant
// this call runs — a fresh install applies the CRD and this Deployment in
// the same batch, and the API server needs a moment to register the new
// type before a dynamic-client Get/Create against it will succeed. Runs
// once per process lifetime, then returns; this is deliberately NOT folded
// into the sweeper below, which only ever edits an existing object's
// contents and must never be the thing that creates it (the sweeper runs
// forever on a timer; a one-time bootstrap belongs on its own bounded
// attempt budget, logged distinctly from an ordinary sweep tick).
func ensureExecutionWindowBootstrap(ctx context.Context, executor *ToolExecutor) {
	if !executor.policyControllerReachable() {
		return
	}
	const (
		bootstrapMaxAttempts = 12
		bootstrapRetryDelay  = 5 * time.Second
	)
	for attempt := 1; attempt <= bootstrapMaxAttempts; attempt++ {
		_, _, exists, err := executor.getExecutionWindowSpec(ctx)
		if err == nil {
			if exists {
				return // already there — a previous agent process, a previous chart revision, or a genuinely open window. Never overwrite.
			}
			if putErr := executor.putExecutionWindowSpec(ctx, nil, "", false); putErr != nil {
				if apierrors.IsAlreadyExists(putErr) || apierrors.IsConflict(putErr) {
					return // a concurrent writer (e.g. this agent restarting into a race with itself) created it first — fine, that's the same steady state.
				}
				logger.Warn("could not bootstrap the ExecutionWindow singleton",
					slog.String("name", executionWindowSingletonName), slog.Int("attempt", attempt), slog.Int("max_attempts", bootstrapMaxAttempts), logging.Err(putErr))
			} else {
				logger.Info("bootstrapped an empty ExecutionWindow object (without it, every Deployment/StatefulSet update on this cluster would be denied, not just argus-remediate's)",
					slog.String("name", executionWindowSingletonName))
				return
			}
		} else {
			logger.Warn("ExecutionWindow bootstrap check failed, likely the CRD is not Established yet",
				slog.String("name", executionWindowSingletonName), slog.Int("attempt", attempt), slog.Int("max_attempts", bootstrapMaxAttempts), logging.Err(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(bootstrapRetryDelay):
		}
	}
	logger.Error("giving up bootstrapping the ExecutionWindow singleton — argus-remediate cannot write spec.progressDeadlineSeconds/spec.revisionHistoryLimit, and no OTHER Deployment/StatefulSet update on this cluster will succeed either, until this object exists (create it manually: kubectl apply -f - with apiVersion: argus.io/v1, kind: ExecutionWindow, spec.windows: [])",
		slog.String("name", executionWindowSingletonName), slog.Int("attempts", bootstrapMaxAttempts))
}

// runExecutionWindowSweeper is BACKLOG.md F14's independent crash-safety
// backstop — see this file's header. Runs until ctx is cancelled; a no-op
// entirely (one log line, then return) when this agent has no
// argus-policy-controller credential, since there is then nothing to sweep
// and no cluster to ask.
func runExecutionWindowSweeper(ctx context.Context, executor *ToolExecutor) {
	if !executor.policyControllerReachable() {
		return
	}
	ticker := time.NewTicker(policyWindowSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			removed, err := executor.sweepStaleExecutionWindows(ctx, time.Now())
			if err != nil {
				logger.Warn("execution-window TTL sweep failed", logging.Err(err))
				continue
			}
			if removed > 0 {
				logger.Info("execution-window TTL sweep removed stale window(s) that the hub opened and never closed",
					slog.Int("removed", removed), slog.Duration("older_than", policyWindowTTL))
			}
		}
	}
}
