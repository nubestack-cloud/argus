// Package helmstatus reports a Helm release's revision history and what its
// most recent operation did, from Secret metadata alone. Helm stores each
// revision as a Secret named sh.helm.release.v1.<release>.v<N> whose labels
// carry the revision number, its status and its timestamps; the payload
// (values, manifests, the revision description, chart and app version) is
// never read. Everything that would need the payload is therefore either
// absent from the analysis or stated as not known.
package helmstatus

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"
)

// OperationKind is what happened.
type OperationKind string

const (
	KindReleaseFailed     OperationKind = "release_failed" // the install (revision 1) failed
	KindUpgradeFailed     OperationKind = "upgrade_failed" // a later revision failed
	KindFailureSuperseded OperationKind = "failure_superseded"
	KindPending           OperationKind = "pending"
)

// OperationStatus is where that left the release.
type OperationStatus string

const (
	StatusFailed    OperationStatus = "failed"
	StatusRecovered OperationStatus = "recovered"
	StatusStuck     OperationStatus = "stuck_pending"
)

// Confidence is how sure the reading is from metadata alone: high for what a
// status label says outright, low where the deciding fact is in the payload.
type Confidence string

const (
	ConfidenceHigh Confidence = "high"
	ConfidenceLow  Confidence = "low"
)

// Source is which revision an operation was read from: the current one, or
// the history before it.
type Source string

const (
	SourceStatus  Source = "helm_status"
	SourceHistory Source = "helm_history"
)

// DefaultPendingStuckAfter is how long a pending-* revision may sit before
// it is called stuck: three times Helm's own five-minute operation timeout,
// well past any rollout that is merely slow.
const DefaultPendingStuckAfter = 15 * time.Minute

// Revision is one Helm release revision as seen from its Secret's metadata.
// Chart and AppVersion live in the payload and are left empty by the
// metadata reader; they are carried for callers that have them some other way.
type Revision struct {
	Revision int    `json:"revision"`
	Status   string `json:"status"`
	// Updated is the latest of CreatedAt and Helm's timestamp labels: when
	// this revision last changed, as far as metadata can tell.
	Updated time.Time `json:"updated,omitzero"`
	// CreatedAt is the release Secret's metadata.creationTimestamp — when
	// the revision was made.
	CreatedAt time.Time `json:"createdAt,omitzero"`
	// ModifiedAt is Helm's own modifiedAt label, verbatim. Helm does not
	// keep it per revision reliably (every revision of a release can carry
	// the same value), so it is shown as Helm's label, never as the
	// revision's date.
	ModifiedAt time.Time `json:"modifiedAt,omitzero"`
	Chart      string    `json:"chart,omitempty"`
	AppVersion string    `json:"appVersion,omitempty"`
}

// Operation is one thing worth telling about a release. Revision is set for
// a failure or a stuck operation; FailedRevision and RecoveredRevision for a
// failure the next revision deployed over.
type Operation struct {
	Kind              OperationKind   `json:"kind"`
	Status            OperationStatus `json:"status"`
	Source            Source          `json:"source"`
	Confidence        Confidence      `json:"confidence"`
	Message           string          `json:"message"`
	Evidence          string          `json:"evidence,omitempty"`
	Revision          int             `json:"revision,omitempty"`
	FailedRevision    int             `json:"failedRevision,omitempty"`
	RecoveredRevision int             `json:"recoveredRevision,omitempty"`
	PendingStatus     string          `json:"pendingStatus,omitempty"`
	Updated           time.Time       `json:"updated,omitzero"`
}

// Options tunes Analyze; zero values take the defaults (and Now the clock).
type Options struct {
	PendingStuckAfter time.Duration
	MaxOperations     int
	Now               time.Time
}

// Analysis is Analyze's answer.
type Analysis struct {
	LastOperation *Operation  `json:"lastOperation,omitempty"`
	Operations    []Operation `json:"operations,omitempty"`
}

// Analyze picks out the operations in a release's history worth showing: an
// install or upgrade that failed, a failure the very next revision deployed
// over, and a pending operation that has stopped moving. Newest first, at
// most opts.MaxOperations when that is set. currentRevision is the release's
// latest revision; 0 means the highest one given.
//
// LastOperation is set only when the current revision is itself the story —
// it failed, it is stuck pending, or it is the revision that deployed over a
// failure. A healthy upgrade after that clears it, though the history keeps
// the failure.
func Analyze(releaseName string, currentRevision int, revisions []Revision, opts Options) Analysis {
	if len(revisions) == 0 {
		return Analysis{}
	}
	stuckAfter := opts.PendingStuckAfter
	if stuckAfter <= 0 {
		stuckAfter = DefaultPendingStuckAfter
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	revs := slices.SortedFunc(slices.Values(revisions), func(a, b Revision) int { return cmp.Compare(a.Revision, b.Revision) })

	var ops []Operation
	for i := 0; i < len(revs); i++ {
		if status(revs[i]) != "failed" {
			continue
		}
		if i+1 < len(revs) && revs[i+1].Revision == revs[i].Revision+1 && settled(status(revs[i+1])) {
			ops = append(ops, recovered(revs[i], revs[i+1]))
			i++ // the recovering revision is accounted for
			continue
		}
		ops = append(ops, failed(releaseName, revs[i], SourceHistory))
	}

	// The current revision: the one asked for, or simply the newest.
	var cur *Revision
	for i := len(revs) - 1; i >= 0; i-- {
		if currentRevision <= 0 || revs[i].Revision == currentRevision {
			cur = &revs[i]
			break
		}
	}
	var live *Operation
	if cur != nil {
		age := now.Sub(cur.Updated)
		switch st := status(*cur); {
		case st == "failed":
			op := failed(releaseName, *cur, SourceStatus)
			live = &op
			// The history pass saw this revision too; report it once, as live.
			ops = slices.DeleteFunc(ops, func(o Operation) bool { return o.Status == StatusFailed && o.Revision == cur.Revision })
		case isPending(st) && !cur.Updated.IsZero() && age >= stuckAfter:
			op := stuck(*cur, age)
			live = &op
		}
	}

	slices.SortStableFunc(ops, func(a, b Operation) int { return cmp.Compare(anchor(b), anchor(a)) })
	if n := opts.MaxOperations; n > 0 && len(ops) > n {
		ops = ops[:n]
	}

	out := Analysis{LastOperation: live, Operations: ops}
	if live == nil && cur != nil {
		for _, op := range ops {
			if op.Kind == KindFailureSuperseded && op.RecoveredRevision == cur.Revision {
				out.LastOperation = &op
				break
			}
		}
	}
	return out
}

// verb names what a revision was: the first is the install, any later one an
// upgrade (or, now and then, a rollback — only the unread description says).
func verb(revision int) string {
	if revision <= 1 {
		return "install"
	}
	return "upgrade"
}

// recovered is a failed revision with a successful one straight after it.
// Whether the successor was `helm rollback` (or --atomic) or a fixed upgrade
// is written only in the revision description, which is payload and never
// read, so the message leaves it open and confidence is low.
func recovered(bad, next Revision) Operation {
	return Operation{
		Kind: KindFailureSuperseded, Status: StatusRecovered, Source: SourceHistory, Confidence: ConfidenceLow,
		Message: fmt.Sprintf("The %s at revision %d failed and revision %d deployed after it — a rollback or a fixed upgrade; Helm records which only in the revision description, which is not read, so which is unknown.",
			verb(bad.Revision), bad.Revision, next.Revision),
		Evidence:       fmt.Sprintf("revision %d failed; revision %d is %s", bad.Revision, next.Revision, status(next)),
		FailedRevision: bad.Revision, RecoveredRevision: next.Revision,
		Updated: next.Updated,
	}
}

// failed is a failed revision, seen in the history or as the current one.
func failed(release string, rev Revision, from Source) Operation {
	kind := KindUpgradeFailed
	if rev.Revision <= 1 {
		kind = KindReleaseFailed
	}
	msg := fmt.Sprintf("The %s at revision %d failed.", verb(rev.Revision), rev.Revision)
	if release = strings.TrimSpace(release); release != "" {
		msg = fmt.Sprintf("Helm release %q: %s", release, msg)
	}
	evidence := "a failed revision in the Helm history"
	if from == SourceStatus {
		evidence = "the current Helm revision is failed"
	}
	return Operation{
		Kind: kind, Status: StatusFailed, Source: from, Confidence: ConfidenceHigh,
		Message: msg, Evidence: evidence, Revision: rev.Revision, Updated: rev.Updated,
	}
}

// stuck is a current revision that has sat in a pending state too long.
func stuck(rev Revision, age time.Duration) Operation {
	st := status(rev)
	return Operation{
		Kind: KindPending, Status: StatusStuck, Source: SourceStatus, Confidence: ConfidenceHigh,
		Message:  fmt.Sprintf("Stuck in %s for %s.", st, roughly(age)),
		Evidence: "the current Helm revision has not left " + st,
		Revision: rev.Revision, PendingStatus: st, Updated: rev.Updated,
	}
}

// anchor is the revision an operation is filed under: the one that
// recovered, else its own, else the one that failed.
func anchor(op Operation) int {
	return cmp.Or(op.RecoveredRevision, op.Revision, op.FailedRevision)
}

func status(r Revision) string { return strings.ToLower(strings.TrimSpace(r.Status)) }

// settled is a revision Helm finished: the live one, or one replaced since.
func settled(st string) bool { return st == "deployed" || st == "superseded" }

// IsPending reports whether a Helm status is one of the pending-* states.
func IsPending(st string) bool { return isPending(strings.ToLower(strings.TrimSpace(st))) }

func isPending(st string) bool {
	switch st {
	case "pending-install", "pending-upgrade", "pending-rollback":
		return true
	}
	return false
}

// roughly is a duration in whole minutes under an hour and whole hours
// beyond, never less than one of either.
func roughly(d time.Duration) string {
	if d < time.Hour {
		return fmt.Sprintf("%dm", max(1, int(d.Round(time.Minute)/time.Minute)))
	}
	return fmt.Sprintf("%dh", max(1, int(d.Round(time.Hour)/time.Hour)))
}
