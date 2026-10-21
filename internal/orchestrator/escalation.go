package orchestrator

import (
	"fmt"
	"time"
)

// This file is BACKLOG.md T3's aging-escalation primitive: the widening
// re-notification schedule shared by mergewatch.go's stale-pull-request
// check and approvalwatch.go's stale-approval check. Before this, both
// halves of "a finished plan waits for someone to notice it" had the same
// gap — mergewatch.go's stale-PR branch notified exactly ONCE, at 48h, and
// never again no matter how much staler the pull request got; AwaitingApproval
// had no aging check at all, only the one-shot "you just transitioned here"
// notification db.go's notifiableStates already sends. See T3's BACKLOG.md
// entry and DESIGN.md §13.3 ("escalation on unattended incidents. An
// unapproved critical fix nobody saw is a product failure") for why a
// one-shot nudge that never repeats is not escalation.
//
// Deliberately a pure, database-free set of functions: both callers already
// have their own DB access and their own idea of "what does 'age' mean for
// this half" (a provider's PullRequestOutcome.CreatedAt vs. this incident's
// own timeline/remediation_recommendations rows) — this file only answers
// "given an age, which tier are we in, and what notify-key suffix names
// it", which is identical arithmetic for both.

// escalationTiers are the widening thresholds after which a stuck incident
// earns a fresh, more urgent notification. BACKLOG.md T3's own rough shape
// ("e.g. 48h, then 5 days, then weekly") is what these are — a documented,
// revisable default in the same spirit as mergeStalenessThreshold's own doc
// comment (DESIGN.md/lld/08 pin no number), not a measured one.
//
// The first entry IS mergeStalenessThreshold, not a second independent
// 48-hour constant, so the pre-existing stale-PR notification this task
// must not change keeps firing at exactly the age it always has — only
// incidents older than that ever reach a SECOND, widened notification that
// did not exist before.
var escalationTiers = []time.Duration{
	mergeStalenessThreshold, // 48h — unchanged first nudge
	5 * 24 * time.Hour,      // 5d — second, more urgent notice
	12 * 24 * time.Hour,     // 12d — third; weekly (escalationRepeatInterval) after this
}

// escalationRepeatInterval is the widening step applied forever past the
// last entry in escalationTiers — DESIGN.md §13.3 does not specify how long
// escalation continues, and T3's brief says "weekly thereafter": a plan or
// pull request that sits stuck for months must keep getting louder, not go
// quiet again once it outlives the last hand-written tier.
const escalationRepeatInterval = 7 * 24 * time.Hour

// escalationTier reports the current escalation tier for age, the time a
// condition (a stale pull request, an un-decided plan) has persisted:
//
//   - threshold is the tier boundary just crossed — the value
//     escalationTierLabel formats into the notify key's suffix.
//   - index is the tier's zero-based depth (0 = the first nudge, at
//     escalationTiers[0]; 1 = the second; 2+ = further widenings, whether
//     from escalationTiers or the repeating interval past it) — used only
//     to scale message urgency, see escalationUrgencyPrefix.
//   - ok is false when age has not crossed the first tier at all, which is
//     the ordinary case for nearly every incident nearly all the time: no
//     escalation, callers send nothing.
//
// Past the last explicit escalationTiers entry, this keeps stepping by
// escalationRepeatInterval for as long as age has crossed the next step —
// bounded by age itself, so even a years-old incident resolves in a
// handful of loop iterations, no separate cap needed.
func escalationTier(age time.Duration) (threshold time.Duration, index int, ok bool) {
	if age < escalationTiers[0] {
		return 0, 0, false
	}
	threshold = escalationTiers[0]
	for i, t := range escalationTiers {
		if age >= t {
			threshold = t
			index = i
		}
	}
	for threshold+escalationRepeatInterval <= age {
		threshold += escalationRepeatInterval
		index++
	}
	return threshold, index, true
}

// escalationTierLabel formats a tier threshold into the short, stable
// suffix a notify key carries — "48h", "5d", "12d", "19d", ... A tier's
// label is a pure function of its threshold, so the SAME tier reached twice
// (a sweep observing an unchanged age bucket on its next tick) always
// produces the SAME label, which is exactly what lets
// notify.NotifyTransition's own dedup guard (an unchanged key is a silent
// no-op) do its job — and a DIFFERENT tier always produces a DIFFERENT
// label, which is what lets it actually escalate instead of colliding with
// whatever tier came before.
func escalationTierLabel(threshold time.Duration) string {
	if threshold < 24*time.Hour {
		return fmt.Sprintf("%dh", int(threshold.Hours()))
	}
	return fmt.Sprintf("%dd", int(threshold.Hours()/24))
}

// escalationNotifyKey combines a caller-supplied, stable condition prefix
// (mergewatch.go's "AwaitingMerge:StalePR", approvalwatch.go's
// "AwaitingApproval:Stale") with the current tier's label into the exact
// key notify.NotifyTransition dedupes incident_notifications on. index is
// returned alongside for callers that want to scale a message's urgency
// (escalationUrgencyPrefix). ok is false — no key, nothing to send — when
// age has not crossed the first tier.
func escalationNotifyKey(prefix string, age time.Duration) (key string, index int, ok bool) {
	threshold, index, ok := escalationTier(age)
	if !ok {
		return "", 0, false
	}
	return prefix + ":" + escalationTierLabel(threshold), index, true
}

// escalationUrgencyPrefix scales a notification's opening words with tier
// depth, per T3's brief ("consider whether escalating tiers should say
// something different"): the first tier is the ordinary first nudge this
// mechanism already sent before this task (unchanged wording, no prefix);
// later tiers say plainly that this is a repeat, and that the wait has
// grown, rather than sending the identical sentence progressively later —
// DESIGN.md §13.3's "the most common way an alerting product fails is
// being ignored" applies exactly as much to a stale re-send that reads
// identically to the first one as it does to silence.
func escalationUrgencyPrefix(index int) string {
	switch {
	case index <= 0:
		return ""
	case index == 1:
		return "Second notice, more urgent: "
	default:
		return "Repeated notice — this has been stuck a long time: "
	}
}
