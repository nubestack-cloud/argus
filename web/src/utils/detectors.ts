// The detector catalogue — one list, shared by every screen that names a
// detector. Previously this lived as a private `DETECTOR_OPTIONS` const in
// SettingsPage.tsx and nowhere else, so the incident screen rendered raw ids
// (`detector k8s-sweep`) while Settings rendered curated labels for the same
// three values. Two label maps for one closed set of ids is the drift this
// module exists to prevent; SettingsPage now imports DETECTOR_OPTIONS from
// here rather than declaring its own.
//
// Distinct from `utils/detection.ts`, which is about detection *timing* (how
// long a sweep takes to notice a fault). This module is about detection
// *provenance* (which detector saw it, and what that implies).
//
// Must exactly match internal/api/settings.go's knownDetectorIDs (and, one
// layer further down, internal/agent/detector.go's warningEventsDetectorID /
// pod_conditions_detector.go's podConditionsDetectorID /
// sweep_detector.go's sweepDetectorID) — there is no way to fetch this list
// from the API instead: it is a hand-maintained, cross-referenced constant on
// the Go side too. An id this module has never heard of therefore has to
// render as *itself*, with no claim attached — see detectionSourceFor.

// Which of the two things a finding actually is, from the operator's point of
// view — the distinction the product's value rests on and the UI did not make:
//
//   'kubernetesEvent' — ARGUS forwarded a Warning-type Kubernetes Event. The
//                       cluster announced this itself; the operator's own
//                       tooling can see the same event.
//   'argusCheck'      — ARGUS read object state and concluded something was
//                       wrong. No Kubernetes event was required for it to be
//                       seen, and internal/agent/sweep_detector.go's own doc
//                       comment is explicit that these conditions "don't
//                       reliably announce themselves as either a Warning-type
//                       Event ... or a Pod status transition".
//
// Deliberately two values, not three. The reader's decision here is binary —
// "was this already in the event stream I can grep?" — and the finer
// three-way split between the detectors is carried by `shortLabel`/`sentence`
// below, in words, rather than by a third colour that encodes nothing extra.
import type { DetectorStatus } from '../api/types'

export type DetectionSourceKind = 'kubernetesEvent' | 'argusCheck'

export interface DetectorInfo {
  id: string
  /** The Settings checkbox label. Unchanged from SettingsPage's original map. */
  label: string
  /** The Settings checkbox description. Unchanged from SettingsPage's original map. */
  description: string
  sourceKind: DetectionSourceKind
  /** Two or three words, for an inline metadata line beside other facts. */
  shortLabel: string
  /**
   * What this detector's provenance means for the reader, as a sentence about
   * the finding it is rendered next to. Hedged exactly as far as the agent-side
   * code is: the sweep detector claims these conditions do not *reliably*
   * announce themselves as events, not that no event can ever exist, and this
   * copy must not overstate that into "kubectl would never have shown you this".
   */
  sentence: string
}

// The Operations area's detector checkboxes, rendered in this fixed order —
// which is also the order any other consumer should present them in.
export const DETECTOR_OPTIONS: DetectorInfo[] = [
  {
    id: 'k8s-warning-events',
    label: 'Warning Kubernetes Events',
    description: 'Every Warning-type Kubernetes Event, cluster-wide.',
    sourceKind: 'kubernetesEvent',
    shortLabel: 'Kubernetes Warning event',
    sentence:
      'Forwarded from the cluster’s own Warning event stream — the same event ' +
      '`kubectl get events` shows, for as long as Kubernetes retains it.',
  },
  {
    id: 'k8s-pod-conditions',
    label: 'Pod status conditions',
    description:
      'CrashLoopBackOff, ImagePullBackOff/ErrImagePull, OOMKilled, and pods stuck Pending.',
    sourceKind: 'argusCheck',
    shortLabel: 'Pod status check',
    sentence:
      'Read by ARGUS from the Pod’s own status, which does not depend on the cluster ' +
      'having emitted a matching Warning event.',
  },
  {
    id: 'k8s-sweep',
    label: 'Sweep detector (sustained conditions)',
    description:
      'Periodic checks for conditions that outlast a single event: replica shortfalls, wedged PVCs, failed Jobs, NotReady/pressured nodes, blocked autoscalers, and Services with no ready endpoints.',
    sourceKind: 'argusCheck',
    shortLabel: 'ARGUS sweep',
    sentence:
      'Found by ARGUS’s periodic sweep of object state — a sustained condition that does ' +
      'not reliably announce itself as a Kubernetes event.',
  },
]

const BY_ID = new Map(DETECTOR_OPTIONS.map((d) => [d.id, d]))

/**
 * The catalogue entry for a detector id, or null for an id this bundle has
 * never heard of — a hub newer than this build, or one of the `test-detector`/
 * `smoketest-detector` fixture ids that exist in real databases.
 *
 * Null means "no wording for it, so no claim about it": callers render the raw
 * id and say nothing about whether an event backed it. Defaulting an unknown
 * detector into either bucket would be a fabricated fact about how ARGUS found
 * something, which is exactly the claim this feature exists to make truthfully.
 */
export function detectionSourceFor(detectorId: string): DetectorInfo | null {
  return BY_ID.get(detectorId) ?? null
}

/**
 * The short, human name for an inline metadata line, falling back to the raw
 * id for an unrecognised detector.
 */
export function detectorShortLabel(detectorId: string): string {
  return BY_ID.get(detectorId)?.shortLabel ?? detectorId
}

/**
 * Which detection sources are present among a set of findings — used to say
 * "this incident carries findings from more than one source" rather than
 * labelling a whole incident with one badge.
 *
 * Presence only, deliberately never a count or a share. The `findings` array
 * on GET /incidents/{id} is a bounded slice (the newest few per reason), so a
 * count derived from it would be a partial wearing the costume of a total.
 * Presence of a second kind is a POSITIVE claim about rows that are actually
 * there, which stays true however much of the history was trimmed — whereas
 * "this incident is sweep-only" is an absence claim the slice cannot support.
 * Unknown detector ids contribute nothing, for the same reason as above.
 */
export function detectionSourceKinds(detectorIds: readonly string[]): Set<DetectionSourceKind> {
  const kinds = new Set<DetectionSourceKind>()
  for (const id of detectorIds) {
    const info = BY_ID.get(id)
    if (info) kinds.add(info.sourceKind)
  }
  return kinds
}

export type DetectorRunLevel = 'running' | 'degraded' | 'blocked' | 'error' | 'unobserved'

// classifyDetectorStatus turns one detector's own reported facts into
// exactly one of five states, in this priority order, so a reader never has
// to weigh two true-at-once signals themselves:
//
//   blocked    -> deniedReads is non-empty. Shown regardless of how recently
//                 this detector last succeeded: a currently-denied read is
//                 true right now and directly actionable (grant the RBAC),
//                 independent of history.
//   error      -> a reported error whose own timestamp is strictly after the
//                 last success (or there has never been a success at all) —
//                 this detector's most recent attempt did not go well.
//   degraded   -> the last pass RAN and completed, but timedOutChecks names
//                 checks that did not answer inside it. The detector is
//                 alive and still reporting; that much of its most recent
//                 pass is simply missing.
//   running    -> a real, timestamped success at least as recent as any
//                 reported error, with nothing timed out.
//   unobserved -> nothing at all: no success, no error, no denied read. A
//                 brand new agent that hasn't completed a first pass yet —
//                 not a claim that anything is wrong.
//
// WHY THE ERROR COMPARISON IS STRICT, AND WHY THE TIE IS THE INTERESTING
// CASE. This used to read `errorAt >= successAt`, which was right when Error
// was the only place a timeout could be recorded, and wrong the moment
// tunnel.DetectorStatus.TimedOutChecks existed. A timed-out sweep pass takes
// internal/agent's recordCheckerTimeout path, which writes BOTH the prefixed
// error text (for a hub predating the field) AND, via recordSuccess, the
// pass's own success — at the same instant. So errorAt === successAt is not
// a coincidence to break arbitrarily: it is the signature of a pass that
// completed with a check hanging, and `>=` classified every one of them as a
// flat "Error". A genuine failure never produces that tie, because
// recordError does not advance lastSuccessAt at all.
//
// Hence: strictly-newer error wins outright (matching the hub's own ordering
// in internal/api/diagnostics.go — a read refused outright is the more
// actionable of the two when one pass produced both), the tie goes to
// degraded when the named field is there to explain it, and the tie still
// goes to Error when it is not, so an older agent that can only report the
// timeout through Error keeps saying something rather than silently reading
// as healthy.
//
// Deliberately never computed from this cluster's incident/finding counts —
// an empty findings table is exactly as consistent with "detector healthy,
// nothing to report" as with "detector broken, seeing nothing because it
// isn't running". Distinguishing those two is PROJECT.md T13's whole point,
// and only this detector's own reported facts can do it.
export function classifyDetectorStatus(status: DetectorStatus | undefined): DetectorRunLevel {
  if (!status) {
    return 'unobserved'
  }
  if (status.deniedReads && status.deniedReads.length > 0) {
    return 'blocked'
  }
  const timedOut = status.timedOutChecks ?? []
  const successAt = status.lastSuccessAt ? new Date(status.lastSuccessAt).getTime() : null
  const errorAt = status.error ? (status.errorAt ? new Date(status.errorAt).getTime() : 0) : null
  if (
    errorAt !== null &&
    (successAt === null || errorAt > successAt || (errorAt === successAt && timedOut.length === 0))
  ) {
    return 'error'
  }
  if (timedOut.length > 0) {
    return 'degraded'
  }
  if (successAt !== null) {
    return 'running'
  }
  return 'unobserved'
}
