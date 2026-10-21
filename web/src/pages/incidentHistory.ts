// The incident's timeline as milestones for HistoryRail — see that
// component's header for why runs collapse. Pure, so it is unit-tested alone.
import type { TimelineEvent } from '../api/types'

export type Tone = 'detect' | 'argus' | 'person' | 'good' | 'bad'

export interface Milestone {
  title: string
  detail?: string
  tone: Tone
  from: string
  to: string
  count: number
}

const INVESTIGATION_RESULT = new Set(['AnalysisCompleted', 'RecommendationReady', 'NoActionableNextStep', 'AnalysisFailed', 'AutoAnalysisFailed', 'ParamsCorrectionAttempted'])

const SINGLE: Record<string, { title: string; tone: Tone }> = {
  IncidentOpened: { title: 'Detected', tone: 'detect' },
  ApprovalGranted: { title: 'Approved', tone: 'person' },
  ApprovalRejected: { title: 'Fix rejected', tone: 'person' },
  PullRequestOpened: { title: 'Pull request opened', tone: 'argus' },
  PullRequestProposalFailed: { title: 'Pull request not opened', tone: 'bad' },
  PullRequestMerged: { title: 'Pull request merged', tone: 'good' },
  PullRequestClosed: { title: 'Pull request closed unmerged', tone: 'bad' },
  ExecutionStarted: { title: 'Fix started', tone: 'argus' },
  ExecutionOutcome: { title: 'Fix ran', tone: 'argus' },
  ValidationOutcome: { title: 'Watch ended', tone: 'argus' },
  IncidentResolved: { title: 'Resolved', tone: 'good' },
  IncidentSelfHealed: { title: 'Self-healed', tone: 'good' },
  IncidentDismissed: { title: 'Dismissed', tone: 'person' },
  IncidentExpired: { title: 'Expired', tone: 'person' },
  IncidentRecurredAfterExpiry: { title: 'Recurred', tone: 'bad' },
  AnalysisFailed: { title: 'Investigation failed', tone: 'bad' },
  AutoAnalysisFailed: { title: 'Automatic investigation failed', tone: 'bad' },
}

export function milestonesFrom(events: TimelineEvent[]): Milestone[] {
  const out: Milestone[] = []
  for (let i = 0; i < events.length; i++) {
    const e = events[i]
    if (e.eventType === 'InvestigationStarted') {
      // Fold the run's own results into it: everything up to the next start or
      // the next non-result event.
      let j = i + 1
      let result: TimelineEvent | undefined
      let failed = false
      while (j < events.length && INVESTIGATION_RESULT.has(events[j].eventType)) {
        if (events[j].eventType === 'AnalysisFailed' || events[j].eventType === 'AutoAnalysisFailed') failed = true
        // The recommendation, when one was made, names the outcome better
        // than the analysis summary (which is often the gate's reasoning).
        if (!result || events[j].eventType === 'RecommendationReady') result = events[j]
        j++
      }
      const end = events[j - 1]
      const detail = failed ? 'failed' : result?.summary ?? 'no result recorded'
      const prev = out[out.length - 1]
      if (prev && prev.title.startsWith('Investigated') && prev.detail === detail) {
        prev.count += 1
        prev.to = end.occurredAt
        prev.title = `Investigated ${prev.count}×`
      } else {
        out.push({ title: 'Investigated', detail, tone: failed ? 'bad' : 'argus', from: e.occurredAt, to: end.occurredAt, count: 1 })
      }
      i = j - 1
      continue
    }
    const known = SINGLE[e.eventType]
    out.push({
      title: known?.title ?? e.eventType.replace(/([a-z])([A-Z])/g, '$1 $2'),
      detail: e.summary,
      tone: known?.tone ?? 'argus',
      from: e.occurredAt,
      to: e.occurredAt,
      count: 1,
    })
  }
  return out
}

