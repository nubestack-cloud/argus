// The incident's history as milestones, for the side rail (incident lifecycle
// redesign, 2026-10-12). GET .../timeline returns every event; an incident
// investigated eight times returns 24 near-identical rows. Here an
// investigation and the events it produced are ONE milestone, and runs that
// reached the same outcome back to back collapse into "Investigated 8×" with
// their date range. The time between milestones is drawn, because how long an
// incident sat in each phase is the part of "what happened" a list of events
// never said. The full, uncollapsed timeline stays one click away below.
import type { ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getIncidentTimeline } from '../../api/client'
import { useAuth } from '../../auth/useAuth'
import { SkeletonLines } from '../../components/Skeleton'
import { compactDuration, formatDateTime } from '../../utils/time'
import { milestonesFrom, type Milestone } from '../incidentHistory'

function when(m: Milestone): string {
  const a = formatDateTime(m.from)
  if (m.from === m.to) return a
  return `${a} – ${formatDateTime(m.to)}`
}

export function HistoryRail({ incidentId, children }: { incidentId: string; children?: ReactNode }) {
  const { accessToken } = useAuth()
  // The same query key WhatHappenedDisclosure uses, so opening the full
  // timeline below reuses this response rather than fetching it again.
  const q = useQuery({
    queryKey: ['incidents', incidentId, 'timeline'],
    queryFn: () => getIncidentTimeline(incidentId, accessToken!),
    enabled: !!accessToken,
    staleTime: 30_000,
  })
  const milestones = milestonesFrom(q.data?.events ?? [])
  return (
    <section className="card lc-rail-card" aria-labelledby="incident-history-h">
      <div className="lc-card-head">
        <h2 id="incident-history-h">History</h2>
        <span className="field-hint">time between steps</span>
      </div>
      {q.isLoading ? (
        <SkeletonLines count={4} />
      ) : q.isError ? (
        <p className="form-error" role="alert">Could not load this incident's history.</p>
      ) : milestones.length === 0 ? (
        <p className="field-hint">No history recorded — this incident predates the timeline.</p>
      ) : (
        <ol className="lc-hist">
          {milestones.map((m, i) => {
            const gap = i > 0 ? compactDuration(milestones[i - 1].to, m.from) : null
            return (
              <li key={`${m.from}-${i}`} className={`lc-hist-item lc-hist-${m.tone}`}>
                {gap && <span className="lc-hist-gap">{gap} later</span>}
                <span className="lc-hist-dot" aria-hidden="true" />
                <span className="lc-hist-body">
                  <strong>{m.title}</strong>
                  {m.detail && <span className="lc-hist-detail">{m.detail}</span>}
                  <span className="lc-hist-time">{when(m)}</span>
                </span>
              </li>
            )
          })}
        </ol>
      )}
      {children}
    </section>
  )
}
