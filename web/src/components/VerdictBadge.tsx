// The closed verdict vocabulary for checks and scans (docs/CLUSTER_INSIGHT_SPECS.md
// CI-U2). "We could not check" is Incomplete — never Passed — and every
// verdict is a word; the colour only repeats it.
export type Verdict = 'passed' | 'review' | 'warning' | 'blocked' | 'incomplete' | 'notApplicable'

const LABEL: Record<Verdict, { text: string; tone: string }> = {
  passed: { text: 'Passed', tone: 'badge-green' },
  review: { text: 'Review', tone: 'badge-blue' },
  warning: { text: 'Warning', tone: 'badge-amber' },
  blocked: { text: 'Blocked', tone: 'badge-red' },
  incomplete: { text: 'Incomplete', tone: 'badge-gray' },
  notApplicable: { text: 'Not applicable', tone: 'badge-gray' },
}

// toVerdict maps the agent's wire statuses (several analyses use slightly
// different words for the same thing) onto the closed set. Anything
// unrecognised is Incomplete: an unknown status must not render as a pass.
export function toVerdict(status: string | undefined | null): Verdict {
  switch ((status ?? '').toLowerCase()) {
    case 'passed':
    case 'pass':
    case 'ok':
    case 'healthy':
    case 'no_known_blockers':
    case 'safe':
      return 'passed'
    case 'review':
      return 'review'
    case 'warning':
    case 'warn':
    case 'degraded':
    case 'atrisk':
    case 'at_risk':
      return 'warning'
    case 'blocked':
    case 'blocker':
    case 'broken':
    case 'failed':
    case 'danger':
      return 'blocked'
    case 'not_applicable':
    case 'notapplicable':
      return 'notApplicable'
    default:
      return 'incomplete'
  }
}

export function verdictLabel(v: Verdict): string {
  return LABEL[v].text
}

export function VerdictBadge({ verdict, reason }: { verdict: Verdict; reason?: string }) {
  const l = LABEL[verdict]
  return (
    <span className={`badge ${l.tone}`} title={reason}>
      {l.text}
      {reason && <span className="visually-hidden">: {reason}</span>}
    </span>
  )
}
