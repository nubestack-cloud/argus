// The lifecycle spine and the "whose move is it" line — the two rows between
// the incident's identity and its argument (incident lifecycle redesign,
// 2026-10-12). Markup only: every fact comes from phaseModel
// (pages/incidentPhases.ts), which reads the existing stage functions.
import type { ReactNode } from 'react'
import type { NowLine, Outcome, Phase, PhaseKey } from '../incidentPhases'
import { formatDateTime, formatRelativeTime } from '../../utils/time'
import { ChipMark } from '../../components/icons'

const STATUS_WORD: Record<Phase['status'], string> = {
  done: 'done',
  current: 'current',
  next: 'not reached',
  skipped: 'skipped',
  failed: 'did not complete',
}

// The node's mark. Never the only carrier of the status: the phase's detail
// line and the visually-hidden status word say it in text.
function mark(p: Phase, n: number): ReactNode {
  if (p.status === 'done') return <ChipMark mark="granted" />
  if (p.status === 'failed') return '!'
  if (p.status === 'skipped') return ''
  return String(n)
}

// `targets`: the id of each phase's card when that card is on the page. A
// phase name is a real link to it (PROJECT.md #12: a plain href the browser
// follows, never an intercepted click); a phase with no card is plain text.
export function LifecycleSpine({ phases, outcome, targets = {} }: { phases: Phase[]; outcome: Outcome; targets?: Partial<Record<PhaseKey, string>> }) {
  return (
    <ol className="lc-spine" aria-label="Incident lifecycle">
      {phases.map((p, i) => {
        const next = phases[i + 1]
        return (
          <li key={p.key} className={`lc-phase lc-${p.status}${next?.status === 'skipped' ? ' lc-before-skip' : ''}`}>
            <div className="lc-track">
              <span className="lc-node" aria-hidden="true">{mark(p, i + 1)}</span>
              <span className="lc-seg" aria-hidden="true">
                {next?.took && <span className="lc-took">{next.took}</span>}
              </span>
            </div>
            <p className="lc-name">
              {targets[p.key] ? <a href={`#${targets[p.key]}`}>{p.name}</a> : p.name}
              {p.routeLabel && <span className="lc-route">{p.routeLabel}</span>}
              <span className="visually-hidden"> — {STATUS_WORD[p.status]}</span>
            </p>
            <p className="lc-detail">{p.detail}</p>
            {p.pips && (
              <p className="lc-pips">
                {p.pips.map((pip, j) => (
                  <span key={pip.label} className="lc-pip-wrap">
                    {j > 0 && <span className="lc-pip-arrow" aria-hidden="true">→</span>}
                    <span className={`lc-pip lc-pip-${pip.status}`}>
                      {pip.label}
                      <span className="visually-hidden"> ({pip.status === 'next' ? 'not reached' : pip.status})</span>
                    </span>
                  </span>
                ))}
              </p>
            )}
            {(p.waiting || p.at) && (
              <p className="lc-when">
                {p.waiting ? (
                  <>waiting {p.waiting}</>
                ) : (
                  <span title={formatDateTime(p.at!)}>{formatRelativeTime(p.at!)}</span>
                )}
              </p>
            )}
          </li>
        )
      })}
      <li className="lc-outcome">
        <p className="lc-name">Outcome</p>
        <span className={`lc-endcap lc-endcap-${outcome.tone}`}>{outcome.label}</span>
      </li>
    </ol>
  )
}

export function NowLineBar({ now, children }: { now: NowLine; children?: ReactNode }) {
  return (
    <div className={`lc-now lc-now-${now.tone}`} role="status">
      <span className="lc-now-who">{now.who}</span>
      <span className="lc-now-what">{now.what}</span>
      {children}
      {now.target && (
        <a className="lc-now-go" href={`#${now.target}`}>
          {now.target === 'incident-fix' ? 'Go to the fix' : now.target === 'incident-why' ? 'Go to the diagnosis' : 'Go to the watch'}
          <span aria-hidden="true"> ↓</span>
        </a>
      )}
    </div>
  )
}
