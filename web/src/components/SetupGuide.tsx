import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { getAIProviders, getClusters, getNotificationRouting, getSettings, getUsers, listPersonalTokens } from '../api/client'
import { CAP_CLUSTER_READ, CAP_MCP_USE, CAP_ORG_SETTINGS_WRITE, CAP_USER_READ } from '../api/capabilities'
import { useAuth } from '../auth/useAuth'
import { useHasCapability } from '../auth/useCapabilities'

// The setup guide (owner, 2026-10-14): the five things a new install needs
// before ARGUS is useful to a team, as a checklist behind a progress button in
// the top bar. Each step is read from the hub — a cluster that is Active, an
// active AI provider, a second user, a notification destination, an AI tool
// token — never ticked by hand, so the count cannot claim what is not true.
//
// Shown to people who can change organisation settings, because setting the
// install up is their job; it is guidance, not an action control, so the
// disabled-not-hidden rule for gated actions does not apply. It disappears
// once every step is done, and a person can put it away sooner. A step the
// viewer cannot read is "not checked", never "done" and never "not done".

type StepState = 'done' | 'todo' | 'unknown'

interface Step {
  key: string
  label: string
  hint: string
  to: string
  state: StepState
}

const DISMISS_KEY = 'argus.setupGuide.dismissed'

function readDismissed(): boolean {
  try {
    return localStorage.getItem(DISMISS_KEY) === '1'
  } catch {
    return false
  }
}

function state(enabled: boolean, loaded: boolean, done: boolean): StepState {
  if (!enabled || !loaded) return 'unknown'
  return done ? 'done' : 'todo'
}

export function useSetupSteps(enabled: boolean): Step[] {
  const { accessToken } = useAuth()
  const canClusters = useHasCapability(CAP_CLUSTER_READ)
  const canSettings = useHasCapability(CAP_ORG_SETTINGS_WRITE)
  const canUsers = useHasCapability(CAP_USER_READ)
  const canTokens = useHasCapability(CAP_MCP_USE)
  const on = (cap: boolean) => enabled && cap && !!accessToken
  const opts = { staleTime: 60_000, refetchOnWindowFocus: false }

  const clusters = useQuery({ queryKey: ['setup', 'clusters'], queryFn: () => getClusters(accessToken!), enabled: on(canClusters), ...opts })
  const providers = useQuery({ queryKey: ['setup', 'providers'], queryFn: () => getAIProviders(accessToken!), enabled: on(canSettings), ...opts })
  const users = useQuery({ queryKey: ['setup', 'users'], queryFn: () => getUsers(accessToken!), enabled: on(canUsers), ...opts })
  const routing = useQuery({ queryKey: ['setup', 'routing'], queryFn: () => getNotificationRouting(accessToken!), enabled: on(canSettings), ...opts })
  const settings = useQuery({ queryKey: ['setup', 'settings'], queryFn: () => getSettings(accessToken!), enabled: on(canSettings), ...opts })
  const tokens = useQuery({ queryKey: ['setup', 'tokens'], queryFn: () => listPersonalTokens(accessToken!), enabled: on(canTokens), ...opts })

  return [
    {
      key: 'cluster',
      label: 'Enrol your first cluster',
      hint: 'An agent enrolled, accepted and reporting.',
      to: '/clusters',
      state: state(canClusters, !!clusters.data, (clusters.data?.clusters ?? []).some((c) => c.state === 'Active')),
    },
    {
      key: 'ai',
      label: 'Choose an AI provider',
      hint: 'Without one, incidents are found but never investigated.',
      to: '/settings?section=providers',
      state: state(canSettings, !!providers.data, !!providers.data?.activeProviderId),
    },
    {
      key: 'team',
      label: 'Add someone who can approve',
      hint: 'A second person, so a fix never waits on one inbox.',
      to: '/users',
      state: state(canUsers, !!users.data, (users.data?.users ?? []).length > 1),
    },
    {
      key: 'notify',
      label: 'Route new incidents somewhere',
      hint: 'A webhook or a routed destination for new incidents.',
      to: '/settings?section=notifications',
      state: state(
        canSettings,
        !!routing.data && !!settings.data,
        !!settings.data?.notify.webhookConfigured || (routing.data?.destinations ?? []).length > 0,
      ),
    },
    {
      key: 'mcp',
      label: 'Give your AI tools access',
      hint: 'A token for Claude Code, Cursor or another MCP client.',
      to: '/settings?section=ai-tools',
      state: state(canTokens, !!tokens.data, (tokens.data?.tokens ?? []).length > 0),
    },
  ]
}

const MARK: Record<StepState, string> = { done: 'Done', todo: 'To do', unknown: 'Not checked' }

export function SetupGuide() {
  const canSetUp = useHasCapability(CAP_ORG_SETTINGS_WRITE)
  const [dismissed, setDismissed] = useState(readDismissed)
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  const steps = useSetupSteps(canSetUp && !dismissed)

  useEffect(() => {
    if (!open) return
    const outside = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false)
    }
    const escape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', outside)
    document.addEventListener('keydown', escape)
    return () => {
      document.removeEventListener('mousedown', outside)
      document.removeEventListener('keydown', escape)
    }
  }, [open])

  if (!canSetUp || dismissed) return null
  const done = steps.filter((s) => s.state === 'done').length
  // Nothing is shown until every step has an answer, so the count never
  // starts at a fabricated 0 and climbs as queries land.
  if (steps.some((s) => s.state === 'unknown' && s.key !== 'team' && s.key !== 'mcp')) return null
  if (done === steps.length) return null

  const dismiss = () => {
    try {
      localStorage.setItem(DISMISS_KEY, '1')
    } catch {
      // A blocked store only means the guide comes back next visit.
    }
    setDismissed(true)
  }

  return (
    <div className="setup-guide" ref={ref}>
      <button
        type="button"
        className="secondary setup-guide-trigger"
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-label={`Getting ARGUS ready, ${done} of ${steps.length} done`}
        onClick={() => setOpen((o) => !o)}
      >
        <svg viewBox="0 0 20 20" width="18" height="18" aria-hidden="true" className="setup-guide-ring">
          <circle cx="10" cy="10" r="8" className="setup-guide-ring-track" />
          <circle
            cx="10"
            cy="10"
            r="8"
            className="setup-guide-ring-fill"
            strokeDasharray={`${(done / steps.length) * 50.27} 50.27`}
            transform="rotate(-90 10 10)"
          />
        </svg>
        <span>
          Ready {done}/{steps.length}
        </span>
      </button>
      {open && (
        <div className="setup-guide-popover" role="dialog" aria-label="Getting ARGUS ready">
          <div className="setup-guide-head">
            <strong>Getting ARGUS ready</strong>
            <span className="text-muted">
              {done} of {steps.length} done
            </span>
          </div>
          <ol className="setup-guide-steps">
            {steps.map((s) => (
              <li key={s.key} data-state={s.state}>
                <span className="setup-guide-check" aria-hidden="true">
                  {s.state === 'done' && (
                    <svg viewBox="0 0 12 12" width="10" height="10" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M2.5 6.2 5 8.5l4.5-5" />
                    </svg>
                  )}
                </span>
                <span className="setup-guide-step">
                  {s.state === 'done' ? (
                    <span className="setup-guide-label">{s.label}</span>
                  ) : (
                    <Link to={s.to} className="setup-guide-label" onClick={() => setOpen(false)}>
                      {s.label}
                    </Link>
                  )}
                  <span className="setup-guide-hint">{s.hint}</span>
                </span>
                <span className="visually-hidden">, {MARK[s.state]}</span>
                {s.state === 'unknown' && <span className="badge badge-gray">Not checked</span>}
              </li>
            ))}
          </ol>
          <button type="button" className="link-button setup-guide-dismiss" onClick={dismiss}>
            Hide this checklist
          </button>
        </div>
      )}
    </div>
  )
}
