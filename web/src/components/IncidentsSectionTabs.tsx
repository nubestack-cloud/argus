import { NavLink } from 'react-router-dom'
import { missingCapabilityMessage } from '../api/capabilityInfo'
import { useMissingCapabilities } from '../auth/useCapabilities'
import { NAV_REQUIRED_CAPABILITIES } from './navCapabilities'

// Incidents, Signals and Tolerations are one section: what ARGUS raised,
// everything it recorded (including what the evidence boundary kept as an
// observation), and the conditions someone said to expect. They share the
// Incidents nav item and this strip rather than taking three sidebar rows.
//
// These are page links, not an ARIA tablist: each view is its own route with
// its own URL and history entry, so NavLink marks the current one
// aria-current="page". A view the viewer lacks the capability for is marked
// the way the sidebar marks it (AppShell's ShellNavLink): still a real link,
// with the words "No access" and the reason in the title and accessible name
// — never hidden, never unclickable.
const VIEWS: Array<{ to: string; label: string }> = [
  { to: '/incidents', label: 'Incidents' },
  { to: '/signals', label: 'Signals' },
  { to: '/tolerations', label: 'Tolerations' },
]

function SectionTab({ to, label }: { to: string; label: string }) {
  const { resolved, missing } = useMissingCapabilities(NAV_REQUIRED_CAPABILITIES[to] ?? [])
  const reason = resolved && missing.length > 0 ? missingCapabilityMessage(missing) : undefined
  return (
    <NavLink to={to} end className="tabs-tab tabs-tab-link" title={reason}>
      {label}
      {reason && (
        <>
          <span className="tabs-tab-note"> · No access</span>
          <span className="visually-hidden"> — {reason}</span>
        </>
      )}
    </NavLink>
  )
}

export function IncidentsSectionTabs() {
  return (
    <nav className="tabs-bar section-tabs" aria-label="Incident views">
      <div className="tabs">
        {VIEWS.map((v) => (
          <SectionTab key={v.to} {...v} />
        ))}
      </div>
    </nav>
  )
}
