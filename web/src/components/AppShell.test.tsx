import { describe, expect, it, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

import {
  CAP_AUDIT_READ,
  CAP_CLUSTER_READ,
  CAP_CLUSTER_INSPECT,
  CAP_INCIDENT_READ,
  CAP_ANALYSIS_READ,
  CAP_INCIDENT_SILENCE,
  CAP_REMEDIATION_APPROVE,
  CAP_USER_READ,
} from '../api/capabilities'

// The nav half of "mark and explain, do not hide" (item 13b).
//
// Three properties, and the first is the one that gets broken by a refactor
// that looks like a tidy-up:
//
//  1. A destination the role cannot use is STILL IN THE DOM and still a link.
//     Removing it makes the feature indistinguishable from one that does not
//     exist, and removes a screen-reader user's only way to find out it does.
//  2. It is marked with a WORD, and the reason is readable — the padlock is
//     aria-hidden decoration beside the word, never the carrier of it.
//  3. Nothing is marked until the grants have actually arrived. Deny-by-default
//     is right for a control and wrong for a label: it would brand every
//     destination "No access" for the first paint of every load.

let resolved = true
const capabilities = new Set<string>()

vi.mock('../auth/useCapabilities', () => ({
  useHasCapability: (capability: string) => capabilities.has(capability),
  useMissingCapabilities: (caps: string[]) =>
    resolved ? { resolved: true, missing: caps.filter((c) => !capabilities.has(c)) } : { resolved: false, missing: [] },
}))

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({
    accessToken: 'test-token',
    email: 'operator@example.com',
    identityStatus: 'ready',
    authMethod: 'password',
    mustChangePassword: false,
    logout: () => {},
  }),
}))

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return { ...actual, getApprovals: () => Promise.resolve({ approvals: [] }) }
})

import { AppShell } from './AppShell'

// jsdom has no matchMedia, and the shell's theme toggle reads it on first
// render (src/theme.ts). Stubbed here rather than in src/test/setup.ts, which
// is deliberately minimal — see its own comment: a test that needs an ambient
// API sets it up itself and says why.
beforeEach(() => {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    configurable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
    }),
  })
})

function renderShell(path = '/overview') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <AppShell>
          <p>content</p>
        </AppShell>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

function navLink(name: RegExp | string) {
  return screen.getByRole('link', { name })
}

beforeEach(() => {
  resolved = true
  capabilities.clear()
})

describe('AppShell — nav access marking', () => {
  it('links to Recent Changes, the front door for undo', () => {
    capabilities.add(CAP_INCIDENT_READ)
    capabilities.add(CAP_ANALYSIS_READ)
    renderShell()
    expect(navLink(/Recent Changes/).getAttribute('href')).toBe('/changes')
  })

  it('MARKS a destination the role cannot use — it is never removed, and never unclickable', () => {
    // A viewer-shaped grant set: reads incidents and analyses, nothing else.
    capabilities.add(CAP_INCIDENT_READ)
    capabilities.add(CAP_ANALYSIS_READ)
    renderShell()

    const auditLog = navLink(/Audit Log/)
    // Still a real link to a real route.
    expect(auditLog.getAttribute('href')).toBe('/audit-log')
    // Marked with a word, not a colour and not a bare glyph.
    expect(auditLog.textContent).toMatch(/No access/)
    // And the reason names both what they cannot do and what to ask for.
    const reason = auditLog.getAttribute('title') ?? ''
    expect(reason).toMatch(/do not have permission/i)
    expect(reason).toMatch(/read the audit log/i)
    expect(reason).toContain(CAP_AUDIT_READ)
    // The same sentence is in the accessible name, so it is not hover-only.
    expect(auditLog.textContent).toContain(CAP_AUDIT_READ)
  })

  it('does not mark a destination the role can use', () => {
    capabilities.add(CAP_INCIDENT_READ)
    capabilities.add(CAP_ANALYSIS_READ)
    capabilities.add(CAP_CLUSTER_READ)
    capabilities.add(CAP_INCIDENT_SILENCE)
    capabilities.add(CAP_REMEDIATION_APPROVE)
    capabilities.add(CAP_AUDIT_READ)
    capabilities.add(CAP_USER_READ)
    capabilities.add(CAP_CLUSTER_INSPECT)
    renderShell()
    expect(screen.queryByText('No access')).toBeNull()
  })

  it('marks nothing while the grants are still loading', () => {
    // Nothing held, but nothing resolved either — "not known yet" must not
    // render as "not permitted".
    resolved = false
    renderShell()
    expect(screen.queryByText('No access')).toBeNull()
  })

  it('leaves Overview and Settings unmarked — neither is a single-capability dead end', () => {
    // No capabilities at all. Both of these degrade panel by panel and say so
    // in place, so a blanket rail marker would be a claim the nav cannot make.
    renderShell()
    expect(navLink(/Overview/).textContent).not.toMatch(/No access/)
    expect(navLink(/Settings/).textContent).not.toMatch(/No access/)
    // While the genuinely single-gated ones are all marked.
    expect(navLink(/Incidents/).textContent).toMatch(/No access/)
    expect(navLink(/Recent Changes/).textContent).toMatch(/No access/)
  })
})

describe('AppShell — the Incidents section', () => {
  it('has no sidebar rows for Signals or Tolerations — they are tabs of Incidents', () => {
    capabilities.add(CAP_INCIDENT_READ)
    renderShell()
    expect(screen.queryByRole('link', { name: /^Signals/ })).toBeNull()
    expect(screen.queryByRole('link', { name: /^Tolerations/ })).toBeNull()
  })

  it.each(['/signals', '/tolerations', '/incidents'])('keeps Incidents active on %s', (path) => {
    capabilities.add(CAP_INCIDENT_READ)
    capabilities.add(CAP_INCIDENT_SILENCE)
    renderShell(path)
    expect(navLink(/Incidents/).className).toContain('active')
  })
})

// Live QA 2026-10-11.
describe('AppShell — live QA fixes', () => {
  it('on a phone the nav is a closed menu behind the burger, which opens and closes it', () => {
    const original = window.matchMedia
    window.matchMedia = ((query: string) => ({
      matches: query.includes('max-width: 720px'),
      media: query,
      addEventListener: () => {},
      removeEventListener: () => {},
    })) as unknown as typeof window.matchMedia
    try {
      const { container } = renderShell()
      const shell = container.querySelector('.app-shell') as HTMLElement
      const toggle = screen.getByRole('button', { name: 'Open navigation' })
      expect(toggle.getAttribute('aria-expanded')).toBe('false')
      expect(shell.className).not.toContain('app-shell-phone-nav-open')
      fireEvent.click(toggle)
      expect(screen.getByRole('button', { name: 'Close navigation' }).getAttribute('aria-expanded')).toBe('true')
      expect(shell.className).toContain('app-shell-phone-nav-open')
      // Opening the phone menu never rewrites the stored desktop preference.
      expect(shell.className).not.toContain('app-shell-sidebar-collapsed')
    } finally {
      window.matchMedia = original
    }
  })

  it('marks a link the viewer cannot use so the "No access" chip can wrap instead of cutting the label', () => {
    renderShell()
    const approvals = navLink(/Approvals/)
    expect(approvals.className).toContain('app-nav-link-blocked')
    expect(approvals.querySelector('.app-nav-label')?.textContent).toBe('Approvals')
  })
})
