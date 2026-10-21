import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { CAP_INCIDENT_READ, CAP_INCIDENT_SILENCE } from '../api/capabilities'

const capabilities = new Set<string>()
vi.mock('../auth/useCapabilities', () => ({
  useMissingCapabilities: (caps: string[]) => ({ resolved: true, missing: caps.filter((c) => !capabilities.has(c)) }),
}))

import { IncidentsSectionTabs } from './IncidentsSectionTabs'

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <IncidentsSectionTabs />
    </MemoryRouter>,
  )
}

beforeEach(() => capabilities.clear())

describe('IncidentsSectionTabs', () => {
  it('links the three views and marks the current one', () => {
    capabilities.add(CAP_INCIDENT_READ)
    capabilities.add(CAP_INCIDENT_SILENCE)
    renderAt('/signals')
    expect(screen.getByRole('navigation', { name: 'Incident views' })).toBeTruthy()
    expect(screen.getByRole('link', { name: 'Incidents' }).getAttribute('href')).toBe('/incidents')
    expect(screen.getByRole('link', { name: 'Signals' }).getAttribute('aria-current')).toBe('page')
    expect(screen.getByRole('link', { name: 'Incidents' }).getAttribute('aria-current')).toBeNull()
    expect(screen.queryByText(/No access/)).toBeNull()
  })

  it('marks a view the role cannot open in words, and keeps it a link', () => {
    capabilities.add(CAP_INCIDENT_READ)
    renderAt('/incidents')
    const tolerations = screen.getByRole('link', { name: /Tolerations/ })
    expect(tolerations.getAttribute('href')).toBe('/tolerations')
    expect(tolerations.textContent).toMatch(/No access/)
    expect(tolerations.getAttribute('title') ?? '').toContain(CAP_INCIDENT_SILENCE)
  })
})
