import { describe, expect, it } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import type { Incident } from '../api/types'
import { ClusterIncidentsTab } from './ClusterIncidentsTab'

const inc = (id: string, over: Partial<Incident> = {}): Incident =>
  ({
    id,
    clusterId: 'cl_1',
    clusterDisplayName: 'rke2',
    fingerprint: id,
    severity: 'critical',
    state: 'Detected',
    firstSeen: '2026-10-07T10:00:00Z',
    lastSeen: '2026-10-10T10:00:00Z',
    occurrenceCount: 2,
    objectGvk: 'v1/Pod',
    objectNamespace: 'nebula',
    objectName: id,
    openingReason: 'Unhealthy',
    ...over,
  }) as Incident

const list = [
  inc('nebula-api-1'),
  inc('nebula-bff-2'),
  inc('nebula-ops-3'),
  inc('openbao', { severity: 'medium', state: 'NeedsHumanInvestigation', objectGvk: 'apps/v1/StatefulSet', objectNamespace: 'nebula-openbao' }),
  inc('old', { state: 'Resolved', resolvedAt: new Date().toISOString() }),
]

function renderTab() {
  return render(
    <MemoryRouter>
      <ClusterIncidentsTab clusterId="cl_1" incidents={list} loading={false} error={null} truncated={false} />
    </MemoryRouter>,
  )
}

describe('Cluster incidents tab', () => {
  it('charts the open set by severity and by stage, as words with counts', () => {
    renderTab()
    expect(screen.getByRole('img', { name: 'Open incidents by severity: 3 critical, 0 high, 1 medium' })).toBeTruthy()
    expect(screen.getByRole('img', { name: 'Open incidents by stage: 3 detected, not investigated, 1 needs a person' })).toBeTruthy()
  })

  it('groups look-alike incidents into one row that expands, and can be ungrouped', () => {
    renderTab()
    const toggle = screen.getByRole('button', { name: /3 Pods/ })
    expect(screen.getAllByRole('row')).toHaveLength(1 + 2)
    fireEvent.click(toggle)
    expect(screen.getAllByRole('row')).toHaveLength(1 + 2 + 3)
    fireEvent.click(screen.getByRole('button', { name: 'Group look-alikes' }))
    expect(screen.getAllByRole('row')).toHaveLength(1 + 4)
  })

  it('shows open by default, and closed ones on request', () => {
    renderTab()
    expect(screen.queryByText('old')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: /^Closed in 7d/ }))
    const table = screen.getByRole('table')
    expect(within(table).getByText('old')).toBeTruthy()
  })
})
