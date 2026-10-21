import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ClusterTimeline as Timeline, TimelineMark, TimelineRow } from '../api/types'

// PROJECT.md AD1 — the cluster Timeline against a fixture shaped like the
// live rke2 hub's own data (a Deployment whose ReplicaSet and Pod changed in
// one second while a critical incident was open; a sweep finding re-reported
// every ten minutes; a dismissed CronJob incident; a lost-history gap).

const mockTimeline = vi.fn()
vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return { ...actual, getClusterTimeline: (...a: unknown[]) => mockTimeline(...a) }
})
vi.mock('../auth/useAuth', () => ({ useAuth: () => ({ accessToken: 't' }) }))

import { ApiError } from '../api/client'
import { ClusterTimeline } from './ClusterTimeline'
import { axisTicks, binMarks, binTotal, clampTipLine, describeMark, incidentLeads, leadSummary, markTime, placeSpans, rowIncidentSummary } from './timelineModel'

const UNTIL = '2026-10-11T09:36:00Z'
const SINCE = '2026-10-11T03:36:00Z'

const mark = (m: Partial<TimelineMark> & Pick<TimelineMark, 'at' | 'type' | 'id'>): TimelineMark => ({ summary: '', ...m })

function edgeRow(): TimelineRow {
  return {
    key: 'argus-gitops-rke2/Deployment/edge',
    kind: 'Deployment',
    apiGroup: 'apps',
    namespace: 'argus-gitops-rke2',
    name: 'edge',
    marks: [
      mark({ at: '2026-10-11T06:32:10Z', type: 'change', id: 'chg_1', op: 'update', summary: 'ready: 2→1, Available: True→False', object: { kind: 'Deployment', apiGroup: 'apps', namespace: 'argus-gitops-rke2', name: 'edge' } }),
      mark({ at: '2026-10-11T06:32:10Z', type: 'change', id: 'chg_2', op: 'update', summary: 'restarts: 1069→1070', object: { kind: 'Pod', namespace: 'argus-gitops-rke2', name: 'edge-5d7f66b8d9-klpp9' } }),
      mark({ at: '2026-10-11T06:32:11Z', type: 'change', id: 'chg_3', op: 'update', summary: 'ready: 1→2', object: { kind: 'ReplicaSet', apiGroup: 'apps', namespace: 'argus-gitops-rke2', name: 'edge-5d7f66b8d9' } }),
      mark({ at: '2026-10-11T08:00:00Z', type: 'change', id: 'chg_4', op: 'update', summary: 'image edge:1 → edge:2', object: { kind: 'Deployment', apiGroup: 'apps', namespace: 'argus-gitops-rke2', name: 'edge' } }),
    ],
    spans: [{ incidentId: 'inc_edge', from: '2026-10-07T13:28:58Z', to: null, severity: 'critical', state: 'Detected', summary: 'CrashLoopBackOff', object: { kind: 'Pod', namespace: 'argus-gitops-rke2', name: 'edge-5d7f66b8d9-klpp9' } }],
    counts: { changes: 4, findingRuns: 0, findingReports: 0, incidents: 1, incidentsOpened: 0, incidentsClosed: 0 },
    marksOmitted: 0,
    spansOmitted: 0,
    markBucketSeconds: 0,
    lastActivityAt: '2026-10-11T08:00:00Z',
  }
}

function jobRow(): TimelineRow {
  return {
    key: 'argus-system/CronJob/argus-hub-argus-hub-postgres-backup',
    kind: 'CronJob',
    apiGroup: 'batch',
    namespace: 'argus-system',
    name: 'argus-hub-argus-hub-postgres-backup',
    marks: [
      mark({ at: '2026-10-11T08:21:00Z', type: 'finding', id: 'fp_job', severity: 'medium', reason: 'JobMissingActiveDeadlineSeconds', summary: 'JobMissingActiveDeadlineSeconds: no activeDeadlineSeconds', detectorId: 'k8s-sweep', until: '2026-10-11T09:31:00Z', reports: 8, object: { kind: 'Job', apiGroup: 'batch', namespace: 'argus-system', name: 'argus-hub-argus-hub-postgres-backup-29331' } }),
      mark({ at: '2026-10-11T08:21:38Z', type: 'incident-opened', id: 'inc_job', incidentId: 'inc_job', severity: 'medium', state: 'Dismissed', summary: 'opened: UnexpectedJob' }),
    ],
    spans: [{ incidentId: 'inc_job', from: '2026-10-11T08:21:38Z', to: '2026-10-11T08:22:59Z', severity: 'medium', state: 'Dismissed', summary: 'UnexpectedJob' }],
    counts: { changes: 0, findingRuns: 1, findingReports: 8, incidents: 1, incidentsOpened: 1, incidentsClosed: 1 },
    marksOmitted: 0,
    spansOmitted: 0,
    markBucketSeconds: 0,
    lastActivityAt: '2026-10-11T09:31:00Z',
  }
}

function timeline(over: Partial<Timeline> = {}): Timeline {
  return {
    clusterId: 'cl_1',
    since: SINCE,
    until: UNTIL,
    types: ['changes', 'findings', 'incidents'],
    onlyIncidents: false,
    rows: [edgeRow(), jobRow()],
    gaps: [{ from: '2026-10-11T05:00:00Z', to: '2026-10-11T05:05:00Z', reason: 'agent buffer overflow' }],
    namespaces: ['argus-gitops-rke2', 'argus-system'],
    totals: { rows: 84, changes: 339, findingRuns: 59, findingReports: 1656, incidents: 73, incidentsOpened: 30 },
    truncated: { rows: 82, changes: 0, findingRuns: 0, incidents: 0 },
    limits: { maxRows: 60, maxMarksPerRow: 60, maxSpansPerRow: 8 },
    findingRunGapSeconds: 2700,
    restricted: [],
    ...over,
  }
}

function Where() {
  const l = useLocation()
  return <p data-testid="where">{l.pathname + l.search}</p>
}

function wrap(url = '/clusters/cl_1?tab=timeline') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[url]}>
        <Routes>
          <Route path="/clusters/:id" element={<ClusterTimeline clusterId="cl_1" />} />
          <Route path="*" element={null} />
        </Routes>
        <Where />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const widthSpy = { value: 1100 }
beforeEach(() => {
  vi.clearAllMocks()
  widthSpy.value = 1100
  vi.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockImplementation(function (this: HTMLElement) {
    return this.classList.contains('tl-track') ? 760 : widthSpy.value
  })
})
afterEach(() => vi.restoreAllMocks())

describe('ClusterTimeline', () => {
  it('draws rows with the incident in words, totals from the hub, and every caveat', async () => {
    mockTimeline.mockResolvedValue(timeline())
    wrap()
    expect(await screen.findByRole('button', { name: 'Open Deployment edge' })).toBeTruthy()
    // Severity is a word beside the colour, in the label column.
    expect(screen.getByText('Critical · open')).toBeTruthy()
    expect(screen.getByText('Medium · Dismissed')).toBeTruthy()
    // Totals are the hub's, not the drawn rows'.
    expect(screen.getByText(/339 changes, 59 findings \(1,656 reports\), 73 incidents/)).toBeTruthy()
    expect(screen.getByText(/across 84 objects/)).toBeTruthy()
    expect(screen.getByText('84 objects · showing 2 most active')).toBeTruthy()
    // Each source chip carries the hub's own total.
    expect(screen.getByRole('button', { name: /Changes\s*339/ })).toBeTruthy()
    expect(screen.getByRole('button', { name: /Findings\s*59/ })).toBeTruthy()
    // The whole-cluster strip sits above the rows.
    expect(screen.getByRole('img', { name: /^Activity over the window: \d+ drawn events/ })).toBeTruthy()
    expect(screen.getByText(/Change history is incomplete from .* \(agent buffer overflow\)/)).toBeTruthy()
    // The default window is 6h and goes to the hub as since/until.
    const [cluster, q] = mockTimeline.mock.calls[0] as [string, { since: string; until: string; types: string[] }]
    expect(cluster).toBe('cl_1')
    expect(Date.parse(q.until) - Date.parse(q.since)).toBe(6 * 3600_000)
    expect(q.types).toEqual(['changes', 'findings', 'incidents'])
  })

  it('names a source the caller may not read instead of drawing it empty', async () => {
    mockTimeline.mockResolvedValue(timeline({ types: ['changes'], restricted: [{ source: 'findings', capability: 'incident:read' }, { source: 'incidents', capability: 'incident:read' }] }))
    wrap()
    expect(await screen.findByText(/Findings are not shown: reading them needs/)).toBeTruthy()
    expect(screen.getByText(/Incidents are not shown/)).toBeTruthy()
  })

  it('sends every filter to the hub rather than filtering the page', async () => {
    mockTimeline.mockResolvedValue(timeline())
    wrap()
    await screen.findByRole('button', { name: 'Open Deployment edge' })
    fireEvent.click(screen.getByRole('button', { name: /^Findings/ }))
    await waitFor(() => expect(mockTimeline.mock.calls.at(-1)?.[1]).toMatchObject({ types: ['changes', 'incidents'] }))
    fireEvent.change(screen.getByLabelText('Namespace'), { target: { value: 'argus-system' } })
    await waitFor(() => expect(mockTimeline.mock.calls.at(-1)?.[1]).toMatchObject({ namespace: 'argus-system' }))
    fireEvent.click(screen.getByRole('button', { name: /Only with an incident/ }))
    await waitFor(() => expect(mockTimeline.mock.calls.at(-1)?.[1]).toMatchObject({ onlyIncidents: true }))
    fireEvent.click(screen.getByRole('button', { name: '24h' }))
    await waitFor(() => {
      const q = mockTimeline.mock.calls.at(-1)?.[1] as { since: string; until: string }
      expect(Date.parse(q.until) - Date.parse(q.since)).toBe(24 * 3600_000)
    })
    expect(screen.getByTestId('where').textContent).toContain('tlw=24h')
  })

  it('keeps one source on: the last checked type cannot be unchecked', async () => {
    mockTimeline.mockResolvedValue(timeline())
    wrap('/clusters/cl_1?tab=timeline&tlhide=findings,incidents')
    await screen.findByRole('button', { name: 'Open Deployment edge' })
    expect((screen.getByRole('button', { name: /^Changes/ }) as HTMLButtonElement).disabled).toBe(true)
  })

  it('opens a single mark’s object, an incident band’s incident, and lists a bin', async () => {
    mockTimeline.mockResolvedValue(timeline())
    wrap()
    const track = await screen.findByRole('group', { name: 'Events on Deployment/edge' })
    // The rollout second: three changes too close to draw apart, one bin.
    const bin = within(track).getByRole('button', { name: /^3 events:/ })
    expect(bin.textContent).toContain('3')
    fireEvent.click(bin)
    const region = await screen.findByRole('region', { name: '3 events on Deployment/edge' })
    expect(within(region).getByText(/restarts: 1069→1070/)).toBeTruthy()
    fireEvent.click(within(region).getByRole('button', { name: 'Open Pod/edge-5d7f66b8d9-klpp9' }))
    expect(screen.getByTestId('where').textContent).toContain('panel=obj%3Acl_1%3A%2FPod%3Aargus-gitops-rke2%2Fedge-5d7f66b8d9-klpp9')

    fireEvent.click(within(track).getByRole('button', { name: /image edge:1 → edge:2\. Open\./ }))
    expect(screen.getByTestId('where').textContent).toContain('panel=obj%3Acl_1%3Aapps%2FDeployment')

    fireEvent.click(within(track).getByRole('button', { name: /Critical incident: CrashLoopBackOff/ }))
    expect(screen.getByTestId('where').textContent).toBe('/incidents/inc_edge')
  })

  // Owner QA 2026-10-11: a count badge's list had no way onward when its
  // events were the row's own, Esc did not close it, and a tooltip carried
  // whole multi-line findings.
  it('lists a bin with a way onward, closes it on Escape and returns focus to the mark', async () => {
    mockTimeline.mockResolvedValue(timeline())
    wrap()
    const track = await screen.findByRole('group', { name: 'Events on Deployment/edge' })
    const bin = within(track).getByRole('button', { name: /^3 events:/ })
    fireEvent.click(bin)
    const region = await screen.findByRole('region', { name: '3 events on Deployment/edge' })
    expect(within(region).getByRole('button', { name: 'Open Deployment/edge' })).toBeTruthy()
    fireEvent.keyDown(region, { key: 'Escape' })
    await waitFor(() => expect(screen.queryByRole('region', { name: '3 events on Deployment/edge' })).toBeNull())
    expect(document.activeElement).toBe(bin)
  })

  it('cuts a tooltip line to a glance', () => {
    const wall = 'Back-off restarting failed container app in pod edge-5d7f66b8d9-klpp9_argus-gitops-rke2(0b1c) '.repeat(4)
    const cut = clampTipLine(wall)
    expect(cut.cut).toBe(true)
    expect(cut.text.length).toBeLessThanOrEqual(141)
    expect(cut.text.endsWith('…')).toBe(true)
    expect(clampTipLine('Changed image edge:1 → edge:2')).toEqual({ text: 'Changed image edge:1 → edge:2', cut: false })
  })

  it('moves between a row’s events with the arrow keys', async () => {
    mockTimeline.mockResolvedValue(timeline())
    wrap()
    const track = await screen.findByRole('group', { name: 'Events on Deployment/edge' })
    const items = within(track).getAllByRole('button')
    // Roving focus: one tab stop per row.
    expect(items.filter((b) => b.tabIndex === 0)).toHaveLength(1)
    act(() => items[0].focus())
    fireEvent.keyDown(items[0], { key: 'ArrowRight' })
    expect(document.activeElement).toBe(items[1])
    fireEvent.keyDown(items[1], { key: 'End' })
    expect(document.activeElement).toBe(items[items.length - 1])
    fireEvent.keyDown(document.activeElement!, { key: 'ArrowDown' })
    const next = screen.getByRole('group', { name: /Events on CronJob/ })
    expect(next.contains(document.activeElement)).toBe(true)
  })

  it('says nothing was recorded, and distinguishes a filter that matched nothing', async () => {
    mockTimeline.mockResolvedValue(timeline({ rows: [], gaps: [], totals: { rows: 0, changes: 0, findingRuns: 0, findingReports: 0, incidents: 0, incidentsOpened: 0 }, truncated: { rows: 0, changes: 0, findingRuns: 0, incidents: 0 } }))
    wrap()
    expect(await screen.findByText(/No recorded activity in the last 6 hours/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Look at the last 7 days' }))
    expect(screen.getByTestId('where').textContent).toContain('tlw=7d')
  })

  it('offers to clear filters when they matched nothing', async () => {
    mockTimeline.mockResolvedValue(timeline({ rows: [], namespace: 'quiet', totals: { rows: 0, changes: 0, findingRuns: 0, findingReports: 0, incidents: 0, incidentsOpened: 0 }, truncated: { rows: 0, changes: 0, findingRuns: 0, incidents: 0 } }))
    wrap('/clusters/cl_1?tab=timeline&tlns=quiet')
    expect(await screen.findByText(/Nothing matches these filters/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }))
    await waitFor(() => expect(screen.getByTestId('where').textContent).not.toContain('tlns'))
  })

  it('renders the problem the hub returned', async () => {
    mockTimeline.mockRejectedValue(new ApiError('Missing required capability', 403, 'this requires capability "cluster:read" on cluster cl_1'))
    wrap()
    expect((await screen.findByRole('alert')).textContent).toContain('cluster:read')
  })

  it('degrades to a list of events at phone width', async () => {
    widthSpy.value = 360
    mockTimeline.mockResolvedValue(timeline())
    wrap()
    const list = await screen.findByRole('list', { name: /Objects, those with an incident first/ })
    expect(within(list).getAllByText(/restarts: 1069→1070/).length).toBe(1)
    expect(within(list).getByText(/reported 8× until/)).toBeTruthy()
    expect(screen.queryByRole('group', { name: /Events on/ })).toBeNull()
  })
})

describe('timelineModel', () => {
  const start = Date.parse(SINCE)
  const end = Date.parse(UNTIL)

  it('scales the axis to the width', () => {
    const narrow = axisTicks(start, end, 300)
    const wide = axisTicks(start, end, 1100)
    expect(wide.length).toBeGreaterThan(narrow.length)
    for (const t of wide) expect(t.x).toBeGreaterThanOrEqual(0)
  })

  it('bins marks that would overprint and counts thinned events', () => {
    const row = edgeRow()
    const bins = binMarks(row.marks, start, end, 760)
    expect(bins.map((b) => b.marks.length)).toEqual([3, 1])
    const thinned = { ...row.marks[3], more: 11 }
    expect(binTotal({ ...bins[1], marks: [thinned] })).toBe(12)
    expect(describeMark(thinned, { ...row, markBucketSeconds: 2880 }, 6 * 3600_000)).toMatch(/and 11 earlier changes in the 48 min before/)
  })

  it('stacks overlapping incidents into lanes', () => {
    const r = edgeRow()
    const { placed, lanes } = placeSpans([...r.spans, { ...r.spans[0], incidentId: 'inc_2', from: '2026-10-11T07:00:00Z' }], start, end)
    expect(lanes).toBe(2)
    expect(placed[0].startsBefore).toBe(true)
    expect(placed[0].open).toBe(true)
  })

  it('words the worst open incident, and keeps the date on an old time', () => {
    expect(rowIncidentSummary(edgeRow())?.text).toBe('Critical · open')
    // Every band's severity is named in the label, not only the worst one's.
    const two = edgeRow()
    two.spans.push({ incidentId: 'inc_m', from: '2026-10-11T07:00:00Z', to: '2026-10-11T07:01:00Z', severity: 'medium', state: 'Resolved', summary: 'OOMKilled' })
    two.counts.incidents = 2
    expect(rowIncidentSummary(two)?.text).toBe('Critical · open, Medium · Resolved')
    expect(markTime('2026-10-07T13:28:58Z', 3600_000, end)).toMatch(/7/)
  })

  it('leads with incidents opened in the window and what changed in the half hour before each', () => {
    const rows = [edgeRow(), jobRow()]
    const { leads, earlier } = incidentLeads(rows, Date.parse(SINCE), false)
    // The edge incident opened days before the window: counted, not led with.
    expect(earlier).toBe(1)
    expect(leads).toHaveLength(1)
    const [l] = leads
    expect(l.span.incidentId).toBe('inc_job')
    expect(l.ownFindings).toBe(1)
    expect(l.ownChanges).toBe(0)
    // edge's 08:00 image change is 21 min before the 08:21:38 opening; its
    // 06:32 changes are not.
    expect(l.nearby.map((n) => [n.row.name, n.changes])).toEqual([['edge', 1]])
    expect(l.atLeast).toBe(false)
    // Truncated changes make every count a lower bound.
    expect(incidentLeads(rows, Date.parse(SINCE), true).leads[0].atLeast).toBe(true)
  })
})

describe('leadSummary', () => {
  it('adds up to the header total from the hub\'s exact counts', () => {
    expect(leadSummary({ windowLabel: 'last 24 hours', total: 75, openedTotal: 22, leadsDrawn: 5, earlierDrawn: 17 })).toEqual({
      heading: '22 incidents opened in the last 24 hours',
      meta: '53 more were already open when it began — 75 open at some point in it.',
      drawnNote: 'Listed: the 5 drawn below. The other 17 are on objects the timeline left out — narrow by namespace to see them.',
    })
    expect(leadSummary({ windowLabel: 'last hour', total: 3, openedTotal: 0, leadsDrawn: 0, earlierDrawn: 3 })).toEqual({
      heading: 'No incident opened in the last hour',
      meta: '3 incidents were already open when it began.',
      drawnNote: null,
    })
  })

  it('names drawn-only counts as such when the hub predates incidentsOpened', () => {
    const s = leadSummary({ windowLabel: 'last 24 hours', total: 75, openedTotal: undefined, leadsDrawn: 5, earlierDrawn: 17 })
    expect(s.heading).toBe('5 incidents on the objects drawn opened in the last 24 hours')
    expect(s.meta).toBe('17 more on them were already open when it began.')
    expect(s.drawnNote).toBe('The other 53 incidents open in it are on objects not drawn.')
  })
})

describe('ClusterTimeline incident lead', () => {
  it('names the incident, what preceded it, and brings a row into view', async () => {
    mockTimeline.mockResolvedValue(timeline())
    wrap()
    const lead = await screen.findByRole('region', { name: 'Incidents opened in this window' })
    // The lead's counts add up to the header's 73: 30 opened in the window +
    // 43 already open; only 1 of the 30 is on the objects drawn.
    expect(within(lead).getByRole('heading', { name: '30 incidents opened in the last 6 hours' })).toBeTruthy()
    expect(within(lead).getByText('43 more were already open when it began — 73 open at some point in it.')).toBeTruthy()
    expect(within(lead).getByText(/Listed: the 1 drawn below. The other 29 are on objects the timeline left out/)).toBeTruthy()
    expect(within(lead).getByText(/Medium incident/)).toBeTruthy()
    // The hub drew 2 of 84 objects, so what happened elsewhere is a lower bound.
    expect(lead.textContent).toContain('Before it opened: ≥ 1 finding on it; elsewhere Deployment/edge (≥ 1 change).')
    expect(within(lead).getByRole('link', { name: /Open the incident/ }).getAttribute('href')).toBe('/incidents/inc_job')
    const scroll = vi.fn()
    Element.prototype.scrollIntoView = scroll
    fireEvent.click(within(lead).getByRole('button', { name: 'Show Deployment/edge on the timeline' }))
    expect(scroll).toHaveBeenCalled()
    expect(document.activeElement?.textContent).toBe('edge')
  })

  it('does not lead with "no incident opened" when incidents are not readable', async () => {
    mockTimeline.mockResolvedValue(timeline({ restricted: [{ source: 'incidents', capability: 'incident:read' }] as never }))
    wrap()
    await screen.findByText(/Incidents are not shown/)
    expect(screen.queryByRole('region', { name: 'Incidents opened in this window' })).toBeNull()
  })
})
