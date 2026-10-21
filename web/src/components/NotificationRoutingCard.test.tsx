import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'

import { CAP_CLUSTER_READ, CAP_ORG_SETTINGS_WRITE } from '../api/capabilities'

const mockGetNotificationRouting = vi.fn()
const mockUpdateNotificationRouting = vi.fn()
const mockGetClusterGroups = vi.fn()

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    getNotificationRouting: (...a: unknown[]) => mockGetNotificationRouting(...a),
    updateNotificationRouting: (...a: unknown[]) => mockUpdateNotificationRouting(...a),
    getClusterGroups: (...a: unknown[]) => mockGetClusterGroups(...a),
  }
})
vi.mock('../auth/useAuth', () => ({ useAuth: () => ({ accessToken: 'test-token' }) }))

const grantedCapabilities = new Set<string>()
vi.mock('../auth/useCapabilities', () => ({
  useHasCapability: (capability: string) => grantedCapabilities.has(capability),
}))

import { NotificationRoutingCard } from './NotificationRoutingCard'

// The shape GET /api/v1/admin/notification-routing returns. Note what is NOT
// here: any destination's url. That absence is the thing most of these tests
// are about — the form has to be able to say "a URL is set" without holding it,
// and must never blank one by accident.
function routing(over: Record<string, unknown> = {}) {
  return {
    destinations: [
      { name: 'team-channel', kind: 'webhook', urlConfigured: true },
      { name: 'on-call-pager', kind: 'webhook', urlConfigured: true },
    ],
    rules: [
      {
        name: 'Page on-call for criticals',
        priority: 1,
        clusterGroupId: null,
        clusterGroupName: null,
        minSeverity: 'critical',
        transition: null,
        destination: 'on-call-pager',
        enabled: true,
      },
      {
        name: 'Production high and above',
        priority: 2,
        clusterGroupId: 'cg_prod',
        clusterGroupName: 'Production',
        minSeverity: 'high',
        transition: 'NewIncident',
        destination: 'team-channel',
        enabled: true,
      },
    ],
    defaultRule: { name: 'Default', urlConfigured: true, source: 'settings.notify.webhookUrl' },
    transitions: ['NewIncident', 'AwaitingApproval', 'Failed'],
    severities: ['low', 'medium', 'high', 'critical'],
    ...over,
  }
}

// `team-channel` reads twice on this screen — once as a destination and once as
// an <option> on every rule that points at it — so a row lookup has to say
// which table it means.
function destinationRow(name: string): HTMLElement {
  const cell = screen
    .getAllByText(name)
    .find((el) => el.tagName === 'CODE')
  if (!cell) throw new Error(`no destination row for ${name}`)
  return cell.closest('tr') as HTMLElement
}

function renderCard() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  // MemoryRouter because the default rule's row links to the Notifications
  // section of this same page — the default's URL genuinely lives there.
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/settings?section=routing']}>
        <NotificationRoutingCard />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  mockGetNotificationRouting.mockReset()
  mockUpdateNotificationRouting.mockReset()
  mockGetClusterGroups.mockReset()
  mockGetNotificationRouting.mockResolvedValue(routing())
  mockUpdateNotificationRouting.mockImplementation(async () => routing())
  mockGetClusterGroups.mockResolvedValue({
    clusterGroups: [{ id: 'cg_prod', name: 'Production', clusterIds: [] }],
  })
  grantedCapabilities.clear()
  grantedCapabilities.add(CAP_ORG_SETTINGS_WRITE)
  grantedCapabilities.add(CAP_CLUSTER_READ)
})

describe('NotificationRoutingCard (PROJECT.md F32)', () => {
  it('renders the rules in evaluation order and says first match wins', async () => {
    renderCard()
    await screen.findByDisplayValue('Page on-call for criticals')
    expect(screen.getByText(/the first one that matches wins/i)).toBeTruthy()
    const names = screen
      .getAllByLabelText('Rule name')
      .map((el) => (el as HTMLInputElement).value)
    expect(names).toEqual(['Page on-call for criticals', 'Production high and above'])
  })

  // The whole point of the write-only URL contract: a save that touched nothing
  // about a destination's URL must OMIT the key, not send an empty string.
  // Sending "" is refused by notify.validateWebhookURL, and sending null-as-""
  // would be the silent delivery break this screen exists to avoid.
  it('omits `url` entirely for a destination whose URL was not touched', async () => {
    renderCard()
    await screen.findByDisplayValue('Page on-call for criticals')
    // Make an unrelated edit so there is something to save.
    fireEvent.click(screen.getByRole('button', { name: /Move Production high and above earlier/i }))
    fireEvent.click(screen.getByRole('button', { name: /Save routing table/i }))

    await waitFor(() => expect(mockUpdateNotificationRouting).toHaveBeenCalledTimes(1))
    const [body] = mockUpdateNotificationRouting.mock.calls[0]
    expect(body.destinations).toEqual([{ name: 'team-channel' }, { name: 'on-call-pager' }])
    for (const d of body.destinations) {
      expect('url' in d).toBe(false)
    }
  })

  it('sends a replacement URL only after Replace URL is chosen, and can be cancelled back to keeping it', async () => {
    renderCard()
    await screen.findByDisplayValue('Page on-call for criticals')
    const destRow = destinationRow('team-channel')

    fireEvent.click(within(destRow).getByRole('button', { name: /Replace URL/i }))
    fireEvent.change(within(destRow).getByLabelText(/New webhook URL for team-channel/i), {
      target: { value: 'https://hooks.example.com/services/NEW' },
    })
    expect(within(destRow).getByText(/New URL, not saved/i)).toBeTruthy()

    // Cancelling returns it to untouched — which is what keeps the stored URL.
    fireEvent.click(within(destRow).getByRole('button', { name: /Keep the stored URL/i }))
    expect(within(destRow).getByText('Set')).toBeTruthy()

    fireEvent.click(within(destRow).getByRole('button', { name: /Replace URL/i }))
    fireEvent.change(within(destRow).getByLabelText(/New webhook URL for team-channel/i), {
      target: { value: 'https://hooks.example.com/services/NEW' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Save routing table/i }))

    await waitFor(() => expect(mockUpdateNotificationRouting).toHaveBeenCalledTimes(1))
    const [body] = mockUpdateNotificationRouting.mock.calls[0]
    expect(body.destinations).toEqual([
      { name: 'team-channel', url: 'https://hooks.example.com/services/NEW' },
      { name: 'on-call-pager' },
    ])
  })

  it('never shows a destination URL back, only whether one is set', async () => {
    renderCard()
    await screen.findByDisplayValue('Page on-call for criticals')
    expect(screen.getAllByText('Set').length).toBe(2)
    // No input holds a URL until one is explicitly being replaced.
    expect(screen.queryByLabelText(/New webhook URL for team-channel/i)).toBeNull()
  })

  // Order IS the configuration — the row's position becomes its priority, so a
  // reorder has to change what is sent, not just what is drawn.
  it('writes the rendered order back as ascending priorities', async () => {
    renderCard()
    await screen.findByDisplayValue('Page on-call for criticals')
    fireEvent.click(screen.getByRole('button', { name: /Move Production high and above earlier/i }))
    fireEvent.click(screen.getByRole('button', { name: /Save routing table/i }))

    await waitFor(() => expect(mockUpdateNotificationRouting).toHaveBeenCalledTimes(1))
    const [body] = mockUpdateNotificationRouting.mock.calls[0]
    expect(body.rules.map((r: { name: string; priority: number }) => [r.name, r.priority])).toEqual([
      ['Production high and above', 1],
      ['Page on-call for criticals', 2],
    ])
  })

  // The default rule is synthetic: it is not a row in `rules`, it is the org's
  // existing webhook, and it must never be sent back as one.
  it('shows the default rule as an uneditable last row and never sends it as a rule', async () => {
    renderCard()
    await screen.findByDisplayValue('Page on-call for criticals')
    const defaultRow = screen.getByText(/always matches, not editable here/i).closest('tr') as HTMLElement
    expect(within(defaultRow).getByText('Default')).toBeTruthy()
    expect(within(defaultRow).getByText(/Organization webhook — URL set/i)).toBeTruthy()
    expect(within(defaultRow).getByText(/settings\.notify\.webhookUrl/i)).toBeTruthy()
    // No control in it: it is not configuration on this screen.
    expect(within(defaultRow).queryByRole('button')).toBeNull()
    expect(within(defaultRow).queryByRole('textbox')).toBeNull()
    expect(within(defaultRow).queryByRole('combobox')).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: /Move Production high and above earlier/i }))
    fireEvent.click(screen.getByRole('button', { name: /Save routing table/i }))
    await waitFor(() => expect(mockUpdateNotificationRouting).toHaveBeenCalledTimes(1))
    const [body] = mockUpdateNotificationRouting.mock.calls[0]
    expect(body.rules.map((r: { name: string }) => r.name)).toEqual([
      'Production high and above',
      'Page on-call for criticals',
    ])
  })

  it('states that every notification matches something — there is no drop path', async () => {
    renderCard()
    await screen.findByDisplayValue('Page on-call for criticals')
    expect(screen.getByText(/There is no rule that drops a notification/i)).toBeTruthy()
  })

  // A default with no URL means everything no rule claimed goes nowhere. The
  // hub reports it precisely so it is not discovered from a log line.
  it('warns when the default rule has no URL', async () => {
    mockGetNotificationRouting.mockResolvedValue(
      routing({ defaultRule: { name: 'Default', urlConfigured: false, source: 'settings.notify.webhookUrl' } }),
    )
    renderCard()
    expect(
      await screen.findByText(/The default rule has no URL, so anything no rule below claims is delivered nowhere/i),
    ).toBeTruthy()
  })

  // minSeverity is a floor, not an equality test. If the control reads "High"
  // an operator configures an equality test in their head and silently misses
  // criticals.
  it('labels minimum severity as a floor, not an equality test', async () => {
    renderCard()
    await screen.findByDisplayValue('Page on-call for criticals')
    const select = screen.getAllByLabelText('Minimum severity')[0] as HTMLSelectElement
    const labels = Array.from(select.options).map((o) => o.textContent)
    expect(labels).toEqual([
      'Any severity',
      'Low and above',
      'Medium and above',
      'High and above',
      'Critical only',
    ])
    expect(screen.getByText(/Severity is a floor, not an equality test/i)).toBeTruthy()
  })

  // "No rules yet" is not an error and not a filtered-to-nothing dead end: it
  // is the fresh-install state, and the default row is still in the table.
  it('has a distinct empty state that explains where notifications go meanwhile', async () => {
    mockGetNotificationRouting.mockResolvedValue(routing({ rules: [] }))
    renderCard()
    expect(
      await screen.findByText(/No rules yet: every notification goes to the default rule below/i),
    ).toBeTruthy()
    expect(screen.getByText(/always matches, not editable here/i)).toBeTruthy()
  })

  it('disables every control with the missing capability named, never hiding them', async () => {
    grantedCapabilities.clear()
    grantedCapabilities.add(CAP_CLUSTER_READ)
    renderCard()
    await screen.findByDisplayValue('Page on-call for criticals')
    for (const name of [/Add destination/i, /Replace URL/i, /Add rule/i, /Save routing table/i]) {
      const button = screen.getAllByRole('button', { name })[0]
      expect(button).toHaveProperty('disabled', true)
      expect(button.title).toMatch(/org:settings:write/)
    }
    const severity = screen.getAllByLabelText('Minimum severity')[0] as HTMLSelectElement
    expect(severity.disabled).toBe(true)
    expect(severity.title).toMatch(/org:settings:write/)
  })

  // A different capability, a different route. Someone who can edit routing but
  // cannot list cluster groups still sees the group a rule is scoped to — from
  // the hub's own resolved clusterGroupName — rather than a rule that reads as
  // though it matched every cluster.
  it('keeps a group-scoped rule readable without cluster:read, and names the missing capability', async () => {
    grantedCapabilities.clear()
    grantedCapabilities.add(CAP_ORG_SETTINGS_WRITE)
    renderCard()
    await screen.findByDisplayValue('Production high and above')
    const group = screen.getAllByLabelText('Cluster group')[1] as HTMLSelectElement
    expect(group.disabled).toBe(true)
    expect(group.title).toMatch(/cluster:read/)
    expect(group.value).toBe('cg_prod')
    expect(within(group).getByText('Production')).toBeTruthy()
  })

  it('refuses to remove a destination a rule still points at, saying how many', async () => {
    renderCard()
    await screen.findByDisplayValue('Page on-call for criticals')
    const destRow = destinationRow('team-channel')
    const remove = within(destRow).getByRole('button', { name: 'Remove' })
    expect(remove).toHaveProperty('disabled', true)
    expect(remove.title).toMatch(/1 rule still send/i)
  })

  it('will not stage a new destination without a URL, since the hub refuses one', async () => {
    renderCard()
    await screen.findByDisplayValue('Page on-call for criticals')
    fireEvent.change(screen.getByPlaceholderText('on-call-pager'), { target: { value: 'incidents-room' } })
    fireEvent.click(screen.getByRole('button', { name: /Add destination/i }))
    expect(screen.getByRole('alert').textContent).toMatch(/needs one/i)
    expect(screen.queryByRole('cell', { name: 'incidents-room' })).toBeNull()
  })

  it('renders the hub\'s own problem detail when a save is refused', async () => {
    const { ApiError } = await vi.importActual<typeof import('../api/client')>('../api/client')
    mockUpdateNotificationRouting.mockRejectedValue(
      new ApiError(
        'Invalid notification routing',
        400,
        'rule "Page on-call for criticals" names destination "gone", which is not in this configuration',
        'https://argus.io/errors/validation',
      ),
    )
    renderCard()
    await screen.findByDisplayValue('Page on-call for criticals')
    fireEvent.click(screen.getByRole('button', { name: /Move Production high and above earlier/i }))
    fireEvent.click(screen.getByRole('button', { name: /Save routing table/i }))
    expect(await screen.findByText(/which is not in this configuration/i)).toBeTruthy()
  })

  it('says nothing is staged until an edit is made, and discards back to the hub\'s table', async () => {
    renderCard()
    await screen.findByDisplayValue('Page on-call for criticals')
    const save = screen.getByRole('button', { name: /Save routing table/i })
    expect(save).toHaveProperty('disabled', true)
    expect(save.title).toMatch(/Nothing staged/i)

    fireEvent.click(screen.getByRole('button', { name: /Move Production high and above earlier/i }))
    expect(save).toHaveProperty('disabled', false)
    expect(screen.getByText(/Staged, not saved/i)).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: /Discard changes/i }))
    const names = screen
      .getAllByLabelText('Rule name')
      .map((el) => (el as HTMLInputElement).value)
    expect(names).toEqual(['Page on-call for criticals', 'Production high and above'])
  })
})
