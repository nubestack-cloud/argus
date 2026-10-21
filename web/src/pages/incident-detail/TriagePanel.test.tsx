import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

const mockResolve = vi.fn()
vi.mock('../../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/client')>()
  return { ...actual, resolveIncident: (...a: unknown[]) => mockResolve(...a) }
})
vi.mock('../../auth/useAuth', () => ({ useAuth: () => ({ accessToken: 't' }) }))

import { TriageControls } from './TriagePanel'

function renderControls() {
  return render(
    <QueryClientProvider client={new QueryClient()}>
      <MemoryRouter>
        <TriageControls incidentId="inc_1" state="AwaitingApproval" />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => mockResolve.mockReset())

// Live QA, 2026-10-11: "Mark resolved" in the Close out menu closed the
// incident on one click with an empty note. Resolving is terminal, so it now
// confirms in the same dialog pattern Dismiss and Tolerate use.
describe('TriageControls — Mark resolved confirms first', () => {
  it('opens a dialog stating what resolving means, and sends nothing yet', () => {
    renderControls()
    fireEvent.click(screen.getByRole('button', { name: /Close out/ }))
    fireEvent.click(screen.getByRole('menuitem', { name: /Mark resolved/ }))
    expect(mockResolve).not.toHaveBeenCalled()
    const dialog = screen.getByRole('dialog')
    expect(dialog.textContent).toMatch(/cannot be undone/)
    expect(dialog.textContent).toMatch(/Optional/)
  })

  it('resolves with the optional note only on confirm', async () => {
    mockResolve.mockResolvedValue({ incidentId: 'inc_1', verdict: 'resolved', incidentState: 'Resolved', message: 'ok' })
    renderControls()
    fireEvent.click(screen.getByRole('button', { name: /Close out/ }))
    fireEvent.click(screen.getByRole('menuitem', { name: /Mark resolved/ }))
    fireEvent.change(screen.getByLabelText(/What fixed it/), { target: { value: 'rolled back by hand' } })
    fireEvent.click(screen.getByRole('button', { name: 'Confirm resolve' }))
    await waitFor(() => expect(mockResolve).toHaveBeenCalledWith('inc_1', 't', 'rolled back by hand'))
  })

  it('cancel closes the dialog without resolving', () => {
    renderControls()
    fireEvent.click(screen.getByRole('button', { name: /Close out/ }))
    fireEvent.click(screen.getByRole('menuitem', { name: /Mark resolved/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(mockResolve).not.toHaveBeenCalled()
  })
})
