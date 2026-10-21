import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'

let authState: { accessToken: string | null; isBootstrapping: boolean; signOut: 'confirmed' | 'unconfirmed' | null }
vi.mock('./useAuth', () => ({ useAuth: () => authState }))

import { ProtectedRoute } from './ProtectedRoute'

function LoginProbe() {
  const location = useLocation()
  const from = (location.state as { from?: { pathname?: string } } | null)?.from?.pathname
  return <p>LOGIN from={from ?? 'none'}</p>
}

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/login" element={<LoginProbe />} />
        <Route path="/incidents/:id" element={<ProtectedRoute><p>INCIDENT</p></ProtectedRoute>} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('ProtectedRoute', () => {
  it('remembers the page when a session ran out under the reader', () => {
    authState = { accessToken: null, isBootstrapping: false, signOut: null }
    renderAt('/incidents/inc_1')
    expect(screen.getByText('LOGIN from=/incidents/inc_1')).toBeTruthy()
  })

  // Live QA 2026-10-11: the next person to sign in landed on the outgoing
  // user's last page.
  it('does not carry the page across an explicit sign-out', () => {
    authState = { accessToken: null, isBootstrapping: false, signOut: 'confirmed' }
    renderAt('/incidents/inc_1')
    expect(screen.getByText('LOGIN from=none')).toBeTruthy()
  })
})
