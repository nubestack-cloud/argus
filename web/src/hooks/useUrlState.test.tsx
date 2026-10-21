import { describe, expect, it } from 'vitest'
import { act, render, screen } from '@testing-library/react'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { urlEnum, urlString, useUrlParam, useUrlState } from './useUrlState'

// CI-U5. The regression this pins: react-router computes a functional
// setSearchParams from the render's params, so two writes in one handler
// used to keep only the second.

const SCHEMA = { sort: urlEnum(['name', 'age'] as const, 'name'), q: urlString('') }

function Probe({ onReady }: { onReady: (api: { setBoth: () => void }) => void }) {
  const [state, set] = useUrlState(SCHEMA)
  const [page, setPage] = useUrlParam<string>('page', '1')
  const loc = useLocation()
  onReady({
    setBoth: () => {
      set({ sort: 'age' })
      set({ q: 'pay' })
      setPage('3')
    },
  })
  return (
    <p data-testid="out">
      {state.sort}|{state.q}|{page}|{loc.search}
    </p>
  )
}

describe('useUrlState', () => {
  it('reads defaults and drops unknown enum values', () => {
    render(
      <MemoryRouter initialEntries={['/?sort=bogus&q=x']}>
        <Probe onReady={() => {}} />
      </MemoryRouter>,
    )
    expect(screen.getByTestId('out').textContent).toBe('name|x|1|?sort=bogus&q=x')
  })

  it('composes several writes made in one handler', () => {
    let api: { setBoth: () => void } | undefined
    render(
      <MemoryRouter initialEntries={['/?keep=1']}>
        <Probe onReady={(a) => (api = a)} />
      </MemoryRouter>,
    )
    act(() => api!.setBoth())
    expect(screen.getByTestId('out').textContent).toBe('age|pay|3|?keep=1&sort=age&q=pay&page=3')
  })
})
