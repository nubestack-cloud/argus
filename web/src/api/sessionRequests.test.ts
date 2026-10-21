import { afterEach, describe, expect, it, vi } from 'vitest'
import { logout, refresh, revokePersonalToken } from './client'

// Live QA 2026-10-11. Two transport details of the session calls, each tied to
// an observed failure:
//  - keepalive on /auth/refresh and /auth/logout, so a rotation the hub has
//    committed still lands its new cookie when the tab closes or navigates
//    mid-request (reproduced live: without it the next load presented the
//    retired token and the hub revoked the session as a reuse);
//  - a 204's empty body is read, because Chromium reports an unread body as a
//    cancelled request (net::ERR_ABORTED) although it succeeded.
function stubFetch(status: number, body: unknown) {
  const text = vi.fn(async () => (body === undefined ? '' : JSON.stringify(body)))
  const fetchMock = vi.fn(async () => ({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text,
  }))
  vi.stubGlobal('fetch', fetchMock)
  return { fetchMock, text }
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('session requests', () => {
  it('sends refresh with keepalive so a committed rotation survives the page going away', async () => {
    const { fetchMock } = stubFetch(200, { accessToken: 'a', expiresIn: 900, mustChangePassword: true })
    const res = await refresh()
    expect(res.mustChangePassword).toBe(true)
    const init = (fetchMock.mock.calls[0] as unknown[])[1] as RequestInit
    expect(init.keepalive).toBe(true)
    expect(init.credentials).toBe('same-origin')
  })

  it('sends logout with keepalive and reads its empty 204 body', async () => {
    const { fetchMock, text } = stubFetch(204, undefined)
    await logout()
    expect(((fetchMock.mock.calls[0] as unknown[])[1] as RequestInit).keepalive).toBe(true)
    expect(text).toHaveBeenCalled()
  })

  it('reads the empty body of every other 204 too, and does not set keepalive on ordinary calls', async () => {
    const { fetchMock, text } = stubFetch(204, undefined)
    await revokePersonalToken('pat_1', 'token')
    expect(text).toHaveBeenCalled()
    expect(((fetchMock.mock.calls[0] as unknown[])[1] as RequestInit).keepalive).toBeUndefined()
  })
})
