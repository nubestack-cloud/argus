import { describe, expect, it } from 'vitest'
import { fleetRolloutSnippet, fleetTokenState } from './FleetTokensDialog'
import type { FleetToken } from '../api/types'

const now = Date.parse('2026-10-20T12:00:00Z')
const token = (over: Partial<FleetToken>): FleetToken => ({
  id: 'tok', name: 'eu', issuedBy: 'usr_1', issuedAt: '2026-10-01T00:00:00Z', expiresAt: '2026-12-01T00:00:00Z',
  redemptions: 3, maxRedemptions: 10, autoAccept: false, ...over,
})

describe('fleetTokenState', () => {
  it('names why a token no longer works, revocation first', () => {
    expect(fleetTokenState(token({}), now)).toBe('Active')
    expect(fleetTokenState(token({ redemptions: 10 }), now)).toBe('Used up')
    expect(fleetTokenState(token({ expiresAt: '2026-10-19T00:00:00Z' }), now)).toBe('Expired')
    expect(fleetTokenState(token({ revokedAt: '2026-10-02T00:00:00Z', expiresAt: '2026-10-19T00:00:00Z' }), now)).toBe('Revoked')
  })
})

describe('fleetRolloutSnippet', () => {
  it('puts the token in a Secret and the chart values beside it', () => {
    const s = fleetRolloutSnippet('abc.def', { chartRef: 'oci://registry-1.docker.io/nubestack/argus-agent-chart', chartVersion: '0.2.0', hubApiUrl: 'https://argus.example.com' })
    expect(s).toContain('--from-literal=token=abc.def')
    expect(s).toContain('apiUrl: https://argus.example.com')
    expect(s).toContain('version 0.2.0')
    expect(s).toContain('name: argus-enrollment-token')
    // The Secret's namespace exists before the chart runs, so the chart must not create it.
    expect(s).toContain('namespace:\n  create: false')
  })
  it('shows a placeholder for an address the hub was not told', () => {
    expect(fleetRolloutSnippet('t', { chartRef: 'c', chartVersion: null, hubApiUrl: null })).toContain('apiUrl: <hub-api-url>')
  })
})
