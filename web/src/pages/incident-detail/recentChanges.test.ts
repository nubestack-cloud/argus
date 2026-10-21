import { describe, expect, it } from 'vitest'
import { dedupeRecentChanges } from '../incidentLifecycle'
import type { RecentChange } from '../../api/types'

const c = (over: Partial<RecentChange>): RecentChange =>
  ({ category: 'object_created', objectKind: 'Pod', objectNamespace: 'apps', objectName: 'p1', time: '2026-10-05T12:00:00Z', source: 'describe_resource', ...over }) as RecentChange

describe('dedupeRecentChanges', () => {
  it('folds the same change seen by several tool calls into one row with a count', () => {
    const rows = dedupeRecentChanges([
      c({ source: 'list_resources' }),
      c({ source: 'describe_resource', time: '2026-10-05T12:00:05Z' }),
      c({ objectKind: 'ReplicaSet', objectName: 'rs1' }),
      c({}),
    ])
    expect(rows).toHaveLength(2)
    expect(rows[0].seen).toBe(3)
    expect(rows[0].change.time).toBe('2026-10-05T12:00:05Z')
    expect(rows[1].change.objectKind).toBe('ReplicaSet')
  })
  it('keeps changes with different messages apart', () => {
    expect(dedupeRecentChanges([c({ message: 'a' }), c({ message: 'b' })])).toHaveLength(2)
  })
})
