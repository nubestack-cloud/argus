import { describe, expect, it } from 'vitest'
import { computeShortLabels, SERIES_COLOR_TOKENS, seriesColor, seriesDisplayLabels, seriesFill } from './colors'

describe('series colours', () => {
  it('are token references that repeat after the last token', () => {
    const n = SERIES_COLOR_TOKENS.length
    const colours = Array.from({ length: 2 * n }, (_, i) => seriesColor(i))
    for (const c of colours) expect(c).toMatch(/^var\(--chart-[a-z]+\)$/)
    expect(new Set(colours).size).toBe(n)
    expect(colours.slice(n)).toEqual(colours.slice(0, n))
  })

  it('leave out the severity red and the medium fill that needs a direct label', () => {
    expect(SERIES_COLOR_TOKENS).not.toEqual(expect.arrayContaining(['--chart-critical']))
    expect(SERIES_COLOR_TOKENS).not.toEqual(expect.arrayContaining(['--chart-medium']))
  })

  it('fill translucently in the line colour', () => {
    expect(seriesFill(1)).toBe(`color-mix(in srgb, ${seriesColor(1)} 14%, transparent)`)
    expect(seriesFill(1)).not.toMatch(/#[0-9a-f]{3,8}\b/i)
  })
})

describe('seriesDisplayLabels', () => {
  it('names a series by its pod, instance or node when those are distinct', () => {
    expect(seriesDisplayLabels([
      { labels: { container: 'worker', pod: 'queue-0' } },
      { labels: { instance: '10.42.1.9:9100' } },
      { labels: { node: 'worker-2', job: 'kubelet' } },
    ])).toEqual(['queue-0', '10.42.1.9:9100', 'worker-2'])
  })

  it('names every series by all its labels once a short name would collide', () => {
    expect(seriesDisplayLabels([
      { labels: { pod: 'queue-0', container: 'worker' } },
      { labels: { pod: 'queue-0', container: 'sidecar' } },
    ])).toEqual(['pod=queue-0, container=worker', 'pod=queue-0, container=sidecar'])
    expect(seriesDisplayLabels([{ labels: { mode: 'user' } }, { labels: { mode: 'system' } }])).toEqual(['mode=user', 'mode=system'])
  })

  it('numbers a series that has no labels at all', () => {
    expect(seriesDisplayLabels([{ labels: { pod: 'queue-0' } }, { labels: {} }])).toEqual(['queue-0', 'series-1'])
  })
})

describe('computeShortLabels', () => {
  it('drops the shared part back to its last separator', () => {
    expect(computeShortLabels(['ledger-6c9f7b5d4-x2l9q', 'ledger-6c9f7b5d4-mm7rt', 'ledger-6c9f7b5d4-08vbk'])).toEqual(['x2l9q', 'mm7rt', '08vbk'])
    expect(computeShortLabels(['shop/cart', 'shop/carts'])).toEqual(['cart', 'carts'])
  })

  it('drops all of a shared part that has no separator', () => {
    expect(computeShortLabels(['gpu0', 'gpu1'])).toEqual(['0', '1'])
  })

  it('keeps the full labels rather than leave one empty or two alike', () => {
    expect(computeShortLabels(['web', 'web-canary'])).toEqual(['web', 'web-canary'])
    expect(computeShortLabels(['a-x', 'b-x'])).toEqual(['a-x', 'b-x'])
    expect(computeShortLabels(['solo'])).toEqual(['solo'])
  })
})
