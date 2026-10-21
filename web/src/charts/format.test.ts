import { describe, expect, it } from 'vitest'
import { formatMetricValue as f } from './format'

describe('formatMetricValue', () => {
  it('states a measured zero as 0, and keeps the sign of a negative', () => {
    expect([f(0, 'bytes'), f(0, 'cores'), f(-1536, 'bytes'), f(-0.5, '')]).toEqual(['0', '0', '-1.5 KiB', '-0.500'])
  })

  it('gives unitless values SI prefixes rather than a long run of k', () => {
    expect(['', '', '', '', ''].map((u, i) => f([3.14159, 640, 48_250, 7_300_000, 2_500_000_000][i], u))).toEqual(['3.14', '640', '48.3k', '7.3M', '2.50G'])
    expect(f(0.004, '')).toBe('4.0e-3')
  })

  it('formats the resource units the incident charts use', () => {
    expect(f(0.0004, 'cores')).toBe('0.4m')
    expect(f(0.125, 'cores')).toBe('125m')
    expect(f(2, 'cores')).toBe('2.00')
    expect(f(300 * 1024 * 1024, 'bytes')).toBe('300.0 MiB')
    expect(f(3 * 1024 ** 3, 'bytes')).toBe('3.00 GiB')
    expect(f(2048, 'bytes/s')).toBe('2.0 KiB/s')
    expect(f(7, 'restarts')).toBe('7')
    expect(f(12_400, 'count')).toBe('12.4k')
    expect(f(99.95, 'percent')).toBe('100.0%')
    expect(f(0.42, 'percent')).toBe('0.42%')
  })

  it('bounds what is too small to show rather than rounding it to zero', () => {
    expect([f(0.00005, 'cores'), f(0.4, 'bytes'), f(0.2, 'bytes/s'), f(0.004, 'req/s')]).toEqual(['< 0.1m', '< 1 B', '< 1 B/s', '< 0.01/s'])
  })

  it('moves durations up through µs, ms, s, m and h', () => {
    expect([0.0002, 0.004, 0.25, 4.2, 42, 900, 7200].map(v => f(v, 'seconds'))).toEqual(['200µs', '4.00ms', '250ms', '4.20s', '42.0s', '15.0m', '2.0h'])
  })
})
