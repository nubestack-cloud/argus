import { describe, expect, it } from 'vitest'
import { chartLayout, integerAxisTop, isCountUnit, yAxisValues } from './axis'

describe('whole-number axes', () => {
  it('tops out on a 1-2-5 step that covers the peak', () => {
    const cases: Array<[max: number, intervals: number, top: number]> = [
      [0, 4, 1], [1, 4, 1], [1.1, 4, 2], [3, 4, 3], [9, 4, 10], [18, 4, 20],
      [41, 4, 60], [250, 4, 300], [7, 1, 10], [18, 1, 20], [1234, 2, 2000],
    ]
    for (const [max, intervals, top] of cases) expect([max, intervals, integerAxisTop(max, intervals)]).toEqual([max, intervals, top])
  })

  it('ticks in whole steps and always ends on the top', () => {
    expect(yAxisValues(0, 1, 4, true)).toEqual([0, 1])
    expect(yAxisValues(0, 3, 2, true)).toEqual([0, 2, 3])
    expect(yAxisValues(0, 60, 4, true)).toEqual([0, 15, 30, 45, 60])
    expect(yAxisValues(0, 10, 1, true)).toEqual([0, 10])
  })

  it('divides any other range evenly', () => {
    expect(yAxisValues(0, 2, 4, false)).toEqual([0, 0.5, 1, 1.5, 2])
    expect(yAxisValues(10, 30, 2, true)).toEqual([10, 20, 30])
  })

  it('knows which units count things', () => {
    expect(['count', 'restarts', 'bytes', 'cores', ''].map(isCountUnit)).toEqual([true, true, false, false, false])
  })
})

describe('chartLayout', () => {
  it('follows the measured width with fixed text and height, adding X ticks when wide', () => {
    for (const width of [300, 640, 1200]) {
      expect(chartLayout(width)).toMatchObject({ width, height: 240, fontSize: 12, yIntervals: 2, xIntervals: width >= 760 ? 4 : 2 })
    }
  })

  it('stands in a fixed box until the container is measured', () => {
    expect(chartLayout()).toMatchObject({ width: 1000, height: 300, yIntervals: 4, xIntervals: 6 })
    expect(chartLayout(0)).toEqual(chartLayout())
  })
})
