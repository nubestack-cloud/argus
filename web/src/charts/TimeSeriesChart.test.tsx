import { describe, expect, it } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { TimeSeriesChart } from './TimeSeriesChart'
import { niceCeil, seriesRuns } from './series'
import type { TimeSeries } from './types'

const series: TimeSeries[] = [
  {
    labels: { pod: 'payments-6d9-aaaaa' },
    dataPoints: [
      { timestamp: 1000, value: 100 },
      { timestamp: 1060, value: null },
      { timestamp: 1120, value: 300 },
    ],
  },
  {
    labels: { pod: 'payments-6d9-bbbbb' },
    dataPoints: [
      { timestamp: 1000, value: 50 },
      { timestamp: 1120, value: 60 },
    ],
  },
]

describe('seriesRuns', () => {
  it('breaks a line at a gap instead of drawing it as zero', () => {
    expect(seriesRuns(series[0].dataPoints)).toEqual([[{ timestamp: 1000, value: 100 }], [{ timestamp: 1120, value: 300 }]])
  })
})

describe('niceCeil', () => {
  it('rounds to a tick-friendly top', () => {
    expect(niceCeil(0)).toBe(1)
    expect(niceCeil(7)).toBe(10)
    expect(niceCeil(230)).toBe(250)
  })
})

describe('TimeSeriesChart', () => {
  it('says there are no samples instead of drawing an empty chart', () => {
    render(<TimeSeriesChart title="CPU usage" unit="cores" series={[{ labels: { pod: 'a' }, dataPoints: [{ timestamp: 1, value: null }] }]} />)
    expect(screen.getByText(/not a measured zero/i)).toBeTruthy()
    expect(screen.queryByRole('img')).toBeNull()
  })

  it('names every series in text and labels markers', () => {
    render(
      <TimeSeriesChart
        title="Memory"
        unit="bytes"
        series={series}
        annotations={[{ timestamp: 1060, label: 'opened', kind: 'opened' }]}
        stepSeconds={60}
      />,
    )
    expect(screen.getByText('aaaaa')).toBeTruthy()
    expect(screen.getByText('bbbbb')).toBeTruthy()
    expect(screen.getByText('opened')).toBeTruthy()
    expect(screen.getByRole('img').getAttribute('aria-label')).toMatch(/Memory: 2 series/)
  })

  it('reads the nearest sample of each series from the keyboard', () => {
    render(<TimeSeriesChart title="Memory" unit="count" series={series} stepSeconds={60} />)
    const plot = screen.getByRole('img')
    fireEvent.keyDown(plot, { key: 'End' })
    expect(screen.getByText(/300/)).toBeTruthy()
    fireEvent.keyDown(plot, { key: 'Home' })
    expect(screen.getByText(/100/)).toBeTruthy()
  })

  it('offers the same data as a table with a dash for a missing sample', () => {
    render(<TimeSeriesChart title="Memory" unit="count" series={series} annotations={[{ timestamp: 1060, label: 'image v1 → v2', kind: 'change' }]} />)
    fireEvent.click(screen.getByRole('button', { name: 'View as table' }))
    const rows = screen.getAllByRole('row')
    expect(rows).toHaveLength(3) // header + two timestamps with any sample
    expect(screen.getByText('image v1 → v2', { exact: false })).toBeTruthy()
  })
})
