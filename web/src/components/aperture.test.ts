// The vigil's schedule is the identity's one moving part, and it is now
// implemented twice — once in CSS for the SVG mark, once in canvas for the
// login backdrop. These tests pin the PROPERTIES the mark exists to carry,
// not the numbers: "three asleep at any moment, spread 120 degrees apart,
// never all of them" is the detail of the Argus Panoptes myth the whole
// drawing is about, and a change that quietly broke it would look like a
// slightly different animation rather than like a bug.
import { describe, expect, it } from 'vitest'
import { APERTURE, VIGIL_CYCLE_MS, bladePhase, bladeProgress, bladeSleep } from './aperture'

const BLADES = [...Array(APERTURE.COUNT).keys()]
const degOf = (i: number) => i * APERTURE.STEP_DEG

// Asleep enough to read as closed. The threshold is deliberately mid-range so
// a blade caught mid-transition counts as neither, which is what the eye does.
const asleep = (s: number) => s > 0.5

describe('the vigil schedule', () => {
  it('splits the blades into four groups of three, each spread 120 degrees apart', () => {
    const groups = new Map<number, number[]>()
    for (const i of BLADES) {
      const p = bladePhase(i)
      groups.set(p, [...(groups.get(p) ?? []), degOf(i)])
    }
    expect([...groups.keys()].sort()).toEqual([0, 1, 2, 3])
    for (const [, degrees] of groups) {
      expect(degrees).toHaveLength(3)
      const sorted = [...degrees].sort((a, b) => a - b)
      expect(sorted[1] - sorted[0]).toBe(120)
      expect(sorted[2] - sorted[1]).toBe(120)
    }
  })

  it('starts from the still mark: 90, 210 and 330 are the blades asleep at rest', () => {
    const atRest = BLADES.filter((i) => asleep(bladeSleep(bladeProgress(i, 0)))).map(degOf)
    expect(atRest.sort((a, b) => a - b)).toEqual([90, 210, 330])
  })

  it('never closes and never fully opens, at any point in the cycle', () => {
    // Sampled every 50ms across two full cycles, so the wrap is covered too.
    for (let t = 0; t < VIGIL_CYCLE_MS * 2; t += 50) {
      const sleeps = BLADES.map((i) => bladeSleep(bladeProgress(i, t)))
      const closed = sleeps.filter(asleep).length
      expect(closed).toBeGreaterThan(0)
      expect(closed).toBeLessThan(APERTURE.COUNT)
      // Three at a time, plus at most one group mid-handover.
      expect(closed).toBeLessThanOrEqual(6)
    }
  })

  it('has exactly three blades asleep whenever no group is mid-handover', () => {
    let settled = 0
    for (let t = 0; t < VIGIL_CYCLE_MS * 2; t += 50) {
      const sleeps = BLADES.map((i) => bladeSleep(bladeProgress(i, t)))
      // Mid-handover means some blade is strictly between open and shut.
      if (sleeps.some((s) => s > 0.001 && s < 0.999)) continue
      settled++
      expect(sleeps.filter(asleep)).toHaveLength(3)
    }
    // Guard against the assertion above never running: most of the cycle is
    // settled, so this proves the loop actually tested something.
    expect(settled).toBeGreaterThan(300)
  })

  it('moves the sleep around the iris rather than blinking one group forever', () => {
    const seen = new Set<string>()
    for (let t = 0; t < VIGIL_CYCLE_MS; t += 50) {
      const shut = BLADES.filter((i) => asleep(bladeSleep(bladeProgress(i, t))))
        .map(degOf)
        .sort((a, b) => a - b)
        .join(',')
      seen.add(shut)
    }
    // All four groups take a turn within one cycle.
    expect([...seen].filter((s) => s.split(',').length === 3).sort()).toEqual([
      '0,120,240',
      '30,150,270',
      '60,180,300',
      '90,210,330',
    ])
  })
})

describe('the aperture geometry', () => {
  it('retracts a sleeping blade to the midpoint of its own span', () => {
    // What makes a sleeping blade read as "pulled back toward the pupil"
    // rather than "shrunk": the inner end holds still and the outer end comes
    // halfway in. The SVG reaches this with scaleY(0.5) about the inner end,
    // the canvas by drawing to SLEEP_OUTER — they have to agree.
    const midpoint = APERTURE.INNER + (APERTURE.OUTER - APERTURE.INNER) / 2
    expect(APERTURE.SLEEP_OUTER).toBeCloseTo(midpoint, 6)
  })

  it('keeps every blade clear of the pupil', () => {
    // A blade's cap reaches HALF_WIDTH past its inner end; if that crossed the
    // pupil the mark would be a solid disc with spokes rather than an iris.
    expect(APERTURE.INNER).toBeGreaterThan(APERTURE.PUPIL)
  })
})
