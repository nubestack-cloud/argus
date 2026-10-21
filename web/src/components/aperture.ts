// THE APERTURE MARK'S GEOMETRY AND SLEEP SCHEDULE, in one place, because two
// different renderers now draw the same mark:
//
//   - `ArgusLogoMark` (icons.tsx) — inline SVG, twelve identical blades, the
//     sleep applied by CSS (`.argus-blade-rest`, `@keyframes argus-vigil`).
//   - `ApertureField` (ApertureField.tsx) — canvas, redrawn per frame at
//     display scale for the login screen's backdrop, where the mark is ~400px
//     across and CSS-animating twelve SVG rects that size is the wrong tool.
//
// Two renderers is a drift risk: the schedule is the identity's one moving
// part, and "three asleep, 120 degrees apart, never all of them" is the detail
// the whole mark exists to carry. It must not be true in the header and subtly
// false on the login screen. So the numbers live here, `aperture.test.ts`
// pins the properties that matter, and `public/favicon.svg`'s own test pins
// the still frame the same way.
//
// Geometry is normalised by the OUTER RADIUS rather than kept on the SVG's
// 64-unit grid, so the same constants draw a 44px mark in the app bar and a
// 400px one behind a login form.

export const APERTURE = {
  /** Blades, at 30-degree steps. */
  COUNT: 12,
  STEP_DEG: 30,
  /** Inner end of every blade — where a sleeping one retracts TO. 9 of 26. */
  INNER: 9 / 26,
  /** Outer end of a waking blade: the radius the mark is measured by. */
  OUTER: 1,
  /**
   * Outer end of a SLEEPING blade — 17.5 of 26, which is the midpoint of the
   * 9-to-26 span. Stated as its own constant rather than derived as
   * `INNER + (OUTER - INNER) / 2` because the two renderers reach it
   * differently: CSS gets there with `scaleY(0.5)` about the inner end (which
   * also squashes the blade's rounded cap, harmlessly at 44px), and the canvas
   * draws to this radius directly. One number both can agree on.
   */
  SLEEP_OUTER: 17.5 / 26,
  /** Half the blade's width: 1.7 of 26. Also the radius of its rounded cap. */
  HALF_WIDTH: 1.7 / 26,
  /** The pupil at the centre. 5.6 of 26. */
  PUPIL: 5.6 / 26,
  /** Opacity a blade fades to while asleep. */
  SLEEP_OPACITY: 0.26,
} as const

/** The vigil's period. Matches `@keyframes argus-vigil`'s 13s in index.css. */
export const VIGIL_CYCLE_MS = 13_000

/**
 * Which of the four sleep groups a blade belongs to.
 *
 * The twelve blades divide into four groups of three whose members sit 120
 * degrees apart — {0,120,240}, {30,150,270}, {60,180,300}, {90,210,330} — so
 * whichever group is asleep, the closed blades are spread evenly around the
 * iris instead of bunched into one dark wedge. Group 0 is {90,210,330}: the
 * three asleep in the still mark, and therefore the state the animation starts
 * from, so nothing jumps on first paint.
 */
export function bladePhase(index: number): number {
  return ((index % 4) + 1) % 4
}

/**
 * How asleep a blade is, 0 (open) to 1 (retracted), given its progress through
 * the cycle. Mirrors `@keyframes argus-vigil`: asleep held to 18%, opening by
 * 25%, open until 93%, closing again by 100%.
 */
export function bladeSleep(progress: number): number {
  const p = progress - Math.floor(progress)
  if (p < 0.18) return 1
  if (p < 0.25) return 1 - smoothstep((p - 0.18) / 0.07)
  if (p < 0.93) return 0
  return smoothstep((p - 0.93) / 0.07)
}

/**
 * A blade's progress through the cycle at time `elapsedMs`. The `+ phase / 4`
 * is the canvas equivalent of the CSS rule's negative `animation-delay`: it
 * starts each group a quarter-cycle apart so one group is always asleep.
 */
export function bladeProgress(index: number, elapsedMs: number): number {
  return elapsedMs / VIGIL_CYCLE_MS + bladePhase(index) / 4
}

function smoothstep(t: number): number {
  return t * t * (3 - 2 * t)
}
