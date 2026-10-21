// Donut-segment arithmetic, extracted from OverviewPage so it can be tested and
// so that page exports only components.
//
// MIN_ARC_FRACTION is the smallest share of the ring any non-zero segment gets.
//
// Without it, one critical incident among 180 draws 0.55% of a 251px
// circumference — a 1.4px sliver, which is to say the single most important
// segment is the one you cannot see. The floor is taken back from the segments
// that can afford it, in proportion to how much they have to spare, so the ring
// still adds up to the full circumference.
//
// The trade is explicit and surfaced in the UI rather than hidden: below this size
// the ARC is no longer to scale, so the legend carries the exact percentage and the
// card says small slices are enlarged. An arc that is honest and invisible is worse
// than one that is visible and says where it rounded.
export const MIN_ARC_FRACTION = 0.025

// arcLengths applies that floor. Pure arithmetic with an easy off-by-a-rounding
// error and no visible symptom when it is wrong, which is exactly the kind that
// should not be verified by looking at the picture.
export function arcLengths(counts: number[], total: number, circumference: number): number[] {
  if (total <= 0) return counts.map(() => 0)
  const raw = counts.map((count) => (count / total) * circumference)
  const floor = MIN_ARC_FRACTION * circumference

  const deficit = raw.reduce((sum, len) => sum + (len > 0 && len < floor ? floor - len : 0), 0)
  if (deficit === 0) return raw

  // Only segments already above the floor can donate, and only their excess.
  const spare = raw.map((len) => Math.max(0, len - floor))
  const totalSpare = spare.reduce((a, b) => a + b, 0)
  // Nothing can afford the floor — every segment is already tiny. Leave the true
  // proportions alone rather than distorting all of them to rescue one.
  if (totalSpare <= 0) return raw

  const scale = Math.min(1, deficit / totalSpare)
  return raw.map((len, i) => (len > 0 && len < floor ? floor : len - spare[i] * scale))
}

// isFloored reports whether a segment's true share is below the floor, i.e. its arc
// has been enlarged and is no longer to scale.
export function isFloored(count: number, total: number): boolean {
  if (total <= 0) return false
  return count > 0 && count / total < MIN_ARC_FRACTION
}
