// Detection-timing derivation, extracted from ClusterDetailPage so it can be
// tested (BACKLOG P3) — this is the one number on that page an operator plans
// around, and it is neither of the two values they configured.
import type { ClusterDetection } from '../api/types'

// detectionLatency is how long this cluster takes to notice a fault that the
// cluster itself does not timestamp — the sweep detector's slowest and most
// common path (internal/agent/sweep_detector.go sustainedLongEnough).
//
// The fault is first OBSERVED at some sweep, at most one interval after it
// began. It is then reported at the first sweep at least `threshold` after that
// observation, so the wait rounds UP to a sweep boundary rather than firing at
// the threshold exactly:
//
//   floor = ceil(threshold / interval) * interval     fault began at a sweep
//   ceiling = floor + interval                        fault began just after one
//
// Both measured data points agree (CAPABILITIES.md §6): 30s/60s predicts 60-90s
// against 61s observed, and the shipped 300s/600s defaults predict 10-15
// minutes against the ten to fifteen minutes seen on lab-dev. Stating the range
// is the point — this is the number an operator is actually waiting through,
// and it is not either of the two configured values.
export function detectionLatency(detection: ClusterDetection): { floorSeconds: number; ceilingSeconds: number } | null {
  const interval = detection.sweepIntervalSeconds
  const threshold = detection.sustainedThresholdSeconds
  if (!interval || !threshold || interval <= 0 || threshold <= 0) {
    return null
  }
  const floorSeconds = Math.ceil(threshold / interval) * interval
  return { floorSeconds, ceilingSeconds: floorSeconds + interval }
}

