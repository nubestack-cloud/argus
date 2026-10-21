import { describe, expect, it } from 'vitest'
import {
  DETECTOR_OPTIONS,
  detectionSourceFor,
  detectionSourceKinds,
  detectorShortLabel,
} from './detectors'

// These cover the two places this module is allowed to be silent and the one
// place it is not allowed to guess. They deliberately do NOT assert that the
// three ids here match internal/api/settings.go's knownDetectorIDs: both sides
// are hand-maintained literals, so a hand-maintained list in a test cannot
// guard a hand-maintained list in code — it would only restate it. The real
// cross-reference is the comment at the top of detectors.ts.

describe('detectionSourceFor', () => {
  it('classifies the warning-events detector as the event-backed kind', () => {
    expect(detectionSourceFor('k8s-warning-events')?.sourceKind).toBe('kubernetesEvent')
  })

  it('classifies BOTH of the non-event detectors as ARGUS checks', () => {
    // The product claim rests on this pair: the sweep detector runs its own
    // predicates, and the pod-conditions detector reads Pod status directly
    // precisely because a matching Warning event may not exist
    // (internal/agent/pod_conditions_detector.go's own doc comment).
    expect(detectionSourceFor('k8s-sweep')?.sourceKind).toBe('argusCheck')
    expect(detectionSourceFor('k8s-pod-conditions')?.sourceKind).toBe('argusCheck')
  })

  it('returns null rather than a default for an id it has never heard of', () => {
    // Both of these are real ids in real databases.
    expect(detectionSourceFor('smoketest-detector')).toBeNull()
    expect(detectionSourceFor('test-detector')).toBeNull()
    expect(detectionSourceFor('')).toBeNull()
  })
})

describe('detectorShortLabel', () => {
  it('gives a readable name for a known detector', () => {
    expect(detectorShortLabel('k8s-sweep')).toBe('ARGUS sweep')
  })

  it('falls back to printing the raw id, so an unknown detector is never hidden', () => {
    expect(detectorShortLabel('some-future-detector')).toBe('some-future-detector')
  })
})

describe('detectionSourceKinds', () => {
  it('reports one kind when every finding came from the same side', () => {
    expect(detectionSourceKinds(['k8s-sweep', 'k8s-sweep', 'k8s-pod-conditions']).size).toBe(1)
  })

  it('reports two kinds for an incident correlating a sweep and a forwarded event', () => {
    const kinds = detectionSourceKinds(['k8s-sweep', 'k8s-warning-events'])
    expect(kinds.size).toBe(2)
    expect(kinds.has('argusCheck')).toBe(true)
    expect(kinds.has('kubernetesEvent')).toBe(true)
  })

  it('ignores unknown ids instead of counting them as a second kind', () => {
    // Otherwise a fixture detector would make a single-source incident render
    // the "more than one kind" note, which is the same fabrication in reverse.
    expect(detectionSourceKinds(['k8s-sweep', 'smoketest-detector']).size).toBe(1)
    expect(detectionSourceKinds([]).size).toBe(0)
  })
})

describe('DETECTOR_OPTIONS', () => {
  it('keeps the fixed display order the Settings checkboxes render in', () => {
    expect(DETECTOR_OPTIONS.map((d) => d.id)).toEqual([
      'k8s-warning-events',
      'k8s-pod-conditions',
      'k8s-sweep',
    ])
  })

  it('gives every entry a label, a description and a source sentence', () => {
    for (const d of DETECTOR_OPTIONS) {
      expect(d.label.length).toBeGreaterThan(0)
      expect(d.description.length).toBeGreaterThan(0)
      expect(d.sentence.length).toBeGreaterThan(0)
      expect(d.shortLabel.length).toBeGreaterThan(0)
    }
  })
})
