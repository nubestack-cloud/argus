import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { DetectionCard, DetectionCoverageCard, RemediationAuthorityCard } from './ClusterDetailPage'

// RemediationAuthorityCard has THREE states and collapsing any two of them
// misleads an approver in a different direction (BACKLOG B4):
//
//   not reported  -> an agent too old to be asked. Unknown.
//   checked=false -> asked, no answer came back. Also unknown, and NOT a denial.
//   checked=true  -> a real per-action answer.
//
// The dangerous collapse is checked=false rendering as "not granted": it tells an
// operator remediation is unavailable when nobody could ask, and the fix for that
// (changing a chart value) is real work done for no reason.

describe('RemediationAuthorityCard', () => {
  it('says the agent has not reported, when there is nothing at all', () => {
    render(<RemediationAuthorityCard remediation={undefined} />)
    expect(screen.getByText(/hasn't reported its remediation authority/i)).toBeTruthy()
    expect(screen.queryByText(/^Not granted$/)).toBeNull()
  })

  it('treats an unanswered check as UNKNOWN, never as a denial', () => {
    render(
      <RemediationAuthorityCard
        remediation={{
          checked: false,
          canPatchDeployments: false,
          canPatchStatefulSets: false,
          canDeletePods: false,
          error: 'authorization endpoint unreachable',
        }}
      />,
    )
    expect(screen.getByText(/Unknown/i)).toBeTruthy()
    // The three false booleans must NOT be rendered as three denials.
    expect(screen.queryByText(/^Not granted$/)).toBeNull()
    expect(screen.getByText(/authorization endpoint unreachable/)).toBeTruthy()
  })

  it('renders a real all-granted answer per action', () => {
    render(
      <RemediationAuthorityCard
        remediation={{ checked: true, canPatchDeployments: true, canPatchStatefulSets: true, canDeletePods: true }}
      />,
    )
    expect(screen.getAllByText('Granted')).toHaveLength(3)
    expect(screen.queryByText('Not granted')).toBeNull()
  })

  it('reports a partial grant per action rather than rounding up to "can remediate"', () => {
    // The real workload-recovery RBAC pack: patch on the two workload kinds, no
    // delete on pods. Rounding this up would tell an approver a RestartPod plan
    // will work when it will not.
    render(
      <RemediationAuthorityCard
        remediation={{ checked: true, canPatchDeployments: true, canPatchStatefulSets: true, canDeletePods: false }}
      />,
    )
    expect(screen.getAllByText('Granted')).toHaveLength(2)
    expect(screen.getAllByText('Not granted')).toHaveLength(1)
  })

  it('when nothing is granted, says approvals will fail at execution and that the hub cannot grant it', () => {
    render(
      <RemediationAuthorityCard
        remediation={{ checked: true, canPatchDeployments: false, canPatchStatefulSets: false, canDeletePods: false }}
      />,
    )
    expect(screen.getAllByText('Not granted')).toHaveLength(3)
    expect(screen.getByText(/will fail at execution/i)).toBeTruthy()
    expect(screen.getByText(/hub cannot grant it/i)).toBeTruthy()
  })

  // B170: the chart's own recommended, least-privilege install
  // (remediate.namespaces) grants write access scoped to a namespace, which
  // correctly answers false to the cluster-wide question the three chips
  // above ask. Denying the capability outright — as this card used to —
  // hides a grant that demonstrably works. These four cover the fix.

  it('never says the cluster-wide false is the whole story when a namespace is actually granted', () => {
    render(
      <RemediationAuthorityCard
        remediation={{
          checked: true,
          canPatchDeployments: false,
          canPatchStatefulSets: false,
          canDeletePods: false,
          namespaces: [
            { namespace: 'default', canPatchDeployments: true, canPatchStatefulSets: true, canDeletePods: true },
          ],
        }}
      />,
    )
    // The cluster-wide chips are still (correctly) three denials...
    expect(screen.getAllByText('Not granted')).toHaveLength(3)
    // ...but the card must not stop there and claim the agent can change
    // nothing: the fallback "cannot change anything" copy must be absent...
    expect(screen.queryByText(/will fail at execution/i)).toBeNull()
    // ...and the real, checked, per-namespace grant must be shown.
    expect(screen.getByText(/granted in 1 of 1 namespace checked/i)).toBeTruthy()
    expect(screen.getByText('default')).toBeTruthy()
    expect(screen.getAllByText('Granted')).toHaveLength(3)
  })

  it('lists a not-granted namespace as a real checked no, not an unknown', () => {
    render(
      <RemediationAuthorityCard
        remediation={{
          checked: true,
          canPatchDeployments: true,
          canPatchStatefulSets: true,
          canDeletePods: true,
          namespaces: [
            { namespace: 'kube-system', canPatchDeployments: false, canPatchStatefulSets: false, canDeletePods: false },
          ],
        }}
      />,
    )
    // Three cluster-wide grants plus three per-namespace denials.
    expect(screen.getAllByText('Granted')).toHaveLength(3)
    expect(screen.getAllByText('Not granted')).toHaveLength(3)
    expect(screen.getByText('kube-system')).toBeTruthy()
  })

  it('states the truncation window rather than presenting a prefix as the whole list', () => {
    render(
      <RemediationAuthorityCard
        remediation={{
          checked: true,
          canPatchDeployments: false,
          canPatchStatefulSets: false,
          canDeletePods: false,
          namespaces: [
            { namespace: 'a-team', canPatchDeployments: true, canPatchStatefulSets: false, canDeletePods: false },
          ],
          namespacesTruncated: true,
        }}
      />,
    )
    expect(screen.getByText(/more may exist and were not checked this pass/i)).toBeTruthy()
  })

  it('renders no per-namespace table when the agent reported no breakdown, not a fabricated empty one', () => {
    render(
      <RemediationAuthorityCard
        remediation={{ checked: true, canPatchDeployments: false, canPatchStatefulSets: false, canDeletePods: false }}
      />,
    )
    expect(screen.queryByText(/Namespace-scoped grants/i)).toBeNull()
    expect(screen.getByText(/hub cannot grant it/i)).toBeTruthy()
  })
})

describe('DetectionCard', () => {
  it('prompts to upgrade when the agent reported no timings', () => {
    render(<DetectionCard detection={undefined} />)
    expect(screen.getByText('— not reported').getAttribute('title')).toMatch(/predates the field/i)
  })

  it('shows the derived latency range alongside the two configured values', () => {
    render(
      <DetectionCard
        detection={{ sweepIntervalSeconds: 30, sustainedThresholdSeconds: 60, resendCooldownSeconds: 300 }}
      />,
    )
    expect(screen.getByText('1m')).toBeTruthy()
    expect(screen.getByText('5m')).toBeTruthy()
    // The derived number, which is neither of the configured ones.
    expect(screen.getByText('60s–90s')).toBeTruthy()
  })

  it('omits the latency row entirely when it cannot be derived, rather than showing a wrong one', () => {
    render(<DetectionCard detection={{ resendCooldownSeconds: 300 }} />)
    expect(screen.queryByText('Detection latency')).toBeNull()
    // The cooldown it DID report is still shown.
    expect(screen.getByText('5m')).toBeTruthy()
  })
})

// DetectionCoverageCard (PROJECT.md T13) has to distinguish four states per
// detector without letting any two collapse into each other — the same
// discipline RemediationAuthorityCard's own test suite above enforces for
// its three states, applied here to the specific claim T13 exists to make
// possible: "healthy but quiet" (a real recent success, nothing else to
// report) must render differently from "not observed" (nothing reported at
// all), and a currently-denied read must be named, not just implied by a
// stale timestamp.
describe('DetectionCoverageCard', () => {
  it('says the agent has not reported detector run health, when there is nothing at all', () => {
    render(<DetectionCoverageCard detectors={undefined} />)
    expect(screen.getByText(/predates the field/i)).toBeTruthy()
    // Must not fabricate a healthy or a failing verdict from nothing.
    expect(screen.queryByText('Running')).toBeNull()
    expect(screen.queryByText('Error')).toBeNull()
  })

  // The core claim of this whole card: a real, recent success with nothing
  // else wrong must read as actively running, not as merely "not observed" —
  // that distinction is what tells an operator a quiet cluster is fine.
  it('renders a detector with a real recent success as Running, distinct from never-observed', () => {
    render(
      <DetectionCoverageCard
        detectors={{
          warningEvents: { lastSuccessAt: '2026-09-18T09:00:00Z' },
          podConditions: {},
          sweep: {},
        }}
      />,
    )
    expect(screen.getByText('Running')).toBeTruthy()
    expect(screen.getAllByText('Not yet observed')).toHaveLength(2)
    // A never-observed detector must not claim a run happened.
    expect(screen.getAllByText('Never')).toHaveLength(2)
  })

  it('names the exact denied reads for a permission-blocked detector, never just a generic warning', () => {
    render(
      <DetectionCoverageCard
        detectors={{
          warningEvents: {},
          podConditions: {},
          sweep: { lastSuccessAt: '2026-09-18T08:00:00Z', deniedReads: ['jobs', 'nodes'] },
        }}
      />,
    )
    expect(screen.getByText('Permission blocked')).toBeTruthy()
    expect(screen.getByText('jobs')).toBeTruthy()
    expect(screen.getByText('nodes')).toBeTruthy()
  })

  // A denied read is shown regardless of how recently the detector last
  // succeeded — it's true right now, not a historical fact.
  it('shows Permission blocked even when the detector has a recent success', () => {
    render(
      <DetectionCoverageCard
        detectors={{
          warningEvents: { lastSuccessAt: '2026-09-18T09:59:00Z', deniedReads: ['events'] },
          podConditions: {},
          sweep: {},
        }}
      />,
    )
    expect(screen.getByText('Permission blocked')).toBeTruthy()
    expect(screen.queryByText('Running')).toBeNull()
  })

  it('shows Error for a detector whose most recent attempt failed after its last success', () => {
    render(
      <DetectionCoverageCard
        detectors={{
          warningEvents: {
            lastSuccessAt: '2026-09-18T08:00:00Z',
            error: 'watch channel closed',
            errorAt: '2026-09-18T09:00:00Z',
          },
          podConditions: {},
          sweep: {},
        }}
      />,
    )
    expect(screen.getByText('Error')).toBeTruthy()
    expect(screen.getByText('watch channel closed')).toBeTruthy()
    // A last-successful-run time is still shown even though the current
    // state is Error — an operator needs "when did this last work" too —
    // never collapsed to "Never" just because the newest attempt failed.
    // (The other two detectors in this fixture never ran at all, so "Never"
    // legitimately appears twice — just not for warningEvents.)
    expect(screen.getAllByText('Never')).toHaveLength(2)
  })

  it('shows Running, not Error, when an old error predates a later success', () => {
    render(
      <DetectionCoverageCard
        detectors={{
          warningEvents: {
            error: 'transient reconnect',
            errorAt: '2026-09-18T08:00:00Z',
            lastSuccessAt: '2026-09-18T09:00:00Z',
          },
          podConditions: {},
          sweep: {},
        }}
      />,
    )
    expect(screen.getByText('Running')).toBeTruthy()
    expect(screen.queryByText('Error')).toBeNull()
  })

  it('renders every entry in the fixed three-detector catalogue, never a partial or dynamic list', () => {
    render(
      <DetectionCoverageCard
        detectors={{ warningEvents: {}, podConditions: {}, sweep: {} }}
      />,
    )
    expect(screen.getByText('Warning events')).toBeTruthy()
    expect(screen.getByText('Pod conditions')).toBeTruthy()
    expect(screen.getByText('Sweep')).toBeTruthy()
  })

  it('says how often each detector runs: on its watch, or the sweep interval', () => {
    render(
      <DetectionCoverageCard detectors={{ warningEvents: {}, podConditions: {}, sweep: {} }} detection={{ sweepIntervalSeconds: 30 }} />,
    )
    expect(screen.getAllByText('on watch')).toHaveLength(2)
    expect(screen.getByText('every 30s')).toBeTruthy()
  })

  // The explicit ban this feature is built under: no coverage percentage or
  // score anywhere on this card.
  it('never renders a coverage percentage or score', () => {
    render(
      <DetectionCoverageCard
        detectors={{ warningEvents: {}, podConditions: {}, sweep: {} }}
      />,
    )
    expect(screen.queryByText(/%/)).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// The three "how much of this do we actually know" facts the hub has been
// serving and no screen read (PROJECT.md B177, B176's residual, P19's
// residual). Every test below exists because the failure mode is the SAME one
// in three costumes: a reassuringly quiet detector table that is quiet for a
// reason it does not disclose. The assertions are therefore mostly negative —
// what must NOT appear — because a fabricated zero or a missing caveat looks
// exactly like a fact.
// ---------------------------------------------------------------------------

describe('DetectionCoverageCard — facts freshness (B177)', () => {
  it('renders a null factsUpdatedAt as "Not reported", never as a zero or a date', () => {
    render(<DetectionCoverageCard detectors={{ warningEvents: {}, podConditions: {}, sweep: {} }} />)
    // Scoped to the freshness line: the finding-queue block below legitimately
    // says "Not reported" too, for its own separately-null field.
    expect(document.querySelector('.card-head-meta')?.textContent).toBe('facts snapshot not reported')
    // The two shapes a fabricated freshness takes: the Go zero time the hub
    // deliberately does not send, and a relative age computed from it.
    expect(screen.queryByText(/0001/)).toBeNull()
    expect(screen.queryByText(/1970/)).toBeNull()
    expect(screen.queryByText(/from the facts snapshot/i)).toBeNull()
  })

  it('states the snapshot age, and that the detector times inside it are as old', () => {
    const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000).toISOString()
    render(
      <DetectionCoverageCard
        detectors={{ warningEvents: { lastSuccessAt: tenMinutesAgo }, podConditions: {}, sweep: {} }}
        factsUpdatedAt={tenMinutesAgo}
      />,
    )
    expect(screen.getByText(/from the facts snapshot/i)).toBeTruthy()
    // The whole point of the line: the reader is told the times below are the
    // snapshot's, not now's.
    expect(screen.getByText(/went quiet after it still reads here exactly as it did then/i)).toBeTruthy()
  })
})

describe('DetectionCoverageCard — finding queue (B176 residual)', () => {
  // The rule this card exists under: "we do not know" must never render as a
  // reassuring zero. Absent object, absent number.
  it('renders an absent finding queue as "Not reported", never as zero discarded', () => {
    render(<DetectionCoverageCard detectors={{ warningEvents: {}, podConditions: {}, sweep: {} }} />)
    expect(screen.getByText('Finding queue')).toBeTruthy()
    expect(document.querySelector('.agent-queue [title]')?.getAttribute('title')).toMatch(/unknown, not none/i)
    expect(screen.queryByText(/findings discarded/i)).toBeNull()
    expect(screen.queryByText(/none discarded/i)).toBeNull()
    expect(screen.queryByText(/\b0\b/)).toBeNull()
  })

  it('names the discarded count and the queue depth against its real bound', () => {
    render(
      <DetectionCoverageCard
        detectors={{ warningEvents: {}, podConditions: {}, sweep: {} }}
        findingQueue={{ pending: 4998, dropped: 137, capacity: 5000 }}
      />,
    )
    expect(screen.getByText(/137 findings discarded/)).toBeTruthy()
    expect(document.querySelector('.agent-queue .meter-head')?.textContent).toBe('4,998 of 5,000')
    // Attention treatment, but the sentence carries the claim — never the
    // colour alone (lld/11 §8).
    expect(document.querySelector('.banner-attention')).toBeTruthy()
  })

  // The caveat is what makes the number readable at all, so it travels with
  // the number in BOTH populated cases — including the zero, which otherwise
  // reads as "nothing has ever been dropped here".
  it('states the per-process reset window beside the number, in both populated cases', () => {
    const { unmount } = render(
      <DetectionCoverageCard
        detectors={{ warningEvents: {}, podConditions: {}, sweep: {} }}
        findingQueue={{ pending: 4998, dropped: 137, capacity: 5000 }}
      />,
    )
    expect(screen.getByText(/a restart resets the total to zero/i)).toBeTruthy()
    expect(screen.getByText(/per-process figure, not a lifetime one/i)).toBeTruthy()
    unmount()

    render(
      <DetectionCoverageCard
        detectors={{ warningEvents: {}, podConditions: {}, sweep: {} }}
        findingQueue={{ pending: 3, dropped: 0, capacity: 5000 }}
      />,
    )
    expect(screen.getByText('none discarded')).toBeTruthy()
    expect(document.querySelector('.agent-queue .meter-head')?.textContent).toBe('3 of 5,000')
    expect(screen.getByText(/a restart resets the total to zero/i)).toBeTruthy()
    // A real, reported zero is not an attention state.
    expect(document.querySelector('.banner-attention')).toBeNull()
  })

  // The queue is reported on the heartbeat, not in `facts` — an agent too old
  // to report detector health can still be reporting its queue, and dropping
  // the queue with the table would hide the more alarming of the two.
  it('still renders the queue when the agent reports no detector health at all', () => {
    render(<DetectionCoverageCard detectors={undefined} findingQueue={{ pending: 1, dropped: 9, capacity: 5000 }} />)
    expect(screen.getByText(/predates the field/i)).toBeTruthy()
    expect(screen.getByText(/9 findings discarded/)).toBeTruthy()
  })
})

describe('DetectionCoverageCard — timed-out checks (P19 residual)', () => {
  // The exact wire shape a timed-out sweep pass produces: internal/agent's
  // recordCheckerTimeout writes the prefixed error AND the pass's own success
  // at the same instant, so errorAt === lastSuccessAt. With the old
  // `errorAt >= lastSuccessAt` rule that read as a flat failure.
  it('renders a timed-out pass as Degraded, not Error, and names the checks', () => {
    render(
      <DetectionCoverageCard
        detectors={{
          warningEvents: {},
          podConditions: {},
          sweep: {
            lastSuccessAt: '2026-09-18T09:00:00Z',
            error: 'sweep checker timeout: service no endpoints, pvc pending (no response within 30s)',
            errorAt: '2026-09-18T09:00:00Z',
            timedOutChecks: ['service no endpoints', 'pvc pending'],
          },
        }}
      />,
    )
    expect(screen.getByText('Degraded')).toBeTruthy()
    expect(screen.queryByText('Error')).toBeNull()
    expect(screen.getByText(/2 checks did not answer/)).toBeTruthy()
    expect(screen.getByText(/service no endpoints, pvc pending/)).toBeTruthy()
  })

  it('says the last pass is what this describes, so it is not read as standing history', () => {
    render(
      <DetectionCoverageCard
        detectors={{
          warningEvents: {},
          podConditions: {},
          sweep: {
            lastSuccessAt: '2026-09-18T09:00:00Z',
            errorAt: '2026-09-18T09:00:00Z',
            error: 'sweep checker timeout: pvc pending',
            timedOutChecks: ['pvc pending'],
          },
        }}
      />,
    )
    expect(screen.getByText(/1 check did not answer/)).toBeTruthy()
    expect(screen.getByText('The rest of the pass completed.').getAttribute('title')).toMatch(/A clean pass clears this/i)
  })

  // A clean pass clears the field, and the row must go straight back to
  // Running — the opposite contract to error/errorAt, which are never cleared.
  it('returns to Running once a clean pass clears the field', () => {
    render(
      <DetectionCoverageCard
        detectors={{
          warningEvents: {},
          podConditions: {},
          sweep: { lastSuccessAt: '2026-09-18T09:05:00Z', timedOutChecks: [] },
        }}
      />,
    )
    expect(screen.getByText('Running')).toBeTruthy()
    expect(screen.queryByText('Degraded')).toBeNull()
    expect(screen.queryByText(/did not answer/)).toBeNull()
  })

  // A real failure outranks a timeout in the same pass — the hub orders it the
  // same way (internal/api/diagnostics.go), because a refused read is the more
  // actionable of the two. The hung checks are still named rather than hidden.
  it('keeps Error for a genuine failure that also timed a check out, and still names it', () => {
    render(
      <DetectionCoverageCard
        detectors={{
          warningEvents: {},
          podConditions: {},
          sweep: {
            lastSuccessAt: '2026-09-18T08:00:00Z',
            error: 'jobs: forbidden',
            errorAt: '2026-09-18T09:00:00Z',
            timedOutChecks: ['pvc pending'],
          },
        }}
      />,
    )
    expect(screen.getByText('Error')).toBeTruthy()
    expect(screen.getByText('jobs: forbidden')).toBeTruthy()
    expect(screen.getByText(/1 check did not answer/)).toBeTruthy()
  })

  // An agent that predates timedOutChecks records the same fact only in the
  // prefixed Error text. It must keep saying something rather than silently
  // reading as healthy.
  it('still reports an old agent’s timeout, which it can only express through Error', () => {
    render(
      <DetectionCoverageCard
        detectors={{
          warningEvents: {},
          podConditions: {},
          sweep: {
            lastSuccessAt: '2026-09-18T09:00:00Z',
            error: 'sweep checker timeout: pvc pending (no response within 30s)',
            errorAt: '2026-09-18T09:00:00Z',
          },
        }}
      />,
    )
    expect(screen.getByText('Error')).toBeTruthy()
    expect(screen.getByText(/sweep checker timeout: pvc pending/)).toBeTruthy()
  })
})
