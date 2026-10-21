// The analysis panel of the incident-detail screen: the Analyze/Download
// report actions, the per-tool-call evidence chips, the causal-chain steps,
// the recent-changes list, and the AnalysisView card that assembles them —
// split out of IncidentDetailPage.tsx (PROJECT.md P25) with no behavior
// change. See that file's own header for the screen this panel belongs to.
import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import type { UseMutationResult } from '@tanstack/react-query'
import { getEvidence, ApiError, PROBLEM_LLM_NOT_CONFIGURED } from '../../api/client'
import { CAP_ORG_SETTINGS_WRITE } from '../../api/capabilities'
import { useHasCapability } from '../../auth/useCapabilities'
import type {
  Analysis,
  AnalysisStarted,
  AnalysisStep,
  EvidenceSummary,
  IncidentDetail,
  RecentChange,
  RecentChangesView,
  ToolCall,
} from '../../api/types'
import { useAuth } from '../../auth/useAuth'
import { formatDateTime, formatRelativeTime } from '../../utils/time'
import { SkeletonLines } from '../../components/Skeleton'
import { ConclusionBlock } from '../../components/AnalysisConclusion'
import { AiClaim } from '../../components/AiClaim'
import { Reproducer } from '../../components/Reproducer'
import { objectRefFromToolCall, reproducerFor } from '../../evidence/reproducer'
import { useOpenObject } from '../../insight/useOpenObject'
import { PathTraceView } from '../../insight/views/PathTraceView'
import { isTraceResult } from '../../insight/pathTrace'
import { RECENT_CHANGE_LABELS, dedupeRecentChanges, toolLabel } from '../incidentLifecycle'
import { buildIncidentReportMarkdown, reportFileName } from '../incidentReport'

// Starts the bounded, tool-calling investigation loop (POST .../analyze).
// PROJECT.md M1: the request answers 202 as soon as the run is claimed and
// the investigation continues server-side, so "is it running" is the
// incident's own state (`investigating`, true in every tab), not this
// mutation's pending flag — that is only the claim's round trip. Likewise a
// run that fails after the 202 reports through the incident (`runError`,
// GET /incidents/{id}'s analysisError), never through this mutation, whose
// own error now only covers a refused start (409 already running, 503 no
// agent / no provider). Disabled, not hidden, when the caller lacks
// incident:reanalyse (lld/11-ui-design.md §6) — the button stays visible so
// a viewer discovers the capability exists, matching every other action
// control in this app.
export function AnalyzeButton({
  mutation,
  disabledReason,
  hasAnalysis,
  investigating = false,
  runError,
}: {
  mutation: UseMutationResult<AnalysisStarted, Error, void>
  disabledReason?: string
  hasAnalysis: boolean
  investigating?: boolean
  runError?: string | null
}) {
  const busy = mutation.isPending || investigating
  const canSetUp = useHasCapability(CAP_ORG_SETTINGS_WRITE)
  const failed = mutation.isError ? mutation.error : null
  const showRunError = !busy && !failed && !!runError
  // The failure floats under the button rather than in the row, so it never
  // moves the header's other actions, and it can be put away. A new failure
  // (a fresh attempt, or a different run error) shows it again.
  const [dismissedFor, setDismissedFor] = useState<unknown>(null)
  const failureKey = failed ? mutation.failureCount + ':' + mutation.submittedAt : showRunError ? runError : null
  const calloutOpen = failureKey !== null && dismissedFor !== failureKey
  useEffect(() => {
    if (!calloutOpen) return
    const escape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setDismissedFor(failureKey)
    }
    document.addEventListener('keydown', escape)
    return () => document.removeEventListener('keydown', escape)
  }, [calloutOpen, failureKey])

  // Opens toward the side with room: from the button's right edge when the
  // button sits near the right of the screen, as it does in the header.
  const calloutRef = useRef<HTMLDivElement>(null)
  const [alignEnd, setAlignEnd] = useState(false)
  useLayoutEffect(() => {
    const el = calloutRef.current
    if (!calloutOpen || !el) return
    const anchor = el.parentElement!.getBoundingClientRect()
    setAlignEnd(anchor.left + el.offsetWidth > document.documentElement.clientWidth)
  }, [calloutOpen, failureKey])

  const noProvider = failed instanceof ApiError && failed.type === PROBLEM_LLM_NOT_CONFIGURED
  return (
    <div className="analyze-control">
      {/* Filled only while analysis is the next move. Once there is one,
          the next move is the fix or the close-out, and the page allows one
          filled button per state (PROJECT.md UX1). */}
      <button
        type="button"
        className={hasAnalysis ? 'secondary' : undefined}
        onClick={() => mutation.mutate()}
        disabled={busy || !!disabledReason}
        title={disabledReason}
      >
        {busy ? 'Investigating…' : hasAnalysis ? 'Re-analyze' : 'Analyze incident'}
      </button>
      {/* BACKLOG.md D9 U4: `title` above is unreachable by keyboard (a
          disabled button is never focusable) and by touch — RepositoryChangePanel's
          own comment names this exact rule (lld/11 §6). The reason is why the
          BUTTON is disabled, not a load-bearing error, so this reads as a
          plain hint rather than `.form-error`. */}
      {disabledReason && <p className="field-hint">{disabledReason}</p>}
      {calloutOpen && (
        <div ref={calloutRef} className={`anchored-callout${alignEnd ? ' anchored-callout-end' : ''}`} role="alert">
          <div className="anchored-callout-body">
            {noProvider ? (
              <>
                <strong>No AI provider is set up</strong>
                <p>ARGUS needs one to investigate. Incidents are still detected without it.</p>
                {canSetUp ? (
                  <Link to="/settings?section=providers">Set up an AI provider</Link>
                ) : (
                  <p>Ask an administrator to add one in Settings → AI providers.</p>
                )}
              </>
            ) : failed ? (
              <>
                <strong>The analysis could not start</strong>
                <p>
                  {failed instanceof ApiError
                    ? failed.detail
                      ? `${failed.message} — ${failed.detail}`
                      : failed.message
                    : 'Something went wrong.'}
                </p>
              </>
            ) : (
              <>
                <strong>The last analysis did not complete</strong>
                <p>{runError}</p>
              </>
            )}
          </div>
          <button
            type="button"
            className="link-button anchored-callout-close"
            aria-label="Dismiss"
            title="Dismiss"
            onClick={() => setDismissedFor(failureKey)}
          >
            ×
          </button>
        </div>
      )}
    </div>
  )
}

// DownloadReportButton — PROJECT.md T17: the one action that produces this
// incident's durable, out-of-band report. Deliberately makes no request of
// its own — `incident` is exactly the IncidentDetail this page's own
// useQuery already fetched and is rendering above, and
// incidentReport.ts's buildIncidentReportMarkdown is a pure function of it
// (see that file's own header comment for why that is the whole point: a
// second query or a second derivation here is exactly the
// two-renderings-can-disagree defect this board has already hit once).
// `secondary`, matching this row's own Cancel/Reject precedent — this reads
// the incident, it does not act on it, so it should not compete visually
// with Analyze or Close out. The only failure mode is the browser's own
// Blob/download plumbing, which is the only error state this needs; there
// is no loading or empty state because this is never rendered before
// `data` exists (see this component's own mount point, inside `{data &&
// (...)}` below, matching AnalyzeButton/TriageControls).
export function DownloadReportButton({ incident }: { incident: IncidentDetail }) {
  const [error, setError] = useState<string | null>(null)

  function download() {
    setError(null)
    try {
      const markdown = buildIncidentReportMarkdown(incident)
      const blob = new Blob([markdown], { type: 'text/markdown;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = reportFileName(incident)
      document.body.appendChild(link)
      link.click()
      link.remove()
      URL.revokeObjectURL(url)
    } catch {
      setError('Could not build the report file — try again, or copy the page instead.')
    }
  }

  return (
    <div>
      <button type="button" className="secondary" onClick={download}>
        Download report
      </button>
      {error && (
        <p className="form-error inline-error" role="alert">
          {error}
        </p>
      )}
    </div>
  )
}

// One tool call behind a causal-chain step, as a `.evidence-chip` (the D7/D8
// vocabulary's primitive for exactly this — "one tool call, named" — built
// for this page and never applied here until now). Still collapsed by
// default (lld/11-ui-design.md §4's "never assert a root cause without
// letting the user open the evidence") — only the AFFORDANCE changed, from a
// <details>/<summary> to a toggle button, so the chip can sit inline in a
// wrapped row of its siblings the way `.tool-call`'s block-level <details>
// never could. args/result/error are cluster-derived, untrusted JSON — plain
// JSX interpolation only, same rule as Finding.reason/message elsewhere in
// this app; never dangerouslySetInnerHTML (SR-17).
//
// `flexBasis: '100%'` when open is deliberate, not decorative: `.chain-node-
// evidence` is a wrapped flex row of same-sized chips, and the args/result
// detail needs the row's full width to be readable — forcing this one item
// onto its own line rather than squeezing a JSON dump into a chip-width
// column.
//
// BACKLOG.md B2: opening a chip now fetches GET .../evidence/{evId} (via
// call.evidenceId) instead of only reading the inline call.args/call.result
// analysis.causalChain already carries. Two reasons to fetch rather than
// just render what is already in hand:
//   - The lazy endpoint is the real architecture lld/11-ui-design.md §4
//     specifies; the inline copy is `ToolCallRecord`'s own documented MVP
//     simplification, kept only because dropping it would be a wire
//     contract change to every stored analysis.
//   - It carries `redacted`/`capturedAt`, which the inline copy does not —
//     and B2's own scoping note requires surfacing the redaction marker
//     rather than letting the drill-down imply raw cluster content.
// Falling back to the inline call.args/call.result/call.error — for a call
// with no evidenceId (an analysis stored before B2 landed), while the fetch
// is in flight, or if it fails — is never a lie: they are documented to be
// the SAME bytes the evidence row stores, not a lesser copy.
//
// UPDATED by BACKLOG.md C10: this used to also be the whole answer to the
// cli-backend gap ("its causalChain is always empty, so no ToolCallChip is
// ever mounted for a cli-backend analysis at all"). That is no longer true —
// the cli backend now self-reports a chain and cross-checks every citation
// against the hub's own record of what it actually served (PROJECT.md B151:
// both call existence AND, when the finding states a checkable value, that
// value's agreement with the real result — internal/llm.crossCheckCausalChain).
// A cli-backend ToolCall never carries evidenceId (there is no dispatched-
// call record to fetch — see ToolCall.evidenceId's own doc comment on when
// it's set), so this chip always falls back to the inline
// call.args/call.result/call.error for one — which, for a self-reported
// citation, means there is no real args/result at all to show, only the
// model's own prose (the REAL content B151 added is checked server-side and
// never round-tripped into this field, precisely so nothing here ever looks
// like a bare "null" where evidence would normally be). The
// `provenance`/`corroborated` handling below is what keeps that self-reported
// content from ever being confused with the api backend's real, hub-
// dispatched evidence.
export function ToolCallChip({
  call,
  incidentId,
  provenance,
  clusterId,
  clusterName,
}: {
  call: ToolCall
  incidentId: string
  // CI-S6/CI-U9: the cluster the call ran against, so the chip can open the
  // object it was about in the inspector and name the cluster beside its
  // reproducer command. Absent → neither affordance is offered.
  clusterId?: string
  clusterName?: string
  // BACKLOG.md C10 / PROJECT.md B151: only a 'self-reported' chain's
  // call.corroborated means anything (see ToolCall.corroborated's own doc
  // comment for its four states) — passed down from the analysis rather
  // than read off `call` alone, so a 'hub-observed' chain's calls (real by
  // construction, corroborated always absent there) can never be mismarked.
  provenance?: 'hub-observed' | 'self-reported'
}) {
  const [open, setOpen] = useState(false)
  const { accessToken } = useAuth()
  const openObject = useOpenObject()

  const evidenceQuery = useQuery({
    queryKey: ['incidents', incidentId, 'evidence', call.evidenceId],
    queryFn: () => getEvidence(incidentId, call.evidenceId!, accessToken!),
    enabled: open && !!call.evidenceId && !!accessToken,
    // One tool call's own record never changes once captured — no reason to
    // ever refetch it.
    staleTime: Infinity,
    retry: false,
  })
  const evidence = evidenceQuery.data
  const args = evidence?.args ?? call.args
  const result = evidence ? evidence.result ?? null : call.result
  const error = evidence ? (evidence.error ?? null) : call.error
  // Redaction happens at the tunnel unconditionally, for every tool call,
  // before any of this content ever reaches the hub (BUGS.md 84, G8) — so
  // this is true of the inline fallback too, not only a fetched row; stated
  // plainly either way rather than only when the fetch happens to land.
  const showLoadingHint = evidenceQuery.isLoading && !!call.evidenceId
  const argRecord = (args ?? {}) as Record<string, unknown>
  const target = clusterId ? objectRefFromToolCall(call.tool, argRecord, clusterId) : null
  const command = reproducerFor(call.tool, argRecord)

  return (
    <div style={open ? { flexBasis: '100%' } : undefined}>
      <button type="button" className="evidence-chip" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        <svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" aria-hidden="true">
          <path d="M9 2H4a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V6z" />
          <path d="M9 2v4h4" />
        </svg>
        {toolLabel(call.tool)}
        {call.error && <span className="badge badge-red">error</span>}
        {/* PROJECT.md B151: a self-reported chain's own four-state verdict,
            always shown in the COLLAPSED view — never only on expand, since
            that used to be one click deeper than the signal a reviewer
            approving a live action might stop at. Colour follows this app's
            existing severity vocabulary, never carries the claim alone (the
            word is the claim; colour is the addition, lld/11 §8):
              - unverified (amber): the model cited a tool call ARGUS never
                actually served at all — this app's existing "we don't
                actually know" vocabulary (RemediationPlanCard's "Outcome
                unknown"), never red, since this is an epistemic gap about
                the CALL, not a confirmed contradiction of a VALUE.
              - unchecked (gray, informational, not a warning): the call
                genuinely happened, but the finding stated nothing checkable,
                or no content exists to check it against.
              - contradicted (red): the call happened, AND a specific value
                it cited does NOT match what that call actually returned —
                the exact gap that let a live CreateResource execution write
                factually wrong data past a step that used to read merely
                "corroborated: true". This is this badge's most serious
                state, matching .badge-red's existing danger meaning.
              - corroborated (green): the call happened, AND every checkable
                value it cited matched the real result — a genuinely
                stronger, earned claim than the old bool ever supported. */}
        {provenance === 'self-reported' && call.corroborated === 'unverified' && (
          <span
            className="badge badge-amber"
            title="ARGUS could not confirm this tool call actually happened — the hub's own record of tool calls served for this investigation has no matching call. Shown as-reported, not as evidence."
          >
            unverified
          </span>
        )}
        {provenance === 'self-reported' && call.corroborated === 'unchecked' && (
          <span
            className="badge badge-gray"
            title="ARGUS confirmed the hub actually served a tool call of this name, but the finding above states no specific value that could be checked against that call's real result — only that the call happened."
          >
            unchecked
          </span>
        )}
        {provenance === 'self-reported' && call.corroborated === 'contradicted' && (
          <span
            className="badge badge-red"
            title="ARGUS confirmed the hub served this tool call, but a specific value the finding above cites does NOT match what that call actually returned. Treat the finding's stated values as unreliable."
          >
            contradicted
          </span>
        )}
        {provenance === 'self-reported' && call.corroborated === 'corroborated' && (
          <span
            className="badge badge-green"
            title="ARGUS confirmed the hub served this tool call, and every specific value the finding above cites matches what that call actually returned."
          >
            corroborated
          </span>
        )}
      </button>
      {open && (
        <div className="tool-call-body">
          {/* BACKLOG.md C10: a self-reported citation never carries real
              args/result — the model names a tool it says it called, not the
              bytes that call sent or received (causalChainStepWire's own doc
              comment: asking for them would just invite inventing
              plausible-looking ones). Saying that plainly beats falling
              through to the args/result blocks below, which would render as
              a bare "null" — a drill-down affordance with genuinely nothing
              behind it, on a screen whose whole premise is that a
              conclusion's evidence must be real. */}
          {provenance === 'self-reported' ? (
            <p className="field-hint">
              {call.corroborated === 'unverified' &&
                'ARGUS has no record of the hub ever serving this tool call for this investigation. The model reported making it; that report is unverified and is not evidence.'}
              {call.corroborated === 'unchecked' &&
                'ARGUS confirmed the hub actually served this tool call, but the finding above states no specific value that could be checked against it — only that the call happened (see the finding above for what the model reports it found).'}
              {call.corroborated === 'contradicted' &&
                'ARGUS confirmed the hub served this tool call, but a specific value the finding above cites does NOT match what that call actually returned. Treat the finding’s stated values as unreliable.'}
              {call.corroborated === 'corroborated' &&
                'ARGUS confirmed the hub served this tool call, and every specific value the finding above cites matches what that call actually returned.'}
            </p>
          ) : (
            <>
              <p className="field-hint">
                Secret values are redacted before this leaves the cluster.
                {evidence && (
                  <span title={formatDateTime(evidence.capturedAt)}> Captured {formatRelativeTime(evidence.capturedAt)}.</span>
                )}
              </p>
              {(target || command) && (
                <div className="tool-call-actions">
                  {target && (
                    <button type="button" className="link-button" onClick={() => openObject(target)}>
                      Open {target.kind} {target.name} in the inspector
                    </button>
                  )}
                  {command && <Reproducer command={command} clusterName={clusterName} />}
                </div>
              )}
              {showLoadingHint ? (
                <SkeletonLines count={2} />
              ) : (
                <>
                  {/* CI-S3/CI-U11: a path trace leads with its headline and
                      hop chain; the raw JSON stays below for audit. */}
                  {call.tool === 'trace_service_path' && !error && isTraceResult(result) && (
                    <PathTraceView trace={result} clusterName={clusterName} />
                  )}
                  <p className="field-hint">Arguments</p>
                  <pre>{JSON.stringify(args, null, 2)}</pre>
                  <p className="field-hint">{error ? 'Error' : 'Result'}</p>
                  <pre>{error ?? JSON.stringify(result, null, 2)}</pre>
                </>
              )}
            </>
          )}
        </div>
      )}
    </div>
  )
}

// One step in the vertical causal chain: what was being investigated, the
// evidence gathered to check it, and what was concluded. A plain connected
// list rather than a real graph-layout component — lld/11-ui-design.md §3
// eventually calls this a CausalChainGraph, but a graph-layout library is
// out of scope for this round; this reads top-to-bottom as "first this was
// checked, then this," which is the actual requirement.
//
// `.chain-node`, not the pre-refresh `.causal-step` this replaces — the D7/D8
// vocabulary's own naming table (index.css) was written FOR this exact page
// and had never been applied here (BACKLOG D8). `sev-neutral` throughout
// rather than inventing a per-step severity: AnalysisStep carries no severity
// field, and colour-ranking reasoning steps the model didn't rate would be a
// fabricated signal, not a styling choice.
export function CausalStep({
  step,
  incidentId,
  provenance,
  clusterId,
  clusterName,
}: {
  step: AnalysisStep
  incidentId: string
  provenance?: 'hub-observed' | 'self-reported'
  clusterId?: string
  clusterName?: string
}) {
  // The chain is drawn open (lifecycle redesign, 2026-10-12), so a long
  // finding is clamped to two lines with its own "more" — the step's claim and
  // its evidence chips stay visible, and the full text is one click away
  // rather than pushing the fix a screen further down per step.
  const long = step.finding.length > 180
  const [expanded, setExpanded] = useState(false)
  return (
    <li className="chain-node sev-neutral">
      <span className="chain-node-track" aria-hidden="true">
        <span className="chain-node-dot" />
      </span>
      <div className="chain-node-body">
        {/* CI-U3: the hypothesis and the finding are the model's words; the
            evidence chips below are what it observed. */}
        <AiClaim>
          <p className="chain-node-text chain-node-hypothesis">{step.hypothesis}</p>
          <p className={`chain-node-text${long && !expanded ? ' chain-node-clamped' : ''}`}>
            <strong>Finding:</strong> {step.finding}
          </p>
          {long && (
            <button type="button" className="link-button chain-node-more" aria-expanded={expanded} onClick={() => setExpanded((e) => !e)}>
              {expanded ? 'Show less' : 'Show the full finding'}
            </button>
          )}
        </AiClaim>
        {step.toolCalls.length > 0 && (
          <div className="chain-node-evidence">
            {step.toolCalls.map((call, i) => (
              <ToolCallChip key={i} call={call} incidentId={incidentId} provenance={provenance} clusterId={clusterId} clusterName={clusterName} />
            ))}
          </div>
        )}
      </div>
    </li>
  )
}

// Human-readable labels for the hub's MCP tool names. The raw names are
// protocol identifiers (get_gitops_ownership), and "2 × get_gitops_ownership"
// asks the reader to parse an API surface to find out what the investigation
// did — which is the opposite of what this line exists for.
//
// Deliberately a plain lookup with a fallback rather than a required exhaustive
// map: the tool surface is defined in Go (llm.InvestigationToolSchemas) and a
// new tool can land there without this file being touched, so an unknown name
// must still read acceptably ("get_owner_chain" -> "owner chain") instead of
// rendering blank or throwing.
// toolLabel moved to incidentLifecycle.ts (PROJECT.md T17) — same reasoning
// as OWNERSHIP_COPY above: incidentReport.ts's Markdown generator names the
// same tools this page does, from the same map.

// "Evidence gathered: 13 tool calls — 5 × events, 4 × describe resource, …"
//
// The whole point of the feature (BACKLOG.md D3): the cli
// backend returns no causal chain, so without this the card above is a verdict
// with no visible work behind it, which reads as oracular rather than
// auditable.
//
// Caller renders this ONLY when there is something to report — see
// EvidenceSummary's own doc comment for why an incident with no recorded calls
// must show nothing here rather than "0 tool calls". This component therefore
// never has an empty state, by construction.
//
// Ordered by count, descending, with a label tiebreak. Ordering by count puts
// what the investigation leaned on first; the tiebreak is there so two tools
// with equal counts do not swap places between renders (the hub sends an object
// whose key order is not a contract).
export function EvidenceGathered({ evidence }: { evidence: EvidenceSummary }) {
  const breakdown = Object.entries(evidence.byTool)
    .sort((a, b) => b[1] - a[1] || toolLabel(a[0]).localeCompare(toolLabel(b[0])))
    .map(([tool, count]) => `${count} × ${toolLabel(tool)}`)
    .join(', ')

  return (
    <p className="field-hint">
      Evidence gathered: {evidence.totalCalls.toLocaleString()} tool call
      {evidence.totalCalls === 1 ? '' : 's'}
      {evidence.failedCalls > 0 && (
        <span title="A tool call that failed is still evidence — what a failed lookup rules out is often what moved the investigation forward. Failed calls are included in the total.">
          , {evidence.failedCalls} failed
        </span>
      )}
      {breakdown && ` — ${breakdown}`}
    </p>
  )
}

// RECENT_CHANGE_LABELS moved to incidentLifecycle.ts (PROJECT.md T17) so this
// page and incidentReport.ts's Markdown generator read the same closed-set
// labels rather than each keeping its own copy — see that file's own comment
// on the four tables it now holds.

// One entry in PROJECT.md T15's bounded "recent changes" list. Reuses
// `.chain-list`/`.chain-node` verbatim, same rationale as TimelineEventNode
// below: a flat, ordered, dot-and-line list is exactly this shape, and a
// change fact carries no severity of its own — `sev-neutral` throughout,
// matching that component's own reasoning, not a fabricated severity
// ranking. `.evidence-chip` here is a plain, non-interactive label (unlike
// ToolCallChip's button): this feature has no per-item drill-down endpoint,
// only the tool name the fact is source-labelled with.
export function RecentChangeNode({ change, seen = 1 }: { change: RecentChange; seen?: number }) {
  const identity =
    change.objectKind &&
    `${change.objectKind} ${change.objectNamespace ? `${change.objectNamespace}/` : ''}${change.objectName ?? ''}`.trim()
  return (
    <li className="chain-node sev-neutral">
      <span className="chain-node-track" aria-hidden="true">
        <span className="chain-node-dot" />
      </span>
      <div className="chain-node-body">
        <p className="chain-node-text">
          {RECENT_CHANGE_LABELS[change.category] ?? change.category}
          {identity && (
            <>
              {' — '}
              <code>{identity}</code>
            </>
          )}
        </p>
        {/* reason/message are a Kubernetes Event's own text, already
            redacted agent-side before this ever reached the hub
            (internal/redact's pattern layer — argus-context non-negotiable
            9) — untrusted cluster-derived content, plain JSX interpolation
            only, same rule as Finding.message elsewhere on this page. */}
        {change.message && <p className="field-hint">{change.message}</p>}
        <p className="field-hint">
          <span title={formatDateTime(change.time)}>{formatRelativeTime(change.time)}</span>
          {' · '}
          <span className="evidence-chip">{toolLabel(change.source)}</span>
          {seen > 1 && <span className="field-hint">{` · seen in ${seen} tool calls`}</span>}
        </p>
      </div>
    </li>
  )
}

// PROJECT.md T15's bounded "recent changes" — what preceded this incident's
// first finding, read only from evidence the investigation already
// gathered (internal/api/incidents.go's getRecentChanges), never a fresh
// cluster query.
//
// Called UNCONDITIONALLY from AnalysisView, unlike EvidenceGathered's
// `evidence && <EvidenceGathered/>` gate just below — this component itself
// decides what null means, because null and "non-null with empty items" must
// render DIFFERENTLY (the whole point of the acceptance bar this exists to
// satisfy):
//   - null: nothing was ever recorded to look through. Renders NOTHING,
//     matching EvidenceGathered's own convention for the identical "not
//     recorded" case on the sibling field it is named after.
//   - non-null, items empty: the investigation genuinely looked and found
//     no relevant change. Rendered as an EXPLICIT sentence naming the
//     window actually checked — silence here would read as "unexamined",
//     which is a different, false claim.
//   - non-null, items present: the chronological list, oldest first —
//     already ordered and capped server-side (recentChangeWindow/
//     maxRecentChangeItems), never re-sorted or re-capped here.
const RECENT_CHANGES_PREVIEW = 5

export function RecentChanges({ recentChanges }: { recentChanges: RecentChangesView | null }) {
  const [showAll, setShowAll] = useState(false)
  if (!recentChanges) return null
  const rows = dedupeRecentChanges(recentChanges.items)
  const shown = showAll ? rows : rows.slice(0, RECENT_CHANGES_PREVIEW)
  return (
    <details className="recent-changes-disclosure">
      <summary>
        <span className="recent-changes-title">Recent changes</span>
        <span className="field-hint">
          {rows.length === 0
            ? ` — none in the ${recentChanges.windowHours}h before the first finding`
            : ` — ${rows.length} distinct change${rows.length === 1 ? '' : 's'}${recentChanges.truncated ? ' (most recent only)' : ''}`}
        </span>
      </summary>
      {rows.length > 0 ? (
        <>
          <ol className="chain-list">
            {shown.map((r, i) => (
              <RecentChangeNode key={i} change={r.change} seen={r.seen} />
            ))}
          </ol>
          {rows.length > RECENT_CHANGES_PREVIEW && (
            <button type="button" className="link-button" onClick={() => setShowAll((v) => !v)}>
              {showAll ? 'Show fewer' : `Show all ${rows.length}`}
            </button>
          )}
          {recentChanges.truncated && <p className="field-hint">Showing the most recent changes only.</p>}
        </>
      ) : (
        <p className="empty-state">
          No recorded change in the {recentChanges.windowHours}h before this incident's first finding.
        </p>
      )}
    </details>
  )
}

// The full analysis: causal chain, ruled-out hypotheses (kept visually
// distinct — explicitly what was disproved, not part of the reasoning that
// led anywhere), the conclusion, and quiet run metadata.
//
// `evidence` is the incident's, not this analysis's (see EvidenceSummary), and
// is passed in here rather than rendered as a sibling card purely for reading
// order: "what it concluded, what it looked at, what it cost" belongs in one
// block. An investigation that gathered evidence but never persisted an
// analysis (a run that failed after its tool calls) therefore shows no evidence
// line — the page's own "Not analyzed yet" state stays truthful, and inventing
// a second placement for that rare case would put a stray tool-call count on a
// page with nothing to attach it to.
export function AnalysisView({
  analysis,
  evidence,
  recentChanges,
  incidentId,
  clusterId,
  clusterName,
}: {
  analysis: Analysis
  evidence: EvidenceSummary | null
  recentChanges: RecentChangesView | null
  incidentId: string
  clusterId?: string
  clusterName?: string
}) {
  // Stage 3's "see the evidence" link targets #causal-chain. Landing on a
  // COLLAPSED section after following a link that promised evidence would be
  // worse than the problem D13 is solving, and browsers do not open a <details>
  // on fragment navigation. So the disclosure starts open when that is how the
  // reader arrived, and collapsed otherwise.
  //
  // Read once at render rather than subscribed to: this only decides an INITIAL
  // state, and re-reading it on every hash change would fight the reader if
  // they then closed it by hand.
  // Collapsed by default (owner, 2026-10-12): the root-cause headline and its
  // confidence are the first-glance answer; the chain is the evidence behind
  // it, one click away, with its step count and provenance on the summary.
  // Open when the reader arrived through the Fix section's "Built from the
  // causal chain" link — landing on a collapsed section after following a link
  // that promised evidence would defeat the link.
  const chainOpenByDefault =
    typeof window !== 'undefined' && window.location.hash === '#causal-chain'

  return (
    // `.analysis-card` alone — the `.card` it also carried made this a bordered,
    // shadowed box nested directly inside the stage card's own bordered box,
    // which is the card-in-a-card the vocabulary rules out (BUGS.md 11/16). The
    // stage card is the container now; this is just the column that spaces its
    // sections.
    <div className="analysis-card">
      {/* CI-U3: a recorded root cause and its confidence are the model's
          claims, marked as such. A partial run's "incomplete" notice is the
          hub's own fact and stays plain. */}
      {/* A requested change's "analysis" is a measurement (model "measured",
          PROJECT.md PG8), not a model's claim, so it is not marked AI. */}
      {analysis.status === 'complete' && analysis.rootCause && analysis.model !== 'measured' ? (
        <AiClaim>
          <ConclusionBlock analysis={analysis} headline />
        </AiClaim>
      ) : (
        <ConclusionBlock analysis={analysis} />
      )}

      {/* SUPERSEDED 2026-09-09 by PROJECT.md D13, and the original reasoning
          is kept because it is still right about the risk. It read:

            "Open by default, not a collapsed <details> — the causal chain is
             the product's actual differentiator (an evidence-backed argument,
             not an assertion), and this page used to be the one place that
             buried it behind a click."

          The owner's decision is that ARGUS's reasoning collapses by default.
          What resolves the tension is WHAT collapses: only the steps. The
          header row below is the <summary>, so in the closed state a reader
          still sees that a chain exists, how many steps it has, and — the part
          that actually matters — its provenance badge. The argument is
          summarised, not buried, which is the distinction the original comment
          was defending.

          Anything that would stop a reader trusting the conclusion must stay
          OUTSIDE this collapse. That is why the provenance badge is in the
          summary and not in the body. */}
      {/* "Causal chain", not "Why it broke" — that is the stage card's own
          question, printed in its head one line above this, so the page asked
          the reader the same question twice and answered it once. This heading
          names the thing beneath it instead. */}
      {/* id target for stage 3's "see the evidence" link (BACKLOG.md D9 U5)
          — the root-cause statement, the plan and the next steps all assert
          things this chain is what actually supports; screens.md's own rule
          is never to assert a root cause without letting the reader open
          the evidence behind it. */}
      <details className="causal-chain-disclosure" id="causal-chain" open={chainOpenByDefault}>
        <summary className="overview-card-header-row">
        <h3>Causal chain</h3>
        <span className="field-hint">
          {/* BACKLOG.md C10: which kind of artifact this is, said plainly next
              to the heading it belongs to — never buried in a tooltip alone,
              and never rendered indistinguishably from the other kind. A
              missing causalChainProvenance (a pre-C10 row) reads as
              hub-observed, which is what every such row actually was — the
              cli backend reported nothing at all until this field existed. */}
          {analysis.causalChain.length > 0 && (
            <span
              className="badge badge-gray"
              title={
                analysis.causalChainProvenance === 'self-reported'
                  ? 'The model reported this chain about its own reasoning after the fact — the cli backend never observes its intermediate turns directly. Every tool call it cites is cross-checked against the hub’s own record of what it actually served.'
                  : 'ARGUS observed every one of these tool calls directly, in real time, as this investigation ran.'
              }
            >
              {analysis.causalChainProvenance === 'self-reported' ? 'Self-reported' : 'Hub-observed'}
            </span>
          )}{' '}
          {analysis.causalChain.length} step{analysis.causalChain.length === 1 ? '' : 's'}
        </span>
        </summary>
        {analysis.causalChain.length > 0 ? (
          <ol className="chain-list">
            {analysis.causalChain.map((step) => (
              <CausalStep
                key={step.step}
                step={step}
                incidentId={incidentId}
                provenance={analysis.causalChainProvenance}
                clusterId={clusterId}
                clusterName={clusterName}
              />
            ))}
          </ol>
        ) : (
          <p className="empty-state">No investigation steps were recorded.</p>
        )}
      </details>

      {analysis.ruledOut.length > 0 && (
        <div className="ruled-out-block">
          <h3>Ruled out</h3>
          <ul>
            {analysis.ruledOut.map((r, i) => (
              <li key={i}>
                <AiClaim as="span">
                  <strong>{r.hypothesis}</strong> — {r.reason}
                </AiClaim>
              </li>
            ))}
          </ul>
        </div>
      )}

      {evidence && <EvidenceGathered evidence={evidence} />}

      <RecentChanges recentChanges={recentChanges} />

      <p className="field-hint">
        {analysis.model} · {analysis.iterations} iteration{analysis.iterations === 1 ? '' : 's'} ·{' '}
        <span
          title={`${analysis.tokensBilledIn.toLocaleString()} prompt tokens (${analysis.tokensCacheRead.toLocaleString()} cache-read) + ${analysis.tokensOut.toLocaleString()} completion tokens`}
        >
          {(analysis.tokensBilledIn + analysis.tokensOut).toLocaleString()} tokens
        </span>{' '}
        · {analysis.costBasis === 'metered' ? (
          `$${analysis.costUsd.toFixed(4)}`
        ) : (
          // Never "$0.0000" for a provider that cannot report cost: the stored
          // zero means unavailable, not free (lld/07-analysis-contracts.md
          // §10.5). Rendering it as a price would be a fabricated figure.
          <span title="This provider bills a flat-rate subscription, so there is no per-investigation cost to report. The stored 0 means unavailable, not free.">
            cost not measured
          </span>
        )} ·{' '}
        <span title={formatDateTime(analysis.createdAt)}>{formatRelativeTime(analysis.createdAt)}</span>
        {/* Understated, same field-hint tier as the rest of this line —
            BACKLOG.md C6: the only way to tell "the hub investigated this on
            its own" from "a person clicked Analyze" used to be a direct
            Postgres query. Manual is the unmarked, default case (most
            analyses are); only auto gets a visible flag, since that's the
            one fact an operator can't otherwise infer. Absent entirely for a
            pre-migration-000074 row (triggeredBy undefined) rather than
            guessing. */}
        {analysis.triggeredBy === 'auto' && (
          <>
            {' '}· <span title="This investigation ran on its own, unattended, because the incident's severity met the automatic-analysis threshold — no one clicked Analyze.">auto-investigated</span>
          </>
        )}
      </p>
    </div>
  )
}
