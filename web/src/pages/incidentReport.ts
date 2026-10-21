// PROJECT.md T17: a durable, shareable incident report — for support,
// review, and post-incident records outside the interactive page.
//
// The single most important property this file has to hold is stated in the
// board item's own acceptance line: "whose claims and state match the
// incident API at generation time." That rules out a second code path that
// re-queries or re-derives a conclusion, gate outcome, ownership fact, or
// stage state — exactly the divergence-between-two-renderings defect this
// board has already hit once (incidentSummaryFields's own doc comment in
// internal/api/incidents.go describes it: a hand-maintained second copy of
// one response silently dropped a field three times).
//
// So this module takes NO query of its own. It is a pure function of the
// exact `IncidentDetail` object IncidentDetailPage.tsx already fetched from
// GET /api/v1/incidents/{id} and is currently rendering on screen, and it
// calls the SAME pure stage/label/derivation functions that page calls to
// build that screen — detectStage/explainStage/recommendStage/approveStage/
// executeStage/validateStage/nextActionSummary/resolvedIdentity/
// nothingWasExecuted (incidentLifecycle.ts) and planChange/
// proposedFilesFromPlan/partialReasonText/isClosedIncidentState/
// stateExplanation/RESOLUTION_KIND_EXPLANATION (utils/incidents.ts), plus
// the four closed-set label tables incidentLifecycle.ts now holds
// (OWNERSHIP_COPY/ROUTE_LABEL/AUTOMATION_GATE_LABEL/RECENT_CHANGE_LABELS/
// toolLabel) precisely so the page and this generator cannot state the fact
// two different ways. If a future change to any of those functions changes
// what the page says, this report changes with it — there is nothing here
// to fall out of step.
//
// Redaction: every string this touches (Finding.message, AnalysisStep
// hypothesis/finding text, ToolCall args/result inside causalChain,
// RecentChange.reason/message) already crossed the tunnel through
// internal/redact's agent-side, capture-time redaction before it reached
// this browser at all (argus-context non-negotiable 9) — the same bytes
// IncidentDetailPage already renders unconditionally. This file adds no
// hub-side redaction pass (there is nothing left for it to do) and exposes
// no field IncidentDetailPage does not already show by default: it
// deliberately excludes ToolCallChip's per-call raw args/result JSON, which
// is fetched lazily via GET /evidence/{evId} only when a reader expands one
// chip — building a report would mean firing one more request per tool call
// with no bound on how many, for content the causal chain's own
// hypothesis/finding prose already carries without expanding anything.
//
// Format: Markdown, not HTML/PDF. It needs no library, diffs and reviews
// cleanly in a support ticket or a pasted comment, and every list/table
// this report renders (the causal chain, the diff pairs, the six-stage
// timeline) is already line-oriented. The print-friendly VIEW is the
// existing page under @media print rules (see index.css) — a real view of
// the real DOM, not a second render — so this file's only job is the one
// artifact that has to leave the browser as a file: the download.
import type {
  Analysis,
  Finding,
  IncidentDetail,
  RecentChangesView,
  RemediationPlan,
} from '../api/types'
import {
  isClosedIncidentState,
  partialReasonText,
  planChange,
  proposedFilesFromPlan,
  RESOLUTION_KIND_EXPLANATION,
  stateExplanation,
  STATE_LABEL,
} from '../utils/incidents'
import {
  approveStage,
  AUTOMATION_GATE_LABEL,
  dedupeRecentChanges,
  detectStage,
  executeStage,
  explainStage,
  nextActionSummary,
  nothingWasExecuted,
  OWNERSHIP_COPY,
  recommendStage,
  RECENT_CHANGE_LABELS,
  resolvedIdentity,
  ROUTE_LABEL,
  toolLabel,
  validateStage,
} from './incidentLifecycle'
import { formatDateTime } from '../utils/time'
import { objectRefFromToolCall, reproducerFor } from '../evidence/reproducer'
import { parseGvk } from '../insight/kinds'

function heading(level: number, text: string): string {
  return `${'#'.repeat(level)} ${text}`
}

// findingLine — the same "<gvk> <namespace>/<name>: <message>" shape stage 1
// (Detection) renders, or its own honest "no finding recorded" fallback.
function findingLine(incident: IncidentDetail, finding: Finding | null): string {
  if (!finding) return `No finding recorded — incident ${incident.fingerprint.slice(0, 12)}`
  return `${finding.gvk} ${finding.namespace}/${finding.objectName}: ${finding.message}`
}

function ownershipLines(incident: IncidentDetail): string[] {
  const ownership = incident.ownership
  if (!ownership) return []
  const copy = OWNERSHIP_COPY[ownership.managedBy]
  if (!copy) return [`Managed by ${ownership.managedBy} (${ownership.sourceKind} ${ownership.sourceName})`]
  const lines = [`Managed by ${copy.badge} — ${copy.subject(ownership)}`]
  if (ownership.repo) {
    const rev = ownership.repo.revision
      ? `${ownership.repo.pinned ? 'pinned at' : 'unpinned, requested as'} ${ownership.repo.revision}`
      : 'no synced revision recorded'
    lines.push(`Source: ${ownership.repo.url} (${ownership.repo.path || '.'}), ${rev}`)
  }
  lines.push(`If a fix is applied directly to the live object: ${copy.revert}`)
  return lines
}

// evidenceLine mirrors EvidenceGathered's own "N tool calls — a × x, b × y"
// sentence in IncidentDetailPage.tsx, from the SAME EvidenceSummary field.
function evidenceLine(evidence: IncidentDetail['evidence']): string | null {
  if (!evidence) return null
  const breakdown = Object.entries(evidence.byTool)
    .sort((a, b) => b[1] - a[1] || toolLabel(a[0]).localeCompare(toolLabel(b[0])))
    .map(([tool, count]) => `${count} × ${toolLabel(tool)}`)
    .join(', ')
  const failed = evidence.failedCalls > 0 ? `, ${evidence.failedCalls} failed` : ''
  return `Evidence gathered: ${evidence.totalCalls} tool call${evidence.totalCalls === 1 ? '' : 's'}${failed}${breakdown ? ` — ${breakdown}` : ''}`
}

// recentChangesLines — the SAME null/empty/populated three-way this
// incident's own RecentChanges component renders (see RecentChangesView's
// own doc comment in api/types.ts): null means nothing was ever recorded to
// look through and renders no section at all; empty items means the
// investigation looked and found nothing in the window; populated items are
// the bounded, source-labelled, chronological list, as sent.
function recentChangesLines(recentChanges: RecentChangesView | null): string[] {
  if (!recentChanges) return []
  const lines = [heading(3, 'Recent changes before this incident\'s first finding')]
  if (recentChanges.items.length === 0) {
    lines.push(`No recorded change in the ${recentChanges.windowHours}h before this incident's first finding.`)
    return lines
  }
  // Folded the way the page's own list folds them: the investigation reads
  // one object many times, and the same change listed once per sighting
  // repeated two changes eighteen times over.
  for (const { change, seen } of dedupeRecentChanges(recentChanges.items)) {
    const identity =
      change.objectKind &&
      `${change.objectKind} ${change.objectNamespace ? `${change.objectNamespace}/` : ''}${change.objectName ?? ''}`.trim()
    const label = RECENT_CHANGE_LABELS[change.category] ?? change.category
    const parts = [`- ${formatDateTime(change.time)} — ${label}`]
    if (identity) parts.push(`\`${identity}\``)
    if (seen > 1) parts.push(`(seen ${seen} times)`)
    lines.push(parts.join(' '))
    if (change.message) lines.push(`  ${change.message} (${toolLabel(change.source)})`)
  }
  if (recentChanges.truncated) lines.push('_Showing the most recent changes only._')
  return lines
}

// planLines — the same before/after `planChange` mapping the Recommendation
// card and the approval queue both render for one plan, plus the plan's own
// gate/risk fields and, for a repository change, the whole-file paths it
// proposes (never their content — a diff this size belongs in the pull
// request itself, not duplicated into a text report).
function planLines(plan: RemediationPlan, label: string): string[] {
  const lines = [heading(3, label), plan.summary]
  lines.push(
    `Action: ${plan.actionType} on ${plan.targetGvk} ${plan.targetNamespace}/${plan.targetName}`,
  )
  const riskLine =
    plan.riskLevel === plan.effectiveRiskLevel
      ? `Risk: ${plan.effectiveRiskLevel}`
      : `Risk: ${plan.effectiveRiskLevel} (model declared ${plan.riskLevel})`
  lines.push(riskLine)
  lines.push(`Gate: ${plan.gateOutcome} — ${plan.gateReason}`)
  const change = planChange(plan)
  if (change.before !== undefined) lines.push(`Before: ${change.before}`)
  if (change.after !== undefined) lines.push(`After: ${change.after}`)
  if (change.note) lines.push(change.note)
  const files = proposedFilesFromPlan(plan)
  if (files.length > 0) {
    lines.push(`Proposed file change${files.length === 1 ? '' : 's'}: ${files.map((f) => f.path).join(', ')}`)
  }
  if (plan.approval) {
    const who = plan.approval.actorEmail ? ` by ${plan.approval.actorEmail}` : ''
    const why = plan.approval.reason ? `: ${plan.approval.reason}` : ''
    lines.push(`Decision: ${plan.approval.verdict}${who} at ${formatDateTime(plan.approval.createdAt)}${why}`)
  }
  if (plan.execution) {
    lines.push(
      `Execution: ${plan.execution.outcome} at ${formatDateTime(plan.execution.executedAt)}${plan.execution.error ? ` — ${plan.execution.error}` : ''}`,
    )
  }
  return lines
}

function pullRequestLines(incident: IncidentDetail): string[] {
  const pr = incident.pullRequest
  if (!pr) return []
  const lines = [heading(3, 'Pull request')]
  const link = pr.url ?? `#${pr.number}`
  if (pr.mergedAt) {
    lines.push(`${link} — merged ${formatDateTime(pr.mergedAt)}`)
  } else if (pr.closedUnmergedAt) {
    lines.push(`${link} — closed without merging ${formatDateTime(pr.closedUnmergedAt)}${pr.rejectionReason ? `: ${pr.rejectionReason}` : ''}`)
  } else {
    lines.push(`${link} — open, awaiting merge`)
  }
  lines.push(
    pr.fieldPath
      ? `Post-merge verification target: ${pr.fieldPath} = ${pr.expectedValue ?? ''}`
      : 'No single-field post-merge check applies to this change (a repository change is a set of whole-file edits) — verify by review.',
  )
  return lines
}

// causalChainLines — the investigation's own reasoning, step by step: what
// it hypothesised, what it asked the cluster (by tool name and count only —
// see this file's own header comment on why the raw per-call args/result
// are not included), and what it concluded at that step. Plus what it
// explicitly ruled out, kept separate for the same reason the page keeps it
// visually distinct: it is not part of the reasoning that led anywhere.
function causalChainLines(analysis: Analysis): string[] {
  if (analysis.causalChain.length === 0) return []
  const lines = [heading(3, 'Causal chain')]
  for (const step of analysis.causalChain) {
    lines.push(`${step.step}. ${step.hypothesis}`)
    if (step.toolCalls.length > 0) {
      const byTool = new Map<string, number>()
      for (const call of step.toolCalls) byTool.set(call.tool, (byTool.get(call.tool) ?? 0) + 1)
      const tools = [...byTool.entries()].map(([tool, count]) => `${count} × ${toolLabel(tool)}`).join(', ')
      lines.push(`   Checked: ${tools}`)
    }
    if (step.finding) lines.push(`   Finding: ${step.finding}`)
  }
  if (analysis.ruledOut.length > 0) {
    lines.push('', 'Ruled out:')
    for (const h of analysis.ruledOut) lines.push(`- ${h.hypothesis} — ${h.reason}`)
  }
  return lines
}

function analysisLines(incident: IncidentDetail): string[] {
  const analysis = incident.analysis
  const lines = [heading(2, "Why it broke — ARGUS's analysis"), explainStage(analysis).text]
  if (!analysis) return lines

  if (analysis.status === 'complete') {
    if (analysis.rootCause) {
      const confidence = analysis.confidence == null ? '' : ` (${Math.round(analysis.confidence * 100)}% confidence)`
      lines.push(`Root cause: ${analysis.rootCause.statement}${confidence}`)
    } else {
      lines.push('This investigation finished without recording a root cause.')
    }
  } else {
    lines.push(`Investigation incomplete: ${partialReasonText(analysis.partialReason)}`)
  }
  if (analysis.suggestedNextSteps && analysis.suggestedNextSteps.length > 0) {
    lines.push('', 'Suggested next steps:')
    for (const step of analysis.suggestedNextSteps) lines.push(`- ${step}`)
  }

  const evidence = evidenceLine(incident.evidence)
  if (evidence) lines.push('', evidence)
  lines.push(
    '',
    `Model: ${analysis.model} · ${analysis.iterations} iteration${analysis.iterations === 1 ? '' : 's'} · analyzed ${formatDateTime(analysis.createdAt)}${analysis.triggeredBy ? ` · ${analysis.triggeredBy === 'auto' ? 'triggered automatically' : 'triggered manually'}` : ''}`,
  )

  const chain = causalChainLines(analysis)
  if (chain.length > 0) lines.push('', ...chain)

  const recent = recentChangesLines(incident.recentChanges)
  if (recent.length > 0) lines.push('', ...recent)

  return lines
}

function recommendationLines(incident: IncidentDetail): string[] {
  const lines = [heading(2, 'How to fix it — recommendation'), nextActionSummary(incident)]
  if (incident.routeReason) {
    lines.push(`Route (${ROUTE_LABEL[incident.route ?? ''] ?? 'unknown'}): ${incident.routeReason}`)
  }
  const plan = incident.analysis?.plan
  if (plan) lines.push('', ...planLines(plan, 'Proposed change'))
  const pairedPlan = incident.analysis?.pairedPlan
  if (pairedPlan) lines.push('', ...planLines(pairedPlan, 'Paired change (second half of this route)'))
  const pr = pullRequestLines(incident)
  if (pr.length > 0) lines.push('', ...pr)
  return lines
}

// lifecycleLines — the six-stage progression, in order, each stage's own
// real text from incidentLifecycle.ts's stage functions (the identical
// functions LifecycleRail/StageCard call to render the page). Mirrors
// nothingWasExecuted's own fold: an incident that never reached execution
// (the majority — see that function's own doc comment) gets ONE line in
// place of three empty-sounding ones, on paper for the same reason it does
// on screen.
function lifecycleLines(incident: IncidentDetail): string[] {
  const lines = [heading(2, 'Lifecycle timeline')]
  lines.push(`1. Detection — ${detectStage(incident).text}`)
  lines.push(`2. Analysis — ${explainStage(incident.analysis).text}`)
  lines.push(`3. Recommendation — ${recommendStage(incident).text}`)
  if (nothingWasExecuted(incident)) {
    lines.push('No fix was executed — nothing to approve, apply or validate.')
    return lines
  }
  lines.push(`4. Approve — ${approveStage(incident).text}`)
  lines.push(`5. Apply — ${executeStage(incident).text}`)
  lines.push(`6. Validate — ${validateStage(incident).text}`)
  return lines
}

function validationLines(incident: IncidentDetail): string[] {
  const lines = [heading(2, 'Validation result'), validateStage(incident).text]
  const cause = incident.reopenedBy
  if (cause && !cause.sameObject) {
    lines.push(
      `Fixed object stopped reporting; now failing: ${cause.objectName ?? 'another object'}${cause.reason ? ` — ${cause.reason}` : ''} (${formatDateTime(cause.occurredAt)})`,
    )
  }
  return lines
}

function automationLines(incident: IncidentDetail): string[] {
  const lines: string[] = []
  if (incident.automationGate) {
    lines.push(
      heading(3, 'Why this did not happen automatically'),
      `${AUTOMATION_GATE_LABEL[incident.automationGate.gate] ?? incident.automationGate.gate}: ${incident.automationGate.reason} (as of ${formatDateTime(incident.automationGate.at)})`,
    )
  }
  if (incident.unattendedBatch) {
    const b = incident.unattendedBatch
    lines.push(
      heading(3, 'Unattended batch'),
      `Wave ${b.waveNumber} of a ${b.batchStatus} ${b.actionType} batch (wave 1 size ${b.wave1Size}, total ${b.totalSize})${b.held ? ' — held' : ''}`,
    )
  }
  return lines
}

// buildIncidentReportMarkdown is the one entry point this module exists
// for: an IncidentDetail in, a Markdown string out, no I/O of its own.
// Callers (IncidentDetailPage.tsx's "Download report" action) pass exactly
// the object their own useQuery already holds — see this file's own header
// comment for why that is the whole safety property this task asked for.
export function buildIncidentReportMarkdown(incident: IncidentDetail, generatedAt: Date = new Date()): string {
  const identity = resolvedIdentity(incident)
  const sections: string[] = []

  sections.push(
    [
      heading(1, `Incident report — ${identity.name || incident.fingerprint.slice(0, 12)}`),
      `Generated ${formatDateTime(generatedAt.toISOString())} from this incident's own ARGUS page at that moment.`,
    ].join('\n\n'),
  )

  const stateNote = stateExplanation(incident.state, incident.analysis)
  const identityLines = [
    heading(2, 'Identity'),
    `- Object: ${identity.name}${identity.kind ? ` (${identity.kind})` : ''}`,
    `- Fault: ${identity.faultLine || 'not recorded'}`,
    `- Incident ID: ${incident.id}`,
    `- Fingerprint: ${incident.fingerprint}`,
    `- Cluster: ${incident.clusterDisplayName}`,
    `- Severity: ${incident.severity}`,
    `- State: ${STATE_LABEL[incident.state] ?? incident.state}${stateNote ? ` — ${stateNote}` : ''}`,
    `- First seen: ${formatDateTime(incident.firstSeen)}`,
    `- Last seen: ${formatDateTime(incident.lastSeen)}`,
    `- Events: ${incident.findingGroups.reduce((sum, g) => sum + g.count, 0)} across ${incident.findingGroups.length} reason${incident.findingGroups.length === 1 ? '' : 's'}`,
  ]
  if (incident.state === 'Resolved' && incident.resolutionKind) {
    identityLines.push(`- Resolution: ${RESOLUTION_KIND_EXPLANATION[incident.resolutionKind]}`)
  }
  if (isClosedIncidentState(incident.state)) {
    identityLines.push(
      incident.state === 'Expired'
        ? '- Closed in bulk, not by an individual decision — if the problem recurs, this incident reopens automatically.'
        : '- Closing is final — if the problem recurs, its detector opens a new incident.',
    )
  }
  const ownership = ownershipLines(incident)
  if (ownership.length > 0) identityLines.push('', heading(3, 'Ownership'), ...ownership)
  sections.push(identityLines.join('\n'))

  sections.push([heading(2, 'What broke — detection'), findingLine(incident, incident.findings[0] ?? null)].join('\n\n'))

  sections.push(analysisLines(incident).join('\n'))
  sections.push(recommendationLines(incident).join('\n'))
  sections.push(lifecycleLines(incident).join('\n'))
  sections.push(validationLines(incident).join('\n'))

  const automation = automationLines(incident)
  if (automation.length > 0) sections.push(automation.join('\n'))

  sections.push(
    [
      heading(2, 'About this report'),
      "Built entirely from the incident data ARGUS showed on this incident's page when the report was generated — no separate query, no recomputed conclusion. Secret values were removed inside the cluster, by the ARGUS agent, before any data left it; this report performs no redaction of its own and there is no unredacted copy to request.",
    ].join('\n\n'),
  )

  return sections.join('\n\n') + '\n'
}

// reportFileName — deterministic and stable across regenerations of the
// same incident, so a support ticket thread accumulating several of these
// (a fix attempted, rejected, retried) can tell them apart by the state at
// the time each was pulled without reading the contents.
export function reportFileName(incident: IncidentDetail): string {
  return `incident-${incident.id}-${incident.state.toLowerCase()}.md`
}

// ---------------------------------------------------------------- Copy summary (CI-U12)
//
// A short Markdown summary for pasting into a channel or ticket — the
// opposite job from buildIncidentReportMarkdown's full record above. Same
// rule: a pure function of the IncidentDetail the page already holds, no
// query of its own. Anything the model wrote is prefixed "AI:" (CI-U3) so it
// cannot be read as an observed fact once it has left the page, and every
// evidence line carries the read-only command that re-derives it (CI-U9).
// Inputs are already redacted at capture time; this adds nothing new.

function describeCall(tool: string, args: Record<string, unknown>, clusterId: string): string {
  const ref = objectRefFromToolCall(tool, args, clusterId)
  const what = ref ? ` — ${ref.kind} ${ref.namespace ? `${ref.namespace}/` : ''}${ref.name}` : ''
  return `${toolLabel(tool)}${what}`
}

export function buildIncidentSummaryMarkdown(incident: IncidentDetail, incidentUrl: string): string {
  const identity = resolvedIdentity(incident)
  const lines: string[] = []
  lines.push(`**${identity.name || incident.fingerprint.slice(0, 12)}**${identity.faultLine ? ` — ${identity.faultLine}` : ''}`)
  lines.push('')
  lines.push(`- Cluster: ${incident.clusterDisplayName}`)
  const objectKind = parseGvk(incident.objectGvk).kind
  const objectName = incident.objectName ? `${incident.objectNamespace ? `${incident.objectNamespace}/` : ''}${incident.objectName}` : ''
  lines.push(`- Object: ${objectName ? [objectKind, objectName].filter(Boolean).join(' ') : identity.kind || 'not recorded'}`)
  lines.push(`- Severity: ${incident.severity}`)
  lines.push(`- State: ${STATE_LABEL[incident.state] ?? incident.state}`)

  const analysis = incident.analysis
  if (!analysis) {
    lines.push('- Root cause: not analysed yet')
  } else if (analysis.status === 'complete' && analysis.rootCause) {
    const confidence = analysis.confidence == null ? '' : ` (model's own confidence ${Math.round(analysis.confidence * 100)}%)`
    lines.push(`- AI: root cause — ${analysis.rootCause.statement}${confidence}`)
  } else if (analysis.status === 'complete') {
    lines.push('- Root cause: the investigation finished without recording one')
  } else {
    lines.push(`- Root cause: investigation incomplete — ${partialReasonText(analysis.partialReason)}`)
  }

  const seen = new Set<string>()
  const evidence: string[] = []
  for (const step of analysis?.causalChain ?? []) {
    for (const call of step.toolCalls) {
      const key = `${call.tool}:${JSON.stringify(call.args ?? {})}`
      if (seen.has(key)) continue
      seen.add(key)
      const cmd = reproducerFor(call.tool, call.args)
      evidence.push(`- ${describeCall(call.tool, call.args ?? {}, incident.clusterId)}${call.error ? ' (failed)' : ''}${cmd ? `: \`${cmd}\`` : ''}`)
    }
  }
  if (evidence.length > 0) {
    lines.push('', `Evidence (run against ${incident.clusterDisplayName}):`, ...evidence)
  }
  lines.push('', `Incident: ${incidentUrl}`)
  return lines.join('\n') + '\n'
}

