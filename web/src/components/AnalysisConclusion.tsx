import type { Analysis } from '../api/types'
import { partialReasonText } from '../utils/incidents'
import { HelpTip } from './HelpTip'
import { SplitBar } from './SplitBar'

// An analysis's bottom line, shared.
//
// Lifted out of IncidentDetailPage (unchanged) once TolerationsPage needed the
// same block: a toleration's expanded detail shows the analysis of the incident
// it was created from, and re-implementing "what did ARGUS conclude" there
// would have produced a second, subtly different rendering of the same stored
// verdict — including the two null cases below, which are easy to get wrong
// and were both real bugs once.

// Qualitative label always paired with the numeric confidence — badge color
// alone never carries the meaning (lld/11-ui-design.md §8's "never color
// alone" rule): the word ("high"/"medium"/"low") is right there in the text.
function confidenceBadge(confidence: number): { label: string; className: string } {
  const pct = Math.round(confidence * 100)
  if (confidence >= 0.75) return { label: `${pct}% confidence (high)`, className: 'badge badge-green' }
  if (confidence >= 0.4) return { label: `${pct}% confidence (medium)`, className: 'badge badge-amber' }
  return { label: `${pct}% confidence (low)`, className: 'badge badge-red' }
}

// A single suggestedNextSteps entry. Rendered as a bulleted list item;
// anything that reads as a shell command (a "be concrete" guidance route
// asks the model to write the exact kubectl invocation — BACKLOG F22 piece
// 5) gets the same bare <code> treatment this app already uses for other
// literal commands (e.g. ClusterDetailPage's `kubectl auth can-i...` line) —
// no new CSS class, just the browser's own monospace default on <code>.
function NextStepItem({ step }: { step: string }) {
  return <li>{/^\s*kubectl\b/.test(step) ? <code>{step}</code> : step}</li>
}

// Shared by both branches below: a "complete" analysis on the guidance route
// and a "partial" one both carry suggestedNextSteps (Investigation
// .SuggestedNextSteps's own doc comment explains the two different paths
// that populate it), and both render it identically.
// `label` is omitted by callers that already carry a heading of their own — the
// incident page's "Fix it manually" block does, and two headings over one list
// is a second title encoding nothing.
export function SuggestedNextSteps({
  steps,
  label = 'Suggested next steps',
}: {
  steps: string[] | null
  label?: string | null
}) {
  if (!steps || steps.length === 0) return null
  return (
    <>
      {label && <p className="field-hint">{label}</p>}
      <ul>
        {steps.map((step, i) => (
          <NextStepItem key={i} step={step} />
        ))}
      </ul>
    </>
  )
}

// The analysis's bottom line. A complete run gets its root-cause statement
// front and center; a partial run — a bound hit before any conclusion — is
// a normal, useful, fully-evidence-linked result, not a failure, so it gets
// the same amber "needs a look" treatment this app already uses for
// NeedsHumanInvestigation/AwaitingApproval states, never the red/danger
// styling reserved for actual errors.
// The first sentence of a root-cause statement, for the headline. Splits on a
// sentence end followed by a capital — not on every full stop, because these
// statements are full of `deployment/x.y`, versions and IPs. Returns the whole
// statement when no clean split exists, so nothing is ever cut mid-thought.
export function firstSentence(statement: string): string {
  const m = statement.match(/^(.{40,}?[.!?])\s+(?=[A-Z])/s)
  return m ? m[1] : statement
}

// `headline`: the incident page's form (incident lifecycle redesign,
// 2026-10-12) — the first sentence as the claim, the full statement one click
// away. A 200-word paragraph as the first thing in "Why" buried the answer.
export function ConclusionBlock({ analysis, headline = false }: { analysis: Analysis; headline?: boolean }) {
  if (analysis.status === 'complete') {
    // rootCause/confidence are independently nullable on a "complete" row
    // (see CompleteAnalysis's doc comment in api/types.ts): the hub omits
    // rootCause when internal/llm returned none, and a legacy row read back
    // through GET /incidents/{id} comes through as complete with both null.
    // Dereferencing rootCause.statement here used to throw and blank the
    // whole app. Each is handled on its own — a row can carry a statement
    // with no confidence, or neither.
    const confidence = analysis.confidence == null ? null : confidenceBadge(analysis.confidence)
    return (
      <div className="analysis-conclusion">
        {analysis.rootCause ? (
          headline && firstSentence(analysis.rootCause.statement) !== analysis.rootCause.statement ? (
            <>
              <p className="analysis-root-cause analysis-root-headline">{firstSentence(analysis.rootCause.statement)}</p>
              <details className="analysis-root-full">
                <summary>Full explanation</summary>
                <p className="analysis-root-cause">{analysis.rootCause.statement}</p>
              </details>
            </>
          ) : (
            <p className="analysis-root-cause">{analysis.rootCause.statement}</p>
          )
        ) : (
          // Never a fabricated "0% confidence (low)" badge, which is what
          // confidenceBadge(null) produced (Math.round(null * 100) === 0):
          // that read as a real, confidently-low verdict where the truth is
          // that nothing was recorded. Same discipline as the "cost not
          // measured" label elsewhere — an absent number is stated as absent.
          <p className="empty-state">
            This investigation finished without recording a root cause. The evidence it gathered is
            below; re-analyze to try for a conclusion.
          </p>
        )}
        <EvidenceCoverageStrip analysis={analysis} />
        {confidence && (
          <p>
            <span className={confidence.className}>{confidence.label}</span>
            <HelpTip text="The model's own estimate of how likely this root cause is correct, based on how directly the gathered evidence supports it — not a statistically calibrated probability yet, since that calibration work is still open. Treat it as a rough signal, and always check the evidence in the steps above before acting on it." />
          </p>
        )}
        {/* NOT rendered here on a complete analysis, deliberately — see the
            "Fix it manually" block in IncidentDetailPage's stage 3.
 
            These steps are a FIX, and this card answers "why it broke". Stage 3
            asks "how do I fix it" and was where the operator was being told to
            "apply that change yourself" with nothing beside it saying what the
            change was; the steps belong next to that sentence, not two cards
            above it. The partial branch below keeps them, because a partial
            analysis reaches no conclusion and leaves stage 3 locked, so there is
            no other place for them to go. */}
      </div>
    )
  }

  return (
    <div className="analysis-conclusion">
      <p>
        <span className="badge badge-amber">Investigation incomplete</span>
      </p>
      <p>{partialReasonText(analysis.partialReason)}</p>
      <EvidenceCoverageStrip analysis={analysis} />

      {/* BACKLOG C2. What the model actually said, when what it said could not be
          read. Behind a <details> because it is a diagnostic for whoever tunes the
          prompt or the harness, not something the operator needs in order to act on
          the incident — but on the page, because it used to exist only in a
          container log line that the next restart erased. Rendered in a <pre> and
          through plain interpolation: this is untrusted model output. */}
      {analysis.rawFinalAnswer && (
        <details className="raw-answer">
          <summary>What the investigation actually returned</summary>
          <p className="field-hint">Its final message did not match the required shape, so no conclusion was recorded.</p>
          {analysis.parseError && (
            <p className="field-hint">Could not be read because: {analysis.parseError}</p>
          )}
          <pre>{analysis.rawFinalAnswer}</pre>
        </details>
      )}

      <SuggestedNextSteps steps={analysis.suggestedNextSteps} />
    </div>
  )
}

const NOT_OFFERED_LABEL: Record<string, string> = {
  metrics: 'metrics (no Prometheus configured)',
  dryRun: 'dry-run checks (not granted)',
  repository: 'the source repository (none readable)',
}

// PROJECT.md IN6: what the investigation could and could not read, drawn as
// one bar so a conclusion reached on refused or failed reads is visible
// beside it. Absent for analyses recorded before coverage was.
export function EvidenceCoverageStrip({ analysis }: { analysis: Analysis }) {
  const c = analysis.evidenceCoverage
  if (!c) return null
  const total = c.answered + c.empty + c.denied + c.failed
  const missing = c.notOffered.map((k) => NOT_OFFERED_LABEL[k] ?? k)
  return (
    <div className="analysis-coverage">
      {total > 0 && (
        <SplitBar
          label="Reads this investigation made"
          parts={[
            { tone: 'ok', value: c.answered, label: c.truncated > 0 ? `answered (${c.truncated} cut short)` : 'answered' },
            { tone: 'neutral', value: c.empty, label: 'found nothing' },
            { tone: 'high', value: c.denied, label: 'refused' },
            { tone: 'critical', value: c.failed, label: 'failed' },
          ]}
        />
      )}
      {missing.length > 0 && <p className="field-hint">Not available to this investigation: {missing.join(', ')}.</p>}
    </div>
  )
}
