import { useEffect, useId, useRef, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'

import {
  ApiError,
  PROBLEM_NOT_FOUND,
  getRepositoryFile,
  openRepositoryChange,
  previewRepositoryChange,
} from '../api/client'
import type {
  OwnershipRepo,
  RemediationPlan,
  RenderEvidence,
  RepositoryChangeFileResult,
  RepositoryChangeResponse,
  RepositoryChangeVerification,
} from '../api/types'
import { UnifiedDiff } from './UnifiedDiff'
import {
  CAP_REMEDIATION_APPROVE,
  CAP_REMEDIATION_EXECUTE_PR,
  CAP_REPO_WRITE,
} from '../api/capabilities'
import { missingCapabilityMessage } from '../api/capabilityInfo'
import { useHasCapability } from '../auth/useCapabilities'
import { useAuth } from '../auth/useAuth'
import { proposedFilesFromPlan } from '../utils/incidents'
import { HelpTip } from './HelpTip'
import { CopyButton } from './CopyButton'
import { SkeletonFileEditor } from './Skeleton'

// Propose the permanent fix as a pull request, from the incident that revealed
// it.
//
// # What a repository change is, and what this panel therefore is
//
// A set of WHOLE FILES — one or many — each carrying the content the file
// should end up holding. ARGUS reads each at the pinned synced commit and
// computes the diff; nothing here sends a diff or a patch, and nothing here
// names a field.
//
// The single-field grammar this panel used to drive was deleted on 2026-08-28.
// It could prove that only one scalar had moved, and that proof was real — but
// it was also the REQUEST shape, so it capped the whole channel at one scalar
// in one already-existing, untemplated, plain-YAML file. DESIGN.md §11.4 states
// the reasoning: minimality was proved and offered as safety, and those are two
// different claims. The safety story is now the human reading the diff, which is
// what the sentence below the editor has said all along.
//
// # Why it lives inside the ownership callout
//
// That callout already tells the operator the fix belongs at the source, and
// already names the repository, the path and the synced commit. "Fix it at the
// source" plus the location plus no way to act is exactly the shape of advice
// people learn to ignore. The action belongs where the reason for it is stated.
//
// # What this panel shows before it asks for anything
//
// An approval is only meaningful if the approver saw what they were approving,
// and DESIGN.md §1.4's second hard problem is "determining root cause reliably
// enough that a human will click approve". A form the operator must fill in
// before ARGUS will show them the diff gets that backwards. So when the analysis
// proposed files, the panel opens with that content already in the editors and
// previews it immediately, rendering the real +/- diff of each file against the
// synced commit. Seeing the proposal first is what makes editing it, or
// accepting it, an informed act rather than a blind one.
//
// (The owner overruled the original no-prefill decision on 2026-08-24 and was
// right to: the audit record is honest either way — it records who APPROVED and
// what was submitted — while a blank editor makes a person retype content ARGUS
// already worked out, from an analysis sitting on the same screen.)

// One file open in the editor.
//
// `origin` is not decoration: it is how the panel knows whether there is
// anything to propose yet. Content seeded from the REPOSITORY is, until the
// operator changes it, exactly what the repository already holds — submitting
// it proposes nothing. Content seeded from the ANALYSIS, or typed into a NEW
// file, is a proposal from the moment it appears.
type EditorFile = {
  // Stable across re-orders and removals, so React does not reconcile one
  // file's textarea onto another's state. Never the path: two files can be
  // added and removed in any order.
  key: string
  path: string
  content: string
  // The content this editor was seeded with.
  seed: string
  origin: 'repository' | 'analysis' | 'new'
}

// The one sentence this whole panel is built around, and the reason there is no
// badge above it. Used once, here: after the pull request exists, the hub's own
// `verification.caveat` makes the same statement, and quoting the hub there is
// deliberate — the operator and the reviewer on the SCM then read one claim
// rather than two paraphrases of it.
const DIFF_IS_THE_SAFETY_STORY =
  'ARGUS refuses content it cannot let a reviewer review, and says beside each file what it could not check. Beyond that, the diff below is the entire safety story: review it the way you would review a hand-written change, not a change ARGUS has already confirmed is correct.'

function fileResultByPath(v: RepositoryChangeVerification | undefined) {
  const byPath = new Map<string, RepositoryChangeFileResult>()
  for (const f of v?.files ?? []) byPath.set(f.path, f)
  return byPath
}

// RenderEvidenceBanner is BACKLOG.md F28 finding 2's fix: the diff above is
// a claim about the SOURCE; this is ARGUS's best answer, where it has one,
// to the question the diff alone cannot: would this actually change what
// the cluster runs. Rendering was already computed for the pull-request
// body once a change was opened (F26) — this surfaces the identical
// evidence here too, before the operator has approved anything.
//
// Nothing renders when `attempted` is false — a badge for a check that
// never ran is worse than no badge, the same rule the pull-request body's
// own "Rendered delta" section follows. When it WAS attempted, colour is an
// addition to the words, never the only signal (lld/11 §8): "degraded" and
// "no effective change" both say plainly, in the sentence itself, what an
// operator needs to do about it, and the warning tone just draws the eye to
// the case that needs one.
function RenderEvidenceBanner({ evidence }: { evidence: RenderEvidence | undefined }) {
  if (!evidence?.attempted) return null

  if (evidence.degraded) {
    return (
      <p className="banner banner-warning" role="alert">
        Rendered comparison inconclusive: {evidence.degraded}
      </p>
    )
  }
  // objectsCompared/objectsChanged are always sent together with
  // effective/rendererKind once a render actually completes (the "real
  // answer" branch of renderEvidenceAuditFields on the hub) — never
  // defaulted to 0 here, which would show a fabricated count if a future
  // change ever left one of them off the wire (reference/anti-patterns.md:
  // "a missing count renders —, never 0").
  if (!evidence.effective) {
    return (
      <p className="banner banner-warning" role="alert">
        ARGUS rendered this {evidence.rendererKind} chart/overlay twice — once as it is today, once
        with this change applied — and compared{' '}
        {evidence.objectsCompared === undefined ? '—' : evidence.objectsCompared} object(s). They are
        identical: this is very likely the values-file-precedence trap this check exists to catch, and
        merging this change would change nothing in the cluster. Verify this is intentional.
      </p>
    )
  }
  return (
    <p className="banner banner-success">
      Rendered comparison confirms an effective change:{' '}
      {evidence.objectsChanged === undefined ? '—' : evidence.objectsChanged.length} of{' '}
      {evidence.objectsCompared === undefined ? '—' : evidence.objectsCompared} rendered object(s)
      differ.
    </p>
  )
}

// What ARGUS could NOT check about one file, always visible and never
// collapsed.
//
// These are ADVISORIES, not refusals, and the difference is the whole reason
// this renders separately from `.form-error`: the backend now advises rather
// than refuses on a templated file it did not render, a file that is not YAML,
// a changed document count, and a file that no longer declares the incident's
// object. Every one of those is a legitimate whole-file edit — a Helm chart
// template, a values.yaml that declares no Kubernetes object at all, a manifest
// being split in two — so refusing them was the single biggest cap on what this
// channel could express.
//
// They are the operator's cue to look harder at THIS file, so: the file's own
// name is already in each sentence (internal/gitops/files.go writes them that
// way), the block is amber rather than the danger red a refusal wears, and the
// words "could not check" carry the meaning with the colour as an addition
// rather than as the signal (lld/11 §8).
function FileAdvisories({ advisories }: { advisories: string[] }) {
  if (advisories.length === 0) return null
  return (
    <div className="repo-change-advisories">
      <p>
        What ARGUS could not check about this file — read the diff with{' '}
        {advisories.length === 1 ? 'it' : 'these'} in mind. Nothing here stopped the change; each is
        something a reviewer has to judge:
      </p>
      <ul>
        {advisories.map((a) => (
          <li key={a}>{a}</li>
        ))}
      </ul>
    </div>
  )
}

// One file's outcome as ARGUS computed it: what kind of change it is, what
// could not be checked, and the diff itself. Shared by the preview and by the
// opened-pull-request record so the two describe a file identically — a reader
// comparing "what it would do" with "what it did" is comparing the same words.
function FileOutcome({ result }: { result: RepositoryChangeFileResult }) {
  return (
    <>
      {/* A created file and an unchanged file are both NORMAL outcomes, stated
          as such. Unchanged especially: opening three files and editing one is
          an ordinary thing to submit, and the hub reports the untouched two
          rather than refusing the proposal or silently committing a no-op.
          A changed, existing file gets no chip at all — UnifiedDiff's own
          +N/−M summary already says how much moved, and a chip repeating it
          would be the same count in two places. */}
      {result.unchanged ? (
        <span className="verification-chip verification-chip-neutral">
          Unchanged from the synced commit — submitted, and not committed
        </span>
      ) : result.created ? (
        // Neutral, not the green `.verification-chip`: that variant means "ARGUS
        // checked this and it holds", and nothing was verified by a file being
        // new. The two outcomes are told apart by their words, which is where
        // the meaning has to live anyway.
        <span className="verification-chip verification-chip-neutral">
          New file — nothing exists at this path at the synced commit
        </span>
      ) : null}
      <FileAdvisories advisories={result.advisories} />
      {result.diff && (
        <UnifiedDiff diff={result.diff} ariaLabel={`Proposed change to ${result.path}`} />
      )}
    </>
  )
}

// One file's editor: its path, what ARGUS computed about it, and its whole
// content, editable.
//
// A component rather than inline JSX so each row can hold its own `useId` —
// a <label htmlFor> has to point at exactly one textarea, and deriving ids from
// an array index breaks the moment a file in the middle is removed.
function FileEditorRow({
  file,
  result,
  revision,
  removable,
  disabled,
  onChange,
  onRemove,
}: {
  file: EditorFile
  // Absent until a preview has been asked for, and cleared again by any edit.
  // Never fabricated: with no preview there is no diff, and the row says so
  // rather than showing an empty one.
  result?: RepositoryChangeFileResult
  revision: string
  removable: boolean
  disabled: boolean
  onChange: (content: string) => void
  onRemove: () => void
}) {
  const id = useId()
  return (
    <div className="repo-change-file">
      <div className="repo-change-file-head">
        <code>{file.path}</code>
        {/* The one attribution this panel can make on its own evidence: this
            content is no longer what the analysis proposed. Stated because the
            operator approving it, and anyone reading the incident afterwards,
            should know whether the diff below is the model's proposal or their
            own edit of it — and because ARGUS itself makes no claim either way
            (the caveat says so in as many words).

            NOT stated as "human-authored in the pull request": lld/11 §4a.1
            asks for that attribution in the PR body and an `Argus-Human-Edit`
            commit trailer, and internal/gitops writes neither today. Claiming
            it here would be describing a trailer that does not exist. */}
        {file.origin === 'analysis' && file.content !== file.seed && (
          <span className="verification-chip verification-chip-neutral">
            Edited by you since the analysis proposed it
          </span>
        )}
        {removable && (
          <button
            type="button"
            className="secondary repo-change-file-remove"
            disabled={disabled}
            onClick={onRemove}
          >
            Remove from this change
          </button>
        )}
      </div>

      {result ? (
        <FileOutcome result={result} />
      ) : (
        <p className="field-hint">
          {file.origin === 'new'
            ? 'A new file. Preview the change to see what would be committed.'
            : 'No diff computed for this file yet — preview the change to see it.'}
        </p>
      )}

      <label htmlFor={id}>
        Content of <code>{file.path}</code>{' '}
        <span className="field-hint">
          {file.origin === 'repository'
            ? `as it is at the synced commit ${revision.slice(0, 7)}`
            : file.origin === 'analysis'
              ? `as the analysis proposed it — the file at ${revision.slice(0, 7)} is what it is diffed against`
              : 'new — nothing exists at this path yet'}
        </span>
      </label>
      <textarea
        id={id}
        className="repo-change-editor"
        spellCheck={false}
        rows={18}
        value={file.content}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  )
}

// The record that the pull request exists, with everything it contains.
//
// Verbose on purpose: the per-file diffs and the advisories ARE the product
// here, and a summary that said only "PR opened" would throw away the part that
// makes the pull request reviewable — which is the same reason the hub returns
// them on the create response rather than only on the preview.
function PullRequestOpenedSummary({ result }: { result: RepositoryChangeResponse }) {
  const v = result.verification
  return (
    <div className="detail-callout">
      <p className="eyebrow">Pull request opened</p>
      <p>
        <a href={result.url} target="_blank" rel="noreferrer">
          {result.repository} #{result.pullRequestNumber}
        </a>
      </p>

      {/* The caveat is what the pull request's own label withholds, and it is on
          the pull request too. Showing the same words in both places means the
          operator and the reviewer are reading the same claim — and it is
          rendered at full size rather than as a footnote, because a whole-file
          change makes NO "only this moved" claim and that is the single most
          decision-relevant sentence here. */}
      <p className="banner banner-info">{v.caveat}</p>

      {/* Each field is a dt+dd pair wrapped in its own <div> — required by
          `.detail-fact-grid`'s `auto-fit` column layout (BACKLOG D7m): without
          the wrapper, auto-fit places dt/dd as independent grid items and
          wraps them wherever the column count lands, so a label and its OWN
          value can end up in different rows/columns entirely. */}
      <dl className="detail-fact-grid compact">
        <div>
          <dt>Files committed</dt>
          {/* The count only. Every path is named once, in its own block below —
              listing them here as well would be the same fact in two places,
              and the two lists would have to agree by hand forever. The count
              is a different fact from any of them: how many of the files that
              were submitted actually moved. */}
          <dd>
            {v.filesChanged} of {v.files.length} submitted
          </dd>
        </div>
        <div>
          <dt>Branch</dt>
          <dd>
            <code>{result.branch}</code> → <code>{result.baseBranch}</code>{' '}
            <span className="field-hint">head {result.commitSha.slice(0, 12)}</span>
          </dd>
        </div>
        {/* Read at the synced commit, branched from base head. Worth stating
            because it is the non-obvious part of how this stays reviewable: the
            content is read from what the cluster is actually running, while the
            diff stays free of everything that landed on base since. */}
        <div>
          <dt>Read at</dt>
          <dd>
            <code>{result.syncedRevision.slice(0, 12)}</code>{' '}
            <span className="field-hint">the commit the controller reports as applied</span>
          </dd>
        </div>
        <div>
          <dt>Pull request label</dt>
          <dd>
            <code>{v.label}</code>{' '}
            <span className="field-hint">applied on the pull request itself</span>
          </dd>
        </div>
      </dl>

      {v.files.map((f) => (
        <div className="repo-change-file" key={f.path}>
          <div className="repo-change-file-head">
            <code>{f.path}</code>
          </div>
          <FileOutcome result={f} />
        </div>
      ))}

      {/* `checks` is null, not [], when the hub ran no aggregate check —
          internal/api/repository_change.go declares it `[]string` with no
          omitempty, so Go's nil slice reaches the wire as JSON null. Rendering
          nothing for that is right; there is no count to fabricate. */}
      {v.checks !== null && v.checks.length > 0 && (
        <details className="repo-change-checks">
          <summary>What ARGUS checked before anything was branched ({v.checks.length})</summary>
          <ul>
            {v.checks.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
        </details>
      )}

      {result.warning && (
        <p className="banner banner-warning" role="alert">
          {result.warning}
        </p>
      )}
      <p className="field-hint">The fix takes effect when this pull request is merged and the controller syncs it.</p>
    </div>
  )
}

// The editor itself: one or more files, one review surface, one submit, one
// pull request.
//
// A separate component rather than state inside RepositoryChangePanel for one
// specific reason: the files need to be SEEDED once and then be fully
// independent of whatever seeded them — a background refetch of the file query
// must never clobber what the operator has typed. Deriving that with a
// `useEffect` (`if (data && files === null) setFiles(data)`) works, but it is
// exactly the "setState synchronously in an effect" shape React's own lint rule
// warns about, because the value is really an INITIAL value rather than one
// being kept in sync with an external system. Mounting a fresh component with
// `useState(initialFiles)` is a plain initializer, evaluated once, no effect
// required. The parent gives this a `key` so "once" means once per seed.
function MultiFileEditor({
  incidentId,
  repo,
  accessToken,
  initialFiles,
  // True only when the seed came from the analysis, i.e. when there is
  // something that plausibly differs from the repository to preview. Previewing
  // an unedited repository file on open would 422 with "nothing differs", and
  // an error on open reads as "this is broken" rather than "there is nothing to
  // propose yet".
  autoPreview,
  // The hub's own words when file DISCOVERY failed. Not an error state for this
  // component: the operator can still name files by hand, which is precisely
  // what discovery failing (none, or several, declaring this object) calls for.
  discoveryProblem,
  onCancel,
  onOpened,
}: {
  incidentId: string
  repo: OwnershipRepo
  accessToken: string
  initialFiles: { path: string; content: string; origin: EditorFile['origin'] }[]
  autoPreview: boolean
  discoveryProblem?: string
  onCancel: () => void
  onOpened: (result: RepositoryChangeResponse) => void
}) {
  const nextKey = useRef(initialFiles.length)
  const [files, setFiles] = useState<EditorFile[]>(() =>
    initialFiles.map((f, i) => ({ key: `f${i}`, path: f.path, content: f.content, seed: f.content, origin: f.origin })),
  )
  const [reason, setReason] = useState('')
  const [addPath, setAddPath] = useState('')

  const body = () => ({
    files: files.map((f) => ({ path: f.path, content: f.content })),
    ...(reason.trim() === '' ? {} : { reason: reason.trim() }),
  })

  const preview = useMutation({
    mutationFn: () => previewRepositoryChange(incidentId, body(), accessToken),
  })

  const mutation = useMutation({
    mutationFn: () => openRepositoryChange(incidentId, body(), accessToken),
    onSuccess: onOpened,
  })

  // Any change to the set of files, or to any file's content, invalidates a
  // preview on screen. Silently keeping it would be the worst state this panel
  // can be in: diffs that do not describe what the button would now do.
  const invalidatePreview = () => {
    if (preview.data || preview.error) preview.reset()
  }

  const addFile = useMutation({
    mutationFn: (path: string) => getRepositoryFile(incidentId, path, accessToken),
    onSuccess: (data) => {
      appendFile(data.filePath, data.content, 'repository')
      setAddPath('')
    },
  })

  const appendFile = (path: string, content: string, origin: EditorFile['origin']) => {
    setFiles((current) => [
      ...current,
      { key: `f${nextKey.current++}`, path, content, seed: content, origin },
    ])
    invalidatePreview()
  }

  // AUTO-PREVIEW ON OPEN — the owner's report: "when I click propose this fix as
  // a pull request, there should be a preview of the change ARGUS will make in
  // the file with +/- code that ARGUS already suggested."
  //
  // Fires ONCE, guarded by a ref rather than by preview state: not on every
  // render, which would hammer a repository read; and not again after the
  // operator edits, because editing resets the preview (invalidatePreview,
  // above) precisely so a stale diff cannot sit next to changed content, and
  // re-firing automatically would fight their typing and race their next
  // keystroke. After the first automatic one, refreshing is theirs to ask for.
  const autoPreviewed = useRef(false)
  useEffect(() => {
    if (!autoPreview || autoPreviewed.current || files.length === 0) return
    autoPreviewed.current = true
    preview.mutate()
    // preview.mutate is stable for the lifetime of the mutation object and the
    // ref is what actually guards re-entry, so the dependency list is the set
    // of things that decide WHETHER to fire rather than everything read inside.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoPreview, files.length])

  const results = fileResultByPath(preview.data?.verification)
  const busy = preview.isPending || mutation.isPending || addFile.isPending

  // Why the buttons are disabled, in words — never a control that is dead for
  // an unstated reason. Both cases are things the hub would refuse anyway; the
  // point of catching them here is that the operator learns it without spending
  // a request and without reading a 422 as a fault.
  const emptyFile = files.find((f) => f.content.trim() === '')
  const proposesNothing =
    files.length > 0 && files.every((f) => f.origin === 'repository' && f.content === f.seed)
  const blockedReason =
    files.length === 0
      ? 'No file is open yet. Add one by path below.'
      : emptyFile
        ? `${emptyFile.path} is empty. A repository change carries each file's whole content; an empty file would be a deletion, which this channel cannot express.`
        : proposesNothing
          ? 'Nothing has been edited yet, so this proposes no change to the repository.'
          : ''

  const addPathAlreadyOpen = files.some((f) => f.path === addPath.trim())
  const addNotFound =
    addFile.error instanceof ApiError && addFile.error.type === PROBLEM_NOT_FOUND

  return (
    <form
      className="repo-change-form"
      onSubmit={(e) => {
        e.preventDefault()
        mutation.mutate()
      }}
    >
      <p className="field-hint">
        A repository change is <strong>one or more whole files</strong>, inside{' '}
        <code>{repo.path || 'the repository root'}</code> — the directory the controller reports
        syncing. ARGUS reads each at the synced commit, computes the diff, branches, commits and
        opens the pull request. {DIFF_IS_THE_SAFETY_STORY}
      </p>

      {discoveryProblem && (
        // Not an error state: it is the reason the editor started empty, and
        // the thing to do about it is directly below. Discovery refuses when
        // the object is declared in none of the synced directory's files or in
        // several — which is the ordinary case for a Helm chart or an overlay,
        // exactly the cases this channel now exists to cover.
        <p className="banner banner-info" role="status">
          ARGUS could not pick a file on its own: {discoveryProblem} Name the file (or files) you
          want to change below.
        </p>
      )}

      {files.length === 0 && !discoveryProblem && (
        <p className="banner banner-info" role="status">
          No file is open. Add one by path below — it must be inside the synced directory.
        </p>
      )}

      {files.map((f) => (
        <FileEditorRow
          key={f.key}
          file={f}
          result={results.get(f.path)}
          revision={repo.revision ?? ''}
          removable={files.length > 1}
          disabled={busy}
          onChange={(content) => {
            setFiles((current) => current.map((x) => (x.key === f.key ? { ...x, content } : x)))
            invalidatePreview()
          }}
          onRemove={() => {
            setFiles((current) => current.filter((x) => x.key !== f.key))
            invalidatePreview()
          }}
        />
      ))}

      {/* ADDING A FILE. A change may span several files — that is most of what
          the whole-file grammar bought — and the only honest way to get a
          second one on screen is to read it at the same pinned commit through
          the same confined, denylisted route the first one came through. */}
      <div className="repo-change-add-file">
        <label htmlFor="repo-change-add-path">
          Add another file
          <HelpTip text="Relative to the repository root, and inside the directory the GitOps controller reports syncing. ARGUS reads it at the same synced commit as the rest of the change." />
        </label>
        <div className="form-actions">
          <input
            id="repo-change-add-path"
            value={addPath}
            onChange={(e) => setAddPath(e.target.value)}
            placeholder={repo.path ? `${repo.path}/values.yaml` : 'values.yaml'}
          />
          <button
            type="button"
            className="secondary"
            disabled={busy || addPath.trim() === '' || addPathAlreadyOpen}
            onClick={() => addFile.mutate(addPath.trim())}
          >
            {addFile.isPending ? 'Reading…' : 'Open this file'}
          </button>
        </div>
        {addPathAlreadyOpen && (
          <p className="field-hint">
            <code>{addPath.trim()}</code> is already open above. One proposal may not carry the same
            path twice.
          </p>
        )}
        {addFile.isError && (
          <p className="form-error" role="alert">
            {addFile.error instanceof ApiError
              ? addFile.error.detail || addFile.error.message
              : 'Could not read that file.'}
          </p>
        )}
        {addNotFound && (
          // A path that does not exist is not a dead end: a repository change
          // may CREATE a file, and the hub's own grammar says so ("a file that
          // does not exist at the synced commit is created"). Offered only on
          // the structural not-found problem type, so it never appears for a
          // forbidden path or one outside the synced directory — those are
          // refusals with nothing to offer.
          <div className="form-actions">
            <button
              type="button"
              className="secondary"
              disabled={busy}
              onClick={() => {
                appendFile(addPath.trim(), '', 'new')
                addFile.reset()
                setAddPath('')
              }}
            >
              Create it as a new file instead
            </button>
          </div>
        )}
      </div>

      <label htmlFor="repo-change-reason">
        Why <span className="field-optional">optional</span>
        <HelpTip text="Quoted into the pull request body. Left blank, ARGUS quotes the incident's own analysis if it has a root cause statement." />
      </label>
      <input
        id="repo-change-reason"
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        placeholder="Why this change fixes the incident"
      />

      {mutation.isError && (
        // Shown in full, never summarised. Every refusal on this path names
        // something the operator has to act on — a forbidden path, a file
        // outside the synced directory, empty or over-large content, plain YAML
        // that does not parse, a duplicate path, content that would write a
        // redaction marker back into a file, no file differing from the
        // repository, drift since the synced commit. Collapsing those into
        // "could not open a pull request" would throw away the only useful part.
        <p className="form-error" role="alert">
          {mutation.error instanceof ApiError
            ? mutation.error.detail || mutation.error.message
            : 'Could not propose this change.'}
        </p>
      )}

      {preview.isError && (
        // Same treatment, and for the same reason: a preview hits every refusal
        // the commit would, so its message is the useful one — and a refusal
        // that costs a request is better than one that costs a branch.
        <p className="form-error" role="alert">
          {preview.error instanceof ApiError
            ? preview.error.detail || preview.error.message
            : 'Could not preview this change.'}
        </p>
      )}

      {preview.data && (
        <div className="repo-change-preview">
          <p className="field-hint">
            {preview.data.verification.files.length > 1 && (
              <>
                {preview.data.verification.filesChanged} of{' '}
                {preview.data.verification.files.length} file(s) would change:{' '}
                {preview.data.verification.linesAdded} line(s) added,{' '}
                {preview.data.verification.linesRemoved} removed.{' '}
              </>
            )}
            Committed onto <code>{preview.data.branch}</code>, a new branch off{' '}
            <code>{preview.data.baseBranch}</code>, from the files as they are at{' '}
            <code>{preview.data.syncedRevision.slice(0, 7)}</code>. Nothing has been branched or
            committed — the diffs above are what the pull request would contain.
          </p>
          <p className="banner banner-info">{preview.data.verification.caveat}</p>
          <RenderEvidenceBanner evidence={preview.data.renderEvidence} />
          {/* Null rather than [] when there is no aggregate check list — see
              the identical guard in VerificationBlock above. */}
          {preview.data.verification.checks !== null && preview.data.verification.checks.length > 0 && (
            // The aggregate list, not the per-file ones: the hub prefixes each
            // sentence with its file when there is more than one, so rendering
            // both surfaces would be the same sentences twice. Collapsed
            // because it is the reassuring half — the advisories, which are the
            // half that needs acting on, sit open beside the file they qualify.
            <details className="repo-change-checks">
              <summary>What ARGUS checked ({preview.data.verification.checks.length})</summary>
              <ul>
                {preview.data.verification.checks.map((c) => (
                  <li key={c}>{c}</li>
                ))}
              </ul>
            </details>
          )}
        </div>
      )}

      {/* The disabled controls' reason, before them and in the flow rather than
          in a tooltip: a disabled button is not focusable, so a `title` on one
          is unreachable by keyboard, and hover is unreachable by touch. */}
      {blockedReason && <p className="field-hint">{blockedReason}</p>}

      <div className="form-actions">
        {/* Preview first, deliberately. Not a required step — an operator who
            already knows the change can open the pull request directly — but the
            default order on screen is see-then-do, because this button changes a
            repository that runs a cluster. */}
        <button
          type="button"
          className="secondary"
          disabled={busy || blockedReason !== ''}
          onClick={() => preview.mutate()}
        >
          {preview.isPending ? 'Preparing…' : preview.data ? 'Refresh preview' : 'Preview the change'}
        </button>
        <button type="submit" disabled={busy || blockedReason !== ''}>
          {mutation.isPending ? 'Opening…' : 'Open pull request'}
        </button>
        <button type="button" className="secondary" disabled={busy} onClick={onCancel}>
          Cancel
        </button>
        <CopyButton text={repo.url} label="Copy repository URL" />
      </div>
    </form>
  )
}

export function RepositoryChangePanel({
  incidentId,
  repo,
  plan,
}: {
  incidentId: string
  repo: OwnershipRepo
  // The analysis's own plan, when there is one. Used to SEED the editors, and to
  // say plainly when the analysis concluded a repository change is not the fix.
  plan?: RemediationPlan | null
}) {
  const { accessToken } = useAuth()
  const canWriteRepo = useHasCapability(CAP_REPO_WRITE)
  const canApprove = useHasCapability(CAP_REMEDIATION_APPROVE)
  const canExecutePR = useHasCapability(CAP_REMEDIATION_EXECUTE_PR)
  const canPropose = canWriteRepo && canApprove && canExecutePR

  const [open, setOpen] = useState(false)
  const [result, setResult] = useState<RepositoryChangeResponse | null>(null)

  // An OpenPR plan carries whole files. Anything else (a restart, a scale)
  // carries none, so there is nothing to seed and — more usefully — the analysis
  // has effectively said a repository change is not what it would do.
  const planFiles = proposedFilesFromPlan(plan)

  // The CURRENT, unedited file — fetched once (staleTime: Infinity) to seed the
  // editor when the analysis proposed nothing to seed it with. Skipped entirely
  // when it did: a plan's files ARE the proposal, and re-reading the repository
  // to overwrite them would discard the thing the operator came to look at.
  const fileQuery = useQuery({
    queryKey: ['repository-change-file', incidentId],
    queryFn: () => getRepositoryFile(incidentId, undefined, accessToken!),
    enabled: open && planFiles.length === 0 && !!accessToken && repo.pinned,
    staleTime: Infinity,
  })

  // An unpinned revision is refused by the hub, and saying so here — before the
  // operator edits anything — is better than a 422 after. The reason is not
  // pedantic: without a resolved commit nobody can state which commit is
  // running, so a change computed against the branch head would be computed
  // against content the cluster has never applied.
  if (!repo.pinned || !repo.revision) {
    return (
      <p className="field-hint repo-change-blocked">
        No pull request yet: the controller reports <code>{repo.revision || 'no revision'}</code>, not a resolved
        commit. Re-analyse once it has synced one.{' '}
        <HelpTip
          label="why a commit is needed"
          text="Without a resolved commit there is no revision whose content is known to be what is running, so a change computed against the branch head would be computed against content the cluster has never applied."
        />
      </p>
    )
  }

  if (result) return <PullRequestOpenedSummary result={result} />

  if (!open) {
    const missingProposeCapabilities = missingCapabilityMessage(
      [
        !canWriteRepo && CAP_REPO_WRITE,
        !canApprove && CAP_REMEDIATION_APPROVE,
        !canExecutePR && CAP_REMEDIATION_EXECUTE_PR,
      ].filter((c): c is string => typeof c === 'string'),
    )
    return (
      <div className="repo-change-cta">
        {/* BACKLOG D7u: unclassed, not `.secondary`. On a GitOps-owned
            incident this is the primary recommended action for this stage —
            the durable fix, not an auxiliary control alongside it — and
            index.css's bare `button` rule (not `.secondary`) is this
            codebase's primary/high-emphasis treatment. */}
        <button
          type="button"
          disabled={!canPropose}
          title={
            canPropose
              ? 'Open a pull request against this repository, changing one or more whole files, with every diff shown before anything is branched'
              : missingProposeCapabilities
          }
          onClick={() => setOpen(true)}
        >
          Propose this fix as a pull request
        </button>
        {!canPropose && (
          // Disabled, never hidden — and the reason readable without hovering,
          // which a `title` alone is not (lld/11 §6). A sentence rather than a
          // comma-joined list of wire constants, with the constants kept in
          // parentheses because that is what a support request has to name
          // (api/capabilityInfo.ts).
          <p className="field-hint">
            {missingProposeCapabilities} Until then you cannot propose a change to this cluster's
            repository.
          </p>
        )}
      </div>
    )
  }

  // Seeded from the analysis: the proposal is already here, so the editor
  // mounts immediately and previews itself.
  if (planFiles.length > 0) {
    return (
      <MultiFileEditor
        key="from-analysis"
        incidentId={incidentId}
        repo={repo}
        accessToken={accessToken!}
        initialFiles={planFiles.map((f) => ({ ...f, origin: 'analysis' as const }))}
        autoPreview
        onCancel={() => setOpen(false)}
        onOpened={setResult}
      />
    )
  }

  if (fileQuery.isPending) {
    return (
      <div className="repo-change-loading">
        <p className="field-hint" role="status">
          Reading the file this object is declared in…
        </p>
        {/* Shaped like the editor that is about to replace it, not a spinner:
            the textarea is by far the tallest thing this panel renders, and a
            placeholder that omits it guarantees the layout jump a skeleton
            exists to prevent (lld/11 §7). */}
        <SkeletonFileEditor />
      </div>
    )
  }

  // Discovery failed, or the file came back. Either way the editor mounts —
  // with the hub's own message and no files in the first case, which is a
  // working state rather than a dead end.
  const discovered = fileQuery.data
  return (
    <MultiFileEditor
      key={discovered?.filePath ?? 'no-file'}
      incidentId={incidentId}
      repo={repo}
      accessToken={accessToken!}
      initialFiles={
        discovered
          ? [{ path: discovered.filePath, content: discovered.content, origin: 'repository' as const }]
          : []
      }
      autoPreview={false}
      discoveryProblem={
        fileQuery.isError
          ? fileQuery.error instanceof ApiError
            ? fileQuery.error.detail || fileQuery.error.message
            : 'the file could not be read.'
          : undefined
      }
      onCancel={() => setOpen(false)}
      onOpened={setResult}
    />
  )
}
