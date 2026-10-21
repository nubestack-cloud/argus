// The resolution/remediation-plan group of the incident-detail screen: the
// rendered in-place and pull-request diff previews, the paired-route
// approval panel, the repository-link discovery/confirm flow, and the
// RecommendationChannels card that assembles them — split out of
// IncidentDetailPage.tsx (PROJECT.md P25) with no behavior change. See that
// file's own header for the screen this panel belongs to.
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  confirmRepositoryLink,
  declineRepositoryLink,
  discoverRepositoryLink,
  ApiError,
} from '../../api/client'
import { CAP_REPO_READ, CAP_REPO_WRITE } from '../../api/capabilities'
import type {
  DiscoverRepositoryLinkResponse,
  LinkCandidate,
  ObjectOwnership,
  RemediationPlan,
} from '../../api/types'
import { HelpTip } from '../../components/HelpTip'
import { PreflightPanel } from '../../components/PreflightPanel'
import { useAuth } from '../../auth/useAuth'
import { useHasCapability } from '../../auth/useCapabilities'
import { SkeletonLines } from '../../components/Skeleton'
import { planChange } from '../../utils/incidents'
import { OWNERSHIP_COPY } from '../incidentLifecycle'

// The in-place channel's own rendered change (BACKLOG D8 A4) — plan.params as
// the same before/after `.diff-pair` the approval queue already shows,
// via the shared planChange() mapping (exported from ApprovalDecisionCard so
// the two screens cannot describe one plan two different ways), plus a
// PreflightPanel rehearsal. Not the primary action (that stays Approve, at
// stage 4 — see index.css's own note on .route-option-list about not
// duplicating a control that must stay in step with a decision elsewhere);
// a dry-run preview has no decision to drift out of step with, so it is safe
// to offer here, before the operator has committed to anything.
export function InPlaceChangePreview({
  plan,
  incidentId,
}: {
  plan: RemediationPlan
  incidentId: string
}) {
  const change = planChange(plan)
  // Once a decision exists (approved/rejected) or it already ran, rehearsing
  // it again describes a plan that is no longer just a proposal — the plan
  // card above already states what actually happened, which is the more
  // relevant fact at that point.
  const canPreflight = !plan.approval && !plan.execution
  return (
    <>
      {(change.before !== undefined || change.after !== undefined) && (
        <div className="diff-pair">
          {change.before !== undefined && (
            <div className="diff-pair-before">
              <span className="visually-hidden">Currently: </span>
              {change.before}
            </div>
          )}
          {change.after !== undefined && (
            <div className="diff-pair-after">
              <span className="visually-hidden">
                {change.before === undefined ? 'This change sets: ' : 'Changed to: '}
              </span>
              {change.after}
            </div>
          )}
        </div>
      )}
      {change.note && <p className="field-hint">{change.note}</p>}
      {canPreflight && <PreflightPanel incidentId={incidentId} />}
    </>
  )
}

// The paired route's own proposed change, read-only — same `.diff-pair` shape
// and the same planChange() mapping InPlaceChangePreview uses above, minus
// the PreflightPanel rehearsal: OpenPR has no cluster patch to dry-run
// (ApprovalDecisionCard's own canPreflight applies the identical rule).
export function PairedPlanChangePreview({ plan }: { plan: RemediationPlan }) {
  const change = planChange(plan)
  if (change.before === undefined && change.after === undefined && !change.note) return null
  return (
    <>
      {(change.before !== undefined || change.after !== undefined) && (
        <div className="diff-pair">
          {change.before !== undefined && (
            <div className="diff-pair-before">
              <span className="visually-hidden">Currently: </span>
              {change.before}
            </div>
          )}
          {change.after !== undefined && (
            <div className="diff-pair-after">
              <span className="visually-hidden">
                {change.before === undefined ? 'This change sets: ' : 'Changed to: '}
              </span>
              {change.after}
            </div>
          )}
        </div>
      )}
      {change.note && <p className="field-hint">{change.note}</p>}
    </>
  )
}


// ROUTE_LABEL moved to incidentLifecycle.ts (PROJECT.md T17) — same
// reasoning as OWNERSHIP_COPY above. data.route is nullable on the wire (an
// incident that predates routing, or was never investigated), and the
// lookup at this page's own call site already falls back to 'Route' for
// that case.

// LinkRepositoryForm — closes the gap Argo CD/Flux don't have: their own
// Application/Kustomization CR tells ARGUS the repo automatically, but a
// plain `helm upgrade` (or a bare `kubectl apply`) leaves no such record
// anywhere in the cluster.
//
// BACKLOG.md F30 replaced the original, Helm-only version of this
// (hand-typed repository + path, blind) with a DISCOVERED and
// RENDER-PROVEN one, for BOTH shapes F30's owner decision 2026-09-09
// widened it to: a Helm release (every registered repository rendered in
// the sandbox and checked against the live object by
// kind+namespace+name — internal/api/objectmapping_discovery.go) and a
// plain-manifest object (every registered repository's own YAML parsed
// directly and checked the same way — internal/api/
// objectmapping_discovery_manifest.go, no sandbox needed since a plain
// manifest has no template step to run). Which shape applies is discovered
// by the backend, not asked of this component — `ownership` may be null
// (an unmanaged object is deliberately never summarized as ObjectOwnership;
// see that type's own doc comment), so this component's copy is driven by
// discoverRepositoryLink's own response `mode` once it loads, not by
// `ownership`.
//
// ARGUS still never links silently, even on an exact match — a human always
// confirms with one click (F30 decision 1). What changed is that the
// release-or-labels/path/scope are no longer typed in; they are proposed,
// proven, and the only decision left is which candidate (if more than one
// genuinely renders/declares the object) and how wide a scope to confirm at.
//
// Deliberately honest about what confirming does NOT do: it does not
// retroactively recompute THIS incident's own route/route_reason — those
// need a re-analyze. ownership.repo itself DOES refresh on this same
// request (the hub re-resolves ownership synchronously on confirm), which is
// why this component invalidates the incident query rather than only the
// repositories one.
// candidatePath is what confirm-repository-link stores as the mapping's
// Path — the values file when one proved a Helm match, the manifest file
// itself when one proved a plain-manifest match, else the chart's own
// directory. A chart at the repository root has chartPath === '' (a real,
// live case: shop-apps-helm's own chart lives there), which the backend's
// "path is required" validation would otherwise reject as though nothing
// had been chosen at all — '.' is the conventional, unambiguous "repository
// root" path instead of an empty string that reads as unset.
export function candidatePath(candidate: LinkCandidate): string {
  return candidate.valuesFile || candidate.chartPath || '.'
}

export function LinkRepositoryForm({ ownership, incidentId }: { ownership: ObjectOwnership | null; incidentId: string }) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const canRead = useHasCapability(CAP_REPO_READ)
  const canWrite = useHasCapability(CAP_REPO_WRITE)
  const writeDisabledReason = canWrite ? undefined : 'Requires repo:write'

  const discoveryQueryKey = ['incidents', incidentId, 'repository-link-discovery']
  const discovery = useQuery({
    queryKey: discoveryQueryKey,
    queryFn: () => discoverRepositoryLink(incidentId, accessToken!),
    enabled: !!accessToken && canRead,
  })

  const [error, setError] = useState<string | null>(null)
  const [confirmed, setConfirmed] = useState<{ objectName: string; objectNamespace: string; repoUrl: string; path: string; scopeLabel: string } | null>(null)

  const confirm = useMutation({
    mutationFn: ({ candidate, scope, scopeLabel }: { candidate: LinkCandidate; scope?: { type: 'Cluster' | 'AllClusters'; clusterId?: string }; scopeLabel: string }) =>
      confirmRepositoryLink(
        incidentId,
        { bindingId: candidate.bindingId, path: candidatePath(candidate), scope },
        accessToken!,
      ).then(() => ({
        objectName: discovery.data?.objectName ?? '',
        objectNamespace: discovery.data?.objectNamespace ?? '',
        repoUrl: candidate.repoUrl,
        path: candidatePath(candidate),
        scopeLabel,
      })),
    onSuccess: (result) => {
      // Invalidating the incident query is what makes ownership.repo (and so
      // the PR-availability chip above) reflect the confirmed link without a
      // page reload. Once that refetch lands, ownership.repo is no longer
      // empty and RecommendationChannels stops rendering this component at
      // all — so `confirmed` below is only ever seen for the moment between
      // this response and that refetch, then superseded by the real,
      // now-available PR route. That is the intended handoff, not a bug to
      // "fix" by keeping this component mounted past its own precondition.
      queryClient.invalidateQueries({ queryKey: ['repositories'] })
      queryClient.invalidateQueries({ queryKey: ['incidents', incidentId] })
      setConfirmed(result)
      setError(null)
    },
    onError: (e) => setError(e instanceof ApiError ? e.detail || e.message : e instanceof Error ? e.message : 'Something went wrong.'),
  })

  const decline = useMutation({
    mutationFn: () => declineRepositoryLink(incidentId, accessToken!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: discoveryQueryKey })
      setError(null)
    },
    onError: (e) => setError(e instanceof ApiError ? e.detail || e.message : e instanceof Error ? e.message : 'Something went wrong.'),
  })

  if (confirmed) {
    return (
      <p className="field-hint">
        <span aria-hidden="true">✓</span> Linked <code>{confirmed.objectName}</code>/<code>{confirmed.objectNamespace}</code> to{' '}
        <code>{confirmed.repoUrl}</code> at <code>{confirmed.path}</code> ({confirmed.scopeLabel}). This incident's own
        recommendation needs a re-analyze to pick up the new route.
      </p>
    )
  }

  if (!canRead) {
    return (
      <p className="banner banner-warning" role="alert">
        You don't have access to check for a repository link. Missing capability: {CAP_REPO_READ}.
      </p>
    )
  }

  // Known immediately from `ownership` for the Helm case (so the heading
  // does not flash from generic to specific once discovery resolves — a
  // real layout-stability regression a first version of this change had);
  // the manifest case has no such prop to read (`ownership` is deliberately
  // null for it) and only becomes known once discovery's own response says
  // so.
  const mode = discovery.data?.mode ?? (ownership?.managedBy === 'helm' ? 'helm' : undefined)
  const heading =
    mode === 'manifest' ? 'Link this object to a repository' : mode === 'helm' ? 'Link this Helm release to a repository' : 'Check for a repository link'
  const helpText =
    mode === 'manifest'
      ? "This object has no Helm release and no Argo CD/Flux controller, so ARGUS has no repository for it yet. ARGUS checks every registered repository's own files for this exact object and asks you to confirm what it found — never a typed label selector."
      : "Argo CD and Flux tell ARGUS their repository automatically, from their own Application/Kustomization object. Helm has nothing equivalent, so ARGUS renders every registered repository and checks whether it produces this exact object — you only confirm what it proved."

  return (
    <div className="repo-change-add-file">
      <label>
        {heading}
        <HelpTip text={helpText} />
      </label>
      {/* 3 lines, not 1 — the populated case is a candidate row (head, proof
          sentence, action row) or more than one, and a skeleton shorter than
          what follows guarantees the layout jump it exists to prevent. */}
      {discovery.isLoading && <SkeletonLines count={3} />}
      {discovery.isError && (
        <p className="form-error inline-error" role="alert">
          {discovery.error instanceof ApiError ? discovery.error.detail || discovery.error.message : 'Could not check for a repository link.'}
        </p>
      )}
      {discovery.data && (
        <DiscoveryResult
          result={discovery.data}
          canWrite={canWrite}
          writeDisabledReason={writeDisabledReason}
          confirmPending={confirm.isPending}
          declinePending={decline.isPending}
          onConfirm={(candidate, scope, scopeLabel) => confirm.mutate({ candidate, scope, scopeLabel })}
          onDecline={() => decline.mutate()}
        />
      )}
      {error && (
        <p className="form-error inline-error" role="alert">
          {error}
        </p>
      )}
    </div>
  )
}

// DiscoveryResult renders discoverRepositoryLink's five possible answers.
// 'none' and 'degraded' are deliberately never merged into one message — a
// chart that could not be rendered has told ARGUS nothing about whether it
// produces the object, which is a different fact from a chart that rendered
// cleanly and did not (F30's own LinkDiscoveryResult doc comment).
export function DiscoveryResult({
  result,
  canWrite,
  writeDisabledReason,
  confirmPending,
  declinePending,
  onConfirm,
  onDecline,
}: {
  result: DiscoverRepositoryLinkResponse
  canWrite: boolean
  writeDisabledReason?: string
  confirmPending: boolean
  declinePending: boolean
  onConfirm: (candidate: LinkCandidate, scope: { type: 'Cluster' | 'AllClusters'; clusterId?: string } | undefined, scopeLabel: string) => void
  onDecline: () => void
}) {
  const isManifest = result.mode === 'manifest'
  // 'helm' identifies the subject by release; 'manifest' has none, so it is
  // identified by the object itself — the two identity shapes F30's owner
  // decision 2026-09-09 introduced, matching helmReleaseTarget's own doc
  // comment on the backend.
  const subject = isManifest ? (
    <>
      <code>{result.objectGvk}</code> <code>{result.objectNamespace}</code>/<code>{result.objectName}</code>
    </>
  ) : (
    <>
      release <code>{result.releaseName}</code>/<code>{result.namespace}</code>
    </>
  )
  const provingWord = isManifest ? 'parsed' : 'rendered'

  if (result.status === 'declined') {
    return (
      <p className="field-hint">
        You previously declined a discovered link for {subject}. ARGUS won't ask again for this{' '}
        {isManifest ? 'object' : 'release'} — it can still be linked by hand in{' '}
        <Link to="/settings?section=repositories">Settings → Repositories</Link>.
      </p>
    )
  }

  if (result.status === 'degraded') {
    return (
      <p className="field-hint">
        <span className="verification-chip verification-chip-neutral">Could not verify — {result.degraded}</span>
        <br />
        Not the same as "no repository {provingWord === 'rendered' ? 'renders' : 'declares'} this" — ARGUS could not attempt
        or complete the check. Try again later, or link it by hand in{' '}
        <Link to="/settings?section=repositories">Settings → Repositories</Link>.
      </p>
    )
  }

  if (result.status === 'none') {
    return (
      <p className="field-hint">
        <span className="verification-chip verification-chip-neutral">
          Not available — no registered repository {provingWord === 'rendered' ? 'renders' : 'declares'} this object
        </span>
        <br />
        ARGUS {provingWord} every registered repository and none produced this exact object — the real answer for content
        nobody has a repository for (e.g. a third-party chart like cert-manager).
      </p>
    )
  }

  // 'proven' (exactly one candidate) and 'ambiguous' (more than one) share
  // the same per-candidate row — F30 decision 5: present every one, pick
  // none. The widen-to-other-clusters offer only applies to Helm mode's
  // 'proven' status: manifest mode has no release identity to widen BY (see
  // the backend's own otherClustersRunningRelease doc comment), and with
  // more than one candidate still open in either mode, which repository is
  // right is the unresolved question, and adding a scope choice on top of
  // it multiplies the decisions rather than helping make one.
  // Null rather than [] in two real cases, both from
  // internal/api/objectmapping_link_endpoints.go's handleDiscoverRepositoryLink:
  // manifest mode never assigns otherClusters at all (there is no release
  // identity to widen BY), and helm mode leaves it nil when the widen query
  // fails non-fatally. Go marshals that nil slice as JSON null, so reading
  // .length off it straight would throw and take this whole panel down — which
  // is exactly what the hand-written type hid (PROJECT.md B189).
  const other = result.otherClusters ?? []
  const candidates = result.candidates ?? []
  const totalClusters = other.length + 1

  return (
    <>
      {result.status === 'ambiguous' && (
        <p className="field-hint">
          ARGUS found {candidates.length} repositories that all {provingWord === 'rendered' ? 'render' : 'declare'} this
          exact object — pick the right one, or decline. A monorepo alongside a split repo, a fork, or dev/prod overlays that
          both happen to match can all look like this.
        </p>
      )}
      {candidates.map((candidate) => (
        <div className="repo-change-file" key={candidate.bindingId + '#' + candidate.chartPath + '#' + (candidate.valuesFile ?? '')}>
          <div className="repo-change-file-head">
            <span className="verification-chip">{isManifest ? 'Parsed — proven match' : 'Rendered — proven match'}</span>
            <code>{candidate.repoUrl}</code>
          </div>
          <p className="field-hint">
            {isManifest ? (
              <>
                ARGUS parsed <code>{candidate.chartPath}</code> and it declares this exact live object.
              </>
            ) : (
              <>
                ARGUS rendered {candidate.chartPath ? <code>{candidate.chartPath}</code> : '(repository root)'}
                {candidate.valuesFile ? (
                  <>
                    {' '}with <code>{candidate.valuesFile}</code>
                  </>
                ) : null}{' '}
                and it produced this exact live object.
              </>
            )}
          </p>
          <div className="form-actions">
            <button
              type="button"
              disabled={!canWrite || confirmPending}
              title={writeDisabledReason}
              onClick={() => onConfirm(candidate, undefined, 'this cluster')}
            >
              {confirmPending ? 'Linking…' : 'Link for this cluster'}
            </button>
            {result.status === 'proven' && other.length > 0 && (
              <button
                type="button"
                className="secondary"
                disabled={!canWrite || confirmPending}
                title={
                  writeDisabledReason ??
                  `Applies to this cluster and every other cluster ARGUS has seen running ${result.releaseName}/${result.namespace}: ${other
                    .map((c) => c.clusterDisplayName)
                    .join(', ')} — and any further cluster that runs the same release.`
                }
                onClick={() => onConfirm(candidate, { type: 'AllClusters' }, `all ${totalClusters} clusters running ${result.releaseName}`)}
              >
                Link for all {totalClusters} clusters running {result.releaseName}
              </button>
            )}
          </div>
        </div>
      ))}
      <div className="form-actions">
        <button type="button" className="secondary" disabled={!canWrite || declinePending} title={writeDisabledReason} onClick={onDecline}>
          {declinePending ? 'Declining…' : "Don't ask again for this release"}
        </button>
      </div>
    </>
  )
}


// "Why this route?" — the provenance behind the route choice, collapsed (see
// the PROJECT.md D13 note in RecommendationChannels for why it is a disclosure).
export function RouteProvenance({ ownership }: { ownership: ObjectOwnership | null }) {
  const copy = ownership ? OWNERSHIP_COPY[ownership.managedBy] : undefined
  return (
    <>
      {ownership && (copy || ownership.repo) && (
        <details className="route-why-disclosure">
          <summary className="field-hint">Why this route?</summary>
      {copy && <p className="field-hint">{copy.fix}</p>}
      {/* "Fix it at the source" is advice nobody can act on without knowing
          where the source IS. The agent has resolved the repository, path and
          synced commit since WORKLOG §121 and the hub has stored it ever since;
          the API view simply dropped it. Shown here because it is useful long
          before ARGUS can open the PR itself (BACKLOG.md F15) — a human told the
          repo, the path and the commit can go and fix it today. */}
      {ownership?.repo && (
        <dl className="detail-fact-grid compact ownership-source">
          {/* Each field is a dt+dd pair wrapped in its own <div> — required by
              `.detail-fact-grid`'s `auto-fit` column layout (BACKLOG D7m):
              without the wrapper, auto-fit places dt/dd as independent grid
              items and wraps them wherever the column count lands, so a
              label and its OWN value can end up in different rows/columns
              entirely. The wrapper makes the PAIR the grid item, matching
              `RemediationPlanCard`'s existing `.detail-fact-grid` markup. */}
          <div>
            <dt>Repository</dt>
            <dd><code>{ownership.repo.url}</code></dd>
          </div>
          {ownership.repo.path && (
            <div>
              <dt>Path</dt>
              <dd><code>{ownership.repo.path}</code></dd>
            </div>
          )}
          {ownership.repo.revision && (
            <div>
              <dt>Synced commit</dt>
              <dd>
                <code>{ownership.repo.pinned ? ownership.repo.revision.slice(0, 12) : ownership.repo.revision}</code>{' '}
                {/* An unpinned revision is a branch name, not a commit. Saying
                    so matters: it means nobody can state which commit is
                    actually running, which changes what a reader should trust. */}
                {!ownership.repo.pinned && (
                  <span className="badge badge-gray" title="The controller reports a branch or tag rather than a resolved commit, so the exact running commit is not known">
                    not pinned
                  </span>
                )}
              </dd>
            </div>
          )}
          {ownership.repo.resolvedFrom && (
            <div>
              <dt>Read from</dt>
              <dd className="field-hint">{ownership.repo.resolvedFrom}</dd>
            </div>
          )}
        </dl>
      )}
        </details>
      )}
    </>
  )
}

