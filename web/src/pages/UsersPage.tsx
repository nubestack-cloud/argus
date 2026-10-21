import { useState } from 'react'
import { createPortal } from 'react-dom'
import type { FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  createGrant,
  createUser,
  disableUser,
  enableUser,
  getClusterGroups,
  getClusters,
  getCustomRoles,
  getUsers,
  removeUser,
  resetPassword,
  revokeGrant,
  ApiError,
} from '../api/client'
import type { BuiltinRole, ClusterGroup, CreateUserResponse, CustomRole, Grant, GrantScope, User } from '../api/types'
import { BUILTIN_ROLES, ROLE_DESCRIPTIONS, ROLE_LABELS } from '../api/types'
import { CAP_USER_MANAGE, CAP_USER_READ, CAP_USER_REMOVE } from '../api/capabilities'
import { useAuth } from '../auth/useAuth'
import { useHasCapability } from '../auth/useCapabilities'
import { TablePagination } from '../components/TablePagination'
import { usePagination } from '../utils/pagination'
import { formatDateTime, formatRelativeTime } from '../utils/time'
import { ActionMenu, type ActionMenuItem } from '../components/ActionMenu'
import { CopyButton } from '../components/CopyButton'
import { ConfirmDialog } from '../components/ConfirmDialog'
import { Dialog } from '../components/Dialog'
import { EmptyState } from '../components/EmptyState'
import { HelpTip } from '../components/HelpTip'
import { SearchIcon, UserPlusIcon } from '../components/icons'
import { SkeletonTableRows } from '../components/Skeleton'
import { STATIC_POLL_MS } from '../realtime/refresh'

// ROLE_DESCRIPTIONS itself now lives in api/types.ts, beside ROLE_LABELS and
// SettingsPage's ROLE_NOTES (BACKLOG D7f remainder) — this page held its own
// hand-maintained copy of "what a role does" and SettingsPage held a second,
// and the two had already drifted in emphasis before the fifth role
// (pr-approver) doubled the chance either copy gets forgotten. See that
// file's doc comment for why the two stayed separate exports.

// This is the "Users/roles/grants" sub-panel of lld/11-ui-design.md §3's
// AdminConsole component — the first slice of it, scoped deliberately
// narrowly (see the backend's internal/api/users.go doc comment for the
// full list of what's intentionally out of scope this round: no
// custom-role authoring, no ClusterGroup scope, no ad hoc capability-set
// grants, no user deletion beyond revoking every grant).

// Grant chips read by role, not one flat colour, matching .design/Users.dc.html's
// graphics: the role IS the fact a scan of this column is looking for, so it
// carries the same weight the app already gives severity/state everywhere else
// (a colour a reader learns once and reads at a glance). Ranked so a person
// holding several grants gets one left-rule below, from the highest tier they
// actually hold — super-admin outranks a viewer grant on another cluster, not
// the other way round. A role outside this map (a future builtin, or a stored
// grant with no role at all — the "custom" case GrantBadge already falls back
// to) gets rank 0 / badge-gray: unranked, not unimportant.
const ROLE_RANK: Record<string, number> = {
  'super-admin': 5,
  'tenant-admin': 4,
  resolver: 3,
  'pr-approver': 2,
  viewer: 1,
}

const ROLE_BADGE_CLASS: Record<string, string> = {
  'super-admin': 'badge-red',
  'tenant-admin': 'badge-orange',
  resolver: 'badge-blue',
  'pr-approver': 'badge-green',
  viewer: 'badge-gray',
}

const ROLE_RULE_COLOR: Record<string, string> = {
  'super-admin': 'var(--danger)',
  'tenant-admin': 'var(--color-orange)',
  resolver: 'var(--color-blue)',
  'pr-approver': 'var(--color-green)',
  viewer: 'var(--color-gray)',
}

function grantBadgeClass(role: string): string {
  return ROLE_BADGE_CLASS[role] ?? 'badge-gray'
}

// The row's own left rule: the colour of the HIGHEST-ranked role this user
// currently holds any grant for, across every cluster — the same "worst/most
// wins" rule ClustersPage/OverviewPage already apply to their own per-row
// accents, just ranked by privilege instead of by severity or state.
function topRoleRuleColor(grants: Grant[]): string {
  let best = { rank: 0, role: '' }
  for (const grant of grants) {
    const rank = ROLE_RANK[grant.role] ?? 0
    if (rank > best.rank) best = { rank, role: grant.role }
  }
  return ROLE_RULE_COLOR[best.role] ?? 'var(--border)'
}

// A stored Grant's `role` is a plain `string` on the wire (a pre-existing
// grant could hold a role this build no longer recognises, or — BACKLOG.md
// S3 — a custom role's id), while ROLE_DESCRIPTIONS is keyed by the closed
// BuiltinRole union — so a lookup from a live grant needs a loosened index
// rather than a cast at every call site. Falls back to a custom role's own
// name, when the id resolves to one, so this reads as prose ("on-call
// viewer") rather than a raw generated id.
function roleDescription(role: string, customRoles: CustomRole[]): string | undefined {
  const builtin = (ROLE_DESCRIPTIONS as Record<string, string>)[role]
  if (builtin) return builtin
  const custom = customRoles.find((r) => r.id === role)
  if (!custom) return undefined
  return `Custom role: ${custom.capabilities.length} capabilit${custom.capabilities.length === 1 ? 'y' : 'ies'} (${custom.capabilities.join(', ')}).`
}

// A role id's DISPLAY name — the builtin label when it's a builtin role, a
// custom role's own name when it resolves to one, and the raw id as a last
// resort (a pre-existing grant naming a role this tenant later deleted).
function roleLabel(role: string, customRoles: CustomRole[]): string {
  const builtin = (ROLE_LABELS as Record<string, string>)[role]
  if (builtin) return builtin
  return customRoles.find((r) => r.id === role)?.name ?? role
}

function scopeLabel(
  scope: GrantScope,
  clusterNames: Map<string, string>,
  clusterGroupNames: Map<string, string>,
): string {
  if (scope.type === 'AllClusters') return 'All clusters'
  if (scope.type === 'Cluster') {
    return clusterNames.get(scope.clusterId ?? '') ?? scope.clusterId ?? 'Unknown cluster'
  }
  const groupId = scope.clusterGroupId ?? ''
  return `Group: ${clusterGroupNames.get(groupId) ?? groupId ?? 'unknown'}`
}

// Human-readable target description for a confirmation step, built from the
// picker's own draft state rather than a committed Grant — the same purpose
// scopeLabel serves for an existing grant's badge, just before the grant
// exists.
function describeDraftScope(
  scopeType: GrantScope['type'],
  clusterId: string,
  clusterGroupId: string,
  clusters: Array<{ id: string; displayName: string }>,
  clusterGroups: ClusterGroup[],
): string {
  if (scopeType === 'AllClusters') return 'ALL clusters — including any added later'
  if (scopeType === 'ClusterGroup') {
    return `the "${clusterGroups.find((g) => g.id === clusterGroupId)?.name ?? clusterGroupId}" cluster group — including any cluster added to it later`
  }
  return clusters.find((c) => c.id === clusterId)?.displayName ?? clusterId
}

// The role's own consequence, surfaced at the point of choosing it rather
// than only as a hover HelpTip on a badge after the grant already exists
// (BACKLOG D7e — the D7h `.consequence-notice` primitive is what makes this
// louder than a `.field-hint` specifically for the one role that mints
// super-admin, the widest possible privilege in this product). `role` is a
// plain `string` now (BACKLOG.md S3): it may name a custom role instead of
// a builtin one, and roleDescription resolves either.
function RoleConsequenceNote({ role, customRoles }: { role: string; customRoles: CustomRole[] }) {
  const text = roleDescription(role, customRoles)
  if (!text) return null
  return <p className={role === 'super-admin' ? 'consequence-notice' : 'field-hint'}>{text}</p>
}

function GrantBadge({
  grant,
  clusterNames,
  clusterGroupNames,
  customRoles,
  userId,
  disabledReason,
}: {
  grant: Grant
  clusterNames: Map<string, string>
  clusterGroupNames: Map<string, string>
  customRoles: CustomRole[]
  userId: string
  disabledReason?: string
}) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const mutation = useMutation({
    mutationFn: () => revokeGrant(userId, grant.id, accessToken!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users'] }),
  })
  const [confirming, setConfirming] = useState(false)

  const label = grant.role ? roleLabel(grant.role, customRoles) : 'custom'
  const scope = scopeLabel(grant.scope, clusterNames, clusterGroupNames)

  return (
    <span className={`badge ${grantBadgeClass(grant.role)} grant-badge`}>
      {/* Provenance goes in the tooltip rather than the badge: who granted a
          permission and when is the first thing asked in an access review, the
          API has always returned both, and nothing displayed either. It belongs
          on hover instead of inline because the badge's job is to be scannable —
          a row of grants each carrying an email and a date stops being one.
          The reason is included too, now that the grant form collects one
          (owner decision 2026-08-22) — it is the answer to the question an
          access review opens with, and it was previously stored by nothing. */}
      <span
        className="grant-badge-text"
        title={[
          `${label} @ ${scope}`,
          grant.grantedBy ? `Granted by ${grant.grantedBy}` : null,
          grant.grantedAt ? `on ${formatDateTime(grant.grantedAt)}` : null,
          grant.justification ? `Reason: ${grant.justification}` : null,
        ].filter(Boolean).join('\n')}
      >
        {/* Role carries the badge's own tone (bold, inheriting the coloured
            text above); scope is deliberately re-muted to neutral — it is
            WHERE, not WHAT, and .design/Users.dc.html draws exactly this
            distinction between the two halves of one chip. */}
        <strong>{label}</strong>{' '}
        <span className="grant-badge-scope">@ {scope}</span>
      </span>
      {grant.role && roleDescription(grant.role, customRoles) && (
        <HelpTip label={label} text={roleDescription(grant.role, customRoles)!} />
      )}
      <button
        type="button"
        className="grant-revoke"
        title={disabledReason ?? 'Revoke this grant'}
        disabled={mutation.isPending || !!disabledReason}
        aria-label={`Revoke the ${label} grant on ${scope}`}
        onClick={() => setConfirming(true)}
      >
        ×
      </button>
      {confirming && (
        <ConfirmDialog
          title="Revoke grant"
          confirmLabel="Revoke grant"
          pendingLabel="Revoking…"
          pending={mutation.isPending}
          error={mutation.error}
          onCancel={() => {
            setConfirming(false)
            mutation.reset()
          }}
          onConfirm={() => mutation.mutate(undefined, { onSuccess: () => setConfirming(false) })}
        >
          <p>
            Revoke <strong>{label}</strong> on <strong>{scope}</strong>? It takes effect immediately. It can be
            undone only by creating a new grant.
          </p>
        </ConfirmDialog>
      )}
    </span>
  )
}

function ScopePicker({
  scopeType,
  setScopeType,
  clusterId,
  setClusterId,
  clusterGroupId,
  setClusterGroupId,
  clusters,
  clusterGroups,
  disabled,
}: {
  scopeType: GrantScope['type']
  setScopeType: (t: GrantScope['type']) => void
  clusterId: string
  setClusterId: (id: string) => void
  clusterGroupId: string
  setClusterGroupId: (id: string) => void
  clusters: Array<{ id: string; displayName: string }>
  clusterGroups: ClusterGroup[]
  disabled?: boolean
}) {
  return (
    <>
      <label htmlFor="scopeType">Scope</label>
      <select
        id="scopeType"
        value={scopeType}
        onChange={(e) => setScopeType(e.target.value as GrantScope['type'])}
        disabled={disabled}
      >
        {/* "(default)" stated on the option itself (BACKLOG D7e) — this was
            the widest-blast-radius choice with nothing on screen saying it
            was also the one already selected, so a person who never opened
            this dropdown at all still granted every cluster. */}
        <option value="AllClusters">All clusters (default)</option>
        <option value="Cluster">A specific cluster</option>
        <option value="ClusterGroup">A cluster group</option>
      </select>

      {scopeType === 'AllClusters' && (
        <p className="consequence-notice">
          Applies to every cluster in the org, including any enrolled later — the widest scope this
          form can grant.
        </p>
      )}

      {scopeType === 'ClusterGroup' && (
        <>
          <label htmlFor="clusterGroupId">Cluster group</label>
          {clusterGroups.length === 0 ? (
            <p className="field-hint">
              No cluster groups exist yet — create one from Settings → Roles & access first.
            </p>
          ) : (
            <>
              <select
                id="clusterGroupId"
                value={clusterGroupId}
                onChange={(e) => setClusterGroupId(e.target.value)}
                disabled={disabled}
              >
                <option value="" disabled>
                  Select a cluster group…
                </option>
                {clusterGroups.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name} ({g.clusterIds.length} cluster{g.clusterIds.length === 1 ? '' : 's'})
                  </option>
                ))}
              </select>
              <p className="consequence-notice">
                Applies to every cluster currently in this group, and any added to it later — access
                follows the group's membership, not a fixed snapshot of it.
              </p>
            </>
          )}
        </>
      )}

      {scopeType === 'Cluster' && (
        <>
          <label htmlFor="clusterId">Cluster</label>
          <select id="clusterId" value={clusterId} onChange={(e) => setClusterId(e.target.value)} disabled={disabled}>
            <option value="" disabled>
              Select a cluster…
            </option>
            {clusters.map((c) => (
              <option key={c.id} value={c.id}>
                {c.displayName}
              </option>
            ))}
          </select>
        </>
      )}
    </>
  )
}

// Mirrors EnrollTokenModal.tsx's exact pattern: a form, then — once the
// mutation succeeds — a dismissible one-time-reveal panel for the secret
// (here, the temporary password) that never appears again after this modal
// closes.
function CreateUserModal({
  clusters,
  clusterGroups,
  customRoles,
  onClose,
}: {
  clusters: Array<{ id: string; displayName: string }>
  clusterGroups: ClusterGroup[]
  customRoles: CustomRole[]
  onClose: () => void
}) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()

  const [email, setEmail] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [grantNow, setGrantNow] = useState(true)
  // Widened from BuiltinRole to `string` (BACKLOG.md S3): the value may be a
  // custom role's id instead of a fixed builtin name — see CreateUserRequest.
  const [role, setRole] = useState<string>('viewer')
  const [scopeType, setScopeType] = useState<GrantScope['type']>('AllClusters')
  const [clusterId, setClusterId] = useState('')
  const [clusterGroupId, setClusterGroupId] = useState('')
  const [result, setResult] = useState<CreateUserResponse | null>(null)

  const mutation = useMutation({
    mutationFn: () =>
      createUser(
        {
          email,
          displayName: displayName || undefined,
          initialGrant: grantNow
            ? {
                role,
                scope:
                  scopeType === 'AllClusters'
                    ? { type: 'AllClusters' }
                    : scopeType === 'ClusterGroup'
                      ? { type: 'ClusterGroup', clusterGroupId }
                      : { type: 'Cluster', clusterId },
              }
            : undefined,
        },
        accessToken!,
      ),
    onSuccess: (data) => {
      setResult(data)
      queryClient.invalidateQueries({ queryKey: ['users'] })
    },
  })

  const canSubmit =
    email.trim() !== '' &&
    (!grantNow ||
      scopeType === 'AllClusters' ||
      (scopeType === 'Cluster' && clusterId !== '') ||
      (scopeType === 'ClusterGroup' && clusterGroupId !== ''))

  // BACKLOG D7e. Revoke/disable/remove/reset-password all confirm and name
  // their target; this could mint a super-admin grant over every cluster on
  // a plain submit with none. Only asks when a grant is actually being
  // created — creating a user with no initial grant isn't a
  // privilege-granting action and doesn't need the same friction.
  //
  // The confirmation is a step inside this dialog rather than a native
  // prompt: the form stays in view above it, so what is being confirmed is
  // on screen, and editing any field takes the step back.
  const [confirming, setConfirming] = useState(false)
  function confirmAndSubmit(e: FormEvent) {
    e.preventDefault()
    if (!grantNow || confirming) {
      mutation.mutate()
      return
    }
    setConfirming(true)
  }
  const draftTarget = describeDraftScope(scopeType, clusterId, clusterGroupId, clusters, clusterGroups)

  return (
    <Dialog title="Create user" onClose={onClose}>
        {!result && (
          <form onSubmit={confirmAndSubmit} onChange={() => setConfirming(false)}>
            <label htmlFor="newUserEmail">Email</label>
            <input
              id="newUserEmail"
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />

            <label htmlFor="newUserDisplayName">Display name (optional)</label>
            <input
              id="newUserDisplayName"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder={email || 'Defaults to the email address'}
            />

            <div className="checkbox-row">
              <input
                id="grantNow"
                type="checkbox"
                checked={grantNow}
                onChange={(e) => setGrantNow(e.target.checked)}
              />
              <label htmlFor="grantNow">Grant a role immediately</label>
            </div>

            {grantNow && (
              <>
                <label htmlFor="newUserRole">Role</label>
                <select
                  id="newUserRole"
                  value={role}
                  onChange={(e) => setRole(e.target.value)}
                >
                  <optgroup label="Builtin roles">
                    {BUILTIN_ROLES.map((r) => (
                      <option key={r} value={r}>
                        {ROLE_LABELS[r]}
                      </option>
                    ))}
                  </optgroup>
                  {customRoles.length > 0 && (
                    <optgroup label="Custom roles">
                      {customRoles.map((r) => (
                        <option key={r.id} value={r.id}>
                          {r.name}
                        </option>
                      ))}
                    </optgroup>
                  )}
                </select>
                <RoleConsequenceNote role={role} customRoles={customRoles} />

                <ScopePicker
                  scopeType={scopeType}
                  setScopeType={setScopeType}
                  clusterId={clusterId}
                  setClusterId={setClusterId}
                  clusterGroupId={clusterGroupId}
                  setClusterGroupId={setClusterGroupId}
                  clusters={clusters}
                  clusterGroups={clusterGroups}
                />
              </>
            )}

            {mutation.isError && (
              <p className="form-error" role="alert">
                {mutation.error instanceof ApiError
                  ? mutation.error.detail
                    ? `${mutation.error.message} — ${mutation.error.detail}`
                    : mutation.error.message
                  : 'Something went wrong. Please try again.'}
              </p>
            )}

            {confirming ? (
              <>
                <p className="consequence-notice" role="status">
                  Create <strong>{email || 'this user'}</strong> and grant them{' '}
                  <strong>{roleLabel(role, customRoles)}</strong> on <strong>{draftTarget}</strong>?
                </p>
                <div className="modal-actions">
                  <button type="button" className="secondary" onClick={() => setConfirming(false)} disabled={mutation.isPending}>
                    Back
                  </button>
                  <button type="submit" disabled={mutation.isPending || !canSubmit}>
                    {mutation.isPending ? 'Creating…' : 'Create user and grant'}
                  </button>
                </div>
              </>
            ) : (
              <div className="modal-actions">
                <button type="button" className="secondary" onClick={onClose}>
                  Cancel
                </button>
                <button type="submit" disabled={mutation.isPending || !canSubmit}>
                  {mutation.isPending ? 'Creating…' : 'Create user'}
                </button>
              </div>
            )}
          </form>
        )}

        {result && (
          <div className="token-result">
            <p>
              User <strong>{result.user.email}</strong> created.
            </p>

            <label>Temporary password</label>
            <div className="code-block-row">
              <code className="code-block">{result.temporaryPassword}</code>
              <CopyButton text={result.temporaryPassword} />
            </div>
            <p className="field-hint">
              This password is shown <strong>once</strong> and is not recoverable after this dialog
              closes. They'll be asked to choose their own password the first time they sign in.
            </p>

            <button type="button" onClick={onClose}>
              Done
            </button>
          </div>
        )}
    </Dialog>
  )
}

// The one-time-reveal panel for a fresh temporary password — the exact same
// markup/CSS pattern (.token-result/.code-block-row/.code-block/.field-hint)
// CreateUserModal's own result panel above uses, just wrapped in its own
// modal rather than following a create-user form, since this one follows a
// native-confirm button click on an existing row (ResetPasswordAction
// below) rather than a form of its own.
function ResetPasswordResultModal({
  userEmail,
  temporaryPassword,
  onClose,
}: {
  userEmail: string
  temporaryPassword: string
  onClose: () => void
}) {
  return (
    <Dialog title="Password reset" onClose={onClose}>
        <div className="token-result">
          <p>
            New temporary password for <strong>{userEmail}</strong>:
          </p>

          <label>Temporary password</label>
          <div className="code-block-row">
            <code className="code-block">{temporaryPassword}</code>
            <CopyButton text={temporaryPassword} />
          </div>
          {/* prose-ok: an irreversible dialog's consequence statement */}
          <p className="field-hint">
            This password is shown <strong>once</strong> and is not recoverable after this dialog
            closes. Every session this user held has already ended — they must sign in with this
            password and will be asked to choose their own straight away.
          </p>

          <button type="button" onClick={onClose}>
            Done
          </button>
        </div>
    </Dialog>
  )
}

// Per-row "Reset password" action — a real, if reversible-by-another-reset,
// destructive action (it ends the user's current session(s) immediately), so
// it asks for confirmation the same way GrantBadge's revoke button above
// does (a ConfirmDialog naming the user) and
// then shows its result through ResetPasswordResultModal above.
//
// A hook, not a component that renders its own button, now that this
// action lives inside a shared per-row ActionMenu (bugs-and-fixes.txt item
// 24: "Rename/Decommission etc... should be a dropdown menu... Users menu
// for example has same issue"): ActionMenu's own popover unmounts the
// moment it closes, so anything that needs to outlive that (this
// mutation's pending/error/success state, and the result modal it shows)
// has to be owned by something that doesn't unmount with it — the row
// itself, via this hook — not by a component living inside the menu.
// Returns the menu item (label/onClick/disabled) plus `extra`: JSX that
// must render in the row regardless of whether the menu is currently open
// (the error message, and the success modal).
function useResetPasswordAction(userId: string, userEmail: string, disabledReason?: string) {
  const { accessToken } = useAuth()
  const mutation = useMutation({
    mutationFn: () => resetPassword(userId, accessToken!),
  })
  const [confirming, setConfirming] = useState(false)

  const item: ActionMenuItem = {
    label: mutation.isPending ? 'Resetting…' : 'Reset password',
    disabled: mutation.isPending || !!disabledReason,
    disabledReason: disabledReason ?? 'Reset this user’s password',
    onClick: () => setConfirming(true),
  }

  const extra = (
    <>
      {confirming && (
        <ConfirmDialog
          title="Reset password"
          confirmLabel="Reset password"
          pendingLabel="Resetting…"
          pending={mutation.isPending}
          error={mutation.error}
          onCancel={() => {
            setConfirming(false)
            mutation.reset()
          }}
          onConfirm={() => mutation.mutate(undefined, { onSuccess: () => setConfirming(false) })}
        >
          <p>
            Reset the password for <strong>{userEmail}</strong>? Every session they hold ends immediately, and
            they'll need the temporary password shown next to sign in again.
          </p>
        </ConfirmDialog>
      )}
      {/* Portaled for the same reason ConfirmDialog is: this renders inside
          the user's table row, whose nowrap cell styles it would inherit. */}
      {mutation.isSuccess &&
        createPortal(
          <ResetPasswordResultModal
            userEmail={userEmail}
            temporaryPassword={mutation.data.temporaryPassword}
            onClose={() => mutation.reset()}
          />,
          document.body,
        )}
    </>
  )

  return { item, extra }
}

// Renders a user's disabled/active state — the same badge conventions
// already used across this page ("Must change password") and the rest of
// the app (badge-green for a healthy/active state, badge-red for a
// stopped/error-like one, matching ClusterDetailPage's Active/Rejected
// badges and AuditLogPage's success/error badges).
function UserStatusBadge({ disabledAt }: { disabledAt: string | null }) {
  if (disabledAt) {
    return (
      <span className="badge badge-red" title={`Disabled ${formatDateTime(disabledAt)}`}>
        Disabled
      </span>
    )
  }
  return <span className="badge badge-green">Active</span>
}

// Per-row "Disable"/"Enable" action — the other half of the "user lifecycle
// management is missing" gap this round closes (creation/grants/password
// reset already existed; there was no way to stop an account from being
// used at all). Disable is a real, if reversible, access-affecting action —
// it ends the user's current session(s) immediately and blocks their next
// login — so it asks for confirmation through the same ConfirmDialog that
// ResetPasswordAction and GrantBadge's revoke button use. Enable is not
// gated behind a confirm step: it's the reversal of that action, not a new
// access-affecting one, matching the backend's own "enabling isn't
// security-sensitive the way disabling is" reasoning.
// Same hook-not-component shape as useResetPasswordAction just above, and
// for the same reason (this action now lives inside a shared per-row
// ActionMenu). Returns exactly one item — Enable or Disable, whichever
// applies to this user's current state — plus `extra`: the error message,
// which must render in the row regardless of whether the menu is open.
function useUserStatusAction(userId: string, userEmail: string, disabledAt: string | null, disabledReason?: string) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()

  const disableMutation = useMutation({
    mutationFn: () => disableUser(userId, accessToken!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users'] }),
  })
  const enableMutation = useMutation({
    mutationFn: () => enableUser(userId, accessToken!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users'] }),
  })
  const [confirmingDisable, setConfirmingDisable] = useState(false)

  if (disabledAt) {
    const item: ActionMenuItem = {
      label: enableMutation.isPending ? 'Enabling…' : 'Enable',
      disabled: enableMutation.isPending || !!disabledReason,
      disabledReason: disabledReason ?? `Re-enable ${userEmail}`,
      onClick: () => enableMutation.mutate(),
    }
    const extra = enableMutation.isError && (
      <p className="form-error inline-error" role="alert">
        {enableMutation.error instanceof ApiError ? enableMutation.error.message : 'Could not enable user.'}
      </p>
    )
    return { item, extra }
  }

  const item: ActionMenuItem = {
    label: disableMutation.isPending ? 'Disabling…' : 'Disable',
    disabled: disableMutation.isPending || !!disabledReason,
    disabledReason: disabledReason ?? `Disable ${userEmail}`,
    danger: true,
    onClick: () => setConfirmingDisable(true),
  }
  const extra = confirmingDisable && (
    <ConfirmDialog
      title="Disable user"
      confirmLabel="Disable user"
      pendingLabel="Disabling…"
      pending={disableMutation.isPending}
      error={disableMutation.error}
      onCancel={() => {
        setConfirmingDisable(false)
        disableMutation.reset()
      }}
      onConfirm={() => disableMutation.mutate(undefined, { onSuccess: () => setConfirmingDisable(false) })}
    >
      {/* prose-ok: an irreversible dialog's consequence statement */}
      <p>
        Disable <strong>{userEmail}</strong>? Every session they hold ends immediately, their AI tool tokens are
        revoked, and they can't sign in until re-enabled. Re-enabling does not restore the tokens — they'd create
        new ones.
      </p>
    </ConfirmDialog>
  )
  return { item, extra }
}

// Per-row "Remove user" action. This is stronger than Disable: the row is
// removed from active user management, active grants are revoked, and the
// user's sessions are ended. The backend keeps historical identity rows so
// audit events remain trustworthy; the UI labels it "Remove" rather than
// "Delete" for that same reason.
function useRemoveUserAction(userId: string, userEmail: string, disabledReason?: string) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const mutation = useMutation({
    mutationFn: () => removeUser(userId, accessToken!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users'] }),
  })
  const [confirming, setConfirming] = useState(false)

  const item: ActionMenuItem = {
    label: mutation.isPending ? 'Removing…' : 'Remove user',
    disabled: mutation.isPending || !!disabledReason,
    disabledReason: disabledReason ?? `Remove ${userEmail}`,
    danger: true,
    onClick: () => setConfirming(true),
  }

  const extra = confirming && (
    <ConfirmDialog
      title="Remove user"
      confirmLabel="Remove user"
      pendingLabel="Removing…"
      pending={mutation.isPending}
      error={mutation.error}
      onCancel={() => {
        setConfirming(false)
        mutation.reset()
      }}
      onConfirm={() => mutation.mutate(undefined, { onSuccess: () => setConfirming(false) })}
    >
      {/* prose-ok: an irreversible dialog's consequence statement */}
      <p>
        Remove <strong>{userEmail}</strong>? Their grants and AI tool tokens are revoked, every session ends, and
        they leave this list. Their past actions stay in the audit log under their name. This can't be undone here.
      </p>
    </ConfirmDialog>
  )
  return { item, extra }
}

// The "Actions" cell for one row — its own component (not inlined in the
// row's .map()) because useResetPasswordAction/useUserStatusAction are
// hooks: calling a hook from inside a .map() callback, rather than from a
// real component, breaks React's rules of hooks the moment the number of
// rows changes between renders. A single ActionMenu now replaces what used
// to be two always-visible buttons per row (bugs-and-fixes.txt item 24),
// plus the "+ Add grant" button that used to sit at the end of the Grants
// cell's badge list — same clutter argument, and it keeps every per-row
// action for a user behind one predictable trigger instead of splitting
// them across two columns.
//
// `onAddGrant` is passed in as a plain callback rather than this component
// owning the dialog itself, for the reason spelled out in ActionMenu's own
// doc comment: the popover unmounts the moment it closes, so the Add-grant
// Dialog has to be owned by the page (via its addGrantForUserId state),
// exactly as it already was when a row button opened it.
function UserActionsCell({
  user,
  disabledReason,
  onAddGrant,
}: {
  user: User
  disabledReason?: string
  onAddGrant: () => void
}) {
  const canRemove = useHasCapability(CAP_USER_REMOVE)
  const resetPassword = useResetPasswordAction(user.id, user.email, disabledReason)
  const status = useUserStatusAction(user.id, user.email, user.disabledAt, disabledReason)
  const remove = useRemoveUserAction(
    user.id,
    user.email,
    canRemove ? undefined : `Missing capability: ${CAP_USER_REMOVE}`,
  )

  // Disabled-with-a-reason, never hidden, when the actor lacks
  // CAP_USER_MANAGE (lld/11-ui-design.md §6) — carrying over exactly what
  // the removed row button did with disabled/title.
  const addGrant: ActionMenuItem = {
    label: 'Add grant',
    disabled: !!disabledReason,
    disabledReason: disabledReason ?? `Grant ${user.email} an additional role`,
    onClick: onAddGrant,
  }

  return (
    <td className="user-actions-cell table-pinned-actions">
      <div className="user-actions-wrap">
        <ActionMenu
          ariaLabel={`Actions for ${user.email}`}
          items={[addGrant, resetPassword.item, status.item, remove.item]}
        />
        {resetPassword.extra}
        {status.extra}
        {remove.extra}
      </div>
    </td>
  )
}

// Inline "add another grant to an existing user" form — the
// POST /users/{id}/grants counterpart to CreateUserModal's optional
// initial-grant field, for the equally common case of granting an
// ADDITIONAL role to a user who already exists (e.g. promoting a viewer to
// resolver on one more cluster) without going through user creation again.
function AddGrantForm({
  userId,
  userEmail,
  clusters,
  clusterGroups,
  customRoles,
  disabledReason,
  onDone,
}: {
  userId: string
  userEmail: string
  clusters: Array<{ id: string; displayName: string }>
  clusterGroups: ClusterGroup[]
  customRoles: CustomRole[]
  disabledReason?: string
  onDone: () => void
}) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  // Widened from BuiltinRole to `string` (BACKLOG.md S3) — see
  // CreateUserModal's identical note.
  const [role, setRole] = useState<string>('viewer')
  const [scopeType, setScopeType] = useState<GrantScope['type']>('AllClusters')
  const [clusterId, setClusterId] = useState('')
  const [clusterGroupId, setClusterGroupId] = useState('')
  // Optional by owner decision (2026-08-22). The column and the API have always
  // accepted a reason and no UI ever collected one, so every stored grant had an
  // empty one — leaving "why does this person have this access", the question an
  // access review opens with, unanswerable from ARGUS. Optional rather than
  // required because a mandatory free-text field collects "asdf" under time
  // pressure: a real reason on the grants someone will actually ask about beats
  // a complete trail of worthless ones.
  //
  // Deliberately not added to CreateUserModal's initial-grant path as well:
  // createUserRequest.initialGrant carries only role and scope, so that would
  // need its own backend change. Worth doing, not silently half-done here.
  const [justification, setJustification] = useState('')

  const mutation = useMutation({
    mutationFn: () =>
      createGrant(
        userId,
        {
          role,
          scope:
            scopeType === 'AllClusters'
              ? { type: 'AllClusters' }
              : scopeType === 'ClusterGroup'
                ? { type: 'ClusterGroup', clusterGroupId }
                : { type: 'Cluster', clusterId },
          ...(justification.trim() !== '' && { justification: justification.trim() }),
        },
        accessToken!,
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      onDone()
    },
  })

  const canSubmit =
    scopeType === 'AllClusters' ||
    (scopeType === 'Cluster' && clusterId !== '') ||
    (scopeType === 'ClusterGroup' && clusterGroupId !== '')

  // BACKLOG D7e. This is the plain-submit path the review named directly:
  // "Add grant" minting a super-admin-over-AllClusters grant with no
  // confirmation at all, while every other privilege-affecting action on
  // this same page (revoke/disable/remove/reset password) confirms and
  // names its target. A step inside this dialog, like Create user's: the
  // choices stay on screen above the question, and editing one steps back.
  const [confirming, setConfirming] = useState(false)
  function confirmAndSubmit(e: FormEvent) {
    e.preventDefault()
    if (confirming) {
      mutation.mutate()
      return
    }
    setConfirming(true)
  }
  const draftTarget = describeDraftScope(scopeType, clusterId, clusterGroupId, clusters, clusterGroups)

  return (
    <form className="dialog-form" onSubmit={confirmAndSubmit} onChange={() => setConfirming(false)}>
      <label htmlFor={`grant-role-${userId}`}>Role</label>
      <select id={`grant-role-${userId}`} value={role} onChange={(e) => setRole(e.target.value)} disabled={!!disabledReason}>
        <optgroup label="Builtin roles">
          {BUILTIN_ROLES.map((r) => (
            <option key={r} value={r}>
              {ROLE_LABELS[r]}
            </option>
          ))}
        </optgroup>
        {customRoles.length > 0 && (
          <optgroup label="Custom roles">
            {customRoles.map((r) => (
              <option key={r.id} value={r.id}>
                {r.name}
              </option>
            ))}
          </optgroup>
        )}
      </select>
      <RoleConsequenceNote role={role} customRoles={customRoles} />
      <ScopePicker
        scopeType={scopeType}
        setScopeType={setScopeType}
        clusterId={clusterId}
        setClusterId={setClusterId}
        clusterGroupId={clusterGroupId}
        setClusterGroupId={setClusterGroupId}
        clusters={clusters}
        clusterGroups={clusterGroups}
        disabled={!!disabledReason}
      />
      <label htmlFor={`grant-justification-${userId}`}>
        Reason <span className="field-optional">(optional)</span>
      </label>
      <input
        id={`grant-justification-${userId}`}
        type="text"
        value={justification}
        maxLength={500}
        placeholder="e.g. on-call rotation, covering for Bob, ticket #4412"
        onChange={(e) => setJustification(e.target.value)}
        disabled={!!disabledReason}
      />
      <p className="field-hint">
        Recorded with the grant and shown on hover, so an access review later can answer why this
        access exists — not just who gave it and when.
      </p>

      {confirming && (
        <p className="consequence-notice" role="status">
          Grant <strong>{userEmail}</strong> <strong>{roleLabel(role, customRoles)}</strong> on{' '}
          <strong>{draftTarget}</strong>?
        </p>
      )}
      <div className="modal-actions">
        <button
          type="button"
          className="secondary"
          onClick={() => (confirming ? setConfirming(false) : onDone())}
          disabled={mutation.isPending}
        >
          {confirming ? 'Back' : 'Cancel'}
        </button>
        <button type="submit" disabled={!!disabledReason || mutation.isPending || !canSubmit} title={disabledReason}>
          {mutation.isPending ? 'Adding…' : confirming ? 'Confirm grant' : 'Add grant'}
        </button>
      </div>
      {mutation.isError && (
        <p className="form-error inline-error" role="alert">
          {mutation.error instanceof ApiError ? mutation.error.message : 'Could not create grant.'}
        </p>
      )}
    </form>
  )
}

export function UsersPage() {
  const { accessToken } = useAuth()
  const [createOpen, setCreateOpen] = useState(false)
  const [addGrantForUserId, setAddGrantForUserId] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'disabled'>('all')
  const [roleFilter, setRoleFilter] = useState<BuiltinRole | ''>('')

  const canManage = useHasCapability(CAP_USER_MANAGE)
  const manageDisabledReason = canManage ? undefined : `Missing capability: ${CAP_USER_MANAGE}`

  const {
    data: usersData,
    isLoading,
    isError,
    isFetching,
    error,
    dataUpdatedAt,
  } = useQuery({
    queryKey: ['users'],
    queryFn: () => getUsers(accessToken!),
    enabled: !!accessToken,
    // No event covers the user list, and none should: it changes only when
    // an admin edits it, and every mutation on this page invalidates
    // ['users'] itself. The interval exists for a second admin working at
    // the same time, which is not a per-10-seconds concern.
    refetchInterval: STATIC_POLL_MS,
  })

  // Fetched for the create-user/grant scope pickers (a specific cluster or
  // cluster group — BACKLOG.md S3 gave the latter real membership) and to
  // render human-readable names instead of raw ids in each grant badge. Not
  // gated on canManage — a user:read-only viewer of this page still
  // benefits from names instead of ids in the read-only grant badges; both
  // lists are already gated server-side (cluster:read), and their own pages
  // (Clusters, Settings → Roles & access) have that check too.
  const { data: clustersData } = useQuery({
    queryKey: ['clusters'],
    queryFn: () => getClusters(accessToken!),
    enabled: !!accessToken,
  })
  const clusters = clustersData?.clusters ?? []
  const clusterNames = new Map(clusters.map((c) => [c.id, c.displayName]))

  const { data: clusterGroupsData } = useQuery({
    queryKey: ['clusterGroups'],
    queryFn: () => getClusterGroups(accessToken!),
    enabled: !!accessToken,
  })
  const clusterGroups = clusterGroupsData?.clusterGroups ?? []
  const clusterGroupNames = new Map(clusterGroups.map((g) => [g.id, g.name]))

  // Fetched for the same two role pickers, alongside the five builtin roles
  // (BACKLOG.md S3) — and to resolve a grant's role id to a real name
  // instead of a raw generated id in each grant badge.
  const { data: customRolesData } = useQuery({
    queryKey: ['customRoles'],
    queryFn: () => getCustomRoles(accessToken!),
    enabled: !!accessToken,
  })
  const customRoles = customRolesData?.roles ?? []

  const users: User[] = usersData?.users ?? []
  const normalizedSearch = search.trim().toLocaleLowerCase()
  const filteredUsers = users.filter((user) => {
    if (statusFilter === 'active' && user.disabledAt) return false
    if (statusFilter === 'disabled' && !user.disabledAt) return false
    if (roleFilter && !user.grants.some((grant) => grant.role === roleFilter)) return false
    if (!normalizedSearch) return true
    return [user.email, user.displayName, user.id].some((value) => value.toLocaleLowerCase().includes(normalizedSearch))
  })
  // The shared hook and footer, like the other four client-side paged lists. This
  // page had its own copy: a fixed 25 rows with no rows-per-page control and a
  // Previous/Next footer that showed "Page 1 of 1" but never how many results there
  // were — so the fifth list in the app looked and behaved unlike the other four for
  // no reason. (The audit log's Previous/Next footer is a real exception: it is
  // cursor-paged, so a total genuinely is not knowable.)
  const { visibleItems: visibleUsers, resetToFirstPage, pagination } = usePagination(filteredUsers)
  const selectedGrantUser = users.find((user) => user.id === addGrantForUserId)

  if (isError && error instanceof ApiError && error.status === 403) {
    return (
      <div className="page">
        <header className="page-header">
          <h1>Users</h1>
        </header>
        <p className="banner banner-warning" role="alert">
          You don't have access to view users. Missing capability: {CAP_USER_READ}.
        </p>
      </div>
    )
  }

  return (
    <div className="page list-page users-page">
      <header className="page-header list-page-header">
        <div>
          <h1>Users</h1>
          <p className="list-live-status" aria-live="polite">
            {/* Not a fabricated 0 while the first fetch is still in flight —
                `users` is `[]` until then, which used to read "0 users"
                exactly as long as the request took — and not one after it has
                FAILED either, which is the same lie with no time limit. */}
            <span>
              {isError ? '—' : isLoading ? '…' : `${users.length} ${users.length === 1 ? 'user' : 'users'}`}
            </span>
            <span aria-hidden="true">·</span>
            {/* No live dot and no "Live" here, unlike the incident and cluster
                lists: nothing publishes an event when a user is added or a
                grant changes, so this list is genuinely a poll (see
                realtime/refresh.ts's STATIC_POLL_MS) and the honest thing to
                show is when it last succeeded. It said "Live" beside a 10s
                tick before PROJECT.md P16; at the safety-net interval that
                would be a freshness claim with nothing behind it. */}
            <span>
              {isError
                ? 'Not updating'
                : isFetching
                  ? 'Updating…'
                  : dataUpdatedAt > 0
                    ? `Updated ${formatRelativeTime(new Date(dataUpdatedAt).toISOString())}`
                    : 'Loading…'}
            </span>
          </p>
        </div>
        <div className="page-header-actions">
          <button
            type="button"
            onClick={() => setCreateOpen(true)}
            disabled={!canManage}
            title={manageDisabledReason}
          >
            <UserPlusIcon />
            Create user
          </button>
        </div>
      </header>

      <div className="list-card">
        {/* BACKLOG D7g. Was gated on `users.length > 0`, which is also true
            of the empty array this page starts every load with — the
            toolbar and its "N results" count were simply absent for the
            entire loading window, then appeared, a real layout jump on
            every visit. Shown through loading now too; only the true empty
            state (no users at all, ever) has no toolbar to filter nothing
            with. */}
        {(isLoading || users.length > 0) && (
          <div className="list-toolbar users-toolbar">
            <label className="list-search-field">
              <span className="visually-hidden">Search users</span>
              <SearchIcon />
              <input
                type="search"
                value={search}
                placeholder="Search name or email…"
                onChange={(event) => { setSearch(event.target.value); resetToFirstPage() }}
              />
            </label>
            <label className="list-filter-field">
              <span className="visually-hidden">Filter by status</span>
              <select value={statusFilter} onChange={(event) => { setStatusFilter(event.target.value as typeof statusFilter); resetToFirstPage() }}>
                <option value="all">All statuses</option><option value="active">Active</option><option value="disabled">Disabled</option>
              </select>
            </label>
            <label className="list-filter-field">
              <span className="visually-hidden">Filter by role</span>
              <select value={roleFilter} onChange={(event) => { setRoleFilter(event.target.value as BuiltinRole | ''); resetToFirstPage() }}>
                <option value="">All roles</option>
                {BUILTIN_ROLES.map((role) => <option key={role} value={role}>{ROLE_LABELS[role]}</option>)}
              </select>
            </label>
            <span className="list-result-count">{isLoading ? '…' : `${filteredUsers.length} results`}</span>
          </div>
        )}

      {isLoading && (
        <div className="table-scroll">
          <table className="cluster-table list-table users-table" aria-busy="true">
            <thead>
              <tr>
                <th>User</th>
                <th>Status</th>
                <th>Grants</th>
                <th className="col-time">Created</th>
                <th className="table-pinned-actions">Actions</th>
              </tr>
            </thead>
            <tbody>
              <SkeletonTableRows columns={5} />
            </tbody>
          </table>
        </div>
      )}

      {isError && (
        <p className="form-error" role="alert">
          {error instanceof ApiError
            ? error.detail
              ? `${error.message} — ${error.detail}`
              : error.message
            : 'Failed to load users.'}
        </p>
      )}

      {!isLoading && !isError && users.length === 0 && (
        <EmptyState variant="users">No users yet. Create one to get started.</EmptyState>
      )}

      {!isLoading && !isError && users.length > 0 && filteredUsers.length === 0 && (
        <EmptyState variant="users">No users match the current filters.</EmptyState>
      )}

      {!isLoading && filteredUsers.length > 0 && (
        <div className="table-scroll">
          <table className="cluster-table list-table users-table">
            <thead>
              <tr>
                <th>User</th>
                <th>Status</th>
                <th>Grants</th>
                <th className="col-time">Created</th>
                <th className="table-pinned-actions">Actions</th>
              </tr>
            </thead>
            <tbody>
              {visibleUsers.map((u) => (
                <tr key={u.id}>
                  <td className="user-identity-cell" style={{ borderLeft: `3px solid ${topRoleRuleColor(u.grants)}` }}>
                    <strong className="col-truncate" title={u.displayName || u.email}>{u.displayName || u.email}</strong>
                    {u.displayName && <span className="col-truncate" title={u.email}>{u.email}</span>}
                  </td>
                  <td>
                    <UserStatusBadge disabledAt={u.disabledAt} />
                    {u.mustChangePassword && <span className="badge badge-amber">Password change required</span>}
                  </td>
                  <td className="grant-cell">
                    <div className="grant-list">
                      {u.grants.length === 0 && <span className="empty-state">No active grants</span>}
                      {u.grants.map((g) => (
                        <GrantBadge
                          key={g.id}
                          grant={g}
                          clusterNames={clusterNames}
                          clusterGroupNames={clusterGroupNames}
                          customRoles={customRoles}
                          userId={u.id}
                          disabledReason={manageDisabledReason}
                        />
                      ))}
                    </div>
                  </td>
                  {/* Relative with the exact instant on hover — the app's one way
                      of showing a time, rather than a browser-locale date. */}
                  <td className="col-time" title={formatDateTime(u.createdAt)}>
                    {formatRelativeTime(u.createdAt)}
                  </td>
                  <UserActionsCell
                    user={u}
                    disabledReason={manageDisabledReason}
                    onAddGrant={() => setAddGrantForUserId(u.id)}
                  />
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* BACKLOG D7g. Was `!isLoading && filteredUsers.length > 0` — no
          footer at all while loading, matching real content the instant it
          arrives. `TablePagination` needs real numbers it does not have
          yet, so this is a footer-shaped placeholder (em dashes, disabled
          controls) rather than a fabricated "Page 1 of 1". */}
      {isLoading && (
        <footer className="list-pagination" aria-hidden="true">
          <span>Showing —</span>
          <label>
            <span>Rows per page</span>
            <select disabled>
              <option>25</option>
            </select>
          </label>
          <span>Page — of —</span>
          <div className="list-page-buttons">
            <button type="button" className="secondary" disabled>‹</button>
            <button type="button" className="secondary" disabled>›</button>
          </div>
        </footer>
      )}
      {!isLoading && filteredUsers.length > 0 && <TablePagination {...pagination} />}
      </div>

      {createOpen && (
        <CreateUserModal
          clusters={clusters}
          clusterGroups={clusterGroups}
          customRoles={customRoles}
          onClose={() => setCreateOpen(false)}
        />
      )}
      {selectedGrantUser && (
        <Dialog title={`Add grant for ${selectedGrantUser.email}`} onClose={() => setAddGrantForUserId(null)}>
          <AddGrantForm
            userId={selectedGrantUser.id}
            userEmail={selectedGrantUser.email}
            clusters={clusters}
            clusterGroups={clusterGroups}
            customRoles={customRoles}
            disabledReason={manageDisabledReason}
            onDone={() => setAddGrantForUserId(null)}
          />
        </Dialog>
      )}
    </div>
  )
}
