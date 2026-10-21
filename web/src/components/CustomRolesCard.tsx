import { useState } from 'react'
import type { FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { ApiError, createCustomRole, deleteCustomRole, getCustomRoles, updateCustomRole } from '../api/client'
import type { CustomRole } from '../api/types'
import { groupCapabilities, groupedCapabilityOptions } from '../api/capabilityInfo'
import { useAuth } from '../auth/useAuth'
import { Dialog } from './Dialog'
import { SkeletonLines } from './Skeleton'
import { HelpTip } from './HelpTip'

// Custom-role authoring (BACKLOG.md S3): composing the SAME capability
// catalogue permissions.go already exposes into a new, named, reusable
// bundle — never a new permission. Deliberately modeled on
// RepositoriesCard.tsx's shape (a small collection with a per-item lifecycle
// — add, edit, remove — not one form with one save button), since a set of
// named roles is exactly that same shape, just for access grammar instead of
// Git connections.
//
// A created role is assigned to a user through the EXISTING Users → Add
// grant flow (UsersPage.tsx now lists custom roles alongside the five
// builtin ones in that same role picker) — there is no second assignment
// control here. This card only defines what a role MEANS.

function CapabilityChecklist({
  selected,
  onToggle,
  disabled,
}: {
  selected: Set<string>
  onToggle: (capability: string) => void
  disabled: boolean
}) {
  const groups = groupedCapabilityOptions()
  return (
    <>
      {groups.map((g) => (
        <fieldset key={g.groupLabel} className="checkbox-group" disabled={disabled}>
          <legend>{g.groupLabel}</legend>
          {g.items.map((item) => (
            <div key={item.value} className="checkbox-row" title={item.value}>
              <input
                id={`cap-${item.value}`}
                type="checkbox"
                checked={selected.has(item.value)}
                onChange={() => onToggle(item.value)}
              />
              <label htmlFor={`cap-${item.value}`}>{item.label}</label>
            </div>
          ))}
        </fieldset>
      ))}
    </>
  )
}

// Shared by "Create role" and "Edit capabilities" — editingRole present means
// edit (name is fixed and shown as a heading instead of an input; every
// grant referencing this role holds its ID, not its name, so a rename isn't
// offered here at all rather than being offered and silently doing nothing
// useful).
function RoleFormDialog({
  editingRole,
  onClose,
}: {
  editingRole: CustomRole | null
  onClose: () => void
}) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const [name, setName] = useState('')
  const [selected, setSelected] = useState<Set<string>>(new Set(editingRole?.capabilities ?? []))

  const create = useMutation({
    mutationFn: () => createCustomRole({ name: name.trim(), capabilities: [...selected] }, accessToken!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['customRoles'] })
      onClose()
    },
  })
  const update = useMutation({
    mutationFn: () => updateCustomRole(editingRole!.id, { capabilities: [...selected] }, accessToken!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['customRoles'] })
      onClose()
    },
  })
  const mutation = editingRole ? update : create

  function toggle(capability: string) {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(capability)) next.delete(capability)
      else next.add(capability)
      return next
    })
  }

  const canSubmit = (editingRole || name.trim() !== '') && selected.size > 0

  function submit(e: FormEvent) {
    e.preventDefault()
    mutation.mutate()
  }

  return (
    <Dialog title={editingRole ? `Edit "${editingRole.name}"` : 'Create custom role'} onClose={onClose}>
      <form onSubmit={submit}>
        {editingRole ? (
          <p className="field-hint">
            Editing the capability set for <strong>{editingRole.name}</strong>. Every user currently
            granted this role is affected immediately.
          </p>
        ) : (
          <>
            <label htmlFor="custom-role-name">Name</label>
            <input
              id="custom-role-name"
              type="text"
              required
              maxLength={100}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. on-call-viewer"
            />
          </>
        )}

        <p className="field-hint">
          At least one capability; only ones you hold yourself.{' '}
          <HelpTip
            label="which capabilities"
            text="Composing a bundle that exceeds your own access is refused — the same rule that already applies to granting an existing role."
          />
        </p>

        <CapabilityChecklist selected={selected} onToggle={toggle} disabled={mutation.isPending} />

        {mutation.isError && (
          <p className="form-error" role="alert">
            {mutation.error instanceof ApiError
              ? mutation.error.detail
                ? `${mutation.error.message} — ${mutation.error.detail}`
                : mutation.error.message
              : 'Something went wrong. Please try again.'}
          </p>
        )}

        <div className="modal-actions">
          <button type="button" className="secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" disabled={!canSubmit || mutation.isPending}>
            {mutation.isPending ? 'Saving…' : editingRole ? 'Save capabilities' : 'Create role'}
          </button>
        </div>
      </form>
    </Dialog>
  )
}

function CustomRoleRow({
  role,
  canManage,
  disabledReason,
  onEdit,
}: {
  role: CustomRole
  canManage: boolean
  disabledReason?: string
  onEdit: () => void
}) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const [confirming, setConfirming] = useState(false)

  const remove = useMutation({
    mutationFn: () => deleteCustomRole(role.id, accessToken!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['customRoles'] })
      setConfirming(false)
    },
  })

  const groups = groupCapabilities(role.capabilities)

  return (
    <li className="ai-provider">
      <div className="ai-provider-identity">
        <strong>{role.name}</strong>
        <span className="field-hint">
          {role.capabilities.length} capabilit{role.capabilities.length === 1 ? 'y' : 'ies'}
        </span>
      </div>

      <div className="role-card-groups">
        {groups.map((g) => (
          <div key={g.groupLabel} className="role-card-group">
            <h4>{g.groupLabel}</h4>
            <ul>
              {g.items.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </div>
        ))}
      </div>

      <div className="ai-provider-actions">
        <button type="button" className="secondary" disabled={!canManage} title={disabledReason} onClick={onEdit}>
          Edit capabilities
        </button>
        {!confirming ? (
          <button
            type="button"
            className="secondary danger"
            disabled={!canManage}
            title={disabledReason}
            onClick={() => setConfirming(true)}
          >
            Delete
          </button>
        ) : (
          <>
            <span className="field-hint">Delete "{role.name}"? This cannot be undone.</span>
            <button type="button" className="secondary" onClick={() => setConfirming(false)}>
              Cancel
            </button>
            <button type="button" className="danger" disabled={remove.isPending} onClick={() => remove.mutate()}>
              {remove.isPending ? 'Deleting…' : 'Confirm delete'}
            </button>
          </>
        )}
      </div>

      {remove.isError && (
        <p className="form-error inline-error" role="alert">
          {remove.error instanceof ApiError ? remove.error.message : 'Could not delete this role.'}
        </p>
      )}
    </li>
  )
}

export function CustomRolesCard({
  canManage,
  disabledReason,
}: {
  canManage: boolean
  disabledReason?: string
}) {
  const { accessToken } = useAuth()
  const [dialogOpenFor, setDialogOpenFor] = useState<'new' | CustomRole | null>(null)

  const query = useQuery({
    queryKey: ['customRoles'],
    queryFn: () => getCustomRoles(accessToken!),
    enabled: !!accessToken,
  })
  const roles = query.data?.roles ?? []

  return (
    <div className="card settings-panel">
      {query.isLoading && <SkeletonLines count={3} />}

      {query.isError && (
        <p className="form-error" role="alert">
          {query.error instanceof ApiError ? query.error.message : 'Could not load custom roles.'}
        </p>
      )}

      {!query.isLoading && roles.length === 0 && (
        <div className="ai-provider-empty">
          <strong>No custom roles yet</strong>
          <p>Every grant uses a builtin role. Create one for a narrower bundle, such as incident read plus policy dry-run.</p>
        </div>
      )}

      {roles.length > 0 && (
        <ul className="ai-provider-list">
          {roles.map((role) => (
            <CustomRoleRow
              key={role.id}
              role={role}
              canManage={canManage}
              disabledReason={disabledReason}
              onEdit={() => setDialogOpenFor(role)}
            />
          ))}
        </ul>
      )}

      <button
        type="button"
        className="secondary"
        disabled={!canManage}
        title={disabledReason}
        onClick={() => setDialogOpenFor('new')}
      >
        + Create role
      </button>

      {dialogOpenFor && (
        <RoleFormDialog
          editingRole={dialogOpenFor === 'new' ? null : dialogOpenFor}
          onClose={() => setDialogOpenFor(null)}
        />
      )}
    </div>
  )
}
