import { useState } from 'react'
import type { FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import {
  addClusterToGroup,
  ApiError,
  createClusterGroup,
  deleteClusterGroup,
  getClusterGroups,
  getClusters,
  removeClusterFromGroup,
} from '../api/client'
import type { ClusterGroup } from '../api/types'
import { useAuth } from '../auth/useAuth'
import { Dialog } from './Dialog'
import { SkeletonLines } from './Skeleton'

// Cluster groups and team ownership (BACKLOG.md S3). A group is a named set
// of clusters; "team ownership" is not a separate concept or schema here —
// it is a grant (Users → Add grant) scoped to a group instead of to one
// cluster or to every cluster, so a team's access follows the clusters it
// owns as the fleet grows rather than being re-granted cluster by cluster.
// This card only manages the groups and their membership; assigning a role
// to one happens in the existing grant flow (UsersPage.tsx's scope picker
// now offers "A cluster group" alongside "A specific cluster"/"All
// clusters").
//
// Shaped like RepositoriesCard/CustomRolesCard: a small collection with a
// per-item lifecycle (create, add/remove a member, delete).

function AddClusterToGroupForm({
  groupId,
  groupName,
  alreadyMemberIds,
  disabledReason,
}: {
  groupId: string
  groupName: string
  alreadyMemberIds: string[]
  disabledReason?: string
}) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const [clusterId, setClusterId] = useState('')

  const clustersQuery = useQuery({
    queryKey: ['clusters'],
    queryFn: () => getClusters(accessToken!),
    enabled: !!accessToken,
  })
  const candidates = (clustersQuery.data?.clusters ?? []).filter((c) => !alreadyMemberIds.includes(c.id))

  const add = useMutation({
    mutationFn: () => addClusterToGroup(groupId, clusterId, accessToken!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['clusterGroups'] })
      setClusterId('')
    },
  })

  if (candidates.length === 0) {
    return <p className="field-hint">Every enrolled cluster is already a member of this group.</p>
  }

  // Privilege-affecting, like AddGrantForm's own confirm (BACKLOG D7e):
  // adding a cluster here immediately extends it to everyone holding a
  // ClusterGroup grant scoped to this group (lld/02-authz-spec.md §3's own
  // "dynamic evaluation" note), so it gets the same window.confirm this
  // page's other access-widening actions already require.
  function confirmAndAdd(e: FormEvent) {
    e.preventDefault()
    if (!clusterId) return
    const clusterName = candidates.find((c) => c.id === clusterId)?.displayName ?? clusterId
    if (window.confirm(`Add ${clusterName} to "${groupName}"? Everyone granted a role scoped to this group gains access to it immediately.`)) {
      add.mutate()
    }
  }

  return (
    <form className="settings-actions-row" onSubmit={confirmAndAdd}>
      <select
        aria-label="Cluster to add"
        value={clusterId}
        onChange={(e) => setClusterId(e.target.value)}
        disabled={!!disabledReason || add.isPending}
        title={disabledReason}
      >
        <option value="" disabled>
          Add a cluster…
        </option>
        {candidates.map((c) => (
          <option key={c.id} value={c.id}>
            {c.displayName}
          </option>
        ))}
      </select>
      <button type="submit" className="secondary" disabled={!clusterId || !!disabledReason || add.isPending} title={disabledReason}>
        {add.isPending ? 'Adding…' : 'Add'}
      </button>
      {add.isError && (
        <p className="form-error inline-error" role="alert">
          {add.error instanceof ApiError ? add.error.message : 'Could not add cluster to group.'}
        </p>
      )}
    </form>
  )
}

function ClusterGroupRow({
  group,
  clusterNames,
  canManage,
  disabledReason,
}: {
  group: ClusterGroup
  clusterNames: Map<string, string>
  canManage: boolean
  disabledReason?: string
}) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const [confirmingDelete, setConfirmingDelete] = useState(false)

  const removeMember = useMutation({
    mutationFn: (clusterId: string) => removeClusterFromGroup(group.id, clusterId, accessToken!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['clusterGroups'] }),
  })
  const removeGroup = useMutation({
    mutationFn: () => deleteClusterGroup(group.id, accessToken!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['clusterGroups'] }),
  })

  return (
    <li className="ai-provider">
      <div className="ai-provider-identity">
        <strong>{group.name}</strong>
        <span className="field-hint">
          {group.clusterIds.length} cluster{group.clusterIds.length === 1 ? '' : 's'}
        </span>
      </div>

      <div className="grant-list">
        {group.clusterIds.length === 0 && <span className="empty-state">No clusters in this group yet</span>}
        {group.clusterIds.map((clusterId) => {
          const clusterName = clusterNames.get(clusterId) ?? clusterId
          return (
            <span key={clusterId} className="badge badge-gray grant-badge">
              <span className="grant-badge-text">{clusterName}</span>
              <button
                type="button"
                className="grant-revoke"
                title={canManage ? 'Remove from this group' : disabledReason}
                disabled={!canManage || removeMember.isPending}
                onClick={() => {
                  // Access-narrowing for the same reason adding one is
                  // access-widening (see AddClusterToGroupForm's own
                  // comment) — the same window.confirm discipline
                  // GrantBadge's own revoke button uses.
                  if (
                    window.confirm(
                      `Remove ${clusterName} from "${group.name}"? Anyone whose access comes only from a role scoped to this group loses it immediately.`,
                    )
                  ) {
                    removeMember.mutate(clusterId)
                  }
                }}
              >
                ×
              </button>
            </span>
          )
        })}
      </div>

      <AddClusterToGroupForm
        groupId={group.id}
        groupName={group.name}
        alreadyMemberIds={group.clusterIds}
        disabledReason={disabledReason}
      />

      <div className="ai-provider-actions">
        {!confirmingDelete ? (
          <button
            type="button"
            className="secondary danger"
            disabled={!canManage}
            title={disabledReason}
            onClick={() => setConfirmingDelete(true)}
          >
            Delete group
          </button>
        ) : (
          <>
            <span className="field-hint">Delete "{group.name}"? This cannot be undone.</span>
            <button type="button" className="secondary" onClick={() => setConfirmingDelete(false)}>
              Cancel
            </button>
            <button type="button" className="danger" disabled={removeGroup.isPending} onClick={() => removeGroup.mutate()}>
              {removeGroup.isPending ? 'Deleting…' : 'Confirm delete'}
            </button>
          </>
        )}
      </div>

      {removeMember.isError && (
        <p className="form-error inline-error" role="alert">
          {removeMember.error instanceof ApiError ? removeMember.error.message : 'Could not remove cluster from group.'}
        </p>
      )}
      {removeGroup.isError && (
        <p className="form-error inline-error" role="alert">
          {removeGroup.error instanceof ApiError ? removeGroup.error.message : 'Could not delete this group.'}
        </p>
      )}
    </li>
  )
}

function CreateClusterGroupDialog({ onClose }: { onClose: () => void }) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const [name, setName] = useState('')

  const create = useMutation({
    mutationFn: () => createClusterGroup({ name: name.trim() }, accessToken!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['clusterGroups'] })
      onClose()
    },
  })

  return (
    <Dialog title="Create cluster group" onClose={onClose}>
      <form
        onSubmit={(e) => {
          e.preventDefault()
          create.mutate()
        }}
      >
        <label htmlFor="cluster-group-name">Name</label>
        <input
          id="cluster-group-name"
          type="text"
          required
          maxLength={100}
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. payments-team"
        />
        <p className="field-hint">Add member clusters afterwards, from this group's own row.</p>

        {create.isError && (
          <p className="form-error" role="alert">
            {create.error instanceof ApiError
              ? create.error.detail
                ? `${create.error.message} — ${create.error.detail}`
                : create.error.message
              : 'Something went wrong. Please try again.'}
          </p>
        )}

        <div className="modal-actions">
          <button type="button" className="secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" disabled={name.trim() === '' || create.isPending}>
            {create.isPending ? 'Creating…' : 'Create group'}
          </button>
        </div>
      </form>
    </Dialog>
  )
}

export function ClusterGroupsCard({
  canManage,
  disabledReason,
}: {
  canManage: boolean
  disabledReason?: string
}) {
  const { accessToken } = useAuth()
  const [creating, setCreating] = useState(false)

  const groupsQuery = useQuery({
    queryKey: ['clusterGroups'],
    queryFn: () => getClusterGroups(accessToken!),
    enabled: !!accessToken,
  })
  const clustersQuery = useQuery({
    queryKey: ['clusters'],
    queryFn: () => getClusters(accessToken!),
    enabled: !!accessToken,
  })
  const clusterNames = new Map((clustersQuery.data?.clusters ?? []).map((c) => [c.id, c.displayName]))
  const groups = groupsQuery.data?.clusterGroups ?? []

  return (
    <div className="card settings-panel">
      {groupsQuery.isLoading && <SkeletonLines count={3} />}

      {groupsQuery.isError && (
        <p className="form-error" role="alert">
          {groupsQuery.error instanceof ApiError ? groupsQuery.error.message : 'Could not load cluster groups.'}
        </p>
      )}

      {!groupsQuery.isLoading && groups.length === 0 && (
        <div className="ai-provider-empty">
          <strong>No cluster groups yet</strong>
          <p>
            Create one to grant a role to "the clusters this team owns" instead of naming every cluster,
            or granting every cluster in the org.
          </p>
        </div>
      )}

      {groups.length > 0 && (
        <ul className="ai-provider-list">
          {groups.map((group) => (
            <ClusterGroupRow
              key={group.id}
              group={group}
              clusterNames={clusterNames}
              canManage={canManage}
              disabledReason={disabledReason}
            />
          ))}
        </ul>
      )}

      <button type="button" className="secondary" disabled={!canManage} title={disabledReason} onClick={() => setCreating(true)}>
        + Create group
      </button>

      {creating && <CreateClusterGroupDialog onClose={() => setCreating(false)} />}
    </div>
  )
}
