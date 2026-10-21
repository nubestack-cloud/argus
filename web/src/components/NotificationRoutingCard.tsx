import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import type { FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import {
  ApiError,
  getClusterGroups,
  getNotificationRouting,
  updateNotificationRouting,
} from '../api/client'
import { CAP_CLUSTER_READ, CAP_ORG_SETTINGS_WRITE } from '../api/capabilities'
import { missingCapabilityMessage } from '../api/capabilityInfo'
import type {
  NotificationRoutingResponse,
  UpdateNotificationRoutingRequest,
} from '../api/types'
import { useAuth } from '../auth/useAuth'
import { useHasCapability } from '../auth/useCapabilities'
import { STATE_LABEL } from '../utils/incidents'
import { ChevronIcon } from './icons'
import { HelpTip } from './HelpTip'
import { PanelHead } from './SettingsBlocks'
import { SkeletonLines } from './Skeleton'

// Settings → Integrations → Notification routing (PROJECT.md F32).
//
// # Why this card edits a TABLE and saves it whole
//
// internal/api/notification_routing.go exposes exactly two routes: a GET and a
// whole-set PUT. That is not an API convenience — a routing table is ordered
// and its rows are only meaningful relative to each other, so a per-row CRUD
// surface has intermediate states in which notifications are genuinely
// mis-routed (the general rule deleted, the specific one not yet created) and
// nothing a client can do avoids them. This card therefore stages every edit
// locally and sends one payload. The cost is a window where the screen shows a
// table the hub has not accepted, so the save bar states how many changes are
// staged rather than leaving it to be inferred.
//
// # The write-only URL, and the one way to get it wrong
//
// The GET never returns a destination URL — a Slack incoming-webhook URL embeds
// a bearer-equivalent token in its path. So this form has to be able to say "a
// URL is set" without knowing it, and must never blank one by accident. The
// mechanism is `DraftDestination.replacementUrl`:
//
//   - null  → the operator has not touched this destination's URL. The payload
//             OMITS `url` entirely, which is what keeps the stored one.
//   - a string → the operator typed a replacement. It is sent, and it replaces.
//
// An empty string is never sent: notify.validateWebhookURL refuses it, and the
// refusal would arrive as a 400 on an unrelated-looking save. "Replace URL" is
// therefore an explicit, cancellable mode rather than an always-live field an
// operator can clear by tabbing through it.
//
// Destinations are keyed by NAME server-side (ReplaceRouting looks the stored
// row up by name), so a changed name is a new destination plus a deletion, not
// a rename — and a new destination must carry a URL. Rather than let an
// operator discover that as a 400, the name is simply not editable after it is
// saved; the card says so.
//
// # What this card deliberately does NOT do
//
// It does not re-implement notify.ValidateRoutingUpdate. Duplicate names, an
// unknown severity or transition, a rule naming a destination that is not in
// the same request — all of those come back as the hub's own RFC 9457 `detail`,
// which is better worded than a second copy here would be. The two rules stated
// locally are the two the UI can prevent an operator from ever reaching: a
// destination needs a name and a URL to be created at all, and a destination
// still named by a rule cannot be removed.
//
// It also does not offer "send a test notification", a delivery history, or a
// preview of which rule a given incident would match. None of those has an
// endpoint, and drawing any of them would be inventing a fact.

/** A destination as staged locally. `urlConfigured` is the HUB's answer; `replacementUrl` is this session's. */
type DraftDestination = {
  name: string
  kind: string
  /** What the hub reports today. False for one added locally and not yet saved. */
  urlConfigured: boolean
  /** null means untouched — see this file's doc comment. Never the empty string. */
  replacementUrl: string | null
  /** True until a save round-trips it, which is what makes its name still editable. */
  isNew: boolean
}

/**
 * A rule as staged locally.
 *
 * `key` is a local, stable handle for React and for the reorder controls. It is
 * never sent: notify.ReplaceRouting deletes and re-inserts every rule on each
 * PUT, so a rule has no identity of its own beyond its position and its
 * matchers, and inventing an id here would imply one it does not have.
 */
type DraftRule = {
  key: string
  name: string
  clusterGroupId: string | null
  /** Resolved by the hub for display. Kept so a group's name still shows without cluster:read. */
  clusterGroupName: string | null
  minSeverity: string | null
  transition: string | null
  destination: string
  enabled: boolean
}

type Draft = { destinations: DraftDestination[]; rules: DraftRule[] }

let keySeq = 0
function nextKey(): string {
  keySeq += 1
  return `rule-${keySeq}`
}

function draftFrom(data: NotificationRoutingResponse): Draft {
  return {
    destinations: data.destinations.map((d) => ({
      name: d.name,
      kind: d.kind,
      urlConfigured: d.urlConfigured,
      replacementUrl: null,
      isNew: false,
    })),
    rules: data.rules.map((r) => ({
      key: nextKey(),
      name: r.name,
      clusterGroupId: r.clusterGroupId,
      clusterGroupName: r.clusterGroupName,
      minSeverity: r.minSeverity,
      transition: r.transition,
      destination: r.destination,
      enabled: r.enabled,
    })),
  }
}

/**
 * The exact payload a save would send.
 *
 * `priority` is the row's position, not a number an operator types. The stored
 * order is `(priority, id)` and first match wins, so the visible order IS the
 * configuration — writing ascending priorities from the rendered order is what
 * makes reordering a row mean what it looks like it means.
 *
 * A destination whose `replacementUrl` is null contributes `{ name }` with no
 * `url` key at all. That is the difference between keeping a stored URL and
 * clearing it, and it is the single most breakable thing on this screen.
 */
function payloadFor(draft: Draft): UpdateNotificationRoutingRequest {
  return {
    destinations: draft.destinations.map((d) =>
      d.replacementUrl === null ? { name: d.name } : { name: d.name, url: d.replacementUrl },
    ),
    rules: draft.rules.map((r, index) => ({
      name: r.name,
      priority: index + 1,
      clusterGroupId: r.clusterGroupId,
      minSeverity: r.minSeverity,
      transition: r.transition,
      destination: r.destination,
      enabled: r.enabled,
    })),
  }
}

// The severity floor, in words. `minSeverity` is a FLOOR (internal/notify's
// Match compares ranks), so "high" has to read as "high and above" or an
// operator will configure an equality test and get a table that silently misses
// criticals. Critical is the top of the ladder, so "and above" would be noise
// there and the label says "only" instead.
const SEVERITY_FLOOR_LABEL: Record<string, string> = {
  low: 'Low and above',
  medium: 'Medium and above',
  high: 'High and above',
  critical: 'Critical only',
}

function severityFloorLabel(value: string): string {
  return SEVERITY_FLOOR_LABEL[value] ?? value
}

// `NewIncident` is not an incident state and has no STATE_LABEL entry — it is
// the first-sighting queue, deliberately distinct from Detected (see
// internal/notify/routing.go's TransitionNewIncident). Everything else the hub
// serves is a state name, so it reads through the same map the incident screens
// use rather than acquiring a second house style. A token this build does not
// recognise renders as itself: the hub is the authority on the list, and
// dropping an unknown one would hide a rule that is really in force.
function transitionLabel(value: string): string {
  if (value === 'NewIncident') return 'New incident'
  return STATE_LABEL[value as keyof typeof STATE_LABEL] ?? value
}

function ruleCountFor(rules: DraftRule[], destination: string): number {
  return rules.filter((r) => r.destination === destination).length
}

export function NotificationRoutingCard() {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const canWrite = useHasCapability(CAP_ORG_SETTINGS_WRITE)
  const disabledReason = canWrite ? undefined : missingCapabilityMessage([CAP_ORG_SETTINGS_WRITE])
  const canReadGroups = useHasCapability(CAP_CLUSTER_READ)

  const query = useQuery({
    queryKey: ['notification-routing'],
    queryFn: () => getNotificationRouting(accessToken!),
  })

  // Cluster groups come from a different route behind a different capability
  // (cluster:read), so this can legitimately be unavailable to someone who can
  // edit routing. When it is, the group select is disabled with the capability
  // named and the rule's own clusterGroupName — resolved server-side, already
  // in the routing response — still renders, so an existing group-scoped rule
  // is never shown as if it matched everything.
  const groupsQuery = useQuery({
    queryKey: ['cluster-groups'],
    queryFn: () => getClusterGroups(accessToken!),
    enabled: canReadGroups,
  })

  // The draft is stored WITH the server answer it was derived from, and re-seeded
  // during render when that answer changes identity — React's own
  // adjust-state-during-render pattern rather than an effect. An effect here
  // would render the previous table once against fresh data, which on a screen
  // whose whole point is "what is staged versus what the hub is using" is a
  // frame of exactly the wrong claim.
  const [state, setState] = useState<{ source: NotificationRoutingResponse | null; draft: Draft | null }>({
    source: null,
    draft: null,
  })
  const [editingUrlFor, setEditingUrlFor] = useState<string | null>(null)
  const [newName, setNewName] = useState('')
  const [newUrl, setNewUrl] = useState('')
  const [addError, setAddError] = useState('')

  const serverData = query.data
  if (serverData && state.source !== serverData) {
    setState({ source: serverData, draft: draftFrom(serverData) })
  }
  const draft = state.source === serverData ? state.draft : null

  function setDraft(next: Draft | ((current: Draft | null) => Draft | null)) {
    setState((current) => ({
      ...current,
      draft: typeof next === 'function' ? next(current.draft) : next,
    }))
  }

  const save = useMutation({
    mutationFn: (body: UpdateNotificationRoutingRequest) =>
      updateNotificationRouting(body, accessToken!),
    onSuccess: (fresh) => {
      // The PUT returns the table re-read after the write, so the cache takes
      // the hub's answer rather than the locally-built one — that is what makes
      // "a kept URL" and "a normalised priority" visible instead of assumed.
      queryClient.setQueryData(['notification-routing'], fresh)
      setEditingUrlFor(null)
    },
  })

  const baseline = useMemo(
    () => (serverData ? JSON.stringify(payloadFor(draftFrom(serverData))) : null),
    [serverData],
  )
  const staged = draft ? JSON.stringify(payloadFor(draft)) : null
  const dirty = baseline !== null && staged !== null && baseline !== staged

  if (query.isLoading) {
    return (
      <div className="card settings-panel" aria-busy="true">
        <h2>Notification routing</h2>
        <SkeletonLines count={12} />
      </div>
    )
  }

  if (query.isError || !serverData || !draft) {
    return (
      <div className="card settings-panel">
        <h2>Notification routing</h2>
        {/* The GET is behind org:settings:write too, so a viewer without it
            gets a 403 from the read as well as the write. Naming the
            capability is the same disabled-not-hidden discipline applied to a
            whole panel (lld/11 §6) — a bare "Forbidden" tells someone nothing
            they can act on. */}
        {query.error instanceof ApiError && query.error.status === 403 ? (
          <p className="banner banner-warning" role="alert">
            You don't have access to view or change notification routing.{' '}
            {missingCapabilityMessage([CAP_ORG_SETTINGS_WRITE])}
          </p>
        ) : (
          <p className="form-error" role="alert">
            {query.error instanceof ApiError
              ? query.error.detail
                ? `${query.error.message} — ${query.error.detail}`
                : query.error.message
              : 'Could not load the notification routing table.'}
          </p>
        )}
      </div>
    )
  }

  const transitions = serverData.transitions ?? []
  const severities = serverData.severities ?? []
  const defaultRule = serverData.defaultRule
  const groups = groupsQuery.data?.clusterGroups ?? []
  // Two different reasons the group select can be unusable, and they are not
  // the same sentence: one is a capability the viewer can ask for, the other is
  // a request that failed. Either way the rule's own group still renders from
  // the hub's resolved clusterGroupName, so a group-scoped rule is never shown
  // as though it matched every cluster.
  const groupsUnavailable = !canReadGroups
    ? `The cluster groups cannot be listed here. ${missingCapabilityMessage([CAP_CLUSTER_READ])}`
    : groupsQuery.isError
      ? 'The cluster groups could not be loaded, so only the group this rule already names can be chosen.'
      : undefined

  function update(next: Partial<Draft>) {
    setDraft((current) => (current ? { ...current, ...next } : current))
  }

  function updateRule(key: string, patch: Partial<DraftRule>) {
    setDraft((current) =>
      current
        ? { ...current, rules: current.rules.map((r) => (r.key === key ? { ...r, ...patch } : r)) }
        : current,
    )
  }

  function moveRule(index: number, delta: number) {
    setDraft((current) => {
      if (!current) return current
      const target = index + delta
      if (target < 0 || target >= current.rules.length) return current
      const rules = [...current.rules]
      const [row] = rules.splice(index, 1)
      rules.splice(target, 0, row)
      return { ...current, rules }
    })
  }

  function addDestination(e: FormEvent) {
    e.preventDefault()
    const name = newName.trim()
    const url = newUrl.trim()
    if (name === '') {
      setAddError('Enter a name — rules refer to a destination by its name.')
      return
    }
    if (draft!.destinations.some((d) => d.name === name)) {
      setAddError(`${name} is already a destination.`)
      return
    }
    if (url === '') {
      // Stated here rather than left to the hub's 400: a destination the hub
      // has never seen is new, and a new one with no URL is refused outright
      // (notify.ReplaceRouting). The operator should not be able to stage one.
      setAddError('Enter a webhook URL — a destination the hub has not seen before needs one.')
      return
    }
    setAddError('')
    setNewName('')
    setNewUrl('')
    update({
      destinations: [
        ...draft!.destinations,
        { name, kind: 'webhook', urlConfigured: false, replacementUrl: url, isNew: true },
      ],
    })
  }

  function addRule() {
    const destination = draft!.destinations[0]?.name
    if (!destination) return
    update({
      rules: [
        ...draft!.rules,
        {
          key: nextKey(),
          name: `Rule ${draft!.rules.length + 1}`,
          clusterGroupId: null,
          clusterGroupName: null,
          minSeverity: null,
          transition: null,
          destination,
          enabled: true,
        },
      ],
    })
  }

  const noDestinations = draft.destinations.length === 0

  return (
    <div className="card settings-panel">
      <PanelHead
        title="Notification routing"
        lede="Rules are considered in order and the first one that matches wins — a notification is never sent twice."
        help="Which destination a notification goes to, by cluster group, minimum severity and what happened. Anything no rule claims falls through to the default rule, which always matches and cannot be edited here. There is no rule that drops a notification. This screen sends every destination and every rule together: a rule only means something relative to the rules above it, so editing one row at a time would leave moments where notifications go to the wrong place."
      />

      {/* The consequences, next to the control rather than in a help panel
          (reference/screens.md mode E) — three facts an operator cannot infer
          from the table's own contents, each one line. */}
      <ul className="settings-facts">
        <li>
          <strong>Saving replaces the whole table, in one transaction.</strong> Nothing here changes
          what the hub does until you save.
        </li>
        <li>
          <strong>Every notification matches something.</strong> Unclaimed ones go to the default rule.
        </li>
        <li>
          <strong>Severity is a floor, not an equality test.</strong> "High and above" matches
          critical too.
        </li>
      </ul>

      {!defaultRule.urlConfigured && (
        // Not a fabricated reassurance and not a silent state: with no default
        // URL, everything no rule claims is delivered nowhere. The hub reports
        // this precisely so it does not have to be found in a log line.
        <p className="banner banner-warning" role="alert">
          <strong>The default rule has no URL, so anything no rule below claims is delivered
          nowhere.</strong>{' '}
          Set a notification webhook under Settings → Notifications, or add a rule that claims
          the traffic you care about.
        </p>
      )}

      <h3 className="settings-subhead">
        Destinations
        <HelpTip
          label="destinations"
          text="A destination is a name and a webhook URL. ARGUS never shows a destination's URL back — an incoming-webhook URL carries its own access token in the address, so the hub reports only whether one is set. Leaving a URL alone keeps it; replacing one is an explicit action."
        />
      </h3>
      <p className="field-hint">A name and a webhook URL. <strong>ARGUS never shows a destination's URL back.</strong></p>

      {noDestinations ? (
        // "Nothing is configured yet" — a fresh install, not a failure and not
        // a filtered-to-nothing dead end. It says what would appear here and
        // what happens meanwhile, rather than reading as an error.
        <p className="empty-state">
          No destinations yet. Every notification currently goes to the default rule below. Add a
          destination to start sending some of them somewhere else.
        </p>
      ) : (
        <div className="table-scroll">
          <table className="cluster-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Webhook URL</th>
                <th className="col-numeric">Rules using it</th>
                <th>
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {draft.destinations.map((d) => {
                const used = ruleCountFor(draft.rules, d.name)
                const editing = editingUrlFor === d.name
                return (
                  <tr key={d.name}>
                    <td>
                      <code>{d.name}</code>
                      {d.isNew && <span className="badge badge-amber"> Not saved</span>}
                    </td>
                    <td>
                      {/* Status is the word first; the badge tone is an
                          addition to it, never the signal (lld/11 §8). */}
                      {d.replacementUrl !== null ? (
                        <span className="badge badge-amber">New URL, not saved</span>
                      ) : d.urlConfigured ? (
                        <span className="badge badge-green">Set</span>
                      ) : (
                        <span className="badge badge-red">No URL — delivers nothing</span>
                      )}
                      {editing && (
                        <>
                          <label
                            className="visually-hidden"
                            htmlFor={`routing-url-${d.name}`}
                          >
                            New webhook URL for {d.name}
                          </label>
                          <input
                            id={`routing-url-${d.name}`}
                            type="password"
                            autoComplete="new-password"
                            placeholder="https://hooks.example.com/services/…"
                            value={d.replacementUrl ?? ''}
                            onChange={(e) =>
                              update({
                                destinations: draft.destinations.map((candidate) =>
                                  candidate.name === d.name
                                    ? { ...candidate, replacementUrl: e.target.value }
                                    : candidate,
                                ),
                              })
                            }
                            disabled={!canWrite}
                            title={disabledReason}
                          />
                        </>
                      )}
                    </td>
                    <td className="col-numeric">{used}</td>
                    <td>
                      {editing && !d.isNew ? (
                        <button
                          type="button"
                          className="secondary"
                          onClick={() => {
                            // Back to untouched — which is what omits `url`
                            // from the payload and keeps the stored one.
                            update({
                              destinations: draft.destinations.map((candidate) =>
                                candidate.name === d.name
                                  ? { ...candidate, replacementUrl: null }
                                  : candidate,
                              ),
                            })
                            setEditingUrlFor(null)
                          }}
                        >
                          Keep the stored URL
                        </button>
                      ) : (
                        !d.isNew && (
                          <button
                            type="button"
                            className="secondary"
                            disabled={!canWrite}
                            title={
                              canWrite
                                ? `Replace the webhook URL stored for ${d.name}`
                                : disabledReason
                            }
                            onClick={() => {
                              update({
                                destinations: draft.destinations.map((candidate) =>
                                  candidate.name === d.name
                                    ? { ...candidate, replacementUrl: '' }
                                    : candidate,
                                ),
                              })
                              setEditingUrlFor(d.name)
                            }}
                          >
                            Replace URL…
                          </button>
                        )
                      )}{' '}
                      <button
                        type="button"
                        className="secondary"
                        disabled={!canWrite || used > 0}
                        title={
                          !canWrite
                            ? disabledReason
                            : used > 0
                              ? `${used} rule${used === 1 ? '' : 's'} still send here. Point them somewhere else first.`
                              : `Remove ${d.name} when you save`
                        }
                        onClick={() =>
                          update({
                            destinations: draft.destinations.filter((c) => c.name !== d.name),
                          })
                        }
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      <form onSubmit={addDestination} className="settings-inline-add">
        <div className="settings-field">
        <label htmlFor="routing-new-name">
          Destination name
          <HelpTip label="Destination name" text="How rules refer to this destination, and the only identifier ARGUS gives back. It cannot be changed once saved: the hub keys a destination by its name, so a rename is a new destination plus a deletion, and the new one would need its URL entered again." />
        </label>
        <input
          id="routing-new-name"
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
          placeholder="on-call-pager"
          disabled={!canWrite}
          title={disabledReason}
        />
        </div>
        <div className="settings-field">
        <label htmlFor="routing-new-url">
          Webhook URL
          <HelpTip label="Webhook URL" text="The full incoming-webhook URL to POST to. ARGUS stores it and never shows it again — this field is the only time it is on screen." />
        </label>
        <input
          id="routing-new-url"
          type="password"
          autoComplete="new-password"
          value={newUrl}
          onChange={(e) => setNewUrl(e.target.value)}
          placeholder="https://hooks.example.com/services/…"
          disabled={!canWrite}
          title={disabledReason}
        />
        </div>
        {addError && (
          <p className="form-error" role="alert">
            {addError}
          </p>
        )}
        <div className="form-actions">
          <button type="submit" disabled={!canWrite} title={disabledReason}>
            Add destination
          </button>
        </div>
      </form>

      <h3 className="settings-subhead">Rules, in the order they are considered</h3>

      {draft.rules.length === 0 ? (
        <p className="empty-state">
          No rules yet: every notification goes to the default rule below.{' '}
          <HelpTip
            label="routing rules"
            text="A rule claims some of that traffic — say, critical incidents on the production cluster group — and sends it to one of the destinations above instead."
          />
        </p>
      ) : null}

      <div className="table-scroll">
        <table className="cluster-table">
          <thead>
            <tr>
              <th className="col-numeric">Order</th>
              <th>Name</th>
              <th>Cluster group</th>
              <th>Minimum severity</th>
              <th>What happened</th>
              <th>Destination</th>
              <th>Enabled</th>
              <th>
                <span className="visually-hidden">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {draft.rules.map((rule, index) => (
              <tr key={rule.key}>
                <td className="col-numeric">
                  {index + 1}{' '}
                  <button
                    type="button"
                    className="secondary"
                    aria-label={`Move ${rule.name} earlier`}
                    disabled={!canWrite || index === 0}
                    title={canWrite ? 'Consider this rule earlier' : disabledReason}
                    onClick={() => moveRule(index, -1)}
                  >
                    <ChevronIcon direction="up" size={14} />
                  </button>{' '}
                  <button
                    type="button"
                    className="secondary"
                    aria-label={`Move ${rule.name} later`}
                    disabled={!canWrite || index === draft.rules.length - 1}
                    title={canWrite ? 'Consider this rule later' : disabledReason}
                    onClick={() => moveRule(index, 1)}
                  >
                    <ChevronIcon direction="down" size={14} />
                  </button>
                </td>
                <td>
                  <label className="visually-hidden" htmlFor={`routing-rule-name-${rule.key}`}>
                    Rule name
                  </label>
                  <input
                    id={`routing-rule-name-${rule.key}`}
                    value={rule.name}
                    onChange={(e) => updateRule(rule.key, { name: e.target.value })}
                    disabled={!canWrite}
                    title={disabledReason}
                  />
                </td>
                <td>
                  <label className="visually-hidden" htmlFor={`routing-rule-group-${rule.key}`}>
                    Cluster group
                  </label>
                  <select
                    id={`routing-rule-group-${rule.key}`}
                    value={rule.clusterGroupId ?? ''}
                    onChange={(e) =>
                      updateRule(rule.key, { clusterGroupId: e.target.value || null })
                    }
                    disabled={!canWrite || groupsUnavailable !== undefined}
                    title={!canWrite ? disabledReason : groupsUnavailable}
                  >
                    <option value="">Any cluster group</option>
                    {/* A rule scoped to a group this select cannot list still
                        names that group, from the hub's own resolved
                        clusterGroupName — never silently re-read as "any". */}
                    {rule.clusterGroupId && !groups.some((g) => g.id === rule.clusterGroupId) && (
                      <option value={rule.clusterGroupId}>
                        {rule.clusterGroupName ?? rule.clusterGroupId}
                      </option>
                    )}
                    {groups.map((g) => (
                      <option key={g.id} value={g.id}>
                        {g.name}
                      </option>
                    ))}
                  </select>
                </td>
                <td>
                  <label className="visually-hidden" htmlFor={`routing-rule-sev-${rule.key}`}>
                    Minimum severity
                  </label>
                  <select
                    id={`routing-rule-sev-${rule.key}`}
                    value={rule.minSeverity ?? ''}
                    onChange={(e) => updateRule(rule.key, { minSeverity: e.target.value || null })}
                    disabled={!canWrite}
                    title={disabledReason}
                  >
                    <option value="">Any severity</option>
                    {severities.map((s) => (
                      <option key={s} value={s}>
                        {severityFloorLabel(s)}
                      </option>
                    ))}
                  </select>
                </td>
                <td>
                  <label className="visually-hidden" htmlFor={`routing-rule-transition-${rule.key}`}>
                    What happened
                  </label>
                  <select
                    id={`routing-rule-transition-${rule.key}`}
                    value={rule.transition ?? ''}
                    onChange={(e) => updateRule(rule.key, { transition: e.target.value || null })}
                    disabled={!canWrite}
                    title={disabledReason}
                  >
                    <option value="">Anything</option>
                    {transitions.map((t) => (
                      <option key={t} value={t}>
                        {transitionLabel(t)}
                      </option>
                    ))}
                  </select>
                </td>
                <td>
                  <label className="visually-hidden" htmlFor={`routing-rule-dest-${rule.key}`}>
                    Destination
                  </label>
                  <select
                    id={`routing-rule-dest-${rule.key}`}
                    value={rule.destination}
                    onChange={(e) => updateRule(rule.key, { destination: e.target.value })}
                    disabled={!canWrite}
                    title={disabledReason}
                  >
                    {/* A destination removed above while this rule still points
                        at it stays listed, so the rule keeps reading as what it
                        is rather than silently repointing itself. The hub
                        refuses the save and says which rule. */}
                    {!draft.destinations.some((d) => d.name === rule.destination) && (
                      <option value={rule.destination}>{rule.destination} — removed</option>
                    )}
                    {draft.destinations.map((d) => (
                      <option key={d.name} value={d.name}>
                        {d.name}
                      </option>
                    ))}
                  </select>
                </td>
                <td>
                  <div className="checkbox-row">
                    <input
                      id={`routing-rule-enabled-${rule.key}`}
                      type="checkbox"
                      checked={rule.enabled}
                      onChange={(e) => updateRule(rule.key, { enabled: e.target.checked })}
                      disabled={!canWrite}
                      title={disabledReason}
                    />
                    {/* The label is what the control MEANS, not what it
                        currently reads — an unchecked box labelled "Disabled"
                        announces as a disabled-and-unchecked control, which is
                        the opposite of what it is. The checked state carries
                        the value. */}
                    <label htmlFor={`routing-rule-enabled-${rule.key}`}>Enabled</label>
                  </div>
                </td>
                <td>
                  <button
                    type="button"
                    className="secondary"
                    disabled={!canWrite}
                    title={canWrite ? `Remove ${rule.name} when you save` : disabledReason}
                    onClick={() =>
                      update({ rules: draft.rules.filter((r) => r.key !== rule.key) })
                    }
                  >
                    Remove
                  </button>
                </td>
              </tr>
            ))}

            {/* The synthetic default, rendered as the last row of the same
                table rather than as a footnote — because that is what it is:
                the rule every notification no other rule claimed matches. It is
                NOT in `rules`, is not editable here, and has no priority
                number; its position is structural (internal/notify's
                defaultRule is appended after the ORDER BY, so no stored rule
                can tie with it). The row says all three things. */}
            <tr className="routing-default-row">
              <td className="col-numeric">
                <span className="badge badge-gray">Last</span>
              </td>
              <td>
                {defaultRule.name}
                <span className="field-hint"> — always matches, not editable here</span>
              </td>
              <td>Any cluster group</td>
              <td>Any severity</td>
              <td>Anything</td>
              <td>
                {defaultRule.urlConfigured ? (
                  <span className="badge badge-green">Organization webhook — URL set</span>
                ) : (
                  <span className="badge badge-red">Organization webhook — no URL</span>
                )}
              </td>
              <td>
                <span className="badge badge-gray">Always</span>
              </td>
              <td>
                {/* A real link, not a sentence naming a screen: the default's
                    URL genuinely lives on another section of this same page,
                    and `source` is the hub's own answer for which one. */}
                <Link to="/settings?section=notifications">Set under Notifications</Link>
                <span className="field-hint"> (<code>{defaultRule.source}</code>)</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="form-actions">
        <button
          type="button"
          className="secondary"
          disabled={!canWrite || noDestinations}
          title={
            !canWrite
              ? disabledReason
              : noDestinations
                ? 'Add a destination first — a rule has to name one.'
                : 'Add a rule at the end of the table'
          }
          onClick={addRule}
        >
          Add rule
        </button>
      </div>

      {save.isError && (
        <p className="form-error" role="alert">
          {save.error instanceof ApiError
            ? save.error.detail
              ? `${save.error.message} — ${save.error.detail}`
              : save.error.message
            : 'Could not save the routing table.'}
        </p>
      )}

      {save.isSuccess && !dirty && (
        <p className="banner banner-success" role="status">
          Routing table saved. It is what the hub is using now.
        </p>
      )}

      <div className="form-actions">
        <button
          type="button"
          disabled={!canWrite || !dirty || save.isPending}
          title={
            !canWrite
              ? disabledReason
              : !dirty
                ? 'Nothing staged — this table is what the hub is using.'
                : 'Replace the whole routing table with what is on screen'
          }
          onClick={() => save.mutate(payloadFor(draft))}
        >
          {save.isPending ? 'Saving…' : 'Save routing table'}
        </button>
        <button
          type="button"
          className="secondary"
          disabled={!dirty || save.isPending}
          title={dirty ? 'Throw away the staged changes' : 'Nothing staged'}
          onClick={() => {
            setDraft(draftFrom(serverData))
            setEditingUrlFor(null)
            setAddError('')
          }}
        >
          Discard changes
        </button>
      </div>

      {dirty && (
        <p className="field-hint">
          Staged, not saved. Nothing on this screen changes where a notification goes until you
          save — and saving replaces the whole table, including any row you removed.
        </p>
      )}
    </div>
  )
}
