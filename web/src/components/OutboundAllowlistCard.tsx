import { useState } from 'react'
import type { FormEvent } from 'react'

import type { OutboundPrivateDestination } from '../api/types'
import { HelpTip } from './HelpTip'
import { PanelHead } from './SettingsBlocks'

// Settings → Integrations → Outbound access: the operator's named exceptions
// to internal/outbound's default-deny on private destinations (migration
// 000115, owner decision 2026-09-19).
//
// # Why this is a controlled component and not another self-saving card
//
// AutomationWindowsCard and CircuitBreakerCard own their own endpoints and
// save on click. This list has no endpoint of its own — it is one section of
// PUT /api/v1/admin/settings — so it stages edits the way every other
// settings section on that page does, and the page's own "Save settings" bar
// commits them. The cost of that is a window where the screen shows an entry
// the hub has not accepted, which on a SECURITY control is a real honesty
// problem, so every row states whether it is in effect or only staged (see
// rowsFor below) rather than leaving the page-level "Unsaved changes" flag to
// carry it.
//
// # What this component deliberately does NOT do
//
// It does not re-implement outbound.ParseAllowlist. The rules there —
// private-ranges-only, no metadata address or any CIDR containing one, no
// host bits set, no pasted URL/port, no duplicate, at most 64 — are the same
// code that decides whether a dial is permitted, and a second copy here would
// be a place for the two to disagree while producing a worse message than the
// one the hub already writes. A rejected save surfaces the hub's own `detail`
// verbatim through the page's mutation feedback.
//
// The one rule this component does enforce locally is the required reason,
// because the UI must never offer "add" as an operation that can produce an
// unjustified exception in the first place. The hub enforces it too; this is
// the same rule stated at the point of entry, not a second rule.

/**
 * The three shapes a destination can take, for DISPLAY only — never a
 * validation gate (see the component's doc comment).
 *
 * The bias is deliberate: anything not confidently an IP literal or a CIDR is
 * labelled a hostname, so an ambiguous value gets the caution about DNS trust
 * rather than the reassurance about a fixed address. A value that is neither
 * is refused by the hub on save anyway.
 */
type DestinationForm = 'cidr' | 'ip' | 'hostname'

function destinationForm(destination: string): DestinationForm {
  const value = destination.trim()
  if (value === '') return 'hostname'
  if (value.includes('/')) return 'cidr'
  // IPv4 dotted quad, or an IPv6 literal (hex digits and colons only — which
  // is what keeps "vllm.internal:8000", a pasted host:port, out of here).
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return 'ip'
  if (value.includes(':') && /^[0-9a-fA-F:]+$/.test(value)) return 'ip'
  return 'hostname'
}

const FORM_LABEL: Record<DestinationForm, string> = {
  cidr: 'CIDR range',
  ip: 'IP address',
  hostname: 'Hostname',
}

// The trade a hostname entry makes, said twice on purpose and never in the
// same words twice: internal/outbound/allowlist.go's parsedEntry.host resolves
// the name at dial time and permits whatever it resolves to, so a hostname
// entry's trust is DNS's trust, while an IP or CIDR cannot be moved that way.
//
// HOSTNAME_HINT is what someone reads about the value they have actually
// typed, at the moment they are choosing it; the panel's consequence notice
// states the same trade as general guidance, in its own sentence. The two are
// not interchangeable and neither is a copy of the other.
const HOSTNAME_HINT =
  'It will permit whatever it resolves to at dial time — name an IP address or a CIDR range instead if you can, since those cannot be moved by a DNS change.'
const FIXED_ADDRESS_HINT = 'It permits exactly this address, and no DNS change can move it.'

type RowStatus = 'in-effect' | 'pending-add' | 'pending-removal'

type Row = {
  entry: OutboundPrivateDestination
  status: RowStatus
}

function key(entry: OutboundPrivateDestination): string {
  // Same case-insensitive identity the hub's duplicate check uses
  // (outbound.ParseAllowlist lowercases before comparing).
  return entry.destination.trim().toLowerCase()
}

/**
 * The union of what is staged and what the server currently holds, so a
 * removal stays on screen as "removed on save" instead of vanishing while the
 * destination is still allowed.
 */
function rowsFor(
  entries: OutboundPrivateDestination[],
  savedEntries: OutboundPrivateDestination[],
): Row[] {
  const savedKeys = new Set(savedEntries.map(key))
  const stagedKeys = new Set(entries.map(key))
  const rows: Row[] = entries.map((entry) => ({
    entry,
    status: savedKeys.has(key(entry)) ? 'in-effect' : 'pending-add',
  }))
  for (const saved of savedEntries) {
    if (!stagedKeys.has(key(saved))) rows.push({ entry: saved, status: 'pending-removal' })
  }
  return rows
}

const STATUS_LABEL: Record<RowStatus, string> = {
  'in-effect': 'In effect',
  'pending-add': 'Not saved',
  'pending-removal': 'Removed on save',
}

// Status is carried by the word first; the badge tone is an addition to it,
// never the signal itself (lld/11 §8). Amber on both pending states because
// both mean the same thing — what is on screen is not what the hub is
// enforcing until this page is saved.
const STATUS_TONE: Record<RowStatus, string> = {
  'in-effect': 'badge badge-gray',
  'pending-add': 'badge badge-amber',
  'pending-removal': 'badge badge-amber',
}

export function OutboundAllowlistCard({
  entries,
  savedEntries,
  onChange,
  canWrite,
  disabledReason,
}: {
  /** The staged list — what a save would send. */
  entries: OutboundPrivateDestination[]
  /** What the hub currently holds, for the in-effect/staged distinction. */
  savedEntries: OutboundPrivateDestination[]
  onChange: (next: OutboundPrivateDestination[]) => void
  canWrite: boolean
  disabledReason?: string
}) {
  const [destination, setDestination] = useState('')
  const [reason, setReason] = useState('')
  const [addError, setAddError] = useState('')

  const rows = rowsFor(entries, savedEntries)
  const hasPending = rows.some((r) => r.status !== 'in-effect')
  const typedForm = destinationForm(destination)

  function add(e: FormEvent) {
    e.preventDefault()
    const dest = destination.trim()
    const why = reason.trim()
    if (dest === '') {
      setAddError('Enter a destination — an IP address, a CIDR range or a hostname.')
      return
    }
    if (why === '') {
      // The rule this list exists for: an exception that cannot state why it
      // exists is one nobody can review later. The hub refuses it too
      // (outbound.ParseAllowlist); stating it here means the operator never
      // gets as far as a rejected save.
      setAddError('Enter a reason — this list does not accept a destination without one.')
      return
    }
    if (entries.some((entry) => key(entry) === dest.toLowerCase())) {
      setAddError(`${dest} is already listed.`)
      return
    }
    setAddError('')
    setDestination('')
    setReason('')
    onChange([...entries, { destination: dest, reason: why }])
  }

  return (
    <div className="card settings-panel">
      <PanelHead
        title="Private destinations"
        lede="Named exceptions to ARGUS refusing private and internal addresses when it dials an AI or Git provider."
        help="ARGUS refuses outbound connections to private, internal, loopback and link-local addresses when it dials an AI provider's base URL or a Git provider's API. That default stays. The entries here are the named exceptions to it: a destination an operator has decided to trust, with the reason they decided it. Anything not listed here is still refused. A public address, a range that is not wholly private, and the cloud metadata address (169.254.169.254, and any range containing it) are refused whatever is listed here — there is no way to spell 'allow everything'."
      />

      {/* The consequence and the DNS-versus-IP trade, stated where someone is
          choosing (reference/screens.md mode E) — one line each. */}
      <ul className="settings-facts">
        <li>
          <strong>An entry only ever permits an address that is otherwise refused.</strong> Public
          addresses and the cloud metadata address are refused whatever is listed.
        </li>
        <li>
          <strong>Prefer an IP address or a CIDR range.</strong> A hostname entry trusts whoever
          controls that name's DNS record.
        </li>
      </ul>

      {rows.length === 0 ? (
        // "Nothing is allowlisted" and "we could not load this" are different
        // states: a failed GET never reaches this component at all (the page
        // renders the problem detail instead), so an empty list here is the
        // hub's actual answer — the secure default — and reads as one.
        <p className="empty-state">
          Nothing is allowlisted, which is the default and the secure state: every private or
          internal destination is refused.
        </p>
      ) : (
        <div className="table-scroll">
          <table className="cluster-table">
            <thead>
              <tr>
                <th>Destination</th>
                <th>Form</th>
                <th>Reason</th>
                <th>Status</th>
                <th>
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ entry, status }) => {
                const form = destinationForm(entry.destination)
                return (
                  <tr key={`${status}:${key(entry)}`}>
                    <td>
                      {/* No wrap-anywhere on either of these two cells,
                          deliberately: it drops the column's min-content width
                          to one character, and at 768px it broke a hostname
                          into "ghe.inter / nal.examp / le.com" — an address
                          someone is checking character by character is the
                          last thing to hyphenate. A long value widens the
                          column and .table-scroll scrolls the table inside its
                          own box instead, which is this codebase's standard
                          answer for wide content. */}
                      <code>{entry.destination}</code>
                    </td>
                    <td>
                      {FORM_LABEL[form]}
                      {form === 'hostname' && (
                        <span className="field-hint"> — trust follows DNS</span>
                      )}
                    </td>
                    <td>{entry.reason}</td>
                    <td>
                      <span className={STATUS_TONE[status]}>{STATUS_LABEL[status]}</span>
                    </td>
                    <td>
                      {status === 'pending-removal' ? (
                        <button
                          type="button"
                          className="secondary"
                          disabled={!canWrite}
                          title={canWrite ? 'Keep this destination allowed' : disabledReason}
                          onClick={() => onChange([...entries, entry])}
                        >
                          Keep
                        </button>
                      ) : (
                        <button
                          type="button"
                          className="secondary"
                          disabled={!canWrite}
                          title={canWrite ? 'Remove this destination' : disabledReason}
                          onClick={() =>
                            onChange(entries.filter((candidate) => key(candidate) !== key(entry)))
                          }
                        >
                          Remove
                        </button>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {hasPending && (
        <p className="field-hint">
          Nothing on this list takes effect, or stops taking effect, until you save.
        </p>
      )}

      {/* Its own form, not the page's: this one adds a row to the staged list,
          and the page's Save bar is what sends it. */}
      <h3 className="settings-subhead">Add a destination</h3>
      <form onSubmit={add} className="settings-inline-add">
        <div className="settings-field">
        <label htmlFor="outbound-destination">
          Destination
          <HelpTip label="Destination" text="An IP address (10.20.0.5), a CIDR range written as its network address (10.20.0.0/16), or a bare hostname (vllm.internal.example.com) — no scheme, port or path. Only private, loopback and link-local addresses can be named: a public address is refused here because it needs no entry." />
        </label>
        <input
          id="outbound-destination"
          value={destination}
          onChange={(e) => setDestination(e.target.value)}
          placeholder="10.20.0.0/16"
          disabled={!canWrite}
          title={disabledReason}
        />
        {/* The trade, while the value is being typed rather than after it is
            saved. It describes what the typed form MEANS; it never accepts or
            rejects one — the hub does that. */}
        {destination.trim() !== '' && (
          <p className="field-hint">
            {FORM_LABEL[typedForm]}.{' '}
            {typedForm === 'hostname' ? HOSTNAME_HINT : FIXED_ADDRESS_HINT}
          </p>
        )}
        </div>
        <div className="settings-field">
        <label htmlFor="outbound-reason">
          Reason <span className="badge badge-amber">required</span>
          <HelpTip label="Reason" text="Why this destination is trusted, in your own words. Required, and kept with the entry: an exception that cannot say why it exists is one no future reviewer can evaluate. The hub refuses an entry without one." />
        </label>
        <input
          id="outbound-reason"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="Self-hosted vLLM on the cluster network"
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
    </div>
  )
}
