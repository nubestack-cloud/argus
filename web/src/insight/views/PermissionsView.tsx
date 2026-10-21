import { useState } from 'react'
import type { PermissionsResult } from '../types'

const TRIGGER_WORD: Record<string, string> = {
  clusterAdmin: 'Bound to cluster-admin',
  verbWildcard: 'Every verb (*) cluster-wide',
  escalationVerb: 'Can escalate, bind or impersonate',
  clusterCreatePods: 'Can create pods cluster-wide',
}

const RULES_SHOWN = 25

function ref(r: { kind: string; namespace?: string; name: string }): string {
  return `${r.kind} ${r.namespace ? `${r.namespace}/` : ''}${r.name}`
}

function list(v: string[] | undefined): string {
  return v && v.length > 0 ? v.join(', ') : '—'
}

// What an identity can do (CI-S3 get_subject_permissions): the blast-radius
// flags lead — the bindings that make a compromise of this identity a
// cluster-level problem — then each binding, then the flattened rules.
export function PermissionsView({ result }: { result: PermissionsResult }) {
  const [allRules, setAllRules] = useState(false)
  const flags = result.blastRadius?.flags ?? []
  const via = result.viaBindings ?? []
  const flat = result.flat ?? []
  const rules = allRules ? flat : flat.slice(0, RULES_SHOWN)
  return (
    <div className="insight-stack">
      {flags.length > 0 ? (
        <div className="banner banner-warning" role="note">
          <p className="insight-gap-line">
            <strong>Broad access</strong> — {flags.length} binding{flags.length === 1 ? '' : 's'} make compromise of this identity a cluster-level problem:
          </p>
          <ul className="insight-plain-list">
            {flags.map((f, i) => (
              <li key={i}>
                <strong>{TRIGGER_WORD[f.trigger] ?? f.trigger}</strong> via <code>{ref(f.binding)}</code>
                {f.inheritedFromGroup ? ` (through group ${f.inheritedFromGroup})` : ''} — {f.reason}
              </li>
            ))}
          </ul>
        </div>
      ) : (
        <p className="insight-lead">
          No cluster-takeover binding found (cluster-admin, wildcard verbs, escalation verbs, or cluster-wide pod creation).
        </p>
      )}
      {typeof result.blastRadius?.score === 'number' && (
        <p className="field-hint">
          Most permissive rule scores {result.blastRadius.score} — a ranking between identities, not a probability.
        </p>
      )}
      {via.length > 0 ? (
        <div className="table-scroll">
          <table className="data-table">
            <caption className="insight-caption">Granted through {via.length} binding{via.length === 1 ? '' : 's'}</caption>
            <thead>
              <tr>
                <th scope="col">Binding</th>
                <th scope="col">Role</th>
                <th scope="col">Scope</th>
                <th scope="col" className="col-numeric">Rules</th>
              </tr>
            </thead>
            <tbody>
              {via.map((b, i) => (
                <tr key={i}>
                  <td className="insight-mono">
                    {ref(b.binding)}
                    {b.inheritedFromGroup ? <span className="field-hint"> via group {b.inheritedFromGroup}</span> : null}
                  </td>
                  <td className="insight-mono">
                    {ref(b.role)}
                    {b.roleMissing ? <span className="badge badge-amber">role missing</span> : null}
                  </td>
                  <td>{b.scopeNamespace ? `namespace ${b.scopeNamespace}` : 'cluster-wide'}</td>
                  <td className="col-numeric">{typeof b.ruleCount === 'number' ? b.ruleCount : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="empty-state">No role binding grants this identity anything.</p>
      )}
      {flat.length > 0 && (
        <div className="table-scroll">
          <table className="data-table">
            <caption className="insight-caption">Effective rules, most permissive first</caption>
            <thead>
              <tr>
                <th scope="col">Verbs</th>
                <th scope="col">Resources</th>
                <th scope="col">API groups</th>
                <th scope="col" className="col-numeric">Score</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r, i) => (
                <tr key={i}>
                  <td className="insight-mono">{list(r.verbs)}</td>
                  <td className="insight-mono insight-wrap">
                    {r.nonResourceURLs && r.nonResourceURLs.length > 0 ? list(r.nonResourceURLs) : list(r.resources)}
                    {r.resourceNames && r.resourceNames.length > 0 ? ` (only ${r.resourceNames.join(', ')})` : ''}
                  </td>
                  <td className="insight-mono">{r.apiGroups ? r.apiGroups.map((g) => g || 'core').join(', ') : '—'}</td>
                  <td className="col-numeric">{typeof r.score === 'number' ? r.score : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {flat.length > RULES_SHOWN && (
            <button type="button" className="link-button" onClick={() => setAllRules((v) => !v)} aria-expanded={allRules}>
              {allRules ? `Show the first ${RULES_SHOWN} only` : `Show all ${flat.length} rules`}
            </button>
          )}
        </div>
      )}
      {result.truncated && <p className="insight-note">This identity holds more bindings or rules than are listed; the flags above were computed over all of them.</p>}
    </div>
  )
}
