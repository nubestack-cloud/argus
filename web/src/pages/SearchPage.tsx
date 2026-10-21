import { useEffect, useState } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { searchObjects } from '../api/client'
import { CAP_CLUSTER_INSPECT } from '../api/capabilities'
import { missingCapabilityMessage } from '../api/capabilityInfo'
import { useAuth } from '../auth/useAuth'
import { useMissingCapabilities } from '../auth/useCapabilities'
import { SearchIcon } from '../components/icons'
import { SkeletonTableRows } from '../components/Skeleton'
import { useUrlParam } from '../hooks/useUrlState'
import { withObjectPanel } from '../insight/panelUrl'
import { apiErrorText } from '../fleet/apiErrorText'
import { SEARCH_GRAMMAR, coverageSentences, groupHitsByCluster, type SearchHit } from '../fleet/searchModel'
import { useRowNavigation } from '../fleet/useRowNavigation'

// Find an object across the fleet (docs/CLUSTER_INSIGHT_SPECS.md CI-S12).
//
// Mode A (triage scan): the question is "where does payments-api exist, and
// is it healthy there?" Hits are grouped by cluster, each row leads with the
// object's identity and carries the agent's status word; a hit opens the
// object inspector over this page (?panel=), so the result list survives.
// The fan-out is partial by nature — a cluster can time out or be
// disconnected — so what was NOT searched is stated in sentences above the
// results, never left for the reader to infer from an absence.

const MIN_QUERY = 2

function HitRow({
  hit,
  navProps,
  onOpen,
}: {
  hit: SearchHit
  navProps: ReturnType<ReturnType<typeof useRowNavigation>['rowProps']>
  onOpen: () => void
}) {
  return (
    <tr
      {...navProps}
      className={['fleet-row-clickable', navProps['aria-current'] ? 'fleet-row-active' : ''].filter(Boolean).join(' ')}
      onClick={(e) => {
        if (!(e.target as HTMLElement).closest('a, button')) onOpen()
      }}
    >
      <td>
        <div className="identity-block">
          <button type="button" className="link-button identity-block-name fleet-expander" onClick={onOpen} title="Open in the inspector">
            {hit.name}
          </button>
          <span className="identity-block-kind">
            {hit.kind}
            {hit.apiGroup ? `.${hit.apiGroup}` : ''}
            {hit.namespace ? ` · ${hit.namespace}` : ' · cluster-scoped'}
          </span>
        </div>
      </td>
      <td>{hit.status ? hit.status : <span className="text-muted">No status reported</span>}</td>
      <td className="text-muted">{(hit.matched ?? []).join(', ') || '—'}</td>
    </tr>
  )
}

export function SearchPage() {
  const { accessToken } = useAuth()
  const [params, setParams] = useSearchParams()
  const [q, setQ] = useUrlParam<string>('q', '')
  const [draft, setDraft] = useState(q)
  const { resolved, missing } = useMissingCapabilities([CAP_CLUSTER_INSPECT])
  const allowed = resolved && missing.length === 0

  // Typing updates the URL after a pause; the URL is what is searched, so a
  // link (or the palette's "search for …") lands on the same results.
  useEffect(() => {
    const t = setTimeout(() => {
      if (draft.trim() !== q) setQ(draft.trim())
    }, 300)
    return () => clearTimeout(t)
  }, [draft, q, setQ])

  const query = useQuery({
    queryKey: ['search', q],
    queryFn: () => searchObjects(q, accessToken!),
    enabled: !!accessToken && allowed && q.length >= MIN_QUERY,
    placeholderData: keepPreviousData,
    staleTime: 30_000,
    retry: false,
  })
  const data = query.data
  const groups = data ? groupHitsByCluster(data.hits ?? []) : []
  const flat = groups.flatMap((g) => g.hits)
  const open = (h: SearchHit) =>
    setParams(
      withObjectPanel(params, {
        clusterId: h.clusterId,
        kind: h.kind,
        apiGroup: h.apiGroup || undefined,
        namespace: h.namespace || undefined,
        name: h.name,
      }),
    )
  const nav = useRowNavigation({ count: flat.length, onOpen: (i) => flat[i] && open(flat[i]) })
  const coverage = data ? coverageSentences(data) : []
  let index = 0

  return (
    <div className="page list-page fleet-search">
      <header className="page-header list-page-header">
        <div>
          <h1>Search</h1>
          <p className="text-muted">Find a Kubernetes object by name, namespace, label or image on every cluster you can inspect.</p>
        </div>
      </header>

      <form
        className="fleet-search-field"
        role="search"
        onSubmit={(e) => {
          e.preventDefault()
          setQ(draft.trim())
        }}
      >
        <label className="list-search-field">
          <span className="visually-hidden">Search objects</span>
          <SearchIcon />
          <input
            type="search"
            data-page-filter
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="payments-api, kind:Deployment ns:payments, label:app=api"
            disabled={resolved && !allowed}
            title={resolved && !allowed ? missingCapabilityMessage(missing) : undefined}
          />
        </label>
      </form>

      {resolved && !allowed && (
        <p className="banner banner-warning" role="note">
          Search asks each cluster&apos;s agent directly. {missingCapabilityMessage(missing)}
        </p>
      )}

      {allowed && q.length < MIN_QUERY && (
        <div className="fleet-grammar">
          <p>
            Type at least {MIN_QUERY} characters. Plain words match object names first, then namespaces, labels and
            images. Narrow with:
          </p>
          <dl className="kv-list">
            {SEARCH_GRAMMAR.map((g) => (
              <div key={g.token} className="fleet-counts-row">
                <dt>
                  <code>{g.token}</code>
                </dt>
                <dd>{g.meaning}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}

      {allowed && q.length >= MIN_QUERY && query.isLoading && (
        <div className="table-scroll" aria-busy="true" aria-label="Searching">
          <table className="cluster-table list-table">
            <tbody>
              <SkeletonTableRows columns={3} rows={6} />
            </tbody>
          </table>
        </div>
      )}

      {allowed && q.length >= MIN_QUERY && query.isError && (
        <p className="form-error" role="alert">
          {apiErrorText(query.error, 'The search could not run.')}
        </p>
      )}

      {allowed && q.length >= MIN_QUERY && data && (
        <>
          <p className="fleet-count-line" aria-live="polite">
            {query.isFetching ? 'Searching… ' : ''}
            {data.hits.length} {data.hits.length === 1 ? 'match' : 'matches'}
            {data.truncated ? ' (more exist — narrow the query)' : ''} for &ldquo;{data.query}&rdquo; · {data.clustersAnswered} of{' '}
            {data.clustersQueried} {data.clustersQueried === 1 ? 'cluster' : 'clusters'} answered
          </p>
          {coverage.map((c) => (
            <p key={c} className="fleet-scope-note" role="note">
              {c}
            </p>
          ))}
          {groups.length === 0 ? (
            <p className="empty-state">
              {data.clustersAnswered === 0
                ? 'No cluster answered, so nothing could be searched. See above for which clusters were asked.'
                : `No objects match “${data.query}” on the ${data.clustersAnswered} ${data.clustersAnswered === 1 ? 'cluster' : 'clusters'} that answered.`}
            </p>
          ) : (
            <div {...nav.containerProps}>
            {groups.map((g) => (
              <section key={g.clusterId} className="fleet-cluster-results" aria-label={`Matches on ${g.clusterName}`}>
                <h2>
                  <Link to={`/clusters/${encodeURIComponent(g.clusterId)}`}>{g.clusterName}</Link>{' '}
                  <span className="text-muted">
                    · {g.hits.length} {g.hits.length === 1 ? 'match' : 'matches'}
                  </span>
                </h2>
                <div className="table-scroll">
                  <table className="cluster-table list-table">
                    <thead>
                      <tr>
                        <th>Object</th>
                        <th>Status</th>
                        <th>Matched on</th>
                      </tr>
                    </thead>
                    <tbody>
                      {g.hits.map((h) => {
                        const i = index++
                        return <HitRow key={`${h.kind}/${h.namespace}/${h.name}/${i}`} hit={h} navProps={nav.rowProps(i)} onOpen={() => open(h)} />
                      })}
                    </tbody>
                  </table>
                </div>
              </section>
            ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}
