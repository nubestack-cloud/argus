import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { listApplications } from '../api/client'
import { useAuth } from '../auth/useAuth'

// Version skew across clusters (PROJECT.md PG19), as one line in the
// Overview's Delivery & agents card. Failing releases and apps are already
// drawn there and open incidents; the one fact only the fleet view has is the
// same application running different versions on different clusters. So this
// says nothing until that is true, and then one line with the list behind a
// disclosure. Each row names how its copies were matched, because a match by
// release name alone is a guess.

export type AppInstance = {
  clusterId: string
  clusterName: string
  kind: string
  namespace: string
  name: string
  version?: string
}
export type Application = { key: string; name: string; matchedBy: string; instances: AppInstance[]; skew: boolean }

const MATCH_HINT: Record<string, string> = {
  annotation: 'Matched by the argus.io/app annotation on its objects.',
  source: 'Matched because each copy deploys the same repository and path or chart.',
  name: 'Matched by release name only: two unrelated releases with one name would match.',
}

/** Skewed applications in scope: all of them, or those with a copy on the
 *  one cluster the Overview is narrowed to. */
export function skewedInScope(apps: Application[], scope: string): Application[] {
  return apps.filter((a) => a.skew && (scope === 'all' || a.instances.some((i) => i.clusterId === scope)))
}

export function VersionSkew({ scope }: { scope: string }) {
  const { accessToken } = useAuth()
  const q = useQuery({ queryKey: ['applications'], queryFn: () => listApplications(accessToken!), enabled: !!accessToken })
  if (q.isError) return <p className="ov-card-note">Versions across clusters could not be read.</p>
  const skewed = skewedInScope((q.data?.applications ?? []) as Application[], scope)
  if (skewed.length === 0) return null
  return (
    <details className="ov-skew">
      <summary>
        <span className="ov-state-warn">
          {skewed.length} application{skewed.length === 1 ? '' : 's'}
        </span>{' '}
        run{skewed.length === 1 ? 's' : ''} different versions across clusters
      </summary>
      <ul className="ov-skew-list">
        {skewed.map((a) => (
          <li key={a.key}>
            <span className="mono" title={MATCH_HINT[a.matchedBy]}>
              {a.name}
              {a.matchedBy === 'name' && <span className="text-muted"> (by name)</span>}
            </span>
            {a.instances.map((i) => (
              <Link key={`${i.clusterId}/${i.namespace}/${i.name}`} className="ov-skew-copy" to={`/clusters/${i.clusterId}?tab=${i.kind === 'Helm release' ? 'helm' : 'gitops'}`}>
                {i.clusterName} <span className="mono">{i.version ?? '—'}</span>
              </Link>
            ))}
          </li>
        ))}
      </ul>
    </details>
  )
}
