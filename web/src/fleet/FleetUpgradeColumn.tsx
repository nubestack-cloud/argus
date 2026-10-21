import { Link } from 'react-router-dom'
import type { UpgradeScan } from '../api/types'
import { VerdictBadge, toVerdict } from '../components/VerdictBadge'
import { formatDateTime } from '../utils/time'

// The Clusters list's upgrade column (docs/CLUSTER_INSIGHT_SPECS.md CI-S5):
// each cluster's latest stored scan, as a verdict word. "Not scanned" is a
// fact, not a pass; a scan that failed to load is "—", not a pass either.

export function UpgradeVerdictCell({
  clusterId,
  scan,
  loading,
  failed,
  showTarget,
}: {
  clusterId: string
  scan: UpgradeScan | undefined
  loading: boolean
  failed: boolean
  showTarget: boolean
}) {
  if (loading || failed) {
    return (
      <span className="text-muted" title={loading ? 'Upgrade scans are loading' : 'Upgrade scans could not be loaded'}>
        —
      </span>
    )
  }
  if (!scan) return <span className="text-muted">Not scanned</span>
  return (
    <Link
      to={`/clusters/${encodeURIComponent(clusterId)}?tab=upgrade`}
      title={`Upgrade ${scan.currentVersion || 'from an unreported version'} → ${scan.targetVersion}, scanned ${formatDateTime(scan.scannedAt)}; checks reviewed through ${scan.reviewedThrough}`}
    >
      {showTarget && <span className="cluster-version">to {scan.targetVersion} </span>}
      <VerdictBadge verdict={toVerdict(scan.verdict)} />
    </Link>
  )
}
