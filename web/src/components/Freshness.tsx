import { useEffect, useState } from 'react'

function relative(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000))
  if (s < 45) return 'just now'
  const m = Math.round(s / 60)
  if (m < 60) return `${m} min ago`
  const h = Math.round(m / 60)
  if (h < 48) return `${h} h ago`
  return `${Math.round(h / 24)} days ago`
}

// Freshness says how old a piece of agent-sourced data is (docs/CLUSTER_INSIGHT_SPECS.md
// CI-U10) and, when the cluster is not connected, says the data is stale
// rather than letting it read as current. The relative time re-renders each
// minute.
export function Freshness({
  at,
  stale,
  staleReason,
}: {
  at: string | Date | null | undefined
  stale?: boolean
  staleReason?: string
}) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), 60_000)
    return () => window.clearInterval(t)
  }, [])
  if (!at) {
    return <span className="freshness">Age unknown</span>
  }
  const d = typeof at === 'string' ? new Date(at) : at
  if (Number.isNaN(d.getTime())) {
    return <span className="freshness">Age unknown</span>
  }
  const clock = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  if (stale) {
    return (
      <span className="freshness freshness-stale" role="status">
        Stale — as of {clock} ({relative(now - d.getTime())}){staleReason ? `; ${staleReason}` : ''}
      </span>
    )
  }
  return (
    <span className="freshness">
      As of <time dateTime={d.toISOString()}>{clock}</time> ({relative(now - d.getTime())})
    </span>
  )
}

export { relative as relativeAge }
