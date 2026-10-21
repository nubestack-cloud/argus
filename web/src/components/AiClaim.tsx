import type { ReactNode } from 'react'

// AiClaim marks words a model wrote — a hypothesis, a root-cause sentence, a
// confidence statement — so they cannot be mistaken for a fact a detector or
// tool observed (docs/CLUSTER_INSIGHT_SPECS.md CI-U3; evidence discipline,
// argus-context non-negotiable 8). The "AI" label is text, so the
// distinction survives without colour; observed facts stay in the plain
// style with an evidence chip beside them.
export function AiClaim({
  children,
  label = 'AI',
  as: Tag = 'div',
}: {
  children: ReactNode
  label?: string
  as?: 'div' | 'span' | 'p'
}) {
  return (
    <Tag className="ai-claim">
      <span className="ai-claim-label">{label}</span>
      {children}
    </Tag>
  )
}
