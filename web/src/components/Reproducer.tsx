import { CopyButton } from './CopyButton'

// Reproducer shows a command that re-derives a piece of evidence outside
// ARGUS (docs/CLUSTER_INSIGHT_SPECS.md CI-U9), so an operator can check a
// claim with their own credentials. Commands never carry a kube context:
// the cluster is named in words beside them.
export function Reproducer({ command, clusterName, label }: { command: string; clusterName?: string; label?: string }) {
  return (
    <div className="reproducer">
      <span className="reproducer-label">
        {label ?? 'Check it yourself'}
        {clusterName ? ` — run against ${clusterName}` : ''}
      </span>
      <div className="code-block-row">
        <code className="code-block">{command}</code>
        <CopyButton text={command} />
      </div>
    </div>
  )
}
