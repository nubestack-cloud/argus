import type { NodeStatus } from '../api/types'

// Kubernetes quantity parsing and node usage roll-ups, shared by the cluster
// page's node table (ClusterDetailPage.tsx), its health ledger
// (ClusterOverviewSummary.tsx) and the Overview's cluster cards. Moved here
// unchanged from ClusterDetailPage.tsx so the three cannot drift.

export function formatQuantityNumber(value: number, maximumFractionDigits = 1): string {
  return new Intl.NumberFormat(undefined, { maximumFractionDigits }).format(value)
}

// The numeric halves of the two formatters below, split out so the utilization
// bars can divide used by allocatable without a second, subtly-different copy of
// the Kubernetes quantity grammar. `null` means "this string is not a quantity we
// understand" — distinct from zero, and the callers must keep it distinct: a
// bar that renders an unparseable value as 0% is a fabricated fact.
export function parseCPUCores(quantity?: string): number | null {
  if (!quantity) return null
  const match = quantity.trim().match(/^([+-]?(?:\d+(?:\.\d+)?|\.\d+)(?:e[+-]?\d+)?)(n|u|m)?$/i)
  if (!match) return null
  const value = Number(match[1])
  const suffix = match[2]?.toLowerCase() ?? ''
  return suffix === 'n' ? value / 1e9 : suffix === 'u' ? value / 1e6 : suffix === 'm' ? value / 1e3 : value
}

const MEMORY_MULTIPLIERS: Record<string, number> = {
  '': 1,
  K: 1e3,
  M: 1e6,
  G: 1e9,
  T: 1e12,
  Ki: 1024,
  Mi: 1024 ** 2,
  Gi: 1024 ** 3,
  Ti: 1024 ** 4,
}

export function parseMemoryBytes(quantity?: string): number | null {
  if (!quantity) return null
  const match = quantity.trim().match(/^([+-]?(?:\d+(?:\.\d+)?|\.\d+)(?:e[+-]?\d+)?)([a-zA-Z]*)$/)
  if (!match) return null
  const multiplier = MEMORY_MULTIPLIERS[match[2]]
  if (multiplier === undefined) return null
  return Number(match[1]) * multiplier
}

export function formatCPUQuantity(quantity?: string): string {
  if (!quantity) return 'Unknown'
  const cores = parseCPUCores(quantity)
  // Unparseable: show the raw string rather than "Unknown". It came from the
  // cluster and the reader may recognise a unit this app does not.
  if (cores === null) return quantity

  if (cores >= 1) {
    return `${formatQuantityNumber(cores, 2)} ${cores === 1 ? 'core' : 'cores'}`
  }
  if (cores >= 0.001) return `${formatQuantityNumber(cores * 1000, 0)} millicores`
  return `${formatQuantityNumber(cores * 1e6, 0)} microcores`
}

export function formatMemoryQuantity(quantity?: string): string {
  if (!quantity) return 'Unknown'
  const bytes = parseMemoryBytes(quantity)
  if (bytes === null) return quantity

  if (bytes >= 1024 ** 3) return `${formatQuantityNumber(bytes / 1024 ** 3, 1)} GiB`
  if (bytes >= 1024 ** 2) return `${formatQuantityNumber(bytes / 1024 ** 2, 0)} MiB`
  if (bytes >= 1024) return `${formatQuantityNumber(bytes / 1024, 0)} KiB`
  return `${formatQuantityNumber(bytes, 0)} bytes`
}

// Utilization as a bar. The one graphical element on the node table, and it earns its
// place because "which node is nearly full" is a comparison ACROSS ROWS, which a
// column of formatted strings does not give you at a glance and a column of bars
// does.
//
// Three honesty rules, all of them following from `cpuUsed`/`memoryUsed` being
// optional on the wire — metrics-server is not installed on every cluster, and
// the agent omits what it cannot read:
//
//   1. No bar at all when the numerator is missing or unparseable. A 0%-wide bar
//      is indistinguishable from a genuinely idle node, which turns "we did not
//      measure this" into "this is using nothing".
//   2. The percentage is always TEXT beside the bar, never carried by the bar's
//      length or its colour alone.
//   3. Over 100% — a node using more than it reports allocatable, which happens
//      under memory pressure — shows the true number in text and clamps only the
//      fill, so the bar cannot quietly misreport.
//
// The 50%/75%/90% thresholds are this UI's own reading convention and NOT a signal
// from the hub: nothing in internal/agent computes a CPU or memory severity, and
// the sweep detector's node checks look at conditions (NotReady, MemoryPressure)
// rather than at a ratio. So the colour is a scanning aid on top of an already
// labelled number, which is what tokens.md allows — and nothing here calls a
// node "critical" in words, because ARGUS has not decided that.
// Four bands rather than three (owner, 2026-10-11): with only a 75% step, a
// fleet that sits between 10% and 70% painted every bar the same green, and
// the colour read as decoration. The medium band uses --chart-medium, which is
// legal here only because the percentage is printed beside every bar.
export const MEDIUM_UTILIZATION = 0.5
export const HIGH_UTILIZATION = 0.75
export const CRITICAL_UTILIZATION = 0.9

export type UsageBand = 'normal' | 'medium' | 'high' | 'critical'

/** The band a used/allocatable ratio reads in (utilizationFillClass colours the bar from it). */
export function usageBand(ratio: number): UsageBand {
  if (ratio >= CRITICAL_UTILIZATION) return 'critical'
  if (ratio >= HIGH_UTILIZATION) return 'high'
  if (ratio >= MEDIUM_UTILIZATION) return 'medium'
  return 'normal'
}

/** The fill class for a usage bar (the cluster Overview's Resource use card),
 *  from the same bands as usageBand so every meter agrees on its thresholds. */
export function utilizationFillClass(ratio: number): string {
  return `resource-usage-fill resource-usage-fill-${usageBand(ratio)}`
}

// The cluster-wide roll-up, summed over the nodes that reported BOTH numbers.
// `reporting`/`total` is not decoration: summing a subset and calling it the
// cluster's utilization is exactly the unlabelled partial anti-patterns.md bans,
// so the tile renders the coverage next to the figure and the two travel
// together.
export function aggregateUsage(
  nodes: NodeStatus[],
  parse: (quantity?: string) => number | null,
  pick: (node: NodeStatus) => { used?: string; allocatable?: string },
): { ratio: number | null; used: number; capacity: number; reporting: number; total: number } {
  let used = 0
  let capacity = 0
  let reporting = 0
  for (const node of nodes) {
    const values = pick(node)
    const u = parse(values.used)
    const c = parse(values.allocatable)
    if (u === null || c === null || c <= 0) continue
    used += u
    capacity += c
    reporting += 1
  }
  return {
    ratio: reporting > 0 && capacity > 0 ? used / capacity : null,
    used,
    capacity,
    reporting,
    total: nodes.length,
  }
}


export type UsageRollup = ReturnType<typeof aggregateUsage>

/** Cluster CPU and memory usage over the nodes that reported both numbers. */
export function clusterUsage(nodes: NodeStatus[]): { cpu: UsageRollup; memory: UsageRollup } {
  return {
    cpu: aggregateUsage(nodes, parseCPUCores, (n) => ({ used: n.cpuUsed, allocatable: n.cpuAllocatable })),
    memory: aggregateUsage(nodes, parseMemoryBytes, (n) => ({ used: n.memoryUsed, allocatable: n.memoryAllocatable })),
  }
}
