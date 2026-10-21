import type { InspectResult } from '../api/client'
import type { DescribeResult, KubeObject } from '../insight/types'
import { diffLines } from './lineDiff'
import { hideInstanceFields, type InstanceHidden, type Revision } from './instance'
import { diffFields, stripNoise, toYaml, type FieldChange, type StrippedField } from './normalize'

// One comparison: both objects stripped of noise, rendered to YAML, diffed
// line by line for the view and field by field for the summary.

export interface Comparison {
  linesA: string[]
  linesB: string[]
  yamlA: string
  yamlB: string
  ops: ReturnType<typeof diffLines>['ops']
  aligned: boolean
  added: number
  removed: number
  changes: FieldChange[]
  redactedEqual: number
  stripped: StrippedField[]
  /** Per-instance fields hidden (empty when the option is off). */
  instanceHidden: InstanceHidden[]
  /** A and B are different ReplicaSets of one Deployment (option on only). */
  revision: Revision | null
}

export interface CompareOpts {
  includeStatus: boolean
  specOnly: boolean
  ignoreInstance: boolean
}

export function compareObjects(a: KubeObject, b: KubeObject, opts: CompareOpts): Comparison {
  const sa = stripNoise(a, opts)
  const sb = stripNoise(b, opts)
  const inst = opts.ignoreInstance ? hideInstanceFields(sa.value, sb.value, a, b) : { a: sa.value, b: sb.value, hidden: [], revision: null }
  const yamlA = toYaml(inst.a)
  const yamlB = toYaml(inst.b)
  const linesA = yamlA.split('\n')
  const linesB = yamlB.split('\n')
  const { ops, aligned } = diffLines(linesA, linesB)
  const fields = diffFields(inst.a, inst.b)
  return {
    linesA,
    linesB,
    yamlA,
    yamlB,
    ops,
    aligned,
    added: ops.filter((o) => o.kind === 'add').length,
    removed: ops.filter((o) => o.kind === 'del').length,
    changes: fields.changes,
    redactedEqual: fields.redactedEqual,
    stripped: [...new Set([...sa.stripped, ...sb.stripped])],
    instanceHidden: inst.hidden,
    revision: inst.revision,
  }
}

/** compareObjects over two describe_resource reads; null until both have an object. */
export function compareReads(
  a: InspectResult<DescribeResult> | undefined,
  b: InspectResult<DescribeResult> | undefined,
  opts: CompareOpts,
): Comparison | null {
  const oa = a?.result?.object
  const ob = b?.result?.object
  return oa && ob ? compareObjects(oa, ob, opts) : null
}
