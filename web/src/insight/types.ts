// Wire shapes of the agent's cluster-insight tool results, as the hub's
// POST /clusters/{id}/inspect/{tool} returns them inside `result`. They are
// the JSON tags of the Go structs named beside each type; every field is
// optional here because an older agent may omit any of them, and the UI must
// render "not reported" rather than crash or invent a value.

/** objcache.KindStatus — a kind an answer needed that was not synced. */
export interface CoverageEntry {
  group?: string
  kind: string
  state: string
  reason?: string
}

/** insightMeta / insightStamp (internal/agent/tools_insight.go). */
export interface InsightMeta {
  observedAt?: string
  coverage?: CoverageEntry[]
  truncated?: boolean
}

/** tools_events.go eventResult. */
export interface EventResult {
  namespace?: string
  involvedObjectKind?: string
  involvedObjectName?: string
  reason?: string
  message?: string
  type?: string
  count?: number
  lastTimestamp?: string
}

/** tools_describe.go describeResourceResult. */
export interface DescribeResult {
  object?: KubeObject
  events?: EventResult[] | null
}

export interface KubeObject {
  apiVersion?: string
  kind?: string
  metadata?: {
    name?: string
    namespace?: string
    uid?: string
    creationTimestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
    ownerReferences?: { apiVersion?: string; kind?: string; name?: string; controller?: boolean }[]
  }
  spec?: Record<string, unknown>
  status?: Record<string, unknown>
  [k: string]: unknown
}

/** tools_ownerchain.go ownerChainNode. */
export interface OwnerChainNode {
  gvk: string
  namespace?: string
  name: string
  resolved?: boolean
}

/** topology.Subgraph + Node/Edge. */
export interface NeighborhoodResult extends InsightMeta {
  root?: { kind: string; apiGroup?: string; namespace?: string; name: string }
  nodes?: {
    id: string
    kind: string
    apiGroup?: string
    namespace?: string
    name: string
    status?: string
    statusReason?: string
    summary?: Record<string, unknown>
  }[]
  edges?: { id: string; source: string; target: string; type: string }[]
  omitted?: number
  unavailable?: string[]
  /** True when the agent's relationship index does not map this kind (most
   *  custom resources): the object exists, its edges are simply not known.
   *  `note` says so in words. */
  unmapped?: boolean
  note?: string
}

/** rbacgrants.Report. */
export interface PermissionsResult extends InsightMeta {
  subject?: { kind: string; namespace?: string; name: string }
  viaBindings?: {
    binding: { kind: string; namespace?: string; name: string }
    role: { kind: string; namespace?: string; name: string }
    scopeNamespace?: string
    inheritedFromGroup?: string
    roleMissing?: boolean
    ruleCount?: number
    maxRuleScore?: number
  }[]
  flat?: { verbs?: string[]; apiGroups?: string[]; resources?: string[]; resourceNames?: string[]; nonResourceURLs?: string[]; score?: number }[]
  blastRadius?: {
    flags?: { trigger: string; binding: { kind: string; namespace?: string; name: string }; inheritedFromGroup?: string; reason: string }[]
    score?: number
  }
}

/** hpaexplain.Explanation wrapped in autoscalerResult. */
export interface AutoscalerResult extends InsightMeta {
  diagnosis?: {
    state?: string
    summary?: string
    target?: { kind?: string; name?: string }
    bounds?: { min?: number; max?: number; current?: number; desired?: number }
    metrics?: { type?: string; name?: string; current?: string; target?: string; status?: string }[]
    reasons?: { id?: string; message?: string; detail?: string }[]
  } | null
}

/** rolloutcheck.Report wrapped in rolloutResult. */
export interface RolloutResult extends InsightMeta {
  /** stuck | inProgress | paused | atRisk | safe | complete | notApplicable |
   *  unknown — live progress (from the Progressing condition and replica
   *  counts) decides first; the availability policy only when it is settled. */
  verdict?: string
  reason?: string
  strategy?: string
  replicas?: number
  risk?: { maxSurge?: string; maxUnavailable?: string; message?: string; remediation?: string } | null
  progress?: {
    state?: string
    conditionReason?: string
    conditionMessage?: string
    desired?: number
    updated?: number
    ready?: number
    available?: number
    unavailable?: number
    total?: number
    newReplicaSet?: string
    notReadyPods?: { name: string; phase?: string; waiting?: string; node?: string }[] | null
  } | null
  policyVerdict?: string
  policyReason?: string
  notes?: string[] | null
}

/** schedexplain.Explanation wrapped in schedulingResult. */
export interface KarpenterPoolVerdict {
  pool: string
  fits: boolean
  reason?: string
  weight?: number
}

export interface SchedulingResult extends InsightMeta {
  /** Each Karpenter NodePool's verdict for this pod (CI-S9). */
  karpenter?: KarpenterPoolVerdict[] | null
  pod?: string
  signature?: string
  similarPendingPods?: number
  schedulerMessage?: string
  schedulerTotalNodes?: number
  parsed?: { class: string; nodeCount?: number; detail?: string }[]
  nodes?: { predicate: string; reason: string; count: number; examples?: string[]; detail?: string }[]
  nodesEvaluated?: number
  unsatisfiable?: string[]
  verdict?: string
  /** The pod is already bound to a node: not a scheduling problem, and no
   *  predicate was evaluated. */
  alreadyScheduled?: boolean
  nodeName?: string
}

/** policyFindingsResult. */
export interface PolicyResult extends InsightMeta {
  findings?: { policy?: string; rule?: string; result?: string; severity?: string; category?: string; message?: string; source?: string }[]
}

/** gitOpsInsightResult (gitopsinsight Summary/ParsedFailure/Drift). */
export interface GitOpsInsightResult extends InsightMeta {
  summary?: {
    tool?: string
    kind: string
    namespace?: string
    name: string
    sync?: string
    health?: string
    operationPhase?: string
    operationMessage?: string
    source?: string
    targetRevision?: string
    lastRevision?: string
    lastReconcile?: string
    autoSync?: string
    terminating?: boolean
    conditions?: { type: string; status?: string; reason?: string; message?: string; action?: string }[]
    conditionsTruncated?: boolean
    managedResources?: { group?: string; kind: string; namespace?: string; name: string; status?: string; health?: string }[]
    managedResourcesTotal?: number
    // resourceHealthUnavailable (PG3, 2026-10-13 parity review): Argo CD 3.x's
    // status.resourceHealthSource: appTree stops writing per-resource health
    // into the Application at all — managedResources[].health is then never
    // populated by Argo itself, not by a read failure here.
    resourceHealthUnavailable?: boolean
    // history (PG3): the controller's own past-operation/release log — Argo's
    // status.history, or a Flux HelmRelease's own. Newest first.
    history?: { revision?: string; deployedAt?: string; initiatedBy?: string; outcome?: string }[]
    historyTruncated?: boolean
  }
  parsedFailure?: { class?: string; cause?: string; affectedKind?: string; affectedName?: string; missingNamespace?: string; retryCount?: number; stuck?: boolean }
  drift?: {
    source?: string
    entries?: { path: string; op: string; desired?: string; live?: string }[]
    truncated?: boolean
    unavailableReason?: string
    /** The controller's own per-resource verdict (Argo CD status.resources). */
    controller?: { controller: string; application: string; status: string; health?: string }
  }
}

/** helmStatusResult. */
export interface HelmStatusResult extends InsightMeta {
  release?: string
  namespace?: string
  latestRevision?: number
  /** `updated` is Helm's modifiedAt label; `createdAt` is the release
   *  record's own creation time (metadata only, never the payload). */
  history?: { revision: number; status: string; updated?: string; createdAt?: string; chart?: string; appVersion?: string }[]
  analysis?: {
    lastOperation?: { kind?: string; status?: string; message?: string; revision?: number } | null
    operations?: { kind?: string; status?: string; message?: string; revision?: number }[]
  }
  note?: string
  // hookJobs (PG4, 2026-10-13 parity review): failed or stuck Helm lifecycle
  // hook Jobs correlated to this release. inferred is always true — see
  // internal/agent/helmstatus.HookJob's own doc comment for why this is a
  // label match, not an ownership proof.
  hookJobs?: { hook: string; name: string; namespace: string; phase: string; reason?: string; message?: string; startedAt?: string; inferred: boolean }[]
}

/** pathtrace.Trace wrapped in traceResult — see pathtrace/model.ts. */
export interface TraceResult extends InsightMeta {
  subject?: { group?: string; kind: string; namespace?: string; name: string }
  upstreams?: { resource: { kind: string; namespace?: string; name: string }; edge?: string }[] | null
  downstream?: { resource: { kind: string; namespace?: string; name: string }; edge?: string }[] | null
  verdict?: string
  brokenAt?: number
  headline?: string
  reason?: string
  findings?: { code: string; hop?: string; severity: string; message: string; command?: string }[] | null
}

/** evaluate_network_policy's result (internal/agent/tools_insight.go netpolResult). */
export interface NetpolResult extends InsightMeta {
  verdict?: { verdict: 'allowed' | 'denied' | 'unknown'; direction?: string; decidingPolicies?: string[] }
  backends?: number
  explanations?: {
    policy: string
    direction: string
    explanation: { effect: 'admits' | 'doesNotAdmit' | 'undecidable' | 'notApplicable'; reason: string }
  }[]
  note?: string
}
