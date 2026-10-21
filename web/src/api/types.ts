// Shapes for the hub's JSON HTTP API, per the fixed contract this UI is
// built against.
//
// PROJECT.md T12: the types below that read `= components['schemas']['X']`
// are GENERATED, not transcribed — their shape comes from `docs/openapi.yaml`
// via `npm run generate-api-types` (openapi-typescript), and
// `internal/api/openapi_contract_test.go`/`_db_test.go` verify that spec
// against the real handlers, so a handler that changes shape fails a Go test
// rather than silently drifting from this file the way B158 did. The doc
// comment immediately above each such type is kept HERE, hand-maintained,
// deliberately — see docs/openapi.yaml's own top-level description for why:
// most of these comments are the load-bearing prose this task was told not
// to lose, and duplicating them as OpenAPI `description` fields as well
// (which `npm run generate-api-types` would then also put in `generated.ts`)
// would give the same sentence two homes that can drift from each other.
// Never hand-edit `generated.ts`; regenerate it.
//
// PROJECT.md F33 took docs/openapi.yaml from 47 documented operations to 98 —
// all but seven of the hub's routes (two probes, the Prometheus scrape target,
// the SPA catch-all, the WebSocket upgrade and the two dev-only demo-data
// routes). B189 then converted every hand-written interface that had gained a
// generated twin, so THERE IS NOW ONE HOME PER SHAPE: every type in this file
// is an alias of the generated contract, and the prose above it is the only
// hand-maintained part. `LiveEvent` is the single remaining transcription, and
// it is one on purpose — it describes frames on the WebSocket route, which is
// one of the seven the spec deliberately does not cover.
//
// Keep it that way. A new shape belongs in docs/openapi.yaml first, where the
// Go contract test can hold the handler to it; transcribing one here
// recreates exactly the divergence B158 and B189 each had to be paid for.
//
// Two aliases carry a deliberate OVERRIDE rather than a plain re-export —
// `RenderEvidence` and, following it, `RepositoryPreviewResponse`. Each says at
// its own definition which spec field is wrong and how it was proved wrong
// against the handler. An override is a recorded disagreement with the
// contract, not a licence to re-transcribe: it names one field, and it is
// deleted the day the spec is corrected.
//
// What B189 found when the two homes were finally compared, all of it now
// fixed in the screens rather than papered over: Go marshals a nil slice as
// JSON `null`, not `[]`, and six response fields the transcriptions declared
// as plain arrays are genuinely null on the wire — see
// `DiscoverRepositoryLinkResponse.otherClusters`, `IdentityProvider.scopes`,
// `RepositoryChangeVerification.checks`/`advisories` and
// `DiagnosticsBundle.recentInternalErrors`.
import type { components, operations } from './generated'

// Most shapes below alias `components['schemas'][...]`. A handful of operations
// declare their request or response body INLINE in docs/openapi.yaml rather
// than as a named schema, so those are reached through `operations` instead.
// Same generated file, same `npm run generate-api-types` regeneration path,
// same Go contract test behind it — just a different address inside it. Two
// helpers keep the call sites readable rather than repeating the full
// responses/content/media-type walk at each one.
type ResponseBody<
  O extends keyof operations,
  S extends number,
> = operations[O] extends { responses: infer R }
  ? S extends keyof R
    ? R[S] extends { content: { 'application/json': infer T } }
      ? T
      : never
    : never
  : never

type RequestBody<O extends keyof operations> = operations[O] extends {
  requestBody?: { content: { 'application/json': infer T } }
}
  ? T
  : never

export type LoginRequest = components['schemas']['LoginRequest']

// One federated sign-in option, as offered by the unauthenticated
// GET /auth/sso/providers (PROJECT.md S2). Deliberately just an id and a
// label: the endpoint runs before anyone is authenticated and publishes the
// minimum that makes the login screen work — not the issuer, not the client
// id.
export type SSOProvider = components['schemas']['SSOProvider']

// Whether the password form should be offered at all. The server currently
// always says true, because break-glass local login survives SSO being
// enabled — a super-admin can always use a password so an identity-provider
// outage cannot lock everyone out. Read rather than assumed, so the day that
// policy changes the screen follows it without a frontend release.
// (`localLoginAvailable`)
//
// `loginStyle` — which sign-in layout to render (org_settings.login_style,
// chosen in Settings → Appearance). Served here because this is already the
// one unauthenticated call this screen makes. Optional on the wire: a hub
// older than this bundle omits it, and `frameFor` treats anything it does
// not recognise as the default.
//
// `version` — this hub build's version, shown in the sign-in footers.
// Optional on the wire: an older hub omits it, and the screens render
// nothing rather than a placeholder.
export type SSOProvidersResponse = components['schemas']['SSOProvidersResponse']

// LoginResponse deliberately carries no refreshToken field (PROJECT.md
// B164). The refresh token now travels ONLY as a Secure(-when-applicable)/
// HttpOnly/SameSite=Lax cookie the hub sets alongside this body
// (internal/api/auth.go's setRefreshCookie) — no page script, including
// this one, can read it. AuthContext.tsx no longer persists a refresh token
// in localStorage; the browser's cookie jar carries it instead, and every
// request that needs it (POST /auth/refresh, /auth/logout) sends it
// automatically because those routes are same-origin.
export type LoginResponse = components['schemas']['LoginResponse']

// GET /api/v1/users/me (internal/api/auth.go's handleMe) — who the access
// token currently held actually authenticates as.
//
// Note what LoginResponse above does NOT contain: any identity at all. That is
// deliberate on the server (both sign-in paths return the same token-only
// shape), and it is why this type exists rather than the client inferring the
// account from the email typed into the password form — a federated sign-in
// never sees one, and a session restored from a refresh token on page load
// sees nothing either. PROJECT.md B165.
// How this account signs in. 'federated' accounts have no ARGUS password at
// all (the users_local_xor_federated constraint), so the change-password
// control is disabled for them with that reason named rather than left
// looking available and failing — see handleMe's Go comment. (`authMethod`)
export type MeResponse = components['schemas']['MeResponse']

export type ClusterState = components['schemas']['ClusterState']

// T16. The hub's single, server-owned verdict on whether this cluster's
// agent build is current, worth upgrading, or too old to accept in full —
// mirrors internal/agentversion.Verdict (internal/agentversion/policy.go).
// Never computed here: this string comes straight off the wire, and no
// component may re-derive it from agentVersion by comparing a version
// itself — that is exactly the "two policies drift" failure T16 exists to
// avoid. A fifth value added to the Go side without a matching arm here is a
// TS exhaustiveness error at COMPATIBILITY_VERDICT_LABEL's definition, not a
// silent gap.
export type AgentCompatibilityVerdict = components['schemas']['AgentCompatibilityVerdict']

// One capability or fact this agent's reported version is too old to have —
// mirrors internal/agentversion.Feature. wireContract states how an agent
// below minVersion presents on the wire (e.g. "omits the field"), which is
// what tells a reader an absence must never be read as a denial.
export type AgentCompatibilityFeatureGap = components['schemas']['AgentCompatibilityFeatureGap']

// A copyable `helm upgrade` for this cluster — guidance for a human to run,
// never a claim that ARGUS performed or will perform the upgrade. Mirrors
// internal/agentversion.UpgradeGuidance. releaseContextKnown is false for
// every cluster today (see that type's doc comment for why: nothing in the
// enrollment/heartbeat protocol reports a Helm release name or namespace),
// in which case `command` carries `<release-name>`/`<namespace>` placeholders
// and `note` explains why, rather than a guessed name that could target the
// wrong release.
export type AgentUpgradeGuidance = components['schemas']['AgentUpgradeGuidance']

// Mirrors internal/agentversion.Compatibility — the one verdict object both
// GET /api/v1/clusters and GET /api/v1/clusters/{id} attach to every
// cluster, from the identical server-side evaluation
// (internal/api/clusters.go's scanClusterSummary). missingFeatures and
// upgrade are only ever present for 'upgrade_recommended'/'upgrade_required'
// — an 'unknown' verdict carries neither, because naming a feature gap or
// handing out an upgrade command both require knowing the version.
export type AgentCompatibility = components['schemas']['AgentCompatibility']

export type Cluster = components['schemas']['Cluster']

export type ClustersResponse = components['schemas']['ClustersResponse']

// Mirrors internal/tunnel.NodeStatus (protocol.go). cpuAllocatable/
// memoryAllocatable are always present on a reachable cluster (they come
// straight from the Node object's own status.allocatable). cpuUsed/
// memoryUsed are only present when metrics-server is installed on the
// target cluster and reporting metrics.k8s.io data — absent (not zero) on
// any cluster that doesn't run one; render that as "not available," never
// as 0.
export type NodeStatus = components['schemas']['NodeStatus']

// Mirrors internal/tunnel.ClusterFacts's exposed subset (protocol.go) —
// the agent's best-effort inventory. kubernetesVersion is omitted (not
// omitempty-null) by the agent when unreachable, hence optional here;
// nodeCount/reachable/nodes are always present (nodes is [], not omitted,
// whenever the agent has nothing to report).
export type ClusterFacts = components['schemas']['ClusterFacts']

// Mirrors internal/tunnel.ClusterDetectors (protocol.go) — PROJECT.md T13:
// each of ARGUS's three built-in, shipped detectors' own reported run
// health. Absent entirely on an agent that predates this field — the same
// nil-means-unknown convention every other optional ClusterFacts field
// already uses (see ClusterRemediation's own comment). An agent that DOES
// report this always reports all three; there is no partial shape.
export type ClusterDetectors = components['schemas']['ClusterDetectors']

// Mirrors internal/tunnel.DetectorStatus. The zero value (no lastSuccessAt,
// no error, no deniedReads) is NOT a claim that this detector is failing —
// it means "this agent has not completed a run of it yet" (see that Go
// type's own doc comment). Never render the all-absent case as healthy or
// as failing; render it as unknown/not-yet-observed.
//
// error/errorAt are deliberately NOT cleared by a later success — compare
// errorAt against lastSuccessAt to tell whether the most recent attempt was
// the success or the failure, rather than assuming the newer field wins.
//
// deniedReads is named the way an operator would recognise the read
// ("events", "jobs"), not a raw GVR. Absent/empty means either "nothing is
// denied" or "this agent's discovered-watch-set check was not available
// yet" — indistinguishable on the wire, like ClusterRemediation.namespaces,
// and must be treated the same safe way: never read as a clean bill of
// health on its own.
//
// timedOutChecks is the ONE field on this type whose contract is "the last
// pass" rather than "ever": it names the sweep checkers that did not answer
// within their per-checker timeout during the most recent pass, and a clean
// pass CLEARS it — deliberately unlike error/errorAt, which are never
// cleared. That is what makes it answer "is a check hanging right now", so a
// consumer must not render it as sticky history. A timed-out pass still
// advances lastSuccessAt (the sweep loop ran; one read did not come back),
// and the agent writes the same fact into error behind the stable
// "sweep checker timeout: " prefix for a hub that predates the field — which
// is why the two timestamps land on the same instant in that case, and why
// classifyDetectorStatus (ClusterDetailPage.tsx) treats that tie as degraded
// rather than as a failure.
export type DetectorStatus = components['schemas']['DetectorStatus']

// What the cluster's own API SERVER says this agent may change, via
// SelfSubjectAccessReview — not a report of the remediate.enabled chart value,
// which can have drifted from the RBAC actually in force.
//
// checked=false means the question could not be asked. That is NOT the same as
// "not allowed", and the UI must not render it as a denial.
//
// canPatchDeployments/canPatchStatefulSets/canDeletePods above are the
// CLUSTER-SCOPED answer only — B170: the chart's own recommended,
// least-privilege install (remediate.namespaces, rather than
// remediate.allNamespaces) grants write access scoped to a Role in each
// selected namespace, and a namespace-scoped grant correctly answers false to
// a cluster-scoped question. These three fields alone therefore understate
// authority on exactly the recommended install shape. `namespaces` below is
// where that gets corrected — read it, not just these three, before telling an
// operator a cluster "cannot" remediate.
//
// `namespaces` — per-namespace breakdown behind the three fleet-wide fields
// above, one entry per namespace the agent found a namespace-scoped
// "argus-remediate" Role bound in, each independently asked with the
// identical three SelfSubjectAccessReviews. Absent or empty means "no
// per-namespace breakdown available" — either an agent that predates this
// field, or one that checked and found no namespace-scoped Role for its own
// identity. Those two cases are indistinguishable on the wire by design
// (internal/tunnel.ClusterRemediation's own comment) and MUST be treated
// identically here too: never read an absent/empty array as "this agent may
// change nothing anywhere" — the three fleet-wide fields above remain the
// fallback answer regardless.
//
// `namespacesTruncated` — true when more namespace-scoped Roles existed than
// the agent checked in one pass (internal/agent/facts.go's
// maxNamespaceRemediationChecks) — `namespaces` above is then a prefix, not
// the complete set. Any count or list derived from `namespaces` must state
// that window when this is true.
export type ClusterRemediation = components['schemas']['ClusterRemediation']

// One namespace's write authority, asked the same way ClusterRemediation's own
// three fleet-wide fields are — a real SelfSubjectAccessReview, namespace-scoped
// instead of cluster-scoped. Every entry here was actually checked: an entry
// present with every field false is a genuine, checked "no" for that namespace,
// not an unknown.
export type NamespaceRemediation = components['schemas']['NamespaceRemediation']

// The agent's RESOLVED detector timings, reported on every inventory sync.
// Every field is omitempty on the wire and absent from an agent predating the
// field, so all three are optional and zero must be read as "not reported"
// rather than as zero seconds.
export type ClusterDetection = components['schemas']['ClusterDetection']

// One agent's finding-queue occupancy as it reported it on its last
// heartbeat — counters about ARGUS's own plumbing, never object identity.
// The agent holds detected findings until the hub acks each one and discards
// the oldest once `capacity` distinct findings are pending, so a non-zero
// `dropped` means findings this cluster produced never reached the hub at
// all and never will.
//
// Two reading rules, both load-bearing and both the reason this is a
// separate nullable object rather than three numbers on ClusterDetail:
//
//   1. The WHOLE OBJECT is null when the agent does not report it (a build
//      older than the field, or a cluster that has not heartbeated since).
//      That is "we do not know", NOT "nothing has been dropped" — rendering
//      it as 0 would be exactly the fabricated zero this codebase's own
//      conventions ban. Render "Not reported".
//   2. `dropped` is a per-PROCESS running total, reset to 0 by an agent
//      restart. A decrease is a restart, not a recovery, and a freshly
//      restarted agent reports 0 regardless of how much it discarded
//      yesterday — so any surface showing the number states that window.
export type FindingQueueStatus = components['schemas']['FindingQueueStatus']

// GET /api/v1/clusters/{id}. Beyond the list row's fields it carries two
// null-bearing facts about how much ARGUS actually knows right now:
//
//   factsUpdatedAt — when the HUB last received `facts`, on the hub's clock.
//     Everything inside `facts` is an absolute-state snapshot carrying no
//     evidence of its own age, so this is the only thing separating "the
//     sweep detector succeeded two minutes ago" from that same sentence
//     recorded an hour ago and never revisited. Null exactly when `facts` is
//     null — a fabricated "0001-01-01" was deliberately not sent instead.
//   findingQueue — see FindingQueueStatus above; null means not reported.
export type ClusterDetail = components['schemas']['ClusterDetail']

export type IncidentSeverity = components['schemas']['IncidentSeverity']

// Mirrors internal/migrations/000005_incidents_and_analysis.up.sql's CHECK
// constraint and lld/08-remediation-contracts.md's incident state machine.
//
// 'ExecutionUnknown' — BACKLOG.md C8 / BUGS.md 104: a mutating execution
// whose own tunnel-call result was indeterminate (disconnect/timeout, not an
// explicit tool error) and a follow-up verify against the live cluster could
// not confidently resolve either way. Distinct from 'Failed' on purpose.
//
// 'ValidationUnknown' — the fix was applied, and ARGUS could not assert
// either that it held or that the original fault is gone. Distinct from
// Resolved, which is a positive claim.
//
// 'PlanRejected' — a human read the plan ARGUS proposed and refused it.
// Rejection used to land in 'Dismissed', which is terminal and means "needs
// no action from ARGUS", so refusing an unsafe fix silently dropped a live
// fault out of the queue. The incident is open, the fault is unchanged, and
// the refusal (with its reason) is on the plan — see
// RemediationPlan.approval. (POST /incidents/{id}/reject's incidentState is
// always this value, never "Dismissed" — an earlier build's comment here
// claimed otherwise; the Go source is the authority.)
//
// 'Expired' — PROJECT.md T2: a BULK or AUTOMATIC closure ("ARGUS would no
// longer raise an incident for any of these"), never a considered verdict on
// this one incident — as opposed to 'Dismissed', which after T2 means only
// "a named person looked at THIS incident and decided it did not need
// action." Closed (nobody's queue item), but a genuine recurrence can still
// reopen it.
export type IncidentState = components['schemas']['IncidentState']

// fleetGroupId — set by internal/fleetgroup.Recompute whenever this
// fingerprint is currently open on 2+ distinct clusters at once; absent
// otherwise (the API omits the field rather than sending null).
//
// workloadGroupId/workloadKey/openingReason — replica-level correlation
// (BACKLOG.md's A3, internal/replicagroup) — set only when this incident's
// Finding named a Pod whose owning workload was resolved, and
// workloadGroupId specifically only when 2+ currently-open incidents on
// this CLUSTER share (workloadKey, openingReason) at once. Same
// "absent, not null" convention as fleetGroupId.
//
// objectGroupId/relatedWorkloadKey — cross-object correlation
// (BACKLOG.md's A3b, internal/objectgroup): a Service's selector matched
// against the Pods it targets, or a PVC matched against the Pod(s) that
// mount it, resolved to a workload identity and joined against that SAME
// workload's own incident. Set only when 2+ currently-open incidents on
// this cluster share an anchor workload this way — same "absent, not null"
// convention, and the same read-only guarantee: this never merges
// incident state.
//
// objectGvk/objectNamespace/objectName — the object this incident is
// about, split out of incidents.object_key. Omitted entirely (not empty)
// when the opening finding named no object — the fingerprint-only
// correlation fallback.
//
// resolvedAt — the moment this incident actually closed (BACKLOG.md H4) —
// distinct from lastSeen (the last FINDING recurrence, not the close).
// Absent for every incident that has never closed.
//
// resolutionKind — BACKLOG.md T2: whether ARGUS's own remediation is
// linked to this incident's close — set only on the transition INTO
// Resolved. Absent for every incident that isn't Resolved, and for a
// Dismissed one too: a human's active rejection of a plan is a different
// fact, not a third value of this one.
//
// importanceExplanation — PROJECT.md T1: set only when this row was
// fetched with ?sort=importance. Absent (not empty) for every other sort,
// and for an incident where nothing about it stood out on any factor.
//
// route — the resolution channel internal/resolution.RouteFor chose from
// ownership facts BEFORE the model was asked anything (ADR-18). Absent —
// never a fallback value — for an incident that predates routing or has
// never been investigated, which is the majority. Render it through
// ROUTE_LABEL (pages/incidentLifecycle.ts); the raw wire value is never a
// user-facing string. The prose routeReason is IncidentDetail-only.
export type Incident = components['schemas']['Incident']

// ResolutionRoute is the closed set of internal/resolution.Route wire
// values, shared by Incident and IncidentDetail so a caller can key a label
// or a filter off it without re-typing the union.
export type ResolutionRoute = components['schemas']['ResolutionRoute']

// BACKLOG.md T2 (candidate 2): GET /api/v1/incidents/digest's response —
// the same incidents, grouped by fingerprint, so a pile of near-identical
// rows reads as "N incidents, M distinct problems" instead of a wall of
// rows. See internal/api/incident_digest.go's own header comment.
export type IncidentDigestGroup = components['schemas']['IncidentDigestGroup']

// truncated — present only when the (generous, 200-group) cap was actually
// hit — same "absent unless it matters" convention as
// IncidentsResponse.nextCursor.
export type IncidentDigestResponse = components['schemas']['IncidentDigestResponse']

// The six columns GET /api/v1/incidents can sort by server-side (BACKLOG
// P10) — internal/api/incidents.go's incidentSortSpecs, one to one.
// "failure" is the leading "Incident" column (IncidentsPage's
// incidentFailureLabel/incidentIdentity — reason · object name, with
// fallbacks); everything else is the column name it looks like.
export type IncidentSortKey = components['schemas']['IncidentSortKey']
export type IncidentSortDirection = components['schemas']['IncidentSortDirection']

// IncidentsPage's five quick-view tab numbers, computed server-side over
// EVERY incident matching the request's clusterId/state/fleetGroupId/
// workloadGroupId scope — never limited by the list's own page size, so
// (unlike `incidents.length`) these never silently shrink once a fleet has
// enough open incidents to fill a page. See internal/api/incidents.go's
// incidentCounts.
//
// requiresAction, not "open" — the two are different questions and this
// number answers the second one. "Open" meant "not Resolved and not
// Dismissed", which counts an incident ARGUS is mid-investigation on
// identically to one waiting on an approver, and gives a finished-but-live
// Diagnosed incident no explanation for why it never moves. This counts the
// states where nothing happens until a person acts. The tab it feeds is
// labelled "Needs action".
export type IncidentQuickViewCounts = components['schemas']['IncidentQuickViewCounts']

// GET /incidents/overview — see getIncidentOverview.
export type IncidentOverview = components['schemas']['IncidentOverview']
export type IncidentOverviewCluster = IncidentOverview['byCluster'][number]
export type IncidentOverviewDay = IncidentOverview['daily'][number]

// nextCursor — present only when a FULL page came back, meaning there is
// more (BACKLOG P9). A client may ignore it — the shape did not change, a
// field was added — but a client that ignores it is holding a truncated
// list and must not present its own array length as a total.
//
// counts — always present (BACKLOG P10) — see IncidentQuickViewCounts.
export type IncidentsResponse = components['schemas']['IncidentsResponse']

// One detector-reported occurrence backing an incident. reason/message are
// Kubernetes-event-derived text — untrusted (lld/11-ui-design.md §2, SR-17)
// — always render through plain JSX interpolation, never
// dangerouslySetInnerHTML.
export type Finding = components['schemas']['Finding']

// One reason's whole-history totals on an incident — the collapsed row in
// IncidentDetailPage's findings history.
//
// count/firstSeen/lastSeen are computed by the hub over EVERY finding stored
// for this reason (internal/api/incidents.go's incidentFindingsQuery), never
// over the bounded `findings` slice that arrives with them. That is the whole
// point of the field existing: `findings` carries only the newest few events
// per reason, so counting the array client-side would report "34 times" as
// "10 times" and quietly turn an accelerating symptom into a settled one.
//
// reason is '' for a legacy finding stored without one (the column is
// nullable). Render a stand-in label, never an empty row.
export type FindingReasonGroup = components['schemas']['FindingReasonGroup']

// --- PROJECT.md F31: the fleet-wide findings surface (GET /api/v1/findings) ---
//
// The contract half only. There is no findings screen yet, and these exist so
// that when one is built it consumes the same generated types the Go contract
// tests already hold the handlers to, rather than a fresh hand-transcription
// (which is exactly what B158 was).
//
// FindingListItem is a RICHER shape than Finding above, which describes a
// finding already known to belong to an incident and so carries no evidence
// dimensions and no disposition. The two are deliberately separate types
// rather than one optional-everything union: a component rendering an
// incident's own findings must not have to check whether `disposition` is
// present before it can trust what it is looking at.
export type FindingListItem = components['schemas']['FindingListItem']

// What ARGUS did with the observation: `correlated` (it is part of an
// incident — `incidentId` is present on exactly these), `retained_unpromoted`
// (the promotion boundary kept it as an observation, and
// `promotion.unmet` names which criteria it missed), or `suppressed` (it
// CLEARED the boundary and a toleration or storm protection stopped the
// incident anyway — which of the two is in the audit log, not on the row, so
// a UI must not claim one).
//
// Derived from the row against TODAY's boundary, never stored — so a
// finding's disposition legitimately changes when the boundary moves, and a
// screen must not cache it as a fact about the past.
export type FindingDisposition = components['schemas']['FindingDisposition']

// Why this finding is where it is. class/confidence/impact here are the
// EFFECTIVE tuple the boundary judged, which differs from the row's own
// stored values only when `evidenceCorrected` is set (a legacy generic
// mechanism carrying migration 000092's column defaults). Render BOTH where
// they differ: a row shown as fault/verified/degraded and labelled "not
// raised" reads as a bug rather than as the correction it is.
export type FindingPromotionVerdict = components['schemas']['FindingPromotionVerdict']

// The promotion boundary itself, carried in every response — derived from the
// live gate in internal/gateway/promotion.go rather than written out, so it
// cannot describe a rule the hub is not enforcing.
//
// `notRecorded` is not decoration and must be rendered: findings dropped
// before storage (a disabled detector, a disabled rule, a condition the
// polarity gate resolved as healthy) are in no table and appear at no filter
// setting. A screen that shows this list as "everything ARGUS saw" without it
// is overstating the product's own coverage.
export type FindingPromotionRule = components['schemas']['FindingPromotionRule']
export type FindingPromotionCriterion = components['schemas']['FindingPromotionCriterion']

// The disposition breakdown over the FULL scoped set — never the length of
// the returned page, and deliberately NOT narrowed by ?disposition= (so the
// tab an operator is on and the ones they are not both keep reading
// correctly). Same rule as IncidentQuickViewCounts: never present
// `findings.length` as a total.
export type FindingCounts = components['schemas']['FindingCounts']

// The resolved time bounds the rows AND the counts were both taken over.
// Always present, because ?since= defaults to seven days rather than meaning
// "everything" — a count is only honest displayed alongside its window.
export type FindingWindow = components['schemas']['FindingWindow']

export type FindingsResponse = components['schemas']['FindingsResponse']

// One tool invocation made by the investigation loop while working a step
// of the causal chain — get_events/get_logs/describe_resource/
// get_owner_chain per the fixed analysis contract this UI is built against.
// `args`/`result` are free-form JSON straight from the cluster (or the
// tool's error text) — untrusted, cluster-derived content exactly like
// Finding.reason/message above; render through plain JSX interpolation
// only, never dangerouslySetInnerHTML (lld/11-ui-design.md §2, SR-17).
// Exactly one of result/error is non-null for a given call.
//
// evidenceId (BACKLOG.md B2) is set for every call the api backend actually
// dispatched to a cluster — success or error — and omitted for one
// isOfferedTool refused before dispatch (nothing was asked, so there is no
// evidence row) and for any analysis stored before this field existed.
// When present it can be handed to getEvidence() for the lazy-fetch view
// lld/11-ui-design.md §4 specifies (redaction marker and capture time
// included); args/result/error above remain a correct fallback either way
// — internal/llm.ToolCallRecord's own doc comment confirms they are the
// SAME bytes the evidence row stores, not a lesser copy.
// corroborated (BACKLOG.md C10, upgraded from a bool by PROJECT.md B151) is
// meaningful ONLY when the enclosing Analysis's causalChainProvenance is
// 'self-reported' — the cli backend's model reports its own reasoning after
// the fact, and this citation was checked against the hub's own record of
// what it actually served for this investigation
// (internal/llm.crossCheckCausalChain). One of:
//   - 'corroborated': the call happened for real, AND this step's finding
//     stated a checkable value, AND it matched the real result.
//   - 'contradicted': the call happened for real, but a checkable value did
//     NOT match — the exact gap that let a live CreateResource execution
//     write factually wrong data past a step that used to read merely "true".
//   - 'unchecked': the call happened for real, but the finding stated no
//     checkable value, or no content exists to check one against. NEVER the
//     same as 'corroborated' — this is the honest default.
//   - 'unverified': the model cited a tool call ARGUS never actually served
//     at all.
// On a 'hub-observed' analysis every call is real by construction, so this
// field is always absent there and must be IGNORED — never rendered as any
// of the above for that provenance. Always check causalChainProvenance
// first. Exactly one of result/error is non-null for a given call.
export type ToolCall = components['schemas']['ToolCall']

// One row of GET /api/v1/incidents/{id}/timeline (BACKLOG.md B1,
// internal/api/timeline.go) — the incident's own chronology, which is
// exactly the thing `IncidentDetailPage`'s `WhatHappenedDisclosure` is the
// reserved slot for (BACKLOG.md D8: "the incident's history, which no
// stage produces"). The hub always returns these oldest-first; render in
// that order rather than re-sorting, and compute any gap-between-events
// duration client-side from adjacent occurredAt values — the server's only
// ordering obligation per lld/11-ui-design.md §4.
//
// summary is a short, human-readable sentence built server-side at write
// time (internal/timeline.Event.Summary's own doc comment) — render it
// through plain JSX interpolation only. Some summaries embed a Finding's
// own reason/message text verbatim (the IncidentOpened event), which is
// cluster-derived and therefore untrusted exactly like Finding.message
// itself; others embed a human-typed rejection reason. Never
// dangerouslySetInnerHTML, same rule as everywhere else on this page.
//
// detail is the full write-time payload (a duplicate of summary under its
// own key, plus whatever event-specific facts were cheap to attach) — NOT
// rendered as a raw JSON dump (that belongs on the audit log, not here), but
// as of BACKLOG.md D6's re-audit (2026-08-29) one field IS read back out:
// `planId`/`actionType`, so an approval/execution/pull-request event can be
// tied to WHICH of the incident's recommendations it concerns — see
// `planActionTypes` in IncidentDetailPage.tsx. Before that, an incident with
// more than one recommendation in its history (a rejected-then-reanalyzed
// plan, or a paired in-place+PR plan) rendered "Approved"/"Execution
// succeeded" with nothing tying the decision back to which plan, other than
// list order.
export type TimelineEvent = components['schemas']['TimelineEvent']

export type TimelineResponse = components['schemas']['TimelineResponse']

// GET /api/v1/incidents/{id}/evidence/{evId} (BACKLOG.md B2,
// internal/api/evidence.go) — one dispatched tool call's own args/result/
// error, fetched lazily via ToolCall.evidenceId rather than relying only on
// analysis.causalChain's inline copy. redacted is carried on the wire
// rather than assumed client-side: the agent-side redaction chokepoint
// (BUGS.md 84, G8) is what actually makes this content safe to show, and
// this field is the server's own record of that fact for this exact row —
// render it as a real statement, never implied silence (BACKLOG.md B2's own
// warning against implying the operator is seeing the raw object).
export type EvidenceDetail = components['schemas']['EvidenceDetail']

// One step of the investigation's causal chain: a hypothesis, the tool
// calls made to test it, and what was concluded. hypothesis/finding are
// model-generated prose over cluster-derived evidence — same untrusted-text
// rule as ToolCall above.
export type AnalysisStep = components['schemas']['AnalysisStep']

// A hypothesis the investigation considered and disproved — kept separate
// from causalChain because it's explicitly what *wasn't* the cause, not
// part of the reasoning that led to the conclusion.
export type RuledOutHypothesis = components['schemas']['RuledOutHypothesis']

// Mirrors every value internal/llm actually emits. 'malformed_final_answer'
// is a real third case, not a hypothetical one: internal/llm/cli_investigator
// .go records it when the CLI backend ran fine but its final answer didn't
// parse (deliberately kept distinct from 'time_limit' — a parse failure must
// not masquerade as a budget bound). It was missing here, which made
// partialReasonText's exhaustive switch fall through and return undefined, so
// the "why it's incomplete" sentence rendered as an empty paragraph.
// Mirrors every value internal/llm actually emits. 'malformed_final_answer'
// is a real third case, not a hypothetical one — internal/llm/
// cli_investigator.go records it when the CLI backend ran fine but its
// final answer didn't parse (kept distinct from 'time_limit' — a parse
// failure must not masquerade as a budget bound). Not its own named schema
// in docs/openapi.yaml (it's inlined as PartialAnalysis.partialReason's
// enum there), so this stays hand-written rather than aliased.
export type PartialReason = 'iteration_limit' | 'time_limit' | 'malformed_final_answer'

// Shared fields across both Analysis variants (id, rawFinalAnswer/
// parseError [set only when the concluding message could not be read —
// their presence IS the signal, there is no separate flag], model,
// causalChain, causalChainProvenance [absent on a row written before this
// field existed, treated the same as 'hub-observed'], ruledOut, iterations,
// createdAt, token/cost accounting [costUsd is honestly 0 when the hub has
// no per-model USD pricing table configured — costBasis distinguishes a
// measured figure from an unavailable one, never render 0 as "free"],
// triggeredBy, incidentState/stateReason [only meaningfully populated on a
// FRESH POST /analyze response; "" on GET's historical read-back, by
// design — see docs/openapi.yaml's CompleteAnalysis/PartialAnalysis
// description], plan, and pairedPlan [present only when the route resolved
// pullRequest+inPlace and both halves were proposed; never present without
// `plan`]) are now generated per-variant rather than composed via `extends`
// — kin-openapi's schema validator (internal/api/openapi_contract_test.go)
// works most reliably against two flat, self-contained schemas rather than
// an allOf composition for a two-member oneOf, so docs/openapi.yaml
// duplicates the shared fields into CompleteAnalysis and PartialAnalysis
// directly. The comments below stay attached to the union member they
// actually describe.

// The investigation loop reached a conclusion before hitting its bounds.
//
// rootCause/confidence are nullable even here, which reads odd next to
// "reached a conclusion" but is what the hub really sends — a legacy row's
// `root_cause`/`confidence` columns can both be empty. Narrow on `status` to
// know which *set* of fields is relevant, then still null-check
// rootCause/confidence themselves.
//
// rootCause.isFault (PROJECT.md T4 gap 3) is the model's own honest verdict
// on whether this incident is a real problem at all — omitted (not merely
// false) on every row from before this field existed, and whenever the
// model was never asked (treated identically to true). Explicit `false` is
// the one case a caller may act on distinctly.
//
// suggestedNextSteps is null for almost every "complete" analysis —
// populated only on the guidance route: no in-cluster action exists, so the
// model's own concrete manual steps are what the operator has to act on
// instead of a proposed plan.
export type CompleteAnalysis = components['schemas']['CompleteAnalysis']

// The investigation loop hit an iteration or time bound before reaching a
// conclusion. This is a normal, useful, fully-evidence-linked result — the
// causalChain/ruledOut are still populated with whatever real evidence was
// gathered before the bound hit — never render this as an error state;
// render it as "didn't reach a conclusion, here's what it found and what to
// check next."
export type PartialAnalysis = components['schemas']['PartialAnalysis']

// A bounded, evidence-gathering investigation loop's result — a real causal
// chain built from read-only tool calls against the live cluster. `status`
// discriminates which of rootCause/confidence vs.
// partialReason/suggestedNextSteps are populated — always narrow on it
// rather than optional-chaining every field.
export type Analysis = components['schemas']['Analysis']

// internal/remediation.ActionType's full closed set (internal/remediation/
// plan.go's own constants) — never a freeform string. `PatchField` cannot
// execute today (the agent tool exists but internal/api has no case for
// it, so approving one 500s). `OpenPR` stays in the union even though the
// model is no longer offered it fresh: historical plans still carry it.
// This union previously named only 5 of these 11 values (harmless at
// runtime, since the UI renders plan.summary rather than switching
// exhaustively on actionType, but it meant the type stopped describing
// reality) — widened back to the real Go set when
// TestOpenAPIContract_ApprovalsListMatchesSchema caught a real
// `DeleteResource` row failing validation against the narrower set; see
// PROJECT.md T12's report.
export type RemediationActionType = components['schemas']['RemediationActionType']

// internal/remediation.Outcome's closed set — what
// internal/remediation.Evaluate decided for this exact plan, recorded once
// at proposal time (see migration 000027's gate_outcome column comment),
// never recomputed against whatever autonomy policy happens to be in force
// when a caller reads it back.
export type GateOutcome = components['schemas']['GateOutcome']

// One proposed remediation plan — shared shape returned by
// POST /incidents/{id}/analyze (a freshly authored plan), GET /incidents/{id}
// (the plan tied to its current analysis, if any), and GET /approvals (the
// plan that put an incident into AwaitingApproval). `summary` is
// plain-language ("Scale payments/checkout-worker to 4 replicas") — render
// that, not `params`, in any UI; `params` is kept for anyone who wants the
// raw structured values, not for direct display (lld/11-ui-design.md §2:
// cluster/model-derived text always renders through plain JSX
// interpolation, never dangerouslySetInnerHTML — summary/params are no
// exception even though they're server-computed, not raw cluster text).
//
// riskLevel is the model's own DECLARED risk — persisted verbatim, never
// overwritten (internal/remediation/risk.go: rewriting it would destroy
// the calibration signal that a class of plans is under-classified).
// effectiveRiskLevel, not this field, is what the gate actually enforced
// — BACKLOG.md D11 #1 found the UI badging riskLevel alone, which can
// flatly contradict gateReason's own text ("risk=high and
// reversible=false") when the deterministic floor raised it.
//
// effectiveRiskLevel is internal/remediation.EffectiveRiskLevel's result
// for this plan — riskLevel raised to the deterministic floor for this
// action type and target, exactly as internal/remediation.Evaluate
// computed it at gate time. This is the value that decided whether the
// gate needed a human, so it is what any risk badge on this plan MUST
// show; render riskLevel only as a secondary "model declared X" note, and
// only when it differs from effectiveRiskLevel.
//
// approval/execution are both undefined until they actually happen. Only
// ever populated on GET /incidents/{id}'s embedded plan — GET /approvals
// never carries these, since a ScaleDeployment/RestartPod plan that
// successfully commits to executing moves the incident off
// AwaitingApproval (and so off that endpoint's own listing) before a
// decision could appear on it there.
export type RemediationPlan = components['schemas']['RemediationPlan']

// One differing field in a preflight diff, as internal/objdiff reports it.
// path is a dotted path, with list elements keyed by name where
// Kubernetes' merge key allows it — `spec.template.spec.containers[web]
// .image`, not `[0]`. added/removed distinguish a field appearing or
// disappearing from its value changing; defaulting shows up as `added`.
export type DiffChange = components['schemas']['DiffChange']

// requested — what this plan's own patch asked to change. additional —
// what the cluster would change as well (API-server defaulting, mutating
// admission webhooks); usually empty, and when it is not, it is the part
// of the diff the approver could not have predicted, so the UI leads with
// it. suppressed — server bookkeeping filtered out, named rather than
// counted so a reviewer can check the filter instead of trusting it.
export type PreflightDiff = components['schemas']['PreflightDiff']

// PreflightResponse is POST /incidents/{id}/preflight — the cluster's own
// answer to "what would this change do", obtained by a server-side dry run
// that persists nothing. `target` is the object the change actually lands
// on, which for a pod-template action is NOT the object the finding named.
// `diffUnavailable` is set instead of `diff` when the rehearsal succeeded
// but no comparison could be produced — must never be read as "nothing
// would change". `noChange` means the rehearsal was accepted but nothing
// would actually change — usually a stale plan whose fix is already
// applied. `blockedBy` is advisory here on purpose, so the diff is still
// shown for the GitOps-managed objects where it matters most.
export type PreflightResponse = components['schemas']['PreflightResponse']

export type PlanApprovalDecision = components['schemas']['PlanApprovalDecision']

// internal/api/remediation_exec.go's recordExecutionOutcome — the real
// outcome of actually executing a ScaleDeployment/RestartPod plan.
// 'unknown' (BACKLOG.md C8 / BUGS.md 104): the mutating tunnel call's own
// result was indeterminate (disconnect/timeout) and a follow-up verify
// against the live cluster could not confidently confirm the change either
// applied or didn't — never asserted as 'failed' from that ambiguity
// alone. `id` addresses the EXECUTION, not the plan: one recommendation
// can have two executions — the change and its reversal — and only the
// row knows which. `rollback` is what undoing this would do, in the words
// captured from the live object BEFORE the change was made; absent when
// the action type has no representable undo (a workload restart cannot be
// un-restarted) — absent because there is nothing to offer, not a
// permission problem. `rolledBackAt` is set once this execution has been
// undone, so the UI shows history rather than an Undo button that would 409.
export type PlanExecutionOutcome = components['schemas']['PlanExecutionOutcome']

// POST /executions/{id}/rollback — see internal/api/rollback.go. All four fields
// are acknowledgements, not options: each corresponds to one refusal the endpoint
// makes, and sending it says "I have read that refusal and want to proceed
// anyway". confirmValueChanged is separate from the two guardrail confirmations
// on purpose — it is not "I know this is a stop-gap", it is "I know I am about to
// overwrite a value somebody else set".
export type RollbackRequest = components['schemas']['RollbackRequest']

export type RollbackResponse = components['schemas']['RollbackResponse']

// What the investigation actually asked the cluster, as a compact per-incident
// aggregate (internal/api/evidence.go, migration 000037's mcp_tool_calls).
//
// This exists because the cli investigator backend contributes no causalChain
// at all — it does not own the tool-calling loop, so the hub never sees the
// intermediate turns and AnalysisCommon.causalChain is honestly empty for those
// runs. Without this the page showed a confident verdict with nothing behind
// it. The hub does resolve and now records every tool call the CLI made back
// through its MCP server, which is enough to say "13 tool calls: 5 events, 4
// describe resource, …" truthfully.
//
// Keyed to the INCIDENT, not to one analysis (see internal/api/incidents.go's
// comment on why it is a top-level field rather than part of `analysis`): an
// incident analysed twice reports both runs' calls together.
//
// failedCalls is a subset of totalCalls, not a separate bucket to add on — a
// call that failed was still a question asked, and a failure is often the
// informative part of an investigation.
//
// `byTool`'s keys are raw MCP tool names straight from the hub, deliberately
// not a closed union: the tool surface is defined in Go
// (llm.InvestigationToolSchemas) and grows there, so an unrecognised key must
// render, not break the page. Never render a key directly — see
// IncidentDetailPage's toolLabel.
export type EvidenceSummary = components['schemas']['EvidenceSummary']

// PROJECT.md T15: one already-observed fact about the object this incident is
// about, immediately preceding its first finding — internal/api/incidents.go's
// getRecentChanges, reading only analysis.causalChain (the api backend) and
// the stored mcp_tool_call_content ledger (the cli backend). Never the result
// of a fresh cluster query made for this page.
//
// `time` is when the underlying Kubernetes fact itself happened (a Warning
// event's own lastTimestamp, an object's own creationTimestamp) — never when
// the investigation asked about it. `category` is a closed, small vocabulary
// the hub assigns; render a label per category, never `reason`/`message`
// verbatim as the primary label (they exist for the detail/tooltip, and are
// only set for the four event-sourced categories).
//
// Deliberately does NOT include a "container image changed" or "replica
// count changed" fact built from the object's current spec — that would be a
// snapshot presented as a diff, with nothing to compare it against. What IS
// here for those two cases is the controller's OWN account of the change
// (Pulling/Pulled, ScalingReplicaSet), which states only what was actually
// observed to happen.
export type RecentChange = components['schemas']['RecentChange']

// The container GET /api/v1/incidents/{id} returns for `recentChanges`.
//
// Only ever non-null when SOME evidence existed for the hub to look
// through — see IncidentDetail.recentChanges' own doc comment for the
// null-vs-empty distinction this exists to carry. `windowHours` is the
// bound actually enforced server-side (internal/api/incidents.go's
// recentChangeWindow), echoed here so an empty list can say "looked at the
// {windowHours}h before the first finding and found nothing" instead of
// reading as unexamined.
export type RecentChangesView = components['schemas']['RecentChangesView']

// What manages the live object, and therefore whether a fix applied in place
// on the cluster survives — a Helm release rewrites its objects on the next
// `helm upgrade`, and Argo CD/Flux reconcile theirs back to Git within seconds.
//
// Derived by the hub (internal/api/incidents.go's deriveOwnership) from the
// tool calls the investigation actually made — a positive get_gitops_ownership
// answer, or Helm's own meta.helm.sh/release-name annotation on an object the
// investigation described. It is not a fresh cluster query, so it reports only
// what that investigation happened to look at.
//
// null means UNKNOWN, never "unmanaged": no analysis has run, the analysis came
// from the cli backend (which contributes no causalChain — same gap
// EvidenceSummary above exists to cover), ownership was never checked, or it
// was checked and came back "none". All of those must render as silence. A
// revert warning shown over an object nothing manages is worse than no warning
// at all — it is what trains an operator to skip past the true ones.
//
// The object is named in full because the investigation may have checked
// ownership on the owning Deployment while the findings are about its Pods.
// Render the object, so the claim stays true rather than merely plausible.
// sourceKind/sourceNamespace can be '' when the tool result carried neither.
export type ObjectOwnership = components['schemas']['ObjectOwnership']

// `revision` — the commit the controller reports as last synced. `pinned`
// says whether it is a real resolved SHA or only the branch/tag that was
// requested — an unpinned revision means nobody can say which commit is
// actually running.
export type OwnershipRepo = components['schemas']['OwnershipRepo']

// Whether this incident is (or was) staged into a fleet-correlated
// `BatchExecution` unattended rollout (BACKLOG.md R3, internal/orchestrator/
// batch.go) — a small "wave 1" executes first, and the rest of the batch
// (wave 2+) is held until wave 1's real ValidationSweeper outcome, not a
// timer, decides whether it is safe to proceed.
//
// null for the large majority of incidents, which have never shared a fleet
// group and an unattended action_type with anything else, so it takes the
// same "absent means nothing to say" treatment as `ownership` — never a
// placeholder for the common case.
//
// `held` is the field this exists to expose: false for every wave-1 member
// (wave 1 always runs — it is what produces the signal wave 2 waits on) and
// for a wave-2+ member once the batch has released; true for a wave-2+
// member while the batch is still `wave1_pending`, or indefinitely once it is
// `blocked`/`abandoned` (see internal/orchestrator/batch.go's Eligible/
// HoldReason, which this mirrors in prose — the API has no separate reason
// string field, so the UI derives the sentence from batchStatus/waveNumber
// itself rather than inventing a field the hub does not send).
export type UnattendedBatchInfo = components['schemas']['UnattendedBatchInfo']

// GET /api/v1/incidents/{id} — Incident plus everything the detail page
// needs.
//
// findings is a SLICE, newest first — the hub sends only the most recent
// few events per reason, because object-level correlation plus detector
// resends make this list grow with an incident's age without bound. Never
// present this as the complete history, and never derive a count or a
// time range from its length — findingGroups carries those, computed over
// everything stored.
//
// evidence: null means NOT RECORDED, never "no evidence was gathered" —
// every analysis that predates evidence tracking gathered real evidence
// the hub simply did not keep, so a "0 tool calls" rendering would be a
// lie about it.
//
// recentChanges: null and "non-null with an empty items array" are two
// DIFFERENT answers, matching evidence's own null-means-not-recorded
// convention — render null as "no evidence exists for this incident" and
// empty items as "we looked and found nothing relevant", using two
// distinct empty states.
//
// pullRequest: the durable record that a pull request exists for this
// incident. Null when none has been opened.
//
// reopenedBy: why this incident reopened, and crucially WHETHER IT WAS THE
// SAME OBJECT that was fixed. Null unless state is 'Reopened'.
//
// route/routeReason — BACKLOG.md D9's "the one that matters most" finding:
// a real, operator-legible sentence for why ARGUS chose pull request /
// in-place / guidance. Both null for an incident that predates routing, or
// has never been investigated.
//
// automationGate — PROJECT.md T14: the exact gate and reason an automatic
// analysis or execution was most recently skipped or blocked on, read back
// verbatim from the enforcing sweeper's own refusal. Null whenever no
// automatic path is currently gating this incident — never render a
// fallback reason in that case. Do NOT compute or infer a gate/reason in
// this file or any component — that is precisely the "two evaluations
// that agree today and drift silently later" bug this field exists to
// prevent. Always render automationGate.reason verbatim.
//
// priorIncidents — PROJECT.md T7: prior CLOSED incidents sharing this
// exact object, newest first, capped at 5. Always an array, never null.
//
// analysisStartedAt/analysisBackend/analysisModel/analysisError — PROJECT.md
// M1: POST /analyze answers 202 and investigates in the background, so the
// run's start and, if it failed, its reason are read from here. analysisError
// is about the LATEST run only; it is null again once a new one starts.
export type IncidentDetail = components['schemas']['IncidentDetail']

// AnalysisStarted is POST /incidents/{id}/analyze's 202 body (PROJECT.md M1):
// the run was claimed and is under way. Its outcome is read from
// GET /incidents/{id}, never from this response.
export type AnalysisStarted = components['schemas']['AnalysisStarted']

// IncidentAutomationGate is the closed set of gate identifiers
// internal/api/automation_gate.go defines (AutomationGate), mirrored here so
// a caller can key styling/grouping off `gate` without parsing `reason`'s
// prose. Keep this list in sync with that Go file's own const block — it is
// a display-only mirror, never a second place either one is decided.
export type IncidentAutomationGate = components['schemas']['IncidentAutomationGate']

// A pull request opened for an incident (GET /api/v1/incidents/{id}).
//
// fieldPath/expectedValue are the post-merge verification target, and they are
// absent for a real reason rather than by oversight: a repository change is a
// set of whole-file edits, so there is no single field the hub could re-read to
// confirm the change landed. Since 2026-08-28 EVERY route leaves them NULL
// (internal/api/repository_change.go's recordOpenedPullRequest, approvals.go's
// counterpart) — they survive only on pull requests opened by earlier builds,
// whose column internal/api/pr_verify.go still genuinely re-reads.
//
// So both branches are real and both must be rendered honestly: PRESENT means a
// post-merge check will actually run against that field, and ABSENT means no
// automatic check is possible here. Never render a check that cannot run, and
// never drop the statement that one will. `url` is absent, not fabricated, on
// a pull request opened before migration 000089 — a client renders the bare
// number when this is absent.
export type IncidentPullRequest = components['schemas']['IncidentPullRequest']

// What recurred to reopen an incident.
//
// `sameObject` is the field that matters, and it exists because of a real
// misreport: correlation runs at the WORKLOAD tier when a Pod's owner is known,
// so every Pod of a Deployment shares one incident. A fix can therefore be
// merged, hold perfectly, and the incident still reopen because a DIFFERENT Pod
// of the same workload started failing — at which point every layer told the
// operator their fix had failed. When this is false, it did not.
export type IncidentReopenCause = components['schemas']['IncidentReopenCause']

// PROJECT.md T7: "a recurrence reuses what was learned rather than starting
// from zero." The owner's decided mechanism is LINK, not reopen — this
// incident is a brand-new row (Resolved/Dismissed/Expired all stay
// terminal), and this array is computed at READ time by
// internal/api/incidents.go's priorIncidentLinksFor, via a join on
// incidents.object_key, rather than a stored edge on the new incident
// itself. Newest first, capped at 5; always an array, never null — empty
// when this incident names no object or nothing closed on it before.
// `rootCause` is absent when the prior incident was closed with no
// analysis. `rejectedPlan` is set when a human refused a proposed fix on
// THIS prior incident (internal/orchestrator/recurrence.go's
// demoteIfPreviouslyRejected acts on it: an identical action type on this
// same object can no longer auto-approve unattended on a LATER incident
// either — it always reaches a human again first).
export type PriorIncidentLink = components['schemas']['PriorIncidentLink']

export type RejectedPlanSummary = components['schemas']['RejectedPlanSummary']

// One GET /api/v1/approvals row — everything ApprovalsPage needs to render
// one worklist item without a second round trip per row.
// causalChain/ruledOut/causalChainProvenance (PROJECT.md D12) are the SAME
// per-analysis evidence IncidentDetailPage's "Why?" section renders —
// joined onto this row directly so an approver can see it without
// navigating away. Always present as an array (never undefined) even when
// the investigation made no tool calls at all; causalChainProvenance is
// omitted only for an analysis stored before this field existed. Always
// check causalChainProvenance before reading any ToolCall.corroborated
// value inside causalChain.
//
// alreadyApproved — true once someone has already approved this plan
// without the incident leaving AwaitingApproval — realistically an
// OpenPR-only case now: a ScaleDeployment/RestartPod plan that
// successfully commits to executing moves the incident to Executing
// immediately, which drops it out of this endpoint's own
// `state = AwaitingApproval` filter before a second render could ever
// observe alreadyApproved on it. This is what tells ApprovalsPage to
// render "already approved" instead of a live Approve/Reject pair.
//
// supersededByUrl — set when ARGUS has already proposed the durable fix at
// the object's source. Approving is refused with a 409, because the
// in-place plan was derived from the cluster's state BEFORE that fix. The
// row stays in the queue: "should I merge this pull request?" is a real
// decision, and hiding it would drop work off the only screen an operator
// watches. What changes is the action offered, not whether it is shown.
//
// `plan.approval`/`plan.execution` are always absent on this endpoint's
// rows (only populated on GET /incidents/{id}'s embedded plan).
export type ApprovalQueueItem = components['schemas']['ApprovalQueueItem']

// The three columns GET /api/v1/approvals can sort by server-side
// (PROJECT.md B167) — internal/api/approvals.go's approvalSortSpecs, one to
// one. Each key keeps its OWN default direction server-side when
// `direction` is omitted ("waiting" -> asc/oldest-first, the rest ->
// desc/highest-first) — the same "longest waiting first by default" this
// screen always showed, moved server-side rather than changed.
export type ApprovalSortKey = components['schemas']['ApprovalSortKey']
export type ApprovalSortDirection = components['schemas']['ApprovalSortDirection']

// GET /api/v1/approvals' own aggregate (internal/api/approvals.go's
// approvalCounts) — always present, always computed over the FULL matching
// clusterId/actionType[/riskLevel] scope, never just the bounded page this
// response's own `approvals` array carries. pending/approved narrow with
// riskLevel (they describe "how many rows match what I'm looking at right
// now"), high/medium/low deliberately don't (they describe the risk
// breakdown of the whole scope, which riskLevel itself is a slice of, not a
// further narrowing of).
export type ApprovalCounts = components['schemas']['ApprovalCounts']

// nextCursor — present only when a full page came back. ApprovalsPage
// never sends ?cursor= itself today (same as IncidentsPage): a generous
// bounded ?limit= plus real server-side filtering is what stops the
// over-fetch PROJECT.md B167 is about.
export type ApprovalsResponse = components['schemas']['ApprovalsResponse']

// POST /incidents/{id}/approve|reject's shared response shape.
//
// For **reject**: incidentState is `"PlanRejected"` — a distinct, still-open
// orchestrator state, NOT `"Dismissed"`. (This comment previously claimed
// "always Dismissed"; that was true of an earlier build and is no longer
// true of the Go source — refusing an unsafe fix is not the same fact as
// deciding the incident needs no action, so `internal/orchestrator` now
// transitions to PlanRejected instead. See docs/openapi.yaml's
// ApprovalDecisionResponse description, verified against
// internal/api/approvals.go, for the correction and the reasoning.)
//
// For **approve** (internal/api/remediation_exec.go):
//   - ScaleDeployment/RestartPod/PatchResourceLimits/RevertContainerImage:
//     the plan is signed and actually executed against the cluster within
//     this same request. incidentState is "Validating" (the cluster
//     accepted the patch — confirm the underlying symptom separately, this
//     does not mean "resolved") or "Failed"/"ExecutionUnknown" — never
//     "AwaitingApproval" on success.
//   - OpenPR: this ACTUALLY OPENS THE PULL REQUEST within this same
//     request (this comment previously said "execution-free... GitOps
//     execution isn't implemented"; that is no longer true either — see
//     approveByOpeningPullRequest). incidentState stays "AwaitingApproval".
// Always render `message`, never discard it as unused metadata — it's the
// only place the real per-action-type outcome is stated.
export type ApprovalDecisionResponse = components['schemas']['ApprovalDecisionResponse']

// IncidentTriageResponse is what POST /incidents/{id}/resolve|dismiss return.
// No planId: these close the INCIDENT, and most incidents never have a plan.
// `message` states what actually happened, including the important caveat that
// closing an incident is a statement about the past — if the fault is still
// present its detector will open a new one, because nothing here mutes
// detection.
export type IncidentTriageResponse = components['schemas']['IncidentTriageResponse']

// Toleration is a suppression rule (migration 000041): "stop opening new
// incidents for this object" — either every reason (allReasons true, the
// hub's `reasons` column is NULL) or a specific set. Created from an
// already-open incident via POST /incidents/{id}/tolerate, which also
// dismisses that incident; managed afterwards via GET/DELETE /tolerations.
//
// clusterDisplayName — empty if the cluster row is gone; a rule that
// outlived its cluster is still listed, because it is still a rule someone
// needs to see and remove.
//
// objectKey is the raw composite `gvk|namespace|name`. Prefer the three
// split fields for display: the composite's most identifying part, the
// object name, is at the END, so any width-limited column truncates away
// exactly the half a reader needs. objectNamespace is empty for a
// cluster-scoped object (Node, PersistentVolume) — normal, not missing data.
//
// note — why this was tolerated, in the operator's own words — required by
// the hub at creation time. The one field on the row whose entire job is
// explaining the decision, so render it as content, never as trailing
// metadata (BUGS.md item 37(b), which is exactly that regression).
//
// incidentId — absent for a rule created before that column existed, or
// whose incident has aged out of retention — a normal state, and
// distinguishable from "the incident is gone" by whether
// TolerationDetail.origin comes back null with this set.
//
// suppressedCount — what this rule has actually DONE: the findings it
// stopped from opening incidents. A zero count means the rule is silencing
// nothing and is a candidate for removal, which no other field could reveal.
export type Toleration = components['schemas']['Toleration']

// One reason a toleration has been suppressing — part of GET /tolerations/{id}.
// firstSeen/lastSeen span every suppressed finding in the group, not just
// the sampled one; sampleMessage is the most recent message for this reason.
export type SuppressedFindingGroup = components['schemas']['SuppressedFindingGroup']

// The incident a toleration was created FROM: what was detected, and — if an
// investigation ever ran — what ARGUS concluded and proposed doing about it.
//
// Deliberately the SAME Incident and Analysis shapes the incident screens use,
// not narrower copies, so a toleration's detail renders through the same
// components (components/IncidentBadges, AnalysisConclusion, RemediationPlanCard)
// instead of a second vocabulary for one set of facts — a toleration is an
// incident that has been accepted.
//
// analysis is null when the incident was never investigated, which is the
// common case: tolerating is what an operator does with a condition they
// already understand. Null means "never investigated", never "no cause".
//
// ownership — where the real fix lives, if a Helm release or a GitOps
// controller owned the object. Absent when nothing did. Read from the
// incident's stored ownership rather than asked of the cluster, because by
// the time anyone reviews a muted rule the object is very often gone.
export type TolerationOrigin = components['schemas']['TolerationOrigin']

// GET /tolerations/{id} — everything behind an expanded toleration row: the
// rule, where it came from, and what it has actually silenced. One request,
// because the panel needs all three at once and none of them is useful alone.
//
// origin is null in two situations the UI must tell apart, using
// toleration.incidentId: no originating incident is recorded at all (no id), or
// one is recorded but its row is no longer stored (id present, origin null).
export type TolerationDetail = components['schemas']['TolerationDetail']

// TolerateIncidentResponse is what POST /incidents/{id}/tolerate returns —
// the closed incident's new state plus the rule that was just created, so
// the UI can show both without a second round trip.
export type TolerateIncidentResponse = components['schemas']['TolerateIncidentResponse']

export type AcceptClusterResponse = ResponseBody<'acceptCluster', 200>

export type DecommissionClusterResponse = ResponseBody<'decommissionCluster', 200>

export type RenameClusterResponse = ResponseBody<'renameCluster', 200>

export type TtlClass = 'A' | 'B' | 'C'

export type CreateEnrollmentTokenRequest = components['schemas']['CreateEnrollmentTokenRequest']

export type CreateEnrollmentTokenResponse = components['schemas']['CreateEnrollmentTokenResponse']

export type FleetToken = components['schemas']['FleetToken']

// GET /api/v1/admin/settings's response shape. Secret values (the LLM API
// key, the notification webhook URL) are never returned — only whether one
// is currently set — so the UI can never show or pre-fill a real secret.
export type LlmProviderKind = 'api' | 'cli'

// One configured AI provider (migration 000034). Several can exist; exactly one
// is active at a time, and the active one is what every investigation uses.
// Secrets are never returned — only the ...Set booleans, matching LlmSettings.
// BACKLOG.md F19 mechanism 1: an operator's explicit statement of where a
// plain-Helm or kubectl-applied object's config lives inside a registered
// repository — the thing Argo CD's own Application CR gives ARGUS for free,
// with nothing equivalent for a bare `helm upgrade`. internal/scm/store.go's
// ObjectMapping is the authority on this shape; mirrored here field-for-field.
//
// Exactly one of two forms, never both, never neither (enforced server-side
// by ObjectMapping.Validate()):
//   - releaseName + namespace: matches a Helm release by its Helm-set
//     `meta.helm.sh/release-name`/`release-namespace` annotations.
//   - labelSelector: a subset-match against the object's own labels — the
//     only form that can match an object with no Helm release identity at
//     all (a plain `kubectl apply`).
// path is required in both forms: where in the repository this object's
// config lives.
export type ObjectMapping = components['schemas']['ObjectMapping']

// BACKLOG.md F30's discover/confirm/decline trio — the render-proven
// replacement for typing a release/namespace/path blind. One (repository,
// chart path, values file) combination a real render either proved or is
// still ambiguous about; valuesFile is '' when the chart's own defaults
// alone already produced the live object. Mirrors internal/api/
// objectmapping_discovery.go's LinkCandidate field-for-field.
export type LinkCandidate = components['schemas']['LinkCandidate']

// Another cluster ARGUS has independently recorded an incident against this
// exact release/namespace on — NOT a live fleet-wide inventory scan. A
// cluster running the release with no incident ever opened on it is
// genuinely unknown to this list; never present it as exhaustive.
export type OtherClusterRunningRelease = components['schemas']['OtherClusterRunningRelease']

// Exactly one of: 'proven' (one render-proven candidate — the one-click
// case), 'ambiguous' (two or more genuinely render the same live object —
// present every one, pick none), 'none' (every render that ran completed
// cleanly and produced nothing — a real negative, e.g. a third-party chart
// ARGUS has no repository for), 'degraded' (rendering could not be
// attempted or run to completion at all — NEVER the same claim as 'none'),
// 'declined' (an operator already said no for this exact cluster/release/
// namespace — F30 decision 4's "never ask twice").
export type LinkDiscoveryStatus = 'proven' | 'ambiguous' | 'none' | 'degraded' | 'declined'

// POST /incidents/{id}/discover-repository-link's response. Mirrors
// internal/api/objectmapping_link_endpoints.go's discoverRepositoryLinkResponse.
//
// `mode` says which of F30's two identity shapes this discovery ran
// against. 'helm': releaseName/namespace are set, the confirmed mapping is
// release-keyed, and a widen-to-other-clusters offer may be present.
// 'manifest': a plain-manifest object — no Helm release, no GitOps
// controller — releaseName/namespace are empty, and the confirmed mapping
// is a LabelSelector built from the object's own reported labels, never
// typed by an operator. Lets the frontend render the right copy without
// depending on ObjectOwnership, which is deliberately null for an
// unmanaged object (see that type's own doc comment).
//
// Optional (rather than always-present) purely so this stays an ADDITIVE
// change to an existing response shape: every caller/fixture written
// before F30's manifest mode existed sent none of these four fields, and
// treating that as "mode: helm" (DiscoveryResult's own fallback) is the
// correct reading of it, not a gap to plug.
// `objectGvk` — The live object this discovery is actually about — set whenever `mode`
// is, in both modes.
export type DiscoverRepositoryLinkResponse = components['schemas']['DiscoverRepositoryLinkResponse']

// POST /incidents/{id}/confirm-repository-link's body. releaseName/
// namespace are never sent — the hub re-reads them from the incident's own
// stored ownership (a client naming its own release/namespace could
// register a mapping this incident's own evidence never proved). scope
// omitted defaults server-side to {type: 'Cluster', clusterId: <this
// incident's own cluster>} — F30's "propose Scope: Cluster, narrow is
// safe." GrantScope (below) mirrors internal/authz.Scope exactly, so it is
// reused here rather than a second scoping type.
export type ConfirmRepositoryLinkRequest = components['schemas']['ConfirmRepositoryLinkRequest']

// A registered Git repository ARGUS may open a pull request against, and the
// credential it uses. REMEDIATION_ROADMAP.md D-R9 settles the credential model:
// one fine-grained token per provider, org-level rather than per-user,
// envelope-encrypted at rest, scoped to named repositories — never "everything
// this account can reach".
// A registered Git repository ARGUS may open a pull request against, and
// the credential it uses. The token is never returned in any form — only
// whether one is stored (`credentialStored`). `apiBaseUrl` empty means the
// provider's public API; non-empty is a self-hosted GitHub Enterprise
// Server or GitLab CE/EE. `expiresInDays` is computed server-side so every
// consumer agrees on when to warn — NEGATIVE means already expired, which
// reads differently from "expires soon" and the UI must show it
// differently. `objectMappings` is never omitted, even when empty — an
// absent key and an empty list are different facts for a form deciding
// whether to render "no mappings configured yet" or a client bug.
export type RepositoryBinding = components['schemas']['RepositoryBinding']

export type RepositoriesResponse = components['schemas']['RepositoriesResponse']

// token is write-only and never comes back. `expiresAt` is optional, and
// its absence is not an error — but supplying it is what lets ARGUS warn
// before the token dies rather than reporting the resulting PR failures
// after. Omitting `objectMappings` (or sending an empty list) registers
// the repository with no mappings.
export type CreateRepositoryBindingRequest = components['schemas']['CreateRepositoryBindingRequest']

// PUT /repositories/{id}'s body. A genuine partial update, unlike create's
// implicit full overwrite via re-registering the same URL: every field here
// is independently optional, and OMITTING one leaves it exactly as stored.
// `provider` is deliberately not editable — changing it changes what the
// stored token can even authenticate as, big enough to ask for through
// delete-and-re-register. `token`: omit to leave the stored credential
// untouched; a non-empty value rotates it — unlike create's token, there is
// no "required" case here. `expiresAt`: omit to leave the stored expiry
// untouched, `""` clears it, anything else must be an RFC 3339 timestamp.
// `objectMappings`: omit to leave the stored mappings untouched; a non-nil
// list — including an empty one — REPLACES it (there is no per-mapping
// add/remove, so clearing every mapping means sending `[]` deliberately).
export type UpdateRepositoryBindingRequest = components['schemas']['UpdateRepositoryBindingRequest']

// What POST /repositories/{id}/check returns on success. A failure comes back as
// an ApiError carrying the provider's own reason, which distinguishes an expired
// token from an under-scoped one from a rate limit — each has a different fix.
export type RepositoryCheckResult = components['schemas']['RepositoryCheckResult']

export type AIProvider = components['schemas']['AIProvider']

// The success body of POST /admin/ai-providers/{id}/test. A FAILURE arrives as
// an RFC 9457 problem (422, type .../ai-provider-unusable) and therefore as an
// ApiError, so this shape only ever describes a pass — the same split
// RepositoryCheckResult already uses.
//
// `kind` — The machine-readable classification (internal/llm's Probe* constants).
// Present so a future caller can branch structurally; nothing does today,
// deliberately — see AIProvidersCard.
// `summary` is the headline, `detail` the actionable part. Two fields rather
// than one because the hub's failure path returns exactly the same pair as
// an RFC 9457 title/detail, so the UI can render a pass and a failure
// identically.
// `caveat` — What the test did NOT prove. Always present on a pass, and always worth
// showing: a green tick read as "analysis will work" is the one genuinely
// misleading outcome this feature could have.
// `model` — The model the PROVIDER named in its response — not the configured one.
// They can differ, and that difference is a real misconfiguration.
export type AIProviderTestResult = components['schemas']['AIProviderTestResult']

// `activeProviderId` — Empty when no provider is active — a real state (fresh install, or the
// active one was deleted), not an error.
export type AIProvidersResponse = components['schemas']['AIProvidersResponse']

// Create/update body. apiKey/runnerToken follow the same absent-means-unchanged
// contract as UpdateLlmSettingsRequest.apiKey.
export type AIProviderRequest = components['schemas']['AIProviderRequest']
export type CliAgent = 'claude' | 'codex'

// `providerKind` is always concrete — the backend normalizes the
// never-configured case to 'api', so this is never ''.
// `cliAgent` — Superseded by the per-provider AIProvider.agent / runnerTokenSet once
// provider configuration became multi-provider (AIProvidersCard). Kept only
// because GET /admin/settings still returns them; nothing reads them.
// `cliBackendAvailable` — Whether this HUB can serve a `cli` provider at all — the CLI backend needs
// an MCP listener, which is off unless ARGUS_MCP_ADDR is set. A hub-level
// fact the client cannot infer, so the hub reports it: a `cli` provider can
// be configured perfectly and still be unusable.
export type LlmSettings = components['schemas']['LLMSettings']

// The sign-in screen's style. `styles` is the hub's own list of valid values,
// shipped with the current one so the selector cannot offer a style this hub
// cannot store, or miss one it can.
export type AppearanceSettings = components['schemas']['AppearanceSettings']

export type NotifySettings = components['schemas']['NotifySettings']

// --- Notification routing (PROJECT.md F32, internal/api/notification_routing.go) ---
//
// Two routes, GET and a whole-set PUT, both behind `org:settings:write` — the
// same capability as /admin/settings, because the single webhook URL these
// rules generalise is already behind it.
//
// # Why there is no per-row CRUD here to model
//
// A routing table is ordered and its rows are only meaningful relative to each
// other: "critical anywhere pages the on-call, everything else goes to the team
// channel" is one statement about three rules, not three independent facts. A
// per-row surface has intermediate states in which notifications are genuinely
// mis-routed — the general rule deleted, the specific one not yet created — and
// nothing a client can do avoids them. One PUT is one transaction.

// One configured destination. There is no `url` field and there never will be:
// a Slack incoming-webhook URL embeds a bearer-equivalent token in its path, so
// the hub reports only whether one is set. That is what makes this response
// safe to render, log and screenshot — and it is why the PUT's `url` is
// nullable (below), since a client that read this back has no URL to send.
export type NotificationDestination = components['schemas']['NotificationDestination']

// One rule. The three matchers are nullable rather than empty strings so
// "matches any severity" is visibly different from "matches the empty
// severity". `minSeverity` is a FLOOR, not an equality test — a rule set to
// `high` matches high and critical (internal/notify's Match compares ranks).
//
// `clusterGroupName` is resolved server-side for display only and is not part
// of the match; the match is on `clusterGroupId`.
export type NotificationRule = components['schemas']['NotificationRule']

// The synthetic catch-all. It is NOT a row in `rules` and is not editable
// here: it is whatever the settings tree resolves the webhook URL to, and
// `source` names the screen to change it on. It is reported at all because
// every notification matches something — there is no "matched nothing, dropped"
// path — so a default with no URL silently delivers everything no rule claimed
// to nowhere, which is a state worth showing rather than finding in a log.
export type NotificationDefaultRule = components['schemas']['NotificationDefaultRule']

// `transitions` and `severities` are the closed sets a rule may name, served
// with the configuration so a client's selects are built from what THIS build
// accepts rather than from a list copied into a frontend that then drifts. Both
// are nullable on the wire (Go marshals a nil slice as null), so read them
// defensively rather than mapping straight over them.
export type NotificationRoutingResponse = components['schemas']['NotificationRoutingResponse']

// The whole table. Anything omitted is REMOVED — this is a replacement, not a
// merge.
//
// Two field-level contracts a caller has to get right, both of which fail
// silently rather than loudly if it does not:
//
//   - A destination's `url` absent or null KEEPS the URL already stored under
//     that name. Sending a URL replaces it; sending `""` is refused outright
//     (notify.validateWebhookURL). A destination the hub has never seen is new
//     and MUST carry one. Destinations are keyed by NAME, so a changed name is
//     a new destination plus a deletion — not a rename.
//   - A rule's `enabled` absent means ENABLED. A rule an operator said nothing
//     about should be in force; the other default would silently disable every
//     rule written by a client that has not learned the field yet.
export type UpdateNotificationRoutingRequest = components['schemas']['UpdateNotificationRoutingRequest']

// The investigation loop's bounds (internal/llm/toolloop.go's Investigate) —
// a separate top-level section from `llm`, since it configures the loop's
// turn/time budget rather than the provider connection itself. Unlike
// LlmSettings' apiKeySet, there's no secret here to hide: maxIterations/
// timeLimitSeconds are the literal configured value, null meaning "not
// overridden in the DB, falling back to the env var or the hardcoded
// default" rather than "unset and broken." effectiveMaxIterations/
// effectiveTimeLimitSeconds are always a concrete number — whatever is
// actually in force for the very next analysis — so the UI can show that
// as a placeholder/hint even while the raw field is null.
//
// `retrievalEnabled` — Whether internal/knowledge.Store.RetrieveSimilar augments an
// investigation's prompt with prior similar analyses (migration 000102).
// Defaults to false: a live measurement found 31% higher cost with no
// measurable confidence benefit on one real repeated fault — an
// inconclusive result, not yet a validated feature. No UI control for
// this exists yet; toggle via `PUT /api/v1/admin/settings`.
export type AnalysisSettings = components['schemas']['AnalysisSettings']

// The "automatic investigation" toggle (internal/autoanalyze): whether a
// newly-detected incident with no analysis yet gets POST
// /api/v1/incidents/{id}/analyze run against it automatically instead of
// waiting for someone to click "Analyze," and (once enabled) which
// severities qualify. A top-level sibling of llm/notify/analysis, not nested
// under any of them — a genuinely distinct concern (whether an incident
// gets analyzed at all without a human, not how the provider connects or
// how long one analysis loop is allowed to run).
//
// autoAnalysisSeverities replaces a superseded single "minimum severity"
// threshold with a genuine checklist: any subset of the four severities is
// valid, including a non-contiguous one (e.g. `["high", "critical"]` with
// `medium` deliberately excluded) that no single ordered threshold could
// ever express — the direct reason this field is a set, not a floor. It is
// always a plain array on the wire, never null (the hub normalizes a nil
// value to `[]` — see internal/api/settings.go's automationSettingsView doc
// comment): an empty array means nothing is currently selected, which — per
// internal/settings.Config's AutoAnalysisSeverities doc comment — means
// nothing gets auto-analyzed while autoAnalysisEnabled is true, NOT "every
// severity qualifies." An admin who wants every severity investigated
// automatically must check all four boxes explicitly.
export type AutomationSettings = components['schemas']['AutomationSettings']

// How long to keep audit_events / incidents / findings before
// internal/partition's daily maintenance job drops that table's oldest
// partitions entirely (migration 000021_retention_settings.up.sql has the
// full rationale) — a top-level sibling of llm/notify/analysis/automation,
// not nested under any of them: retention is a data-lifecycle policy,
// unrelated to the AI provider, the investigation loop's bounds, or whether
// investigation happens automatically.
//
// Each field is the literal org_settings column value, echoed straight
// back — none is a secret. null means "keep forever," and — unlike
// AnalysisSettings' maxIterations/timeLimitSeconds — that is also the
// shipped default, not a fallback to some other configured tier: there is
// no "effective" pair to compute here, because there is no third tier to
// resolve against. A number is a real, explicit, operator-chosen retention
// window in days.
export type RetentionSettings = components['schemas']['RetentionSettings']

// The detection layer's first real, hub-side, live-editable configuration
// (internal/settings.Config's doc comment and migration
// 000026_detection_settings have the full rationale) — a top-level sibling
// of llm/notify/analysis/automation/retention, not nested under any of
// them: it configures which detectors' findings the hub accepts at all, and
// how many brand-new incidents a single cluster may produce in a rolling
// window, none of which is about the AI provider, the investigation loop,
// automatic investigation, or data retention.
//
// disabledDetectorIds is a hub-side filter, NOT a signal that reaches the
// agent: the agent itself keeps running a "disabled" detector and keeps
// sending its findings exactly as before — internal/gateway/finding.go's
// handleFinding just drops them before they're ever recorded. Always a
// plain array on the wire, never null (same normalization as
// AutomationSettings.autoAnalysisSeverities) — an empty array means every
// detector's findings are currently accepted.
//
// stormProtectionMaxNewIncidents/stormProtectionWindowSeconds cap how many
// brand-new (never-seen-fingerprint) incidents a single cluster may produce
// within the trailing window before handleFinding stops creating further
// new incidents from that cluster for the remainder of the window (an
// already-open incident sharing a suppressed finding's fingerprint still
// updates normally — only *new*-incident creation is throttled). null means
// "no ceiling" — the shipped default, matching RetentionSettings' null-
// means-off convention, not AnalysisSettings' null-means-consult-a-further-
// fallback-tier convention. The two fields are always both null or both a
// positive number — the hub rejects one set without the other.
//
// disabledRuleIds is BUGS.md 111's fix: every rule-format finding from
// internal/agent/rules/default-rules.yaml (33 rules, as of this writing)
// shares ONE DetectorID ("k8s-sweep") with the other 32 rules and every
// hand-written Go check in that detector, so disabledDetectorIds alone could
// only silence all of them at once, never one rule on its own. This is the
// narrower control: a rule's own id (internal/tunnel.Finding.RuleID), same
// hub-side-filter-only shape and same non-null-on-the-wire convention as
// disabledDetectorIds above — checked ALONGSIDE it, never instead of it.
export type DetectionSettings = components['schemas']['DetectionSettings']

// The DB-backed override for internal/orchestrator.DefaultAutonomyPolicy —
// closing the gap WORKLOG.md §50 flagged explicitly ("no DB-backed config
// exists yet"). A top-level sibling of llm/notify/analysis/automation/
// retention/detection, not nested under any of them: this configures
// internal/remediation.Evaluate's autonomy CEILING for
// internal/orchestrator.Advance's gate, unrelated to the AI provider, the
// investigation loop's bounds, whether investigation happens automatically,
// data retention, or the detection layer.
//
// autoApproveMaxRisk/minConfidenceForAutoApprove are the literal
// org_settings column values, echoed straight back — neither is a secret.
// null means "not configured in the DB" — unlike DetectionSettings' null-
// means-off convention, this null does NOT mean "never auto-approve"; it
// means "fall back to internal/orchestrator.DefaultAutonomyPolicy's own
// conservative value," mirroring AnalysisSettings' maxIterations/
// timeLimitSeconds null-means-consult-a-further-tier convention.
// effectiveAutoApproveMaxRisk/effectiveMinConfidenceForAutoApprove are
// always a concrete value — whatever the hub would actually apply to the
// very next investigation — the same "show what the fallback currently
// resolves to" pattern AnalysisSettings' effective* pair already
// established.
//
// requireReversibleForAutoApprove is now (BUGS.md 97, migration 000085)
// nullable too, following autoApproveMaxRisk/minConfidenceForAutoApprove's
// exact contract: null means "not configured in the DB", and
// effectiveRequireReversibleForAutoApprove is the concrete value the hub
// would actually apply (true, DefaultAutonomyPolicy's own value, when
// null). It used to be a plain boolean with no effective field, on the
// theory that the column was NOT NULL DEFAULT true — but that meant a PUT
// whose "autonomy" section omitted this key decoded server-side to false,
// the permissive direction, and silently weakened this safety gate.
//
// unattendedExecutionEnabled is the switch that makes the three fields above
// mean something against a real cluster. While it is false — the shipped
// default — an AutoApprove verdict is recorded and the plan still waits for a
// human, which is what this whole section did unconditionally before the
// switch existed. While it is true, a plan the gate auto-approves executes
// with nobody watching.
//
// The three max*/window fields are the blast-radius cap DESIGN.md §10.5
// requires in the same release as unattended mode, and they exist because no
// per-incident risk assessment can see the failure they prevent: one bad image
// tag across thirty clusters is thirty individually low-risk, individually
// auto-approvable incidents. They follow AnalysisSettings' null-means-consult-
// a-further-tier convention, NOT DetectionSettings' null-means-off — a blank
// cap falls back to a deliberately small default (3 per cluster, 10 fleet-wide,
// per hour), never to "unlimited". The effective* trio is what would actually
// apply right now, so a blank field can still show its real value.
//
// Neither the switch nor the caps can weaken internal/remediation.Evaluate's
// hard, non-configurable high-risk+irreversible safety floor (WORKLOG.md §31) —
// that check runs unconditionally, before any field here is consulted.
//
// `unattendedNamespaces` — The namespace allowlist unattended execution may act in — always an
// array (never null; an empty one is the server's own deny-everything
// default, migration 000055). Was served by GET /admin/settings all
// along but missing here (BACKLOG.md H4's "also found" note) — OverviewPage
// used to read it through a local structural type instead of this shared
// declaration.
export type AutonomySettings = components['schemas']['AutonomySettings']

// The operator-configured LLM pricing table and the hard daily spend
// ceiling (DESIGN.md §16.4) — a top-level sibling of
// llm/notify/analysis/automation/retention/detection/autonomy, not nested
// under "llm": it's a genuinely distinct concern (turning already-real
// token counts into a real dollar figure, and capping how much of that a
// day may accumulate). Closes the gap WORKLOG.md §28/§49 both documented
// rather than papered over — analyses.cost_usd has always been a real,
// honest 0 because no per-model USD pricing table existed anywhere in this
// codebase.
//
// pricePerMillionInputTokens/pricePerMillionCachedTokens/
// pricePerMillionOutputTokens are the literal org_settings column values,
// echoed straight back — none is a secret. All three are null (the shipped
// default) until an operator sets them; the hub treats "not all three set"
// as "no pricing table configured" and computes a real, honest cost_usd of
// exactly 0 — never a guessed, hardcoded per-model rate. pricingConfigured
// mirrors that exact same all-three-set check server-side, so this UI never
// has to re-derive it from three raw nullable numbers itself.
//
// dailySpendCeilingUsd is null by default too ("no ceiling," today's actual
// unbounded behavior, unchanged until an operator sets one). todaySpendUsd
// is NOT an org_settings column — it's the real, current answer to "how
// much have we actually spent today," the same number the hub's own
// ceiling check compares against. It is the sum of MEASURED spend only, so
// it must never be rendered as a complete figure when spendCountable is
// false.
//
// spendCountable is false under a CLI/subscription provider, where a
// per-investigation cost genuinely does not exist and the notional figure
// the CLI reports is excluded from todaySpendUsd on purpose.
// ceilingEnforceable is "a ceiling is set AND pricing is configured AND
// spend is countable" — the honest answer to "can this guardrail fire",
// which pricingConfigured alone was being read as and is not. Both are
// computed server-side for pricingConfigured's own stated reason: a claim
// about whether a safety control works is not something this UI should
// re-derive from raw fields.
//
// `ceilingBreached` — The hub's own SpendCeilingBreached answer. Never re-derive this from
// todaySpendUsd >= dailySpendCeilingUsd: that comparison is true in states
// where the hub's check is not running at all, and rendering it would
// claim a guardrail fired when nothing was blocked.
export type CostSettings = components['schemas']['CostSettings']

// The operator's named exceptions to the hub's default-deny on private
// outbound destinations (internal/outbound, migration 000115). Applies to the
// two clients whose destination is an operator fact rather than a code fact:
// an AI provider's base URL and a Git provider's API URL.
//
// Nothing here is a secret — a destination and its written justification are
// echoed back in full, unlike LlmSettings' apiKeySet, because an exception
// nobody can read back is one nobody can review.
//
// `destination` — An IP literal, a CIDR range, or a bare hostname. A hostname is resolved
// by the hub at dial time and permits whatever it resolves to then, so its
// trust follows DNS; an IP or CIDR cannot be moved that way.
// `reason` — Required and never empty — the hub refuses an entry without one.
export type OutboundPrivateDestination = components['schemas']['OutboundPrivateDestination']

// `privateDestinations` — Never null on the wire: an empty list is returned as [], so "no
// exceptions" is never indistinguishable from a missing field.
export type OutboundSettings = components['schemas']['OutboundSettings']

export type Settings = components['schemas']['SettingsResponse']

// GET /api/v1/spend/today's response shape — a narrower, real-time report
// of today's spend and ceiling status, gated on spend:read alone (not
// org:settings:write) so a resolver can see it without needing full
// admin-settings access. See CostSettings' doc comment above for what each
// field means; this shape mirrors it but is NOT the same request/response
// pair — this one never configures anything, it only reports.
// ceilingBreached can be true while ceilingEnforceable is false (a
// deployment that switched from an api provider to a cli one mid-day still
// has countable rows from earlier in the same UTC day), so anything showing
// both must let "breached" win — that one actually stopped automatic
// investigation.
export type SpendToday = components['schemas']['SpendTodayResponse']

// PUT /api/v1/admin/settings's request shape. apiKey/webhookUrl are
// deliberately optional: omitting the field entirely means "leave
// unchanged," while sending it as "" means "explicitly clear it" — a real,
// if rare, distinct action. Never default a missing value to "" when
// building this object; that would silently turn "leave unchanged" into
// "clear."
// `cliRunnerToken` follows `apiKey`'s absent-means-leave-unchanged contract,
// being the other secret in this section; the non-secret fields overwrite
// whatever is stored.
export type UpdateLlmSettingsRequest = NonNullable<UpdateSettingsRequest['llm']>

export type UpdateNotifySettingsRequest = NonNullable<UpdateSettingsRequest['notify']>

// The "analysis" section of a PUT request. Unlike apiKey/webhookUrl above,
// maxIterations/timeLimitSeconds are plain, always-submitted number fields —
// not secrets, so there's no omit-vs-clear distinction to make. A number
// sets an explicit override for the very next analysis; null explicitly
// clears it back to the env-var/hardcoded-default fallback.
export type UpdateAnalysisSettingsRequest = NonNullable<UpdateSettingsRequest['analysis']>

// The "automation" section of a PUT request. Like UpdateAnalysisSettingsRequest,
// both fields are plain and always-submitted — neither is a secret, so
// there's no omit-vs-clear distinction to make. autoAnalysisSeverities is
// sent exactly as checked, including `[]` when every box is unchecked — a
// real, valid selection in its own right ("nothing gets auto-analyzed," per
// AutomationSettings' doc comment above), not a "leave unchanged"/clear-to-
// fallback sentinel the way apiKey/webhookUrl's omission is.
export type UpdateAutomationSettingsRequest = NonNullable<UpdateSettingsRequest['automation']>

// The "retention" section of a PUT request. Like UpdateAnalysisSettingsRequest,
// all three fields are plain and always-submitted — none is a secret, so
// there's no omit-vs-clear distinction to make. A number sets an explicit,
// opt-in retention window in days; null explicitly clears it back to "keep
// forever," which is also this feature's shipped default (see
// RetentionSettings' doc comment) — there is no other fallback tier null
// could mean here.
export type UpdateRetentionSettingsRequest = NonNullable<UpdateSettingsRequest['retention']>

// The "detection" section of a PUT request. Like UpdateRetentionSettingsRequest,
// all three fields are plain and always-submitted — none is a secret, so
// there's no omit-vs-clear distinction to make. disabledDetectorIds is sent
// exactly as checked, including `[]` when every detector is enabled — a
// real, valid selection, not a "leave unchanged" sentinel.
// stormProtectionMaxNewIncidents/stormProtectionWindowSeconds must be sent
// both-null or both-a-positive-number — the hub returns a 400 otherwise.
//
// disabledRuleIds is BUGS.md 111's rule-level sibling of disabledDetectorIds
// — see DetectionSettings' doc comment. Sent exactly as checked, same "[] is
// a real, valid selection" contract. NOT sent by the dry-run preview request
// below (SettingsPage.tsx hardcodes `[]` there deliberately): the dry-run
// replay (internal/api/detection_dryrun.go) was not extended to simulate
// this control, so sending whatever is currently checked would silently be
// ignored by the hub rather than actually previewed — see that file's own
// scope note.
export type UpdateDetectionSettingsRequest = components['schemas']['DetectionSettingsRequest']

// POST /api/v1/detection/dry-run (internal/api/detection_dryrun.go) — a
// scoped, real slice of lld/11-ui-design.md §3's PolicyEditor
// "dry-run-against-history" feature, applied to the two real detection
// controls above instead of the not-yet-built RemediationPolicy CRD. The
// request body is exactly UpdateDetectionSettingsRequest (the SAME
// candidate shape a real PUT would send) — this endpoint never writes it
// anywhere, it only replays it against real findings/incidents history.
//
// The replay reuses handleFinding's own decision functions verbatim
// (internal/gateway's exported IsDetectorDisabled/StormProtection*
// helpers) — see that file's own doc comment. "Actual" below means what
// really happened, under whichever settings were live at the time each
// historical finding arrived; "candidate" means what this request's
// settings would have done to the exact same history.
export type DetectionDryRunFilterBucket = components['schemas']['DetectionDryRunFilterBucket']

export type DetectionDryRunStormOutcome = components['schemas']['DetectionDryRunOutcome']

export type DetectionDryRunStormBucket = components['schemas']['DetectionDryRunStormBucket']

export type DetectionDryRunResponse = components['schemas']['DetectionDryRunResponse']

// The "autonomy" section of a PUT request — see AutonomySettings' doc
// comment. autoApproveMaxRisk/minConfidenceForAutoApprove are plain and
// always-submitted, like UpdateRetentionSettingsRequest's fields: neither is
// a secret, so there's no omit-vs-clear distinction to make. A real value
// sets an explicit override; null explicitly clears it back to
// internal/orchestrator.DefaultAutonomyPolicy's own hardcoded value (NOT
// "never auto-approve" — see AutonomySettings' doc comment for why this null
// means something different from UpdateDetectionSettingsRequest's).
// requireReversibleForAutoApprove is a plain, always-submitted boolean here
// too: the hub's wire contract now accepts null for this field as well
// (BUGS.md 97, migration 000085 made it nullable server-side, matching its
// two siblings above), but this client never exercises that — SettingsPage
// always round-trips the current concrete value on every save (seeded from
// effectiveRequireReversibleForAutoApprove so a load never has to guess),
// so the "send null to clear back to the default" path exists for other
// callers, not for this UI.
// The three caps are null-clears-to-default like the two fields above them —
// but the hub REJECTS a zero or negative value rather than coercing it, because
// a 0 typed meaning "never" would otherwise resolve to the default and do the
// opposite. It also rejects a per-cluster cap above the fleet-wide one, which
// could never take effect.
//
// Every key here is OPTIONAL on the generated contract, where the transcription
// this replaced made `requireReversibleForAutoApprove` and
// `unattendedExecutionEnabled` required. That was a client-side guard against
// BUGS.md 97 — a PUT that included "autonomy" while omitting one of them.
// internal/api/settings.go's putAutonomySettingsRequest has since made
// RequireReversibleForAutoApprove a *bool (absent clears to the SAFE default,
// true) and leaves UnattendedExecutionEnabled a plain bool (absent decodes
// false, also the safe direction), so neither omission is dangerous at the
// handler any more. The form still sends both on every save; keep it that way.
export type UpdateAutonomySettingsRequest = NonNullable<UpdateSettingsRequest['autonomy']>

// The "cost" section of a PUT request — see CostSettings' doc comment. All
// four fields are plain and always-submitted, like
// UpdateRetentionSettingsRequest's fields: none is a secret, so there's no
// omit-vs-clear distinction to make. The three price fields must be sent
// either all-null (no pricing configured) or all-set (a real price table) —
// the hub rejects a partial set with a 400, since that would compute a
// systematically wrong cost. dailySpendCeilingUsd, if set, must be a
// positive number; null disables the ceiling.
export type UpdateCostSettingsRequest = NonNullable<UpdateSettingsRequest['cost']>

// Every section is optional, matching the backend: an absent section means
// "leave this whole area untouched" (internal/settings.UpdateInput's nil
// checks), which is not the same as sending it with cleared values. These were
// all required until AIProvidersCard took over provider configuration and this
// page legitimately needed to omit "llm" — the types had been stricter than the
// API for no reason.
export type UpdateSettingsRequest = components['schemas']['UpdateSettingsRequest']

// The appearance section of a settings PUT. `loginStyle` is required when the
// section is present: an install always serves some sign-in screen, so there
// is no "unset" to express. The hub rejects anything outside its own
// `appearance.styles` list with a 400 naming the valid values.
export type UpdateAppearanceSettingsRequest = NonNullable<UpdateSettingsRequest['appearance']>

// The outbound section of a settings PUT. Present the section at all and
// `privateDestinations` is taken exactly as given — there is no per-entry
// merge, so an empty list clears every exception back to plain default-deny.
// Removing an exception is the operation that matters most on a list of
// security exceptions, and merge semantics would make it unexpressible.
//
// The hub validates every entry with the same code that decides whether a
// dial is permitted (internal/outbound.ParseAllowlist) and returns a 400
// whose `detail` names the specific problem — render that, never a
// re-implementation of those rules in TypeScript.
export type UpdateOutboundSettingsRequest = NonNullable<UpdateSettingsRequest['outbound']>

// RFC 9457 problem+json — every error response across the API.
// RFC 9457 problem+json — named ProblemDetails here (docs/openapi.yaml
// calls the same schema `Problem`) since that's the name every caller of
// this file already imports.
//
// confirmationToken is an RFC 9457 extension member, present only on a
// remediation guardrail refusal (writeGuardrailRefusal,
// internal/api/approvals.go). Echo it back on a confirmed retry — the
// boolean alone no longer proves the refusal was shown, only this token
// does.
export type ProblemDetails = components['schemas']['Problem']

// Mirrors internal/authz.Scope (lld/02-authz-spec.md §3's grammar).
export type GrantScope = components['schemas']['GrantScope']

// Mirrors internal/authz.EffectiveGrant.
export type EffectiveGrant = components['schemas']['EffectiveGrant']

export type EffectivePermissionsResponse = components['schemas']['EffectivePermissionsResponse']

// The 5 fixed builtin roles (internal/authz/permissions.go's
// builtinRoleCapabilities) — a closed set, unlike a custom role's id
// (BACKLOG.md S3, CustomRole below), which is data rather than a fixed
// union. A grant's `role` field (CreateGrantRequest/CreateUserRequest) is a
// plain `string` for exactly that reason — it accepts either shape.
export type BuiltinRole = 'super-admin' | 'tenant-admin' | 'resolver' | 'pr-approver' | 'viewer'

export const BUILTIN_ROLES: BuiltinRole[] = ['super-admin', 'tenant-admin', 'resolver', 'pr-approver', 'viewer']

// The readable name for each built-in role. Beside BUILTIN_ROLES because it is
// the same vocabulary, and shared because it was not: SettingsPage held this map
// while UsersPage rendered the raw wire value ('super-admin') in three selects
// and a filter (BACKLOG D7f). A raw enum is never a user-facing label.
// Readable names for cluster states, beside ROLE_LABELS for the same reason:
// three screens held parallel copies and had already diverged, with
// ClusterDetailPage rendering the raw wire value (BACKLOG D7f). Lives here rather
// than next to ClusterStateBadge because a module that exports both a component
// and a constant breaks react-refresh.
export const CLUSTER_STATE_LABEL: Record<ClusterState, string> = {
  PendingApproval: 'Pending approval',
  Provisioning: 'Provisioning',
  Active: 'Active',
  Degraded: 'Degraded',
  Disconnected: 'Disconnected',
  IncompatibleVersion: 'Incompatible version',
  Rejected: 'Rejected',
  Archived: 'Archived',
}

// The cluster's own fault, in plain English, or null when nothing is wrong —
// a healthy cluster gets no third line. Moved here from ClustersPage.tsx
// (BACKLOG D7i): ClusterDetailPage answered the four-question standard's
// "what is broken?" for every OTHER object in this app except the cluster
// itself, while this exact sentence already existed one page over. Not a
// restatement of the state badge beside it — each line says the CONSEQUENCE
// of the state, in the terms internal/gateway actually means it: Degraded is
// two consecutive missed heartbeats and Disconnected is five (health.go's
// own doc comment), Provisioning is "accepted, first heartbeat not yet
// received" (clusters.go sets it on accept; gateway/server.go clears it on
// the first heartbeat).
export const CLUSTER_FAULT_LINE: Record<ClusterState, string | null> = {
  PendingApproval: 'Waiting to be accepted before it can report',
  Provisioning: 'Accepted — waiting for its first heartbeat',
  Active: null,
  Degraded: 'Missing heartbeats',
  Disconnected: 'Stopped sending heartbeats',
  IncompatibleVersion: 'Running an agent version this hub cannot accept',
  Rejected: 'Enrollment was rejected',
  Archived: 'Decommissioned',
}

// T16. The one human-facing label per AgentCompatibilityVerdict — the
// TypeScript exhaustiveness (Record<AgentCompatibilityVerdict, string> fails
// to compile if a value is missing) is what keeps this from silently
// dropping a verdict the way CLUSTER_STATE_LABEL's own header comment
// describes three older per-page copies doing. Mirrors
// internal/agentversion.VerdictLabel; kept as a separate copy because the
// wire carries the verdict STRING, not this map — see that Go map's comment.
export const COMPATIBILITY_VERDICT_LABEL: Record<AgentCompatibilityVerdict, string> = {
  unknown: 'Unknown',
  current: 'Current',
  upgrade_recommended: 'Upgrade recommended',
  upgrade_required: 'Upgrade required',
}

export const ROLE_LABELS: Record<BuiltinRole, string> = {
  'super-admin': 'Super-admin',
  'tenant-admin': 'Tenant-admin',
  resolver: 'Resolver',
  'pr-approver': 'PR approver',
  viewer: 'Viewer',
}

// Two more role-prose maps, merged here for the same reason ROLE_LABELS was
// (BACKLOG D7f): UsersPage held ROLE_DESCRIPTIONS and SettingsPage held
// ROLE_NOTES as independently hand-maintained copies of "what this role can
// do," and by the time this merge happened there were 5 roles to keep in
// sync by hand across two files instead of 4.
//
// Kept as TWO exports rather than unified into one string, because they are
// not actually the same fact told twice — read both before assuming they
// are:
//   ROLE_DESCRIPTIONS   a general capability SUMMARY, written for the point
//                       where a grant is being chosen (UsersPage's create/
//                       add-grant forms) — what this role broadly lets
//                       someone do, in isolation.
//   ROLE_NOTES          a comparison against the role ABOVE it, calling out
//                       the specific capabilities internal/authz/
//                       permissions.go's own comments say are deliberately
//                       withheld (SettingsPage's "Roles & access" reference,
//                       read beside the live capability list from
//                       GET /api/v1/roles). "Tenant-admin can do everything
//                       super-admin can except X" answers a different
//                       question than "here is what tenant-admin does," and
//                       collapsing them into one string would have made one
//                       of the two contexts read oddly no matter which
//                       phrasing won.
// Unifying the CONTENT would have meant picking one voice and making the
// other screen worse; unifying the LOCATION (this file, once, like
// ROLE_LABELS) removes the actual bug — two hand-maintained copies that can
// silently diverge — without forcing that tradeoff.
export const ROLE_DESCRIPTIONS: Record<BuiltinRole, string> = {
  'super-admin':
    'Full control of everything: incidents, remediations, policies, clusters, repos, integrations, users, and spend, plus the super-admin-only powers to remove users, read the audit log, and change organization-wide settings.',
  'tenant-admin':
    'Manages incidents, remediations, policies, clusters, repos, integrations, ordinary user lifecycle actions, and spend — except removing users, reading the audit log, or changing organization-wide settings, which are reserved to super-admin.',
  resolver:
    'Investigates and resolves incidents: read/silence/reanalyse incidents, approve or run remediations, and read/write policies. Can read clusters and spend, but can’t manage users, onboard clusters, or configure integrations.',
  'pr-approver':
    'Same as resolver, but may only approve remediations that open a pull request — never one that executes directly against a cluster. For a team that wants every fix to pass through Git review before it touches anything live.',
  viewer:
    'Read-only across incidents, analyses, clusters, and policies. Can also request temporary breakglass access to act on an incident when needed — the one write-shaped thing a viewer can trigger.',
}

export const ROLE_NOTES: Record<BuiltinRole, string> = {
  'super-admin':
    'Full control of everything below, plus the two things no other role can do: read the audit log, and change organization-wide settings.',
  'tenant-admin':
    'Everything super-admin can do below, except reading the audit log or changing organization-wide settings — those two are deliberately reserved to super-admin only.',
  resolver:
    "Focused on day-to-day incident response: can investigate, silence, and remediate incidents, and read/write policies. Can't manage users, onboard clusters, or configure repos/integrations.",
  'pr-approver':
    "Everything resolver can do below, except one thing: may approve a remediation that opens a pull request, but never one that executes directly against a cluster — remediation:execute:inplace is withheld.",
  viewer:
    'Read-only across incidents, analyses, clusters, and policies — with one deliberate exception: requesting temporary breakglass access to act on an incident when needed.',
}

// GET /api/v1/roles (internal/api/roles.go) — the raw capability list per
// builtin role, straight from internal/authz/permissions.go's
// builtinRoleCapabilities (the real source of truth), keyed by role id.
// Backs SettingsPage.tsx's "Roles" tab. Only the raw capability *strings*
// come from here; that screen's human-readable grouping/labels for each
// string are a separate, hand-maintained frontend concern (see
// ROLE_CAPABILITY_GROUPS' own doc comment there) — this response is never
// itself hand-transcribed, so a role/capability change on the backend can't
// silently drift out of sync with what this type describes.
// GET/POST/PUT/DELETE /api/v1/admin/identity-providers (PROJECT.md S2).
// ARGUS is an OIDC relying party and speaks exactly one flow: LDAP, Active
// Directory and SAML reach it through a broker rather than through a
// per-vendor provider catalogue, so there is no provider "type" here.
//
// `hasClientSecret` — Whether a secret is STORED, never the secret. A form needs this to offer
// "leave blank to keep the existing one" without being handed the value.
export type IdentityProvider = components['schemas']['IdentityProvider']

// One directory group mapped to one ARGUS role. There is no scope field
// because the hub writes every one of these at AllClusters scope today; a
// narrower per-mapping scope is a real future addition, and inventing a
// picker for it here would offer something the API cannot honour.
export type IdentityGroupMapping = components['schemas']['IdentityGroupMapping']

export type IdentityProvidersResponse = ResponseBody<'listIdentityProviders', 200>

// `clientSecret` — null leaves a stored secret untouched; a string replaces it.
export type SaveIdentityProviderRequest = components['schemas']['SaveIdentityProviderRequest']

export type RolesResponse = components['schemas']['RolesResponse']

// One grants row, as returned by GET /users, POST /users/{id}/grants (and
// nested in POST /users' response when an initial grant is requested).
// `role` is '' only for a pre-existing, non-role (ad hoc capability_set)
// grant — this UI never creates one of those, but must still render one
// without crashing if it already exists.
//
// `justification` — Why this access was given. Optional — the form does not require one, so
// absent means "nobody wrote a reason", not "there was no reason".
export type Grant = components['schemas']['Grant']

export type User = components['schemas']['User']

export type UsersResponse = ResponseBody<'listUsers', 200>

// POST /api/v1/users' request shape. initialGrant is optional — omitting it
// creates a user with no grants at all (no effective permissions until a
// grant is added separately via POST /users/{id}/grants).
//
// `role` widened from BuiltinRole to `string` (BACKLOG.md S3): the hub now
// accepts a custom role's id here too (internal/authz.ResolveRoleCapabilities
// tries both) — a plain string is the only type that can name either without
// a union that would have to keep enumerating custom role ids, which are
// data, not a closed set like BUILTIN_ROLES.
export type CreateUserRequest = components['schemas']['CreateUserRequest']

// POST /api/v1/users' response. temporaryPassword is plaintext, shown
// exactly once — this response is the only place it ever appears; it is
// never returned again by GET /users or anything else.
export type CreateUserResponse = components['schemas']['CreateUserResponse']

// `role` widened to `string` for the identical reason as
// CreateUserRequest.initialGrant.role above.
export type CreateGrantRequest = components['schemas']['CreateGrantRequest']

// --- Custom roles (internal/api/custom_roles.go, BACKLOG.md S3) ---
//
// A tenant-defined named bundle composed from the SAME capability catalogue
// GET /api/v1/roles already exposes for the five builtin roles — never a new
// permission, only a different combination of existing ones. Assigned to a
// user through the EXISTING grant mechanism: `role` on CreateGrantRequest/
// CreateUserRequest.initialGrant accepts this row's `id` exactly as it
// accepts a BuiltinRole string.
export type CustomRole = components['schemas']['CustomRole']

export type CustomRolesResponse = ResponseBody<'listCustomRoles', 200>

export type CreateCustomRoleRequest = components['schemas']['CreateCustomRoleRequest']

// PUT /api/v1/custom-roles/{id} — capabilities only; the name is immutable
// through this route (every grant referencing the role holds its id, not
// its name, so nothing depends on a rename, and none is offered).
export type UpdateCustomRoleRequest = RequestBody<'updateCustomRole'>

// --- Cluster groups (internal/api/cluster_groups.go, BACKLOG.md S3) ---
//
// A named set of clusters. "Team ownership" is a grant scoped to
// `{type: 'ClusterGroup', clusterGroupId: group.id}` (GrantScope above) —
// there is no separate ownership field on this type.
export type ClusterGroup = components['schemas']['ClusterGroup']

export type ClusterGroupsResponse = ResponseBody<'listClusterGroups', 200>

export type CreateClusterGroupRequest = RequestBody<'createClusterGroup'>

// PUT /api/v1/users/me/password's request shape (internal/api/auth.go's
// handleChangePassword). currentPassword is verified against the caller's
// own stored hash server-side before newPassword is accepted — even for a
// mustChangePassword account whose "current" password is a just-issued
// temporary one.
export type ChangePasswordRequest = RequestBody<'changeOwnPassword'>

// POST /api/v1/users/{id}/reset-password's response shape
// (internal/api/users.go's handleResetPassword) — mirrors
// CreateUserResponse.temporaryPassword's exact discipline: plaintext, shown
// exactly once, never returned again by any other endpoint.
export type ResetPasswordResponse = ResponseBody<'resetUserPassword', 200>

// POST /api/v1/users/{id}/disable, POST /api/v1/users/{id}/enable, and
// DELETE /api/v1/users/{id}'s shared response shape
// (internal/api/users.go's userLifecycleResponse) — the same "id + new
// status string" convention revokeGrant's response already uses below.
export type UserLifecycleResponse = components['schemas']['UserLifecycleResponse']

// GET /api/v1/audit-events' response shape (internal/api/audit.go). Mirrors
// auditEventSummary exactly — see that Go type's doc comment for why
// `details` itself isn't included here (shapes vary per write path, some
// large enough not to want in a list response by default): detailsSummary is
// a short, generic "key=value, key=value" digest, and the full, structured
// details/scope/hash-chain fields are only in AuditEventDetail
// (GET /api/v1/audit-events/{id}), matching Incident/IncidentDetail's split.
// action — what happened, for the "Action" column. Prefers the write
// path's own action name and falls back to the capability, so the column
// is populated for system-raised events too (those have no capability).
// Empty string for the few rows that support neither, where the client
// renders an em dash.
//
// detailsSummary — NOTE: no longer rendered. The list's Details column is
// the button alone — see AuditLogPage for why the inline preview was
// removed. Still returned by the API; remove the server-side summarizer
// with its tests if it is not wanted back.
export type AuditEventSummary = components['schemas']['AuditEventSummary']

// nextCursor — absent/undefined once the last page has been reached — see
// getAuditEvents' doc comment for the keyset-pagination contract this
// mirrors from internal/api/audit.go's handleListAuditEvents.
export type AuditEventsResponse = components['schemas']['AuditEventsResponse']

// GET /api/v1/audit-events/{id}'s response shape. `scope`/`details` are
// free-form JSON (this schema's audit_events.scope/details columns) — never
// render either through dangerouslySetInnerHTML (SR-17); render as plain
// text/JSON, same rule as Finding.reason/message elsewhere in this file.
// prevHash/hash are this row's own hash-chain fields (internal/audit's
// ComputeHash) — non-secret, shown so an admin can eyeball one row's chain
// linkage without needing `argusctl audit verify`'s full-table pass.
export type AuditEventDetail = components['schemas']['AuditEventDetail']

// Query params for GET /api/v1/audit-events — every field optional/ANDed.
// `capability` is this schema's name for what a UI filter dropdown presents
// as "action" (see internal/api/audit.go's handleListAuditEvents doc
// comment for why the existing vocabulary is reused rather than adding a
// second name for the same concept).
//
// `cluster` — exact match against cluster_id. Rows with no cluster (org-level
// events — a settings write, login, user/grant change) never match,
// deliberately; see internal/api/audit.go's parseAuditEventFilters.
//
// `resource` — free text against the object an event was about, matched
// server-side either directly (details.objectKey) or via the incident the
// event names (details.incidentId -> incidents.object_key). Events with
// neither key have no resource concept and are never matched; see
// parseAuditEventFilters' doc comment for exactly what this can and can't
// find, and its cost with no cluster/time bound alongside it.
//
// Query parameters rather than a body, so this reaches the generated contract
// through `operations` rather than `components['schemas']`.
export type AuditEventFilters = NonNullable<operations['listAuditEvents']['parameters']['query']>

// GET /api/v1/insights' response shape (internal/api/insights.go). See that
// file's own header comment for the full reasoning: this is a deliberately
// scoped-down slice of lld/11-ui-design.md §15.1's "Insights" screen — real
// SQL aggregation over incidents/findings/analyses, with `notBuilt` as an
// explicit, honest list of the two sub-features (a calibration curve, an
// autonomy-readiness rating) that genuinely can't be built honestly yet.
export type IssueClassSummary = components['schemas']['IssueClassSummary']

export type NoisyNamespaceSummary = components['schemas']['NoisyNamespaceSummary']

// BUGS.md 121 part (b): a fingerprint/namespace with NO history at all
// before newSignalWindowDays but WITH occurrences inside it — a genuinely
// new signal, surfaced alongside (not instead of) the all-time top-N lists
// above, which structurally cannot show a small new signal once an old,
// high-volume one already dominates the ranking. See
// internal/api/insights.go's queryNewIssueClasses/queryNewNoisyNamespaces
// doc comments for the exact definition and why this is scoped to "brand
// new" only, not also "quiet, then spiking above its own baseline."
export type NewNoisyNamespaceSummary = components['schemas']['NewNoisyNamespaceSummary']

// completeRate/avgIterations are both null (never a fabricated 0) when
// totalAnalyses is 0 — see investigationOutcomes' Go doc comment for why
// that distinction matters.
export type InvestigationOutcomes = components['schemas']['InvestigationOutcomes']

export type DailyTrendPoint = components['schemas']['DailyTrendPoint']

export type CostAndTokensSummary = components['schemas']['CostAndTokensSummary']

export type NotBuiltSection = components['schemas']['NotBuiltSection']

// BACKLOG.md L4's "unstable clusters" analytic — incidents grouped by
// cluster, ranked by how many are currently Reopened or Failed (a real,
// current value of incidents.state, not a derived history — this codebase
// has no state-transition history to compute anything fancier from, see
// reference/screens.md's verified gaps table). reopenedOrFailedCount can be
// 0 for every cluster (a fleet that has never had a reopen/failure), in
// which case the ranking degrades to "busiest by incident volume" — the UI
// says exactly what it's sorted by rather than implying a trained score.
export type UnstableClusterSummary = components['schemas']['UnstableClusterSummary']

// `newIssueClasses` — "New in this window" — BUGS.md 121 part (b), added alongside
// issueClasses/noisyNamespaces above WITHOUT changing either's own
// count-based ranking. newSignalWindowDays is the server's own fixed
// lookback (see insightsNewSignalWindowDays in insights.go), carried on
// the payload rather than hardcoded here.
export type InsightsResponse = components['schemas']['InsightsResponse']

// GET /api/v1/insights/remediation-quality's response shape — BACKLOG.md
// L4's other two analytics, on a SEPARATE endpoint from InsightsResponse
// above because they read remediation_recommendations/
// remediation_approval_decisions, which this codebase already gates behind
// remediation:approve specifically (the same capability GET /api/v1/approvals
// reads under) — narrower than incident:read + analysis:read, which gate
// InsightsResponse. See internal/api/insights_remediation.go's header
// comment for the full reasoning.

// One (actionType, targetGvk) group with at least one real rejection —
// rejectionRate is always well-defined (never a divide-by-zero 0) because
// the backend only returns a group here once it has seen a genuine
// rejection, which guarantees at least one decision exists.
export type RejectedRecommendationSummary = components['schemas']['RejectedRecommendationSummary']

// One (actionType, targetGvk, riskLevel) group still gated NeedsApproval,
// with at least one real human decision on it (an inner join server-side —
// a recommendation nobody has decided on yet is correctly absent, not shown
// with an invented rate). approvalRate == 1 (rejectedCount == 0) is the
// strongest form of "this combination could be promoted to auto-approve."
export type AutomationCandidateSummary = components['schemas']['AutomationCandidateSummary']

export type RemediationQualityResponse = components['schemas']['RemediationQualityResponse']

// POST /api/v1/ws/ticket's response — see client.ts's createWSTicket.
export type WSTicketResponse = ResponseBody<'createWebSocketTicket', 201>

// The three live-update event types internal/events.Bus (Go) broadcasts over
// GET /ws/events — IDs only, deliberately (lld/11-ui-design.md §5: "trigger
// an in-place refetch," never "replace the fetch with the WS payload").
// FindingRecorded (PROJECT.md F31) is the lighter-weight third: it fires for
// every finding handleFinding durably records, not only the ones that
// touched an incident — see internal/events.FindingRecorded's own doc
// comment and realtime/refresh.ts's EVENT_REFRESHES entry for it.
//
// The one hand-written shape left in this file, and deliberately so: these are
// WebSocket frames, and the upgrade route is one of the seven docs/openapi.yaml
// does not describe. There is no generated twin to alias, so there is no second
// home for this shape either.
export interface LiveEvent {
  type: 'IncidentUpdated' | 'ClusterUpdated' | 'FindingRecorded'
  incidentId?: string
  clusterId?: string
  occurredAt: string
}

// The repository-change channel (internal/api/repository_change.go,
// repository_preview.go, repository_files.go) — three routes that share one
// request shape.
//
// # What a repository change IS, since 2026-08-28
//
// A set of WHOLE FILES: one or many, each carrying the content the file should
// end up holding. Not a field and a value. The previous grammar — one scalar,
// in one already-existing, untemplated, plain-YAML file — could prove that
// nothing else moved, and that proof was real; it was also the request shape,
// so it capped the whole channel at the small fraction of real fixes that look
// like that. A Helm values key feeding a template, a Kustomize overlay patch, a
// probe block that has to be ADDED, two files that move together: none of them
// were expressible. See internal/gitops/files.go and DESIGN.md §11.4.
//
// The repository, the synced directory and the commit are deliberately NOT in
// the request: the hub takes those from the incident's stored GitOps ownership,
// never from the caller, so a request cannot redirect ARGUS's credential at a
// repository the incident has nothing to do with. The PATHS are the caller's to
// state, and are confined to that directory and checked against the
// forbidden-path denylist before anything is read or written.

// One file's whole proposed content — a path plus the bytes the file should
// hold afterwards. Never a diff or a patch: ARGUS computes the diff from this
// against the file at the pinned commit, so there is no diff format for a
// client (or a model) to get wrong.
//
// `path` — Relative to the repository root.
// `content` — The file exactly as it should read after the change.
export type RepositoryChangeFile = components['schemas']['RepositoryChangeFile']

// `files` — At least one. A file that does not exist at the synced commit is created.
// `reason` — Quoted into the pull request body. Omitted, ARGUS quotes the incident's own
// analysis if it has a root cause statement.
export type RepositoryChangeRequest = components['schemas']['RepositoryChangeRequest']

// One file's outcome, as the hub reports it. Everything here is read back out
// of the file at the pinned commit and the content proposed for it — nothing is
// a claim about intent.
//
// `created` — The file does not exist at the synced commit and would be created. A normal
// outcome, not an error.
// `unchanged` — The submitted content already matched the file. Reported and NOT committed
// — opening three files and editing one is an ordinary thing to submit, so
// this is a normal outcome too, not an error.
// `documentCount` — How many YAML documents the proposed content holds, or 0 when ARGUS did not
// parse it. Meaningful ONLY when `parsed` is true — a templated file's
// YAML-ness is an accident, so a count for one would be a number about the
// wrong artefact.
// `parsed` — Whether ARGUS parsed this file as YAML at all.
// `checks` — What ARGUS asserted about this file, in words.
// `advisories` — What a reviewer must check BECAUSE ARGUS COULD NOT: a templated file it did
// not render, a file that is not YAML at all, a changed document count, an
// object identity that moved. These are advisories, not refusals — the change
// proceeds — and a client MUST render them next to the diff they qualify.
// They are the operator's cue to look harder at a specific file, so they are
// never collapsed and never carried by colour alone.
export type RepositoryChangeFileResult = components['schemas']['RepositoryChangeFileResult']

// What ARGUS checked across the whole proposal, per file and in aggregate.
//
// There is no fieldPath/oldValue/newValue here, and the absence is the point:
// a whole-file change makes no "only this moved" claim, so there is no field to
// name. `caveat` states that in words, and it is the same sentence the pull
// request body carries.
//
// `files` — One entry per submitted file, in the order submitted, INCLUDING the
// unchanged ones.
// `filesChanged` — How many entries are actually being committed (unchanged files are not).
// `checks` — The aggregate of the per-file lists, prefixed with the file they came from
// when there is more than one file. Rendering these AND the per-file ones is
// the same fact twice — pick one surface per list.
// `label` — The label ARGUS puts on the pull request, and — in words — what that label
// withholds. Both are in the response as well as on the pull request so the
// operator and the reviewer read the same claim.
export type RepositoryChangeVerification = components['schemas']['RepositoryChangeVerification']

// RenderEvidence is BACKLOG.md F26's render-and-diff result, wired (F28
// finding 2) into the preview response as well as the two paths that open a
// pull request — so the SAME "is this an effective change" evidence reaches
// an operator BEFORE they approve, not only after.
//
// attempted: false (the only field present) means rendering was never
// attempted at all — no render sandbox configured, no known repository, or
// a plain-YAML source with no renderer to run. Not a refusal and not a
// claim; a client should render nothing for it, matching the pull-request
// body's own "never a badge for a check that didn't run" rule.
//
// degraded, when present, means a render was tried and could not produce a
// trustworthy answer — including, per F28 finding 2's own honesty
// requirement, a Helm chart with no discoverable values-file list: a
// defaults-only render cannot confirm the real deployed configuration, so
// its result (even one that happens to say "no effective change") is never
// treated as authoritative.
//
// Otherwise this is a real, checked answer: rendererKind is "helm" or
// "kustomize", effective is whether at least one rendered object genuinely
// differs, objectsCompared/objectsChanged/summary describe what was
// compared.
//
// `objectsChanged` is the ONE field here that is NOT taken from the generated
// twin, and the override is deliberate rather than a leftover transcription.
// docs/openapi.yaml declares it `integer`; internal/api/render_evidence.go's
// renderEvidenceAuditFields assigns `re.ObjectsChanged`, which is
// internal/gitops.RenderEvidence's `[]string` — the NAMES of the objects that
// differ, not a count. The wire carries the array, so the spec is what is
// wrong here, and aliasing this field would make every consumer typecheck
// against a shape the hub does not send. Drop the override once the spec says
// `array of string`; do not "fix" the screens to match the spec instead.
export type RenderEvidence = Omit<components['schemas']['RenderEvidence'], 'objectsChanged'> & {
  objectsChanged?: string[]
}

// POST /incidents/{id}/repository-change/preview — what the pull request WOULD
// contain, with nothing branched, committed or opened.
//
// Deliberately NOT RepositoryChangeResponse with empty fields: that type's shape
// says "a pull request exists" (a number, a URL, a commit), and reusing it would
// invite a client to render an empty pull-request link.
//
// `branch` — The branch the change WOULD be opened on, so a client can warn about an
// existing one before the operator commits to anything.
//
// `renderEvidence` carries RenderEvidence's own `objectsChanged` override for
// the reason recorded above that type — the generated twin inlines the spec's
// (wrong) `integer` here, so the field is re-pointed at the corrected type
// rather than left to disagree with the wire.
export type RepositoryPreviewResponse = Omit<
  components['schemas']['RepositoryChangePreviewResponse'],
  'renderEvidence'
> & { renderEvidence: RenderEvidence }

// `commitSha` — The branch head. `commits` is one SHA per file actually committed.
// `syncedRevision` — The commit the files were READ at: what the controller reports as applied,
// not the branch head. The branch is cut from the base head instead, so the
// pull request's diff does not include everything that landed since.
// `warning` — Set when the pull request exists but something non-fatal did not. Non-empty
// means "read this", not "it failed".
export type RepositoryChangeResponse = components['schemas']['RepositoryChangeResponse']

// GET /incidents/{id}/repository-change/file?filePath=... — the CURRENT,
// unedited file at the pinned synced commit. What an editor is seeded with
// before a human proposes new content for it, and what a client re-reads when
// the operator wants a second file in the same change.
//
// filePath is optional: with none, ARGUS finds the single file under the synced
// directory that declares this incident's object, and refuses if there are none
// or several. `filePathSource` says which of the two happened, so a UI can show
// a path with its provenance rather than a path from nowhere.
export type RepositoryFileResponse = components['schemas']['RepositoryFileResponse']

// One configured maintenance or freeze window (GET /admin/automation-windows).
//
// The two kinds do not combine symmetrically, and the asymmetry is the thing to
// understand before using them: a **freeze** forbids automation whenever it is
// open, whatever else is configured, so adding one can only make the system
// safer. A **maintenance** window is a permission, so an empty maintenance list
// means *no time restriction* rather than "nothing is permitted" — the literal
// reading would silently stop automation on every installation the day the
// feature shipped. See internal/orchestrator.CheckWindows.
// A freeze forbids automation whenever it is open, whatever else is
// configured, so adding one can only make the system safer. A maintenance
// window is a PERMISSION, so an empty maintenance list means no time
// restriction rather than "nothing is permitted". `schedule` is a 5-field
// cron expression naming the window's START, not "when it applies" — a
// bare cron is an instant, which is why duration exists. `openNow` is
// evaluated server-side so the UI shows the same verdict the sweeper
// reaches. `invalidReason` is set when a stored window cannot be
// evaluated — a malformed FREEZE is treated as in force, so this must be
// visible.
export type AutomationWindow = components['schemas']['AutomationWindow']

// automationOpenNow/decisionReason — whether automation would run right
// now, and why. The question an operator actually has, answered once by
// the same code the sweeper uses.
export type AutomationWindowsResponse = components['schemas']['AutomationWindowsResponse']

// The circuit breaker (BACKLOG R2's second half). Bounds unattended execution on
// OUTCOME, where the windows above bound time and the blast-radius caps bound
// volume — none of the three substitutes for the others. fleetWide trips
// carry no cluster: they stop unattended execution everywhere. `resetAt` is
// absent while the trip is OPEN — reset is manual by design, so this is the
// field that separates "needs someone to look" from history.
export type CircuitBreakerTrip = components['schemas']['CircuitBreakerTrip']

export type CircuitBreakerResponse = components['schemas']['CircuitBreakerResponse']

export type CreateAutomationWindowRequest = components['schemas']['CreateAutomationWindowRequest']

// GET /api/v1/diagnostics/bundle (PROJECT.md T18) — a bounded, redacted support
// artifact. Every field here is presence/state, never a secret value: apiKeySet/
// runnerTokenSet/credentialStored mirror AIProvider's/RepositoryBinding's own
// contract, and every connectivity*/error string has already been through the
// hub's redaction scrub before it reaches this response.
//
// `status` — 'degraded' is internal/api/diagnostics.go's diagnosticsStatusFor verdict
// for a pass that COMPLETED but was incomplete — at least one checker did
// not answer in time (see timedOutChecks below). It is deliberately not
// 'failing': the detector is running and reporting, and calling an
// incomplete pass plain 'ok' would claim a coverage it did not have. The
// hub orders 'failing' above it, because a read refused outright is the
// more actionable of the two when one pass produced both.
// `timedOutChecks` — The checkers that did not answer within their per-checker timeout during
// the MOST RECENT pass. Absent means either "the last pass was complete" or
// "this agent predates the field" — the wire does not distinguish them.
// Unlike every other field here this one describes one pass, not history: a
// clean pass clears it. Do not render it as a standing fault.
export type DiagnosticsDetectorStatus = components['schemas']['DiagnosticsDetectorStatus']

export type DiagnosticsClusterDetectors = components['schemas']['DiagnosticsDetectors']

// `detectors` — Absent means "no detector data available" (an older agent, or facts not
// synced yet) — never render its absence as healthy or as failing.
export type DiagnosticsCluster = components['schemas']['DiagnosticsCluster']

export type DiagnosticsAIProvider = components['schemas']['DiagnosticsAIProvider']

export type DiagnosticsRepository = components['schemas']['DiagnosticsRepository']

export type DiagnosticsInternalError = components['schemas']['DiagnosticsInternalError']

export type DiagnosticsOmission = components['schemas']['DiagnosticsOmission']

export type DiagnosticsManifest = components['schemas']['DiagnosticsManifest']

export type DiagnosticsBundle = components['schemas']['DiagnosticsBundle']

// ---------------------------------------------------------------- changes
//
// GET /api/v1/changes (internal/api/changes.go) — the front door for undo.
// Two kinds of change on one list, because "ARGUS changed my cluster" is one
// fact from an operator's point of view even though it is reached by two
// routes (ADR-18): an in-place execution, and a repository change whose pull
// request MERGED. An open or closed-unmerged pull request is a proposal, not
// a change, and is not listed — see changes.go's header for why, including
// the fact that no column anywhere records when a pull request was opened.
//
// `undo` is the part worth reading twice. It is not a UI-derived boolean: the
// hub computes it by asking rollback.go's own checkUndoable, so `reason`/
// `detail` are literally the refusal POST /executions/{id}/rollback would
// return. The screen must render them rather than paraphrasing — a second
// copy of a safety rule is how one of them ends up wrong.
//
// `available: true` is still not a promise. Three refusals can only be
// evaluated against the live cluster at request time (the field has moved
// since, the change is already gone, the agent is disconnected), so the
// control is offered and the refusal, if one comes, is shown in full.
export type ChangeUndo = components['schemas']['ChangeUndo']
export type Change = components['schemas']['Change']
export type ChangesResponse = components['schemas']['ChangesResponse']

// Cluster insight (docs/CLUSTER_INSIGHT_SPECS.md).
export type ResourceChange = components['schemas']['ResourceChange']
export type ResourceChangeGap = components['schemas']['ResourceChangeGap']
export type ResourceChangeList = components['schemas']['ResourceChangeList']
export type UpgradeScan = components['schemas']['UpgradeScan']
// GET /api/v1/fleet/summary — the Overview's fleet aggregate (internal/api/fleet_summary.go).
export type FleetSummary = components['schemas']['FleetSummary']
export type FleetClusterSummary = components['schemas']['FleetClusterSummary']
export type FleetCertificatesSummary = NonNullable<components['schemas']['FleetCheckCertificates']['summary']>
export type FleetPostureSummary = NonNullable<components['schemas']['FleetCheckPosture']['summary']>
export type FleetHelmSummary = NonNullable<components['schemas']['FleetCheckHelm']['summary']>
export type FleetGitOpsSummary = NonNullable<components['schemas']['FleetCheckGitOps']['summary']>
export type UpgradeScanEnvelope = components['schemas']['UpgradeScanEnvelope']
export type SearchResult = components['schemas']['SearchResult']
export type IncidentMetrics = components['schemas']['IncidentMetrics']
export type WorkloadMetrics = components['schemas']['WorkloadMetrics']
export type MetricPanel = components['schemas']['MetricPanel']

// PROJECT.md AD5/AD6: the results of the cluster page's Helm, GitOps and Map
// inspect tools (docs/openapi.yaml HelmReleaseList / GitOpsAppList /
// NamespaceTopology; internal/agent/tools_inventory.go).
export type HelmReleaseList = components['schemas']['HelmReleaseList']
export type HelmReleaseRow = HelmReleaseList['releases'][number]
export type GitOpsAppList = components['schemas']['GitOpsAppList']
export type GitOpsAppRow = GitOpsAppList['apps'][number]
export type NamespaceTopology = components['schemas']['NamespaceTopology']
export type NamespaceIndexRow = NonNullable<NamespaceTopology['namespaces']>[number]

// The cluster page's Network policy tab (get_network_policy_map;
// internal/agent/netpolmap).
export type NetworkPolicyMap = components['schemas']['NetworkPolicyMap']
export type NetworkPolicyWorkload = NonNullable<NetworkPolicyMap['workloads']>[number]
export type NetworkPolicyAllow = components['schemas']['NetworkPolicyAllow']
export type NetworkPolicyPeer = NetworkPolicyAllow['peer']
export type NetworkPolicyFinding = NonNullable<NetworkPolicyMap['findings']>[number]
export type NetworkPolicyIndexRow = NonNullable<NetworkPolicyMap['namespaces']>[number]

// PROJECT.md AD1 — the cluster timeline (GET /clusters/{id}/timeline).
export type ClusterTimeline = components['schemas']['ClusterTimeline']
export type TimelineRow = components['schemas']['TimelineRow']
export type TimelineMark = components['schemas']['TimelineMark']
export type TimelineSpan = components['schemas']['TimelineSpan']
export type TimelineObjectRef = components['schemas']['TimelineObjectRef']
export type TimelineSource = 'changes' | 'findings' | 'incidents'

// PROJECT.md AD3 — personal access tokens for the MCP endpoint
// (GET/POST /users/me/mcp-tokens, DELETE /users/me/mcp-tokens/{id}).
export type PersonalToken = components['schemas']['PersonalToken']
export type PersonalTokenStatus = components['schemas']['PersonalTokenStatus']
export type PersonalTokenList = components['schemas']['PersonalTokenList']
export type CreatePersonalTokenRequest = components['schemas']['CreatePersonalTokenRequest']
export type CreatePersonalTokenResponse = components['schemas']['CreatePersonalTokenResponse']
