import type {
  ClusterTimeline,
  TimelineSource,
  IncidentMetrics,
  WorkloadMetrics,
  ResourceChangeList,
  SearchResult,
  UpgradeScan,
  FleetSummary,
  UpgradeScanEnvelope,
  AcceptClusterResponse,
  AIProviderRequest,
  AIProvidersResponse,
  AIProviderTestResult,
  AnalysisStarted,
  AuditEventDetail,
  AuditEventFilters,
  AuditEventsResponse,
  ChangePasswordRequest,
  ChangesResponse,
  ClusterDetail,
  ClusterGroup,
  ClusterGroupsResponse,
  ClustersResponse,
  ConfirmRepositoryLinkRequest,
  CreateClusterGroupRequest,
  CreateCustomRoleRequest,
  CreateEnrollmentTokenRequest,
  CreateEnrollmentTokenResponse,
  FleetToken,
  CreateGrantRequest,
  CreateRepositoryBindingRequest,
  CreateUserRequest,
  CreateUserResponse,
  CustomRole,
  CustomRolesResponse,
  DecommissionClusterResponse,
  DetectionDryRunResponse,
  DiagnosticsBundle,
  DiscoverRepositoryLinkResponse,
  EffectivePermissionsResponse,
  Grant,
  ApprovalDecisionResponse,
  ApprovalsResponse,
  ApprovalSortDirection,
  ApprovalSortKey,
  IncidentDetail,
  IncidentDigestResponse,
  IncidentQuickViewCounts,
  IncidentOverview,
  IncidentsResponse,
  IncidentSortDirection,
  IncidentSortKey,
  IncidentTriageResponse,
  InsightsResponse,
  LoginRequest,
  LoginResponse,
  MeResponse,
  NotificationRoutingResponse,
  PreflightResponse,
  ProblemDetails,
  RemediationQualityResponse,
  RenameClusterResponse,
  RepositoriesResponse,
  RepositoryBinding,
  RepositoryCheckResult,
  ResetPasswordResponse,
  IdentityGroupMapping,
  IdentityProvider,
  IdentityProvidersResponse,
  RolesResponse,
  SaveIdentityProviderRequest,
  SSOProvidersResponse,
  Settings,
  SpendToday,
  TolerationDetail,
  Toleration,
  TolerateIncidentResponse,
  UpdateDetectionSettingsRequest,
  UpdateNotificationRoutingRequest,
  UpdateRepositoryBindingRequest,
  UpdateSettingsRequest,
  UserLifecycleResponse,
  UsersResponse,
  WSTicketResponse,
  AutomationWindowsResponse,
  CircuitBreakerResponse,
  CreateAutomationWindowRequest,
  RepositoryChangeRequest,
  RollbackRequest,
  RollbackResponse,
  RepositoryChangeResponse,
  RepositoryPreviewResponse,
  RepositoryFileResponse,
  TimelineResponse,
  EvidenceDetail,
  UpdateCustomRoleRequest,
} from './types'
// The findings shapes are aliased straight off the generated document rather
// than re-exported through `./types`, and the reason is the rule stated at the
// top of that file: an alias there exists to carry the hand-maintained prose
// that openapi.yaml does not. For findings, openapi.yaml already carries the
// whole explanation — what a disposition is derived from, why `counts` is never
// page-derived, why `notRecorded` has to be rendered — so it is already in
// `generated.ts` on every one of these types. A second hop would add a place
// for that prose to go stale, not a place for it to live.
import type { components } from './generated'

// Always call the hub through a relative /api/... path. In dev this is
// forwarded by Vite's server.proxy (see vite.config.ts) to whatever hub
// VITE_API_BASE_URL points at; in a production build the built assets are
// served by the hub itself (go:embed), so relative paths resolve correctly
// there too with no separate runtime config needed.
const API_PREFIX = '/api/v1'

// A problem `type` URI a caller branches on. Only add one here when a UI
// genuinely has to tell one failure apart from another and do something
// different about it — the title/detail are for showing, this is for
// deciding.
//
// scale-from-zero-refused (internal/api/approvals.go) is not an error in the
// "something broke" sense at all: the hub read the target's live replica
// count as 0, treated that as somebody having deliberately switched the
// workload off, and declined to turn it back on without an explicit human
// confirmation. Nothing was executed or recorded, and the same request
// succeeds when repeated with confirmScaleFromZero — which is exactly why the
// UI needs to recognize it structurally instead of grepping the message.
export const PROBLEM_SCALE_FROM_ZERO_REFUSED = 'https://argus.io/errors/scale-from-zero-refused'

// An inspection the agent answered with "that object is not there" (404, not
// the 502 of an agent that failed): an expected empty state — a deleted Pod
// an old incident still names — never an error banner.
export const PROBLEM_OBJECT_NOT_FOUND = 'https://argus.io/errors/object-not-found'

// The second guardrail of the same shape: ARGUS refuses to patch an object whose
// spec is owned by a Helm release or an Argo CD/Flux controller, because the next
// reconcile rewrites it and the "successful" fix quietly disappears. Its own
// problem type, not a shared one, so the UI asks the matching question — a "yes,
// turn it back on" click must never double as "yes, I accept this gets reverted".
export const PROBLEM_GITOPS_MANAGED_REFUSED = 'https://argus.io/errors/gitops-managed-refused'

// A file that does not exist at the synced commit. Branched on for one specific
// reason: GET .../repository-change/file refuses with this when the operator
// asks to open a path that is not in the repository, and "create it" is a
// legitimate answer to that — a repository change may create a file. Without
// the structural check the UI could only show the refusal, which would cap it
// below what the endpoint it calls can actually do.
//
// Recognized by problem type, never by message text: titles and details are
// human-facing prose that gets reworded, and a UI matching on prose breaks
// silently with no type error to catch it.
export const PROBLEM_NOT_FOUND = 'https://argus.io/errors/not-found'
// POST /incidents/{id}/analyze refused because no AI provider is configured.
export const PROBLEM_LLM_NOT_CONFIGURED = 'https://argus.io/errors/llm-not-configured'

// Thrown for any non-2xx response. Carries the RFC 9457 problem+json title
// (always) and detail (when non-empty) so callers can show them directly.
export class ApiError extends Error {
  readonly status: number
  readonly detail: string
  // The RFC 9457 `type` URI, or '' when the response carried no problem+json
  // body at all (a network failure, or a proxy erroring in HTML). Callers
  // deciding WHICH failure this is must use this and never the title/detail:
  // those are human-facing prose that gets reworded, and a UI that matches on
  // prose breaks silently the next time someone improves the wording — with
  // no type error to catch it. See PROBLEM_SCALE_FROM_ZERO_REFUSED above for
  // today's only such caller.
  readonly type: string

  // confirmationToken carries one RFC 9457 extension member — present only on
  // a remediation guardrail refusal (internal/authz.GuardrailConfirmationIssuer)
  // — that the client must echo back on a confirmed retry to prove the
  // refusal was actually shown, not merely that the client decided to set a
  // boolean. '' for every other error.
  readonly confirmationToken: string

  constructor(title: string, status: number, detail: string, type = '', confirmationToken = '') {
    super(title)
    this.name = 'ApiError'
    this.confirmationToken = confirmationToken
    this.status = status
    this.detail = detail
    this.type = type
  }
}

async function request<TResponse>(
  path: string,
  options: { method?: string; body?: unknown; accessToken?: string; keepalive?: boolean } = {},
): Promise<TResponse> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json'
  }
  if (options.accessToken) {
    headers.Authorization = `Bearer ${options.accessToken}`
  }

  let res: Response
  try {
    res = await fetch(`${API_PREFIX}${path}`, {
      method: options.method ?? 'GET',
      headers,
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
      // Explicit, not load-bearing on its own (fetch already defaults to
      // 'same-origin'): this is what lets the browser attach the HttpOnly
      // refresh cookie (PROJECT.md B164) on /auth/refresh and /auth/logout
      // without this file ever touching the token itself. Every call this
      // client makes is same-origin (API_PREFIX is a relative path), so this
      // never sends the cookie anywhere it wasn't already going.
      credentials: 'same-origin',
      // Only the two session calls set this (refresh, logout). It lets the
      // request finish — and its Set-Cookie land in the cookie jar — even if
      // the page that sent it closes or navigates away first. Without it a
      // rotation the hub has already committed can lose its new cookie with
      // the tab, and the browser's next refresh presents the token the hub
      // just retired: reproduced live on 2026-10-11, where it revoked the
      // whole session and was audited as a stolen-token replay.
      keepalive: options.keepalive,
    })
  } catch {
    throw new ApiError('Network error', 0, 'Could not reach the ARGUS hub API.')
  }

  if (!res.ok) {
    let title = `Request failed (${res.status})`
    let detail = ''
    let type = ''
    let confirmationToken = ''
    try {
      const problem = (await res.json()) as Partial<ProblemDetails>
      if (problem.title) title = problem.title
      if (problem.detail) detail = problem.detail
      if (problem.type) type = problem.type
      if (typeof problem.confirmationToken === 'string') confirmationToken = problem.confirmationToken
    } catch {
      // Body wasn't problem+json (or wasn't JSON at all) — fall back to the
      // generic status-based title above, and leave `type` empty rather than
      // inventing one: a caller branching on a type must not match anything
      // here, since we don't actually know what failed.
    }
    throw new ApiError(title, res.status, detail, type, confirmationToken)
  }

  if (res.status === 204) {
    // Read the (empty) body anyway. A response whose body stream is never
    // consumed is reported by Chromium as cancelled — net::ERR_ABORTED in
    // DevTools and in any network log — although the request succeeded,
    // which made every sign-out and token revocation look like a failure.
    if (typeof res.text === 'function') await res.text().catch(() => '')
    return undefined as TResponse
  }
  return (await res.json()) as TResponse
}

export function login(body: LoginRequest): Promise<LoginResponse> {
  return request('/auth/login', { method: 'POST', body })
}

// Federated login (PROJECT.md S2). Three of the four SSO endpoints are not
// reached from here: /auth/sso/start and /auth/sso/callback are browser
// NAVIGATIONS rather than fetches (the whole point is that the identity
// provider redirects the browser, which fetch cannot do), so the login page
// sets window.location for the first and the provider sends the browser to the
// second. Only these two are real API calls.
export function ssoProviders(): Promise<SSOProvidersResponse> {
  return request('/auth/sso/providers', { method: 'GET' })
}

// Trades the single-use handoff code from the callback redirect for a real
// token pair. Returns the same LoginResponse shape as a password login on
// purpose — a federated session is not a different kind of session.
export function ssoExchange(code: string): Promise<LoginResponse> {
  return request('/auth/sso/exchange', { method: 'POST', body: { code } })
}

// handleRefresh's response carries the account's real mustChangePassword
// (internal/api/auth.go reads it from the users row), so a session restored
// on page load knows what the sign-in response told the original one.
//
// Takes no refresh token as a parameter (PROJECT.md B164): there is nothing
// in JavaScript to pass any more. The browser attaches the HttpOnly
// argus_refresh cookie itself, scoped by the server to exactly this path
// prefix (internal/api/auth.go's refreshCookiePath) — request()'s
// credentials: 'same-origin' is what makes that happen.
export function refresh(): Promise<LoginResponse> {
  return request('/auth/refresh', { method: 'POST', keepalive: true })
}

// logout is POST /api/v1/auth/logout (PROJECT.md B164): ends the current
// refresh token's WHOLE rotation family server-side (not just this tab's
// local state) and clears the cookie. Like refresh above, there is no token
// to pass — the cookie is what identifies which session to end.
//
// Its failure never blocks the local sign-out the person asked for (see
// AuthContext.tsx's logout) — but it is awaited and reported, so a sign-out
// the hub never confirmed is not presented as one it did.
export function logout(): Promise<void> {
  return request('/auth/logout', { method: 'POST', keepalive: true })
}

// `archived` is a trailing OPTIONAL parameter for the same reason
// getIncidents' later filters are: every existing call site — the cluster
// pickers on Overview, Audit log, Users, Insights and ClusterGroupsCard, and
// the fleet list itself — keeps compiling unchanged AND keeps getting the
// hub's default, which excludes retired clusters. Excluding a decommissioned
// cluster from a picker is therefore not something each of those call sites
// has to remember; it is what happens when they say nothing.
export function getClusters(
  accessToken: string,
  archived?: 'exclude' | 'only' | 'include',
): Promise<ClustersResponse> {
  const query = archived ? `?archived=${archived}` : ''
  return request(`/clusters${query}`, { accessToken })
}

// Mints a short-lived, single-use ticket for the GET /ws/events upgrade
// handshake (internal/api/ws.go) — a browser's WebSocket API can't attach
// an Authorization header the way every other request here does, so a
// ticket obtained through a normal authenticated call is passed as a query
// parameter on the immediately-following upgrade request instead. See
// that Go file's package comment for the full reasoning.
export function createWSTicket(accessToken: string): Promise<WSTicketResponse> {
  return request('/ws/ticket', { method: 'POST', accessToken })
}

export function getCluster(id: string, accessToken: string): Promise<ClusterDetail> {
  return request(`/clusters/${id}`, { accessToken })
}

// clusterId/state/fleetGroupId/workloadGroupId/search/sort/direction/
// objectGroupId are all optional — omitting them (every existing call site,
// for clusterId/state) preserves the original "every incident across the
// tenant, every state, newest first" behavior unchanged. ClusterDetailPage
// passes clusterId to scope this same endpoint down to one cluster's own
// incidents; IncidentsPage's fleet-group filter (reached from OverviewPage's
// "Fleet-wide issues" section) passes fleetGroupId; workloadGroupId is its
// replica-level counterpart and objectGroupId (BACKLOG.md A3b) its
// cross-object one. search/sort/direction are BACKLOG P10 — moving
// IncidentsPage's free-text search and column sort server-side, added as new
// trailing parameters rather than reshaping this into an options object, so
// every existing positional call site (ClustersPage, ClusterDetailPage,
// OverviewPage) keeps compiling unchanged; objectGroupId is a later trailing
// addition for the identical reason. (GET /api/v1/incidents?
// clusterId=&state=&fleetGroupId=&workloadGroupId=&search=&sort=&direction=&
// objectGroupId=, internal/api/incidents.go's handleListIncidents) — one
// endpoint, no separate one for any of these.
export function getIncidents(
  accessToken: string,
  clusterId?: string,
  state?: string,
  fleetGroupId?: string,
  workloadGroupId?: string,
  search?: string,
  sort?: IncidentSortKey,
  direction?: IncidentSortDirection,
  // objectGroupId (BACKLOG.md A3b) is a new trailing parameter, appended
  // rather than inserted earlier, for the same reason search/sort/direction
  // were: every existing positional call site keeps compiling unchanged.
  objectGroupId?: string,
  // The incident list's severity dropdown and status tabs (pages/incidentFilters.ts).
  severity?: string,
  status?: string,
  // Whole-set look-alike group counts (PROJECT.md UX13).
  groups?: 'lookalike',
): Promise<IncidentsResponse> {
  const params = new URLSearchParams()
  if (groups) params.set('groups', groups)
  if (clusterId) params.set('clusterId', clusterId)
  if (state) params.set('state', state)
  if (severity) params.set('severity', severity)
  if (status) params.set('status', status)
  if (fleetGroupId) params.set('fleetGroupId', fleetGroupId)
  if (workloadGroupId) params.set('workloadGroupId', workloadGroupId)
  if (search) params.set('search', search)
  if (sort) params.set('sort', sort)
  if (direction) params.set('direction', direction)
  if (objectGroupId) params.set('objectGroupId', objectGroupId)
  const query = params.toString()
  return request(`/incidents${query ? `?${query}` : ''}`, { accessToken })
}

// getIncidentCounts asks the incident list for its COUNTS and deliberately
// throws the rows away (`?limit=1`, the smallest page the hub accepts).
//
// WHY A SECOND REQUEST RATHER THAN READING getIncidents' OWN counts. The
// counts on any list response are scoped exactly like that request. The
// Overview fetches incidents unscoped — its charts need the whole recent
// array and scope it client-side — so when an operator narrows the page to one
// cluster, those counts still describe the fleet. Putting a fleet number under
// a tile labelled with one cluster's name is the fabricated-figure failure
// mode, not a rounding error, so the tiles get their own correctly-scoped
// request instead of a number that is right two thirds of the time.
//
// It is cheap on purpose: one row, and the counts are five FILTERed aggregates
// over an index the list query already uses.
export function getIncidentCounts(
  accessToken: string,
  clusterId?: string,
): Promise<IncidentQuickViewCounts> {
  const params = new URLSearchParams({ limit: '1' })
  if (clusterId) params.set('clusterId', clusterId)
  return request<IncidentsResponse>(`/incidents?${params.toString()}`, { accessToken }).then((r) => r.counts)
}

// The fleet Overview's whole-set incident aggregates (GET /incidents/overview):
// open incidents per state and per cluster, and a per-day series. Every figure
// is a server aggregate, so nothing here is counted from a capped page.
export function getIncidentOverview(
  accessToken: string,
  opts: { clusterId?: string; days?: number } = {},
): Promise<IncidentOverview> {
  const params = new URLSearchParams()
  if (opts.clusterId) params.set('clusterId', opts.clusterId)
  if (opts.days) params.set('days', String(opts.days))
  const query = params.toString()
  return request(`/incidents/overview${query ? `?${query}` : ''}`, { accessToken })
}

// The incidents waiting on a person (?requiresAction=true), worst first. The
// response's counts.requiresAction is the whole-set total; the rows are capped
// at `limit`, so a caller compares the two before claiming it has them all.
export function getIncidentQueue(
  accessToken: string,
  opts: { clusterId?: string; limit?: number } = {},
): Promise<IncidentsResponse> {
  const params = new URLSearchParams({ requiresAction: 'true', sort: 'severity', direction: 'desc' })
  if (opts.clusterId) params.set('clusterId', opts.clusterId)
  if (opts.limit) params.set('limit', String(opts.limit))
  return request(`/incidents?${params.toString()}`, { accessToken })
}

export function getIncident(id: string, accessToken: string): Promise<IncidentDetail> {
  return request(`/incidents/${id}`, { accessToken })
}

// GET /incidents/digest — BACKLOG.md T2 (candidate 2): the same incidents,
// grouped by fingerprint. Accepts the identical scope parameters as
// getIncidents above (see internal/api/incident_digest.go's own doc
// comment for why): no ?sort=/?direction=/?cursor= here, since a digest of
// a bounded number of GROUPS earns none of the list's keyset-pagination
// machinery.
export function getIncidentsDigest(
  accessToken: string,
  clusterId?: string,
  state?: string,
  search?: string,
  fleetGroupId?: string,
  workloadGroupId?: string,
  objectGroupId?: string,
): Promise<IncidentDigestResponse> {
  const params = new URLSearchParams()
  if (clusterId) params.set('clusterId', clusterId)
  if (state) params.set('state', state)
  if (search) params.set('search', search)
  if (fleetGroupId) params.set('fleetGroupId', fleetGroupId)
  if (workloadGroupId) params.set('workloadGroupId', workloadGroupId)
  if (objectGroupId) params.set('objectGroupId', objectGroupId)
  const query = params.toString()
  return request(`/incidents/digest${query ? `?${query}` : ''}`, { accessToken })
}

// GET .../timeline (BACKLOG.md B1) — the incident's own chronology, per
// internal/api/timeline.go. Gated identically to getIncident itself
// (incident:read), and separate from it because it is a separate resource,
// not because it needs a stricter or looser check.
export function getIncidentTimeline(id: string, accessToken: string): Promise<TimelineResponse> {
  return request(`/incidents/${id}/timeline`, { accessToken })
}

// GET .../evidence/{evId} (BACKLOG.md B2) — one dispatched tool call's own
// args/result/error, lazily. Same incident:read gate as getIncident — see
// internal/api/handleGetEvidence's own doc comment for why no stricter
// capability applies.
export function getEvidence(incidentId: string, evidenceId: string, accessToken: string): Promise<EvidenceDetail> {
  return request(`/incidents/${incidentId}/evidence/${evidenceId}`, { accessToken })
}

// POST /clusters/{id}/inspect/{tool} (docs/CLUSTER_INSIGHT_SPECS.md CI-S6) —
// one allowlisted read-only agent tool, run on behalf of the signed-in person.
// Gated on cluster:inspect for that specific cluster. `result` is the tool's
// own JSON, already redacted by the agent; its shape depends on the tool, so
// callers narrow it with the type parameter.
export interface InspectResult<T = unknown> {
  tool: string
  receivedAt: string
  result: T
}

export function inspectCluster<T = unknown>(
  clusterId: string,
  tool: string,
  args: Record<string, unknown>,
  accessToken: string,
): Promise<InspectResult<T>> {
  return request(`/clusters/${encodeURIComponent(clusterId)}/inspect/${encodeURIComponent(tool)}`, {
    method: 'POST',
    body: args,
    accessToken,
  })
}

// POST /incidents/{id}/analyze answers 202 once the run is claimed
// (PROJECT.md M1) — the investigation continues server-side, and the incident
// (state Investigating, then the analysis or analysisError) is where its
// outcome appears. A 409 analysis-in-progress means one is already running.
export function analyzeIncident(id: string, accessToken: string): Promise<AnalysisStarted> {
  return request(`/incidents/${id}/analyze`, { method: 'POST', accessToken })
}

// GET /users/me — the signed-in account, read after every sign-in path
// (PROJECT.md B165). No specific capability required, like its two siblings
// below: being authenticated as yourself is enough to learn who you are.
//
// The response is validated here rather than trusted, and that guard is the
// point of this wrapper. An unmatched path under /api/v1/ does not 404 on this
// hub — it falls through to the SPA handler and returns index.html with HTTP
// 200 (internal/api/static.go's catch-all). A bundle served by a hub too old
// to have this route would therefore be handed a page of HTML where it asked
// for an identity, and `request` would either throw on the JSON parse or, on a
// lenient body, produce an object with no email. Both must end as "we do not
// know who you are", never as a name on screen, so anything that is not an
// object carrying a non-empty string email is rejected as an error.
export async function getMe(accessToken: string): Promise<MeResponse> {
  const body = await request<Partial<MeResponse>>('/users/me', { accessToken })
  if (!body || typeof body.email !== 'string' || body.email === '' || typeof body.userId !== 'string') {
    throw new ApiError(
      'Could not read the signed-in account',
      0,
      'The hub did not return an identity for this session.',
    )
  }
  return {
    userId: body.userId,
    email: body.email,
    // Anything other than the one value that unlocks the password control is
    // treated as 'federated', which is the safe direction: it disables that
    // control (with a reason) rather than offering a flow the hub may refuse.
    authMethod: body.authMethod === 'password' ? 'password' : 'federated',
    // Falls back to the hub's own shipped defaults — same reasoning as
    // authMethod above, for an older hub build that predates these four
    // fields (PROJECT.md, 2026-10-14) and simply omits them.
    primaryColorId: typeof body.primaryColorId === 'string' && body.primaryColorId !== '' ? body.primaryColorId : 'teal',
    overviewDefaultWindowDays: body.overviewDefaultWindowDays === 30 ? 30 : 14,
    minPasswordLength: typeof body.minPasswordLength === 'number' && body.minPasswordLength > 0 ? body.minPasswordLength : 12,
    sessionIdleTimeoutMinutes:
      typeof body.sessionIdleTimeoutMinutes === 'number' ? body.sessionIdleTimeoutMinutes : null,
  }
}

export function getEffectivePermissions(accessToken: string): Promise<EffectivePermissionsResponse> {
  return request('/users/me/effective-permissions', { accessToken })
}

// No specific capability required — authenticated as yourself is always
// enough to change your own password (internal/api/auth.go's
// handleChangePassword). The response mirrors LoginResponse's shape: a
// fresh access/refresh token pair, since the server-side change also
// revokes the caller's own outstanding refresh token and bumps their
// token_generation (ending every other session) — the caller (AuthContext)
// must swap in these new tokens rather than keep using the ones that
// authenticated this request.
export function changePassword(
  body: ChangePasswordRequest,
  accessToken: string,
): Promise<LoginResponse> {
  return request('/users/me/password', { method: 'PUT', body, accessToken })
}

// No specific capability required — see internal/api/roles.go's doc
// comment for why (same "not sensitive" reasoning as
// effective-permissions above). Backs SettingsPage's "Roles" tab.
export function getIdentityProviders(accessToken: string): Promise<IdentityProvidersResponse> {
  return request('/admin/identity-providers', { accessToken })
}

export function saveIdentityProvider(
  body: SaveIdentityProviderRequest,
  accessToken: string,
  id?: string,
): Promise<IdentityProvider> {
  return id
    ? request(`/admin/identity-providers/${id}`, { method: 'PUT', body, accessToken })
    : request('/admin/identity-providers', { method: 'POST', body, accessToken })
}

export function deleteIdentityProvider(id: string, accessToken: string): Promise<void> {
  return request(`/admin/identity-providers/${id}`, { method: 'DELETE', accessToken })
}

export function addIdentityGroupMapping(
  providerId: string,
  body: { groupName: string; roleId: string },
  accessToken: string,
): Promise<IdentityGroupMapping> {
  return request(`/admin/identity-providers/${providerId}/group-mappings`, { method: 'POST', body, accessToken })
}

export function deleteIdentityGroupMapping(
  providerId: string,
  mappingId: string,
  accessToken: string,
): Promise<void> {
  return request(`/admin/identity-providers/${providerId}/group-mappings/${mappingId}`, {
    method: 'DELETE', accessToken,
  })
}

export function getRoles(accessToken: string): Promise<RolesResponse> {
  return request('/roles', { accessToken })
}

// GET /applications (PROJECT.md PG19).
export function listApplications(accessToken: string): Promise<{ applications: unknown[]; truncated?: string[]; asOf?: string }> {
  return request('/applications', { accessToken })
}

// POST /clusters/{id}/rightsizing/proposals (PROJECT.md PG8).
export function proposeRightsizing(
  clusterId: string,
  body: { namespace: string; kind: string; workload: string; container: string },
  accessToken: string,
): Promise<{ incidentId: string; planId: string; outcome: string; reason: string }> {
  return request(`/clusters/${clusterId}/rightsizing/proposals`, { method: 'POST', body, accessToken })
}

// POST /clusters/{id}/agent-upgrade (PROJECT.md AD10).
export function upgradeClusterAgent(clusterId: string, accessToken: string): Promise<{ image: string; from?: string }> {
  return request(`/clusters/${clusterId}/agent-upgrade`, { method: 'POST', accessToken })
}

export function acceptCluster(
  clusterId: string,
  accessToken: string,
): Promise<AcceptClusterResponse> {
  return request(`/clusters/${clusterId}/accept`, { method: 'POST', accessToken })
}

export function decommissionCluster(
  clusterId: string,
  accessToken: string,
): Promise<DecommissionClusterResponse> {
  return request(`/clusters/${clusterId}/decommission`, { method: 'POST', accessToken })
}

export function renameCluster(
  clusterId: string,
  displayName: string,
  accessToken: string,
): Promise<RenameClusterResponse> {
  return request(`/clusters/${clusterId}/rename`, { method: 'POST', body: { displayName }, accessToken })
}

export function createEnrollmentToken(
  body: CreateEnrollmentTokenRequest,
  accessToken: string,
): Promise<CreateEnrollmentTokenResponse> {
  return request('/clusters/enrollment-tokens', { method: 'POST', body, accessToken })
}

export function listFleetTokens(accessToken: string): Promise<{ items: FleetToken[] }> {
  return request('/clusters/fleet-tokens', { accessToken })
}

export function revokeFleetToken(id: string, accessToken: string): Promise<void> {
  return request(`/clusters/fleet-tokens/${encodeURIComponent(id)}`, { method: 'DELETE', accessToken })
}

// Super-admin only, gated by org:settings:write for both the read and the
// write — there's no separate read capability for this screen.
export function getSettings(accessToken: string): Promise<Settings> {
  return request('/admin/settings', { accessToken })
}

export function updateSettings(
  body: UpdateSettingsRequest,
  accessToken: string,
): Promise<Settings> {
  return request('/admin/settings', { method: 'PUT', body, accessToken })
}

// --- Notification routing (internal/api/notification_routing.go, PROJECT.md F32) ---
//
// Both routes are behind org:settings:write — the GET too, because the rules
// name the cluster groups a reader would otherwise not be entitled to enumerate,
// and because they generalise the single webhook URL that capability already
// gates. A viewer without it gets a 403 from BOTH, so the screen's read path
// and its write path fail together rather than showing a table nobody can save.

export function getNotificationRouting(accessToken: string): Promise<NotificationRoutingResponse> {
  return request('/admin/notification-routing', { accessToken })
}

// Whole-set replacement in one transaction, and it returns the same shape the
// GET does — re-read AFTER the write, so the caller never has to guess what the
// hub made of what it sent (a destination's stored URL kept, a rule's priority
// normalised). Feed the response straight back into the query cache rather than
// keeping the locally-built table.
export function updateNotificationRouting(
  body: UpdateNotificationRoutingRequest,
  accessToken: string,
): Promise<NotificationRoutingResponse> {
  return request('/admin/notification-routing', { method: 'PUT', body, accessToken })
}

// --- AI providers (internal/api/ai_providers.go) ---
//
// Several providers can be configured; one is active, and the active one is
// what every investigation uses. Every mutation returns the full list back, so
// callers never have to guess what else changed (an activate flips two rows;
// a delete can clear the active pointer).
export function getAIProviders(accessToken: string): Promise<AIProvidersResponse> {
  return request('/admin/ai-providers', { accessToken })
}

export function createAIProvider(
  body: AIProviderRequest,
  accessToken: string,
): Promise<AIProvidersResponse> {
  return request('/admin/ai-providers', { method: 'POST', body, accessToken })
}

export function updateAIProvider(
  id: string,
  body: AIProviderRequest,
  accessToken: string,
): Promise<AIProvidersResponse> {
  return request(`/admin/ai-providers/${encodeURIComponent(id)}`, { method: 'PUT', body, accessToken })
}

export function deleteAIProvider(id: string, accessToken: string): Promise<AIProvidersResponse> {
  return request(`/admin/ai-providers/${encodeURIComponent(id)}`, { method: 'DELETE', accessToken })
}

export function activateAIProvider(id: string, accessToken: string): Promise<AIProvidersResponse> {
  return request(`/admin/ai-providers/${encodeURIComponent(id)}/activate`, { method: 'POST', accessToken })
}

// Sends one minimal live request to the provider and reports whether it worked.
// The counterpart to checkRepository below: prove the integration works now,
// rather than finding out during an incident.
//
// This one COSTS MONEY — a few tens of tokens for an `api` provider, nothing at
// all for a `cli` one (see internal/llm/probe.go). So it is only ever called
// from a click handler: never on mount, never in a useQuery, never on save or
// activate. A retry-on-mount here would bill the owner for every page load.
export function testAIProvider(id: string, accessToken: string): Promise<AIProviderTestResult> {
  return request(`/admin/ai-providers/${encodeURIComponent(id)}/test`, { method: 'POST', accessToken })
}

// GET /api/v1/diagnostics/bundle (PROJECT.md T18). Not routed through request()
// above: that helper always parses the body as the JSON value a caller wants —
// this endpoint's body IS that JSON (unlike a binary export), but the caller
// also wants the exact raw text to hand to a browser download unchanged, and
// the server-chosen filename from Content-Disposition, so it needs its own
// small fetch rather than request<DiagnosticsBundle>(...) throwing that away.
//
// probe=true asks the hub to also run a LIVE connectivity check against every
// configured AI provider and repository — the same "spends a trivial amount of
// money / makes a real outbound call" cost testAIProvider's own doc comment
// describes, generalized to a whole bundle. Never set unless the caller is
// reacting to an explicit, separate opt-in control — never on mount, never
// polled, matching testAIProvider's own rule.
export async function getDiagnosticsBundle(
  accessToken: string,
  probe: boolean,
): Promise<{ bundle: DiagnosticsBundle; raw: string; filename: string }> {
  let res: Response
  try {
    res = await fetch(`${API_PREFIX}/diagnostics/bundle${probe ? '?probe=true' : ''}`, {
      method: 'GET',
      headers: { Accept: 'application/json', Authorization: `Bearer ${accessToken}` },
      credentials: 'same-origin',
    })
  } catch {
    throw new ApiError('Network error', 0, 'Could not reach the ARGUS hub API.')
  }

  if (!res.ok) {
    // Mirrors request()'s own RFC 9457 handling exactly — this is a plain
    // fetch precisely so the raw body/filename are reachable on success, not
    // because the error contract should differ.
    let title = `Request failed (${res.status})`
    let detail = ''
    let type = ''
    try {
      const problem = (await res.json()) as Partial<ProblemDetails>
      if (problem.title) title = problem.title
      if (problem.detail) detail = problem.detail
      if (problem.type) type = problem.type
    } catch {
      // Not a problem+json body — fall back to the generic status title.
    }
    throw new ApiError(title, res.status, detail, type)
  }

  const raw = await res.text()
  const bundle = JSON.parse(raw) as DiagnosticsBundle

  // Content-Disposition: attachment; filename="argus-diagnostics_....json" —
  // parsed rather than reconstructed client-side, so the saved file's name
  // always matches what the hub actually generated.
  const disposition = res.headers.get('Content-Disposition') ?? ''
  const match = /filename="([^"]+)"/.exec(disposition)
  const filename = match ? match[1] : 'argus-diagnostics.json'

  return { bundle, raw, filename }
}

// Gated by org:settings:write, same as getSettings/updateSettings above —
// see internal/api/detection_dryrun.go's own doc comment for why a
// read-only simulation shares that capability rather than a broader read
// one. body is a CANDIDATE detection-settings section (never saved — see
// DetectionDryRunResponse's own doc comment in api/types.ts); days is the
// historical window to replay it against (the hub defaults to 7, accepts
// 1-90).
export function dryRunDetectionSettings(
  body: UpdateDetectionSettingsRequest,
  accessToken: string,
  days?: number,
): Promise<DetectionDryRunResponse> {
  const query = days ? `?days=${days}` : ''
  return request(`/detection/dry-run${query}`, { method: 'POST', body, accessToken })
}

// Gated by spend:read alone — deliberately narrower than
// getSettings/updateSettings above (org:settings:write), which is what
// actually configures pricing/the daily spend ceiling. A resolver holds
// spend:read but not org:settings:write (authz-spec §5's matrix), so this
// is reachable without full admin-settings access — see
// api/capabilities.ts's CAP_SPEND_READ doc comment.
export function getSpendToday(accessToken: string): Promise<SpendToday> {
  return request('/spend/today', { accessToken })
}

// Gated by user:read — see api/capabilities.ts's CAP_USER_READ.
export function getUsers(accessToken: string): Promise<UsersResponse> {
  return request('/users', { accessToken })
}

// Gated by user:manage. The response's temporaryPassword is shown to the
// admin exactly once by the caller (UsersPage) — never persisted, never
// re-fetchable.
export function createUser(
  body: CreateUserRequest,
  accessToken: string,
): Promise<CreateUserResponse> {
  return request('/users', { method: 'POST', body, accessToken })
}

// Gated by user:manage.
export function createGrant(
  userId: string,
  body: CreateGrantRequest,
  accessToken: string,
): Promise<Grant> {
  return request(`/users/${userId}/grants`, { method: 'POST', body, accessToken })
}

// Gated by user:manage. The response's temporaryPassword is shown to the
// admin exactly once by the caller (UsersPage) — same one-shot discipline as
// createUser's above. Ends every session the target user currently holds
// (both their refresh tokens and any outstanding access token) — this admin
// isn't the target user, so unlike changePassword above, no token pair for
// the target is returned; they must sign in fresh with this password.
export function resetPassword(userId: string, accessToken: string): Promise<ResetPasswordResponse> {
  return request(`/users/${userId}/reset-password`, { method: 'POST', accessToken })
}

// Gated by user:manage. Sets disabled_at and immediately ends every session
// the target currently holds -- both refresh tokens and any outstanding
// access token (same authz.RevokeAllRefreshTokens + token_generation-bump
// mechanism resetPassword above uses) -- so a disabled user can't keep
// using an already-issued token. Rejected with 409 against an
// already-disabled user, or against the last remaining active super-admin
// disabling themselves.
export function disableUser(userId: string, accessToken: string): Promise<UserLifecycleResponse> {
  return request(`/users/${userId}/disable`, { method: 'POST', accessToken })
}

// Gated by user:manage. Clears disabled_at -- the natural inverse of
// disableUser above. Does not touch sessions; re-enabling isn't a
// security-sensitive reversal the way disabling is. Rejected with 409
// against an already-enabled user.
export function enableUser(userId: string, accessToken: string): Promise<UserLifecycleResponse> {
  return request(`/users/${userId}/enable`, { method: 'POST', accessToken })
}

// Gated by user:remove (super-admin only). Soft-removes the user from active
// management/authentication while preserving audit history; also revokes
// active grants and sessions.
export function removeUser(userId: string, accessToken: string): Promise<UserLifecycleResponse> {
  return request(`/users/${userId}`, { method: 'DELETE', accessToken })
}

// Gated by user:manage.
export function revokeGrant(
  userId: string,
  grantId: string,
  accessToken: string,
): Promise<{ grantId: string; status: string }> {
  return request(`/users/${userId}/grants/${grantId}`, { method: 'DELETE', accessToken })
}

// --- Custom roles (internal/api/custom_roles.go, BACKLOG.md S3) ---

// Gated by user:read — the same floor getUsers above uses; a custom role's
// name/capability set is no more sensitive than the grants list that route
// already returns holding the same capability names.
export function getCustomRoles(accessToken: string): Promise<CustomRolesResponse> {
  return request('/custom-roles', { accessToken })
}

// Gated by role:manage.
export function createCustomRole(
  body: CreateCustomRoleRequest,
  accessToken: string,
): Promise<CustomRole> {
  return request('/custom-roles', { method: 'POST', body, accessToken })
}

// Gated by role:manage. Capabilities only — the name is immutable through
// this route, see UpdateCustomRoleRequest's own doc comment.
export function updateCustomRole(
  id: string,
  body: UpdateCustomRoleRequest,
  accessToken: string,
): Promise<CustomRole> {
  return request(`/custom-roles/${encodeURIComponent(id)}`, { method: 'PUT', body, accessToken })
}

// Gated by role:manage. Refused with 409 while any grant still references
// this role — see the hub's own handleDeleteCustomRole doc comment.
export function deleteCustomRole(id: string, accessToken: string): Promise<{ roleId: string; status: string }> {
  return request(`/custom-roles/${encodeURIComponent(id)}`, { method: 'DELETE', accessToken })
}

// --- Cluster groups (internal/api/cluster_groups.go, BACKLOG.md S3) ---

// Gated by cluster:read — the same floor getClusters above uses.
export function getClusterGroups(accessToken: string): Promise<ClusterGroupsResponse> {
  return request('/cluster-groups', { accessToken })
}

// Gated by cluster:group:manage.
export function createClusterGroup(
  body: CreateClusterGroupRequest,
  accessToken: string,
): Promise<ClusterGroup> {
  return request('/cluster-groups', { method: 'POST', body, accessToken })
}

// Gated by cluster:group:manage. Refused with 409 while any grant is still
// scoped to this group.
export function deleteClusterGroup(id: string, accessToken: string): Promise<{ groupId: string; status: string }> {
  return request(`/cluster-groups/${encodeURIComponent(id)}`, { method: 'DELETE', accessToken })
}

// Gated by cluster:group:manage.
export function addClusterToGroup(
  groupId: string,
  clusterId: string,
  accessToken: string,
): Promise<{ groupId: string; clusterId: string }> {
  return request(`/cluster-groups/${encodeURIComponent(groupId)}/clusters`, {
    method: 'POST',
    body: { clusterId },
    accessToken,
  })
}

// Gated by cluster:group:manage.
export function removeClusterFromGroup(
  groupId: string,
  clusterId: string,
  accessToken: string,
): Promise<{ groupId: string; clusterId: string; status: string }> {
  return request(`/cluster-groups/${encodeURIComponent(groupId)}/clusters/${encodeURIComponent(clusterId)}`, {
    method: 'DELETE',
    accessToken,
  })
}

// Gated by audit:read (super-admin only). filters/cursor/limit are all
// optional and become query params on GET /api/v1/audit-events
// (internal/api/audit.go's handleListAuditEvents) — omitting all of them
// (AuditLogPage's initial load) preserves that endpoint's default behavior
// unchanged: the most recent defaultAuditEventLimit (50) events, no filter.
export function getAuditEvents(
  accessToken: string,
  filters: AuditEventFilters = {},
): Promise<AuditEventsResponse> {
  const params = new URLSearchParams()
  if (filters.actor) params.set('actor', filters.actor)
  if (filters.capability) params.set('capability', filters.capability)
  if (filters.cluster) params.set('cluster', filters.cluster)
  if (filters.resource) params.set('resource', filters.resource)
  if (filters.outcome) params.set('outcome', filters.outcome)
  if (filters.since) params.set('since', filters.since)
  if (filters.until) params.set('until', filters.until)
  if (filters.cursor) params.set('cursor', filters.cursor)
  if (filters.limit) params.set('limit', String(filters.limit))
  const query = params.toString()
  return request(`/audit-events${query ? `?${query}` : ''}`, { accessToken })
}

// Gated by audit:read. The full-record counterpart to getAuditEvents' summary
// rows — see AuditEventDetail's doc comment (api/types.ts).
export function getAuditEvent(id: string, accessToken: string): Promise<AuditEventDetail> {
  return request(`/audit-events/${id}`, { accessToken })
}

// --- Findings (PROJECT.md F31) ----------------------------------------------
//
// GET /api/v1/findings is the other half of GET /api/v1/incidents: incidents
// are what ARGUS raised, findings are everything it recorded, including what
// internal/gateway/promotion.go's evidence boundary deliberately kept as an
// observation. See internal/api/findings.go's package comment for why the
// route exists at all, and web/src/pages/SignalsPage.tsx for the screen.

export type FindingListItem = components['schemas']['FindingListItem']
export type FindingsResponse = components['schemas']['FindingsResponse']
export type FindingDisposition = components['schemas']['FindingDisposition']
export type FindingSuppressionReason = components['schemas']['FindingSuppressionReason']
export type FindingClass = components['schemas']['FindingClass']
export type FindingConfidence = components['schemas']['FindingConfidence']
export type FindingImpact = components['schemas']['FindingImpact']
export type FindingCounts = components['schemas']['FindingCounts']
export type FindingWindow = components['schemas']['FindingWindow']
export type FindingPromotionRule = components['schemas']['FindingPromotionRule']

// Every field here is an independently-ANDed query parameter on the route, and
// the names match the wire names one-for-one on purpose: a filter the screen
// offers must be one the SERVER applies, or the list shows this filter's share
// of the global most-recent-N rather than its own true set.
export type FindingFilters = {
  clusterId?: string
  reason?: string
  disposition?: FindingDisposition
  class?: FindingClass
  confidence?: FindingConfidence
  impact?: FindingImpact
  /** RFC 3339. Omitted means the server's own default window (7 days back), which it echoes in `window`. */
  since?: string
  until?: string
  limit?: number
  cursor?: string
}

// Gated by incident:read — the same capability GET /incidents/{id} already
// returns findings under, rather than a finding:read nobody could hold without
// also holding incident:read (internal/api/findings.go says why).
//
// Note what this function does NOT do: it never narrows, sorts or counts
// anything locally. `counts` on the response is exact over the whole scoped
// set and `window` is the time range the server actually resolved, and both
// stop being true the moment a caller post-filters the array.
export function getFindings(
  accessToken: string,
  filters: FindingFilters = {},
): Promise<FindingsResponse> {
  const params = new URLSearchParams()
  if (filters.clusterId) params.set('clusterId', filters.clusterId)
  if (filters.reason) params.set('reason', filters.reason)
  if (filters.disposition) params.set('disposition', filters.disposition)
  if (filters.class) params.set('class', filters.class)
  if (filters.confidence) params.set('confidence', filters.confidence)
  if (filters.impact) params.set('impact', filters.impact)
  if (filters.since) params.set('since', filters.since)
  if (filters.until) params.set('until', filters.until)
  if (filters.cursor) params.set('cursor', filters.cursor)
  if (filters.limit) params.set('limit', String(filters.limit))
  const query = params.toString()
  return request(`/findings${query ? `?${query}` : ''}`, { accessToken })
}

// Gated by incident:read AND analysis:read (internal/api/insights.go's own
// doc comment explains why both). One combined fetch for InsightsPage —
// five server-side aggregate queries in one round trip, matching how this
// screen is a single reporting view, not several independently-filterable
// lists.
export function getInsights(
  accessToken: string,
  filters: { clusterId?: string; days?: 14 | 30 | 90 } = {},
): Promise<InsightsResponse> {
  const params = new URLSearchParams()
  if (filters.clusterId) params.set('clusterId', filters.clusterId)
  if (filters.days) params.set('days', String(filters.days))
  const query = params.toString()
  return request(`/insights${query ? `?${query}` : ''}`, { accessToken })
}

// GET /api/v1/insights/remediation-quality — BACKLOG.md L4's "recommendations
// frequently rejected" and "automation candidates," a separate endpoint from
// getInsights above because it's gated on remediation:approve alone (the
// same capability GET /api/v1/approvals reads under), not incident:read +
// analysis:read. Callers must check useHasCapability(CAP_REMEDIATION_APPROVE)
// before calling this — see InsightsPage.tsx's own gating for why (a viewer
// role holds incident:read/analysis:read but not remediation:approve).
export function getInsightsRemediationQuality(
  accessToken: string,
  filters: { clusterId?: string; days?: 14 | 30 | 90 } = {},
): Promise<RemediationQualityResponse> {
  const params = new URLSearchParams()
  if (filters.clusterId) params.set('clusterId', filters.clusterId)
  if (filters.days) params.set('days', String(filters.days))
  const query = params.toString()
  return request(`/insights/remediation-quality${query ? `?${query}` : ''}`, { accessToken })
}

// Gated by remediation:approve — the same capability gates BOTH this read
// and the approve/reject writes below (internal/api/approvals.go's own doc
// comment explains why, matching org:settings:write's precedent). Backs
// ApprovalsPage's worklist.
// clusterId/actionType/riskLevel/alreadyApproved/sort/direction/cursor/limit
// are all optional query params on GET /api/v1/approvals
// (internal/api/approvals.go's handleListApprovals, PROJECT.md B167) —
// mirrors getAuditEvents' own `filters` options-object shape rather than
// getIncidents' positional one, since this endpoint had exactly one call
// site (ApprovalsPage) to update, not several to keep compiling unchanged.
// Omitting alreadyApproved defaults to the pending queue (the endpoint's own
// default, not this function inventing one) — ApprovalsPage passes it
// explicitly both ways so the "already approved" section's request reads
// the same as the pending one's.
export interface ApprovalFilters {
  clusterId?: string
  actionType?: string
  riskLevel?: 'low' | 'medium' | 'high'
  alreadyApproved?: boolean
  sort?: ApprovalSortKey
  direction?: ApprovalSortDirection
  cursor?: string
  limit?: number
}

export function getApprovals(accessToken: string, filters: ApprovalFilters = {}): Promise<ApprovalsResponse> {
  const params = new URLSearchParams()
  if (filters.clusterId) params.set('clusterId', filters.clusterId)
  if (filters.actionType) params.set('actionType', filters.actionType)
  if (filters.riskLevel) params.set('riskLevel', filters.riskLevel)
  if (filters.alreadyApproved !== undefined) params.set('alreadyApproved', String(filters.alreadyApproved))
  if (filters.sort) params.set('sort', filters.sort)
  if (filters.direction) params.set('direction', filters.direction)
  if (filters.cursor) params.set('cursor', filters.cursor)
  if (filters.limit) params.set('limit', String(filters.limit))
  const query = params.toString()
  return request(`/approvals${query ? `?${query}` : ''}`, { accessToken })
}

// Gated by remediation:approve. Approving IS executing: the hub signs the
// plan, re-reads a live resourceVersion as a precondition, and patches the
// target cluster in the same request, moving the incident to Validating.
// (This comment previously said execution wasn't built — it has been since
// WORKLOG §69, and was verified end to end against a live cluster in §87.)
//
// confirmScaleFromZero is the operator's explicit "yes, turn this workload
// back on" for a target the hub finds LIVE at 0 replicas. It defaults to
// false and is sent as false — a workload at zero is treated as deliberately
// switched off, and the hub refuses to scale it up (409,
// PROBLEM_SCALE_FROM_ZERO_REFUSED) unless this says otherwise. Passing it
// must always be a fresh, deliberate act by a human on one specific plan, so
// no caller should ever remember it, default it on, or send it on the first
// attempt: ApprovalsPage only sets it when re-submitting after the hub has
// actually refused.
// confirmGitOpsManaged is the same kind of statement for the second guardrail:
// "yes, I accept this in-place fix is a stop-gap on an object whose source of
// truth is a Helm release or a Git manifest, and I will change that source."
//
// Both are listed explicitly and normalised to a real boolean rather than
// spread from the options object. That is not style: the flags are passed
// through as a variable from a lookup table, so TypeScript's excess-property
// check does not apply, and an earlier version of this function silently
// DROPPED confirmGitOpsManaged while still compiling — the confirm button sent
// nothing and the hub refused the retry forever. Naming each field here means a
// future third guardrail fails to compile instead of failing silently.
export function approveIncident(
  incidentId: string,
  accessToken: string,
  options: { confirmScaleFromZero?: boolean; confirmGitOpsManaged?: boolean; confirmationToken?: string } = {},
): Promise<ApprovalDecisionResponse> {
  return request(`/incidents/${incidentId}/approve`, {
    method: 'POST',
    accessToken,
    body: {
      confirmScaleFromZero: options.confirmScaleFromZero === true,
      confirmGitOpsManaged: options.confirmGitOpsManaged === true,
      // Echoes back the token the refusal minted (ApiError.confirmationToken)
      // — required for either boolean above to actually be honoured; see
      // internal/authz.GuardrailConfirmationIssuer.
      confirmationToken: options.confirmationToken ?? '',
    },
  })
}

// Preflight: ask the cluster what this plan would do, without doing it.
//
// POST rather than GET because it is not inert — a server-side dry run runs the
// full admission chain, so a mutating webhook that does not declare
// `sideEffects: NoneOnDryRun` still fires. Nothing is persisted and no approval
// is recorded.
//
// No body, deliberately. The approve endpoint takes guardrail confirmations;
// this one must never forward them, because those tokens are single-use and
// spending one here would leave the operator's real approval refused by the
// guardrail they had just confirmed.
export function preflightIncident(incidentId: string, accessToken: string): Promise<PreflightResponse> {
  return request(`/incidents/${incidentId}/preflight`, { method: 'POST', accessToken })
}

// The expandable detail behind a toleration row: the incident the rule was
// created from (with that incident's analysis and the remediation ARGUS
// proposed), and which findings the rule has actually suppressed. Fetched on
// expand rather than with the list, so neither a rule that has suppressed
// thousands of findings nor an incident with a long causal chain costs anything
// until someone looks.
export function getToleration(tolerationId: string, accessToken: string): Promise<TolerationDetail> {
  return request(`/tolerations/${tolerationId}`, { accessToken })
}

// Git repository bindings (repo:read / repo:write). The token is write-only:
// it is sent here and never returned by any endpoint.
export function getRepositories(accessToken: string): Promise<RepositoriesResponse> {
  return request('/repositories', { accessToken })
}

export function createRepository(
  body: CreateRepositoryBindingRequest,
  accessToken: string,
): Promise<RepositoryBinding> {
  return request('/repositories', { method: 'POST', body, accessToken })
}

// A genuine partial update — every field in body is independently optional,
// and omitting one leaves it exactly as stored (UpdateRepositoryBindingRequest's
// own doc comment). Unlike createRepository, token is optional here too: it
// only rotates the credential when supplied.
export function updateRepository(
  id: string,
  body: UpdateRepositoryBindingRequest,
  accessToken: string,
): Promise<RepositoryBinding> {
  return request(`/repositories/${id}`, { method: 'PUT', body, accessToken })
}

export function deleteRepository(id: string, accessToken: string): Promise<void> {
  return request(`/repositories/${id}`, { method: 'DELETE', accessToken })
}

// Proves the credential works now, rather than letting a failing remediation PR
// be the first thing to discover it does not.
export function checkRepository(id: string, accessToken: string): Promise<RepositoryCheckResult> {
  return request(`/repositories/${id}/check`, { method: 'POST', accessToken })
}

// F30's discover/confirm/decline trio for the incident-detail Helm-link flow
// (LinkHelmReleaseForm in IncidentDetailPage.tsx). All three are gated at the
// route server-side by resolveHelmReleaseTarget, not by anything sent here —
// the release/namespace/object identity always comes from the incident's own
// stored ownership.
export function discoverRepositoryLink(
  incidentId: string,
  accessToken: string,
): Promise<DiscoverRepositoryLinkResponse> {
  return request(`/incidents/${incidentId}/discover-repository-link`, { method: 'POST', accessToken })
}

export function confirmRepositoryLink(
  incidentId: string,
  body: ConfirmRepositoryLinkRequest,
  accessToken: string,
): Promise<RepositoryBinding> {
  return request(`/incidents/${incidentId}/confirm-repository-link`, { method: 'POST', body, accessToken })
}

export function declineRepositoryLink(incidentId: string, accessToken: string): Promise<void> {
  return request(`/incidents/${incidentId}/decline-repository-link`, { method: 'POST', accessToken })
}

// Human incident close-out, gated by incident:triage — distinct from
// approve/reject, which decide the fate of a proposed plan. These decide the
// fate of the incident itself, which matters because most incidents never
// produce a plan at all: of seven fault types driven end to end, five had no
// executable fix (CAPABILITIES.md §2). Without these the only exits from
// the open set ran through remediation, so anything fixed by hand stayed open
// forever.
//
// resolve: the problem is gone (fixed, or the object no longer exists).
// A note is optional.
export function resolveIncident(
  incidentId: string,
  accessToken: string,
  note?: string,
): Promise<IncidentTriageResponse> {
  return request(`/incidents/${incidentId}/resolve`, { method: 'POST', body: { note: note ?? '' }, accessToken })
}

// dismiss: the problem is real but needs no action. The note is REQUIRED —
// the hub 400s without one, deliberately, because Dismissed is terminal and
// nobody should be able to permanently silence a real problem without saying
// why.
export function dismissIncident(
  incidentId: string,
  note: string,
  accessToken: string,
): Promise<IncidentTriageResponse> {
  return request(`/incidents/${incidentId}/dismiss`, { method: 'POST', body: { note }, accessToken })
}

// Gated by remediation:reject. reason is required (internal/api/approvals.go
// rejects an empty one with 400) — moves the incident to Dismissed.
export function rejectIncident(
  incidentId: string,
  reason: string,
  accessToken: string,
): Promise<ApprovalDecisionResponse> {
  return request(`/incidents/${incidentId}/reject`, { method: 'POST', body: { reason }, accessToken })
}

// Gated by incident:silence. note is required, same rationale as dismiss's.
// reasons omitted/empty (with allReasons false) lets the hub default to
// exactly the reasons already on this incident's findings — "tolerate what
// I'm looking at" — rather than the caller having to enumerate them.
// expiresInSeconds omitted means the rule never expires.
export function tolerateIncident(
  incidentId: string,
  accessToken: string,
  options: { note: string; reasons?: string[]; allReasons?: boolean; expiresInSeconds?: number },
): Promise<TolerateIncidentResponse> {
  return request(`/incidents/${incidentId}/tolerate`, {
    method: 'POST',
    accessToken,
    body: {
      note: options.note,
      reasons: options.reasons ?? [],
      allReasons: options.allReasons === true,
      expiresInSeconds: options.expiresInSeconds,
    },
  })
}

// Gated by incident:silence. Every active (non-removed) rule visible to the
// caller's RLS scope, newest first — the management surface behind
// TolerationsPage.
export function listTolerations(accessToken: string): Promise<Toleration[]> {
  return request('/tolerations', { accessToken })
}

// Gated by incident:silence. Soft-deletes the rule — future findings on that
// object resume opening incidents normally.
export function removeToleration(tolerationId: string, accessToken: string): Promise<void> {
  return request(`/tolerations/${tolerationId}`, { method: 'DELETE', accessToken })
}

// The repository-change channel: three calls, one request shape.
//
// A change is a set of WHOLE FILES — `{files: [{path, content}], reason}` — one
// file or many, against any repository kind, Helm and Kustomize included. ARGUS
// computes the diff; a caller never sends one. See RepositoryChangeRequest in
// ./types for why the single-field grammar was removed.
//
// All three require repo:write + remediation:approve + remediation:execute:pr,
// checked at the route and again per-cluster in the handler. The read route
// carries the same three despite writing nothing: it returns real repository
// content, so whoever can call it can read any file the binding reaches under
// the synced directory.

// Fetches the CURRENT, unedited content of one file at the pinned synced
// commit — what an editor is seeded with, and what a client re-reads to add a
// second file to the same change. filePath is optional: omit it and ARGUS finds
// the one file under the synced directory that defines this incident's object,
// refusing if there are none or several.
export function getRepositoryFile(
  incidentId: string,
  filePath: string | undefined,
  accessToken: string,
): Promise<RepositoryFileResponse> {
  const query = filePath ? `?filePath=${encodeURIComponent(filePath)}` : ''
  return request(`/incidents/${incidentId}/repository-change/file${query}`, { accessToken })
}

// What the pull request WOULD contain, with nothing branched or committed.
//
// Runs the same read-and-verify pipeline as the open call — gitops.PreviewChanges
// and gitops.ProposeChanges share prepareChanges verbatim, the preview simply
// stopping where the other cuts a branch — so the diffs shown here are the diffs
// that would be committed, not a separate estimate of them. Every refusal the
// open call can make is reachable here too, which is the point: a refusal that
// costs a request beats one that costs a branch.
//
// Callable repeatedly as the operator edits, and it is also how a multi-file
// change is assembled: send every file you have so far and show the whole set of
// diffs before anything is proposed.
export function previewRepositoryChange(
  incidentId: string,
  body: RepositoryChangeRequest,
  accessToken: string,
): Promise<RepositoryPreviewResponse> {
  return request(`/incidents/${incidentId}/repository-change/preview`, {
    method: 'POST',
    body,
    accessToken,
  })
}

// Opens the pull request. Every refusal — a forbidden path, a file outside the
// synced directory, empty or over-large content, plain YAML that does not parse,
// a duplicate path, content that would write a redaction marker, nothing
// differing from the repository, drift since the synced commit — arrives as an
// ApiError whose detail is the reason, and that reason is the most useful thing
// this endpoint produces. Shown in full, never summarised.
export function openRepositoryChange(
  incidentId: string,
  body: RepositoryChangeRequest,
  accessToken: string,
): Promise<RepositoryChangeResponse> {
  return request(`/incidents/${incidentId}/repository-change`, { method: 'POST', body, accessToken })
}

// Undo one execution (remediation:rollback + remediation:execute:inplace). Every
// refusal — a failed execution, one already undone, a field somebody else has
// moved, a value that is already back where the undo wants it — arrives as an
// ApiError whose detail explains which and what to do instead.
export function rollbackExecution(
  executionId: string,
  body: RollbackRequest,
  accessToken: string,
): Promise<RollbackResponse> {
  return request(`/executions/${executionId}/rollback`, { method: 'POST', body, accessToken })
}

// Every change ARGUS has made recently, across every incident (incident:read +
// analysis:read) — the front door for the undo above, which was previously
// reachable only by someone who already knew which incident made the change.
//
// Every filter is a request parameter, never a client-side pass over a fetched
// array: the list is capped server-side, so narrowing it here would show the
// selection's share of the global most-recent-N rather than its own.
export function listChanges(
  params: { windowHours?: number; clusterId?: string; limit?: number },
  accessToken: string,
): Promise<ChangesResponse> {
  const query = new URLSearchParams()
  if (params.windowHours !== undefined) query.set('windowHours', String(params.windowHours))
  if (params.clusterId) query.set('clusterId', params.clusterId)
  if (params.limit !== undefined) query.set('limit', String(params.limit))
  const suffix = query.toString()
  return request(`/changes${suffix ? `?${suffix}` : ''}`, { accessToken })
}

// Maintenance and freeze windows (org:settings:write). The hub validates the
// schedule at write time — a bad cron expression, an absurd duration, an unknown
// timezone, or a freeze with no reason all come back as an ApiError whose detail
// names what was wrong, rather than being accepted and failing to open later.
export function getAutomationWindows(accessToken: string): Promise<AutomationWindowsResponse> {
  return request('/admin/automation-windows', { accessToken })
}

export function createAutomationWindow(
  body: CreateAutomationWindowRequest,
  accessToken: string,
): Promise<{ id: string }> {
  return request('/admin/automation-windows', { method: 'POST', body, accessToken })
}

export function deleteAutomationWindow(id: string, accessToken: string): Promise<void> {
  return request(`/admin/automation-windows/${id}`, { method: 'DELETE', accessToken })
}


// The circuit breaker (org:settings:write, same as the windows above).
export function getCircuitBreaker(accessToken: string): Promise<CircuitBreakerResponse> {
  return request('/admin/circuit-breaker', { accessToken })
}

// Resets one trip by id, not "the breaker": a cluster trip and a fleet-wide trip
// can be open at once, and an operator who has read one reason has not necessarily
// read the other. A 404 means it was already reset — by this operator in another
// tab, or by someone else.
export function resetCircuitBreaker(
  id: string,
  note: string,
  accessToken: string,
): Promise<{ reset: boolean }> {
  return request(`/admin/circuit-breaker/${id}/reset`, { method: 'POST', body: { note }, accessToken })
}

// ---------------------------------------------------------------- cluster insight
// docs/CLUSTER_INSIGHT_SPECS.md — the hub routes behind the inspector, the
// incident's change/metrics sections, upgrade readiness, search and quick
// actions. Each is capability-gated server-side; see docs/openapi.yaml.

export function getResourceChanges(
  clusterId: string,
  q: { namespace?: string; kind?: string; name?: string; since?: string; until?: string; limit?: number },
  accessToken: string,
): Promise<ResourceChangeList> {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(q)) if (v !== undefined && v !== '') p.set(k, String(v))
  return request(`/clusters/${encodeURIComponent(clusterId)}/resource-changes?${p}`, { accessToken })
}

export function getIncidentPrecedingChanges(
  incidentId: string,
  accessToken: string,
): Promise<ResourceChangeList & { since?: string }> {
  return request(`/incidents/${encodeURIComponent(incidentId)}/preceding-changes`, { accessToken })
}

export function getIncidentMetrics(incidentId: string, range: '1h' | '6h' | '24h', accessToken: string): Promise<IncidentMetrics> {
  return request(`/incidents/${encodeURIComponent(incidentId)}/metrics?range=${range}`, { accessToken })
}

// PROJECT.md AD7: the object panel's Metrics tab.
export function getWorkloadMetrics(
  clusterId: string,
  obj: { kind: string; namespace: string; name: string },
  range: '1h' | '6h' | '24h',
  accessToken: string,
): Promise<WorkloadMetrics> {
  const p = new URLSearchParams({ kind: obj.kind, namespace: obj.namespace, name: obj.name, range })
  return request(`/clusters/${encodeURIComponent(clusterId)}/workload-metrics?${p}`, { accessToken })
}

export function getLatestUpgradeScan(clusterId: string, accessToken: string): Promise<UpgradeScanEnvelope> {
  return request(`/clusters/${encodeURIComponent(clusterId)}/upgrade-scans/latest`, { accessToken })
}

export function runUpgradeScan(clusterId: string, targetVersion: string, accessToken: string): Promise<UpgradeScanEnvelope> {
  return request(`/clusters/${encodeURIComponent(clusterId)}/upgrade-scans`, {
    method: 'POST',
    body: targetVersion ? { targetVersion } : {},
    accessToken,
  })
}

export function getFleetUpgradeScans(accessToken: string): Promise<{ scans: UpgradeScan[] }> {
  return request('/upgrade-scans/latest', { accessToken })
}

/** Every readable cluster's facts digest and stored fleet checks, in one read. */
export function getFleetSummary(accessToken: string): Promise<FleetSummary> {
  return request('/fleet/summary', { accessToken })
}

export function searchObjects(q: string, accessToken: string): Promise<SearchResult> {
  return request(`/search?q=${encodeURIComponent(q)}`, { accessToken })
}

export type QuickAction =
  | 'argoRefresh'
  | 'argoHardRefresh'
  | 'fluxReconcileKs'
  | 'fluxReconcileHr'
  | 'fluxReconcileGit'
  | 'fluxReconcileHelm'
  | 'fluxReconcileOci'

export function requestQuickAction(
  incidentId: string,
  body: { action: QuickAction; namespace: string; name: string },
  accessToken: string,
): Promise<{ recommendationId: string; gateOutcome: string; gateReason: string }> {
  return request(`/incidents/${encodeURIComponent(incidentId)}/quick-actions`, { method: 'POST', body, accessToken })
}

// PROJECT.md AD1: the cluster timeline. Every filter is a query parameter so
// the hub applies it before its caps (never a client-side slice of a page).
export function getClusterTimeline(
  clusterId: string,
  q: { since: string; until: string; namespace?: string; types?: TimelineSource[]; onlyIncidents?: boolean },
  accessToken: string,
): Promise<ClusterTimeline> {
  const p = new URLSearchParams({ since: q.since, until: q.until })
  if (q.namespace) p.set('namespace', q.namespace)
  if (q.types && q.types.length < 3) p.set('types', q.types.join(','))
  if (q.onlyIncidents) p.set('onlyIncidents', 'true')
  return request(`/clusters/${encodeURIComponent(clusterId)}/timeline?${p}`, { accessToken })
}

// PROJECT.md AD3 — your own personal access tokens for the MCP endpoint.
// Listing and revoking need only a session; creating needs mcp:use. The
// secret is in createPersonalToken's response and nowhere else, ever.
export function listPersonalTokens(accessToken: string): Promise<components['schemas']['PersonalTokenList']> {
  return request('/users/me/mcp-tokens', { accessToken })
}

export function createPersonalToken(
  body: components['schemas']['CreatePersonalTokenRequest'],
  accessToken: string,
): Promise<components['schemas']['CreatePersonalTokenResponse']> {
  return request('/users/me/mcp-tokens', { method: 'POST', body, accessToken })
}

export function revokePersonalToken(id: string, accessToken: string): Promise<void> {
  return request(`/users/me/mcp-tokens/${encodeURIComponent(id)}`, { method: 'DELETE', accessToken })
}
