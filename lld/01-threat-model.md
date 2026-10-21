# LLD-01: Threat Model and Security Requirements

| | |
|---|---|
| **Document** | Low-Level Design — Threat Model and Security Requirements |
| **Status** | Maintained security requirements |
| **Date** | 2026-08-18; audited against the implementation 2026-09-08 |
| **Purpose** | Maintain the assets, trust boundaries, actors, data classification, misuse cases, and testable security-requirements register that the implementation must satisfy. |
| **Depends on** | HLD §5 (identity/tenancy), §6 (cluster lifecycle), §8.6/§18.7 (MCP/AI controls), §16 (AI provider layer), §18 (security architecture) |

This document does not re-argue accepted architecture. The decision register owns those choices; this
document asks what can go wrong and which specific, testable requirement closes each gap.

> **How to read this document after the 2026-09-08 audit.** Every stated control was checked against
> the code. Where the code did not match, the original text is **kept** and a dated correction is
> added beside it — nothing was quietly rewritten, and no risk was softened. Corrections come in two
> shapes, and the distinction matters when triaging: *"the control is absent"* (nothing implements it
> — SR-3, SR-5, SR-9, SR-13, SR-14, SR-16, and depth-limit-one in SR-12) and *"the control is thinner
> than described"* (something real exists but is weaker, narrower, or differently shaped than the
> sentence claims — the Secret exclusion, the KEK's placement, `actorId` in the plan signature,
> SR-20's `patch_field` hole, SR-23's missing egress restriction). §8 carries a per-requirement status
> table; §9's acceptances were re-checked against it. Two claims that had gone stale in the safer
> direction were also corrected: T7's repository sandbox is built (§9's row said it was unmitigated),
> and this document counts **T15–T21**, not T15–T20.

---


> ## ✅ Correction resolved (2026-08-25): capture-time redaction is now BUILT
>
> **History, kept because the shape of the mistake is instructive.** From 2026-08-24 this banner
> read *"SPECIFIED, NOT BUILT"*: the document reasoned downstream from redaction-at-capture as
> though it existed — the asset table, the boundary analysis (B5), the data-classification table and
> the residual-risk section all say evidence crosses the LLM boundary *"after redaction"* — while a
> code audit found no redaction anywhere on the evidence path. Every "after redaction" qualifier
> below was false for roughly a year of drafting. Defect: `PROJECT.md` 84; fix: `PROJECT.md` **G8**.
>
> **What is now built** (`internal/redact`, called only from `internal/agent`):
>
> - **Structural drops, at capture, in the agent, before the tunnel.** Applied depth-independently by
>   key name, so they fire on a bare Pod and equally on a Deployment's
>   `spec.template.spec.containers[*]` or a CronJob's `spec.jobTemplate...`: every
>   `env[*].value` (keeping `name`/`valueFrom`), every `data`/`stringData` value (keeping keys), and
>   the `kubectl.kubernetes.io/last-applied-configuration` annotation outright.
> - **A bounded pattern layer** over freeform strings — log lines, event/condition text in
>   `Finding.Message`, container `args`/`command` — covering PEM private keys, JWTs, bearer
>   credentials, AWS access key IDs, credentials in URL userinfo, and values of credential-implying
>   keys. Deliberately no generic high-entropy rule: it would redact image digests and
>   resourceVersions, which are load-bearing evidence.
> - **Two chokepoints, not per-call discipline.** `ToolExecutor.Execute` wraps the tool dispatch, so
>   a newly added tool is filtered before its author has an opinion about redaction; the agent's
>   tunnel writer filters `Finding.Message`, so a newly added detector is covered the same way.
>   `internal/agent/redact_egress_test.go` fails if a tool is added and left unclassified.
> - **Fails closed.** A payload `internal/redact` cannot parse or re-encode is replaced with a
>   self-describing marker, never forwarded as-is.
>
> **`denySendKinds: [Secret]` still holds and is still the more important control** — `Secret`
> objects are absent from `supportedGVKs` and the agent ClusterRole never grants access.
> §"Residual risk"'s observation that *"the actual backstop is architectural, not a better regex"*
> was correct, and G8 followed it: the primary layer drops field *classes*, and patterns are only
> the second layer for text with no structure to exploit.
>
> > **⚠️ Correction (2026-09-08 code audit): the two sentences above are no longer true of the code,
> > and the control they describe has been WEAKENED — read this before relying on any "Secret objects
> > are unfetchable" statement anywhere in this document.**
> >
> > Since 2026-08-29 the agent ClusterRole grants **a single `get` on `secrets`**
> > (`deploy/helm/argus-agent/templates/clusterrole.yaml`'s header note), and
> > `{"", "v1", "Secret"}` **is** an entry in `internal/agent/tools.go`'s `supportedGVKs`
> > (tools.go:399). So neither half of the claim above — "absent from `supportedGVKs`", "never grants
> > access" — holds. There is also no `denySendKinds`/`denySendFields` config anywhere in the
> > codebase; that name describes a design-time mechanism that was never built, and every reference
> > to it in this document should be read as naming an intent, not a switch an operator can set.
> >
> > **What is actually enforced now, and it is narrower than "unfetchable" but not nothing:**
> > `list`/`watch` on Secrets remain permanently withheld, and `list_resources` refuses `Secret`
> > outright rather than relying on the RBAC to fail closed (tools.go:1517); `Secret` is in
> > `neverAWorkloadChildKinds`, so the owner-chain walk never enumerates them; and
> > `describe_resource` is the only tool that can reach the `get`, routing every fetched Secret
> > through `secretMetadataOnly` (tools.go:1328), which builds a fresh map holding only
> > `apiVersion`, `kind`, `metadata` (name/namespace/labels/annotations/creationTimestamp) and
> > `type` — copy-in-only, so it cannot forward a field nobody named. `data`/`stringData` are never
> > marshaled, not even as redaction markers.
> >
> > **The gap this opens, stated plainly rather than absorbed:** the guarantee has moved from
> > *architectural* ("the object cannot be fetched, regardless of what is in it") to *field-level*
> > ("the object is fetched, and one function is trusted to emit only five keys of it"). That is a
> > materially weaker class of control — a bug, a refactor, or a second caller of the Secret GVR
> > would leak values, where before no code path existed to leak. Two tests
> > (`TestDescribeResource_SecretReturnsMetadataAndTypeOnly`,
> > `TestListResources_SecretCannotBeEnumerated`) are what stand in for the missing structural
> > impossibility; treat adding any second reader of `secretGVK` as a security change, not a
> > refactor. `argus-remediate` and `argus-dryrun` still hold **no** Secret verb at all.
> >
> > This does not soften §"T8"'s residual risk — it raises it, and T8's own entry below is corrected
> > to match.
>
> **So read the qualifiers below as accurate again — with these limits, which are real:**
>
> 1. The pattern layer is best-effort by construction. A credential in a log line or a container arg
>    with no recognisable format and no credential-implying key name still crosses B5. The structural
>    layer has no such gap, which is why env values are dropped as a class rather than pattern-matched.
> 2. **Accepted cost, decided deliberately:** ARGUS is now worse at "the env var holds the wrong
>    value" faults. There is no bypass, no disable flag, and no unredacted path for admins, by design.
> 3. Redaction is agent-side only, and that is the control. A hub-side filter producing identical
>    bytes would not be equivalent — by the time the hub can act, the data has already left the
>    cluster. Do not "simplify" this by moving it.
>
> **One claim in `PROJECT.md` 84 did not reproduce and is worth recording:** under the `cli` analysis
> backend, `analyses.causal_chain` came back *empty*, so the persisted copy it describes arrives via
> the model's own narrative (`root_cause`/`ruled_out`) rather than that column. `mcp_tool_calls`
> stores no args or results (migration 000037), and `evidence` blobs need an object store that local
> deployments do not run. The leak was real at the tunnel — verified directly, see below — but the
> DB-side shape differs from the defect's description.


## 1. Scope and methodology

Two threat-identification passes, combined:

1. **Asset- and boundary-driven** (top-down): enumerate what's worth attacking (§2) and where trust boundaries are actually crossed on the wire (§4), then ask what an attacker positioned at each boundary or in possession of each asset can do.
2. **Component-driven** (bottom-up, STRIDE-flavoured but not mechanically applied): for each component in HLD §4.1, ask what a compromise or misuse of that specific component enables, independent of the boundaries it happens to cross.

The HLD's own T1–T14 table (§18.1) is the output of pass 1 at architecture depth. This document keeps those fourteen (renumbered here as T1–T14 for continuity — do not renumber them again in later artifacts) and expands each into a misuse-case narrative (§6). It also adds **T15–T21** (T21 was added 2026-08-21 with the CLI investigator backend, after this sentence was first written): threats visible only once you're reasoning about specific implementation surfaces (a webhook URL field, a log-rendering component, a signature-comparison function) rather than architecture boxes — the kind of thing a threat model written at HLD altitude structurally cannot catch, and exactly what this artifact exists to add.

**What this document is not:** a penetration-test plan, a compliance control mapping (that's SOC2/ISO work, HLD §18.8, explicitly P4), or a restatement of the HLD's mitigations. Where the HLD's mitigation is already sufficient and specific, this document cites it rather than repeating it.

---

## 2. Asset inventory

Ranked by what a compromise actually costs, not by where the asset lives.

| Asset | Why it matters | Where it lives | Confidentiality/integrity requirement |
|---|---|---|---|
| **Cluster write credentials** (the `argus-remediate` service account's token, per cluster) | Direct path to mutating a managed cluster | Spoke-side only, projected SA token, never leaves the cluster (§6.4) | Integrity: must not be forgeable or replayable off-cluster. Confidentiality: cluster-scoped, no cross-cluster reuse. |
| **Agent mTLS private key** (per cluster) | Impersonating a cluster's agent to the hub | Generated and held spoke-side only; hub never sees it (§6.2) | Must never leave the spoke. Loss = re-enroll that one cluster, not a fleet-wide event (this is the design's central bet — see T5). |
| **Hub CA private key** (signs agent certs) | Compromise = mint a trusted identity for *any* cluster | Hub, envelope-encrypted, ideally in an external KMS/HSM | Single highest-value hub-side secret. Compromise blast radius = the whole fleet's trust relationship, not one cluster's. |
| **Git credentials** (fine-grained PAT / GitLab group access token — was "GitHub App private key" before `lld/14-adrs.md` D-R9; note the stored secret is now a live bearer token rather than a signing key, which RAISES the impact of disclosure, per `RepositoryBinding`) | Write access to the organisation's source of truth | Hub, envelope-encrypted (§18.6) | Scoped to specific repos, minimum `contents`+`pull_requests` (§18.5). Compromise = arbitrary commits to those repos, gated by `writeScope` (§11.1) but not by anything upstream of the credential itself. |
| **LLM provider API keys** | Spend, and (for hosted providers) the channel through which evidence leaves the deployment | **Hub, PLAINTEXT — not envelope-encrypted** (corrected 2026-09-08): `ai_providers.api_key` and `ai_providers.runner_token` are plain `text` columns (migration 000034), and `internal/secretbox` has exactly one caller, `internal/scm.Store` for the Git token. The predecessor column `org_settings.llm_api_key` said so in as many words (migration 000018) and the table inherited the gap. The only protections that do hold are write-only handling (never returned by `GET /api/v1/admin/settings`) and redaction from error paths. One per configured provider is accurate; "envelope-encrypted" is not | Compromise = financial exposure (§16.4's ceilings bound this) and potential data exfiltration if evidence was flowing to that provider. |
| **IdP/OIDC client secret** (Dex connector config) | Authentication trust anchor | Hub config, encrypted | Compromise = ability to mint sessions for arbitrary identities depending on connector type. **Status 2026-09-08: this asset does not exist yet.** No Dex/OIDC connector is built or deployed (`deploy/compose/docker-compose.yaml`'s `dex` service is commented out; `PROJECT.md` `S2` defers SSO). Login today is a local password (`internal/authz/password.go`, bcrypt + constant-time compare) issuing an ES256 JWT. Kept in the table because the row becomes live the moment `S2` is picked up — not because it is currently protecting anything. |
| **Session tokens / refresh tokens** | Authenticated user sessions | Browser (access token, short-lived) + hub DB (refresh token, hashed) | Short-lived by design (§5.3); refresh-token theft is the higher-value target since it renews. |
| **Approval tokens / plan signatures** | The thing standing between "AI proposed a change" and "change happened" | Generated hub-side, transmitted to executor over the tunnel (§10.3) | Must be unforgeable, single-use, and bound to `(incidentId, planHash, actorId)` (§5.4). This is the asset T9's misuse case targets directly. **Status 2026-09-08 — thinner than this row states, in one specific respect.** `internal/remediation.Sign` HMACs `planHash(PlanContent) \| clusterID \| expiresAt`, where `PlanContent` carries `recommendationId`, action type, target GVK/namespace/name, params, the pre-captured rollback, the live `resourceVersion` and the `dryRun` flag (`internal/remediation/sign.go`). So the envelope is unforgeable and bound to recommendation, target, cluster, live object version and expiry — but **`actorId` is not inside the signature.** The approver is bound only in the DB row and the audit chain (`internal/api/approvals.go`), and single-use is enforced by a state-guarded compare-and-swap on the incident (only `AwaitingApproval` may be approved, `approvals.go:646`/`:978`/`:1499`) rather than by burning a token. Consequence to be explicit about: a compromised hub can sign a plan attributed to an approver who never approved it — which is inside T2's stated residual risk, not outside it, but it is not what "bound to actorId" promises. |
| **Evidence blobs** (logs, describe output, rendered manifests) | May contain sensitive infrastructure detail even after redaction; the input to every LLM call | **Postgres, not an object store** (corrected 2026-09-08): the `evidence` table (migration 000005, given a real writer/reader by 000069) plus `mcp_tool_calls` (000037, which deliberately stores counts and no content). No object store is deployed or referenced by any Go code, so "tenant/scope-prefixed object store" describes an intended design, and the rows are protected by the same RLS the rest of the schema is | Redacted at capture time (§18.4), but redaction is explicitly best-effort (§18.4's own caveat) — treat residual sensitivity as non-zero. |
| **Audit log** | The record of who-did-what-when-with-what-authority; the thing regulators and incident responders actually query | Postgres, append-only, hash-chained (§14.2, §18.8) | Integrity is the primary requirement here, more than confidentiality — a tamperable audit log is worse than a missing one because it creates false confidence. |
| **Encryption master key (KEK)** | Everything envelope-encrypted in the DB is only as safe as this | External KMS/Vault, explicitly *not* the DB or app image (§18.6) | Compromise = every secret in the DB becomes readable. This is why it lives outside the DB. **⚠️ Status 2026-09-08: it does not live outside the DB.** `internal/secretbox` ships only §18.6's local-KEK evaluation mode (`KeyVersionLocalV1`), and the KEK is loaded via `internal/data.LoadOrCreateSigningKey` under purpose `secret_kek_local_v1` — i.e. **the KEK sits in the same Postgres as the ciphertext it wraps**, which is the exact placement this row says it must not have. That is a recorded owner decision (`lld/14-adrs.md` D-R9, "local KEK with a loud warning") and `Keeper.LocalKEKWarning` exists so a deployment says so out loud, but the security consequence is unchanged and worth stating without hedging: **against an attacker who can read the database, envelope encryption of the Git token currently buys nothing.** `keyVersion` travels with every ciphertext so an external-KMS KEK is a re-wrap rather than a migration; until that ships, treat every envelope-encrypted secret as plaintext-at-rest in the DB-compromise scenario. |
| **User PII** (email, name, IdP subject claim) | Comparatively low sensitivity for this product, but still personal data | Postgres `users` table | Standard access-control, not a novel concern here — noted for completeness, not because it drives new requirements. |

---

## 3. Actors and principals

Each row is "what does a compromise or malicious act by this actor actually let them do, given everything else in the design."

| Actor | Normal capability | If compromised / malicious | What limits the damage |
|---|---|---|---|
| **Viewer** | Read incidents/evidence/recommendations on their scoped clusters | Reads more than they should if a scope check is missing (T1) | RLS + capability check at every layer (§5.4) |
| **Resolver** | Viewer + approve/execute within scope | Approves a bad plan, or approves outside their actual authority if server-side re-check is missing | Re-authorisation at execution time (§5.4 layer 3), not just at click time |
| **tenant-admin** (this row's "org-admin" is not a role that exists in code; the builtin set is `super-admin`/`tenant-admin`/`resolver`/`pr-approver`/`viewer`, `internal/authz/permissions.go`) | Manage users, clusters, repos, policies | Grants themselves or a collaborator excessive scope | Grants are additive/deny-by-default (§5.2) — no path to self-escalate past the capability grammar itself; cannot touch org-wide settings reserved for super-admin |
| **pr-approver** *(added to this table 2026-09-08; the role shipped earlier and was missing here)* | Viewer + approve/reject + `CapRemediationExecPR` — may approve a pull request, may never execute in place | Can land a bad change in the repository, where a second human reviewing the PR is the gate | Holds neither `CapRemediationExecInplace` nor `CapRemediationRollback` (`internal/authz/permissions.go`'s `builtinRoleCapabilities`), and both are fail-closed-checked per action by `planApprovalGates` (`internal/api/approvals.go`) — so this role's compromise reaches Git, never a live cluster directly |
| **super-admin** | Everything | Insider abuse — the one actor with no ceiling above them | Tamper-evident audit log (T14), optional two-person rule on high-risk classes (§5.2's approval-separation), break-glass grants are themselves audited (§5.5) |
| **Cluster agent (`argus-investigate`)** | Read-only evidence collection on its one cluster | Total compromise still cannot write via the K8s API (§18.3 layer 2) — its damage ceiling is "can read everything the RBAC profile allows, on one cluster". **Since 2026-10-21 that is, by default, every API group the cluster serves** (`read.allApiGroups`): everything outside the core group, minus `read.excludeApiGroups` (groups whose reads are credentials or sessions, such as Rancher tokens, OpenShift OAuth tokens, KubeVirt consoles), plus CRDs aggregated to `view`. The core group stays kind by kind, so Secret listing and contents, `*/proxy` and `pods/exec`/`attach`/`portforward` remain unreachable; output from unreviewed kinds goes through `redact.AggressiveObject` | Read-only verbs only (`get`/`list`/`watch`), no `pods/exec`, no `nodes/proxy`, no `bind`/`escalate`/`impersonate`; scoped to one cluster's own mTLS identity. **Corrected 2026-09-08: "excludes Secrets" is no longer accurate** — since 2026-08-29 this ClusterRole holds a single `get` on `secrets` (never `list`/`watch`), reachable only through `describe_resource`, whose response is rebuilt by `secretMetadataOnly` from metadata+`type` alone. The ceiling therefore includes "can confirm a named Secret exists, and read its labels/annotations/type" — not its values. See the correction inside this document's redaction banner for why that is a weaker *class* of control than the exclusion it replaced |
| **Cluster agent (`argus-dryrun`)**, where granted | Read + dry-run-only mutation | A webhook lacking `sideEffects: NoneOnDryRun` can be induced to act for real (§8.3's own caveat) — this is a **reduced**, not zero, privilege actor | Admission-policy-enforced `dryRun=All` restriction; opt-in per cluster; absence degrades gracefully (D14) |
| **Cluster agent (`argus-remediate`)**, where granted | Scoped write, opt-in per cluster | The highest-value spoke-side compromise target — but scoped by resource/namespace and gated behind signed, single-use, precondition-checked plans (§10.3) | Excluded from Secrets/RBAC/webhooks/CRDs regardless of pack — verified 2026-09-08 against `deploy/helm/argus-agent/templates/clusterrole.yaml`'s `argus-remediate` role and `remediate-role.yaml`; the verbs it does hold are `get`/`patch`/`update` on a named kind set, plus `delete` on Pod/Job/PersistentVolumeClaim and `create` on ConfigMap only. **But "every mutation independently re-validated against `LocalGuardrail`" is NOT a control that exists** (corrected 2026-09-08): there is no `LocalGuardrail` CRD, CR, controller or Go type — `internal/migrations/schema_coverage_test.go` records it as unbuilt, and freeze/maintenance windows shipped hub-side instead. The spoke-side backstops that *are* real, and which should be cited in its place: the agent re-verifies the plan signature itself before any write (`internal/agent/tools.go`'s `verifySignedPlan`), the live `resourceVersion` precondition travels inside the signed envelope and is enforced by the API server, and a `ValidatingAdmissionPolicy` field allowlist scoped by exact `userInfo.username` refuses out-of-allowlist writes even if everything hub-side is compromised (`deploy/helm/argus-agent/templates/validatingadmissionpolicy.yaml`). Those are strong; they are not the locally-*owned* policy object §18.3 layer 4 asks for, so the layer-4 claim is currently unmet. See SR-3 |
| **Cluster agent (`argus-policy-controller`)**, where granted *(added to this table 2026-09-08; the identity shipped earlier and was missing here — a write-capable spoke identity absent from the threat model)* | Creates/updates the single `argus.io/v1 ExecutionWindow` CR that widens the standing `ValidatingAdmissionPolicy` for exactly one approved execution, then re-locks (`lld/14-adrs.md` D-R1's per-execution policy scoping) | It is the identity that can loosen the one control designed to hold when `argus-remediate` *and* the hub are both compromised — so its compromise collapses the field-allowlist backstop into "whatever the window says" | Opt-in per cluster and **off by default** (`policyController.enabled: false`); deliberately a fourth credential rather than folded into `argus-investigate` (which must stay write-incapable) or `argus-remediate` (which must not be able to widen its own bound); its RBAC names `ExecutionWindow` and nothing else — never a workload resource, never `ValidatingAdmissionPolicy`/`Binding` objects themselves (`deploy/helm/argus-agent/templates/policycontroller.yaml`) |
| **The LLM** | Proposes analyses and plans via typed tool calls and closed-schema output | Never an "actor" with standing authority in this model — see §18.2's trust-boundary diagram: its output is "semi-trusted," always validated before anything acts on it | This is the design's core security property, not a control on top of it — see non-negotiable 2 in `argus-context` |
| **External MCP server** (customer-attached, §8.6) — **unbuilt as of 2026-09-08: no MCP client exists anywhere in the codebase**, no `mcp_servers` table, no admin allowlist, no credential store, and no sensitivity/side-effect classification. `internal/mcp` is the hub acting as an MCP *server* for the CLI investigator backend (boundary B12), which is the opposite direction. This row is a design requirement for when the capability lands, not a description of a live actor | Provides evidence to the Analysis Engine when queried | A malicious or compromised server returns poisoned evidence — this *is* a T3 (prompt injection) vector, just from an admin-approved source instead of cluster data | Allowlisted per organisation, minimum-context passed to it, its output treated as untrusted data identically to cluster-sourced evidence (§18.7) |
| **Repository content** (not an actor with credentials, but adversarial data) | N/A — it's data | A malicious Helm chart, Kustomize plugin, or CI fragment attempts to execute in the rendering sandbox or escalate via write-scope | §11's sandboxing (flagged as a **known gap** in the HLD — see §6 misuse case for T7 below and the LLD artifact `repo-gitops-design`, which must close it) |

---

## 4. Trust boundaries — the actual wire-level crossings

HLD §18.2's four-box diagram (untrusted cluster data → semi-trusted LLM output → trusted policy code → authoritative human approval) is the right conceptual model. This table is its low-level counterpart: every place data or a request actually crosses a process/network/privilege boundary, with the concrete mechanism enforcing the crossing.

| # | Boundary | Protocol | Authn/authz mechanism | What crosses |
|---|---|---|---|---|
| B1 | Browser ↔ Public API | HTTPS/WSS | **Bearer JWT for every capability-gated route; one narrow cookie exception added 2026-09-18 for PROJECT.md B164** (this row previously said "no cookie and no CSRF token exist," corrected 2026-09-08 — that is no longer the full picture, and this update is the "must be re-established the moment any cookie-borne session is introduced" this row already called for). `internal/api/middleware.go`'s `requireAuth` is unchanged: it still reads only `Authorization: Bearer`, and no other route ever looks at a cookie. The exception is the refresh-token lifecycle only: `internal/api/auth.go` sets one cookie (`argus_refresh`) carrying the rotating refresh token — HttpOnly always, Path-scoped to `/api/v1/auth`, SameSite=Lax, and Secure only when `isRequestSecure` finds the connection actually arrived over TLS (directly, or via a proxy's `X-Forwarded-Proto`), never unconditionally, since the product's own documented local deployment reaches the hub over plain HTTP at a LAN address. Exactly two routes ever read it back — `POST /auth/refresh` and `POST /auth/logout` — both POST, both under the cookie's own Path. CSRF is re-established for exactly this exposure rather than merely inherited from bearer-only: SameSite=Lax withholds the cookie from any cross-site request to either route regardless of CORS configuration, and every other mutating route remains bearer-only and just as CSRF-unreachable as before. Lax rather than Strict because `auth_oidc.go`'s SSO flow ends with the identity broker redirecting the browser to this hub's own callback — a cross-site, top-level GET navigation a Strict cookie would not survive — though that navigation never carries this cookie either way, so Lax costs nothing there. Revocation is server-side and family-scoped (`internal/authz.RevokeRefreshTokenFamily`, keyed on `refresh_tokens.family_id`), so a logout actually ends every token descended from the session, not merely the browser's own copy. The one origin check that exists beyond this is WebSocket-only (`internal/api/ws.go`'s `CheckOrigin`, which permits a missing `Origin`) | User requests, live incident/cluster updates |
| B2 | Public API ↔ Postgres | TCP, **direct — no PgBouncer or any pooler is deployed** (corrected 2026-09-08; compose and the Helm chart both point the hub straight at Postgres, and `pool_mode` is configured nowhere). Scope is set with `set_config(..., true)` inside an explicit `pgx` transaction, so the session-mode property §18.4 requires is satisfied by using transactions rather than by a pooler setting — which also means introducing a transaction-mode pooler later would silently break RLS scoping, and is the specific thing SR-2 does *not* check | DB role with RLS-enforcing `app.tenant_id`/scope session var (§18.4) | All persisted state |
| B3 | Agent ↔ Agent Gateway | gRPC bidi stream over mTLS | Per-cluster X.509 client cert (§6.2, §6.4) | Findings, tool-call requests/results, execution plans, heartbeats |
| B4 | Agent Gateway ↔ NATS JetStream — **this boundary does not exist** (corrected 2026-09-08): no NATS client is in `go.mod`, no service is deployed, and `PROJECT.md` `P5` defers it until measured scale justifies it. Findings are ingested straight into Postgres and fanned out by an in-process bus (`internal/events`), so the crossing is intra-process and inherits no network boundary. Kept as a row because ADR-3/ADR-5 still name JetStream as the decided design | Internal, hub-only | Network policy (no external exposure) | Ingested findings queued for the Orchestrator |
| B5 | Analysis Engine ↔ LLM provider | HTTPS | Provider API key (§16.2), scoped per task-tier | Prompts (evidence + system context), completions (analysis/plan text) — **the primary data-exfiltration-shaped boundary in the whole system** |
| B6 | Analysis Engine ↔ external MCP server — **unbuilt as of 2026-09-08** (no MCP client anywhere in the codebase; see the actor table's own note). Requirement for when it lands, not a live crossing | MCP (JSON-RPC over stdio/HTTP) | Admin-allowlisted endpoint + credential (§8.6) | Evidence requests/results for customer-attached tool servers |
| B7 | GitOps Service ↔ SCM (GitHub/GitLab) | HTTPS | fine-grained PAT / group access token (D-R9). **The control is a per-binding host match, not a global host+port allowlist** (corrected 2026-09-08): `internal/scm.Store.Resolve` refuses to use a binding's credential against a URL whose host does not match the host recorded on that binding, and `internal/scm/scm.go` enforces https-only with no embedded userinfo. There is no `allowedRepoHosts` config, and no IP-range or connect-time re-resolution check — see T6/SR-9 and T15/SR-16 | **Provider REST API reads and writes — no clones** on this boundary (`lld/14-adrs.md` D-R5): read one file, create branch/commit/PR entirely through the provider API. Helm rendering still fetches a chart archive. `internal/gitops/clone.go` survives and is still reached by the repo-tool checkout cache and the object-file locator, so "no clones anywhere" is not yet true of the whole system — see D-R5's own 2026-09-08 note |
| B8 | Notification Service ↔ Slack/Teams/webhook | HTTPS | **Outbound only, and unauthenticated by ARGUS** (corrected 2026-09-08): `internal/notify` POSTs a Slack-incoming-webhook-shaped JSON body to one operator-configured URL. There is no bot token, no request signing, and **no inbound callback route at all** — so the "interactive approval callbacks (inbound)" half of this row is not built, and T9's whole attack surface is currently absent. The URL is treated as a secret (write-only in the settings API) but is validated only for being a URL | Incident summaries. Deliberately no raw evidence (§13.3) |
| B9 | Executor (`argus-remediate`/`argus-dryrun`) ↔ Kubernetes API | HTTPS (in-cluster) | Projected SA token, cluster-local RBAC | Structured mutations / dry-run requests |
| B10 | Bootstrap installer ↔ user-supplied kubeconfig | Local, in-memory only | Whatever the kubeconfig itself grants | One-time cluster credential, held only for the duration of agent installation (§6.3) — the boundary that closes immediately after crossing |
| B11 | Hub internal services ↔ Redis — **this boundary does not exist** (corrected 2026-09-08): no Redis client in `go.mod`, nothing deployed, deferred by `PROJECT.md` `P5`. Locks are Postgres advisory locks, rate-limit buckets and the gateway registry are in-process (`internal/authz/login_rate_limit.go`, `internal/gateway`), and there is no session cache. §21's fail-closed requirement therefore has no consumer to bind today — which is *safer* than a live Redis, but also means the requirement is untested | Internal, hub-only | Network policy, optional AUTH | Locks, rate-limit buckets, session cache, gateway registry |
| B12 | Hub ↔ CLI-agent runner | HTTPS (or pod-local HTTP) both directions | Bearer token hub→runner; **per-investigation MCP token** runner→hub, scoped to one cluster and read-only tools with a minutes-long TTL | Outbound: the assembled initial prompt. Inbound: MCP tool calls, then the finished `Investigation` JSON. *Present only when the CLI investigator backend is enabled (`analysis-contracts` §10); absent entirely in a default deployment.* See T21 |

**The two boundaries that carry the least explicit hardening today, and why they matter:** B5 (every token sent to an LLM provider is a token that has left the deployment's direct control, redaction notwithstanding — §18.4's own caveat that redaction is best-effort applies with full force here) and B6/B7 (both accept data from, or send credentials toward, systems outside ARGUS's control based on admin configuration rather than a hardcoded allowlist — the SSRF concern in T15 lives at exactly these two boundaries).

**Re-checked 2026-09-08, and the sentence above is now understated rather than overstated.** B6 does not exist yet, so the live admin-configured egress surfaces are B7 (SCM API base URL), B5 (the model `base_url` on `ai_providers`, which `internal/llm/provider.go` concatenates and calls unchecked) and B8 (the notification webhook URL). ~~**None of the three validates the target against private, link-local or cloud-metadata ranges, and none pins or re-resolves the IP at connect time** — SR-16 and SR-9 are both unimplemented.~~ **Re-checked 2026-09-19: all three now do.** `internal/outbound` is the single hardened client constructor all three use; it refuses metadata unconditionally, refuses private/link-local/loopback by default, and resolves-then-dials-the-literal-IP inside its own `DialContext`. B5 and B7 additionally consult an operator-named allowlist of specific private destinations (migration 000115) for the internal-vLLM / internal-GHES case; B8 does not and stays hard-blocked. The per-binding host match described in B7's row is still there and is still what closes the confused deputy — the two controls answer different questions and neither replaces the other.

**B12 is the one boundary in this table that is optional**, and it is worth noting what enabling it costs: it is the only crossing where a process outside the hub's own trust envelope makes *inbound* tool calls that read live cluster state. That is why its inbound direction is scoped per-investigation rather than by a long-lived service credential (SR-24) — a runner that is compromised, or simply buggy, should not be able to enumerate the fleet. An operator who never enables the CLI backend never has this boundary at all, which is itself an argument for keeping the API backend the default.

---

## 5. Data classification and handling

| Class | Examples | Storage rule | Transmission rule | Retention |
|---|---|---|---|---|
| **Restricted** | Secret *values* (never collected — §18.3), KEK, agent private keys, Git/LLM/IdP credentials | Envelope-encrypted (credentials) or never persisted at all (keys, Secret values) | Never transmitted in cleartext; never sent to an LLM provider (`denySendKinds`/`denySendFields`, §16.2) | Until rotated/revoked; never backed up in cleartext |

> **Corrections to the Restricted row, 2026-09-08.** Three of its four claims need qualifying, and none of the qualifications is cosmetic. (1) **`denySendKinds`/`denySendFields` is not a mechanism that exists** — there is no such config, setting, column or code path anywhere; what enforces the intent is `internal/redact`'s structural field-class drops at capture plus `secretMetadataOnly`'s field-level omission for the one Secret `get` the agent now holds. (2) **"Secret *values* (never collected)" still holds**, and is the one part of this row the code fully backs. (3) **"Envelope-encrypted (credentials)" is true of exactly one credential** — the SCM token, via `internal/secretbox`; the LLM/runner credentials in `ai_providers` are plaintext columns, and the KEK that wraps the one encrypted secret is itself in the same Postgres. See the asset-inventory rows for both.
| **Confidential** | Pod logs, `describe` output, cluster resource specs, rendered manifests, evidence blobs | Postgres (`evidence`, `mcp_tool_calls`), RLS-scoped, capture-time-redacted — **not an object store**, corrected 2026-09-08; see the asset inventory | May cross B5 (LLM) and B6 (external MCP) after redaction; never cross B7/B8 unredacted | 90 days default (§14.3) |
| **Internal** | Incident/analysis/plan records, audit events, cluster inventory/facts | Postgres, RLS-scoped | API/UI only (B1); audit events may export to SIEM (§18.8) | 1 year (incidents), 2 years (audit), configurable |
| **Public-within-org** | Notification summaries, dashboard aggregates | Postgres / in-memory | Any channel (B8) — deliberately contains no raw evidence (§13.3) | Ephemeral / follows parent incident |

**The rule that makes this enforceable rather than aspirational:** classification is attached at the point evidence is *captured* (in the agent, before B3), not decided later at the point of use. A field that isn't classified and redacted before it crosses B3 has already left the boundary where enforcement is cheap and reliable.

---

## 6. Misuse cases

Each threat from the HLD's T1–T14 plus seven added at this depth (T15–T21), as a concrete attack narrative: precondition → attack steps → what would actually be observed → residual risk after the HLD's stated mitigation.

### T1 — Cross-scope data access

- **Precondition:** a query handler omits or mis-scopes its `WHERE`/RLS filter.
- **Attack:** an authenticated low-privilege user requests `GET /api/v1/incidents/{id}` for an incident on a cluster they hold no grant on; if the handler trusts the path parameter over the session's scope, the response leaks another team's cluster data.
- **Observable:** an authorization-denial metric that *doesn't* fire when it should — the dangerous failure mode here is silent, not loud.
- **Residual risk after RLS (§18.4):** low, provided the RLS preconditions in §18.4 point 1 all hold (non-owner app role, `FORCE ROW LEVEL SECURITY`, session-mode pooling). **Any one of those four preconditions being missed reduces residual risk back to "none, RLS is decoration"** — this is why `authz-spec` and `rbac-profiles` must include a test that deliberately tries to violate scope with a crafted request and asserts a 403/empty result, not just unit-test the RLS policy SQL in isolation.

### T2 — Hub compromise → fleet-wide reach

- **Precondition:** RCE or credential theft in any hub service.
- **Attack:** attacker attempts to use the compromised hub's position to reach a managed cluster.
- **Observable:** the hub attempting an *outbound* connection to a cluster's API server directly — this should be structurally impossible, not just unusual, since the hub never holds a cluster credential (§3.1, §6.3).
- **Residual risk:** the compromised hub can still push looser *policy* down to a spoke (hub-pushable fields, §18.3 layer 4) and can request tool calls / dispatch signed plans within whatever the currently-approved policy and pending approvals allow. It **cannot** rewrite `LocalGuardrail`, forge a new approval from nothing, or act outside a cluster's own RBAC. This split (hub-pushable vs. locally-owned) is a v1 requirement per §18.3 — verify it's actually implemented as two separate CRs with separate RBAC before considering T2 mitigated, not just designed.
- **Verified 2026-09-08, and the answer is no: T2 is NOT mitigated on this criterion.** The hub-pushable half exists and is genuinely well separated — one CRD (`executionwindows.argus.io`) written by a dedicated fourth identity that can touch nothing else (`argus-policy-controller`). The locally-owned half does not exist at all: no `LocalGuardrail` CRD, CR, controller or Go type, and freeze/maintenance windows shipped **hub-side** (`internal/orchestrator/windows.go`, enforced from `internal/api/unattended.go`) — i.e. inside the very trust envelope a hub compromise owns. `deploy/helm/argus-agent/templates/namespace.yaml` only reserves the namespace for a hand-placed object. So the sentence "it cannot rewrite `LocalGuardrail`" is technically true only because there is nothing to rewrite; a compromised hub can push a looser freeze window because the window is its own state. The residual risk is correspondingly **higher** than this entry's original text implies, and SR-3 is open.

### T3 — Prompt injection via cluster/repo data

- **Precondition:** attacker can influence any string the Analysis Engine reads as evidence (pod name, annotation, log line, ConfigMap value, repo file content, or — T3's newer cousin — an external MCP server's response, §8.6).
- **Attack:** the injected string instructs the model to reach a favourable conclusion or propose a dangerous action ("the fix is to create a cluster-admin binding for `default:attacker`").
- **Observable:** a proposed plan whose action type or target doesn't correlate with the detector that opened the incident — a plan resolution engine can flag this as an anomaly even before the deterministic gate blocks it.
- **Residual risk after all seven layers in §18.7:** genuinely non-zero, and the HLD says so explicitly — this is the one threat in this document where "fully mitigated" is not an honest claim. The requirement this generates (SR-6, below) is about ensuring layer 1 (deterministic risk floors) is what actually gets tested and monitored, since it's the layer that holds regardless of how good the injection is.

### T4 — Command injection via model-authored strings

- **Precondition:** any code path that constructs a shell command, SQL string, or K8s API call by concatenating model output.
- **Attack:** irrelevant in this design's happy path (§10.3's typed action list has no such path) — the attack surface is a **future regression**, not a current gap: a developer adding a new remediation action type (via `argus-add-remediation-action`) who takes a shortcut and adds a generic "run this kubectl command" action type.
- **Residual risk:** near-zero today; the ongoing risk is process, not architecture — this is why `argus-add-remediation-action`'s skill explicitly refuses a generic patch-by-string action outside the one flagged elevated manual escape hatch.

### T5 — Agent credential theft (lateral movement)

- **Precondition:** compromise of one cluster's agent pod or its projected token.
- **Attack:** attacker attempts to use the stolen credential against another cluster's hub state, or to impersonate the cluster to receive plans intended for it.
- **Observable:** a cert presenting from an unexpected source IP/network relative to the cluster's known egress pattern (soft signal, not a hard control); more reliably, any attempt to use cluster A's cert to authenticate a tunnel already claimed by an active session for cluster A from a different origin.
- **Residual risk:** the stolen credential grants exactly that cluster's own hub-side state and nothing more (per-cluster cert scoping, §6.4) — lateral movement to *other clusters'* hub state is structurally blocked, not just monitored. The residual risk is entirely local to the one compromised cluster, which is the design's intended ceiling.
- **Verified 2026-09-08: the per-cluster scoping holds; the session-conflict detection SR-5 asks for does not exist.** `internal/gateway/server.go` authenticates a tunnel by client-cert serial → cluster and rejects only an unknown serial or an `Archived`/`Rejected` cluster; it logs `RemoteAddr` but never stores or compares it, and `registerConn` is last-writer-wins by design (to tolerate fast reconnects). So a stolen cert presented from anywhere silently **displaces** the legitimate agent's connection rather than being flagged as a conflict — the theft is not merely unmonitored, it is indistinguishable from a reconnect. The ceiling stays one cluster, but the "observable" bullet above overstates what would actually be seen: nothing would be.

### T6 — Confused deputy on Git credentials

- **Precondition:** the model or evidence-derived data influences which repository URL a `CreateRepositoryChange` action targets.
- **Attack:** point the action at an attacker-controlled host; if the hub attaches its Git credential to whatever URL it's handed, the credential is exposed to that host.
- **Observable:** an outbound Git operation to a host not in `allowedRepoHosts`. *(2026-09-08: `allowedRepoHosts` is not a config that exists. The equivalent observable is an SCM API call whose host does not match the host stored on the binding whose credential is being used — refused by `internal/scm.Store.Resolve`, which is the mechanism that actually closes the confused deputy here.)*
- **Residual risk after exact host+port allowlisting (§18.5):** low. **Re-checked 2026-09-08: still low, but for a different reason than this line gives, and the DNS-rebinding gap below is fully open.** The confused deputy is closed by construction rather than by an allowlist — a repository change resolves to a *registered binding*, and that binding's credential is refused against any host but the one recorded on it, so a model-supplied or evidence-derived URL cannot attract a credential registered for somewhere else. `internal/scm/scm.go` additionally requires https and rejects embedded userinfo. What is genuinely absent: any IP-range validation and any connect-time re-resolution (see below), and any port constraint — "host+port allowlisting" overstates what is enforced. The specific low-level gap worth calling out: **DNS rebinding** — a hostname that resolves to an allowlisted IP at validation time and a different (internal/attacker) IP at connection time. Matching on hostname string is necessary but not sufficient; the HTTP/Git client must pin or re-validate the resolved IP at connection time, not just the hostname at config time. ~~**SR-9 is unimplemented as of 2026-09-08** — there is no custom `DialContext`, no IP pinning and no re-resolution anywhere in the codebase.~~ **Re-checked 2026-09-19: built, for the REST path.** `internal/outbound` resolves the name once, validates the resolved address, and dials that IP literal, so a rebind between check and connect has nowhere to happen; the same validation re-runs on every redirect. The residual is narrower and worth stating exactly: it covers `internal/scm`'s REST calls (the live path under D-R5), not `internal/gitops/clone.go`'s git transport or the Helm chart fetch, which still dial with their own unvalidated clients.

### T7 — Malicious repository content

- **Precondition:** a registered repository contains a malicious Helm chart, Kustomize plugin, CI fragment, or script.
- **Attack:** the content executes during rendering (a KRM exec plugin, a Helm hook, a `Chart.yaml` pointing at an attacker registry) inside the GitOps Service's rendering environment.
- **Observable:** a rendering process making network calls or filesystem writes outside its designated workspace.
- **Residual risk: PARTLY CLOSED.** Rendering uses single-use pods with no host mounts and denied
  network access. The stronger gVisor boundary is not present where the cluster has no suitable
  `RuntimeClass`; `PROJECT.md` and `docs/VERIFICATION.md` retain that limitation explicitly.

  **Update 2026-08-31 (`PROJECT.md` F26): mitigated in fact, with one named exception.** `internal/render/sandbox` builds and runs the pod this entry specified — single-use, no host mounts, no Docker socket, tmpfs-only scratch, network disabled by default (live-verified enforced on the real `rke2` cluster this was tested against, not assumed), resource limits equal to requests, a wall-clock timeout. **The one property NOT achieved is the gVisor runtime named above**: no gVisor `RuntimeClass` is installed on that cluster (only `crun`/`nvidia`/`nvidia-experimental` are registered), and installing one needs node-level access this environment doesn't have — `sandbox.Config.RuntimeClassName` exists so a deployment that installs gVisor can opt in, but the pod runs under the cluster's default runtime (`runc`) as shipped. This is disclosed rather than silently accepted: T7's residual risk is therefore "mitigated at the level a hardened-but-not-syscall-sandboxed container namespace/cgroup boundary provides," one notch below the "gVisor-grade" residual §2's own conclusion names, until gVisor is actually installed somewhere ARGUS's render sandbox runs.

### T8 — Secrets leaking into LLM context or evidence

- **Precondition:** a Secret value, or something that looks like one, ends up in a tool result.
- **Attack:** not really an attack — mostly an accidental-leak scenario, e.g. a `describe` on a Pod whose env vars reference Secret data get resolved somewhere in the pipeline, or a log line contains a connection string.
- **Residual risk after capture-time redaction (§18.4):** explicitly non-zero and stated as such in the HLD — pattern-based redaction of high-entropy strings/JWTs/connection strings will miss unusual formats. The actual backstop is architectural, not a better regex: `denySendKinds: [Secret]` at the config layer (never fetch Secret *objects* at all, regardless of what's in them) plus the self-hosted-model option for any environment where "assume redaction is imperfect" isn't an acceptable posture.
- **⚠️ Corrected 2026-09-08 — the backstop is no longer architectural, and T8's residual risk is therefore HIGHER than the paragraph above states.** There is no `denySendKinds` config layer in the codebase, and since 2026-08-29 the agent holds a `get` on `secrets` with `Secret` present in `supportedGVKs`. "Never fetch Secret objects at all" has been replaced by "fetch the object, then emit only five named keys of it" (`secretMetadataOnly`), backed by withheld `list`/`watch`, a single reachable tool, and two tests. Secret *values* are still never marshaled, so no known path leaks one today — but the guarantee now depends on that function staying correct and staying the only reader, which is a maintenance property rather than a structural impossibility. The self-hosted-model option is unchanged and remains the only posture that does not require trusting redaction. See the full correction in this document's redaction banner; do not re-tighten this wording without re-reading the code.

### T9 — Approval forgery via chat callback

- **Precondition:** an interactive Slack/Teams approval button.
- **Attack:** anyone in the channel clicks Approve on someone else's behalf, or a forged callback payload claims a Slack user ID that maps to a privileged ARGUS identity.
- **Observable:** an approval whose account-linked identity doesn't match the plan's expected approver pool, or a callback failing signature/timestamp verification.
- **Verified 2026-09-08: T9's attack surface does not exist yet, and neither do two of the four mitigations this entry credits.** `internal/notify` is outbound-only — one operator-configured webhook URL, a Slack-incoming-webhook-shaped JSON body, no bot token, no interactive buttons, and **no inbound callback route on the hub at all**. So there is nothing to forge today. But of the four controls named below, only two are real: server-side re-authorisation (`internal/api/approvals.go` re-checks capability and scope at approve time, and only an incident in `AwaitingApproval` may be approved) and plan-bound single-use approval (state compare-and-swap plus the signed, expiring, target-bound envelope — see the asset inventory's correction on `actorId`). **Callback signature/timestamp verification and chat-account-to-identity linking are entirely unbuilt.** The practical consequence: this entry must not be read as "T9 is mitigated", but as "T9 is unreachable, and SR-10 plus callback signature verification have to ship *with* the interactive-approval feature, not after it" — shipping the button first would make this a live, unmitigated forgery path.
- **Residual risk after signature verification + account linking + server-side re-authorisation + single-use plan-bound tokens (§5.4, §13.4):** low. The remaining concrete gap: **account-linking bootstrap** — the first time a Slack user ID is linked to an ARGUS identity is itself a trust decision (self-service link-your-account flow vs. admin-provisioned mapping). A self-service flow that doesn't re-verify the corporate identity (e.g., via the same OIDC flow used for login) reopens exactly this threat one step earlier. `authz-spec` should specify which linking model is used (SR-10).

### T10 — Privilege escalation via self-authored policy

- **Precondition:** a user with `policy:write` on some scope authors a `RemediationPolicy`.
- **Attack:** attempt to grant a detector `mode: automatic` with a high `maxRiskLevel` to escalate the system's own autonomy beyond what the author's role should permit.
- **Observable:** a policy write that increases autonomy beyond what §7.5's precedence rules would allow to survive merge with any broader (tenant/org) policy.
- **Verified 2026-09-08: this threat is currently unreachable because the mechanism it targets is unbuilt.** There is no `RemediationPolicy` CRD, no cluster-side policy controller, and no policy-authoring API. `internal/authz.CapPolicyWrite` and `CapPolicyDryrun` are declared in the capability catalogue and granted to roles, but **gate no route** — `PROJECT.md` `P7` tracks exactly this class of declared-but-unreachable capability, and `S4` defers the CRD. Autonomy policy today is hub-side org settings behind `org:settings:write`. Two things follow, and both matter: a capability that gates nothing cannot be audited as if it did, and **SR-11 must be satisfied when the authoring path is built** — it is not "met", it is "not yet applicable", which is a different status and should not be allowed to read as the first.
- **Residual risk:** low — guardrails only accumulate (§7.5), so a narrow policy cannot unlock what a broader one forbids. The remaining requirement: `policy:write` itself must be scoped identically to the cluster/group it's being granted for (SR-11) — a user with `policy:write` on cluster A must not be able to author a policy object that, through a labeling or selector mistake, matches cluster B.

### T11 — Runaway automation

- Covered in depth by HLD §10.5 (blast-radius batching, halt-on-failure default) and §12.2 (depth-limit-one on validation-triggered remediation). No new low-level gap identified beyond what's specified there; the requirement (SR-12) is that these are implemented as hard invariants in the Remediation Orchestrator, not configurable defaults someone can quietly disable.
- **Verified 2026-09-08: SR-12 is half met, and the missing half is the one this threat is actually about.** *Halt-on-failure is a genuine hard invariant* — `internal/orchestrator/batch.go`'s `decideBatchOutcome` checks failure before completeness, treats every unexpected state as failure in its default branch, hardcodes the wave-1 size, and is called unconditionally from `internal/api/unattended.go` with no enable/disable flag. Its scope is narrower than it looks, though: batching only binds fleet-group-correlated candidates sharing an action type, so an uncorrelated candidate passes ungated by it. *Depth-limit-one does not exist.* No depth, generation or attempt counter exists anywhere; a failed validation moves the incident to `Reopened`, and `internal/autoanalyze` deliberately makes a `Reopened` incident eligible for fresh auto-analysis, which can produce a new plan and another unattended execution with nothing capping the hops. The only restraints are rate-shaped and **operator-configurable with no upper bound** — the circuit breaker and the blast-radius counters (`internal/orchestrator/blastradius.go`) — i.e. precisely the "configurable defaults someone can quietly disable" shape SR-12 was written to forbid. Unattended execution being off by default, and gated on an empty-by-default namespace allowlist, is what currently bounds this in practice; that is a deployment default, not an invariant.

### T12 — LLM spend attack

- Covered by HLD §16.4's hierarchical pre-flight ceilings. Low-level addition: the ceiling check and the investigation-start action must be the same atomic operation (check-then-reserve-budget, not check-then-separately-decrement) or a burst of concurrent requests can each pass a stale check before any of them records its spend — a TOCTOU variant, same family as T19 below (SR-13).
- **Verified 2026-09-08: SR-13 is unimplemented, and the manual path does not even block.** `internal/api/spend.go`'s `TodaySpend` is a read-only `SUM(cost_usd)` over `analyses` and `SpendCeilingBreached` is a pure function; there is no reservation, lock or counter of any kind, and spend is recorded only *after* an investigation finishes. The unattended sweep at least skips when the ceiling is breached, but the check is per-sweep and holds nothing. The manual `/analyze` path checks the ceiling and **proceeds anyway, logging that it is doing so** (`internal/api/analyze.go`) — so for that path the ceiling is an observation, not a control. The exact TOCTOU this entry names is therefore live, and the honest bound on spend today is the provider's own account limits plus the fact that investigations are human- or poller-triggered rather than attacker-triggered.

### T13 — Supply-chain compromise of the agent image

- Covered by HLD §16.7/§20.1 (signing, SBOM, admission-policy verification). No new gap; the requirement (SR-14) is that verification happens *in the spoke* before the agent runs, not just as a hub-side build-time check — a spoke that doesn't verify at admission time trusts whatever image reference it's given.
- **Verified 2026-09-08: SR-14 is unimplemented, in the spoke and everywhere else.** No cosign/sigstore/notation tooling, no image-policy admission resource, and no signature or SBOM verification step exists in `deploy/` or in CI. The agent chart pulls whatever image reference its values name. So T13 has no mitigation at all today, not a partial one — the entry above describes the design, and nothing implements it.

### T14 — Insider abuse by a super-admin

- Covered by the hash-chained audit log (§14.2, §18.8) and optional two-person rule. Low-level addition: the audit log's hash chain must be independently verifiable (a documented verification procedure/tool, not just "it's hash-chained" as an assertion) — otherwise tamper-evidence is a property nobody can actually check (SR-15).

### T15 — SSRF via admin-configured integration URLs *(new at this depth)*

- **Precondition:** an admin configures a notification webhook (§13.2), an external MCP server (§8.6), or a `RepositoryBinding` self-hosted API base URL (§11.3) pointing at an internal address.
- **Attack:** even without a malicious admin, a compromised admin session or a supply-chain-tampered config value could point one of these at `169.254.169.254` (cloud metadata service) or an internal-only management endpoint, and the hub would dutifully make the request with whatever ambient credentials/network access it has.
- **Residual risk:** unaddressed in the HLD at this level of specificity — these URLs are admin-configured, which is a meaningfully lower bar of trust than model-influenced (T6), but not zero-risk. `deployment-design`/`api-spec` should specify: validation against RFC 1918/link-local/metadata-service ranges for any admin-supplied URL that the hub itself will call, unless explicitly allowlisted for legitimate internal use (SR-16).

### T16 — Stored XSS via evidence rendering *(new at this depth)*

- **Precondition:** the incident evidence viewer (§15.2) renders raw `describe`/log output, which is attacker-influenceable cluster data, in a browser.
- **Attack:** a pod annotation or log line containing `<script>` or an event-handler payload executes in the browser of a human reviewer viewing the incident — a client-side analogue of T3, targeting the human instead of the model.
- **Residual risk:** unaddressed explicitly in the HLD (§15's UI requirements don't mention output encoding). This is a standard, well-understood control (context-aware output encoding / a framework that escapes by default, e.g. React's default JSX escaping — consistent with the React choice in §4.4) but must be an explicit requirement given how much of this UI's content is adversary-influenceable by design (SR-17), not assumed as "the framework probably handles it."

### T17 — Auth token validation weaknesses *(new at this depth)*

- **Precondition:** JWT verification code accepts an unexpected algorithm (`alg: none` or algorithm confusion between symmetric/asymmetric), or omits issuer/audience validation.
- **Attack:** a forged token bypasses signature verification entirely, or a token issued for a different purpose/audience is accepted where it shouldn't be.
- **Residual risk:** the HLD specifies short-lived JWTs (§5.3) but doesn't specify validation strictness. `authz-spec` must pin the algorithm allowlist (no `none`, no algorithm negotiation from the token header) and require issuer+audience+expiry validation on every verification path, including internal service-to-service calls (SR-18).

### T18 — Timing side-channels on signature/token comparison *(new at this depth)*

- **Precondition:** approval-token, plan-signature, or webhook-signature comparison uses a naive `==`/`strcmp`-style check.
- **Attack:** a timing side-channel allows byte-by-byte recovery of a valid token/signature over many attempts.
- **Residual risk:** low-probability but cheap to close entirely. `remediation-contracts`/`api-spec` should require constant-time comparison for every signature/token verification path (SR-19).

### T19 — TOCTOU between precondition check and mutation *(new at this depth)*

- **Precondition:** a remediation action's precondition check (§10.3: target `resourceVersion` match) and the actual mutation are two separate API calls rather than one atomic operation.
- **Attack:** the target object changes between check and apply, and the mutation proceeds against a state that no longer matches what was approved.
- **Residual risk:** the HLD's intent (§10.3, §10.4) is clearly optimistic-concurrency-based, but the *implementation* must express the precondition as part of the mutating call itself (Kubernetes's native `resourceVersion`-checked update, not a separate GET-then-PATCH), or the design's own stated guarantee doesn't actually hold. `remediation-contracts` must specify this as a single-call requirement, not an implementation detail left to whoever writes the executor (SR-20).
- **Verified 2026-09-08: SR-20 holds for every action type but one, and the exception is a real open TOCTOU.** The signed envelope carries a `resourceVersion` fetched fresh at approval time, and the strategic-merge executors embed it in the patch body so the API server does the compare-and-swap atomically (`internal/agent/tools.go`'s `applyPlanPatch`); `delete_resource` uses `metav1.Preconditions{ResourceVersion, UID}`; `annotate_resource`/`label_resource` embed it too; `create_resource` is legitimately exempt. **`patch_field` is the exception**: `internal/agent/patchfield.go` does a GET and then submits a JSON Patch carrying **no `resourceVersion` precondition at all** — only a `test`/`replace` on the target field pointer, and in the field-absent branch a bare `add` with no `test` whatsoever — and passes no `Preconditions` on the call. Its own doc comment asserts that "the resourceVersion precondition already catches an object that changed", which is not true of this code path; nor does the file do the `live.GetResourceVersion() != plan.ResourceVersion` comparison its siblings do. The field-value `test` narrows the window but does not close it: a concurrent change elsewhere in the object, and the whole absent-field case, are unguarded. Mitigating context, not an excuse: `PatchField` is deliberately not model-reachable (`lld/14-adrs.md` D-R8's 2026-08-26 note), so reaching this path takes an operator-driven plan — but the gap must be closed before `F11` is ever unparked.

### T20 — Audit/log injection *(new at this depth)*

- **Precondition:** attacker-influenceable strings (pod names, annotations, log lines — the same T3 data sources) are written into the hub's own structured logs or audit trail via naive string concatenation.
- **Attack:** a crafted string containing log-format control sequences or embedded newlines forges what looks like a separate, fabricated log/audit entry when the log is later viewed or parsed.
- **Residual risk:** low if structured logging (JSON fields, not concatenated strings — already implied by §19's "structured JSON" requirement) is used consistently, including for the append-only audit log itself. `data-model` should confirm the audit-event schema uses typed fields exclusively, with no free-text field that gets parsed downstream as if it were structured (SR-21).

### T21 — Evidence-driven tool execution inside a CLI-agent runner *(new 2026-08-21, with the CLI investigator backend)*

Registered separately from T3 rather than folded into it, because the *consequence* differs in kind. T3 is "the model may be misled about a diagnosis, and the deterministic risk floor holds regardless." T21 is "attacker-controlled evidence reaches a process that ships its own shell."

- **Precondition:** the operator has enabled the CLI investigator backend (`analysis-contracts` §10). Both candidate CLIs ship built-in filesystem, shell-execution and web-fetch tools of their own, entirely separate from the tool surface ARGUS defines in `analysis-contracts` §2. Investigation prompts carry untrusted cluster content by definition (§5's Confidential/Internal classes — pod logs, event messages, ConfigMap values).
- **Attack:** a crafted log line, annotation, or event message in the evidence stream induces the CLI to invoke one of *its own* built-in tools rather than an ARGUS tool — reading files in the runner container, executing a shell command, or fetching an attacker-controlled URL to exfiltrate whatever the runner can see. Unlike T3, no model "belief" has to be changed for this to cause harm; a single successful tool invocation is the compromise.
- **Why the existing mitigations don't cover it:** SR-6's deterministic risk floor protects *remediation* — it constrains what mutations can be applied to a cluster. It says nothing about code execution inside the analysis path itself, which has never previously been a place code could execute. §6 T3's prompt-hygiene layer is explicitly non-load-bearing (§9) and cannot be the answer here.
- **Residual risk:** manageable but only through configuration that must be *verified*, not assumed — the built-in tools are enabled by default in both CLIs, so the secure state is the one you have to actively construct. Two independent requirements, one per layer: the loop-side allowlist (SR-22, owned by `analysis-contracts` §10.4) and the runner's own process/network isolation (SR-23, owned by `deployment-design` §12), on the standing assumption that the first will eventually be bypassed by something and the second is what limits the damage when it is.
- **Verified 2026-09-08: SR-22 ships, SR-24 ships, and SR-23 ships only half — the half that is missing is the network half, which is the one this entry says limits the damage.** `cmd/cli-runner` passes `--strict-mcp-config`, an explicit namespaced `--allowedTools`, and `--disallowedTools Bash,Read,Write,Edit,NotebookEdit,WebFetch,WebSearch,Task,TodoWrite`, refuses a request with an empty allowlist, and has tests locking both the deny list and the no-MCP-config completion path. The runner pod is genuinely credential-isolated: a separate deployment, `automountServiceAccountToken: false`, `runAsNonRoot`, holding no Postgres credential, no agent mTLS material and no plan-signing key, and it never learns which cluster it is investigating (scope lives in the per-investigation MCP token). **But there is no NetworkPolicy anywhere in this repository**, for the runner or anything else, so "egress restricted to the hub's MCP listener and the configured model endpoint" is not enforced by anything — a successful injection that reaches a built-in tool, or any other outbound path in that image's dependency tree, has unrestricted egress. Read §9's T21 acceptance accordingly: it says enabling this backend without SR-23 is "not a partial mitigation, it is an unmitigated remote-code-execution path", and SR-23 is currently partial.

---

## 7. Model/provider data policy

Concrete allow/deny matrix implementing HLD §16.2's `privacy` config and §18.4's redaction rules — this is the thing an implementer checks before wiring up a new evidence field or a new provider.

| Data class (§5) | May cross B5 (LLM provider)? | May cross B6 (external MCP)? | Notes |
|---|---|---|---|
| Restricted | **Never** | **Never** | `denySendKinds`/`denySendFields` enforced at the point of assembling the tool-call result, not just at the prompt-construction step — a field denied from the prompt but still present in a stored evidence blob is a partial fix. |
| Confidential | Yes, after capture-time redaction | Yes, minimum-context only (§8.6) | This is the class redaction is actually protecting; treat any gap here as directly actionable, not theoretical. |
| Internal | Only as much as the Analysis Engine's context construction genuinely needs (e.g. an incident's own metadata) | Same | Don't pass full incident/audit history into a prompt "for context" by default. |
| Public-within-org | Yes | Yes | No special handling needed. |

> **Status note, 2026-09-08.** This matrix is a requirement, not a description of an enforcement point that exists. `denySendKinds`/`denySendFields` is not a config, setting or code path anywhere in the codebase — what actually keeps Restricted-class data off B5 is `internal/redact`'s structural field-class drops at capture plus `secretMetadataOnly`, and what keeps it off B6 is that B6 does not exist. Read the Restricted row as the rule an implementer must satisfy by construction, and see the redaction banner at the top of this document for what construction currently means.

**Provider selection interacts with this table, not just with cost (§16.0):** an organisation with a hard requirement that Confidential-class data never leave its infrastructure should route the `investigation`/`planning` tiers to a self-hosted model (§16.2's per-task-tier routing), not rely on redaction alone to make a hosted provider acceptable. This is a policy choice `authz-spec`/`api-spec` should expose as an explicit, auditable org-level setting, not an implicit consequence of which provider happens to be configured.

---

## 8. Security requirements register

Testable requirements this threat model generates, for downstream LLD artifacts to implement against. "Owner" is the LLD artifact responsible for the concrete specification; this document defines the requirement, not the implementation.

| ID | Requirement | Derived from | Owner artifact |
|---|---|---|---|
| SR-1 | Every tenant/scope-filtered query has an automated test that attempts cross-scope access and asserts it fails | T1 | `authz-spec` |
| SR-2 | RLS preconditions (non-owner role, `FORCE ROW LEVEL SECURITY`, session-mode pooling, parameterised `set_config`) are verified in a startup health check, not just at migration time | T1 | `data-model` |
| SR-3 | `LocalGuardrail` and hub-pushable policy are two separate CRs with separably-enforced RBAC in the spoke | T2 | `rbac-profiles` |
| SR-4 | Every new remediation action type is reviewed against the "no generic string-based patch" rule before merge | T4 | `remediation-contracts` (process requirement, enforced via `argus-security-review`) |
| SR-5 | Cert-based tunnel auth rejects a credential already claimed by an active session from a conflicting origin | T5 | `agent-protocol` |
| SR-6 | Deterministic risk-floor enforcement (§9.3/§18.7 layer 1) has dedicated monitoring/alerting independent of model-output-based signals | T3 | `analysis-contracts` / `remediation-contracts` |
| SR-7 | Repository rendering runs in a workspace with no Docker socket, no host mounts, read-only base filesystem, network disabled by default, and no execution of repo-provided scripts unless explicitly policy-approved | T7 (known HLD gap) | `repo-gitops-design` |
| SR-8 | `denySendKinds`/`denySendFields` are enforced at evidence-assembly time, before storage, not only at prompt-construction time | T8 | `analysis-contracts` |
| SR-9 | Git client pins/re-validates the resolved IP at connection time, not only the hostname at config time (DNS rebinding defense) | T6 | `repo-gitops-design` |
| SR-10 | Chat-account-to-platform-identity linking re-verifies corporate identity via the same OIDC flow as login, not a weaker self-service claim | T9 | `authz-spec` |
| SR-11 | `policy:write` grants are scope-checked against the actual clusters/labels a policy object would match, not just the grant's nominal scope | T10 | `authz-spec` |
| SR-12 | Blast-radius batching halt-on-failure and validation-triggered-remediation depth-limit-one are hard invariants, not configurable-away defaults | T11 | `remediation-contracts` |
| SR-13 | Spend-ceiling check-and-reserve is a single atomic operation | T12 | `remediation-contracts` |
| SR-14 | Agent image signature verification happens in-spoke at admission time | T13 | `deployment-design` |
| SR-15 | Audit-log hash-chain has a documented, independently runnable verification procedure | T14 | `data-model` |
| SR-16 | Admin-supplied integration URLs the hub will call are validated against private/link-local/metadata-service IP ranges unless explicitly allowlisted | T15 | `deployment-design` / `api-spec` |
| SR-17 | Evidence rendering in the UI uses context-aware output encoding by default (framework-enforced escaping); no raw HTML injection path from cluster/repo data | T16 | `ui-design` |
| SR-18 | JWT verification pins the algorithm allowlist and validates issuer/audience/expiry on every path | T17 | `authz-spec` |
| SR-19 | Signature/token comparisons use constant-time equality | T18 | `remediation-contracts` / `api-spec` |
| SR-20 | Remediation preconditions are expressed as part of the atomic mutating API call, not a separate check-then-apply sequence | T19 | `remediation-contracts` |
| SR-21 | Audit-event and structured-log schemas use exclusively typed fields; no free-text field is later parsed as structured data | T20 | `data-model` |
| SR-22 | A CLI-agent runner's tool surface is an explicit allowlist of ARGUS-defined tools with every CLI built-in disabled and project-config discovery skipped, **asserted at runner startup** rather than assumed from configuration | T21 | `analysis-contracts` |
| SR-23 | The CLI-agent runner runs in its own process/container holding no database credential, no agent mTLS material and no plan-signing key, with egress restricted to the hub's MCP listener and the configured model endpoint | T21 | `deployment-design` |
| SR-24 | An MCP token issued to a runner is scoped to a single investigation, a single cluster, and read-only tools; the hub resolves cluster identity from the token and never from runner-supplied parameters | T21, T1 | `analysis-contracts` / `api-spec` |

---

### Implementation status of the register, audited 2026-09-08

The table above is unchanged — it defines requirements, and a requirement does not stop being one
because the code has not met it yet. This subsection records **what the code actually does**, so a
reader cannot mistake a listed requirement for a shipped control. Verified against the
implementation, not against comments claiming compliance.

| ID | Status | Evidence / what is missing |
|---|---|---|
| SR-1 | **Partial** | Scope-negative tests exist for several routes, but not as a blanket per-query requirement; RLS itself is force-enabled and startup-checked (SR-2) |
| SR-2 | **Partial** | `internal/data.DB.CheckRLSPreconditions` is a hard startup gate (`cmd/hub/main.go` exits non-zero) and re-runs per readiness probe; it checks the app role identity, `rolbypassrls = false`, and that no table has RLS enabled-but-not-forced. It does **not** check session-mode pooling (no pooler is deployed, so nothing to check — but nothing would catch one being introduced) or that `set_config` is parameterised (a single-call-site convention only) |
| SR-3 | **Open** | Hub-pushable half shipped (`executionwindows.argus.io` + the dedicated `argus-policy-controller` identity). `LocalGuardrail` is unbuilt; freeze windows shipped hub-side. See T2 |
| SR-4 | **Met (as a process)** | `argus-add-remediation-action`/`argus-security-review` skills carry the rule; no generic string-patch action type exists in `internal/remediation` |
| SR-5 | **Open** | Tunnel auth binds cert serial → cluster and rejects unknown/archived clusters; no origin recording and no session-conflict check. Re-registration is last-writer-wins. See T5 |
| SR-6 | **Partial** | The deterministic risk floor is real and unbypassable (`internal/remediation/risk.go` — rules set a floor the model may only raise), but there is no dedicated monitoring/alerting on it independent of model-output signals |
| SR-7 | **Met, with one named exception** | `internal/render/sandbox` builds single-use render pods: no host mounts, no Docker socket, tmpfs-only scratch, network disabled by default (live-verified), limits equal to requests, wall-clock timeout. The gVisor `RuntimeClass` is **not** present — see T7 and §9 |
| SR-8 | **Met by a different mechanism than the requirement names** | There is no `denySendKinds`/`denySendFields` config. Enforcement is at capture, in the agent, ahead of both storage and prompt construction (`internal/redact` at `ToolExecutor.Execute` and the tunnel writer; `secretMetadataOnly` for the Secret `get`) — which satisfies the requirement's intent at an earlier point than it asks for, but is not configurable and is not a denylist |
| SR-9 | **Met on the hub's HTTP egress, not on Git clone/chart fetch** *(re-checked 2026-09-19)* | `internal/outbound` is a custom `DialContext`: it resolves the hostname itself, validates the resolved address, and dials that literal IP, so the address checked is the address connected to — closing the rebinding window this requirement names. It re-runs on every redirect. It covers `internal/llm`, `internal/scm`, `internal/notify`, `internal/idp` and `internal/knowledge`, which is the SCM REST path D-R5 made the live one. It does **not** cover `internal/gitops/clone.go`'s git transport or the Helm chart fetch, which still use their own. See T6 |
| SR-10 | **Not applicable yet** | No chat-account linking exists, because no interactive chat approval exists. Must ship *with* that feature. See T9 |
| SR-11 | **Not applicable yet** | No policy-authoring path exists; `CapPolicyWrite`/`CapPolicyDryrun` gate no route (`PROJECT.md` `P7`). See T10 |
| SR-12 | **Half met** | Halt-on-failure is a genuine hard invariant (`internal/orchestrator/batch.go`, called unconditionally, no flag) though scoped to correlated same-action candidates. Depth-limit-one **does not exist** — no depth/generation counter; the only restraints are operator-configurable rate caps. See T11 |
| SR-13 | **Open** | No reservation of any kind; read-only `SUM` plus a pure predicate. The manual `/analyze` path logs the breach and proceeds. See T12 |
| SR-14 | **Open** | No signature/SBOM verification in the spoke, in the chart, or in CI. See T13 |
| SR-15 | **Met** | Hash chain written under `pg_advisory_xact_lock` (`internal/audit`); `argusctl audit verify` recomputes both the self-hash and the `prev_hash` link, refuses to run under a non-`BYPASSRLS` role so it cannot "verify" an RLS-filtered empty view, and is deliberately not a hub API route. Procedure documented in `RUNBOOK.md` |
| SR-16 | **Met, including the "unless explicitly allowlisted" clause** *(re-checked 2026-09-19)* | `internal/outbound` refuses loopback/link-local/RFC1918/RFC4193 by default for the notification webhook, the model `base_url` and the SCM API base URL, and refuses cloud metadata addresses unconditionally for every caller including the two that hold a blanket private allowance (`internal/idp`, `internal/knowledge`). The allowlist half of this requirement is `internal/outbound/allowlist.go` plus `org_settings.outbound_private_allowlist` (migration 000115): an operator names specific private destinations, each with a required reason, and it is consulted only for the AI-provider and repository clients. It is not a boolean, it cannot name a public range, and no entry of any form can reach a metadata address — see the T15 allowlist-granularity decision in §10 |
| SR-17 | **Met** | No `dangerouslySetInnerHTML` on any render path in `web/src` (only comments naming the rule); React's default escaping carries it, as §4.4's framework choice intended |
| SR-18 | **Met** | `internal/authz/jwt.go` parses with `WithValidMethods([ES256])`, `WithIssuer`, `WithAudience`, and jwt/v5's default expiry validation. It is the only JWT parse site in the repo, so "every path" holds literally; `alg: none` and wrong-audience are directly tested |
| SR-19 | **Met where a secret is compared** | `subtle.ConstantTimeCompare` for passwords and MCP tokens; `hmac.Equal` for plan and enrollment signatures. No plaintext `==` on any credential. Deliberate, documented exceptions: WS tickets and guardrail-confirmation tokens are single-use map lookups, and refresh tokens are located by an indexed SHA-256 `WHERE token_hash = $1` |
| SR-20 | **Met except `patch_field`** | The precondition rides inside the mutating call for every other action type. `internal/agent/patchfield.go` submits a JSON Patch with no `resourceVersion` precondition and no live-version comparison. See T19 |
| SR-21 | **Met** | Audit and structured-log events use typed fields; no free-text field is re-parsed downstream |
| SR-22 | **Met** | `cmd/cli-runner` passes `--strict-mcp-config`, an explicit namespaced `--allowedTools`, and `--disallowedTools` covering every built-in; refuses an empty allowlist; both properties are locked by tests |
| SR-23 | **Half met — the missing half is the network half** | Credential isolation is real (separate pod, `automountServiceAccountToken: false`, no DB credential, no mTLS material, no signing key, never told which cluster). **No NetworkPolicy exists anywhere in this repo**, so egress is unrestricted. See T21 and §9 |
| SR-24 | **Met, with the documented `dry_run_patch` narrowing** | Per-investigation, single-cluster tokens minted hub-side, cluster resolved from the token and never from runner-supplied parameters (`internal/mcp`). The one write-capable tool on that surface is covered by the addendum at the end of this document |

---

## 9. Residual risk acceptance

Threats where the stated mitigation does not reduce residual risk to negligible, and which therefore need an explicit accepted-risk sign-off rather than an implicit "it's handled":

| Threat | Residual risk | Why it can't go to zero | Accept, or invest further? |
|---|---|---|---|
| T3 (prompt injection) | Non-trivial | No known technique fully prevents an LLM from being influenced by adversarial input in its context; the design's answer is that the deterministic layer holds regardless, not that injection is prevented | **Accept**, contingent on SR-6 actually shipping and being monitored — this is a "defense in depth compensates for an unsolvable problem" acceptance, not a "we're fine" one |
| T8 (secret leakage via imperfect redaction) | Non-trivial | Pattern-based redaction cannot cover every possible secret format | **Accept for hosted-provider deployments**; organisations with a harder requirement should route Confidential-class evidence to a self-hosted model (§7) instead of accepting this risk |
| T7 (repository sandboxing) | ~~Currently **unmitigated**, not just residual~~ — **superseded 2026-08-31, confirmed 2026-09-08: SR-7 landed.** Residual is now "one notch below gVisor-grade": a hardened container namespace/cgroup boundary, not a syscall sandbox | ~~The relevant subsection doesn't exist yet in the HLD or any LLD artifact~~ — it does, and so does the code (`internal/render/sandbox`: single-use pods, no host mounts, no Docker socket, tmpfs-only scratch, network disabled by default and live-verified enforced, limits = requests, wall-clock timeout). What cannot go to zero is the runtime: no gVisor `RuntimeClass` is installed on the cluster ARGUS is tested against, and installing one needs node-level access this environment does not have. `sandbox.Config.RuntimeClassName` exists so a deployment that has gVisor can opt in | **Accept the container-boundary residual**, and keep the gVisor gap disclosed rather than closed — `PROJECT.md`'s known limitations and `docs/VERIFICATION.md` both carry it, and this row must keep carrying it too. The original "do not accept / block implementation" verdict is retained above, struck through, because it is why SR-7 was built before the repository path shipped rather than after |
| T21 (tool execution in a CLI-agent runner) | Non-trivial, and it inherits T3's unsolvability — the injection itself cannot be prevented | The mitigations are configuration (SR-22) plus isolation (SR-23/SR-24), not prevention. The secure state is the one that must be actively constructed, since CLI built-in tools are on by default | **Accept only as an opt-in, off-by-default backend, contingent on SR-22/23/24 all shipping together.** Enabling the CLI backend without the runner isolation of SR-23 is not a partial mitigation, it is an unmitigated remote-code-execution path reachable from pod logs — treat shipping SR-22 alone as a blocker, not a milestone. **⚠️ This acceptance condition is not currently satisfied (audited 2026-09-08).** SR-22 and SR-24 ship; SR-23 ships its credential-isolation half but **not** its egress half — there is no NetworkPolicy anywhere in this repository, so a runner that is compromised has unrestricted network. By this row's own standard that is the state it says not to accept, so the honest position is: the `cli` backend remains opt-in and off by default, and enabling it in an environment where the runner's egress is not restricted by some means outside this chart is an accepted-by-the-operator RCE exposure, not a mitigated one |

---

## 10. Open decisions and questions

- **SIEM export destination and format** for the audit log (§18.8 mentions "syslog/OTLP/S3" as options but doesn't commit) — needed before `data-model` finalizes the audit-event schema's export path. *(Still open 2026-09-08. No syslog/OTLP/S3 exporter exists; what ships is `GET /api/v1/audit-events/export` — a pull, not a push — so the schema is not yet pinned by an export path.)*
- **Two-person-rule enforcement point**: is it enforced in the Policy & Risk Engine (server-side, so it can't be bypassed by a UI change) or partly in the UI? This document assumes server-side per §5.4's "middleware, not per-handler code" principle, but `authz-spec` should state it explicitly rather than leaving it implied. *(Still open 2026-09-08 — and no two-person rule exists in code at all, so this is a decision about something unbuilt. T14's mitigation should be read as the hash-chained audit log alone until it lands.)*
- **DNS-rebinding mitigation approach (SR-9)** — ~~pin resolved IP at TLS handshake time vs. re-resolve-and-compare immediately before connect~~. **Decided and built (2026-09-19 re-check).** Neither of the two options as written: `internal/outbound` resolves the name once inside its own `DialContext`, validates the resolved address, and then dials that literal IP, so there is no second resolution to disagree with the first and nothing to compare. A handshake-time pin was unnecessary once the dial target is an IP literal.
- **T15's allowlist granularity** — ~~should admin-supplied integration URLs support an explicit override, or should internal-range URLs be hard-blocked with no override?~~ **Decided by the product owner, 2026-09-19: an override exists, and it names destinations rather than enabling a mode.** Default-deny stays; an operator may add specific private hosts, IPs or CIDRs to `org_settings.outbound_private_allowlist`, each carrying a required written reason, and anything unnamed stays refused. Both alternatives were considered and rejected: allowing private destinations by default, and shipping no override at all. Granularity, for the record: one list, consulted **only** by the AI-provider client (`internal/llm`) and the repository clients (`internal/scm`) — the two boundaries where an internal endpoint is a plausible real deployment. The notification webhook (B8) is deliberately NOT covered, and not because it is stricter — `internal/notify` already holds a compile-time blanket `AllowPrivate` on the reasoning that an internal chat receiver or corporate proxy is the expected target for a self-hosted ARGUS, so there is no default-deny there for an allowlist to relax. `internal/idp` and `internal/knowledge` hold the same pre-existing blanket allowance and likewise do not read the list. Cloud metadata is outside the override entirely, by three independent checks (`internal/outbound/allowlist.go`).

---

## Addendum (2026-08-26): SR-24's "read-only tools" clause, narrowed deliberately

§8's SR-24 table row states the requirement verbatim as originally written: "An MCP token issued
to a runner is scoped to a single investigation, a single cluster, and read-only tools." `PROJECT.md`
C4 / ADR-14 (`lld/14-adrs.md`) has since added one exception to that clause, deliberately and after
review, not by drift: `dry_run_patch` is a write-CAPABLE tool (a real `PATCH`/`CREATE` call reaches
the API server) that can be present in a token minted for the CLI backend's scoped MCP surface
(`internal/mcp`), when — and only when — the target cluster's agent reported holding the opt-in
`argus-dryrun` grant (`internal/llm.CLIInvestigator`'s `toolNamesForTarget`).

**Why this doesn't reopen T21/T1 the way a generic write tool would:** SR-24's actual worry, per its
own listed threats, is a compromised or prompt-injected runner reaching a cluster capability it
should not have. `dry_run_patch` is bound to a request the target cluster's OWN
`ValidatingAdmissionPolicy` refuses to let become anything other than a rehearsal
(`deploy/helm/argus-agent/templates/dryrun.yaml`'s `argus-dryrun-enforce-dryrun` policy,
`request.dryRun == true`, scoped by exact `userInfo.username` so it cannot be satisfied by any other
identity's real write) — enforced by the API server itself, independent of whether the runner, the
hub's MCP server, or this LLD's own reasoning about it is ever wrong. So the residual capability a
compromised runner gains is "cause the API server to evaluate a hypothetical write and report the
result," not "cause a write." That is a real capability increase over pure read-only tools (it can
still name resources/fields a compromised runner should not be probing, and it does consume the
argus-dryrun identity's request quota) — it is not the T1/T21 write-execution risk SR-24 was written
to close off.

**What follows from this, stated rather than left implicit:** SR-24's clause should be read as
"read-only tools, plus any tool whose write capability is independently neutralized by a
cluster-enforced, identity-scoped admission restriction — currently exactly one: `dry_run_patch`" —
not as a blanket guarantee that has quietly stopped being true. Any FUTURE tool added to this surface
that is write-capable without an equivalent independent, cluster-enforced restriction is a real SR-24
violation and should be treated as one, not waved through on this addendum's precedent.

## Addendum (2026-10-10): cluster-insight egress and the served-certificate probe

Three additions from `docs/CLUSTER_INSIGHT_SPECS.md`, each with its control:

- **A new agent→hub stream, change batches** (CI-S2). Field-level object changes leave the cluster
  continuously. Controls: the object cache hashes env and ConfigMap values at capture (they are never
  in agent memory as plaintext beyond the informer decode); the stream has its own redaction
  chokepoint (`internal/agent/changes_stream.go` `redactChange`: secret-bearing paths reduced to
  added/removed/modified, every string through the pattern layer); Secrets are never cached. Covered by
  the agent's egress tests; same T8 class as findings.
- **Served-certificate probing, opt-in** (CI-S16, `certExpiry.probeIngressHosts`, default off). When on,
  the investigate agent opens a TLS connection to each Ingress load-balancer address with the host as SNI,
  reads the presented certificate's expiry and closes — no HTTP request, no verification, no Secret read.
  This is the read-only identity's only outbound connection that is not to the API server or the hub.
  Residual: the agent's network position can reach those addresses; an operator who cannot accept that
  leaves the option off (cert-manager expiry still works).
- **Live inspection by people** (CI-S6, capability `cluster:inspect`). Read-only tools reachable from
  the UI through one allowlisted route; output is the same capture-redacted tool output the model sees.
  Logs are the highest-residual read (free text, pattern redaction only) and every log read is written to
  the audit log with actor and arguments.

## Addendum (2026-10-11): personal access tokens and the user-facing MCP endpoint (B13)

`PROJECT.md` AD3 adds a new credential type and a new inbound crossing: people point their own MCP
clients (Claude Code, Cursor, VS Code) at `POST /api/v1/mcp` with a **personal access token**.
Recorded as boundary **B13 — person's MCP client ↔ hub**. It is a second mount of the same
`internal/mcp` server code B12 uses; only the authenticator and the tool executor differ.

**The asset.** A long-lived bearer credential (`argus_pat_<id>_<64 hex>`) that sits in a config file
on a laptop and is used unattended by an AI client. It is more exposed than a session (lives for up
to a year, outside the browser, readable by anything that can read the user's files or the client's
config) and is used by a party — a model — that is itself susceptible to T3 prompt injection.

**Controls, and where each lives:**

- **No capability of its own.** The token names a person; every call re-resolves that person's
  grants and checks the tool's own capability (`cluster:read`, `incident:read`, `cluster:inspect`) on
  the cluster the call names, through the same RLS narrowing as `requireAuth`
  (`internal/api/mcp_user.go`). The cluster is an argument, but it is an argument *checked against
  the actor's scope*, never trusted — non-negotiable 3. A role change, narrowed scope or disabled
  account applies on the next call. Holding a token at all needs `mcp:use`, also re-checked per
  request, so withdrawing it stops existing tokens without revoking them one by one.
- **Read-only by construction, three ways.** The surface (`userMCPCatalogue`) is list/get/search plus
  exactly `POST /clusters/{id}/inspect`'s allowlist; no remediation action, approval, dry-run, triage
  or settings tool exists on it, and `internal/mcp` refuses any other name before dispatch. Hub-side
  tools run their REST handler in a transaction that is always rolled back. Cluster tools reach only
  the read-only `argus-investigate` identity, whose output is capture-redacted (non-negotiable 9).
  A successful injection of the user's AI client therefore gets that user's *reads*, nothing more.
- **Storage.** Only a SHA-256 of the 256-bit secret is stored (`mcp_personal_tokens`, migration
  000128, tenant RLS); the token embeds its row id so authentication is a primary-key lookup followed
  by `crypto/subtle` comparison of hashes (SR-19). The secret is returned once, at creation.
- **Lifetime and revocation.** Expiry is mandatory (default 90 days, max 365). Revocation is
  immediate (`revoked_at`, checked per request); listing and revoking need only a session, never a
  capability, so a person can always kill their own token. Disabled or removed owners are refused.
- **Separation from the REST API.** `requireAuth` accepts only hub-signed JWTs, so a leaked personal
  token cannot drive any REST route — in particular none that mutates. The MCP mount accepts only
  personal tokens; a JWT is refused there.
- **Audit and rate.** Every call — allowed, denied for a capability, refused as off-surface, or
  failed — writes an `audit_events` row in the hash chain (`actor_auth_method = mcp_token`, the token
  id, tool, arguments up to 4 KiB, cluster, outcome), in its own committed transaction. Creation and
  revocation are audited. Each token is rate-limited (60/minute, bursts of 30, in-process like the
  login limiter).

**Residual risk, accepted:** (1) A stolen token is a stolen *read* identity for up to its lifetime —
including log reads, the highest-residual read class (free text, best-effort pattern redaction).
Mitigated by mandatory expiry, per-call auditing (an unfamiliar source IP or tool pattern is visible
in the audit log), and immediate revocation; not prevented. (2) A password change does **not**
revoke personal tokens (they are independent credentials, as with most PAT schemes); an administrator
responding to a suspected account compromise must disable the account, which does stop them. There is
no admin "revoke another user's token" route yet. (3) The rate limiter is per hub process; a
multi-replica hub would multiply the effective limit by the replica count. (4) Data a user's AI
client reads leaves ARGUS for whatever model that client uses — a B5-class exfiltration path the
organisation does not configure. That is inherent to the feature and is the reason `mcp:use` exists
as a separate, withdrawable capability.

## Addendum (2026-10-11): a 10-second grace for a lost refresh-token rotation

**What changed.** Refresh-token reuse detection revoked the whole token family whenever a superseded
token was presented. Live QA showed one ordinary browser tripping it: the hub committed a rotation, the
tab closed or navigated before the response's Set-Cookie landed, and the next page load presented the
retired token — signed out, and audited as theft (`refresh_token.reuse_detected`, 35 events in 36 minutes
on the lab hub, none of them an attack). The client now sends refresh and logout with `keepalive` (the
primary fix). The server additionally accepts **once** the immediate predecessor of a head that has never
been used and was rotated under `RefreshReuseGrace` (10 s, by the database clock), and that exchange
rotates the head itself, so the family never forks; it is audited as `refresh_token.grace_exchange`.
Tokens revoked by sign-out, password change, an administrator or an earlier reuse never qualify.

**Residual risk accepted.** A stolen token replayed within 10 s of its legitimate rotation, before the
real client uses its new token, gets a session. It is not undetected: the grace exchange retired the
real client's token, so the real client's next refresh is reuse — the family is revoked and audited
then. Detection is delayed by at most one renewal interval, not lost. Against that, without the grace a
dropped response costs a forced sign-out and a false compromise alert, and false alerts train
administrators to ignore the real ones. `internal/authz/session.go`; tests in
`internal/authz/session_grace_test.go` and `internal/api/session_lifecycle_db_test.go`.

## Addendum (2026-10-15): node actions, agent self-upgrade, a live path probe, and new agent egress

**What changed.**

- **Node actions** (`CordonNode`, `DrainNode`; PROJECT.md PG15) are typed remediation actions under the
  remediate identity, behind their own chart opt-in (`remediate.nodeOps.enabled`). Their RBAC cannot
  be narrowed: `patch nodes` reaches every node and `create pods/eviction` every pod. Two things bound
  them. An admission policy (`argus-remediate-node-restriction`) refuses any Node update by that
  identity that changes anything but `spec.unschedulable`. Evictions go through the eviction API, so
  disruption budgets hold. Both are on `neverAutoApprove`, and a drain refuses before changing anything
  when a pod has no controller, or has emptyDir data that was not explicitly accepted.
- **Agent self-upgrade** (PROJECT.md AD10) adds a write the model can never reach. `UpgradeAgent` is in
  no list the model is offered. It is signed with the cluster's plan key and pinned to the agent
  Deployment's resourceVersion. It is served only by the remediate identity, whose opt-in Role names
  exactly the two agent Deployments, and the existing Deployment admission policy limits the change to
  the container image. The agent also refuses any image outside its chart's `image.repository`. The
  residual: a compromised hub holding `agent:upgrade` can roll an agent to any image in that one
  repository, including an older one. That is the same trust the hub already holds over what the
  agent chart installs.
- **Live path probe** (PROJECT.md PG16): `trace_service_path` with `probe: true` sends real traffic from
  the agent pod — a DNS lookup, TCP connects, and one HTTP `GET /` — to a Service the agent's cache
  already holds, its cluster IP and up to five ready endpoints. The model can ask for it. Only the
  status is returned, never a body or headers. The new reach is that a model can cause an
  unauthenticated `GET /` against any in-cluster Service, which an application could log or act on.
  That is accepted, with the limits stated: the target is chosen from objects that exist, and the
  request carries nothing.
- **Agent egress to operator-named endpoints** (PROJECT.md PG17, PG22, CI-P9 b): an external
  Prometheus-compatible URL (`metrics.external`), a Kubecost API (`cost.kubecost`) and Argo CD's API
  (`gitops.argocd`). Each is optional and named in the agent chart, never by the hub or the model.
  Credentials come from mounted Secrets, are never in values, and are never returned. Argo CD diff
  values pass the same sensitive-path redaction as last-applied drift, and then the agent's egress
  redaction.
- **Requested changes** (PROJECT.md PG8): a person can turn a rightsizing row into a
  `PatchResourceLimits` plan. The hub re-reads the measurement from the agent and takes no value from
  the request body. The plan enters the ordinary approval path and cannot auto-approve.
- **The remediation identity reports its own authority.** Its heartbeat now carries the answers to
  its own SelfSubjectAccessReviews (patch Deployments and StatefulSets, delete Pods, per namespace).
  These are booleans about ARGUS's own grants, no cluster data. The hub writes them only into the
  `remediation` block of that cluster's facts, from a connection that declared the remediate role
  on the cluster's own mTLS certificate. A forged report could at most make the cluster page claim
  authority the cluster does not grant; execution is still decided by the cluster's RBAC and
  admission, which the report does not touch.
