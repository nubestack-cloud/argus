# LLD-14: Decision registers — ADR and D-R

| | |
|---|---|
| **Document** | Low-Level Design — the project's two decision registers |
| **Status** | Accepted decision register |
| **Date** | 2026-08-18; D-R register merged in 2026-09-05; statuses audited against the implementation 2026-09-08 |
| **Purpose** | **Part I** preserves the accepted architecture decisions as ADRs. **Part II** preserves the `D-R` remediation decision register, consolidated here on 2026-09-05. |
| **Depends on** | HLD §23 (the decisions table Part I formalizes, one entry per ADR below) |

**Two ID series, neither ever renumbered.** `ADR-N` in Part I, `D-R N` in Part II; both are cited from
Go, TSX, Helm templates and migrations, so a decision that stops being true is **retired in place**,
with the reason, rather than deleted or renumbered.

> **Audited against the code 2026-09-08.** Where an entry's *status* was wrong, or its Consequences
> read as describing shipped behaviour that the implementation does not have, a dated
> **Implementation status** note was added beneath it. **No entry's reasoning was edited or removed** —
> a decision register's value is that it preserves what was thought at the time, including reasoning
> later overtaken, so a supersession is recorded rather than substituted. Notes added this pass:
> ADR-3/ADR-5 (NATS unbuilt), ADR-4 (its open follow-on is answered in practice), ADR-6 (built;
> retrieval defaults off), ADR-8 (**superseded** — all three controllers now have real ownership
> detection), ADR-10 (its calibration consequence is not implemented), ADR-12 (CRD path unbuilt),
> ADR-16 (harness shipped), **ADR-17 (status was wrong: "designed, not implemented" — it is built)**,
> ADR-18 (persistence landed), D-R1, D-R3, D-R5, D-R7, D-R8 (**stale counts corrected**), D-R9,
> D-R10, and open decisions 0b/5.

**Format:** each ADR follows Context → Decision → Consequences → Alternatives considered. **ADR-15 and ADR-16 are marked `Accepted (provisional)`** rather than plain `Accepted` — they are chosen defaults pending real data (per HLD §0's confidence-marker framework), not settled facts, and every downstream document that cites them says so; this document is where that distinction is formally recorded rather than scattered across citing documents.

---

# Part I — Architectural decisions

## ADR-1: Fork `dot-ai-controller` vs. clean-room the spoke controller

**Status:** Accepted

**Context:** `dot-ai-controller` is MIT-licensed Go/kubebuilder code with a `RemediationPolicy` CRD and event-watching logic close to what this platform needs. Forking is legally unencumbered; the question was maintenance divergence.

**Decision:** Clean-room the controller implementation; copy only the CRD schema and prompt library as specifications to read, not code to inherit.

**Consequences:** No ongoing merge/rebase burden against upstream `dot-ai-controller` changes. Some initial development cost that a fork would have saved is spent instead on re-implementing straightforward reconciliation logic — accepted, because that cost is paid once, while merge-divergence cost compounds indefinitely.

**Alternatives considered:** Forking outright — rejected because the event-egress model (tunnel, not HTTP POST) differs at the core, meaning most of any forked reconciliation loop would need rewriting anyway, at which point a fork provides git history and little else.

---

## ADR-2: LLM evidence-collection loop — hub-side vs. agent-side

**Status:** Accepted

**Context:** The investigation loop could run fully agent-side (fewer tunnel round-trips, better partition tolerance) or hub-side (centralized cost/credential control).

**Decision:** Hub-side for v1.

**Consequences:** Every evidence-gathering hop crosses the tunnel as a `ToolRequest`/`ToolResult` pair (`agent-protocol` §6), adding round-trip latency per turn. In exchange, no cluster ever holds an LLM provider credential, and spend/rate governance (HLD §16.4) has exactly one enforcement point instead of one per spoke.

**Alternatives considered:** Agent-side loop — rejected for v1 because it would require distributing LLM credentials and spend-ceiling enforcement to every cluster, which directly undermines the credential-custody argument (HLD §3.1) the whole pull-topology decision rests on. Revisit only if measured p99 investigation latency becomes a real problem, not a hypothetical one.

---

## ADR-3: Workflow engine for the incident lifecycle

**Status:** Accepted

**Context:** An incident's lifecycle (investigate → approve → execute → validate) is long-running and failure-prone. Options were Temporal (full durable-execution engine), a simpler job-queue library, or a hand-rolled Postgres+NATS state machine.

**Decision:** No Temporal for v1 — a Postgres-backed state machine plus NATS JetStream durable consumers, as fully specified in `remediation-contracts` LLD-08 §2 and its underlying rationale in `retired HLD` §4.3.

**Consequences:** No second stateful distributed system to operate. Idempotency, timeout scheduling, and crash recovery are hand-built rather than inherited from an engine's guarantees — a real engineering cost, mitigated by the fact that the two properties Temporal is usually praised for (exactly-once execution, audit history) were never actually going to come from the engine itself (see the `remediation-contracts` and `retired HLD` §4.3 analysis: idempotency requires application-level keys regardless, and the audit log was always a separate, independent write).

**Implementation status (2026-09-08):** the Postgres-backed state machine is real and load-bearing (`internal/orchestrator/state.go`'s 16 states, `allowedTransitions`, and the `CanTransition` gate inside `SetState`). **The NATS JetStream half was never built** — see ADR-5's note. Idempotency, timeout scheduling and crash recovery are hand-built as this entry predicted, but over Postgres alone plus an in-process event bus (`internal/events`), so "no second stateful distributed system to operate" understates the outcome: there is no second system at all.

**Alternatives considered:** Temporal — the original default recommendation, reversed once single-organisation scope and a 200+ (not 1,000+-from-day-one) cluster target were confirmed, making "fewer moving parts for a smaller platform team" the dominant consideration. River/Asynq-style job queues — considered as a middle ground but not chosen, since the hand-rolled state-machine approach ultimately needed the same idempotency work regardless and a job queue alone doesn't provide the state-machine semantics an incident's lifecycle needs. Temporal remains a valid future fallback if the workflow logic outgrows this design.

---

## ADR-4: Analysis Engine language

**Status:** Accepted (revised 2026-08-19 — superseded original TypeScript decision below)

**Context:** TypeScript and Python were both viable — TypeScript for `dot-ai` lineage and the reference MCP SDK, Python for LLM eval/observability tooling maturity. Revisited once every other hub component (Agent Gateway, Public API, Incident Orchestrator, Policy & Risk Engine, GitOps Service, Notification Service) turned out to already be Go: TypeScript-for-the-Analysis-Engine was the one remaining reason the hub needed two runtimes/containers instead of one, which conflicted with the explicit goal of minimizing end-product container count (`retired HLD` §4.4).

**Decision:** Go.

**Consequences:** The hub's non-datastore components can now run as a single Go binary/container, with the built Web UI's static assets embeddable via `go:embed` — the end product becomes effectively two containers (the hub binary + Postgres) rather than hub + a separate Node.js Analysis Engine. Traded away: the MCP Go SDK is less mature than the TypeScript reference implementation, and `dot-ai`'s TypeScript prompts/tool definitions must be ported as specifications rather than reused as code. The eval-harness tradeoff from the original decision (bespoke tooling instead of Python's eval ecosystem) is unchanged either way, since Python was never chosen.

**Alternatives considered:** TypeScript (the original decision, superseded here) — was correct on its own narrow technical merits (MCP reference SDK, `dot-ai` lineage) but is no longer the dominant consideration once hub-wide consolidation to one binary became the priority. Python — rejected for the same reason as originally: MCP tool-calling is this component's core job, not offline model evaluation.

**Open follow-on, not yet decided:** whether the hub is actually deployed as one process (single container) or kept as separately-deployable Go services sharing one image (current D7 framing — one image, multiple entrypoints). Go for the Analysis Engine makes the former possible; it doesn't by itself decide it. See `PROJECT.md` for this as a flagged next decision.

**Implementation status (2026-09-08): answered in practice, by build rather than by a recorded decision.** The hub ships as one process — `cmd/hub/main.go` runs the gateway, orchestrator sweepers, autoanalyze poller, MCP listener and the embedded UI as goroutines in a single binary (`deploy/helm/argus-hub/README.md` states it plainly), and the only additional container is the optional `cli-runner`. So the follow-on is settled *de facto* for the single-process shape; what remains genuinely undecided is whether the multi-entrypoint capability ADR-7 preserves is ever exercised. Recorded here rather than in the Decision above because nobody appears to have taken it as an explicit decision.

---

## ADR-5: Message bus

**Status:** Accepted

**Context:** NATS JetStream, Kafka, or a Postgres-only queue.

**Decision:** NATS JetStream.

**Consequences:** Lighter operational footprint than Kafka; native subject hierarchies map cleanly onto the cluster/tenant routing model (`agent-protocol` §11's gateway registry, `data-model`'s scope model).

**Alternatives considered:** Kafka — the stated fallback if the organisation already ran it; confirmed it does not, closing this decision without further analysis needed. Postgres-only queue — rejected as insufficiently durable/performant for the findings-ingestion burst rates in HLD §17.1.

**Implementation status (2026-09-08): NOT BUILT, and the rejected alternative is what actually runs.** There is no NATS client in `go.mod`, no NATS service in the Helm chart, and the compose file keeps it commented out with the reason inline. Findings are ingested straight into Postgres and fanned out by an in-process bus (`internal/events/bus.go`, which names JetStream as the eventual design), and Redis is absent for the same reason — `PROJECT.md` `P5` defers both until measured scale justifies them. This is a deliberate deferral, not drift, but two consequences should be stated rather than inferred: the "insufficiently durable/performant" objection to a Postgres-only queue has never been tested against real burst rates, and `lld/01-threat-model.md`'s boundaries **B4** (NATS) and **B11** (Redis) describe crossings that do not exist. The decision stands; the subject group has simply not shipped.

---

## ADR-6: Vector store

**Status:** Accepted

**Context:** Qdrant (dedicated, more scalable) vs. `pgvector` (runs inside the existing Postgres, simpler operationally).

**Decision:** `pgvector` for v1.

**Consequences:** One fewer stateful service to run, monitor, and back up. A ceiling exists on vector-search scale and sophistication that Qdrant doesn't have — accepted, because the knowledge base's own size (not cluster count) is what would actually approach that ceiling, and `analysis-contracts` §5's retrieval interface is written to swap providers behind it without a wider redesign.

**Alternatives considered:** Qdrant — the originally-recommended default for fleets at this scale; reversed once "fewer moving parts for an internal platform team" was established as the deciding factor across several related decisions (ADR-3, ADR-7). Kept as an explicit, low-cost migration path rather than ruled out permanently.

**Implementation status (2026-09-08): built, and the retrieval it enables now defaults OFF.** `internal/knowledge` writes `analysis_embeddings` with a real `pgvector` column and retrieves by cosine distance (`embedding <=> $1::vector`), refusing to persist a fabricated or zero vector when embedding fails. Retrieval is wired into both investigation backends as *labelled prior-belief context, never evidence*, on both the manual (`internal/api/analyze.go`) and automatic (`internal/autoanalyze`) paths — and is gated on `org_settings.retrieval_enabled`, which migration 000102 defaults to `false`. The owner's decision behind that default (2026-09-07, `PROJECT.md` `L2`) is worth recording here because it is exactly the kind of thing this register exists for: measured live against a real repeated fault, retrieval showed **no clear confidence benefit at roughly 31% higher cost**, so it ships as a real setting an operator can turn on rather than running unconditionally wherever embedding happens to be configured. That is an honest negative measurement, not a build gap. ADR-6's own premise is untouched — the provider seam did what it was chosen for; whether the knowledge base earns its place is a separate, still-open question.

---

## ADR-7: Hub image granularity

**Status:** Accepted

**Context:** One multi-entrypoint image for every hub service, vs. one image per service.

**Decision:** One multi-entrypoint image.

**Consequences:** Simpler to build, sign, version, and ship for a self-hosted product — one artifact to track through the supply-chain controls in `deployment-design` §2, not N. Slightly less granular independent-service scaling than separate images would allow, which is not currently a binding constraint at this design's target scale.

**Alternatives considered:** One image per service — rejected as unnecessary operational complexity at this scale; would be reconsidered only if independent per-service release cadences become a real operational need.

---

## ADR-8: Argo CD/Flux integration depth in v1

**Status:** Accepted — **build-priority half SUPERSEDED 2026-09-08 by what shipped; see the Implementation status note below**

**Context:** Read-only detection only, vs. registering Argo CD instances and triggering syncs — originally framed as a phasing question (P2 vs. P3), then resolved further once actual tooling usage was confirmed.

**Decision:** Neither Argo CD nor Flux is in use in the target environment currently. The full design (`retired HLD` §11, `repo-gitops-design` LLD-09) is retained and specified in full, but implementation priority defers Argo/Flux-specific work (ownership detection via tracking annotations, `ApplicationSet` resolution, deep API registration) behind the GitOps-controller-agnostic path (plain kubectl/Helm, the `inPlace`/paired-PR channels).

**Consequences:** No wasted design effort if GitOps tooling is adopted later — the specification exists and doesn't need to be written under time pressure at that point. Some implementation effort that would otherwise go toward Argo-specific code goes toward the paths the current environment actually exercises instead.

**Alternatives considered:** Building Argo/Flux-specific detection first regardless of current usage — rejected once usage was confirmed, since it would front-load engineering effort against a capability nothing in the current environment needs yet.

**Implementation status (2026-09-08) — SUPERSESSION, recorded rather than edited into the Decision above.** Both halves of this entry have been overtaken, and the reasoning is preserved because it is *why* the controller-agnostic path was built first, which is still the right explanation for the shape of the code:

- **The premise no longer holds.** Argo CD is now installed on the `rke2` test cluster and Rancher Fleet is present alongside it (D-R3), and the live GitOps test repository is an Argo CD application. "Neither is in use in the target environment currently" was true when written and is not true now.
- **The deferral no longer holds either — and it was over-delivered rather than skipped.** Of the three items this entry names as deferred, two shipped for *three* controllers, not two: tracking-annotation ownership detection and repository/path/pinned-SHA resolution are real for **Argo CD** (`argocd.argoproj.io/tracking-id`, the `app.kubernetes.io/instance` variant corroborated against the Application, multi-installation disambiguation via `installation-id`, repo resolution from `spec.source`/`status.sync.revision`), **Flux** (`kustomize.toolkit.fluxcd.io`/`helm.toolkit.fluxcd.io` annotation refs resolved through `GitRepository`) and **Rancher Fleet** (`fleet.cattle.io` bundle labels resolved Bundle → GitRepo) — all in `internal/agent/tools.go`'s `get_gitops_ownership`, with a dedicated Argo sync-failure detector in `internal/agent/syncfailure.go` and Argo self-heal field-manager detection in `internal/objdiff/fieldowner.go`. Deep API registration is real too: seven GVKs across the three controllers' groups, read-only in the agent ClusterRole.
- **One of the three genuinely is still deferred, and deliberately so:** `ApplicationSet` resolution. `ApplicationSet` is registered and describable and appears in `argoOwnerKinds`, but is excluded from *repo* resolution because it has no single `spec.source` of its own (`tools.go`). That exclusion is a correct narrowing, not an unfinished edge.

**What survives unchanged, and is the durable part of this decision:** the ownership/back-trace abstraction was built controller-agnostic first and only then given three concrete implementations — D-R3's "two controllers from the start, so the abstraction is forced to be general rather than quietly Argo-shaped" is the decision that actually governed the code, and it held. Argo/Flux support being real does not reinstate the paired-channel or sync-triggering scope this entry deferred; nothing here triggers a sync or registers an Argo CD instance's API.

---

## ADR-9: Cross-tenant learning

**Status:** Accepted — moot

**Context:** Originally framed as "never / opt-in anonymised patterns / opt-out" for a multi-tenant product where one customer's incident patterns might inform another's.

**Decision:** Moot. Single-organisation scope (ADR accompanying the tenancy decision, `retired HLD` §5.1) means there is exactly one tenant; the knowledge base (`analysis-contracts` §5) is org-wide by construction, with no cross-*tenant* boundary to opt into or out of.

**Consequences:** No product decision needed for v1. The dormant multi-tenancy infrastructure (`tenant_id` throughout `data-model`) means this ADR is revisitable as a real decision, not a schema change, if a second organisation is ever hosted on the same hub.

**Alternatives considered:** N/A — superseded by the tenancy-scope decision rather than resolved on its own merits.

---

## ADR-10: Confidence calibration mechanism

**Status:** Accepted

**Context:** Trust the model's self-reported confidence directly, calibrate per-issue-class from shadow-mode outcomes, or train a separate classifier.

**Decision:** Shadow-mode calibration per issue class (HLD §9.4–9.5).

**Consequences:** Raw self-reported confidence is never treated as a probability anywhere in the system (HLD §9.1's explicit rule) — every threshold used for gating (HLD §9.2) is informed by observed shadow-mode outcomes for that specific issue class, not the model's own stated number. Requires a soak period (ADR-15) before any class can rely on this calibration.

**Implementation status (2026-09-08): the Consequences paragraph above describes a control that is NOT implemented, and this is the most consequential status note in this register.** The autonomy gate compares the model's **own self-reported confidence** against an operator-set floor: `internal/remediation.Evaluate` takes `confidence *float64` straight from the analysis and tests it against `AutonomyPolicy.MinConfidenceForAutoApprove` (`org_settings.autonomy_min_confidence_for_auto_approve`, migration 000028). There is no per-issue-class calibration table, no shadow-mode outcome store feeding a threshold, and nothing anywhere that converts a self-reported number into an observed frequency — `PROJECT.md` defers the prerequisite (`L3`/`H3`: "feedback and shadow-mode data exist in sufficient volume for calibration"), and operator feedback is recorded but read by nothing (`L1`).

So "raw self-reported confidence is never treated as a probability anywhere in the system" is, today, false in the one place it matters. Two things keep that from being as bad as it sounds, and both are worth naming so this is not read as either fine or catastrophic: the gate is **conjunctive**, so confidence is never the only condition (risk ceiling, reversibility, deterministic risk floor, freeze/maintenance windows, blast-radius cap, circuit breaker and the namespace allowlist all apply independently, and `internal/remediation/risk.go`'s floor is rules-first per ADR-11); and a `nil` confidence can never satisfy any threshold however low, so an incomplete investigation fails closed rather than reading as 0.0. **The decision is not superseded** — shadow-mode calibration is still the intended mechanism, and ADR-15's soak is still its prerequisite. What is corrected is the tense: this ADR's Consequences should be read as the target state, not the current one.

**Alternatives considered:** Trusting raw self-report — rejected outright as "numerology" (HLD §9.1's own word for it). A separately-trained classifier — a plausible P3+ refinement, not pursued for v1 given the added ML-ops surface it would introduce for a capability shadow-mode calibration already delivers adequately.

---

## ADR-11: Where the risk classifier lives

**Status:** Accepted

**Context:** Should risk be assessed by the LLM, by deterministic rules alone, or by rules with LLM refinement.

**Decision:** Deterministic rules establish a risk floor; the model may only raise risk above that floor, never lower it.

**Consequences:** This is the layer LLD-01 §6 (T3) and §9 identify as the one that actually holds against prompt injection, independent of how sophisticated the injection is — the security posture of the entire remediation path depends on this ADR being implemented as a hard floor, not a suggestion the model can argue past.

**Alternatives considered:** LLM-only risk assessment — rejected as the single highest-severity gap prompt injection could exploit (an attacker-influenced "this is low risk" conclusion with nothing beneath it to catch the error). Rules-only, no LLM input at all — rejected as too rigid to handle legitimate nuance (HLD §9.3's replica-count example: five-replica vs. single-replica restarts of "the same" action type genuinely differ in risk, and a pure rule table would need to enumerate every such distinction by hand).

---

## ADR-12: Multi-cluster policy — CRD-only, hub-only, or both

**Status:** Accepted

**Context:** `RemediationPolicy` could be expressed only as spoke-resident CRDs (GitOps-able but hard to keep in sync across a fleet), only as hub-side config pushed down (easy to keep in sync but not locally-editable), or both.

**Decision:** Both — hub-authored fleet/tenant-wide policy pushed down as CRs, plus locally-authored namespace-scoped policies, merged by the precedence algorithm in `detection-framework` LLD-06 §6.

**Consequences:** Requires the precedence-resolution complexity `detection-framework` specifies (including the catch-all-detector footgun fix) — a real engineering cost, accepted because the alternative (either extreme) fails a real use case: hub-only can't support team self-service; CRD-only can't express fleet-wide policy without manually syncing hundreds of copies.

**Implementation status (2026-09-08): neither half of "both" has shipped as a CR; policy is hub-side settings.** There is no `RemediationPolicy` CRD, no cluster-side policy controller, and no policy-authoring API — `PROJECT.md` `S4` defers the CRD explicitly, and `internal/agent/{detector,pod_conditions_detector,rules}.go` say so in their own headers. What runs is org-level settings behind `org:settings:write` (autonomy ceilings, freeze/maintenance windows, the unattended namespace allowlist) plus declarative rules shipped with the agent (`internal/agent/rules/default-rules.yaml`). Two knock-ons to record rather than leave implicit: `internal/authz.CapPolicyWrite` and `CapPolicyDryrun` exist in the capability catalogue and are granted to roles but **gate no route** (`PROJECT.md` `P7`), and the precedence-resolution complexity this entry accepts as its cost has therefore not been paid or tested. `lld/01-threat-model.md`'s T10 and SR-11 are correspondingly "not applicable yet" rather than met. The one CRD that does ship is unrelated to this decision: `executionwindows.argus.io`, D-R1's per-execution admission-policy scoping.

**Alternatives considered:** CRD-only — rejected, matches `dot-ai`'s own limitation (no fleet-wide policy expression). Hub-only — rejected as removing legitimate local autonomy `rbac-profiles` §6's guardrail split depends on existing at all (a hub-only model has nothing locally-owned to split guardrails into).

---

## ADR-13: Product name

**Status:** Accepted

**Context:** "AEGIS" was a working placeholder; the API group, CRD prefixes, and service-account names all derive from it.

**Decision:** **ARGUS.**

**Consequences:** Every identifier across the design doc, LLD artifacts, and skills was renamed (`argus.io` API group, `argus-investigate`/`argus-dryrun`/`argus-remediate`/`argus-controller` service accounts, `argusctl` CLI). Completed as a mechanical rename with no residual "AEGIS" references in any actively-maintained document. *(Verified 2026-09-08: no "AEGIS" outside `archive/` and this entry's own history. One name in the list never materialised — the fourth spoke identity shipped as `argus-policy-controller`, not `argus-controller`; see D-R1.)*

**Alternatives considered:** Keeping "AEGIS" — available as a no-cost option at decision time; ARGUS was chosen instead, no further alternatives were evaluated since naming doesn't warrant the same depth of trade-off analysis as the other 15 decisions.

---

## ADR-14: Dry-run-capable service account

**Status:** Accepted

**Context:** A strict two-SA (read-only, write) split loses `dry_run_patch` and the precondition-validation capability it enables, since server-side dry-run needs real write verbs. A three-SA split adds one more identity to reason about.

**Decision:** Ship both: `argus-investigate` (pure read) always present; `argus-dryrun` (write restricted to `dryRun=All` by admission policy) as a per-cluster opt-in, with graceful degradation to static validation when absent.

**Consequences:** `rbac-profiles` LLD-04 §5 must specify and maintain the admission-policy binding that makes this SA's write grant meaningfully restricted — without it, this ADR's premise (a "reduced, not zero, privilege" identity) doesn't hold. Clusters that decline the opt-in get weaker validation, an explicit and accepted trade-off rather than a silent one.

**Alternatives considered:** Two-SA split without dry-run — rejected because it silently loses a real validation capability. Merging dry-run capability into `argus-remediate` — rejected because it would mean every cluster wanting *any* remediation validation also has to accept the full remediate SA's write surface, collapsing a meaningful distinction the three-tier design otherwise provides.

---

## ADR-15: Mandatory shadow-soak duration

**Status:** Accepted (provisional — chosen default, not derived from data)

**Context:** Before an issue class can reach Stage 3 (Approve) in the autonomy ladder (HLD §9.4), some minimum shadow-mode observation period is needed so the calibration data (ADR-10) means something. No real per-class incident-frequency data exists yet to derive the right number from.

**Decision:** 20 occurrences of that issue class, or 30 calendar days, whichever is later.

**Consequences:** A rare issue class may take considerably longer than 30 days to accumulate 20 occurrences, delaying its eligibility for approval-gated remediation — accepted as the correct trade-off (a rare class's calibration data is exactly as valuable per-occurrence as a common class's, so waiting for enough of it is right, not a bug). A noisy class hits 20 occurrences quickly but still waits out the 30-day floor, preventing a short lucky/unlucky streak from counting as calibration.

**Alternatives considered:** A free-choice, admin-set number — rejected as not actually resolving the "needs a number" gap HLD §23 flagged; committing to a concrete default, explicitly marked provisional, was judged more useful than leaving it unset. Per-tenant rather than per-issue-class soak — rejected, since calibration is a property of the issue class's behavior, not of which tenant happens to be observing it (and doubly so now that there is exactly one tenant).

---

## ADR-16: Cost model verification

**Status:** Accepted (provisional — process commitment, not a value)

**Context:** HLD §16.3's cost table depends on cumulative-token accounting and prompt-cache hit-rate assumptions that were, at design time, unmeasured hypotheses rather than observed data.

**Decision:** Not a value to pick — a process commitment. A token/cost measurement harness (`analysis-contracts` LLD-07 §7's accounting implementation) ships as an explicit Phase 1 deliverable (`retired HLD` §22), and §16.3's cost table is re-derived from real observed data before any figure from it is quoted externally.

**Consequences:** §16.3's current numbers remain explicitly labeled as hypotheses (per HLD §0's confidence-marker framework) until Phase 1 produces real data — every document in this series that cites the cost model (this one included) inherits that caveat rather than treating the numbers as settled.

**Implementation status (2026-09-08): the process commitment was kept.** Per-analysis token/cost accounting ships, and it ships with the honesty clause this decision implies rather than a convenient number: `analyses.cost_basis` distinguishes `metered` from `subscription` from `unknown`, `internal/api/spend.go` sums only `metered` rows and reports the rest as a separate count instead of folding an unavailable cost into a total, cost is computed from an operator-configured price table (an honest `0` until one is configured, never a fabricated default), and under `subscription` a spend ceiling is surfaced as *inapplicable* rather than silently satisfied — ADR-17's own discipline. What has **not** happened is the second half: §16.3's cost table has not been re-derived from the collected data, so ADR-16 stays `Accepted (provisional)` and its figures stay hypotheses. Separately, and relevant to any capacity claim built on this: the ceiling is measurement, not enforcement — SR-13 (check-and-reserve) is unimplemented, and the manual analyze path logs a breached ceiling and proceeds.

**Alternatives considered:** Accepting the current estimates as sufficient without a measurement harness — rejected, since HLD §16.3 itself states the naive-vs-tuned cost gap is roughly 25×, meaning an error in the underlying assumptions could be off by a similarly large factor — too consequential a number to leave unverified before it's used for real capacity or pricing decisions.

---

## ADR-17: Investigation loop ownership — pluggable investigator backends

**Status:** Accepted (2026-08-21) — ~~designed, not implemented~~ **BUILT; status corrected 2026-09-08.** Both backends ship: `internal/llm.Investigator` with the `api` implementation and `internal/llm/cli_investigator.go`'s `CLIInvestigator`, the runner service at `cmd/cli-runner`, the hub's MCP server surface at `internal/mcp`, per-provider rows in `ai_providers` (`kind IN ('api','cli')`, migration 000034), and `analyses.cost_basis`. `api` remains the default; `cli` is opt-in and off by default, as decided

**Context:** HLD §16.0 answered "can a Claude/ChatGPT subscription substitute for the API?" with a three-reason no. Two of those reasons were specific to *desktop chat applications* and have since been overtaken: coding-agent CLIs (Claude Code, Codex) grew a headless single-shot mode with structured JSON output, which is a genuine programmatic entry point (defeating reason 1), and while a desktop app is an MCP client where ARGUS needs to be the host, a CLI *is* an MCP host — so the relationship inverts rather than blocking (defeating reason 2). Reason 3 (subscription terms) survives, but attaches to the operator's chosen credential, not to the architecture.

Separately, this is not only a cost question. Both CLIs front several model backends — Bedrock, Vertex, corporate gateways, enterprise seat plans, metered keys — including the two (Bedrock, Vertex) whose native APIs are *not* OpenAI-chat-shaped, a gap HLD §16.1's "the abstraction is thin because everything is OpenAI-compatible" premise glosses over.

**Decision:** Introduce a second *kind* of provider backend behind one `Investigator` interface, with the seam at the whole-investigation level rather than at the HTTP client:

- **`api`** — ARGUS owns the loop (`analysis-contracts` §2–§7). **Remains the default and the recommended production path.**
- **`cli`** — an external agent CLI owns the loop; ARGUS becomes an MCP *server* supplying read-only tools. Opt-in, off by default.

The seam cannot go lower: a CLI exposes no per-turn completion call to intercept, so the loop itself is the unit that differs.

**Consequences:**

- Everything downstream of `Investigate` — LLD-08's plan schema, the risk gate, the approval queue, `analyses` persistence — is untouched by construction. That property is the main reason this seam was chosen.
- **Real guarantees are lost under `cli`, and are documented rather than smoothed over** (`analysis-contracts` §10.3): §3's stable-prefix prompt caching becomes unverifiable, so HLD §16.3's cache-hit assumption cannot be measured from this backend; §4's check-bounds-before-each-turn degrades to CLI flags plus a hard process deadline, permitting up to one turn of cost overshoot; §7's per-turn token accounting collapses to an exit-time aggregate, available only for metered credentials.
- **A new threat class, not a louder version of an old one.** Both CLIs ship built-in shell/filesystem/web tools, so prompt injection from evidence content becomes potential code execution in the runner — registered as T21 with SR-22 (pinned allowlist, built-ins disabled, asserted at startup), SR-23 (isolated runner holding no DB credential, mTLS material or signing key, egress-restricted), and SR-24 (per-investigation, single-cluster, read-only MCP tokens). LLD-01 §9 accepts T21 **only** with all three shipping together; SR-22 alone is a blocker, not a milestone.
- **Cost observability must degrade honestly.** A new `cost_basis` (`metered`/`subscription`/`unknown`) is recorded per analysis, and under `subscription` the spend ceiling is surfaced as *inapplicable* rather than silently satisfied by a zero — same discipline as `confidence: null` on a partial analysis. A green-looking safety control that no longer constrains anything is worse than one visibly marked unavailable.

**Implementation status (2026-09-08), against this entry's own three-way T21 condition.** The consequences above all landed as written, and the honesty clauses in particular are real in code (`cost_basis` filtering in `internal/api/spend.go`, `confidence: null` never satisfying a threshold in `internal/remediation.Evaluate`). The T21 mitigations landed **two and a half out of three**, and the half matters:

- **SR-22 — ships.** `cmd/cli-runner` passes `--strict-mcp-config`, an explicit namespaced `--allowedTools`, and `--disallowedTools Bash,Read,Write,Edit,NotebookEdit,WebFetch,WebSearch,Task,TodoWrite`; it refuses a request with an empty allowlist; tests lock both the deny list and the no-MCP-config completion path.
- **SR-24 — ships,** with one reviewed narrowing recorded in `lld/01-threat-model.md`'s own addendum (`dry_run_patch`, neutralised by a cluster-enforced identity-scoped admission policy).
- **SR-23 — ships only its credential half.** The runner is a separate pod with `automountServiceAccountToken: false`, holding no Postgres credential, no agent mTLS material and no plan-signing key, and it is never told which cluster it is investigating. But **no NetworkPolicy exists anywhere in this repository**, so the "egress-restricted" clause is unenforced. This entry says LLD-01 §9 accepts T21 *only* with all three shipping together and that SR-22 alone is a blocker rather than a milestone — by that standard the `cli` backend's off-by-default posture is currently doing work that SR-23 was supposed to do.
- The `cli` backend must not be positioned as a way to avoid API cost. It is a credential/deployment-flexibility feature; the operator determines whether their credential's terms permit unattended use, and the UI states that plainly.

**Alternatives considered:**

- **Swap at the HTTP/chat-completions layer instead.** Rejected as impossible rather than merely worse: there is no per-turn call to intercept when the CLI owns the loop.
- **Host the CLI inside the hub container.** Rejected — it would add a language runtime, a large dependency tree, and a writable `HOME` to a deliberately distroless, read-only, shell-less image that holds the Postgres credential, agent mTLS material, and the plan-signing root key (`deployment-design` §12.1).
- **Implement Bedrock/Vertex native adapters instead**, getting enterprise reach without a CLI backend at all. Still the more correct long-term answer for those two specifically, and not foreclosed by this ADR — but materially more work per provider, and it does nothing for the gateway/enterprise-seat cases.
- **Decline the backend entirely and keep §16.0's original "no."** Rejected because two of its three reasons are now factually obsolete; leaving them standing would make the design doc wrong rather than conservative.


## ADR-18: Resolution channel is decided by code, not by the model

**Status:** **Accepted 2026-08-24.** Implementation: `internal/resolution` and `internal/orchestrator`.

**Context.** `retired HLD` §10.1 specifies four resolution channels (`pullRequest`, `inPlace`,
`pullRequest + inPlace`, `guidance`) chosen by asking who owns the affected resource's desired state.
Migration 000006 created `remediation_plans.channel` for it. That table never held a row and is
declared dead by `schema_coverage_test.go`; the live `remediation_recommendations` has only
`action_type`. So in running code there is no channel concept: it is implied by whichever `ActionType`
the model emitted, steered by one unenforced sentence of prompt text (`internal/llm/toolloop.go`).
Consequences measured in the review: `guidance` is a fallthrough rather than an outcome, the paired
channel is unrepresentable, and the deterministic layer can only *veto* a channel
(`checkGitOpsPrecedence`, at approval time) rather than choose one.

**Decision.** Compute a `Route` in non-AI code *before* the model proposes — a pure function over
ownership, applier presence and source editability — and use it to constrain which action shapes the
per-incident system prompt offers. Persist the route, not the channel-implied-by-action-type.

**Consequences.** Requires a schema change (one `action_type` column cannot express a paired route),
a new pre-proposal applier check (nothing today reads `syncPolicy.automated` or deploy-on-merge CI),
and a channel-neutral notion of "the fix landed" in validation (at the time of this ADR it inner-joined
`remediation_executions`, which the pull-request path never writes — `PROJECT.md` 77; **built 2026-08-24**,
and `internal/orchestrator/validation.go` now carries two clocks, `remediation_executions.executed_at`
for `inPlace` and `incidents.pr_merged_at` for `pullRequest`).
`checkGitOpsPrecedence` keeps its execution-time veto unchanged; routing does not replace defence in
depth.

**Alternatives considered.** *Let the model keep choosing and add a re-router that rewrites an
in-place plan into a PR plan.* Cheaper, and rejected: the rewrite needs the file, the field path and
the pinned revision — exactly the inputs routing would have gathered anyway — so it does the same work
later, to preserve a decision the model should not have made.

**Implementation status (2026-09-08): fully landed, including the schema change this entry said it required.** The route is computed by non-AI code before the model proposes (`internal/resolution.RouteFor`), persisted on the incident rather than implied by action type (`incidents.route`/`route_reason`/`applier`, migration 000062 — the paired route is expressible, which one `action_type` column could not do), constrains the per-incident prompt (`internal/llm.SystemPrompt` via `resolution.PermittedActionTypes`) and is re-checked fail-closed at parse time (`internal/orchestrator.EnforceRoute`). The dead schema this entry's Context describes is gone rather than merely unused: migration 000064 **dropped** `remediation_plans` (and `plan_actions`, `executions`, `approvals`, `action_results`, `pull_requests`, `validations`), so `remediation_plans.channel` no longer exists to mislead anyone — only a comment in `internal/orchestrator/db.go` still names it. `checkGitOpsPrecedence` keeps its execution-time veto, as decided.

**Contract:** `internal/resolution.RouteFor` and its table tests define the `Applier` input, routing
table, and permitted action types. The incident schema, orchestrator tests, and validation sweepers
define persistence, terminal `guidance`, and per-route validation.

**Both open questions were decided 2026-08-24** (§12.9): deploy-on-merge detection does not ship in
the first cut (two appliers — controller, or none), and the route recomputes on re-analysis, visibly,
but never while a plan is in flight. No design input remains open.

---


---

# Part II — the D-R register: how ARGUS changes things

> **Merged in from `REMEDIATION_ROADMAP.md` on 2026-09-05.** *(Corrected 2026-09-08: this banner
> previously named `lld/14-adrs.md` as the source file three times, which is this file — a
> self-referential loop that made the provenance unreadable. The source was the root-level
> `REMEDIATION_ROADMAP.md`, which is what every code citation of a `D-R` decision actually names.)*
> That file had been reduced to "just the D-R decision register" and this file *is* the decision
> register — two registers doing one job. The D-R IDs are **unchanged and never renumbered**: they
> are cited as `REMEDIATION_ROADMAP.md D-R<N>` from Go (`internal/domain/id.go`,
> `internal/gitops/clone.go`, `internal/scm/`, `internal/orchestrator/blastradius.go` and
> `breaker.go`, `internal/secretbox/`, `internal/api/{server,repositories,repository_change}.go`,
> `cmd/hub/main.go`, migrations 000045/000046/000052), from TSX (`web/src/api/types.ts`,
> `web/src/components/RepositoriesCard.tsx`), from Helm templates, and from `retired HLD`,
> `docs/ARCHITECTURE.md`, `lld/01` and `retired LLD-09`.
> `REMEDIATION_ROADMAP.md` was **deleted**, not left as a pointer stub — those citations resolve
> here by the repo's standing convention for retired root documents (`lld/README.md`'s citation
> table), the same way `BACKLOG.md`/`BUGS.md`/`DESIGN.md` references do.
>
> **Two ID series live in this file and they never interleave.** `ADR-N` above — the 16 decisions of
> `retired HLD` §23, plus ADR-17 and ADR-18 (18 entries in total). `D-R N` below — how remediation changes things. Neither
> is ever renumbered; a decision that stops being true is retired in place, with the reason.
>
> **The register is now in numeric order (D-R1 → D-R10).** In the former remediation roadmap it ran
> D-R5–D-R8, D-R9, D-R10, then D-R1–D-R4, an artifact of the order they were written in. Nothing was
> dropped in the reordering; the few sentences that pointed at a *position* ("further down this
> document") now name the decision they meant.

| Question | File |
|---|---|
| What is outstanding? | [`PROJECT.md`](../PROJECT.md) |
| In what order, and why now? | [`PROJECT.md`](../PROJECT.md) |
| What is the contract? | Current implementation and tests under `internal/resolution`, `internal/remediation`, `internal/orchestrator`, `internal/repotools`, and `internal/scm` |
| Does it demonstrably work? | [`docs/VERIFICATION.md`](../docs/VERIFICATION.md), live-observed only |

> **Correction (2026-08-24 review):** D-R8 reads as though the in-place-editing path is settled and
> F11 is next. It is not — `PROJECT.md` records both as open questions, and the review recommended
> the pull-request channel be fixed first (it was; see D-R10). D-R8's own section carries the full
> note.

### The direction these were taken under (owner, 2026-08-22)

Read this before D-R5–D-R8. Four decisions were taken after a review of stages A and B, and
**two of them (D-R5, D-R7) supersede older material the roadmap carried.** Where older text conflicts,
this direction wins.

The owner's stated goal, in their words, is that ARGUS's *"exceptional ability to analyse/discover and
resolve issues"* becomes broad — *"not just basic 101 things"* — with **risk stated to the user and
the acceptable risk level left to their configuration.** That is not a loosening of the safety
position; it is the same conclusion the roadmap reached independently in "How we end up more
capable than dot-ai" (a section moved to `PROJECT.md` on 2026-08-24): breadth is safe when a change is *structured and verified*, and verification is
the prerequisite for the most valuable capability rather than a tax on it.

---

### D-R1. Field-change freedom: per-execution policy scoping

Of the three options in "the one place
breadth genuinely costs something" (a section cut from the old roadmap on 2026-08-24; `git log` has
it), the owner chose **unlock exactly the approved change, briefly,
then re-lock** — full capability *and* a tight compromised-hub bound, at the cost of building a
controller that manages policy lifecycle. This resolves `PROJECT.md` F14 and sets the target for F11:
the allowlist is no longer a permanent fence, so F11 can be planned as genuinely broad. It also means
**unattended execution stays reachable**, which the other two options would have foreclosed or made
irresponsible.

**Implementation status (2026-09-08): the controller was built, and F11 — the thing it was unblocked *for* — was then parked.** The lifecycle machinery is real: the `argus.io/v1 ExecutionWindow` CRD, a dedicated fourth spoke identity (`argus-policy-controller`) whose RBAC names `ExecutionWindow` and nothing else, and `paramRef` clauses on the standing field-restriction `ValidatingAdmissionPolicy` that read it. It is opt-in and **off by default** (`policyController.enabled: false`). The reasoning for keeping it a separate credential is worth preserving verbatim from the chart: `argus-investigate` must stay structurally write-incapable, and letting `argus-remediate` widen its own admission bound would make the one control designed to hold when `argus-remediate` is compromised modifiable by the thing it bounds. What did not follow is F11 — parked by decision 2026-08-26 (see D-R8's correction), so the per-execution unlock currently has no model-reachable breadth to unlock. Recorded because "F14 resolved, F11 unblocked" now reads as a sequence that completed, and it did not.

---

### D-R2. First work item: milestone 2.0 — resolve repo URL + path + pinned SHA from the GitOps controller's own CR

Chosen over "more typed actions" for the reason the roadmap already argued:
on a Helm-managed fleet an in-place fix is reverted by the next upgrade, whereas better advice is not.

---

### D-R3. Test environment: install Argo CD on `rke2`, and also use the already-present Fleet

Two
controllers from the start, so the ownership/back-trace abstraction is forced to be general rather
than quietly Argo-shaped.

**Implementation status (2026-09-08): done, and it worked — the abstraction generalised to three controllers, not two.** Argo CD and Fleet both have real ownership detection, and Flux does too, all behind one `get_gitops_ownership` seam (see ADR-8's supersession note for the specifics). This decision is the reason ADR-8's deferral was over-delivered rather than skipped.

**One operational decision belongs beside this one, recorded 2026-09-06 by the owner:** the GitOps test repository checkout (`~/argus-gitops-work/argocd-argus-test`) is **disposable** — test runs push to it freely and reset it to the remote before a round; setup and the refresh command are in `RUNBOOK.md`. Worth capturing here because it retired a false blocker rather than resolving a real one: the "ambiguous state" that had held up four `E14` matrix rows turned out to be nothing but a checkout 69 commits behind `origin/main` — clean tree, nothing unpushed, no stashes. Nothing was ever at risk. Kept in the register because the next person to find that checkout stale should reset it rather than re-investigate it.

---

### D-R4. Helm guidance before proof: yes, clearly labelled

ARGUS may name a *likely* values key as
explicitly-unverified guidance for a human to check. It may **never** open a PR from that guess —
`retired HLD` §11.1 hard-blocks writing to a file not proven to be the field's source, and that stands
unchanged. This settles open decision 4's interim; the fallback policy for a *proven-impossible*
back-trace at milestone 2.4 is still open.

---

### D-R5. Git access is via provider APIs — **not** cloning

**Cloning is no longer the mechanism.** ARGUS integrates through the **provider REST APIs with one scoped token per provider** (D-R9 — originally written here as "a GitHub App / GitLab application"):
read one file in one request, and create the branch, commit and pull request entirely through the
provider API. No repository copy on disk, no push credential, per-repository grant and revocation by
the customer, and an audit trail on their side as well as ours. This is the model Dependabot,
Renovate and Snyk use, and it is the right one for a product other people run.

Consequences, stated plainly because they invalidate earlier work and earlier text:

- **`internal/gitops/clone.go` (WORKLOG §122) is superseded.** It works and is tested, but it is not
  the path. It is left in place, marked, and should be deleted once the API provider lands unless a
  real "bare git host with no API" customer appears.

  > **Status correction, 2026-09-08.** The API provider landed — `internal/scm/github.go` and
  > `gitlab.go` are real provider-API implementations, and the pull-request write route goes
  > entirely through them (`internal/gitops/propose.go`). But **`clone.go` is not merely "left in
  > place"; it is still on live paths**, so "it is not the path" is no longer accurate as a
  > description of the running system: `internal/repotools`'s checkout cache calls it (the
  > read-only repository tools offered to the model), and `internal/api/repository_locate.go`
  > calls it via `locateObjectFileWithFallback`. Its own header still reads *SUPERSEDED — DO NOT
  > BUILD ON THIS*, which is now misleading about the call graph rather than about the decision.
  > Two consequences to state rather than leave inferred: the "no repository copy on disk, no push
  > credential" property this decision claims holds for the **write** route only, and the "delete
  > it once the API provider lands" instruction cannot be followed without first replacing those
  > two read callers. Neither is a reversal of D-R5 — the write path is exactly as decided — but
  > the clean claim is not yet true end to end.
- **`internal/gitops/locate.go` survives unchanged and is still needed.** It operates on a local
  directory tree, which is exactly what remains after an API tarball fetch for Helm rendering. Its
  hard-won finding stands: the same object was defined twice in Argo CD's own example repo, so
  returning every match and narrowing by the controller's reported path is still correct.
- **Open decisions 0a and 0c below are moot** and marked as such. There is no scratch directory to
  design and no partial-clone gap to close, because there are no clones. This is the clearest
  evidence the decision was right: it deleted two open problems rather than solving them.
- **Helm rendering still needs a whole chart.** That comes from the provider's archive/tarball
  endpoint — one request, no git, no `.git` directory, no push scope — extracted into the renderer
  pod's own tmpfs. Still sandboxed, because rendering still executes untrusted templates.


---

### D-R6. Both providers, GitHub first

Build the `SCMProvider` abstraction (`retired LLD-09` §3 already specifies its shape) against GitHub, then add
GitLab immediately. GitHub first because its App model is the most mature and best documented, and the
live test fixture already uses it; GitLab immediately after so the interface is forced to be genuinely
provider-neutral rather than quietly GitHub-shaped — the failure mode dot-ai demonstrates, where PR
support is github.com-only and everything else degrades (§116).

**Correction to how this was framed (WORKLOG §125).** I asked whether *the owner's* hub could reach
*their* GitLab. Wrong question: this is a product other people buy, so reachability is a **variable the
architecture must accommodate**, not a fact to establish once. And `retired HLD` had already answered it:
ARGUS is **self-hosted in the customer's own infrastructure** (Goals G8, *"no dependency on a vendor
SaaS"*), so the hub sits inside their network and their internal Git is normally reachable. What the
design already requires — and what makes this work rather than an open question — is
**§11.3's "configurable API base URL — required, not optional"** for GHES and GitLab CE/EE. Build that
in from the first commit; it is not a later enterprise add-on.

Two further corrections from the same source: `retired HLD` §11.3 makes **GitLab first-class from v1**
("the more common choice in the kind of organisation that runs 1000 clusters"), so GitHub-first is a
build order and never a tier; and the credential model is **not symmetric** — GitHub has
installation-scoped Apps, GitLab has project/group tokens — so "GitHub App / GitLab app" was sloppy
shorthand on my part.

Open decision 0b is therefore **narrowed, not closed**: the residual case is a customer who runs the
hub somewhere their Git genuinely is not reachable from. The honest answer for them is `retired HLD`
§11.2's own step 6 — *"give up honestly → channel `guidance`, and tell the user that registering the
repo would unlock PR-based fixes. A prompt to configure, not a silent degradation."*


---

### D-R7. Safety net before unattended execution

Auto-remediation is the goal, and the design calls three things mandatory: **R1** rollback replay,
**R2** freeze/maintenance windows, **R3** blast-radius limits.

**Revised 2026-08-22, on the owner's call, and the revision is worth stating rather than quietly
editing.** Unattended execution shipped with **R3 only** (WORKLOG §139). The reasoning: R3 is the one
piece that cannot be added afterwards, because it is the only one that sees a failure no per-incident
assessment can — thirty clusters, one bad image tag, thirty individually low-risk auto-approvable
incidents. R1 and R2 were genuinely absent at that point, so the feature shipped **off by default** with the
setting naming what was missing instead of implying a complete net. **Both have since landed** — R1 as
`POST /api/v1/executions/{id}/rollback` (`internal/api/rollback.go`, live-proven `docs/VERIFICATION.md`
§6w) and R2 as real freeze/maintenance windows enforced in the unattended sweeper
(*path corrected 2026-09-08*: the evaluation is `orchestrator.CheckWindows` in
`internal/orchestrator/windows.go`, called per candidate from `internal/api/unattended.go`;
`internal/api/windows.go` is only the CRUD for the window records, §6s). The revision above is kept because the *reasoning* for shipping R3
first is what a future reader would otherwise re-litigate; the gap it describes is closed.

The risk policy surface itself largely exists — `AutoApproveMaxRisk`, `MinConfidenceForAutoApprove`,
`RequireReversibleForAutoApprove` (migration 000028) are real and enforced, and every plan carries a
computed `RiskLevel` the UI already shows.

So the honest state of the owner's point 5 is: **the policy, the enforcement, the cap, the windows
and the reversal all exist.** What is still deliberately absent is an *automatic* undo when validation
fails — the undo endpoint is real and a human triggers it.

Sequence, as revised, and now complete: broaden capability under human approval → **R3 with auto, off
by default** → **R1 and R2** → auto is something a customer can enable without accepting a known gap.
All three steps are done; whether to enable it against real infrastructure remains an owner decision.

**Status of that last sentence, 2026-09-08 — answered once, narrowly, and deliberately not carried forward.**
The owner authorised unattended execution against real infrastructure for **one scoped run only**
(`E14` row 18, 2026-09-06): one dedicated throwaway namespace, the namespace allowlist confirmed empty
beforehand, scoped to that namespace alone, and returned to empty immediately afterwards — *"not
authorized anywhere else, and this authorization does not carry to a later run."* The run itself
proved the mechanism (a `ScaleDeployment` plan, `risk=low`, gated `AutoApprove`, executed by
`internal/api/unattended.go` with zero human approval action, `unattended=true` confirmed in Postgres)
and the fix held. It also surfaced a separate defect on the incident's own path back to `Resolved`,
tracked on `PROJECT.md`'s board. Read this as: the standing default is still off, the general
"enable it against real infrastructure" decision is **still open**, and a single authorised run is
evidence, not precedent.

**Two gates this section does not mention, verified 2026-09-08 because they bound everything above.**
Unattended execution is gated twice, independently and deny-by-default: `autonomy_unattended_execution_enabled`
defaults `false` (migration 000046), and the namespace allowlist `autonomy_unattended_namespaces`
defaults to the empty array (000055), where empty means deny. Every candidate additionally passes
`CheckWindows`, `CheckBreaker` and `CheckBlastRadius`. What is **not** bounded, and should be read
alongside "the policy, the enforcement, the cap, the windows and the reversal all exist": the
blast-radius and breaker limits are operator-configurable with no upper bound, and there is no
depth limit on the validate-fail → reopen → re-analyse → execute-again loop
(`lld/01-threat-model.md` T11/SR-12). Off-by-default is currently what stands in for that invariant.


---

### D-R8. First build: in-place manifest editing (the owner's path #2)

> **Correction (2026-08-24 architecture review): the framing below reads as decided and is not.**
> `PROJECT.md` §3 records two live questions this section assumes away — *how in-place remediation
> gains breadth at all*, and *whether the enumerated action menu is the right shape* — and STATUS is
> the file that wins on what is settled. Two concrete things changed under this section since it was
> written: `PatchField` was built agent-side and then dead-ended (`internal/api` had no case for it,
> so approving one returned HTTP 500 — `PROJECT.md` 78, **since fixed**: `internal/api/remediation_exec.go`
> has a real `ActionPatchField` execution case and real executions have succeeded), and its per-tenant
> allowlist table was created and orphaned (`patchfield_enabled_fields`, still queried by no Go code).
> So "F11 is next" is a proposal, not a plan of record.
>
> The review's own recommendation is that **F11 is not next**: the pull-request channel, which the
> issue catalogue assigns to 659 of its 1,032 entries against 108 for in-place, was worth more than
> widening the menu. That recommendation was followed and the channel is now fixed — a merged pull
> request closes its own incident (`PROJECT.md` 77, fixed 2026-08-24: `ValidationSweeper` selects on
> `incidents.pr_merged_at` for the pull-request route), and the paired route is expressed. **F11
> itself was then parked by decision on 2026-08-26 — do not make `PatchField` model-reachable** — so
> "F11 is next" is not merely unproven, it is retired. See `PROJECT.md` F11.

F11 (structured patch proposals) plus its two prerequisites, F12 (machine-attested dry-run) and F13
(computed diff + an approval UI that shows it). This is the largest single capability jump available,
D-R1's per-execution policy scoping already unblocked it to be broad rather than narrow, and it
applies to every object whether GitOps-managed or not.

**Progress: F12's gate is built and live-proven (WORKLOG §126).** Every approved remediation is now
rehearsed against the cluster — the hub signs a dry-run twin, the agent submits the byte-identical
patch with `dryRun=All`, and the approval proceeds only if the API server accepted it. Two things this
changed about the plan below:

- **F12 was never blocked on C4.** A dry-run patch uses the same `patch` verb `argus-remediate`
  already holds, so the gate needed no new ServiceAccount. C4's `argus-dryrun` is for the separate,
  model-facing `dry_run_patch` investigation tool and stays blocked.
- **F13 is now much smaller than specified.** A server-side dry run *returns the resulting object*, so
  the API server's own post-defaulting, post-admission "after" state already reaches the hub. F13 is
  hub-side diffing plus UI, with no agent work — the two items turned out to be one mechanism with two
  consumers.

**F13 is also built and live-proven (WORKLOG §127).** `POST /incidents/{id}/preflight` plus a **Preview
change** panel on the approvals page. `internal/objdiff` classifies the diff into what the plan asked
for and what the cluster would do as well — the latter being the only part an approver could not have
predicted, and computable only because the "after" comes from the API server. It cost zero extra cluster
round-trips. ~~**So of D-R8's three items, two are done and F11 is next.**~~ **Superseded 2026-08-26, restated 2026-09-08: two are done and F11 is PARKED, not next** — see the correction block at the head of this section. The sentence is struck rather than deleted because it records the state at the time F13 landed, which is when it was true.

With the honest caveat repeated from Phase 1's own section: **on a Helm-managed fleet these fixes are
stop-gaps the next `helm upgrade` reverts.** They are worth having for unmanaged objects and for
emergency mitigation; the durable answer for the real fleet is still path #4.

### The owner's five paths, mapped

| Path | State | Where it lands |
|---|---|---|
| **1.** Standard methods/calls to resolve issues | **Recounted against the code 2026-09-08 — the previous "5 execute / the other 5 dormant" split is stale.** 11 action types are declared (`internal/remediation/plan.go`). **9 are model-reachable**: eight in-place (`ScaleDeployment`, `RestartPod`, `PatchResourceLimits`, `RevertContainerImage`, `DeleteResource`, `AnnotateResource`, `LabelResource`, `CreateResource`) plus `OpenPR`, per `resolution.PermittedActionTypes` — the authoritative list, read by both the prompt builder and the fail-closed parse-time check. **2 are not model-reachable**, for two different reasons: `PatchField` executes end to end (a real `internal/api` case, real live executions) and is dormant purely on `F11`'s parked decision, while `StructuredPatch` maps to an agent tool name (`patch_structured`) the agent **does not implement**, so it exists only to give the dry-run/attestation pipeline a name. `DeleteResource` is the one verb offered on *every* executable route including `pullRequest` — deliberately, because its narrowly-permitted orphaned-PVC case targets an object that is by definition never GitOps-tracked. | `PROJECT.md` `B130`/`F9`, **decided 2026-09-06 and shipped**: expose all three previously-dormant verbs (`AnnotateResource`, `LabelResource`, `CreateResource`) to the model. This row's old "reachability question, not a build one" is therefore answered for those three. Still deferred by decision: `replaceResource` (never declared) and `F11`/`PatchField` |
| **2.** Edit object YAML in place, like `kubectl edit` | **F12's gate and F13's preflight diff both built and live-proven** (§126, §127); F11 not built | ~~**F11 next**~~ — **F11 PARKED by decision 2026-08-26** (D-R8's correction block). `PatchField` is built, safe and dormant; do not make it model-reachable without a fresh decision. `PROJECT.md` lists `F11` under deferred work, revisited only if a product decision reopens model-authored structured patches |
| **3.** Discover helm/argo/fleet ownership and recommend at source | ✅ **Built and live** — repo, path and pinned commit (WORKLOG §121) | Done; feeds #4 |
| **4.** Suggest changes to argo/helm/GitHub/GitLab | **Built and live** — real pull requests since 2026-08-24; the change shape was generalised to whole-file edits on 2026-08-28 (**D-R10**) | Done; breadth now bounded by *verifying effect*, not by shape |
| **5.** State risk, and let users configure accepted risk | Risk computed and shown; settings real and enforced; unattended execution available but off by default (twice over — the feature flag *and* an empty-by-default namespace allowlist), capped, with freeze/maintenance windows, a circuit breaker and a recorded undo | D-R7 (revised) — R3 shipped with auto, R1/R2 followed. Only *automatic* undo on validation failure is deliberately absent. **2026-09-08:** the confidence half of the risk gate is the model's own self-reported number against an operator floor, not calibrated data — see ADR-10's status note; and the caps are operator-configurable with no depth limit on the reopen→re-execute loop (`lld/01-threat-model.md` SR-12) |


---

### D-R9. Git credentials: one scoped token per provider, org-level, envelope-encrypted

Settles `PROJECT.md` item 33. Arrived at in two passes — the first chose a GitHub App, the owner then
challenged that as unnecessary complexity, and the challenge was largely right. The App analysis is
kept at the bottom as the record of what was considered.

**The mechanism, decided by the owner 2026-08-22: a fine-grained access token per provider. No App.**

| Provider | Credential | Scope |
|---|---|---|
| GitHub / GHES | **Fine-grained personal access token** | The specific repositories, `contents: write` + `pull_requests: write`, with an expiry |
| GitLab / self-hosted | **Group access token** | The group, `api` scope |

`retired HLD` §18.6 already permitted exactly this — *"GitHub App **or fine-grained PAT**, never a
classic PAT"* — so this is choosing between two options the design had already sanctioned, not relaxing
it.

**Why the token and not the App.** Three reasons, in the order that decided it:

1. **It is one mechanism instead of two.** GitLab has no App concept, so an App-based GitHub path would
   have meant two credential models, two setup flows and two code paths behind one interface. D-R6's
   explicit worry is that `SCMProvider` ends up *"quietly GitHub-shaped"* — the failure dot-ai
   demonstrates, where PR support is github.com-only and everything else degrades. A token for both
   providers makes the interface provider-neutral **by construction** rather than by discipline.
2. **Substantially less to build**, and none of what is skipped is a safety control: no App-manifest
   endpoint, no OAuth callback, no one-time code exchange, no JWT signing, no installation-token
   minting or caching, no installation→repository resolution.
3. **The blast radius is nearly identical.** A fine-grained PAT restricted to named repositories with
   those two permissions can do essentially what an App installation scoped the same way can do. The
   App's advantages are real but narrow, and none of them is "safer against a malicious change" — see
   what we give up, below.

#### What this consciously gives up, and the requirement each one creates

Recorded so none of these is rediscovered as a surprise. Each is a real cost, and two of them turn into
implementation requirements rather than mere caveats.

1. **What sits at rest is a live bearer token, not a signing key.** An App stores a private key, which
   is useless without an installation; a PAT row in the database is directly usable by anyone who reads
   it. **This makes D-R9's envelope encryption load-bearing rather than belt-and-braces**, and §18.6's
   other three rules (never logged, redacted in every error path, zeroed after use) stop being
   hygiene and become the actual control.
2. **Renewal is a human's calendar, not a protocol.** App installation tokens re-mint hourly by
   themselves. A fine-grained PAT expires, and when it does, PR creation simply starts failing.
   **Requirement: store the expiry and warn before it, not after.** Reporting "PR creation failed" on
   the day a token dies is exactly the silent-degradation failure this product exists to avoid; the
   same reasoning as the dry-run gate's fail-closed echo (WORKLOG §126).
3. **Rate limits are one account's budget** (a user token gets ~5000 requests/hour) shared with
   everything else that account does, where an App gets per-installation limits. Unlikely to bite,
   because the PR path is low-volume by nature — one PR per *approved* remediation, not per incident —
   but it is the specific thing that would force revisiting this, and at 1000 clusters it is worth
   watching rather than assuming.
4. **Commits and PRs appear as the token's account.** So that account **must be a dedicated machine
   user**, not a real person's, for three separate reasons: it survives offboarding; `git blame` does
   not attribute hundreds of changes to someone who never saw them; and many organisations forbid
   self-approval, so a PAT belonging to a human reviewer would make that reviewer unable to approve
   ARGUS's own PRs — a gotcha that only shows up after the integration is live.

#### The line that holds: named repositories, never "everything this account can reach"

Confirmed by the owner. A classic PAT stays refused, and the reason is sizing rather than purity: *"these
four repositories, two permissions, expires in 90 days"* is an exposure an operator can reason about,
audit and revoke. *"Everything this admin account can reach, forever"* cannot be sized — and a risk that
cannot be sized cannot be *accepted*, only ignored.

The argument that a human reviews the PR anyway is true and does not reach this: **review bounds what
lands, not what the credential can do.** A token can read every file in every reachable repository —
committed secrets, `.env` files, internal source — and delete branches, without ever producing a PR for
anyone to look at. That asymmetry is the whole reason scope is chosen at token-creation time rather than
argued about later.

It also keeps ARGUS internally consistent. The product already ships a `ValidatingAdmissionPolicy` whose
stated purpose is to hold *"even if everything on the ARGUS side is compromised"* (`docs/ARCHITECTURE.md`
§7). Holding repository credentials to a visibly looser standard than cluster writes would undercut the
claim the rest of the product makes about itself.

**Implementation note that follows:** a GitHub organisation can disable fine-grained tokens by policy.
When that is the case ARGUS must say so plainly at setup — "your organisation does not permit
fine-grained tokens; ask an owner to enable them" — rather than failing later with an opaque 403.

#### Org-level, not per-user (unchanged from the first pass)

One integration per installation, configured under `org:settings:write`. Three reasons, in order of
weight:

1. **Unattended remediation has no user.** D-R7's direction is auto-remediation once rollback, freeze
   windows and blast-radius limits exist. A per-user credential makes the PR path *structurally*
   unavailable in the mode it matters most in.
2. **Offboarding breaks it silently** — and the machine-user requirement above is what actually fixes
   this, since a token on a real person's account dies with their access.
3. `retired HLD` §407 already fixes **one organisation per installation**.

**Attribution is kept, just moved off the credential.** The commit and PR come from the machine user;
the human who approved is recorded in the PR body, a commit trailer, and the audit chain. Stronger
provenance than borrowing someone's token: a token proves whose credential was used, the audit chain
proves who decided.

#### Storage (unchanged from the first pass)

Envelope encryption, DEK per secret, **local KEK with a loud warning** — the mode §18.6 explicitly
permits (*"a local key for evaluation only, with a loud warning"*) — ciphertext plus `key_version`, so
§18.6's own rotation rule (*"rotation re-wraps without re-encrypting payloads"*) makes external KMS a
re-wrap later rather than a migration.

Deliberately **not** copying the existing `llm_api_key` precedent, which migration 000018 stores in
plaintext and which is already out of compliance with §18.6. A repository-write credential does not
inherit that gap — and per point 1 above, it now matters more here than it would have with an App.

**Schema:** the seam already exists and is still codeless — `repository_bindings(id, tenant_id,
provider, url, credential_ref, spec jsonb)` from migration 000007. `credential_ref` points at the
encrypted token row; `spec` holds §11.3's `RepositoryBinding` shape.

Builds as **F15**. Nothing here changes D-R8's order.

**Implementation status (2026-09-08): F15 shipped, the seam is no longer codeless, and one of the two
"requirements this creates" is met while the other is the register's most load-bearing open gap.**

- **Built.** `repository_bindings` has real code (`internal/scm/store.go`, extended by migration 000045
  with `credential_ref`, `api_base_url`, `host`, `default_branch`), the org-level CRUD is
  `internal/api/repositories.go` behind `repo:read`/`repo:write`, and both providers are real
  (`internal/scm/github.go`, `gitlab.go`) with §11.3's **configurable API base URL present from the
  start**, exactly as D-R6 required — not retrofitted.
- **Requirement 2 ("store the expiry and warn before it, not after") — MET.** `credential_expires_at`
  is stored and `expiresInDays` is computed server-side so every consumer agrees on when to warn,
  with already-expired distinguishable from expiring-soon; `scm.ErrCredentialExpired` maps a provider
  401 to a message that says *renew it rather than widening its scope*.
- **Requirement 1 ("envelope encryption is load-bearing rather than belt-and-braces") — ⚠️ NOT MET IN
  SUBSTANCE, and this is worth stating bluntly because this decision's own reasoning is what makes it
  serious.** `internal/secretbox` does implement the envelope (fresh 256-bit DEK per secret,
  AES-256-GCM twice, `key_version` beside the ciphertext, `Zero` after use, and it is the SCM token's
  only storage path — the `llm_api_key` plaintext precedent was correctly not inherited). But it
  ships only §18.6's **local-KEK evaluation mode**, and that KEK is loaded through
  `internal/data.LoadOrCreateSigningKey` under purpose `secret_kek_local_v1` — i.e. **it lives in the
  same Postgres as the ciphertext it wraps.** Against the threat this decision names by name — "a PAT
  row in the database is directly usable by anyone who reads it" — the envelope currently buys
  nothing, because whoever can read the row can read the key. `Keeper.LocalKEKWarning` exists so a
  deployment says so out loud, and `key_version` means an external KMS is a re-wrap rather than a
  migration, so the structural work was done and only the KEK's *placement* is wrong. Recorded here
  rather than filed away because this decision explicitly traded the App's signing-key-at-rest
  property for the token's convenience **on the strength of envelope encryption**, and that half of
  the trade is not yet delivered. See `lld/01-threat-model.md`'s KEK asset row.
- **Point 4's machine-user requirement** is documented but not enforceable by ARGUS — it is a property
  of the account the operator creates the token on. Unchanged; noted so it is not mistaken for a
  control.

<details>
<summary>First pass: the GitHub App analysis, kept as the record of what was considered</summary>

The first version of this decision chose a GitHub App for GitHub — installation-scoped, hourly tokens,
per-repository grant and revocation. The owner challenged it as unnecessary complexity given that a
human approves every PR, and that challenge was largely right: the App's advantages turned out to be
narrower than the first pass implied (see "what this gives up" above — none of the four is *safety*
against a malicious change).

One genuinely useful thing came out of the App pass and is worth keeping, because it is the reason the
App would have been more work than it looked. `retired HLD`, D-R9's first draft, F15 and `retired LLD-09` all
said "GitHub App" **without ever saying whose**, and the phrase "the ARGUS App identity" reads as a
vendor-published Marketplace app. That model is structurally impossible here on two counts:

- **ARGUS is self-hosted** (Goals G8). The customer's own hub calls the API, so it would need the
  vendor's private key shipped in the image — one credential able to act on every customer's
  repositories.
- **GHES.** A github.com-published App has no route to a customer's internal GitHub Enterprise Server,
  contradicting §11.3's own required configurable API base URL.

So an App here would have had to be **customer-created, in their own org, from a manifest ARGUS
supplies** (the self-hosted Renovate / Atlantis model) — which is a manifest endpoint, a callback and a
code exchange before the first PR can open. That cost is part of why the token won.

If a customer ever needs the App's specific advantages — hourly token rotation, per-installation rate
limits, a distinct bot identity — it can be added behind the same `SCMProvider` credential interface
without disturbing the token path.

</details>

---

### D-R10. A repository change is a set of whole-file edits, and the pull request's gate is human review (owner, 2026-08-28)

**Decision.** The single-field repository-change grammar — `filePath` + `fieldPath` + `newValue`, proved
minimal by `gitops.verifyOnlyFieldChanged` — is **deleted**. The only repository-change shape is **a set
of whole-file edits, one file or many**, each carrying the file's complete new content, against any
repository kind: plain YAML, Helm charts and values, Kustomize, templated anything.

**Why, in the owner's terms.** *"We need to build this AI-assisted solution ability and mechanisms that
facilitate us achieving this, not hardcoded per-issue narrow mechanisms… we need to cover hundreds and
thousands of cases."* A grammar extended one source format at a time cannot reach that; `PROJECT.md`
F22's own six-piece breakdown — six pieces to reach *one* more format — is the evidence.

**Why the safety argument holds.** `verifyOnlyFieldChanged` proved *minimality* and was being offered as
proof of *safety*. They are different claims: a one-line edit to the wrong key is minimal and wrong. The
pull-request channel's gate always was human review of the diff, backed by boundaries that are
unchanged — `scm.ForbiddenPath` (CI, `.github/**`, `Chart.yaml`, secrets, `scripts/**`), repository and
synced-directory confinement, reads pinned to the synced commit with compare-and-swap on push, **no
auto-merge ever**, `CapRemediationExecPR` plus approval, plan signing, redaction on egress. **The
in-place channel is untouched** and its checks stay airtight, because nothing stands between it and a
live cluster. Never relax one channel on the strength of the other.

**What it cost to keep, and what it buys to drop.** The old grammar could reach one scalar, in one file
that already existed, that was not templated. The pull-request route is the route **659 of 1,032**
catalogue entries need. It also silently closed seven separate live findings recorded in `PROJECT.md`
(`AA1`, `AB1`, `AC1`, `AE1`, `AK1`, `AM1`, `AY1`), each of which was the same finding: the correct fix
had no expressible shape.

**Implementation status (2026-09-08): the boundaries are real, and it is worth recording exactly WHERE
the denylist is enforced, because that shape is easy to misread as defence in depth and it is not.**
Every boundary this decision names is present in code: `scm.ForbiddenPath`'s non-overridable
`builtinForbiddenPaths` (CI definitions and everything that configures them, the things CI invokes —
`Dockerfile`/`Makefile`/`scripts/**`/`**/*.sh` — encrypted content ARGUS cannot read and therefore
cannot minimally edit, `Chart.yaml`/`Chart.lock`, Kustomize entry points, and Argo's
`.argocd-source*.yaml`), binding patterns checked *in addition to* rather than instead of those, a
path normaliser that refuses a `..` traversal with a sentinel rather than cleaning it up, synced-directory
confinement, pinned reads with compare-and-swap on push, no auto-merge, `CapRemediationExecPR`, plan
signing, and redaction echo-guarding on egress (`internal/gitops/files.go` refuses proposed content
carrying `redact.Marker` that the original did not).

**The denylist is enforced at exactly ONE point on this write route, and this entry should not be read
as claiming otherwise.** The five byte-writing provider methods — `CreateBranch`, `PutFile`,
`PutFiles`, `DeleteFile`, `OpenPullRequest` in `internal/scm/{github,gitlab}.go` — apply **no denylist
of their own**; `scm.ForbiddenPath` is called by the caller, in `internal/gitops/propose.go`. That is
currently sound, and the reason is structural rather than lucky: `internal/gitops/propose.go` is the
**only** file in the repository that calls any of those five methods, and its two entry points
(`PreviewChanges`, `ProposeChanges`) are the only way in. It is nevertheless a single chokepoint, so
the invariant to preserve is *"nothing outside `internal/gitops/propose.go` calls an `SCMProvider`
write method"* — a second caller would bypass the denylist silently, with no test failing. The
model-facing repository tools (`internal/repotools`) and the preview/read routes apply
`ForbiddenPath` independently for their own reasons; those are separate surfaces, not a second layer
under this one.

**Supersedes:** D-R8's premise that widening the in-place action menu is where breadth comes from; the
2026-08-24 review's recommendation that the pull-request channel be fixed first was right, and this is
that fix. **Full reasoning:** `retired HLD` §11.4, "Why the minimality proof was removed".

---

### D-R11. Earned promotion is on, and an anomaly with no observed consequence never opens an incident (owner, 2026-09-18)

Two decisions, taken together because the second is what makes the first safe.

**Earned promotion is enabled.** `internal/gateway/earned_promotion.go`'s
`defaultEarnedPromotionConfig.Enabled` is `true`. It stays a compile-time constant rather than a
settings row on purpose: a remotely flippable row would let this be re-decided by whoever next
calls `PUT /api/v1/admin/settings`.

It was enabled against a measurement, and the measurement only became meaningful once the
sustained-window clock was fixed — that criterion previously read the condition's own
`lastTransitionTime`, which for a persistent misconfiguration never advances, so the window was
permanently zero and the mechanism could not have fired for the cases it exists to serve. On the
corrected ingest clock: **195 anomaly groups pass corroboration and the sustained window, and 2 of
those also satisfy the impact criterion.**

**The impact criterion stands, and the consequence is accepted.** An `Anomaly`-classed finding is
promoted only where a real fault was observed on the same object, or on an object that names it.
That ratio (195 -> 2) is the mechanism working as designed, not a gap to close.

The accepted cost, stated plainly so it is not rediscovered as a bug: **a dangling reference with
no observed consequence never opens an incident.** Measured the same day,
`GenericDanglingReference` had 80 groups passing corroboration and the sustained window and **0**
passing impact. So a `RoleBinding` naming a nonexistent `ServiceAccount` stays a queryable finding
forever. Two board items whose acceptance bar was exactly "this opens an incident" were closed
against this decision rather than left open: the generic-reference scan fix (which was itself
complete and committed), and the last half of the Gateway API coverage item.

If that trade is ever revisited, the change is to relax impact for *reference-direction* findings
specifically, and the number to re-measure first is that 80.

### Decided by the owner, but not yet given a register entry — flagged 2026-09-08, deliberately not numbered here

`PROJECT.md`'s own maintenance rule 3 says durable architectural decisions belong in this file rather
than in an item narrative. Two owner decisions from 2026-09-07 are durable by that standard, are
already implemented or in build, and have **no ADR or D-R entry**. They are recorded here as a
pointer rather than minted as `D-R11`/`D-R12`, because assigning an ID in a never-renumbered series
is the owner's call, not an auditor's:

1. **A distinct `Expired` incident outcome, rather than overloading `Dismissed`** (`PROJECT.md` `T2`).
   Built: `orchestrator.StateExpired` with its own legal transitions, migration 000101 reclassifying
   42 historical rows, and `internal/api/incident_promotion_reconcile.go` closing as `Expired` with a
   reason on the audit chain. The distinction it buys is honest and load-bearing — `Expired` means
   *nobody established that anything was wrong or that anything was fixed*, so it leaves
   `resolution_kind` NULL where `Dismissed` would have implied a judgement, and correlation
   deliberately still treats it as **open** so a genuine recurrence can re-attach. Worth an entry
   because a future reader will otherwise ask why there are two closed-but-not-resolved states.
   *(Note: `PROJECT.md` still lists `T2` under Open decisions as well as under Decided — that
   inconsistency is in that file, not this one.)*
2. **Earned promotion for generic anomalies** (`PROJECT.md` `B153`). A generic condition anomaly may
   open an incident, but only by earning it — repeated observation over time, condition polarity
   confirmed, observed impact — never on first sight. `internal/gateway/earned_promotion.go` is built
   and **disabled by default** (`Enabled: false`, short-circuited before any query), which is the
   correct posture given the measured basis: all 58 incidents these predicates opened before the
   promotion gate closed were dismissed. The counter-argument the decision preserves is why the
   predicates exist at all — they are the only detection reaching kinds nobody coded for, and are
   what makes Gateway API's 32 catalogue entries visible with no Gateway-specific detector. Three of
   the six kind-agnostic predicates emit `Class=Anomaly` and therefore cannot open an incident today
   (`internal/gateway/promotion.go` requires `Fault`); the other three set no class and can.

### D-R12. Cluster insight: Helm status from Secret labels, GitOps quick actions, live inspection (owner, 2026-10-10)

**Context.** The cluster-insight features (`docs/CLUSTER_INSIGHT_SPECS.md`) needed three decisions the
non-negotiables do not settle on their own.

**Decision.**
1. **Helm release status reads release Secrets' labels, never their payload** (CI-S17). The agent's single
   named Secret `get` — until now used only by `describe_resource` — gains a second consumer,
   `internal/agent/tools_certs_helm.go`'s `helmSecretMeta`, which fetches `sh.helm.release.v1.<release>.v<N>`
   by exact name, keeps the `name/owner/status/version/modifiedAt/createdAt` labels and discards
   `data` in the same function. No `list` on Secrets is granted; release names come from the
   `meta.helm.sh/release-*` annotations on objects already in the object cache. Chart version, values,
   manifests and notes stay unread, and the UI says so.
2. **GitOps quick actions are human-initiated AnnotateResource plans** (CI-S15): Argo CD
   `argocd.argoproj.io/refresh` and Flux `reconcile.fluxcd.io/requestedAt`. They become ordinary
   recommendations on the incident's latest analysis, gated by the live autonomy policy (nil confidence,
   so never auto-approved), and execute only through the normal approval and remediate-identity path.
   A dedicated admission policy (`argus-remediate-gitops-reconcile-only`) holds the remediate identity
   to exactly those two annotation keys on those kinds. Neither request changes desired state, so the
   GitOps rule (non-negotiable 5) is respected. **Suspend/resume is NOT included**: `spec.suspend` is
   excluded from the PatchField allowlist as intent (`patchfield_test.go`), and changing that rule is a
   separate decision.
3. **Live inspection is its own capability** (CI-S6): `cluster:inspect` gates on-demand reads through the
   agent — redacted YAML, events, logs, relationships and the cluster-insight analyses — via one
   allowlisted route (`POST /api/v1/clusters/{id}/inspect/{tool}`). Log reads are audited.

**Consequences.** One more code path touches Secrets (metadata only); the ClusterRole comment names it.
Quick actions need remediation enabled on the cluster. Viewers can read live object detail unless a
custom role withholds `cluster:inspect`.

### D-R open decisions that still need an owner

**Raised by an owner review of stage B (WORKLOG §123) — these three were the ones blocking
further Phase 2 work, and none of them should be decided by whoever writes the next commit:**

0a. ~~**Where do clones land, and on what filesystem?**~~ **MOOT — resolved by D-R5.** There are no
   clones, so there is no hub scratch directory to design. The renderer pod still needs a tmpfs for an
   extracted chart archive, which it owns itself at milestone 2.2. Kept for the record because the
   decision that removed the problem is more interesting than an answer would have been. Original
   text: Not yet decided, and stage B shipped without
   deciding it — `CloneOptions.Dir` is caller-supplied and nothing in production calls it, so the
   question was deferred by accident rather than on purpose. It needs an answer before anything wires
   this into an incident path. Constraints that shape it: the agent runs with
   `readOnlyRootFilesystem: true` and one `emptyDir` for its data dir, and `retired LLD-09` §2 requires the
   renderer's only writable filesystem to be a size-capped `tmpfs` destroyed on completion. There is
   the `argus-hub` Helm chart only landed on 2026-08-22 (`PROJECT.md` P1), so nothing has
   forced the decision. Options: a size-capped `emptyDir`/tmpfs on the hub; a dedicated renderer pod
   owning its own scratch (which is where this ends up anyway at 2.2); or a PVC-backed content-addressed
   cache as `retired LLD-09` §4's design implies. Whichever, it must be wiped per operation, not accumulated.

0b. **Is the repository reachable from the hub at all?** — **NOW ON THE CRITICAL PATH** (D-R6 picks
   GitLab as the second provider, and an internal GitLab is exactly the case this asks about).
   **Status 2026-09-08: narrowed further, still open, and no longer urgent.** D-R6's actual
   requirement shipped — both providers are real and each takes a configurable API base URL
   (`internal/scm/{github,gitlab}.go`, `repository_bindings.api_base_url`), so a hub inside the
   customer's network reaches their internal GHES or GitLab CE/EE with no new mechanism. The
   residual case is unchanged and unanswered: a hub deployed somewhere its Git genuinely is not
   reachable from, for which the honest answer remains §11.2 step 6's `guidance` channel plus a
   prompt to configure. Also still untested rather than decided: GitLab behaviour is covered by
   implementation tests only and has never been exercised against a live GitLab installation
   (`PROJECT.md`'s known limitations). `retired LLD-09` assumes hub-side repository work,
   and that assumption has never been tested against a customer whose Git server is an internal
   GitLab reachable only from inside the cluster network, or an air-gapped install. If it is not
   reachable, hub-side cloning cannot work and the repository leg would have to move to the agent —
   which changes the credential model completely (a per-cluster Git credential in the cluster, rather
   than one hub-side secret). This is a genuine architectural question, not a bug, and it is cheaper to
   answer now than after 2.1–2.6 are built on the hub-side assumption.

0c. ~~**Partial clone needs the `git` binary.**~~ **MOOT — resolved by D-R5.** No clones, so no
   partial-clone gap and no clone cache to build. A provider API fetches one file directly; Helm
   rendering fetches one archive. Original text: `retired LLD-09` §4
   asks for `--depth 1 --filter=blob:none` plus sparse checkout. Sparse is now implemented and
   measured (71 → 2 files materialised on the real repo); `--filter=blob:none` is **not supported by
   go-git at all**, so it reduces what is written to disk but not what is fetched over the network.
   Closing it means either the git binary (in the renderer image, which needs `helm` anyway — so this
   may resolve itself at 2.2) or accepting full-blob fetches. Also still unbuilt: `retired LLD-09` §4's
   content-addressed clone cache keyed on `(repo_url, resolved_sha, sparse_path)`, without which a
   repo is re-cloned per operation.

**On the read mechanism itself, for the record — and this paragraph describes a position that was
subsequently reversed.** Cloning was originally kept over the provider Contents APIs on portability
grounds: one code path for GitHub, GitLab, Gitea, Bitbucket and a bare https remote, where provider
APIs need an implementation each, and dot-ai shows the cost of the other choice (github.com-only PR
support, everything else degrading to `pushed_without_pr`). **D-R5 later reversed this** — cloning is
no longer the mechanism, and `internal/scm/github.go` and `internal/scm/gitlab.go` are real provider-API
implementations. The portability cost the paragraph predicted was paid exactly as described: two
implementations, with three documented GitLab/GitHub asymmetries. It is kept because the tradeoff is
the thing a future third provider will have to re-decide.

**Distroless stays.** The hub image carries no shell and no package manager, which is why go-git was
the right call over shelling out to `git`. The apparent tension — Helm rendering needs the `helm`
binary — resolves without touching the hub, because `retired LLD-09` §2 puts rendering in a *separate*
sandboxed pod, which can carry whatever binaries it needs. There is already precedent and a written
argument for exactly this shape: the `cli-runner` image is "the ONE image in this repo that is
deliberately not distroless", justified because it "holds no database credential, no agent mTLS
material and no plan-signing key (SR-23)". A renderer pod is the same trade.



1. **gVisor vs Firecracker** for the rendering sandbox — `retired LLD-09` §9 leaves this open. Not needed
   until milestone 2.2.
2. **The network opt-in mechanism** for chart `dependencies` fetching is unspecified (`retired LLD-09` §9).
3. **Does Phase 1a stay single-object?** — *provisionally yes, no decision needed yet.* Re-examined
   while recording D-R1: `CreateResource`'s headline case does not actually need two objects. Creating
   the missing ConfigMap alone fixes the fault, because the kubelet retries the mount on its own — the
   Deployment needs no edit. Multi-object plans can wait for a case that genuinely requires them.
4. **Helm back-trace fallback at milestone 2.4** — when a values key is *provably* unavailable (the
   field is hardcoded in a template, or set in a dependency subchart), is a patch/post-renderer overlay
   an acceptable PR shape, or is a human-readable description the only honest output? Some teams reject
   overlay-shaped PRs on style grounds. D-R4 covers the pre-proof interim; this is the end state.
5. **`replaceResource`** — recommendation is that it stays deferred (the old roadmap's "Phase 1c"; `git log`); confirm when F11
   lands, since F11's structured patches make it largely unnecessary. **Status 2026-09-08: still deferred, but its confirmation trigger has become unreachable.** F11 was parked by decision on 2026-08-26, so "confirm when F11 lands" now waits on something that is not scheduled to happen. `replaceResource` was never declared as an `ActionType`, and `internal/agent/createresource.go` and `internal/api/remediation_exec.go` both refuse to let `CreateResource` silently become a replace, each pointing at this deferral by name. Needs a new trigger, or an explicit "deferred indefinitely".
6. **Credential model** — settled by D-R9: a fine-grained PAT / group access token (originally written here as "GitHub App (recommended: scoped, revocable, auditable)") vs PAT, and where
   `credential_ref` resolves to. Needed at milestone 2.1, i.e. before stage D of the test loop. *(2026-09-08: closed in code — `credential_ref` resolves to an envelope-encrypted row read through `internal/scm.Store`, migration 000045. The one part of D-R9 still open is the KEK's placement, not the credential model; see D-R9's status note.)*
