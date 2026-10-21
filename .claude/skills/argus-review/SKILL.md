---
name: argus-review
description: The "is this ARGUS change actually done" review — runs argus-qa for the checks, then reviews the diff against this codebase's recurring bug classes (RLS scope, capability gates, nullable columns read back, raw error text, hidden controls, tool and action allowlists) and brings PROJECT.md, VERIFICATION.md, the OpenAPI spec and the docs in line with what is now true. Use after implementing a feature or fix, before reporting work complete, or when asked for a review or QA pass on recent changes.
argument-hint: [area or description of what changed — defaults to the working-tree diff]
---

# ARGUS review

The general done-gate for a change under `cmd/`, `internal/`, `web/`, migrations, charts or scripts.
Two other reviews sit beside it and are not replaced by it:

- [`argus-security-review`](../argus-security-review/SKILL.md): the threat-model pass. Run it as
  well for anything touching auth, RLS, credentials, signing, the tunnel, RBAC, a new capability or
  route, or what the model may cause to happen.
- [`argus-design-review`](../argus-design-review/SKILL.md): for anything a user will see.

Work in order. A review that reports success without having run the commands creates false
confidence, which is worse than no review.

## 1. Scope

`$ARGUMENTS` if given; otherwise `git status --short` and `git diff`. The working tree usually holds
several streams of uncommitted work, so review what this change touched, not the whole tree. Ask
if the boundary is unclear.

## 2. Checks

Run [`argus-qa`](../argus-qa/SKILL.md) for the delta and keep its report. Stop and fix anything
red before reviewing further: a review of code that does not build is wasted.

Then ask whether tests exist where they should:

- New or changed pure logic (parsing, validation, a rule, a risk floor, a route decision) has a
  `_test.go` with the happy path **and** an adversarial case. `internal/authz/jwt_test.go`'s
  rejection of an `alg: none` token is the bar.
- A query, a correlation rule or a lifecycle transition has a `*_db_test.go` through
  `internal/dbtest`, and it was run with `ARGUS_TEST_DATABASE_URL` set.
- A new route has its success, 401 and 403 cases covered, in a Go handler test or
  `scripts/smoke-test.sh`.
- A behaviour against a cluster (detection, closure, remediation) was exercised with
  [`argus-live-test`](../argus-live-test/SKILL.md), or the report says it was not.

A plausible test that does not exist is a finding, not a pass.

## 3. The bug classes this codebase keeps reintroducing

Check each one explicitly against the diff:

- **RLS scope.** A handler for one cluster named in the URL calls `authorizeClusterScoped` first: it checks the capability on that cluster and narrows the scope, and tables like `cluster_facts` return no rows without the narrowing. Every query against a `FORCE ROW LEVEL SECURITY` table runs in a transaction
  scoped with `internal/data.SetRequestScope` (handlers get one as `rc.Tx`), or one that sets scope
  itself for a no-session path, as `authz.RotateRefreshToken` does. A bare pool query against a
  scoped table returns zero rows silently under the app role. That has shipped more than once.
- **New tables** carry `tenant_id` (and `cluster_id` when scope-bearing) and are in the RLS set:
  the generic loop in migration `000009`, or their own policy as in `000010_enrollment_tokens`.
- **Routes** go through `requireAuth`, and through `requireCapability` when gated. Capabilities are
  named constants in `internal/authz/permissions.go`, placed in the right built-in roles, never
  inline strings and never handed to every role for convenience.
- **Nullable columns are tested on the read side.** When a migration makes a column nullable, find
  every `SELECT` of it and what it scans into. A bare scan into `string` turned one list route into
  a 500 for every caller the moment the first NULL row existed, and the write path's tests were all
  green.
- **Promises in migration comments.** If a migration says the UI shows something, check something
  renders it.
- **Client errors** never carry raw internal error text. Log it, and return a generic
  `writeProblem` detail; the `requestId` it attaches is what the operator quotes.
- **Constant-time comparison** (`crypto/subtle`) for every token, signature or password check.
- **Disabled, not hidden.** A capability-gated control renders disabled with the missing
  capability named. A refactor that "tidies" it into a conditional render is a regression.
- **Allowlists that decide reachability.** A new remediation action must be in
  `resolution.PermittedActionTypes` or the model can never propose it. A new write tool must be in
  `tunnel.writeToolRoles` or it is dispatched to the read-only identity. A new agent tool must be
  classified in `internal/agent/redact_egress_test.go`. A new rule ID must be in
  `internal/api/settings.go`'s `knownRuleIDs`.
- **Narrowly typed client calls.** A lookup-table value passed to a TypeScript options object with
  one optional field compiles and is silently dropped. Check that the new UI signal reaches the
  request.

Rank the findings by severity with `file:line` and a concrete failure scenario, not "this could be a
problem". Escalate anything security-shaped to `argus-security-review` rather than half-covering it
here.

## 4. Bring the documents in line — do it, do not recommend it

- **`PROJECT.md`** lists open work only (its own "Maintenance rules" section is the authority). A
  finished item is removed, and git history is its record. A partly finished item is rewritten to
  what remains. A new gap gets a row with a never-reused ID. No implementation diaries.
- **`docs/VERIFICATION.md`** gains an entry only for behaviour observed on a live cluster. Passing
  tests does not earn a row. After editing it, or a rule, run `go run ./scripts/coverage`.
- **`docs/openapi.yaml`** changes with any request or response shape, followed by
  `cd web && npm run generate-api-types`.
- **`lld/14-adrs.md`** records a durable decision; a decision that stops being true is retired in
  place with a dated note, never renumbered. **`lld/01-threat-model.md`** gets an addendum when a
  security boundary moves.
- **The user documentation** (the `docs-argus` repository), **`docs/DEPLOYMENT.md`** and **`RUNBOOK.md`** change when behaviour,
  configuration or a procedure changes.
- **Reasoning goes in a comment beside the code** whose shape depends on it: what is true now, and why.
  The history belongs in the commit message.

Never create the retired documents (`STATUS.md`, `BACKLOG.md`, `BUGS.md`, `WORKLOG.md`,
`CAPABILITIES.md`, `DESIGN.md`, or the deleted LLDs), and never add a new citation to one.
`lld/README.md` maps the existing citations.

## 5. Report

1. The checks, as [`argus-qa`](../argus-qa/SKILL.md) reported them.
2. Test coverage findings.
3. Bug-class findings, ranked, with `file:line` and the failure scenario.
4. What was changed in which document.
5. What is handed to `argus-security-review` or `argus-design-review`.

A clean section says so; it is not left out.
