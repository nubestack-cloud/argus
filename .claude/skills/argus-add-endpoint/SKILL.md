---
name: argus-add-endpoint
description: Add a hub HTTP route in ARGUS's established pattern — registration in internal/api/server.go behind requireAuth and requireCapability, a handler on the RLS-scoped transaction, RFC 9457 errors without internal text, a typed response, the OpenAPI schema and generated web types, and tests for success, 401 and 403. Use when adding or changing an API route, or wiring a backend for a new screen.
argument-hint: [method and path, e.g. "GET /api/v1/fleet/summary — what it returns"]
---

# Add a hub API route

Apply [`argus-context`](../argus-context/SKILL.md) first. Work from a precedent rather than from
first principles:

- `internal/api/clusters.go`'s `handleCreateEnrollmentToken` for a write;
- `internal/api/cluster_inspect.go` for a read that goes to an agent over the tunnel;
- any list handler for pagination and scope.

## 1. Does it need auth?

Almost certainly. The exceptions are `/healthz`, `/readyz` and the pre-session auth routes (login,
refresh, the SSO handoff), which scope their own transaction because no session exists yet. An
unauthenticated route that returns data needs an explicit reason. Say it before writing it.

## 2. Register it

```go
s.mux.HandleFunc("POST /api/v1/clusters/{id}/inspect/{tool}",
    s.requireAuth(s.requireCapability(authz.CapClusterInspect, s.handleClusterInspect)))
```

- `requireAuth` (`internal/api/middleware.go`) verifies the session, opens the transaction, sets RLS
  scope, and narrows it to the caller's accessible clusters when their grants are cluster-scoped.
  The handler gets a `*requestContext` (`rc.Tx`, `rc.UserID`, `rc.TenantID`, `rc.Grants`,
  `rc.RequestID`). It commits on a status below 400 and rolls back otherwise; run post-commit side
  effects through `rc.OnCommit`.
- A capability that does not exist yet is a named constant in `internal/authz/permissions.go`,
  added deliberately to the right built-in roles, never to all of them for convenience. Mirror it in
  `web/src/api/capabilities.ts`.
- **A route for one cluster named in the URL** calls `s.authorizeClusterScoped(w, r, rc, capability,
  clusterID)` (`internal/api/resource_changes.go`) before reading anything about it. It checks the
  capability on **that** cluster, records a denial, and narrows the RLS scope to it. The narrowing
  is required as well as the check: an unrestricted caller's scope carries no cluster list, and
  tables such as `cluster_facts` admit only the clusters the scope names. Without it they return
  no rows, silently, on every request. (That shipped once: the metrics gate read "no Prometheus"
  on a cluster that had one.) Never narrow to a client-supplied ID without the check first, because
  narrowing to an unchecked ID widens a scoped caller's reach.
- A route whose cluster comes from a row the caller could already see (an incident's
  `cluster_id`) may narrow to that cluster directly; it cannot widen anything.

## 3. The handler

- **Every query on `rc.Tx`**, never the bare pool. A bare query on a scoped table returns zero rows
  silently under the app role, and has shipped that way more than once.
- **Validate the input before any DB work**, and return 400 with a detail the caller can act on.
- **Never echo internal errors.** Log with the request's logger, and return a generic
  `writeProblem` detail. The problem body already carries `requestId`.
- **Return a typed struct through `writeJSON`.** A missing value is `null` or absent, never a
  fabricated `0` or `""`. A capped list says it is capped and gives the true total.
- **Calls to an agent** go through the gateway with a timeout, and degrade to a typed unavailable
  answer when the agent is offline, rather than a 500.
- **A write** that changes something an operator should be able to trace writes an audit event
  (`internal/audit`) and, for incident state, a timeline event.

## 4. A new table

Carry `tenant_id` (and `cluster_id` when scope-bearing). Enable and force RLS with a policy: the
generic loop in migration `000009`, or its own policy as in `000010_enrollment_tokens`. Migrations
live in `internal/migrations`, with up and down files. A nullable column gets its read paths
checked: `COALESCE` it or scan it into a pointer.

## 5. Contract and client

- `docs/openapi.yaml`: the path, parameters, the response schema with `required` fields, and the
  problem responses. Then `cd web && npm run generate-api-types`.
- Add a typed function to `web/src/api/client.ts` that uses the generated types. No ad hoc `fetch`
  in a component.

## 6. Tests

- Pure validation extracted into a function with its own unit test, including an invalid case.
- A `*_db_test.go` through `internal/dbtest` for the query, including a scope-negative case:
  another tenant's or cluster's row is not returned (SR-1).
- The success, no-token 401, and missing-capability 403 cases, in a handler test or
  `scripts/smoke-test.sh`.
- Then [`argus-qa`](../argus-qa/SKILL.md), and
  [`argus-security-review`](../argus-security-review/SKILL.md) when the route is new or changes who
  can do what.

## Output

The registration line, the handler, any capability and role changes, any migration, the OpenAPI
diff, the client function, the tests, and anything deliberately left out.
