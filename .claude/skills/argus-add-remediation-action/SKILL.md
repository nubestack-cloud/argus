---
name: argus-add-remediation-action
description: Add a typed remediation action to ARGUS — the closed plan schema, a deterministic risk floor, the resolution route that may offer it, the hub-side preparation and guardrails, the agent executor under the separate remediate identity with its admission-policy fence, live preconditions, rollback, validation, and the unattended-eligibility decision. The highest-risk extension point in the product. Use when asked to add a remediation action, fix type, executor capability or new kind of change ARGUS can make.
argument-hint: [action name and what it changes, e.g. "SetHPAMinReplicas — raise an HPA's minReplicas"]
---

# Add a remediation action

Apply [`argus-context`](../argus-context/SKILL.md) first, especially non-negotiables 2 (the model
proposes, code decides and executes), 5 (GitOps-owned objects change through Git), 6 and 7 (the
automation gate and approval integrity). Finish with **both**
[`argus-review`](../argus-review/SKILL.md) and
[`argus-security-review`](../argus-security-review/SKILL.md). This path writes to production, and
it does not get the lighter pass.

Study an existing type end to end before writing one. `RevertContainerImage` shows the hub
resolving a value from live state instead of trusting the model. `AnnotateResource` and
`LabelResource` are the smallest complete pair. Follow one through every file below.

## 1. Is a new type the right answer?

There are eleven types (`internal/remediation/plan.go`'s `validActionTypes`), and two of them are
general: `PatchField` (one allowlisted field path) and `StructuredPatch` (several). Many "new
actions" are a new allowlisted path in `internal/remediation/fieldpaths.go` instead, which keeps
the closed schema closed. Add a type only when the change has its own shape: its own
preconditions, rollback or validation. **Never** add a generic "path plus value" or string-patch
type (SR-4).

## 2. The schema — `internal/remediation`

- An `ActionType` constant, the entry in `validActionTypes`, and a typed params struct with every
  field bounded. Validation lives in the type's own file, in the style of `annotatelabel.go`.
- **The risk floor** in `risk.go` (`BaseRiskFloors`, plus the context modifiers: stateful kinds,
  protected namespaces, protected annotations). The model may raise risk and never lower it below
  this floor. Decide the floor from what the action can break, not from how it is usually used.
- **Unattended eligibility.** `neverAutoApprove` in `risk.go` lists types that always need a human.
  Anything whose value needs judgement (a limit, an image, a field value) or that deletes belongs
  on it. Assume an action not on the list is reachable by the unattended executor
  (`internal/api/unattended.go`), even though that executor is off by default.

## 3. The route decides whether the model may even offer it — `internal/resolution`

`resolution.PermittedActionTypes(route)` is the only list of what a plan may contain for an
incident's route (pull request, in place, both, or guidance). The prompt builder and the
fail-closed parse check both read it. **A type missing from it is unreachable however well it is
built**, and this has caused three live defects. For a GitOps-owned object the in-place form stays
off unless the route allows it; the pull-request channel is the default.

Also teach the model the shape: the plan schema and the guidance in `internal/llm` (`toolloop.go`,
and `correction.go` for the repair path), so a malformed proposal is corrected rather than dropped.

## 4. The hub side — `internal/execution`

- `execute.go`'s `ToolForAction`: the agent tool that carries it.
- `prepare.go`: resolve the live target and its `resourceVersion`, and resolve hub-derived values
  from live state rather than from the model.
- `guardrails.go`: refuse, or require an explicit confirmation token for, the dangerous cases (scaling
  up from zero, an object a Helm release or GitOps controller owns).
- `undo.go`: capture the rollback **before** the mutation, so undo needs no re-analysis. If there is
  no safe undo, say so and set the risk floor accordingly.
- **Verify the change held**: after execution, read the object back and compare it with what was
  planned (`verifyMutationApplied` and the `verify*Held` functions).
- Preflight (`internal/api/preflight.go`) dry-runs the action through the remediate identity before
  approval, so RBAC and admission are exercised before a human is asked. Make sure the new type
  dry-runs.
- The human-readable summary for audit and the UI lives in `internal/api/remediation.go`.

## 5. The agent side — under the separate remediate identity

- An executor in `internal/agent` (`tools_remediation.go` or the type's own file), dispatched from
  `tools.go`. It re-verifies the plan signature and sends the `resourceVersion` precondition
  **inside** the mutating call (SR-20), never as check-then-apply.
- Its tool name goes in `tunnel.writeToolRoles`, or it is dispatched to the read-only connection and
  fails.
- Classify it in `internal/agent/redact_egress_test.go`.
- RBAC: the exact verbs and resources in `deploy/helm/argus-agent/templates/remediate-role.yaml`,
  namespace-scoped by default. **The admission fence** in `validatingadmissionpolicy.yaml` must allow
  exactly the fields this action changes and nothing more. Never Secrets, RBAC, admission webhooks or
  CRDs.

## 6. Validation

State before execution what proves the fix worked: the condition, the replica count, or the
absence of a recurrence, using the validation sweeper's existing shapes
(`internal/orchestrator/validation.go`). A failed validation reopens the incident; it never
triggers another automatic remediation.

## 7. Tests and proof

- Unit tests: params validation (good and bad), the risk floor with each modifier,
  `PermittedActionTypes` by route, preparation against a fake live object, and undo.
- `*_db_test.go` for the approval-to-execution path if state handling changed.
- **Live** ([`argus-live-test`](../argus-live-test/SKILL.md)): in a lab test namespace with
  remediation switched on for that namespace only, take an incident through plan, preflight,
  approval, execution, validation and resolution. Read the object back. Then run undo. Switch
  remediation off afterwards. Only this earns a `docs/VERIFICATION.md` entry.

## Output

The schema, the risk floor and its reasoning, the unattended verdict, the routes that permit it, the
executor and guardrails, the RBAC and admission delta, the rollback, the validation, the tests, and
what was proven live. If any of these cannot be filled in with confidence, say which one rather
than inventing a default.
