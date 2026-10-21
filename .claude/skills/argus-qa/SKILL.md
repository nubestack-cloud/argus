---
name: argus-qa
description: The verification pass for an ARGUS change, scaled to what actually changed — Go build/vet/gofmt/tests (with the Postgres-backed suite when DB code moved), the frontend build/lint/tests/design-lint, and a visual check only when rendered UI changed. Use before saying any change is done, when asked to "verify", "check", "QA" or "test this", or as the test step inside another skill. Reports every check as ran, skipped-with-reason, or failed — never silent.
argument-hint: [what changed — defaults to the working-tree diff]
---

# Verify an ARGUS change

Run the checks the **delta** calls for and skip the rest. Reflexively running everything wastes the
owner's time (they have said so, repeatedly); skipping a check the change needed is how this repo has
shipped green suites that did nothing in the running deployment. The table decides, not habit.

## 1. Work out the delta

```
git status --short
git diff --stat
```

Sort the touched files into: Go (`cmd/`, `internal/`, `scripts/*.go`), DB (`internal/migrations/`,
any SQL, anything under `internal/data`), web (`web/src`, `web/scripts`), API contract
(`docs/openapi.yaml`), chart/deploy (`deploy/`), docs only.

## 2. Run what the delta needs

| Delta | Checks |
|---|---|
| Any Go | `go build ./... && go vet ./... && gofmt -l .` (gofmt must print nothing), then `go test` on the touched packages. The whole `go test ./...` only for a cross-cutting change. |
| Go that touches SQL, RLS, a migration, or a `*_db_test.go` | The same tests **with** `ARGUS_TEST_DATABASE_URL` set. Without it every `*_db_test.go` skips and a green run proves nothing about the queries. Fixtures go through `internal/dbtest` — hand-written cleanup has twice deleted real dev data. |
| `docs/openapi.yaml` | `cd web && npm run generate-api-types`, then the web checks below (the generated types feed the build). |
| A rule in `internal/agent/rules/default-rules.yaml`, or `docs/VERIFICATION.md` | `go run ./scripts/coverage` to regenerate `docs/coverage-matrix.*`, and `go test ./internal/api/` (it pins `knownRuleIDs` to the rule file). |
| Any web | `cd web && npm run build` — the authoritative typecheck; **not** `tsc --noEmit`, which has missed real errors here. Then `npm run lint` and `npm test` (or the touched spec files only, for a small change). |
| Web that renders differently | `npm run design-lint`, the `argus-design-review` pass, and decide on `argus-visual-test` (section 3). |
| Chart templates | `helm lint deploy/helm/<chart>` and a `helm template` render with the values the lab uses. |
| Docs only | Nothing to run, unless the doc is `VERIFICATION.md` (coverage matrix above). |

A change to how ARGUS behaves against a cluster — detection, correlation, closure, remediation —
is not verified by any of the above. That needs [`argus-live-test`](../argus-live-test/SKILL.md),
and the honest report until then is "unit-tested, not exercised live".

## 3. The visual check is a decision, and it is always reported

A new or reworked rendered surface — a page, tab, panel, dialog, chart, or a layout change —
should get [`argus-visual-test`](../argus-visual-test/SKILL.md): it catches what the build and the
jsdom tests structurally cannot (does it render, does it fit at 375 and at 2560, is dark mode
legible). Logic, copy, types, a value's formatting, a one-class tweak: skipping is fine.

Either way the report says which, because `build ✓ · test ✓` with no visual line reads as "did it
run or not?":

- `visual: ran · 9 shots · /absolute/path/to/shots/` — an absolute path so the terminal links it.
- `visual: skipped — no rendered change` (or the real reason).

Remember the UI is compiled into the hub with `go:embed` from `internal/api/static`, not `web/dist`.
`npm run build` changes nothing a browser sees until the hub image is rebuilt.

## 4. Report

One line per check, in this shape:

```
go build/vet/gofmt   ✓
go test              ✓ internal/agent internal/gateway (DB suite: ran, ARGUS_TEST_DATABASE_URL set)
web build/lint/test  ✓ 1,412 tests
design-lint          ✓ no new findings
visual               skipped — no rendered change
live                 not exercised — needs argus-live-test
```

A failure is reported with the command and the relevant output lines, not paraphrased. A check you
did not run is listed as not run, with the reason. Never report a number you did not read from the
command's output.
