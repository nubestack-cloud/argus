# ARGUS web UI

The ARGUS React UI. Current behaviour is documented in the user documentation (https://argus.nubestack.com/); source and component
tests are the UI contract.

## Run it

```
npm install
npm run dev
```

Opens on `http://localhost:5173` by default. Requires a running hub API —
by default the dev server proxies `/api/*` requests to
`http://localhost:8080` (see `vite.config.ts`). To point at a hub running
somewhere else, copy `.env.example` to `.env.local` and set
`VITE_API_BASE_URL`.

## Build

```
npm run build
```

Type-checks (`tsc -b`) and produces a static `dist/` bundle. **`npm run build` is the authoritative
typecheck** — `npx tsc --noEmit` has missed real errors in this project. `dist/` is embedded into the
hub binary with `go:embed`, so building here alone changes nothing a browser will see: the hub has to
be rebuilt. `RUNBOOK.md` has that procedure.

## Checks

```
npm test            # Vitest + jsdom + Testing Library
npm run design-lint # the mechanically checkable half of the design system
```

`design-lint` enforces the subset of `.claude/skills/argus-design-system/reference/` that a script can
decide (token use, the component class vocabulary). Everything needing judgement is the
`argus-design-review` skill's job.

## Structure

- `src/api/` — typed fetch client for the hub's REST API (`client.ts`) and
  its request/response shapes (`types.ts`). Errors surface as `ApiError`
  carrying the RFC 9457 problem `title`/`detail`. `capabilities.ts` /
  `capabilityInfo.ts` hold the capability lookups the RBAC discipline below
  needs.
- `src/auth/` — `AuthContext` keeps the access token in memory only; the
  rotating refresh token and a cosmetic display name are the only things in
  `localStorage`, and the access token is re-minted from the refresh token on
  every load, so a page reload does not log you out. Refresh calls are
  coordinated across tabs (`BroadcastChannel`) so two tabs cannot race to
  spend the same single-use token. `ProtectedRoute` redirects to `/login`
  when there is no session.
- `src/pages/` — one module per screen: `Overview`, `Clusters` (+
  `ClusterDetail`), `Incidents` (+ `IncidentDetail`), `Approvals`,
  `Tolerations`, `AuditLog`, `Insights`, `Users`, `Settings`, and `Login`.
- `src/components/` — the shared vocabulary: `AppShell` (nav), the badge
  sets, `RemediationPlanCard` (including the undo control),
  `RepositoryChangePanel` / `UnifiedDiff` (the pull-request review surface),
  `PreflightPanel`, and the Settings cards.
- `src/realtime/` — `useLiveEvents`, the WebSocket subscription that makes a
  screen update when a background sweeper changes an incident.
- `src/index.css` — the token set and the component class vocabulary. Some
  of its values encode measurements you cannot re-derive by eye; read the
  design-system skill before changing them.

Two conventions are load-bearing rather than stylistic: a control the viewer
lacks the capability for is **disabled with a tooltip, never hidden**, and an
unavailable number is never rendered as `0` or `$0.00`.
