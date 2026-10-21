---
name: argus-add-screen
description: The plumbing for a new ARGUS web screen, tab or panel — lazy route registration inside the protected app layout, the sidebar entry and its required capability, RBAC that disables rather than hides, TanStack Query data fetching through the typed client, the four states, and RFC 9457 error rendering. Use when adding a page, a cluster-page tab, a side panel or an admin view, or when wiring the frontend for something already on the hub API. Pair with argus-design-system for how it looks.
argument-hint: [screen or tab and the API it reads, e.g. "cluster tab: network policy map from get_network_policy_map"]
---

# Add a web screen

Apply [`argus-context`](../argus-context/SKILL.md) first. This skill is the plumbing. How the screen
looks — its mode, what earns space, what is drawn rather than written — is
[`argus-design-system`](../argus-design-system/SKILL.md), which you name **before** laying anything
out. [`argus-design-review`](../argus-design-review/SKILL.md) is the check before calling it done.

## 0. Does the backend exist?

Do not build a screen ahead of the API it calls. Find the route in `internal/api/server.go` and its
schema in `docs/openapi.yaml`. If it is missing, build it first with
[`argus-add-endpoint`](../argus-add-endpoint/SKILL.md), or, for something the agent reads from a
cluster, with [`argus-add-mcp-tool`](../argus-add-mcp-tool/SKILL.md) as an inspection tool.

Then decide whether this is a **new page** or belongs on an existing one. Most new cluster facts
belong as a tab on the cluster page, and most incident facts belong on the incident page. A new
top-level page is a product decision; confirm it with the owner.

## 1. Routing

- **A page**: a `lazy(() => import(...))` in `web/src/App.tsx` and a `<Route>` inside the
  `ProtectedAppLayout` element, which supplies the session guard and the app shell. If it belongs in
  the sidebar, add it to `web/src/components/AppShell.tsx`'s nav lists in the same change. A page
  nobody can reach from the nav is a page nobody finds.
- **A cluster-page tab**: an entry in `ClusterDetailPage.tsx`'s tab list (`id`, `label`, `inspect`
  when it needs `cluster:inspect`, `groupStart` for a new group), a lazily loaded panel under
  `web/src/fleet/`, and a badge in `clusterTabBadges.tsx` if the tab has a count worth showing.
  The tab is URL state (`?tab=<id>`), so a link reproduces the view; keep any panel-level filter in
  the URL too.

## 2. RBAC: disabled, not hidden

- Capability strings are named constants in `web/src/api/capabilities.ts`, mirroring
  `internal/authz/permissions.go`. Never an inline literal.
- `useHasCapability` / `useMissingCapabilities` (`web/src/auth/useCapabilities.ts`) decide; an
  action control the viewer cannot use renders **disabled with the missing capability named**
  (`missingCapabilityMessage` in `web/src/api/capabilityInfo.ts`). It is never removed from the
  DOM.
- A nav destination's required capability goes in `components/navCapabilities.ts`, the single map
  the sidebar and the section tabs share.
- State is a different axis: an action that makes no sense in the current state (accept an
  already-active cluster) may be omitted.
- The UI check is cosmetic. The hub's `requireCapability` is the enforcement.

## 3. Data

- TanStack Query: `useQuery` for reads, and `useMutation` plus `invalidateQueries` for writes. Poll
  (`refetchInterval`) only for state that changes server-side on its own, and use the live-events
  stream (`web/src/realtime`) where one exists for it.
- Every call goes through a typed function in `web/src/api/client.ts` that uses
  `web/src/api/generated.ts` (from `npm run generate-api-types`) or `api/types.ts`. No `fetch` in a
  component.
- **Four states**: populated, loading (a skeleton that matches the layout), empty, and error. A
  filtered-empty state and a never-had-data state read differently. A missing value renders as `—`,
  never as `0`.
- **Errors** render the problem's `title` and `detail` from `ApiError`, plus its `requestId` where
  the operator might report it. Branch on the problem `type`, never on prose.
- Cluster data from an offline agent is "unavailable", and says when it was last seen. It is not
  empty.

## 4. Output encoding

Never use `dangerouslySetInnerHTML` on anything derived from cluster, repository or evidence data
(SR-17). React's escaping is the control. A link built from cluster data is checked to be
`http(s)` or an app route.

## 5. Tests and seeing it

- A Vitest spec beside the component (`*.test.tsx`), with the client mocked: the populated, empty
  and error states, and a disabled control for a viewer lacking the capability.
- [`argus-qa`](../argus-qa/SKILL.md) for the web checks (`npm run build` is the typecheck).
- [`argus-visual-test`](../argus-visual-test/SKILL.md) on a rebuilt hub. The UI is embedded with
  `go:embed`, so nothing is visible until the hub image is rebuilt and rolled out.

## Output

The route or tab entry, the nav and capability wiring, the client functions, the component with its
four states, the tests, and the backend it depends on — and whether that backend exists.
