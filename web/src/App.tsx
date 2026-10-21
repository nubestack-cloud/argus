import { Suspense, lazy } from 'react'
import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter, Navigate, Outlet, Route, Routes, useLocation } from 'react-router-dom'
import { AuthProvider } from './auth/AuthContext'
import { ProtectedRoute } from './auth/ProtectedRoute'
import { AppShell } from './components/AppShell'
import { ErrorBoundary } from './components/ErrorBoundary'
import { LoginPage } from './pages/LoginPage'
import { SSOCompletePage } from './pages/SSOCompletePage'
import { LiveStatusContext } from './realtime/liveStatus'
import { useLiveEvents } from './realtime/useLiveEvents'
import { KeyboardShortcutProvider } from './keyboard/shortcuts'
import { GlobalShortcuts } from './keyboard/GlobalShortcuts'
import { shouldRetryQuery } from './api/queryRetry'

// Every route past login is lazy — per-page `import()`, not the static imports
// this file had before. Verified before changing: web/src/pages/*.tsx totals
// ~9,200 lines across these 11 pages, and none of it was code-split, so
// visiting /overview shipped, parsed and JIT-compiled Settings/AuditLog/
// Insights/Tolerations too before the first pixel of the page actually
// requested could paint (confirmed via `npm run build`'s own output: one
// 566 kB JS chunk, the single asset Vite's own chunk-size warning flags).
// `.then(m => ({ default: m.X }))` is needed because every page is a named
// export, and `React.lazy` requires a default one — real per-page renames
// would be a much larger diff for the same result.
//
// LoginPage stays a static import: it is the one page an unauthenticated
// visitor needs before anything else can happen, it is tiny (~100 lines), and
// lazy-loading it would trade a guaranteed-needed synchronous parse for an
// extra network round trip that buys nothing.
//
// SSOCompletePage is static for a sharper version of the same reason: it runs
// with a 15-second single-use handoff code in hand (internal/authz.SSOHandoffTTL),
// so spending part of that budget fetching a chunk before the exchange can
// even start would make a slow connection the difference between a working
// login and an expired one.
const OverviewPage = lazy(() => import('./pages/OverviewPage').then((m) => ({ default: m.OverviewPage })))
const ClustersPage = lazy(() => import('./pages/ClustersPage').then((m) => ({ default: m.ClustersPage })))
const ClusterDetailPage = lazy(() => import('./pages/ClusterDetailPage').then((m) => ({ default: m.ClusterDetailPage })))
const IncidentsPage = lazy(() => import('./pages/IncidentsPage').then((m) => ({ default: m.IncidentsPage })))
const IncidentDetailPage = lazy(() => import('./pages/IncidentDetailPage').then((m) => ({ default: m.IncidentDetailPage })))
const SignalsPage = lazy(() => import('./pages/SignalsPage').then((m) => ({ default: m.SignalsPage })))
const SettingsPage = lazy(() => import('./pages/SettingsPage').then((m) => ({ default: m.SettingsPage })))
const UsersPage = lazy(() => import('./pages/UsersPage').then((m) => ({ default: m.UsersPage })))
const AuditLogPage = lazy(() => import('./pages/AuditLogPage').then((m) => ({ default: m.AuditLogPage })))
const RecentChangesPage = lazy(() => import('./pages/RecentChangesPage').then((m) => ({ default: m.RecentChangesPage })))
const ApprovalsPage = lazy(() => import('./pages/ApprovalsPage').then((m) => ({ default: m.ApprovalsPage })))
const InsightsPage = lazy(() => import('./pages/InsightsPage').then((m) => ({ default: m.InsightsPage })))
const SearchPage = lazy(() => import('./pages/SearchPage').then((m) => ({ default: m.SearchPage })))
const TolerationsPage = lazy(() => import('./pages/TolerationsPage').then((m) => ({ default: m.TolerationsPage })))
const ComparePage = lazy(() => import('./pages/ComparePage').then((m) => ({ default: m.ComparePage })))

// Refusals (4xx) are final and shown at once; only network failures and 5xx
// are retried — see queryRetry.ts for why the library default was wrong here.
const queryClient = new QueryClient({ defaultOptions: { queries: { retry: shouldRetryQuery } } })

// The Suspense fallback covers only the chunk fetch/parse for the page module
// itself — every page's own data loading already renders its own Skeleton*
// components once mounted, which is the ARGUS-specific loading UI (lld/11-ui-
// design.md §7). This one is generic on purpose: it has to work for all 11
// lazy routes, and on a already-cached or fast connection it is on screen for
// a handful of milliseconds, not long enough to be worth a bespoke design.
function RouteFallback() {
  return (
    <div className="page" aria-busy="true">
      <p className="route-loading">Loading…</p>
    </div>
  )
}

// Holds the one live-event socket for the session AND publishes whether it is
// delivering, so a list header can tell "Live" (an event lands in
// milliseconds) apart from "the stream is down and this page is on its 60s
// fallback poll" — see realtime/liveStatus.ts. It wraps the router rather than
// sitting beside it because every screen under it reads that status; it still
// renders nothing of its own.
function LiveEventsProvider({ children }: { children: ReactNode }) {
  const status = useLiveEvents()
  return <LiveStatusContext.Provider value={status}>{children}</LiveStatusContext.Provider>
}

// One persistent protected layout replaces a separate AppShell instance on
// every route. Navigation now swaps only the Outlet content, preserving shell
// state (open account UI, dismissed session reminders) and keeping route
// declarations compact and consistent.
//
// The inner ErrorBoundary is the one that matters day to day: it sits *inside*
// AppShell, so a page that throws while rendering one bad server row loses
// only the content area — the sidebar, the nav and the account menu all keep
// working, and the user can simply go somewhere else. `key={pathname}` is what
// makes that work: a boundary never resets itself, so without re-keying it,
// navigating away from the broken page would keep showing the error screen
// forever. See components/ErrorBoundary.tsx for the crash this was written
// for (a null rootCause blanking the entire app).
function ProtectedAppLayout() {
  const { pathname } = useLocation()
  return (
    <ProtectedRoute>
      <AppShell>
        {/* CI-S18: g-then-letter navigation, "/" and "?" — signed-in only. */}
        <GlobalShortcuts />
        <ErrorBoundary key={pathname} label="this page">
          {/* Suspense lives inside AppShell/ErrorBoundary, not around them —
              the sidebar and account menu must stay interactive and visible
              while a lazy route's chunk is still being fetched; only the
              content area should show the fallback. */}
          <Suspense fallback={<RouteFallback />}>
            <Outlet />
          </Suspense>
        </ErrorBoundary>
      </AppShell>
    </ProtectedRoute>
  )
}

function App() {
  return (
    // Outermost boundary: the last resort for anything the per-page boundary
    // above can't see — AppShell itself, ProtectedRoute, the router, or a
    // provider. A white page is never an acceptable outcome, so nothing in
    // this tree is left uncaught.
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <LiveEventsProvider>
            <BrowserRouter>
              {/* One keyboard registry for the app (keyboard/shortcuts.tsx);
                  inside the router so shortcuts can navigate. */}
              <KeyboardShortcutProvider>
              <Routes>
                <Route path="/login" element={<LoginPage />} />
                {/* The landing page for a completed federated login
                    (PROJECT.md S2). Public, like /login, because it runs
                    BEFORE the session exists — it is what creates one from the
                    handoff code the OIDC callback redirected here with. */}
                <Route path="/auth/sso/complete" element={<SSOCompletePage />} />
                <Route element={<ProtectedAppLayout />}>
                  <Route path="/overview" element={<OverviewPage />} />
                  <Route path="/clusters" element={<ClustersPage />} />
                  <Route path="/clusters/:id" element={<ClusterDetailPage />} />
                  <Route path="/incidents" element={<IncidentsPage />} />
                  <Route path="/incidents/:id" element={<IncidentDetailPage />} />
                  {/* PROJECT.md F31. The other half of /incidents: that route
                      lists what ARGUS raised, this one lists everything it
                      recorded — including the risks and unverified anomalies
                      internal/gateway/promotion.go's evidence boundary
                      deliberately keeps as findings. Gated on the same
                      incident:read the hub enforces on GET /findings. */}
                  <Route path="/signals" element={<SignalsPage />} />
                  <Route path="/tolerations" element={<TolerationsPage />} />
                  <Route path="/approvals" element={<ApprovalsPage />} />
                  <Route path="/users" element={<UsersPage />} />
                  {/* The front door for undo (PROJECT.md: "rollback API works
                      but has no front door"). Reachable from the History nav
                      group, beside the audit log it is deliberately not: that
                      one records every request including reads, this one lists
                      only the mutations ARGUS made, with the undo attached. */}
                  <Route path="/changes" element={<RecentChangesPage />} />
                  <Route path="/audit-log" element={<AuditLogPage />} />
                  <Route path="/insights" element={<InsightsPage />} />
                  {/* docs/CLUSTER_INSIGHT_SPECS.md CI-S12: find an object on
                      every cluster; GET /search requires cluster:inspect. */}
                  <Route path="/search" element={<SearchPage />} />
                  {/* PROJECT.md AD4: two objects of one kind, diffed; not a nav
                      item — reached from the object panel and the palette. */}
                  <Route path="/compare" element={<ComparePage />} />
                  {/* Applications is a card on the Overview now; old links land there. */}
                  <Route path="/applications" element={<Navigate to="/overview" replace />} />
                  <Route path="/settings" element={<SettingsPage />} />
                </Route>
                <Route path="/" element={<Navigate to="/overview" replace />} />
                <Route path="*" element={<Navigate to="/overview" replace />} />
              </Routes>
              </KeyboardShortcutProvider>
            </BrowserRouter>
          </LiveEventsProvider>
        </AuthProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  )
}

export default App
