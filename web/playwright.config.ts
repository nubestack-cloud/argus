import { defineConfig, devices } from '@playwright/test'

// BACKLOG.md P3's remaining gap: "Playwright + Chromium are now installed
// (web/, dev dependency)... What is not built is a committed suite: the
// scripts used were throwaway." This is that committed suite.
//
// DELIBERATELY DIFFERENT FROM `npm test` (Vitest, web/vite.config.ts): that
// suite mocks every `api/client` call and exercises component logic in
// jsdom — fast, and already covers all ten big pages (BACKLOG.md P3's
// component-coverage half, closed). This suite does the opposite on
// purpose: a real Chromium against a REAL running hub (RUNBOOK.md's compose
// or host-run dev stack) — real HTTP responses, real routing, real cookie/
// token-free bearer-auth flow. It exists to catch the class of bug the
// mocked suite structurally cannot: a request shape the mock never checked
// against the real handler, a redirect that only breaks with a real
// history API, a real RLS/capability check the mock always "approved".
//
// PRECONDITION, not something this config starts for you: a real dev stack
// already up per RUNBOOK.md ("docker compose -f deploy/compose/docker-
// compose.yaml up -d", or the host-run hub option). Deliberately not a
// Playwright `webServer` entry — that feature is for starting a throwaway
// dev server Playwright also tears down, and this suite's server is a
// multi-container stack (Postgres + migrate + hub) with real state, not
// something to spin up/tear down per test run. `globalSetup`/
// `globalTeardown` below instead fail fast with a RUNBOOK.md pointer if
// nothing is listening, and seed/clear the one known fixture the specs
// assert against (internal/api/demo_data.go's sample data, via the real
// POST/DELETE /api/v1/demo-data endpoints — never a mocked API response).
//
// THOSE ENDPOINTS ARE THIS SUITE'S ONLY CONSUMER. PROJECT.md D14 removed
// demo data from the product — no Settings panel, no onboarding button — and
// the hub registers the two routes only when ARGUS_ENABLE_DEMO_DATA is set,
// which deploy/compose/docker-compose.yaml does and no real deployment does.
// A 404 in globalSetup means the stack you pointed at does not have it.
//
// baseURL defaults to the hub's own :8080 (what `docker compose up` and
// RUNBOOK.md's "Open http://localhost:8080/" both mean by "the app") —
// override with PLAYWRIGHT_BASE_URL to point at Vite's dev server instead
// (`cd web && npm run dev`, which proxies /api to the same real hub) for
// fast iteration on the specs themselves without a container rebuild.
const baseURL = process.env.PLAYWRIGHT_BASE_URL ?? 'http://localhost:8080'

export default defineConfig({
  testDir: './e2e',
  // The whole suite shares one seeded fixture (see globalSetup) rather than
  // per-test isolation — small and deliberately so (BACKLOG.md P3: "a
  // small, real, high-value set of flows", not a parallel-safe rewrite of
  // the mocked suite). Serial execution keeps that fixture's read-mostly
  // assumptions simple to reason about; there is no per-test throughput
  // pressure at this suite's size to justify the complexity of making every
  // spec independently parallel-safe against shared server state.
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['github'], ['html', { open: 'never' }]] : [['list']],
  globalSetup: './e2e/global-setup.ts',
  globalTeardown: './e2e/global-teardown.ts',
  use: {
    baseURL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
})
