import type { FullConfig } from '@playwright/test'
import { ADMIN_EMAIL, ADMIN_PASSWORD, apiLogin, clearDemoData, seedDemoData } from './api'

// Runs once before the whole suite (playwright.config.ts's `globalSetup`).
//
// Two jobs: (1) fail fast, with a clear pointer to RUNBOOK.md, if there is no
// real hub to test against — a bare ECONNREFUSED from whichever spec happens
// to run first is a much worse first error message; (2) seed the exact known
// fixture every spec in this suite reads its assertions from.
//
// The fixture is internal/api/demo_data.go's sample-data story, seeded
// through the real POST /api/v1/demo-data endpoint (never a mocked
// response) — it already spans every incident state the UI renders,
// including one (the "oomkill" ScaleDeployment plan, AwaitingApproval,
// no decision yet) that is exactly the pending-approval/diff case this
// suite's approval-flow spec needs, so there was no reason to invent a
// second, bespoke fixture path alongside it.
export default async function globalSetup(config: FullConfig): Promise<void> {
  const baseURL =
    config.projects[0]?.use?.baseURL ?? process.env.PLAYWRIGHT_BASE_URL ?? 'http://localhost:8080'

  let ready: Response
  try {
    ready = await fetch(`${baseURL}/readyz`)
  } catch (err) {
    throw new Error(
      `\n\nCould not reach the ARGUS hub at ${baseURL} (${(err as Error).message}).\n` +
        `This suite needs a REAL running dev stack, not a mock — bring one up per RUNBOOK.md, e.g.:\n` +
        `  docker build -t argus/hub:dev .\n` +
        `  docker compose -f deploy/compose/docker-compose.yaml up -d\n` +
        `then re-run. Set PLAYWRIGHT_BASE_URL to point at a different hub (e.g. a host-run one, or\n` +
        `Vite's dev server proxying to one) if that's how you're running it.\n`,
    )
  }
  if (!ready.ok) {
    throw new Error(
      `ARGUS hub at ${baseURL} is not ready (GET /readyz returned HTTP ${ready.status}). ` +
        `Check "docker compose -f deploy/compose/docker-compose.yaml logs hub-api" (RUNBOOK.md).`,
    )
  }

  const { accessToken } = await apiLogin(baseURL, ADMIN_EMAIL, ADMIN_PASSWORD)

  // Idempotent regardless of how the previous run ended (including a crash
  // that skipped its own teardown): always clear before seeding, rather than
  // tolerating a 409 from a stale prior run's demo data, which could be an
  // older shape than what this run's specs expect.
  await clearDemoData(baseURL, accessToken)
  await seedDemoData(baseURL, accessToken)
}
