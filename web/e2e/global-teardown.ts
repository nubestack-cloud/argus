import type { FullConfig } from '@playwright/test'
import { ADMIN_EMAIL, ADMIN_PASSWORD, apiLogin, clearDemoData } from './api'

// Removes exactly what global-setup.ts seeded (DELETE /api/v1/demo-data),
// so a local dev stack this suite ran against is left the way it was found
// rather than permanently carrying a "Demo Cluster (sample data)" fleet
// member. Best-effort: a teardown failure is logged, not thrown — throwing
// here would report the whole run red even when every actual test passed,
// which is a worse failure mode than one stray demo cluster left behind for
// the next run's own clearDemoData() call to remove.
export default async function globalTeardown(config: FullConfig): Promise<void> {
  const baseURL =
    config.projects[0]?.use?.baseURL ?? process.env.PLAYWRIGHT_BASE_URL ?? 'http://localhost:8080'

  try {
    const { accessToken } = await apiLogin(baseURL, ADMIN_EMAIL, ADMIN_PASSWORD)
    await clearDemoData(baseURL, accessToken)
  } catch (err) {
    console.warn(
      `e2e teardown: could not clear demo data (${(err as Error).message}). ` +
        `It will be cleared by the next run's own setup instead.`,
    )
  }
}
