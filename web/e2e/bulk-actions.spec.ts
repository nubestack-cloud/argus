import { randomBytes } from 'node:crypto'
import { test, expect, type Page } from '@playwright/test'
import {
  ADMIN_EMAIL,
  ADMIN_PASSWORD,
  FIXTURE_CLUSTER_PREFIX,
  apiLogin,
  archiveFixtureClusters,
  enrollFixtureCluster,
} from './api'

// BUGS.md's owner note ("a chclist selection style button on the clusters
// page and incidents page where we can select and perform bulk action like
// decommissioning the clusters") — this spec drives the real bulk-selection
// UI against the real running hub, proving the frontend calls the real
// per-item endpoints (POST /clusters/{id}/decommission,
// POST /incidents/{id}/dismiss) once per selected row and reports the real
// per-row outcome, the same discipline every other spec in this suite
// follows (incident-and-approval-flow.spec.ts's own header comment).
//
// The cluster half creates its own two disposable clusters through the real
// enrollment API (api.ts's enrollFixtureCluster — see its comment for why
// that, and not the demo seeder, and why PendingApproval is the right
// "decommissionable" state for a fixture). It used to target two clusters
// that happened to exist on one developer's machine, which is why it could
// never run in CI.
//
// Both names carry a per-run suffix. That is what makes the search below
// match exactly this run's two rows — never a leftover from an earlier run,
// never a real cluster — so each target's OWN checkbox is checked by its
// exact aria-label and the "2 selected" count means two known rows, not
// "whatever the list happened to contain".
//
// The incident half instead reuses global-setup.ts's demo-data fixture
// (POST /api/v1/demo-data), which seeds eleven incidents including four in a
// real Detected state (fingerprints demo-imagepull, demo-crashloop-redis,
// demo-apiserver-probe, demo-failedscheduling) safe to dismiss and re-created
// fresh every run. It was three until PROJECT.md B180 added
// demo-apiserver-probe — the deliberately long-named `kube-apiserver-<node>`
// row that gives list-density.spec.ts something a regression can actually
// make taller. Every count in the incident test below is that fixture's,
// so they move together with it.
const FIXTURE_RUN_PREFIX = `${FIXTURE_CLUSTER_PREFIX}${randomBytes(4).toString('hex')}-`
const CLUSTER_TARGET_1 = `${FIXTURE_RUN_PREFIX}alpha`
const CLUSTER_TARGET_2 = `${FIXTURE_RUN_PREFIX}beta`

async function loginViaUI(page: Page) {
  await page.goto('/login')
  await page.getByLabel('Email').fill(ADMIN_EMAIL)
  await page.getByLabel('Password', { exact: true }).fill(ADMIN_PASSWORD)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page).toHaveURL(/\/overview$/)
}

test.describe('bulk selection and bulk actions (BUGS.md\'s owner note)', () => {
  test.beforeEach(async ({ page }) => {
    await loginViaUI(page)
  })

  // Teardown for the cluster fixture below. Unconditional, and a no-op for
  // any test that created none (it sweeps by THIS RUN's prefix, which only
  // the cluster test ever uses) — running it after every test rather than
  // only after the one that seeds means a failure part-way through that test,
  // at any assertion, still cannot leave a live fixture cluster behind.
  //
  // In the passing case the sweep finds nothing to do either: the test
  // decommissioned both clusters itself, which is the thing it exists to
  // prove, and an Archived cluster is already gone from GET /clusters.
  test.afterEach(async ({ baseURL }) => {
    // playwright.config.ts always sets baseURL (defaulted there from
    // PLAYWRIGHT_BASE_URL), so this is non-null in practice.
    const { accessToken } = await apiLogin(baseURL!, ADMIN_EMAIL, ADMIN_PASSWORD)
    await archiveFixtureClusters(baseURL!, accessToken, FIXTURE_RUN_PREFIX)
  })

  // This used to be skipped, because it named two clusters that existed only
  // on one developer's machine and so could never pass in CI. It is not
  // skipped any more and the assertions are unchanged: the two clusters are
  // now created by the test itself, through the real enrollment API, and
  // swept away again by this describe's afterEach.
  //
  // Do not "fix" a future failure here by relaxing what it checks. The whole
  // point (an owner bug note) is that a two-cluster decommission reports a
  // real PER-ROW outcome — two real POST /clusters/{id}/decommission calls,
  // each one's result named — rather than one pass/fail for the batch.
  test('Clusters page: selecting two real decommissionable clusters and bulk-decommissioning them actually archives both', async ({
    page,
    baseURL,
  }) => {
    // The fixture: two real clusters, enrolled through the real API, live in
    // the fleet before the UI is touched. Seeded here rather than in a
    // beforeEach so the other test in this file never pays for them.
    const { accessToken } = await apiLogin(baseURL!, ADMIN_EMAIL, ADMIN_PASSWORD)
    await enrollFixtureCluster(baseURL!, accessToken, CLUSTER_TARGET_1)
    await enrollFixtureCluster(baseURL!, accessToken, CLUSTER_TARGET_2)

    // `exact` because the Overview this starts on also has a "View clusters"
    // card link, which the default substring match would tie with — the nav
    // link is the one a person would click on their way to the fleet list.
    await page.getByRole('link', { name: 'Clusters', exact: true }).click()
    await expect(page).toHaveURL(/\/clusters$/)

    // This run's own prefix, which matches exactly the two clusters just
    // enrolled above: it cannot match an earlier run's leftovers
    // (different per-run suffix) and it cannot match a real cluster. The
    // list's search is client-side over the full GET /api/v1/clusters
    // response (ClustersPage's `normalizedSearch`), so there is no debounced
    // server fetch to race here — unlike the incidents half below.
    await page.getByPlaceholder('Search by name, ID, or version').fill(FIXTURE_RUN_PREFIX)
    const checkbox1 = page.getByLabel(`Select ${CLUSTER_TARGET_1}`)
    const checkbox2 = page.getByLabel(`Select ${CLUSTER_TARGET_2}`)
    await expect(checkbox1).toBeVisible()
    await expect(checkbox2).toBeVisible()
    await expect(checkbox1).toBeEnabled()
    await expect(checkbox2).toBeEnabled()
    await checkbox1.check()
    await checkbox2.check()
    await expect(page.getByText('2 clusters selected')).toBeVisible()

    await page.getByRole('button', { name: 'Decommission…' }).click()
    const confirmDialog = page.getByRole('dialog', { name: 'Decommission clusters' })
    await expect(confirmDialog).toBeVisible()
    await expect(confirmDialog).toContainText('This permanently archives 2 clusters')

    await confirmDialog.getByLabel(/Type DECOMMISSION to confirm/).fill('DECOMMISSION')
    await confirmDialog.getByRole('button', { name: 'Decommission 2' }).click()

    // The real per-row result of two real POST /clusters/{id}/decommission
    // calls — not a single pass/fail for the batch.
    const resultsDialog = page.getByRole('dialog', { name: 'Bulk decommission results' })
    await expect(resultsDialog).toBeVisible()
    await expect(resultsDialog.getByText('2 of 2 succeeded.')).toBeVisible()
    await expect(resultsDialog.getByText('Succeeded', { exact: true })).toHaveCount(2)
    await resultsDialog.getByRole('button', { name: 'Done' }).click()

    // Real state change, read back from a real refetch. GET /api/v1/clusters
    // filters `WHERE archived_at IS NULL` (internal/api/clusters.go's
    // handleListClusters) — an Archived cluster is not shown with a badge,
    // it disappears from the list entirely, exactly as
    // ConfirmDecommissionModal.tsx's own single-item copy already says
    // ("It will disappear from this list. This cannot be undone."). So the
    // real proof both decommissions actually executed is that the exact
    // same search that showed both target rows a moment ago now shows
    // neither.
    await page.getByPlaceholder('Search by name, ID, or version').fill(CLUSTER_TARGET_1)
    await expect(page.getByText('No clusters match these filters')).toBeVisible()
    await page.getByPlaceholder('Search by name, ID, or version').fill(CLUSTER_TARGET_2)
    await expect(page.getByText('No clusters match these filters')).toBeVisible()
  })

  test('Incidents page: selecting the seeded Detected demo incidents and bulk-dismissing them actually closes all four', async ({
    page,
  }) => {
    await page.getByRole('link', { name: 'Incidents' }).click()
    await expect(page).toHaveURL(/\/incidents$/)

    // demo_data.go's fixture: exactly 4 incidents seeded in Detected state,
    // all with a "demo-" fingerprint. Search narrows to the demo story;
    // the state filter narrows further to just the four Detected ones
    // (the fixture also seeds NeedsHumanInvestigation/AwaitingApproval/
    // Validating/Resolved/Reopened/Failed/Dismissed rows this must exclude).
    //
    // The search is server-side and debounced 300ms (BACKLOG P10); the
    // state filter is client-side over whatever the search already fetched.
    // Waiting for the real ?search=demo- response BEFORE touching the state
    // filter avoids applying that filter to the stale, much larger
    // pre-debounce fetch — the same thing a human would do just by not
    // being faster than 300ms between the two actions. Not asserting an
    // exact intermediate result count here: other, unrelated fixtures in
    // this shared dev database incidentally match "demo" too (e.g. a
    // cluster display name from an earlier session), so the real number
    // fluctuates — the state-filtered count below (4) is what this test
    // actually needs to be exact and stable.
    await page.getByPlaceholder('Search incidents').fill('demo-')
    await page.waitForResponse((res) => res.url().includes('/api/v1/incidents?') && res.url().includes('search=demo'))
    await page.getByLabel('Filter by state').selectOption('Detected')
    // The list header's own count, scoped to `.list-live-status` so this
    // cannot accidentally match a number elsewhere on the page. It read
    // "N results" until the shared ListFreshness header replaced that with
    // the noun ("3 incidents"), which is the better label — "results" does
    // not say results of what. The spec was not updated with it, and the
    // suite was already failing at login, so nothing reported the drift.
    await expect(page.locator('.list-live-status')).toContainText('4 incidents')

    const selectAll = page.getByLabel('Select all eligible incidents on this page')
    await expect(selectAll).toBeEnabled()
    await selectAll.check()
    await expect(page.getByText('4 incidents selected')).toBeVisible()

    await page.getByRole('button', { name: 'Dismiss…' }).click()
    const confirmDialog = page.getByRole('dialog', { name: 'Dismiss incidents' })
    await expect(confirmDialog).toBeVisible()
    await expect(confirmDialog).toContainText('This closes 4 incidents with no action')

    await confirmDialog.getByLabel(/Why are these being dismissed/).fill('e2e bulk-dismiss verification run')
    await confirmDialog.getByRole('button', { name: 'Dismiss 4' }).click()

    const resultsDialog = page.getByRole('dialog', { name: 'Bulk dismiss results' })
    await expect(resultsDialog).toBeVisible()
    await expect(resultsDialog.getByText('4 of 4 succeeded.')).toBeVisible()
    await expect(resultsDialog.getByText('Succeeded', { exact: true })).toHaveCount(4)
    await resultsDialog.getByRole('button', { name: 'Done' }).click()

    // Real state change, read back from a real refetch: the same
    // search+state-filter query (still "Detected") now matches nothing,
    // because all four real rows moved to Dismissed.
    await expect(page.getByText('No incidents match this view')).toBeVisible()

    // And they are genuinely Dismissed, not merely gone from this filter —
    // switch the filter to Dismissed and confirm all four land there. Five,
    // not four: demoStory also seeds one incident already Dismissed from
    // creation (fingerprint demo-dismissed), so the real total here is that
    // one plus the four this test just closed. The state filter only offers
    // the states of the selected status tab, so switch to All first.
    await page.getByRole('navigation', { name: 'Incident status' }).getByRole('button', { name: /^All/ }).click()
    await page.getByLabel('Filter by state').selectOption('Dismissed')
    await expect(page.locator('.list-live-status')).toContainText('5 incidents')
  })
})
