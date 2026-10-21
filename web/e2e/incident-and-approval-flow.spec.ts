import { test, expect, type Page } from '@playwright/test'
import { ADMIN_EMAIL, ADMIN_PASSWORD } from './api'

// The rest of PRODUCT_DIRECTION.md/lld/13's UI-critical list, past login
// (auth.spec.ts): see the incident list, open an incident, see its stages
// render, and see the approval/diff view for a plan that exists. All
// against the real hub, reading the real fixture global-setup.ts seeded via
// the real POST /api/v1/demo-data endpoint (internal/api/demo_data.go) —
// never a mocked response.
//
// The fixture's "oomkill" incident is the one deliberately used throughout:
// a real Deployment (payments/checkout-worker), OOMKilled, State
// AwaitingApproval, with a real analysis and a real ScaleDeployment plan
// that has NOT yet been decided — the one incident in the whole seeded
// story that is simultaneously "has all six stages populated" and "has a
// live entry in the approval queue with a real diff to show", so one
// object serves both halves of this spec without inventing a second
// fixture path.
//
// THE GAP THIS SUITE DISCOVERED, NOW CLOSED (PROJECT.md B180). This header
// used to record that demo_data.go's `INSERT INTO incidents` never set
// `object_key`/`opening_reason`, so every seeded row rendered
// `incidentIdentity()`'s last-resort fallback — `Incident demo-oom`, the
// fingerprint's first eight characters — on the Incidents list and the
// detail page's summary strip, never "checkout-worker", even though the
// object name was right there in the finding row underneath. The note
// called it out of scope to fix "since this suite's job is testing the UI
// against real data, not patching the fixture generator."
//
// That reasoning was the wrong way round, and list-density.spec.ts is how it
// showed: a fixture that renders a one-line fallback is NOT real data, and a
// suite asserting against it was measuring a row shape the product cannot
// produce. demo_data.go now derives all three columns exactly as
// internal/gateway/finding.go does (see demoObjectKey/demoWorkloadKey/
// demoOpeningReason there), so the seeded rows carry the same three-line
// identity block a real incident does. Every assertion below that named an
// incident by its fingerprint hash now names it the way the product does.
//
// The oomkill incident's opening finding is an `apps/v1/Deployment` in
// namespace `payments` named `checkout-worker`, with no owning workload above
// it (a Deployment IS the workload), so `incidentIdentity` puts the object
// itself in the headline: "checkout-worker", over "Deployment · payments",
// over "OOMKilled".
const OOMKILL_IDENTITY = 'checkout-worker'

async function loginViaUI(page: Page) {
  await page.goto('/login')
  await page.getByLabel('Email').fill(ADMIN_EMAIL)
  await page.getByLabel('Password', { exact: true }).fill(ADMIN_PASSWORD)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page).toHaveURL(/\/overview$/)
}

test.describe('incident list, incident detail stages, and the approval queue', () => {
  test.beforeEach(async ({ page }) => {
    await loginViaUI(page)
  })

  test('the incident list renders the seeded fixture and opens one into its detail page', async ({ page }) => {
    await page.getByRole('link', { name: 'Incidents' }).click()
    await expect(page).toHaveURL(/\/incidents$/)

    // Narrow to the one seeded incident in AwaitingApproval by the real
    // state filter (IncidentsPage.tsx) — this dev stack accumulates real,
    // non-demo incidents across sessions too, so this is what actually
    // gets down to exactly the one seeded row, not a search string that
    // happens to be unique today.
    await page.getByLabel('Filter by state').selectOption('AwaitingApproval')

    const row = page.getByRole('row', { name: new RegExp(OOMKILL_IDENTITY) })
    await expect(row).toBeVisible()
    await expect(row).toContainText('High')
    // STATE_LABEL's wording for AwaitingApproval (utils/incidents.ts).
    await expect(row).toContainText('Waiting on a decision')

    await row.getByRole('link', { name: OOMKILL_IDENTITY }).click()
    await expect(page).toHaveURL(/\/incidents\/inc_/)
  })

  test('opening an incident from a scrolled list lands at the top of the detail page', async ({ page }) => {
    await page.goto('/incidents')
    await expect(page).toHaveURL(/\/incidents$/)

    // The scroller is `.app-content`, NOT the window: `.app-shell` is
    // `height: 100dvh; overflow: hidden` and this pane is the `overflow-y: auto`
    // child inside it (index.css). Asserting on `window.scrollY` here would pass
    // no matter what the code did, because the window never scrolls at all.
    const pane = page.locator('.app-content')
    await expect(pane).toBeVisible()

    await pane.evaluate((el) => { el.scrollTop = el.scrollHeight })
    const scrolled = await pane.evaluate((el) => el.scrollTop)

    // If the seeded list is short enough to fit, there is nothing to reset and a
    // passing assertion below would be vacuous — say so rather than bank a green
    // tick. This is the whole reason the scroll is read back instead of assumed.
    test.skip(scrolled === 0, 'incident list is not tall enough to scroll in this viewport')

    // The first row's link to its own detail page, matched by where it
    // GOES rather than by what it says. The previous locator looked for a
    // link named `/^inc_|^[0-9a-f]{8}/` and matched nothing: the identity
    // cell has never rendered a raw id, and even the old fingerprint
    // fallback said "Incident demo-oom", so this click could only ever have
    // timed out. It never did, because the skip above fires first at this
    // viewport — a broken locator sitting behind a skip, reported green.
    // `href^="/incidents/inc_"` is the identity link and nothing else
    // (the other link in a row goes to /clusters/...), and it stays correct
    // whatever the fixture calls its incidents.
    await page.locator('table tbody tr a[href^="/incidents/inc_"]').first().click()
    await expect(page).toHaveURL(/\/incidents\/inc_/)

    await expect.poll(() => pane.evaluate((el) => el.scrollTop)).toBe(0)
  })

  test('an incident detail page answers what broke, why, and the fix', async ({ page }) => {
    await page.goto('/incidents')
    await page.getByLabel('Filter by state').selectOption('AwaitingApproval')
    await page
      .getByRole('row', { name: new RegExp(OOMKILL_IDENTITY) })
      .getByRole('link', { name: OOMKILL_IDENTITY })
      .click()
    await expect(page).toHaveURL(/\/incidents\/inc_/)

    // IncidentDetailPage.tsx answers four questions in order: What broke, Why,
    // Fix, and Did it hold. The first three render for an incident awaiting a
    // decision; "Did it hold" appears only once something was applied, so it
    // must be absent here rather than shown empty.
    for (const section of ['What broke', 'Why', 'Fix']) {
      await expect(page.getByRole('heading', { level: 2, name: section })).toBeVisible()
    }
    await expect(page.getByRole('heading', { level: 2, name: 'Did it hold' })).toHaveCount(0)

    // What broke: the real finding this incident opened on, read
    // from the findings row (IncidentDetailPage.tsx reads `data.findings[0]`)
    // rather than from the incident's own identity columns. Both now name
    // the same object, which is the point of B180 — before it, this was the
    // only place on the whole screen where "checkout-worker" appeared.
    await expect(page.getByText(/checkout-worker: Container checkout-worker was OOMKilled/)).toBeVisible()

    // Why: the real causal-chain conclusion
    // demo_data.go seeded for this incident, not an empty/locked state.
    // `.first()`: the same root-cause sentence legitimately repeats in the
    // Fix section's approval card (item.rootCauseStatement) once a plan exists.
    await expect(
      page.getByText(/OOMKilled repeatedly because its memory limit is too low/).first(),
    ).toBeVisible()

    // Fix: the real proposed plan, in the same ApprovalDecisionCard the queue
    // renders (FixSection.tsx), with its human action label and its diff.
    const fix = page.locator('#incident-fix')
    await expect(fix).toContainText('Scale deployment')
    await expect(fix.locator('.diff-pair-after')).toContainText('spec.replicas: 4')
  })

  test('the approval queue shows the pending plan with its real diff and decision controls', async ({ page }) => {
    await page.getByRole('link', { name: 'Approvals' }).click()
    await expect(page).toHaveURL(/\/approvals$/)

    // The queue used to carry an <h2>Needs decision</h2>. The worklist
    // redesign replaced that heading with a count in the header summary
    // ("N need a decision"), which is a better claim anyway — it says how
    // much work there is, not merely that a section exists. The unit tests
    // were updated with the redesign; this spec was not, and since the whole
    // suite was already failing at login it never reported the drift.
    await expect(page.getByText(/need a decision/i).first()).toBeVisible()

    // The seeded fixture has exactly one plan sitting in AwaitingApproval
    // with no decision recorded yet (every other seeded plan is already
    // approved/rejected, or has no plan at all). This card's target name
    // comes from the remediation_recommendations row (`plan.targetName`),
    // a different column from the incident identity the list renders — so
    // finding "checkout-worker" here and on the list is a real agreement
    // between two independently seeded facts, not one fact read twice.
    const entry = page.locator('.approval-row', { hasText: 'checkout-worker' })
    await expect(entry).toBeVisible()
    // The human label, not the wire value. This asserted the raw
    // 'ScaleDeployment' action type until the approval redesign humanised it
    // to "Scale deployment" — the design system's "never render a raw API
    // identifier as a user-facing value" rule. Asserting the label is also
    // the better test: the raw enum appearing on screen would itself be the
    // defect.
    await expect(entry).toContainText('Scale deployment')

    // The diff view: planChange() (utils/incidents.ts) renders a
    // ScaleDeployment's new replica count as an explicit after-value with no
    // before (the browser cannot know the live count; only the hub does at
    // approval time) — this is the one line in the whole page that answers
    // "what would actually change".
    await expect(entry.locator('.diff-pair-after')).toContainText('spec.replicas: 4')

    // The decision itself is not exercised here — clicking Approve would
    // execute a real signed patch against the (deliberately Disconnected)
    // demo cluster, which is a real mutation with a real failure mode
    // ("gateway: cluster is not connected") that has nothing to do with
    // whether this page renders correctly. This spec's job is to prove the
    // real approval/diff view renders from a real pending plan; exercising
    // the approve/reject mutation's own success and failure paths is
    // already covered at the component level (ApprovalDecisionCard.test.tsx,
    // ApprovalsPage.test.tsx) against a mocked API, which is the right
    // layer for asserting what happens after a click that has side effects.
    //
    // The demo cluster has no remediation agent, so nothing can execute on it:
    // Approve is shown disabled with that reason named, never hidden, and
    // Reject (which changes nothing in the cluster) stays available.
    const approve = entry.getByRole('button', { name: 'Approve' })
    await expect(approve).toBeDisabled()
    await expect(approve).toHaveAttribute('title', /no remediation agent connected/)
    await expect(entry.getByRole('button', { name: 'Reject' })).toBeEnabled()

    // Same card, same data, mounted a second time on the incident's own
    // Approve stage (BACKLOG D8 A8's "one component, two mounts") — confirms
    // the two surfaces actually agree rather than only asserting on whichever
    // one this test happened to check first.
    await entry.getByRole('link', { name: 'checkout-worker' }).click()
    await expect(page).toHaveURL(/\/incidents\/inc_/)
    const onIncidentPage = page.locator('.approval-row', { hasText: 'checkout-worker' })
    await expect(onIncidentPage.locator('.diff-pair-after')).toContainText('spec.replicas: 4')
  })
})
