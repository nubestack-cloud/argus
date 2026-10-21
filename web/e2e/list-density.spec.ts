import { test, expect } from '@playwright/test'
import { ADMIN_EMAIL, ADMIN_PASSWORD } from './api'

// Turns the one review finding nobody could verify from source into a fact CI
// can hold.
//
// An external product review measured the incidents list at 126px per row and
// four rows visible at 1440x900, against 225 incidents — the single biggest
// structural complaint in the report, and the only one that could not be
// checked by reading code, because it is geometry. Row height is an emergent
// property of the identity cell wrapping to three lines, so nothing in the CSS
// states it and no unit test can see it. It can regress silently by someone
// adding one more line to a cell.
//
// This does NOT assert the target design (that is gated on an open product
// decision about what leads the row). It asserts the CURRENT measured geometry
// so that:
//   - the number is in version control rather than in a review document, and
//   - a change that makes it worse fails, instead of being discovered by the
//     next reviewer.
//
// When the row is deliberately rebuilt, this test's constants are the thing you
// update, in the same commit, on purpose. That edit is the record of the
// improvement.
const VIEWPORT = { width: 1440, height: 900 }

// A ceiling, not an equality — the point is that it must not get taller.
//
// Measured 2026-09-19: 101px. Re-measured 2026-09-24 after PROJECT.md B180
// repaired the fixture: 93px, with a three-line identity block of a constant
// 60px. The ceiling is deliberately NOT lowered to 93 — see the closing
// paragraph of this comment.
//
// THIS NUMBER WAS MEANINGLESS UNTIL 2026-09-24, AND THAT IS THE WHOLE STORY
// OF B180. internal/api/demo_data.go never set incidents.object_key,
// workload_key or opening_reason, so every seeded row fell back to
// `incidentIdentity`'s last resort — "Incident demo-ima", ONE 22px line, no
// kind line, no fault line. The identity cell was therefore never what set
// the row's height; the state cell was. Demonstrated on the exact fixture CI
// seeds: deleting B178's nowrap/ellipsis rule outright (index.css) left the
// measured row at 82px and this spec passed identically. The test guarding
// that fix could not see the thing it guards.
//
// With the fixture fixed, the same experiment fails the way it must: the rule
// removed, `overflow-wrap: anywhere` collapses the identity column to its
// min-content width and the measured row goes to 227px. Red without the fix,
// green with it — which is the only thing that makes the constant below a
// guard rather than a number in a file.
//
// The review that started this reported 126px against a real instance. A real
// fleet could still be taller than CI, and until B181 it was: B178's
// truncation made the identity block's height constant, which left the STATE
// cell as the one thing on the row still free to grow with its data, and this
// fixture does not contain every state-and-badge combination a real fleet
// does. That is now closed at the source rather than absorbed by the ceiling
// — index.css keeps each pill on one line, so the state cell is two stacked
// pills (~50px) under the identity block's constant 60px and the row height no
// longer depends on the state vocabulary at all. Measured 2026-09-24 with
// every row forced to the widest label in STATE_LABEL: 93px, unchanged, from
// 1440px down to 900px wide.
//
// The ceiling stays at 110 rather than dropping to 93. The 17px of room is no
// longer about the state cell; it is for the identity block, which is a
// constant only as long as it stays at three lines, and because lowering it to
// the current measurement would make an unrelated one-line change fail for no
// reason anyone could act on.
const MAX_ROW_HEIGHT_PX = 110

test.describe('incidents list density', () => {
  test.use({ viewport: VIEWPORT })

  test('the tallest row stays within its measured height, and the header does not eat the viewport', async ({ page }) => {
    // Same login shape the other specs use: `Password` must be exact, because
    // the sign-in form has a second control whose label also matches /password/.
    await page.goto('/login')
    await page.getByLabel('Email').fill(ADMIN_EMAIL)
    await page.getByLabel('Password', { exact: true }).fill(ADMIN_PASSWORD)
    await page.getByRole('button', { name: 'Sign in' }).click()
    await expect(page).toHaveURL(/\/overview$/)

    await page.goto('/incidents')
    const rows = page.locator('table tbody tr')
    await expect(rows.first()).toBeVisible()

    // CI signs in as the bootstrap admin, still on its first password, so the
    // shell shows a change-password reminder above every page. It is dismissed
    // once and is not the list's own chrome, which is what is measured below.
    const reminder = page.getByRole('button', { name: 'Dismiss password reminder' })
    if (await reminder.isVisible()) await reminder.click()

    // Two rows is the floor for this to mean anything: a ceiling measured
    // over a single row is a measurement of that row, not of the list.
    const rowCount = await rows.count()
    test.skip(rowCount < 2, 'needs at least two incidents to measure the list')

    // EVERY row, and assert on the tallest — PROJECT.md B181.
    //
    // This used to measure `rows.nth(1)` alone, on the reasoning that the
    // first row can carry a sticky or border artefact and that nth(1) is,
    // by the fixture's own `last_seen DESC` timing, demo_data.go's
    // "apiserver-probe" incident: a `kube-apiserver-<node>` static Pod on a
    // Node-owned incident, the long unbroken shape B178's truncation rule was
    // written for. Both halves of that were true and it still hid a live
    // breach for two working days. A row-height CEILING has one correct
    // sample, and it is the maximum: eight of these eleven rows were 93px,
    // one was 100px and one was 118px against a 110px ceiling, and the spec
    // was green because row 2 happened to be one of the eight. Picking a row
    // by what the fixture's timings make interesting only guards the shape
    // someone already thought of.
    //
    // Measuring in one `evaluateAll` rather than N `boundingBox()` round
    // trips also means every row is measured against the same layout, which
    // is the thing being asserted — a per-row await leaves room for a
    // re-layout between samples.
    const measured = await rows.evaluateAll((els) =>
      els.map((el, index) => ({
        index,
        height: el.getBoundingClientRect().height,
        // Both facts a failure needs in order to be actionable: the state
        // cell is what varies (the identity block is a constant 60px since
        // B178), and the name is how you find the row on screen.
        state: (el.querySelector('td.incidents-state-cell')?.textContent ?? '').trim(),
        name: (el.querySelector('.identity-block-name')?.textContent ?? '').trim(),
      })),
    )
    expect(measured.length, 'the rows should be laid out and visible').toBeGreaterThan(0)
    const tallest = measured.reduce((worst, row) => (row.height > worst.height ? row : worst))

    // Report the real number, and WHICH row and state produced it — a bare
    // assertion here would say "expected 140 to be <= 130" without saying what
    // it means, and the previous version could not have named the row at all.
    expect(
      tallest.height,
      `the tallest of ${measured.length} incident rows is ${Math.round(tallest.height)}px ` +
        `(row ${tallest.index + 1}, "${tallest.name}", state cell "${tallest.state}"); ` +
        `${MAX_ROW_HEIGHT_PX}px or less is what was measured. Heights seen: ` +
        `${measured.map((r) => Math.round(r.height)).join(', ')}. ` +
        'Taller rows mean fewer incidents per screen on the product\'s most contested surface. ' +
        'If this is a deliberate redesign, update MAX_ROW_HEIGHT_PX in the same commit.',
    ).toBeLessThanOrEqual(MAX_ROW_HEIGHT_PX)

    // The chrome above row 1 is the other half of the same problem: it is fixed
    // cost paid before a single incident is visible.
    const firstRowTop = (await rows.first().boundingBox())!.y
    expect(
      firstRowTop,
      `${Math.round(firstRowTop)}px of header, tabs, chips and filters sit above the first row at ` +
        `${VIEWPORT.width}x${VIEWPORT.height}. That is viewport spent before any incident is shown.`,
    ).toBeLessThanOrEqual(420)
  })
})
