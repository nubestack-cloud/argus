import { test, expect } from '@playwright/test'
import { ADMIN_EMAIL, ADMIN_PASSWORD } from './api'

// The login flow named first in PRODUCT_DIRECTION.md/lld/13's UI-critical
// list — real auth against the real hub (POST /api/v1/auth/login,
// internal/api/auth.go), not a mocked fetch. Bearer-token auth kept in
// React state (src/auth/AuthContext.tsx) rather than a cookie, so there is
// nothing here for Playwright's cookie jar to manage — every check below
// drives the actual form and reads the actual resulting page.

test.describe('login', () => {
  test('an unauthenticated visit to a protected route is bounced to /login', async ({ page }) => {
    await page.goto('/incidents')
    await expect(page).toHaveURL(/\/login$/)
  })

  test('rejects a wrong password with the hub\'s own error, not a client-side guess', async ({ page }) => {
    await page.goto('/login')
    await page.getByLabel('Email').fill(ADMIN_EMAIL)
    await page.getByLabel('Password', { exact: true }).fill('definitely-the-wrong-password')
    await page.getByRole('button', { name: 'Sign in' }).click()

    // getByRole('alert'), not a class. The sign-in screen is one of three
    // ported designs chosen install-wide in Settings -> Appearance, and each
    // styles itself with CSS modules, so its class names are build-hashed and
    // cannot be asserted on. This spec used to look for `.form-error`, which
    // the old single login page had; when the three designs replaced it the
    // selector silently matched nothing. All three set role="alert" on their
    // error element, and only when there is an error to show — so this is both
    // stable across the three and a real assertion that the message is
    // announced to a screen reader rather than merely painted.
    await expect(page.getByRole('alert')).toBeVisible()
    // Never navigated away — a real 401 from the real hub, not a redirect.
    await expect(page).toHaveURL(/\/login$/)
  })

  test('logs in with the real bootstrap credential, reaches the fleet overview, and can sign out', async ({
    page,
  }) => {
    await page.goto('/login')
    await page.getByLabel('Email').fill(ADMIN_EMAIL)
    await page.getByLabel('Password', { exact: true }).fill(ADMIN_PASSWORD)
    await page.getByRole('button', { name: 'Sign in' }).click()

    await expect(page).toHaveURL(/\/overview$/)
    // The primary nav (components/AppShell.tsx) only renders once AuthContext
    // has a real access token from the real hub response.
    await expect(page.getByRole('link', { name: 'Incidents' })).toBeVisible()

    await page.getByRole('button', { name: `Account menu for ${ADMIN_EMAIL}` }).click()
    await page.getByRole('menuitem', { name: 'Sign out' }).click()

    await expect(page).toHaveURL(/\/login$/)
    // logout() clears the refresh token (AuthContext.tsx), so a reload must
    // not silently restore the session it just tore down.
    await page.reload()
    await expect(page).toHaveURL(/\/login$/)
  })

  test('a visit to /login with an already-restorable session redirects straight through', async ({ page }) => {
    await page.goto('/login')
    await page.getByLabel('Email').fill(ADMIN_EMAIL)
    await page.getByLabel('Password', { exact: true }).fill(ADMIN_PASSWORD)
    await page.getByRole('button', { name: 'Sign in' }).click()
    await expect(page).toHaveURL(/\/overview$/)

    // A second, direct visit to /login should bounce back to /overview
    // rather than showing the form again (LoginPage.tsx's early-return on an
    // existing accessToken) — this is what makes the destination-preserving
    // redirect below meaningful rather than accidental.
    await page.goto('/login')
    await expect(page).toHaveURL(/\/overview$/)
  })
})
