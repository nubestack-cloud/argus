// Manual light/dark theme override, layered on top of the
// prefers-color-scheme-only system that index.css already had. "System" is
// still the default for a first-time visitor (no localStorage entry ->
// getStoredTheme() returns null -> data-theme attribute stays absent ->
// index.css's `@media (prefers-color-scheme: dark)` block, guarded by
// `:root:not([data-theme="light"])`, decides the look same as before). An
// explicit choice is persisted and reapplied on every load, and wins over
// the OS setting in both directions — see index.css's
// `:root[data-theme="dark"]` block, which is unconditional (not gated by
// the media query).
export type ThemeOverride = 'light' | 'dark'

const STORAGE_KEY = 'argus.theme'

function isThemeOverride(value: string | null): value is ThemeOverride {
  return value === 'light' || value === 'dark'
}

// null means "no override — follow the OS setting."
export function getStoredTheme(): ThemeOverride | null {
  try {
    const value = localStorage.getItem(STORAGE_KEY)
    return isThemeOverride(value) ? value : null
  } catch {
    // localStorage unavailable (privacy mode, disabled storage, etc.) —
    // fall back to "system," same as a first-ever visit.
    return null
  }
}

export function applyTheme(theme: ThemeOverride | null): void {
  const root = document.documentElement
  if (theme) {
    root.setAttribute('data-theme', theme)
  } else {
    root.removeAttribute('data-theme')
  }
}

export function setStoredTheme(theme: ThemeOverride | null): void {
  try {
    if (theme) {
      localStorage.setItem(STORAGE_KEY, theme)
    } else {
      localStorage.removeItem(STORAGE_KEY)
    }
  } catch {
    // Same fallback as getStoredTheme — the toggle still works for this
    // page view via applyTheme below, it just won't persist across reloads.
  }
  applyTheme(theme)
}

export function systemPrefersDark(): boolean {
  return typeof window !== 'undefined' && window.matchMedia('(prefers-color-scheme: dark)').matches
}

// applyAccent sets the org-wide primary-colour preset (Settings > Appearance,
// PROJECT.md 2026-10-14) by toggling `data-accent` on <html> — mirroring
// applyTheme above, but NOT persisted to localStorage: this is an org-wide
// setting delivered on every GET /users/me (the same request that resolves
// identity), not a per-browser override, so AuthContext just re-applies it
// every time identity resolves rather than storing it client-side at all. An
// id outside index.css's known `[data-accent=...]` presets is harmless: the
// attribute is simply never matched by any rule, and the base (teal)
// `:root`/`:root[data-theme]` values apply exactly as they did before this
// setting existed.
export function applyAccent(primaryColorId: string | null): void {
  const root = document.documentElement
  if (primaryColorId) {
    root.setAttribute('data-accent', primaryColorId)
  } else {
    root.removeAttribute('data-accent')
  }
}
