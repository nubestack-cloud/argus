import { lazy, Suspense, useEffect, useLayoutEffect, useRef, useState } from 'react'
import { SetupGuide } from './SetupGuide'
import type { ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { NavLink, useLocation } from 'react-router-dom'
import { getApprovals } from '../api/client'
import { CAP_REMEDIATION_APPROVE } from '../api/capabilities'
import { NAV_REQUIRED_CAPABILITIES } from './navCapabilities'
import { missingCapabilityMessage } from '../api/capabilityInfo'
import { useAuth } from '../auth/useAuth'
import type { AuthContextValue } from '../auth/AuthContextBase'
import { useHasCapability, useMissingCapabilities } from '../auth/useCapabilities'
import { applyTheme, getStoredTheme, setStoredTheme, systemPrefersDark } from '../theme'
import type { ThemeOverride } from '../theme'
import { ChangePasswordModal } from './ChangePasswordModal'
import {
  ArgusLogoMark,
  ApprovalsIcon,
  AuditLogIcon,
  ClustersIcon,
  IncidentsIcon,
  InsightsIcon,
  MenuIcon,
  OverviewIcon,
  RecentChangesIcon,
  SearchIcon,
  SettingsIcon,
  UsersIcon,
} from './icons'
import { LIVE_FALLBACK_MS } from '../realtime/refresh'
import { usePhoneLayout } from '../hooks/usePhoneLayout'

// The persistent app shell every authenticated screen renders inside —
// added now, before it's "needed" in the sense of having more than one
// real page, specifically so the second screen (whenever Phase 1 adds one)
// is a new NavLink, not another header/logout copy-pasted per page the way
// ClustersPage originally had its own. Mirrors DESIGN.md
// §15.1's screen list — the two arrays below grow exactly in step with
// which of those screens actually exist as routes, never ahead of them.
// Adding the next entry is exactly one `{ to, label, icon }` object — the
// sidebar maps over each array unconditionally, it never assumes a fixed
// count. `icon` is a distinct glyph per entry (icons.tsx) rather than one
// icon repeated six times — the whole point of adding icons to a text-only
// nav is faster visual scanning, which a repeated glyph wouldn't give.
//
// Split into two arrays (not one, as before this round) so the sidebar can
// render Settings visually apart from the day-to-day screens — a divider
// plus its own pinned-to-the-bottom section, so it reads as "app
// configuration" rather than a seventh item in the same list as Overview or
// Incidents. Nothing about the split changes which routes exist or what
// they're called. (There used to be an `ALL_NAV_ITEMS` concatenation here for
// the top bar's page-title lookup; that lookup went away with the duplicated
// heading in BUGS.md 26, and so did the constant.)
// `section` lists further routes this item stands for: Incidents is also
// active on /signals and /tolerations, which are tabs of its section
// (IncidentsSectionTabs) rather than sidebar rows of their own.
interface NavItem { to: string; label: string; icon: ReactNode; section?: string[] }

// THE DAY-TO-DAY LOOP, and nothing else. An incident arrives, you look at the
// fleet, open the incident, approve the fix. Five items, in the order that work
// actually moves through them, plus Search.
//
// INCIDENTS IS A SECTION, not one list: Incidents (what ARGUS raised), Signals
// (everything it recorded, including what internal/gateway/promotion.go's
// evidence boundary deliberately kept as an observation — PROJECT.md F31) and
// Tolerations (conditions someone said to expect) are tabs of one page
// (IncidentsSectionTabs). They answer one question from three sides — "what is
// wrong, what else did you see, what did we decide to ignore" — and as three
// sidebar rows they read as three unrelated destinations.
const PRIMARY_NAV_ITEMS: NavItem[] = [
  { to: '/overview', label: 'Overview', icon: <OverviewIcon /> },
  { to: '/clusters', label: 'Clusters', icon: <ClustersIcon /> },
  // PROJECT.md PG19: what ships together, across clusters.
  { to: '/incidents', label: 'Incidents', icon: <IncidentsIcon />, section: ['/signals', '/tolerations'] },
  { to: '/approvals', label: 'Approvals', icon: <ApprovalsIcon /> },
  // CI-S12: find an object across every cluster.
  { to: '/search', label: 'Search', icon: <SearchIcon /> },
]

// LOOKING BACK, not working. Neither of these is ever the answer to "an alert
// just fired" — they are what you open when the question is about the past
// (what did ARGUS or a person do) or about the aggregate (what keeps breaking).
// They sat in the middle of the primary list, so the two screens nobody reaches
// during an incident had the same weight as Incidents itself.
const RECORD_NAV_ITEMS: NavItem[] = [
  // Recent changes leads this group. It is the only one of the three that is
  // ever reached WHILE something is wrong — "what changed on Tuesday" is a
  // live question with an undo at the end of it — and it is deliberately not
  // folded into the audit log beside it: that records every request including
  // reads, this lists only the mutations ARGUS made.
  { to: '/changes', label: 'Recent Changes', icon: <RecentChangesIcon /> },
  { to: '/audit-log', label: 'Audit Log', icon: <AuditLogIcon /> },
  { to: '/insights', label: 'Insights', icon: <InsightsIcon /> },
]

// Which capabilities a destination needs before it can show anything.
//
// This is the nav half of the disabled-not-hidden rule (lld/11 §6). A
// destination a role cannot use is MARKED, not removed: the link still
// navigates — the page itself explains what is missing and what to ask for —
// but the rail says so first, so nobody walks into a dead end and nobody has
// to discover a whole screen exists by being told about it.
//
// Two deliberate absences:
//
//   - /overview is the landing route and aggregates several capabilities,
//     degrading per panel. There is no single grant whose absence makes it a
//     dead end, so marking it would be a claim this map cannot support.
//   - /settings is the same shape, more so: its sections each carry their own
//     capability and each says so in place (SettingsPage's own panels). A
//     blanket "no access" on the rail would be wrong for a super-admin-only
//     section sitting beside one anyone can read.
//
// Everything else here is a screen whose whole content is behind one gate, and
// that gate is the one its route enforces in internal/api/server.go — keep the
// two in step; this map is a claim about the hub, not about the UI.
const ObjectInspectorHost = lazy(() => import('../insight/ObjectInspector').then((m) => ({ default: m.ObjectInspectorHost })))
const CommandPaletteHost = lazy(() => import('../palette/CommandPalette').then((m) => ({ default: m.CommandPaletteHost })))


// ADMINISTRATION. Users belongs with Settings, not above Audit Log: both are
// "who and how this install is configured", visited when onboarding somebody or
// changing a policy, never while triaging.
const ADMIN_NAV_ITEMS: NavItem[] = [
  { to: '/users', label: 'Users', icon: <UsersIcon /> },
  { to: '/settings', label: 'Settings', icon: <SettingsIcon /> },
]

const SUN_ICON = (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
    <circle cx="12" cy="12" r="4" />
    <path
      strokeLinecap="round"
      d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"
    />
  </svg>
)

const MOON_ICON = (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
    <path strokeLinejoin="round" d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79Z" />
  </svg>
)

// One nav destination, with the access marking item #13(b) asks for.
//
// The link is NEVER removed and NEVER made unclickable. A removed link is
// indistinguishable from a feature that does not exist, and an unclickable one
// is unreachable by keyboard — both lose the discoverability the
// disabled-not-hidden rule exists to protect. What changes is that the row
// says "No access" and carries, as its accessible name and its tooltip, the
// human sentence naming what the viewer cannot do and which capability to ask
// for (api/capabilityInfo.ts).
//
// Marked only once the grants have actually arrived. useMissingCapabilities'
// `resolved` is the whole reason that hook exists: useHasCapability is
// deny-by-default while the permissions query is in flight, which is right for
// a button and wrong for a label — it would brand every destination "No
// access" for the first few hundred milliseconds of every load.
//
// "No access" is a WORD, not a colour and not a bare glyph: the lock is
// aria-hidden decoration beside it. The tag hides with the label when the rail
// is collapsed to icons, so the `title` carries the whole message there —
// which is the same fallback the labels themselves already rely on.
function ShellNavLink({
  item,
  collapsed,
  children,
}: {
  item: NavItem
  collapsed: boolean
  children?: ReactNode
}) {
  const { resolved, missing } = useMissingCapabilities(NAV_REQUIRED_CAPABILITIES[item.to] ?? [])
  const blocked = resolved && missing.length > 0
  const reason = blocked ? missingCapabilityMessage(missing) : undefined
  const { pathname } = useLocation()
  const inSection = (item.section ?? []).some((p) => pathname === p || pathname.startsWith(p + '/'))

  return (
    <NavLink
      to={item.to}
      className={({ isActive }) =>
        ['app-nav-link', isActive || inSection ? 'active' : '', blocked ? 'app-nav-link-blocked' : '']
          .filter(Boolean)
          .join(' ')
      }
      title={reason ?? (collapsed ? item.label : undefined)}
    >
      {item.icon}
      <span className="app-nav-label">{item.label}</span>
      {blocked && (
        <span className="app-nav-note">
          {/* Decoration beside the word, never the carrier of it: a padlock on
              its own is a glyph a reader has to guess at, and the design rules
              call that out by name. */}
          <svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" strokeWidth="2.2" aria-hidden="true">
            <rect x="5" y="11" width="14" height="10" rx="2" />
            <path d="M8 11V7.5a4 4 0 0 1 8 0V11" />
          </svg>
          <span className="app-nav-note-text">No access</span>
        </span>
      )}
      {/* The reason is in the tooltip for a mouse and in the accessible name
          for a screen reader — hover-only would leave a keyboard or touch user
          with the tag and no explanation. */}
      {blocked && <span className="visually-hidden">{reason}</span>}
      {children}
    </NavLink>
  )
}

// A manual override on top of the prefers-color-scheme-only theming
// index.css already had — "system" (no override) stays the default for a
// first-time visitor, an explicit choice persists in localStorage and wins
// over the OS setting from then on, in either direction. See src/theme.ts
// for the data-theme mechanism this drives.
// initialsFor turns an account identity into a two-letter avatar:
// "jane.doe@corp" → "JD", "admin@localhost" → "AD".
export function initialsFor(identity: string | null | undefined): string {
  const local = (identity ?? '').split('@')[0].trim()
  if (!local) return '?'
  const parts = local.split(/[._\-\s]+/).filter(Boolean)
  const letters = parts.length >= 2 ? parts[0][0] + parts[1][0] : local.slice(0, 2)
  return letters.toUpperCase()
}

const isMac = typeof navigator !== 'undefined' && /mac/i.test(navigator.platform || navigator.userAgent)

// The header's search launcher: a visible, clickable way into the command
// palette, and the place the Ctrl/Cmd+K shortcut is advertised (PROJECT.md
// UX7). It dispatches the palette's open event rather than importing it, so
// the palette stays out of the main bundle.
function SearchLauncher() {
  return (
    <button
      type="button"
      className="secondary topbar-search"
      aria-label={`Search or jump to (${isMac ? 'Command' : 'Control'}+K)`}
      onClick={() => window.dispatchEvent(new Event('argus:open-palette'))}
    >
      <SearchIcon size={14} />
      <span className="topbar-search-text">Search or jump to…</span>
      <kbd className="kbd-hint">{isMac ? '⌘K' : 'Ctrl K'}</kbd>
    </button>
  )
}

function ThemeToggle() {
  const [override, setOverride] = useState<ThemeOverride | null>(() => getStoredTheme())

  const effective: ThemeOverride = override ?? (systemPrefersDark() ? 'dark' : 'light')

  function toggle() {
    const next: ThemeOverride = effective === 'dark' ? 'light' : 'dark'
    setStoredTheme(next)
    setOverride(next)
  }

  return (
    <button
      type="button"
      className="secondary theme-toggle"
      onClick={toggle}
      aria-label={effective === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
      title={effective === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
    >
      {effective === 'dark' ? SUN_ICON : MOON_ICON}
    </button>
  )
}

// What the account control says when the hub could not tell us who is signed
// in (GET /users/me failed, or answered with something that was not an
// identity). An explicit admission, never a remembered address and never a
// plausible-looking placeholder like "SSO user": the whole of PROJECT.md B165
// is that this label is a statement about the audited session, so the only
// honest thing to render when it is unknown is that it is unknown. The rest of
// the menu keeps working, because signing out must not depend on the hub being
// able to answer questions.
const IDENTITY_UNAVAILABLE = 'Account unavailable'

function AccountMenu({
  email,
  identityStatus,
  authMethod,
  onChangePassword,
  onSignOut,
  signingOut,
}: {
  email: string | null
  identityStatus: AuthContextValue['identityStatus']
  authMethod: AuthContextValue['authMethod']
  onChangePassword: () => void
  onSignOut: () => void
  signingOut: boolean
}) {
  const [open, setOpen] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return

    const closeOnOutsideClick = (event: MouseEvent) => {
      if (!containerRef.current?.contains(event.target as Node)) setOpen(false)
    }
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false)
    }
    const closeWhenFocusLeaves = (event: FocusEvent) => {
      if (!containerRef.current?.contains(event.target as Node)) setOpen(false)
    }

    document.addEventListener('mousedown', closeOnOutsideClick)
    document.addEventListener('keydown', closeOnEscape)
    document.addEventListener('focusin', closeWhenFocusLeaves)
    return () => {
      document.removeEventListener('mousedown', closeOnOutsideClick)
      document.removeEventListener('keydown', closeOnEscape)
      document.removeEventListener('focusin', closeWhenFocusLeaves)
    }
  }, [open])

  return (
    <div className="account-menu" ref={containerRef}>
      <button
        type="button"
        className="secondary account-menu-trigger"
        aria-label={email ? `Account menu for ${email}` : 'Account menu'}
        // The control names itself; aria-busy is what says the NAME is still
        // coming, on the element that actually has a role to carry it (a bare
        // <span> with aria-label is not reliably exposed).
        aria-busy={identityStatus === 'pending'}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((current) => !current)}
      >
        {/* An initials avatar, not the full address (owner review 2026-10-10,
            PROJECT.md UX8): the name and email live in the menu below, and
            the button's accessible name still carries the address. */}
        {email ? (
          <span className="account-avatar" aria-hidden="true">{initialsFor(email)}</span>
        ) : identityStatus === 'unavailable' ? (
          // Still says so in words (tooltip and screen-reader text): an
          // avatar of "?" alone would not tell anyone the account is unknown.
          <>
            <span className="account-avatar" aria-hidden="true" title={IDENTITY_UNAVAILABLE}>?</span>
            <span className="visually-hidden">{IDENTITY_UNAVAILABLE}</span>
          </>
        ) : (
          <span className="account-avatar" aria-hidden="true">
            <span className="skeleton" style={{ width: '1.2rem', height: '0.8rem' }} />
          </span>
        )}
        <svg className="account-menu-chevron" viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
          <path d="m3 6 5 5 5-5" />
        </svg>
      </button>

      {open && (
        <div className="account-menu-popover" role="menu" aria-label="Account actions">
          <div className="account-menu-identity">
            <span>Signed in as</span>
            {email ? (
              <strong title={email}>{email}</strong>
            ) : identityStatus === 'unavailable' ? (
              <strong>{IDENTITY_UNAVAILABLE}</strong>
            ) : (
              <strong>
                {/* The skeleton is the sighted placeholder and carries nothing
                    for a screen reader (aria-hidden, as every other skeleton
                    here is); the honest text beside it is what a screen reader
                    gets, so "Signed in as" is never announced with nothing
                    after it. */}
                <span className="skeleton" style={{ width: '12ch', height: '0.85rem' }} aria-hidden="true" />
                <span className="visually-hidden">Loading the signed-in account</span>
              </strong>
            )}
          </div>
          <span className="account-menu-divider" role="separator" />
          {/* Disabled with the reason named, never omitted — lld/11 §6, applied
              here for the same reason it applies to a capability: a control the
              viewer cannot use must still be discoverable, including to a
              screen reader. A federated account has no ARGUS password (the
              users_local_xor_federated constraint), so this flow cannot
              succeed for one; before it was disabled, submitting the form
              reached PUT /users/me/password and came back 500. The reason is
              stated rather than implied, because "why is this greyed out" is
              otherwise unanswerable from the screen.

              'password' specifically, not `!== 'federated'`: while the
              identity is still loading, authMethod is null and the honest
              answer is "not yet known", which must not render as available. */}
          <button
            type="button"
            role="menuitem"
            disabled={authMethod !== 'password'}
            title={
              authMethod === 'federated'
                ? 'This account signs in through your identity provider, so it has no ARGUS password to change.'
                : authMethod === 'password'
                  ? undefined
                  : 'Available once the signed-in account has loaded.'
            }
            onClick={() => {
              setOpen(false)
              onChangePassword()
            }}
          >
            Change password
          </button>
          <button
            type="button"
            role="menuitem"
            onClick={() => {
              setOpen(false)
              window.dispatchEvent(new Event('argus:open-shortcuts'))
            }}
          >
            Keyboard shortcuts <kbd className="kbd-hint">?</kbd>
          </button>
          {/* The menu stays open while the hub answers, with the item saying
              so: sign-out waits for the revocation to be confirmed (bounded —
              see AuthContext's logout) and then the whole shell unmounts. */}
          <button type="button" role="menuitem" disabled={signingOut} onClick={() => onSignOut()}>
            {signingOut ? 'Signing out…' : 'Sign out'}
          </button>
        </div>
      )}
    </div>
  )
}

// Runs once, at module load (before AppShell's first render), so the
// data-theme attribute already reflects a stored override even if
// index.html's own anti-flash inline script were ever removed. Idempotent
// with that script — applying the same value twice is harmless.
applyTheme(getStoredTheme())

const sidebarCollapsedStorageKey = 'argus.sidebarCollapsed'

function getStoredSidebarCollapsed() {
  try {
    return localStorage.getItem(sidebarCollapsedStorageKey) === 'true'
  } catch {
    return false
  }
}

// Sidebar + slim top bar, the standard professional-dashboard split the
// user's feedback asked for by name: the sidebar stays "what screens exist"
// (brand, primary nav, Settings set apart below a divider); the top bar
// carries only the account controls (theme, current user, sign out),
// pushed to its right edge — moving identity/sign-out out of the sidebar's
// bottom-left corner (where the user's own feedback said it read as
// buried) to the conventional top-right corner most dashboard products
// use. It deliberately does NOT also repeat the current page's own name:
// that used to duplicate every page's own <h1> exactly (a second, real,
// user-reported heading-repeats-itself bug), and the sidebar already
// carries the ARGUS brand mark, so there was nothing left for a top-bar
// title to say that wasn't already on screen twice.
export function AppShell({ children }: { children: ReactNode }) {
  const { accessToken, email, identityStatus, authMethod, mustChangePassword, logout, signingOut } = useAuth()
  const canApprove = useHasCapability(CAP_REMEDIATION_APPROVE)
  const [changePasswordOpen, setChangePasswordOpen] = useState(false)
  const [passwordBannerDismissed, setPasswordBannerDismissed] = useState(false)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(getStoredSidebarCollapsed)
  // On a phone the burger does a different job: the nav is a menu, closed by
  // default, rather than a rail to narrow — the whole nav used to sit expanded
  // above every page at 390px, two screens of links before any content. Kept
  // apart from `sidebarCollapsed` (a stored desktop preference) so opening the
  // menu on a phone never changes how the desktop rail is remembered.
  const phoneNav = usePhoneLayout()
  // The menu is open FOR a path: navigating anywhere closes it, with no effect
  // needed to notice the navigation.
  const [phoneNavOpenFor, setPhoneNavOpenFor] = useState<string | null>(null)

  // Reset the reading position when the route changes. Opening an incident from
  // halfway down the incidents list used to land you halfway down the incident,
  // because nothing resets scroll on navigation and the browser has no reason to:
  // this is one document the whole time.
  //
  // It scrolls THIS ELEMENT, not the window, and that is the part worth knowing:
  // `.app-shell` is `height: 100dvh; overflow: hidden` and `.app-content` is the
  // `overflow-y: auto` pane inside it (index.css, the `height`-not-`min-height`
  // comment explains why the frame is fixed). The window never scrolls, so
  // `window.scrollTo(0, 0)` — the usual answer, and what react-router's own
  // ScrollRestoration would do — is a no-op here. A ref rather than a
  // `querySelector` because the element is rendered right below.
  //
  // Keyed on `pathname` alone, deliberately: changing a filter or a page number
  // rewrites `search`, and yanking the reader to the top when they page through a
  // table would be a worse bug than the one this fixes.
  //
  // `useLayoutEffect` so the reset lands before paint — with `useEffect` the new
  // page renders at the old offset for a frame and visibly jumps.
  //
  // Assigning `scrollTop`/`scrollLeft` rather than calling `scrollTo`: the two are
  // equivalent here (a jump, no animation — `scrollTo`'s default `behavior` is
  // already `auto`), but `scrollTo` is a method on Element that not every engine
  // implements, and jsdom is one of them. The first version of this used it and
  // took all 14 AppShell tests down with
  // `contentRef.current?.scrollTo is not a function` — caught by the
  // ErrorBoundary, which is to say the whole app white-screened rather than the
  // scroll merely not resetting. A property assignment cannot fail that way, and
  // an animated scroll on navigation would be disorienting anyway (and would need
  // its own `prefers-reduced-motion` handling).
  const contentRef = useRef<HTMLDivElement>(null)
  const { pathname } = useLocation()
  const phoneNavOpen = phoneNav && phoneNavOpenFor === pathname
  const toggleLabel = phoneNav
    ? phoneNavOpen
      ? 'Close navigation'
      : 'Open navigation'
    : sidebarCollapsed
      ? 'Expand navigation'
      : 'Collapse navigation'
  useLayoutEffect(() => {
    const el = contentRef.current
    if (!el) return
    el.scrollTop = 0
    el.scrollLeft = 0
  }, [pathname])
  const approvalsQuery = useQuery({
    queryKey: ['approvals'],
    queryFn: () => getApprovals(accessToken!),
    enabled: !!accessToken && canApprove,
    // The nav badge follows the queue, and every change to the queue
    // publishes IncidentUpdated (realtime/refresh.ts). This interval is the
    // fallback — and it is the one query mounted on EVERY page, so it was
    // also the one paying its 10s tick on all of them.
    refetchInterval: LIVE_FALLBACK_MS,
  })
  const pendingApprovalCount = approvalsQuery.data?.approvals.filter((approval) => !approval.alreadyApproved).length ?? 0

  useEffect(() => {
    try {
      localStorage.setItem(sidebarCollapsedStorageKey, sidebarCollapsed ? 'true' : 'false')
    } catch {
      // ignore — preference persistence is nice-to-have, not required
    }
  }, [sidebarCollapsed])

  return (
    <div
      className={[
        'app-shell',
        sidebarCollapsed ? 'app-shell-sidebar-collapsed' : '',
        phoneNavOpen ? 'app-shell-phone-nav-open' : '',
      ]
        .filter(Boolean)
        .join(' ')}
    >
      {/* A GLOBAL HEADER, spanning the full width above both panes — the shape
          the owner asked for, and the shape of every app whose sidebar collapses
          (Google Calendar being the reference). Two things follow from it that
          were not true before:

          1. The BRAND lives here, not in the sidebar. Product identity is not a
             navigation item, and it should not disappear or shrink to an icon
             when the nav does. It also means the sidebar's whole height is now
             navigation.
          2. The TOGGLE lives here, beside the brand, as a burger. It has been in
             three places inside the sidebar (the brand lockup, the last row, a
             grip on the seam) and each attempt failed the same way: a control
             that resizes the whole layout has no natural home INSIDE the thing
             it resizes. Out here it is next to nothing it can crowd, it never
             overlaps a nav link, and it does not move when the sidebar does —
             which is what made the grip feel janky.

          The header does not scroll away and carries no page title. A title here
          would duplicate every page's own <h1>, which this bar had once and was
          a real reported bug (BUGS.md 26). */}
      <header className="app-topbar">
        <div className="app-topbar-brand">
          {/* `aria-expanded` + `aria-controls` rather than only a label: this is
              a disclosure for the region below, and a screen-reader user should
              be able to tell whether it is currently open without hunting for
              the nav. The label says what the click will DO, which is the
              convention for a toggle whose state is already exposed. */}
          <button
            type="button"
            className="icon-button app-menu-toggle"
            aria-label={toggleLabel}
            title={toggleLabel}
            aria-expanded={phoneNav ? phoneNavOpen : !sidebarCollapsed}
            aria-controls="app-primary-nav"
            onClick={() =>
              phoneNav
                ? setPhoneNavOpenFor(phoneNavOpen ? null : pathname)
                : setSidebarCollapsed((collapsed) => !collapsed)
            }
          >
            <MenuIcon />
          </button>
          {/* THE PRIMARY HORIZONTAL LOCKUP (identity study, sheet two): the
              aperture mark, then the wordmark with "by Nubestack" stacked under
              it, all on one line. The owner chose this over the compact,
              byline-less form, so the attribution renders in both the header
              and on the login screen.

              The mark is 44px because `--brand-mark-ratio` (index.css) pairs it
              to the wordmark AND byline stacked: 24px * 1.25 + 12px * 1.2
              ~ 44.4. That pairing is why the number is derived rather than
              chosen, and why it has to move if the second line ever does.

              `size` is only the pre-CSS fallback — `.app-logo-mark` sizes the
              mark in `em` from that ratio — kept equal to what the ratio
              computes to so a flash before stylesheets apply is not a
              different shape.

              The blades move here, the same 13s vigil the login screen runs
              (`@keyframes argus-vigil`): three of the twelve asleep at any
              moment, the sleep travelling around the iris. It is the slowest
              motion in the app by a wide margin, and it stops entirely under
              `prefers-reduced-motion`, which leaves the still mark rather than
              a fully open one. */}
          <div className="app-header-brand">
            <ArgusLogoMark className="app-logo-mark" size={44} />
            <span className="app-brand-text">
              <span className="app-brand-wordmark">ARGUS</span>
              <span className="brand-byline">
                by <span className="brand-byline-name">Nubestack</span>
              </span>
            </span>
          </div>
        </div>
        <div className="app-topbar-actions">
          <SetupGuide />
          <SearchLauncher />
          <ThemeToggle />
          {/* Rendered unconditionally, unlike the previous `email && (...)`.
              Sign out is the one control that must never be unreachable, and
              gating the whole menu on knowing the account's NAME meant that a
              federated sign-in — which knew no name at all — had no way to
              sign out except clearing site data (PROJECT.md B165). The
              identity itself is the only thing that varies with
              identityStatus; see AccountMenu. */}
          <AccountMenu
            email={email}
            identityStatus={identityStatus}
            authMethod={authMethod}
            onChangePassword={() => setChangePasswordOpen(true)}
            onSignOut={() => void logout()}
            signingOut={signingOut}
          />
        </div>
      </header>
      <div className="app-body">
      <aside className="app-sidebar" id="app-primary-nav" aria-label="Primary">
        {/* THREE groups, each its own <nav> with its own accessible name, not
            one list of eight with a rule near the end. The rule is the point:
            the day-to-day loop, then the two look-back screens, then
            administration — so a reader scanning the sidebar during an incident
            can stop at the first divider. Each group is a real landmark rather
            than a styled <hr>, so a screen-reader user gets the same grouping
            the dividers give a sighted one. */}
        <nav className="app-nav">
          {PRIMARY_NAV_ITEMS.map((item) => (
            <ShellNavLink key={item.to} item={item} collapsed={sidebarCollapsed}>
              {item.to === '/approvals' && pendingApprovalCount > 0 && (
                <span className="app-nav-badge" aria-label={`${pendingApprovalCount} awaiting approval`}>
                  {pendingApprovalCount}
                </span>
              )}
            </ShellNavLink>
          ))}
        </nav>
        {/* `-pinned` carries the `margin-top: auto` that pushes this group and
            everything after it to the bottom of the sidebar. It is on the FIRST
            of the two bottom groups, not on both: `auto` on each would make the
            second one claim the free space all over again and split them apart. */}
        {/* Visible group headings on the two bottom groups, none on the
            primary one — the same shape the settings nav uses, so the two
            navigations in this product read as one system. A heading over the
            day-to-day loop would be labelling the obvious; over these two it
            says why they are set apart. Hidden when the rail is collapsed and
            when it becomes a horizontal bar, where there is no column for a
            heading to sit above. */}
        <nav className="app-nav-secondary app-nav-secondary-pinned" aria-label="History and analysis">
          <p className="app-nav-heading">History</p>
          {RECORD_NAV_ITEMS.map((item) => (
            <ShellNavLink key={item.to} item={item} collapsed={sidebarCollapsed} />
          ))}
        </nav>
        <nav className="app-nav-secondary" aria-label="Administration">
          <p className="app-nav-heading">Admin</p>
          {ADMIN_NAV_ITEMS.map((item) => (
            <ShellNavLink key={item.to} item={item} collapsed={sidebarCollapsed} />
          ))}
        </nav>
      </aside>
      <div className="app-content" ref={contentRef}>
        {mustChangePassword && !passwordBannerDismissed && (
          // Account-level, not page-level — belongs in the shell so it stays
          // visible no matter which screen the user navigates to, rather than
          // being forgotten the moment a second route exists. Actionable, not
          // just a static nag: the whole complaint this banner used to draw
          // was "there's no way to act on this" — the button opens the exact
          // same ChangePasswordModal the account area's own button does, no
          // second implementation of the form.
          <div className="banner banner-warning banner-with-action">
            <span>You should change your password.</span>
            <div className="banner-actions">
              <button type="button" className="banner-action" onClick={() => setChangePasswordOpen(true)}>
                Change password
              </button>
              <button
                type="button"
                className="banner-dismiss"
                aria-label="Dismiss password reminder"
                title="Dismiss for this session"
                onClick={() => setPasswordBannerDismissed(true)}
              >
                ×
              </button>
            </div>
          </div>
        )}
        <main className="app-main">{children}</main>
        {/* Lazy: the inspector pulls in the graph canvas and its layout
            engine, which most page loads never need. */}
        <Suspense fallback={null}>
          <ObjectInspectorHost />
          <CommandPaletteHost />
        </Suspense>
      </div>
      </div>
      {changePasswordOpen && <ChangePasswordModal onClose={() => setChangePasswordOpen(false)} />}
    </div>
  )
}
