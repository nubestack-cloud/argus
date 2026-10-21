// A small, hand-rolled inline-SVG icon set — no icon-font/npm dependency,
// matching the stroke convention AppShell.tsx's shield logo and sun/moon
// theme toggle already established (viewBox 0 0 24 24, stroke="currentColor",
// fill="none", round caps/joins). Two families live here:
//
//  - Nav icons (one per NAV_ITEMS entry) + a couple of action-button icons,
//    sized for inline use next to text (default 16px).
//  - Empty-state illustrations (EmptyIllustration below), a larger (56px)
//    "glyph inside a rounded frame" motif reused across every page's
//    zero-data state, so a brand-new install's first screens read as one
//    consistent design language rather than one-off art per page.
//
// Every icon is aria-hidden — each is always paired with visible text (a
// nav label, a button label, or the empty-state's own copy), so it's
// decorative, not the only carrier of meaning.

import type { CSSProperties, ReactNode } from 'react'

type IconProps = { size?: number; className?: string }

export function ArgusLogoMark({ size = 24, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      fill="none"
      className={className}
      aria-hidden="true"
    >
      {/* THE APERTURE (identity study, direction A1). An iris diaphragm whose
          blades retract toward the centre when they sleep — never all of them,
          which is the one detail of the Argus Panoptes myth worth keeping: he
          never closed more than half his eyes at once, so partial closure was
          his resting state rather than a fault. A monitoring system, described
          three thousand years early.

          ALL TWELVE BLADES ARE IDENTICAL HERE, and the shape of this markup is
          what makes that possible. Each blade is a full-length rect inside its
          own `<g transform="rotate(...)">`, rather than a rect carrying its own
          rotate. The reason is that CSS `transform` REPLACES an SVG transform
          attribute, so a rect that positions itself by rotating cannot then be
          animated or shortened by CSS without losing its position. With the
          rotation on a wrapper, the rect's own transform is free — so the same
          nine-awake/three-asleep look, and the rotating vigil on the login
          screen, are both CSS over one geometry instead of two hand-drawn
          variants that can drift apart.

          `.argus-blade-rest` marks the three that sleep at rest. index.css
          retracts them (scaleY about the INNER end, which is why the origin is
          y=23 and not the outer tip) and dims them. On the login screen the same
          rule set animates all twelve on a rotating schedule so exactly three
          are asleep at any moment — see `.auth-brand-mark` there.

          One colour, via `currentColor`: the caller decides. This replaced a
          rounded-square badge holding an illustrated eye, iris, pupil, glint and
          three coloured dots — eleven shapes, two gradients, five literals, and
          a rect that had to be forced white in dark mode because a near-black
          badge vanished on a near-black ground. A single-colour mark cannot
          vanish that way, so that whole exception is gone.

          Geometry, on a 64 grid about (32,32): blade 3.4 wide spanning radius 9
          to 26, twelve positions at 30 degrees, pupil r5.6. */}
      <g fill="currentColor">
        {[0, 30, 60, 90, 120, 150, 180, 210, 240, 270, 300, 330].map((deg) => {
          // Which of the four sleep phases this blade belongs to. The twelve
          // blades divide into four groups of three, and each group's members
          // sit 120 degrees apart — {0,120,240}, {30,150,270}, {60,180,300},
          // {90,210,330} — so whichever group is asleep, the closed blades are
          // always spread evenly around the iris instead of bunched into one
          // dark wedge. Phase 0 is {90,210,330}: the three that are asleep in
          // the still mark, and therefore also the state the login screen's
          // animation starts from, so nothing jumps on first paint.
          const phase = ((deg / 30) % 4 + 1) % 4
          return (
            <g key={deg} transform={`rotate(${deg} 32 32)`}>
              <rect
                className={phase === 0 ? 'argus-blade argus-blade-rest' : 'argus-blade'}
                style={{ '--argus-blade-phase': phase } as CSSProperties}
                x="30.3"
                y="6"
                width="3.4"
                height="17"
                rx="1.7"
              />
            </g>
          )
        })}
        <circle cx="32" cy="32" r="5.6" />
      </g>
    </svg>
  )
}

function svg(size: number, className: string | undefined, children: ReactNode) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      {children}
    </svg>
  )
}

export function OverviewIcon({ size = 16, className }: IconProps) {
  return svg(
    size,
    className,
    <>
      <rect x="3" y="3" width="7.5" height="7.5" rx="1.4" />
      <rect x="13.5" y="3" width="7.5" height="7.5" rx="1.4" />
      <rect x="3" y="13.5" width="7.5" height="7.5" rx="1.4" />
      <rect x="13.5" y="13.5" width="7.5" height="7.5" rx="1.4" />
    </>,
  )
}

// Three stacked chevron "layers" — a fleet of clusters rather than one.
export function ClustersIcon({ size = 16, className }: IconProps) {
  return svg(
    size,
    className,
    <>
      <path d="M12 2.5 2.5 7.5 12 12.5l9.5-5Z" />
      <path d="M2.5 12.5 12 17.5l9.5-5" />
      <path d="M2.5 17 12 22l9.5-5" />
    </>,
  )
}

export function IncidentsIcon({ size = 16, className }: IconProps) {
  return svg(
    size,
    className,
    <>
      <path d="M12 3 2.5 20h19Z" />
      <path d="M12 9.5v4.5" />
      <circle cx="12" cy="17" r="0.75" fill="currentColor" stroke="none" />
    </>,
  )
}

// Nav icon for /insights (InsightsPage.tsx) — a simple bar chart, distinct
// from every other nav glyph's silhouette (shield/cluster-stack/triangle/
// person/scroll) at a glance.
export function InsightsIcon({ size = 16, className }: IconProps) {
  return svg(
    size,
    className,
    <>
      <path d="M4 20V10" />
      <path d="M11 20V4" />
      <path d="M18 20v-7" />
      <path d="M3 20h18" />
    </>,
  )
}

export function ApprovalsIcon({ size = 16, className }: IconProps) {
  return svg(
    size,
    className,
    <>
      <rect x="3" y="4" width="18" height="17" rx="2" />
      <path d="M8 2v4M16 2v4M3 10h18" />
      <path d="m8 15 2.2 2.2L15.5 12.5" />
    </>,
  )
}

export function UsersIcon({ size = 16, className }: IconProps) {
  return svg(
    size,
    className,
    <>
      <circle cx="9.5" cy="8" r="3.2" />
      <path d="M3.5 20c0-3.6 2.7-6.2 6-6.2s6 2.6 6 6.2" />
      <path d="M16 9.2c1.3-.2 2.3-1.3 2.3-2.7A2.7 2.7 0 0 0 16 3.8" />
      <path d="M19 14c1.9.5 3.3 2.2 3.5 4.6" />
    </>,
  )
}

export function AuditLogIcon({ size = 16, className }: IconProps) {
  return svg(
    size,
    className,
    <>
      <path d="M6.5 3h8l3 3v15h-11Z" />
      <path d="M9 9.5h6M9 13h6M9 16.5h3.5" />
    </>,
  )
}

// A counter-clockwise arrow around a clock — "what changed, and can it be put
// back". Deliberately distinct from AuditLogIcon's document: the audit log is a
// record of every request, this is the list of mutations with an undo attached.
export function RecentChangesIcon({ size = 16, className }: IconProps) {
  return svg(
    size,
    className,
    <>
      <path d="M3.5 12a8.5 8.5 0 1 0 2.6-6.1" />
      <path d="M3.2 4.2v4.3h4.3" />
      <path d="M12 7.8V12l2.8 1.8" />
    </>,
  )
}

// A "sliders" glyph rather than a sun-ray cog — the theme toggle already
// owns the sun/ray silhouette a classic gear would visually echo.
export function SettingsIcon({ size = 16, className }: IconProps) {
  return svg(
    size,
    className,
    <>
      <line x1="4" y1="6" x2="20" y2="6" />
      <circle cx="9.5" cy="6" r="1.9" />
      <line x1="4" y1="12" x2="20" y2="12" />
      <circle cx="15" cy="12" r="1.9" />
      <line x1="4" y1="18" x2="20" y2="18" />
      <circle cx="7.5" cy="18" r="1.9" />
    </>,
  )
}

export function PlusIcon({ size = 16, className }: IconProps) {
  return svg(
    size,
    className,
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 8v8M8 12h8" />
    </>,
  )
}

export function UserPlusIcon({ size = 16, className }: IconProps) {
  return svg(
    size,
    className,
    <>
      <circle cx="9.5" cy="8.5" r="3.2" />
      <path d="M3.5 20c0-3.6 2.7-6.2 6-6.2 1.3 0 2.5.4 3.5 1.1" />
      <path d="M18.5 8v4.5M16.3 10.2h4.5" />
    </>,
  )
}

export function SaveIcon({ size = 16, className }: IconProps) {
  return svg(
    size,
    className,
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="m8 12.3 2.6 2.6L16.2 9.3" />
    </>,
  )
}

export function FilterIcon({ size = 16, className }: IconProps) {
  return svg(
    size,
    className,
    <path d="M4 5h16l-6 7.5V19l-4 2v-8.5Z" />,
  )
}

export function SearchIcon({ size = 16, className }: IconProps) {
  return svg(
    size,
    className,
    <>
      <circle cx="10.5" cy="10.5" r="5.5" />
      <path d="m15 15 4 4" />
    </>,
  )
}

export function SortIcon({ size = 12, className, direction }: IconProps & { direction?: 'asc' | 'desc' }) {
  return (
    <svg
      width={size}
      height={Math.round(size * 1.2)}
      viewBox="0 0 12 14"
      fill="currentColor"
      className={className}
      aria-hidden="true"
    >
      <path d="M6 1 10 5H2Z" opacity={direction === 'desc' ? 0.28 : 1} />
      <path d="m6 13-4-4h8Z" opacity={direction === 'asc' ? 0.28 : 1} />
    </svg>
  )
}

export function ChevronIcon({
  size = 16,
  className,
  direction,
}: IconProps & { direction: 'left' | 'right' | 'up' | 'down' }) {
  // 'down' is the disclosure caret on a labelled ActionMenu trigger; 'up' is
  // its mirror, added for the reorder controls on Settings → Notification
  // routing, where moving a rule earlier and later are the same affordance
  // pointed opposite ways. Same glyph rotated, rather than a second icon: two
  // separately-drawn chevrons drift.
  const d =
    direction === 'left'
      ? 'm14 5-7 7 7 7'
      : direction === 'down'
        ? 'm5 10 7 7 7-7'
        : direction === 'up'
          ? 'm5 14 7-7 7 7'
          : 'm10 5 7 7-7 7'
  return svg(size, className, <path d={d} />)
}

// The trigger glyph for HelpTip (components/HelpTip.tsx) — a plain
// info-circle, distinct from every action-button icon above so it never
// reads as "clickable in the same way a button is."
export function InfoIcon({ size = 14, className }: IconProps) {
  return svg(
    size,
    className,
    <>
      <circle cx="12" cy="12" r="9" />
      <line x1="12" y1="11" x2="12" y2="16.5" />
      <circle cx="12" cy="7.5" r="0.9" fill="currentColor" stroke="none" />
    </>,
  )
}

// The trigger glyph for a row's "Quick view" button (IncidentsPage/
// ClustersPage) — a plain eye, distinct from InfoIcon (which marks
// hover/focus explanatory text, not an action) and from FilterIcon/PlusIcon
// (which mutate something); this one only ever opens a read-only preview.
export function EyeIcon({ size = 16, className }: IconProps) {
  return svg(
    size,
    className,
    <>
      <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z" />
      <circle cx="12" cy="12" r="3" />
    </>,
  )
}

// The trigger glyph for ActionMenu (components/ActionMenu.tsx) — three
// vertical dots, the standard "more actions" affordance, replacing what
// used to be a row of separate always-visible buttons per row (a real,
// user-reported clutter complaint — bugs-and-fixes.txt item 24).
// The app shell's sidebar toggle. Three lines, on the 24 viewBox and
// stroke="currentColor" like every other member of this set — deliberately the
// plain hamburger rather than a "clever" morphing glyph: it is the single most
// conventional control in any web app, and the whole value of using the
// convention is that nobody has to learn it.
export function MenuIcon({ size = 20, className }: IconProps) {
  return svg(size, className, <path d="M4 7h16M4 12h16M4 17h16" />)
}

export function MoreIcon({ size = 16, className }: IconProps) {
  return svg(
    size,
    className,
    <>
      <circle cx="12" cy="5" r="1.6" fill="currentColor" stroke="none" />
      <circle cx="12" cy="12" r="1.6" fill="currentColor" stroke="none" />
      <circle cx="12" cy="19" r="1.6" fill="currentColor" stroke="none" />
    </>,
  )
}

// Nav icon for /tolerations (TolerationsPage.tsx) — a bell with a slash
// through it, the standard "muted/silenced" glyph, distinct from the plain
// triangle used for Incidents.
export function TolerationsIcon({ size = 16, className }: IconProps) {
  return svg(
    size,
    className,
    <>
      <path d="M18 8a6 6 0 0 0-9.5-4.9" />
      <path d="M6 8a6 6 0 0 0-1 3.4V14l-2 2.5h11" />
      <path d="M13.5 20a1.7 1.7 0 0 1-3 0" />
      <path d="M3 3l18 18" />
    </>,
  )
}

// ==========================================================================
// Empty-state illustrations — a shared "glyph inside a rounded frame" motif
// (see .empty-illustration-frame in index.css) so Clusters/Incidents/Users/
// Audit Log's first-run "nothing here yet" screens read as one deliberate
// design rather than each page improvising its own art. Purely decorative
// (aria-hidden); the existing copy next to each one still carries the
// meaning.
export type EmptyIllustrationVariant = 'clusters' | 'incidents' | 'users' | 'audit' | 'insights'

const EMPTY_GLYPHS: Record<EmptyIllustrationVariant, ReactNode> = {
  clusters: (
    <>
      <path d="M28 16 16 21.5 28 27l12-5.5Z" />
      <path d="M16 27l12 5.5L40 27" />
      <path d="M16 32.5 28 38l12-5.5" />
    </>
  ),
  // A calm shield-check rather than an alert triangle — zero incidents is
  // the good outcome, not a gap in the data.
  incidents: (
    <>
      <path d="M28 14 18 18v8c0 6.5 4.4 10.8 10 13.5 5.6-2.7 10-7 10-13.5v-8Z" />
      <path d="m23.5 27 3.3 3.3L33 22.8" />
    </>
  ),
  users: (
    <>
      <circle cx="23" cy="23" r="4.5" />
      <path d="M14.5 39c0-5 3.8-8.7 8.5-8.7s8.5 3.7 8.5 8.7" />
      <circle cx="35" cy="21" r="3.4" />
      <path d="M31.8 30.6c3.4.6 6 3.6 6.3 8" />
    </>
  ),
  audit: (
    <>
      <path d="M20 13h13l5 5v21H20Z" />
      <path d="M24.5 22h9M24.5 27.5h9M24.5 33h5.5" />
    </>
  ),
  // A small rising bar chart — matches InsightsIcon's shape/meaning above,
  // scaled up to this motif's 56x56 frame.
  insights: (
    <>
      <path d="M18 37V27" />
      <path d="M28 37V19" />
      <path d="M38 37V24" />
      <path d="M16 37h24" />
    </>
  ),
}

export function EmptyIllustration({ variant }: { variant: EmptyIllustrationVariant }) {
  return (
    <svg
      width="56"
      height="56"
      viewBox="0 0 56 56"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      className="empty-illustration"
      aria-hidden="true"
    >
      <rect x="1.5" y="1.5" width="53" height="53" rx="14" className="empty-illustration-frame" />
      {EMPTY_GLYPHS[variant]}
    </svg>
  )
}

// The glyph on a `.verification-chip`. 12px on a 16 viewBox — the D7 chip
// marks from `.design/Components.dc.html`'s verification-chip row, a different
// set from the 24-viewBox nav/action icons above, kept in this file so the two
// callers that need one (ClusterDetailPage's capability chips,
// RepositoryChangePanel's re-verification state) share a glyph instead of
// drawing two.
//
// stroke="currentColor" is mandatory for anything inside a
// `.verification-chip`: the neutral variant recolours by setting `color`, so a
// hardcoded stroke would leave a "not verified" chip wearing a green tick.
export function ChipMark({ mark }: { mark: 'granted' | 'denied' | 'unanswered' }) {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth={mark === 'granted' ? 2.2 : 2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {mark === 'granted' ? (
        <path d="M3 8.5l3.2 3.2L13 5" />
      ) : (
        <>
          <circle cx="8" cy="8" r="6.5" />
          {mark === 'denied' ? <path d="M5 8h6" /> : <path d="M8 4.5v4M8 11h.01" />}
        </>
      )}
    </svg>
  )
}
