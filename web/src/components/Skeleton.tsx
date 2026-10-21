// Reusable skeleton-loading primitives, shaped to match the eventual layout
// of the screen they stand in for — per lld/11-ui-design.md §7 ("skeleton
// screens matching the eventual layout... not a centered spinner"). Pages
// compose these instead of each hand-rolling their own gray bars, but each
// page still decides its own shape (a table page uses SkeletonTableRows
// inside its own real <table>/<thead>, a tile page uses SkeletonTiles,
// etc.) — there's deliberately no single generic "loading card" every page
// reaches for regardless of what it's replacing.

function SkeletonBlock({
  width,
  height = '0.95rem',
  className = '',
}: {
  width: string
  height?: string
  className?: string
}) {
  return <span className={`skeleton ${className}`.trim()} style={{ width, height }} />
}

// A handful of lines of decreasing width, like paragraph/field placeholders
// — used inside a .card wherever a page would otherwise render a few rows
// of "label: value" text once data arrives.
export function SkeletonLines({ count = 3, widths }: { count?: number; widths?: string[] }) {
  const items = Array.from({ length: count }, (_, i) => widths?.[i] ?? `${Math.max(70 - i * 14, 30)}%`)
  return (
    <div className="skeleton-lines">
      {items.map((width, i) => (
        <SkeletonBlock key={i} width={width} />
      ))}
    </div>
  )
}

// Rows for inside an already-rendered <table><thead>...</thead><tbody> —
// keeps the real column headers visible immediately (they don't depend on
// the data) and only the cell contents pulse, so the table's shape never
// jumps once the real rows replace these.
export function SkeletonTableRows({ columns, rows = 4 }: { columns: number; rows?: number }) {
  return (
    <>
      {Array.from({ length: rows }, (_, r) => (
        <tr key={r} aria-hidden="true">
          {Array.from({ length: columns }, (_, c) => (
            <td key={c}>
              <SkeletonBlock width={c === 0 ? '75%' : '55%'} />
            </td>
          ))}
        </tr>
      ))}
    </>
  )
}

// Matches the D7/D8 `.tile-grid` of `.card.metric-tile` elements (a small
// label above a big value) — OverviewPage and InsightsPage's real, loaded
// tiles. This used to render the pre-refresh `.stat-tile` shape (value
// first, then a badge-shaped label), which both of this component's actual
// callers stopped rendering once they moved onto `.metric-tile`: a loading
// flash in the wrong shape right before the real tile replaces it.
export function SkeletonTiles({ count = 3 }: { count?: number }) {
  return (
    <div className="tile-grid" aria-hidden="true">
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className="card metric-tile">
          <SkeletonBlock width="4.5rem" height="0.8rem" />
          <SkeletonBlock width="2.5rem" height="1.9rem" />
        </div>
      ))}
    </div>
  )
}

// Matches OverviewPage's solo donut-card (a ring plus a short legend list)
// for "Cluster health"/"Open incidents" — replaces the SkeletonTiles this
// loading state used before those two sections dropped their redundant
// per-category tile row in favor of the donut's own legend.
export function SkeletonDonutCard() {
  return (
    <div className="card donut-card donut-card-solo" aria-hidden="true">
      <div className="donut">
        <span className="skeleton skeleton-donut-ring" />
        <div className="skeleton-lines">
          <SkeletonBlock width="5rem" />
          <SkeletonBlock width="4rem" />
        </div>
      </div>
    </div>
  )
}

// Matches OverviewPage's .activity-list of .activity-list-item rows.
export function SkeletonActivityList({ count = 3 }: { count?: number }) {
  return (
    <ul className="activity-list" aria-hidden="true">
      {Array.from({ length: count }, (_, i) => (
        <li key={i} className="activity-list-item">
          <div className="activity-list-link">
            <SkeletonBlock width="3.5rem" height="1.3rem" />
            <SkeletonBlock width="9rem" />
            <SkeletonBlock width="4rem" className="skeleton-push-right" />
          </div>
        </li>
      ))}
    </ul>
  )
}

// A .card full of SkeletonLines — the shape of every page's top-of-detail
// "summary card" (ClusterDetailPage, IncidentDetailPage) before its data
// arrives.
export function SkeletonCard({ lines = 4 }: { lines?: number }) {
  return (
    <div className="card" aria-hidden="true">
      <SkeletonLines count={lines} />
    </div>
  )
}

// Matches RepositoryChangePanel's file editor: a path line above a tall
// monospace <textarea> holding a whole manifest.
//
// Its own shape rather than SkeletonLines because of §7's sharpest rule — a
// skeleton that omits the tallest element on the page guarantees the layout
// jump it exists to prevent. The editor is the tallest element in that panel by
// a wide margin (16rem minimum, inside a callout that is otherwise a few lines
// of prose), so a few short bars would stand in for the one thing whose arrival
// actually moves the page. The height matches `.repo-change-editor`'s own
// min-height.
export function SkeletonFileEditor() {
  return (
    <div className="repo-change-file" aria-hidden="true">
      <div className="repo-change-file-head">
        <SkeletonBlock width="18rem" />
      </div>
      <SkeletonBlock width="100%" height="16rem" />
    </div>
  )
}
