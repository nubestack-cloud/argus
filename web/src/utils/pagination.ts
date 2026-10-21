import { useState } from 'react'

// Client-side paging for the tables whose whole list arrives in one response.
//
// Client-side for the endpoints that genuinely return their whole matching set:
// GET /api/v1/clusters takes filter parameters and nothing else — no limit, no
// offset, no cursor (internal/api/clusters.go) — so paging it is a view over an
// array already in memory and "page 4" costs no extra request.
//
// **GET /api/v1/incidents is NOT one of those, and this comment used to say it
// was.** It takes `?limit=` (defaulting to defaultIncidentPageLimit, clamped to
// maxIncidentPageLimit) and `?cursor=`, and it sets `nextCursor` on the response
// whenever a full page came back — internal/api/incidents.go:119-123 and :220.
// The wrong version of this paragraph was the stated justification for two real
// defects (BACKLOG D7c): a page that never read nextCursor and so rendered a
// literal 0 for a cluster whose incidents fell past the cap, and a footer
// claiming "of N" over a capped fetch. If you are paging incidents, pass the
// cursor and carry `truncated` — do not treat the first page as the set.
//
// The audit log is cursor-paged too, which is why it keeps a different footer:
// it cannot state a total or a page count, and it does not claim to.
//
// Extracted rather than copied a third time. ClustersPage and IncidentsPage
// already held character-identical copies of the arithmetic below, and
// ClusterDetailPage's incident list needed the same treatment (BUGS.md 57).
// Three copies would mean re-deriving, correctly and identically each time,
// the slice's off-by-one, the clamp that keeps a shrinking result set from
// stranding the view past the end, and the "any filter change returns to page
// 1" contract — none of which is visible as wrong until someone is on page 6
// of a list that just became three pages long.

// The default page size every table here shipped with. Kept as the parameter's
// default rather than inlined at three call sites so "how many rows is a page"
// has one answer.
const DEFAULT_ROWS_PER_PAGE = 25

// TablePaginationProps is exactly what the footer renders, plus the two
// handlers it needs. Derived values (not raw state) on purpose: `currentPage`
// is the clamped page actually on screen, and the footer must never step from
// a raw page number the view is not showing — see TablePagination.
export type TablePaginationProps = {
  totalItems: number
  firstResult: number
  lastResult: number
  currentPage: number
  totalPages: number
  rowsPerPage: number
  onPageChange: (page: number) => void
  onRowsPerPageChange: (rowsPerPage: number) => void
  // truncated says the SERVER had more rows than it returned (BACKLOG P9), so
  // totalItems is a floor rather than a total and the footer renders "of N+".
  // Optional: the two lists whose data is genuinely complete pass nothing.
  truncated?: boolean
}

// usePagination turns a fully-loaded, already-filtered, already-sorted list
// into the slice to render plus the footer's props.
//
// `resetToFirstPage` is returned separately because it belongs to the caller's
// controls, not to the footer: every search box, filter <select>, quick-view
// button and sortable header has to call it, or narrowing a list while parked
// on page 5 shows an empty table until the clamp catches up on the next render.
//
// The rows-per-page handler resets the page itself, since page 4 at 10 rows is
// not page 4 at 50 and no caller has ever wanted it to be.
export function usePagination<T>(
  items: T[],
  initialRowsPerPage: number = DEFAULT_ROWS_PER_PAGE,
): { visibleItems: T[]; resetToFirstPage: () => void; pagination: TablePaginationProps } {
  const [page, setPage] = useState(1)
  const [rowsPerPage, setRowsPerPage] = useState(initialRowsPerPage)

  const totalPages = Math.max(1, Math.ceil(items.length / rowsPerPage))
  // Clamped rather than corrected in an effect: these lists refetch whenever
  // the hub publishes an event touching them (realtime/refresh.ts), so the
  // result set shrinking under a parked page number is routine here, and
  // clamping renders the right thing on that same paint instead of one frame
  // later.
  const currentPage = Math.min(page, totalPages)
  const firstResult = items.length === 0 ? 0 : (currentPage - 1) * rowsPerPage + 1
  const lastResult = Math.min(currentPage * rowsPerPage, items.length)
  // firstResult is 1-based for display and 0 means "no results at all", so the
  // slice start has to fall back to 0 rather than pass -1.
  const visibleItems = items.slice(firstResult ? firstResult - 1 : 0, lastResult)

  return {
    visibleItems,
    resetToFirstPage: () => setPage(1),
    pagination: {
      totalItems: items.length,
      firstResult,
      lastResult,
      currentPage,
      totalPages,
      rowsPerPage,
      onPageChange: setPage,
      onRowsPerPageChange: (nextRowsPerPage: number) => {
        setRowsPerPage(nextRowsPerPage)
        setPage(1)
      },
    },
  }
}
