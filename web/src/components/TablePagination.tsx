import { ChevronIcon } from './icons'
import type { TablePaginationProps } from '../utils/pagination'

// The footer under every fully-loaded list table in this app: how much of the
// result set is on screen, how big a page is, which page this is, and the two
// steppers. Styled by `.list-pagination` / `.list-page-buttons`, sitting on the
// bottom edge of a `.list-card`.
//
// Those class names used to be `.clusters-*` — carried over verbatim from the
// copies ClustersPage and IncidentsPage each held before this component existed.
// That was the ROOT CAUSE of a nine-page problem, not a cosmetic one (BACKLOG
// D7a): because the shared footer hardcoded one page's namespace, every other
// page that wanted it had to adopt `.clusters-list-card` and `.clusters-table`
// to match — so Audit, Users, Insights, Tolerations, Approvals, Settings and
// ClusterDetail all ended up rendering a neighbour's page-scoped classes, two of
// which set `max-width`. Renaming here is what let the other eight stop.
//
// The page-size choices live here rather than at each call site so the three
// tables cannot end up offering different ones.
const ROWS_PER_PAGE_CHOICES = [10, 25, 50]

export function TablePagination({
  totalItems,
  firstResult,
  lastResult,
  currentPage,
  totalPages,
  rowsPerPage,
  onPageChange,
  onRowsPerPageChange,
  truncated = false,
}: TablePaginationProps) {
  // An empty table has nothing to page through: "Showing 0–0 of 0" with
  // page controls under it said the same as the empty state above it, in a
  // way that reads like a broken counter. The table's own empty state says
  // why there are no rows.
  if (totalItems === 0 && !truncated) return null
  return (
    <footer className="list-pagination">
      <span>
        Showing {firstResult}–{lastResult} of {totalItems}
        {/* "of 500+" rather than "of 500" when the server said there is more.
            The old copy claimed a total it did not have, which is the specific
            thing BACKLOG P9 warned about: showing "of 10" while meaning "of 10 so
            far". `.figure-partial` (BACKLOG D7h) carries this always-visible,
            not only in a hover title — this footer never had one at all. */}
        {truncated && (
          <span className="figure-partial" aria-label="or more, this list was truncated">
            +
          </span>
        )}
      </span>
      <label>
        <span>Rows per page</span>
        <select
          value={rowsPerPage}
          onChange={(event) => onRowsPerPageChange(Number(event.target.value))}
        >
          {ROWS_PER_PAGE_CHOICES.map((choice) => (
            <option key={choice} value={choice}>{choice}</option>
          ))}
        </select>
      </label>
      <span>Page {currentPage} of {totalPages}</span>
      <div className="list-page-buttons">
        <button
          type="button"
          className="secondary"
          aria-label="Previous page"
          disabled={currentPage <= 1}
          // Stepped from currentPage (the clamped value actually on screen),
          // never from the raw page number in state. That number can sit above
          // totalPages after the result set shrinks — a live refetch drops a
          // row, or a filter narrows — and stepping the raw value from 7 to 6
          // while the view is clamped to 3 changed nothing visible, so the
          // first click (and the several after it) read as a dead button. Every
          // list here refetches every five seconds, so that is the ordinary
          // case, not an edge one. This is the bug the copies of this footer
          // each had to be fixed for separately; UsersPage's own, differently
          // shaped footer steps from the clamped value for the same reason.
          onClick={() => onPageChange(currentPage - 1)}
        >
          <ChevronIcon direction="left" />
        </button>
        <button
          type="button"
          className="secondary"
          aria-label="Next page"
          disabled={currentPage >= totalPages}
          onClick={() => onPageChange(currentPage + 1)}
        >
          <ChevronIcon direction="right" />
        </button>
      </div>
    </footer>
  )
}
