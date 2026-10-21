import { useSearchParamsWriter } from '../hooks/useUrlState'
import type { TablePaginationProps } from '../utils/pagination'

// utils/pagination.ts's usePagination with the page and page size in the URL
// (docs/CLUSTER_INSIGHT_SPECS.md CI-U5): ?page= and ?rows=, omitted at their
// defaults. Same contract otherwise — the page is clamped on render (a list
// that shrank under a parked page renders its last page, and the URL keeps
// the request until the data catches up, so a shared link to page 3 survives
// the first empty paint), and changing the page size returns to page 1.

export function pageWindow(total: number, page: number, rowsPerPage: number) {
  const totalPages = Math.max(1, Math.ceil(total / rowsPerPage))
  const currentPage = Math.min(Math.max(1, page), totalPages)
  const firstResult = total === 0 ? 0 : (currentPage - 1) * rowsPerPage + 1
  const lastResult = Math.min(currentPage * rowsPerPage, total)
  return { totalPages, currentPage, firstResult, lastResult }
}

function positive(raw: string | null, def: number): number {
  const n = Number.parseInt(raw ?? '', 10)
  return Number.isFinite(n) && n >= 1 ? n : def
}

export function useUrlPagination<T>(
  items: T[],
  defaultRowsPerPage = 25,
  keys: { page: string; rows: string } = { page: 'page', rows: 'rows' },
): { visibleItems: T[]; resetToFirstPage: () => void; pagination: TablePaginationProps } {
  const [params, write] = useSearchParamsWriter()
  const page = positive(params.get(keys.page), 1)
  const rowsPerPage = positive(params.get(keys.rows), defaultRowsPerPage)
  const { totalPages, currentPage, firstResult, lastResult } = pageWindow(items.length, page, rowsPerPage)
  const visibleItems = items.slice(firstResult ? firstResult - 1 : 0, lastResult)

  const setPage = (next: number) =>
    write((p) => {
      if (next <= 1) p.delete(keys.page)
      else p.set(keys.page, String(next))
    }, { push: true })

  return {
    visibleItems,
    resetToFirstPage: () => write((p) => p.delete(keys.page)),
    pagination: {
      totalItems: items.length,
      firstResult,
      lastResult,
      currentPage,
      totalPages,
      rowsPerPage,
      onPageChange: setPage,
      onRowsPerPageChange: (next: number) =>
        write((p) => {
          p.delete(keys.page)
          if (next === defaultRowsPerPage) p.delete(keys.rows)
          else p.set(keys.rows, String(next))
        }),
    },
  }
}
