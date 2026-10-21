// The app-wide navigation bindings and the page-filter lookup, shared by
// GlobalShortcuts and its tests (docs/CLUSTER_INSIGHT_SPECS.md CI-S18).

export const GO_TO: { keys: string; to: string; label: string }[] = [
  { keys: 'g o', to: '/overview', label: 'Overview' },
  { keys: 'g i', to: '/incidents', label: 'Incidents' },
  { keys: 'g s', to: '/signals', label: 'Signals' },
  { keys: 'g a', to: '/approvals', label: 'Approvals' },
  { keys: 'g c', to: '/clusters', label: 'Clusters' },
  { keys: 'g h', to: '/changes', label: 'Recent changes' },
]

/** The page's filter: an element marked data-page-filter, else the first
 *  field of the page's filter bar or list search. */
export function findPageFilter(root: ParentNode = document): HTMLElement | null {
  return (
    root.querySelector<HTMLElement>('[data-page-filter]:not([disabled])') ??
    root.querySelector<HTMLElement>(
      '.app-main .list-search-field input:not([disabled]), .app-main .filter-bar input:not([disabled]), .app-main .filter-bar select:not([disabled])',
    )
  )
}
