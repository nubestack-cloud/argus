import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from 'react'
import { useDebouncedValue } from '../hooks/useDebouncedValue'
import { useQuery } from '@tanstack/react-query'
import { useLocation, useNavigate } from 'react-router-dom'
import { getClusters, getIncidents, searchObjects } from '../api/client'
import { CAP_CLUSTER_INSPECT, CAP_CLUSTER_READ, CAP_INCIDENT_READ } from '../api/capabilities'
import { missingCapabilityMessage } from '../api/capabilityInfo'
import { useAuth } from '../auth/useAuth'
import { useMissingCapabilities } from '../auth/useCapabilities'
import { Dialog } from '../components/Dialog'
import { withObjectPanel } from '../insight/panelUrl'
import { panelObject } from '../compare/compareUrl'
import { useOverlayOpen, useRegisterShortcuts } from '../keyboard/useShortcuts'
import { apiErrorText } from '../fleet/apiErrorText'
import {
  ALL_PAGE_CAPS,
  clusterEntries,
  compareEntry,
  incidentEntries,
  objectEntries,
  pageEntries,
  paletteResults,
  recentIncidents,
  type PaletteEntry,
} from './entries'

// The command palette (docs/CLUSTER_INSIGHT_SPECS.md CI-S18): Ctrl/⌘+K from
// anywhere, jump to a page, an incident, a cluster or an object found on any
// cluster. Pure navigation — no mutating action is reachable from here.
// Mounted once in AppShell; the open state is local (a palette is a
// transient tool, not a view worth linking to).

const SEARCH_DEBOUNCE_MS = 300

function Palette({ onClose }: { onClose: () => void }) {
  const { accessToken } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const listId = useId()
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  // Dialog focuses its first focusable control (the close button) in its own
  // effect; this parent effect runs after it and moves focus to the input.
  useEffect(() => {
    inputRef.current?.focus()
  }, [])
  const debounced = useDebouncedValue(query.trim(), SEARCH_DEBOUNCE_MS)

  const pagesCaps = useMissingCapabilities(ALL_PAGE_CAPS)
  const incidentCap = useMissingCapabilities([CAP_INCIDENT_READ])
  const clusterCap = useMissingCapabilities([CAP_CLUSTER_READ])
  const inspectCap = useMissingCapabilities([CAP_CLUSTER_INSPECT])
  const canIncidents = incidentCap.resolved && incidentCap.missing.length === 0
  const canClusters = clusterCap.resolved && clusterCap.missing.length === 0
  const canSearch = inspectCap.resolved && inspectCap.missing.length === 0

  // The same keys the incident and cluster lists use, so an open list's
  // cached answer is reused rather than fetched again.
  const incidentsQuery = useQuery({
    queryKey: ['incidents'],
    queryFn: () => getIncidents(accessToken!),
    enabled: !!accessToken && canIncidents,
  })
  const clustersQuery = useQuery({
    queryKey: ['clusters'],
    queryFn: () => getClusters(accessToken!),
    enabled: !!accessToken && canClusters,
  })
  // Debounced, and keyed on the query: a slower answer to an older query is
  // never shown over a newer one.
  const objectsQuery = useQuery({
    queryKey: ['palette-search', debounced],
    queryFn: () => searchObjects(debounced, accessToken!),
    enabled: !!accessToken && canSearch && debounced.length >= 2,
    staleTime: 30_000,
    retry: false,
  })

  const results = useMemo(() => {
    const incidents = incidentsQuery.data?.incidents ?? []
    return paletteResults(query, {
      pages: [
        ...pageEntries(pagesCaps.resolved ? new Set(pagesCaps.missing) : null),
        compareEntry(panelObject(location.search), inspectCap.resolved ? new Set(inspectCap.missing) : null),
      ],
      incidents: incidentEntries(incidents),
      recent: incidentEntries(recentIncidents(incidents)),
      clusters: clusterEntries(clustersQuery.data?.clusters ?? []),
      objects: debounced === query.trim() ? objectEntries((objectsQuery.data?.hits ?? []).slice(0, 10)) : [],
      canSearch,
    })
  }, [query, debounced, incidentsQuery.data, clustersQuery.data, objectsQuery.data, pagesCaps.resolved, pagesCaps.missing, canSearch, location.search, inspectCap.resolved, inspectCap.missing])

  const current = Math.min(active, Math.max(0, results.length - 1))

  const activate = (e: PaletteEntry | undefined) => {
    if (!e || e.disabledReason) return
    onClose()
    if (e.object) {
      navigate({ pathname: location.pathname, search: `?${withObjectPanel(new URLSearchParams(location.search), e.object)}` })
    } else if (e.to) {
      navigate(e.to)
    }
  }

  const onKeyDown = (e: ReactKeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setActive(Math.min(results.length - 1, current + 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setActive(Math.max(0, current - 1))
    } else if (e.key === 'Home') {
      e.preventDefault()
      setActive(0)
    } else if (e.key === 'End') {
      e.preventDefault()
      setActive(Math.max(0, results.length - 1))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      activate(results[current])
    }
  }

  useEffect(() => {
    document.getElementById(`${listId}-opt-${current}`)?.scrollIntoView?.({ block: 'nearest' })
  }, [current, listId])

  const searching = canSearch && query.trim().length >= 2 && (debounced !== query.trim() || objectsQuery.isFetching)

  return (
    <Dialog title="Go to…" onClose={onClose} className="palette-dialog">
      <input
        className="palette-input"
        type="text"
        role="combobox"
        aria-expanded="true"
        aria-controls={listId}
        aria-autocomplete="list"
        aria-activedescendant={results.length ? `${listId}-opt-${current}` : undefined}
        aria-label="Search pages, incidents, clusters and objects"
        placeholder="Page, incident, cluster or object name"
        ref={inputRef}
        value={query}
        onChange={(e) => {
          setQuery(e.target.value)
          setActive(0)
        }}
        onKeyDown={onKeyDown}
      />
      <ul id={listId} role="listbox" aria-label="Results" className="palette-list">
        {results.map((r, i) => {
          const header = i === 0 || results[i - 1].category !== r.category ? r.category : null
          return (
            <li key={r.id} role="presentation">
              {header && (
                <div className="palette-group-label" aria-hidden="true">
                  {header}
                </div>
              )}
              <div
                id={`${listId}-opt-${i}`}
                role="option"
                aria-selected={i === current}
                aria-disabled={r.disabledReason ? true : undefined}
                title={r.disabledReason}
                className="palette-option"
                onMouseMove={() => i !== current && setActive(i)}
                onClick={() => activate(r)}
              >
                <span className="palette-option-label">{r.label}</span>
                {(r.sublabel || r.disabledReason) && (
                  <span className="palette-option-sub">{r.disabledReason ?? r.sublabel}</span>
                )}
              </div>
            </li>
          )
        })}
      </ul>
      <div aria-live="polite">
        {results.length === 0 && query.trim() && !searching && <p className="palette-status">Nothing matches “{query.trim()}”.</p>}
        {searching && <p className="palette-status">Searching objects on every cluster…</p>}
        {objectsQuery.isError && <p className="palette-status">Object search failed: {apiErrorText(objectsQuery.error, 'no answer from the hub')}</p>}
        {objectsQuery.data && debounced === query.trim() && objectsQuery.data.clustersAnswered < objectsQuery.data.clustersQueried && (
          <p className="palette-status">
            {objectsQuery.data.clustersQueried - objectsQuery.data.clustersAnswered} of {objectsQuery.data.clustersQueried} clusters did not
            answer — object results may be incomplete.
          </p>
        )}
        {inspectCap.resolved && !canSearch && query.trim().length >= 2 && (
          <p className="palette-status">Objects are not searched: {missingCapabilityMessage(inspectCap.missing)}</p>
        )}
      </div>
      <p className="palette-footer">↑ ↓ to move · Enter to open · Esc to close</p>
    </Dialog>
  )
}

// Other UI (the header's search button) opens the palette by dispatching
// this window event, so it never needs to import the palette eagerly.
export const OPEN_PALETTE_EVENT = 'argus:open-palette'

export function CommandPaletteHost() {
  const [open, setOpen] = useState(false)
  useOverlayOpen(open)
  useEffect(() => {
    const onOpen = () => setOpen(true)
    window.addEventListener(OPEN_PALETTE_EVENT, onOpen)
    return () => window.removeEventListener(OPEN_PALETTE_EVENT, onOpen)
  }, [])
  useRegisterShortcuts([
    {
      id: 'palette',
      keys: 'Mod+k',
      scope: 'global',
      category: 'General',
      description: 'Open the command palette',
      allowInInputs: true,
      handler: () => setOpen((o) => !o),
    },
  ])
  if (!open) return null
  return <Palette onClose={() => setOpen(false)} />
}
