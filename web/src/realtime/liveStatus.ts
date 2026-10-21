import { createContext, useContext } from 'react'

/**
 * Whether this tab's live event stream (/ws/events) is currently delivering.
 *
 * It became something the UI has to state when PROJECT.md P16 made the event
 * stream the primary refresh mechanism and slowed every page's poll to a
 * safety net (see realtime/refresh.ts). While the socket is up, a list header's
 * "Live" is as true as it ever was — truer, since an event lands in
 * milliseconds rather than at the next tick. While it is down, the screen is
 * refreshing once a minute instead of every five seconds, and saying "Live"
 * over that would be a freshness claim the page cannot back.
 *
 * 'unknown' is the value outside the provider — a component rendered in a unit
 * test, or anywhere useLiveEvents is not mounted. It means "this tab has no
 * opinion", and every consumer treats it as "say nothing about the stream"
 * rather than guessing either way.
 */
export type LiveStatus = 'unknown' | 'connecting' | 'live' | 'offline'

export const LiveStatusContext = createContext<LiveStatus>('unknown')

export function useLiveStatus(): LiveStatus {
  return useContext(LiveStatusContext)
}

/**
 * True only when the tab knows the stream is down. 'connecting' is deliberately
 * not degraded: it is the normal first second of a page load and of every
 * reconnect, and flashing a degradation notice through it would train operators
 * to ignore the one that matters.
 */
export function isLiveStreamDegraded(status: LiveStatus): boolean {
  return status === 'offline'
}
