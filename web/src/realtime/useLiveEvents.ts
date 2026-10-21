import { useEffect, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { ApiError, createWSTicket, getIncident } from '../api/client'
import type { LiveEvent } from '../api/types'
import { useAuth } from '../auth/useAuth'
import type { LiveStatus } from './liveStatus'
import { createEventInvalidator } from './refresh'
import { createIncidentPatcher } from './incidentPatch'

// The frontend half of internal/api/ws.go's live-update surface
// (lld/11-ui-design.md §5): one shared connection per authenticated
// session (mounted once, at the App level — see App.tsx — not per page or
// per component), which invalidates the affected TanStack Query keys on
// every event instead of maintaining a second, parallel copy of server
// state.
//
// Polling on every page's own useQuery stays — a WS-hostile network/proxy,
// a hub restart that dropped an event mid-flight, or a second hub replica
// must all still get a working app. What changed with PROJECT.md P16 is
// which of the two is load-bearing: the event is now the refresh mechanism
// and the interval is the safety net underneath it (60-120s), rather than
// every page re-asking the database every five seconds and the socket being
// a nicety on top. realtime/refresh.ts holds that policy — which event
// refreshes which query key, and how slow each fallback is — in one place
// rather than spread across twenty-four call sites. See internal/events'
// own doc comment for the same reasoning from the Go side.

// 1s initial, doubling, capped at 30s, ±20% jitter — the exact shape
// lld/11-ui-design.md §5 asks for ("mirrors agent-protocol's jittered
// pattern"), matching internal/agent/client.go's jitter() function: a
// uniform random adjustment of up to 20% of the base duration, not a fixed
// fraction always subtracted or added.
const initialBackoffMs = 1000
const maxBackoffMs = 30000

function jitter(ms: number): number {
  const spread = ms * 0.2
  return ms - spread + Math.random() * (2 * spread)
}

// Mount once, near the top of the component tree, inside both
// QueryClientProvider and AuthProvider (see App.tsx). Returns the stream's
// current state for LiveStatusProvider to publish: with the poll slowed to a
// safety net, whether this socket is delivering is the difference between a
// header that may honestly say "Live" and one that must not.
export function useLiveEvents(): LiveStatus {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const [status, setStatus] = useState<LiveStatus>('connecting')

  // A ref, not state: reconnect bookkeeping that must never itself trigger a
  // re-render (a re-render here would tear down and rebuild the effect below,
  // restarting the very backoff sequence it's tracking).
  const backoffRef = useRef(initialBackoffMs)

  useEffect(() => {
    if (!accessToken) {
      return
    }
    // Per-effect-run local, deliberately NOT a ref. This flag has to answer
    // "was *my* run cancelled?", and a ref shared across runs cannot: it
    // holds one value for whoever wrote it last. That leaked a socket on
    // every token renewal (accessToken is in the dep list, and it rotates
    // roughly every 12 minutes). The sequence with a shared ref: cleanup sets
    // it true and calls socket.close(); the replacement effect immediately
    // sets it back to false; then the *old* socket's onclose finally fires,
    // reads false, concludes the connection dropped on its own, and
    // reconnects — producing a third, untracked socket with its own reconnect
    // timer that nothing will ever close. Each leaked socket independently
    // invalidates ['incidents']/['approvals']/['clusters'], so the refetch
    // rate multiplied with every renewal. StrictMode's double-mount hits the
    // same race immediately. Captured in this run's closure, the flag is
    // per-run by construction: the old socket's onclose reads the old run's
    // `cancelled`, which is (correctly, permanently) true.
    let cancelled = false
    backoffRef.current = initialBackoffMs
    let socket: WebSocket | null = null
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null
    // Per-run too, for the same reason `cancelled` is: its pending timers
    // belong to this socket's lifetime and must not outlive it.
    // CI-U8: IncidentUpdated patches the one incident into cached lists
    // rather than refetching them all (realtime/incidentPatch.ts).
    const token = accessToken
    const invalidator = createEventInvalidator(queryClient, {
      patchIncident: createIncidentPatcher(queryClient, (id) => getIncident(id, token)),
    })

    async function connect() {
      let ticket: string
      try {
        const res = await createWSTicket(accessToken!)
        ticket = res.ticket
      } catch (err) {
        // A 403 is a settled answer, not a transient failure, and is the one
        // error worth giving up on. POST /ws/ticket requires at least one of
        // incident:read / cluster:read (internal/api/server.go's
        // requireAnyCapability), so a user with neither will be refused every
        // single time — and that can only change with a new grant, which
        // needs a new session, which mints a new accessToken, which re-runs
        // this whole effect anyway. Retrying would mean a guaranteed 403
        // every ≤30s for as long as the tab stays open, for a user who by
        // definition has nothing to receive over the socket.
        if (err instanceof ApiError && err.status === 403) {
          // Not 'offline': there is nothing degraded to report to a user who
          // can receive no events in the first place, and a permanent banner
          // on every list header would be noise, not information.
          setStatus('unknown')
          return
        }
        // Everything else — login just expired, a 500, the hub briefly
        // unreachable — is transient. The fallback polling on every page is
        // still running underneath, so retry the ticket+connect sequence on
        // the same backoff rather than giving up.
        setStatus('offline')
        scheduleReconnect()
        return
      }
      if (cancelled) return

      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      socket = new WebSocket(`${proto}//${window.location.host}/ws/events?ticket=${encodeURIComponent(ticket)}`)

      socket.onopen = () => {
        backoffRef.current = initialBackoffMs
        setStatus('live')
      }
      socket.onmessage = (msg) => {
        try {
          const event = JSON.parse(msg.data) as LiveEvent
          invalidator.handle(event)
        } catch {
          // A malformed message is never treated as authoritative data in
          // the first place (see LiveEvent's own doc comment) — ignore it
          // rather than tearing down an otherwise-healthy connection.
        }
      }
      socket.onclose = () => {
        if (!cancelled) {
          setStatus('offline')
          scheduleReconnect()
        }
      }
      socket.onerror = () => {
        // onclose always follows onerror for a WebSocket — no separate
        // handling needed here beyond letting that fire.
      }
    }

    function scheduleReconnect() {
      if (cancelled) return
      const delay = jitter(backoffRef.current)
      backoffRef.current = Math.min(backoffRef.current * 2, maxBackoffMs)
      reconnectTimer = setTimeout(connect, delay)
    }

    connect()

    return () => {
      cancelled = true
      if (reconnectTimer) clearTimeout(reconnectTimer)
      invalidator.dispose()
      socket?.close()
    }
  }, [accessToken, queryClient])

  // Reported as 'unknown' rather than the last socket's state while there is
  // no session: the effect below does not run without a token, so `status`
  // would otherwise keep asserting whatever the previous session's socket was
  // doing. Derived here rather than written back into state from the effect —
  // a synchronous setState in an effect is a cascading render, and this is
  // exactly the case the lint rule is about.
  return accessToken ? status : 'unknown'
}
