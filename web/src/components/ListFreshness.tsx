import { isLiveStreamDegraded, useLiveStatus } from '../realtime/liveStatus'
import { formatRelativeTime } from '../utils/time'

/**
 * ListFreshness is the one place a list header says how current its data is.
 *
 * It exists because the same three-part claim — a live dot, a count, and the
 * word "Live" — was hand-written on Overview, Incidents and Clusters, and all
 * three made it unconditionally. With the backend down, every one of them
 * asserted "Live" beside a count of `0` that came from an empty array rather
 * than from the fleet: a fabricated zero next to a fabricated freshness claim,
 * on the screens an operator reaches for first. An external review caught it on
 * Overview; the other two were the same defect waiting to be found.
 *
 * Two rules, both enforced here rather than left to each caller:
 *
 *  1. "Live" is a claim about the last fetch, so it may only be made when the
 *     last fetch succeeded. In error it reads "Not updating", the dot is
 *     dropped (a green dot IS the claim, for anyone who reads the colour before
 *     the word), and the timestamp reframes to "last updated" — the data on
 *     screen is still real, it is simply older than it looks.
 *  2. A count the query does not have is rendered as an em dash, never `0`.
 *     `0 incidents` and `— incidents` mean opposite things, and only one of
 *     them is honest when the fetch failed — or before it has answered at
 *     all: the first load used to read "0 incidents · Updating…", a zero
 *     taken from the empty array a page defaults to while it waits.
 *
 *  3. "Live" also depends on the live event stream, since PROJECT.md P16 made
 *     that stream the refresh mechanism and the poll underneath it a 60-120s
 *     safety net (realtime/refresh.ts). With the socket up, a change reaches
 *     this list in a round trip and "Live" is truer than it ever was on a 5s
 *     tick. With it down — a WS-hostile proxy, a hub restart — the list is
 *     refreshing once a minute, and saying "Live" over that is a freshness
 *     claim the page cannot back. It says "Polling" instead, and drops the
 *     dot, exactly as it does in error: a green dot IS the claim for anyone
 *     who reads the colour before the word. The data on screen is still real
 *     either way, which is why this is a different word and not an error.
 *
 * `countLabel` is passed already-pluralised rather than assembled here: callers
 * differ (one appends a truncation marker to the number itself), and splitting
 * a noun from its number across a component boundary is how "1 incidents"
 * happens.
 */
export function ListFreshness({
  isError,
  isFetching,
  updatedAt,
  count,
  countLabel,
  countSuffix,
  hasData = updatedAt > 0,
}: {
  isError: boolean
  isFetching: boolean
  /** TanStack's `dataUpdatedAt`: 0 when the query has never succeeded. */
  updatedAt: number
  /** Undefined means "not applicable to this header" — the count is skipped entirely. */
  count?: number
  /** The noun, already matched to `count` ("incident" / "incidents"). */
  countLabel?: string
  /** Rendered inside the count span, e.g. the truncation `+` marker. */
  countSuffix?: React.ReactNode
  /**
   * Whether `count` was computed from data the query actually returned — pass
   * `query.data !== undefined`. Kept data shown while a filter change refetches
   * (placeholderData) counts as data; the empty array a page falls back to
   * before the first answer does not. Defaults to "has ever succeeded".
   */
  hasData?: boolean
}) {
  const hasCount = count !== undefined && countLabel !== undefined
  // 'unknown' (no provider — a unit test, or any tree without useLiveEvents)
  // is not degraded: a component with no opinion about the stream says
  // nothing about it rather than guessing either way.
  const streamDown = isLiveStreamDegraded(useLiveStatus())
  return (
    <p className="list-live-status" aria-live="polite">
      {!isError && !streamDown && <span className="list-live-dot" aria-hidden="true" />}
      {hasCount && (
        <>
          <span>
            {isError ? (
              <span title="This count is unknown: the last request for it failed">—</span>
            ) : !hasData ? (
              <span title="Loading — the count appears when the first answer arrives">—</span>
            ) : (
              <>
                {count} {countLabel}
                {countSuffix}
              </>
            )}
            {isError || !hasData ? ` ${countLabel}` : null}
          </span>
          <span aria-hidden="true">·</span>
        </>
      )}
      <span
        title={
          streamDown && !isError && !isFetching
            ? 'Live updates are disconnected — this list is refreshing on a timer instead, so it can be up to a minute behind'
            : undefined
        }
      >
        {isError ? 'Not updating' : isFetching ? 'Updating…' : streamDown ? 'Polling' : 'Live'}
      </span>
      {updatedAt > 0 && (
        <span className="list-last-updated">
          {isError ? 'Last updated' : 'Updated'} {formatRelativeTime(new Date(updatedAt).toISOString())}
        </span>
      )}
      {isError && updatedAt === 0 && <span className="list-last-updated">Never loaded</span>}
    </p>
  )
}
