import { ApiError } from './client'

// The app-wide retry rule for TanStack Query (App.tsx's QueryClient).
//
// The library default retries every failure three times with exponential
// backoff — about 7s of waiting before an error is shown, and longer on a
// second query. That is right for a dropped connection or a hub restarting,
// and wrong for an answer: a 403 means the viewer lacks the capability and will
// still lack it in seven seconds, so a viewer opening Approvals sat on
// "Loading…" for 10–20s before being told they could not see it, and Settings
// asked for /admin/settings four times on every visit.
//
// So: a 4xx is final, shown at once — except 408 (the request timed out) and
// 429 (rate-limited), which are about timing rather than about the request. A
// network failure (ApiError status 0) and a 5xx keep the default three
// retries.
export const MAX_QUERY_RETRIES = 3

export function shouldRetryQuery(failureCount: number, error: unknown): boolean {
  if (failureCount >= MAX_QUERY_RETRIES) return false
  if (error instanceof ApiError && error.status >= 400 && error.status < 500) {
    return error.status === 408 || error.status === 429
  }
  return true
}
