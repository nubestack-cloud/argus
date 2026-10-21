import { ApiError } from '../api/client'

/** The RFC 9457 title and detail when the hub sent them; `fallback` otherwise. */
export function apiErrorText(err: unknown, fallback: string): string {
  if (err instanceof ApiError) return err.detail ? `${err.message} — ${err.detail}` : err.message
  return fallback
}
