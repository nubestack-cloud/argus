import { describe, expect, it } from 'vitest'
import { ApiError } from './client'
import { MAX_QUERY_RETRIES, shouldRetryQuery } from './queryRetry'

describe('shouldRetryQuery', () => {
  it('never retries a refusal: 401, 403, 404 and 409 are answers, not failures', () => {
    for (const status of [400, 401, 403, 404, 409, 422]) {
      expect(shouldRetryQuery(0, new ApiError('no', status, ''))).toBe(false)
    }
  })

  it('retries a network failure, a 5xx, a timeout and a rate limit, up to the cap', () => {
    for (const err of [
      new ApiError('Network error', 0, ''),
      new ApiError('Bad gateway', 502, ''),
      new ApiError('Timeout', 408, ''),
      new ApiError('Slow down', 429, ''),
      new TypeError('Failed to fetch'),
    ]) {
      expect(shouldRetryQuery(0, err)).toBe(true)
      expect(shouldRetryQuery(MAX_QUERY_RETRIES - 1, err)).toBe(true)
      expect(shouldRetryQuery(MAX_QUERY_RETRIES, err)).toBe(false)
    }
  })
})
