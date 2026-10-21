// Command-palette ranking. Pure so the ordering a user sees for a query can be
// pinned in tests without rendering the dialog.

/** The fields of a palette entry that ranking reads. */
export interface ScoredEntry {
  label: string
  sublabel?: string
  category: string
  /** Extra terms matched during search but not displayed (a cluster's ID, a
   *  page's synonyms). */
  searchTerms?: readonly string[]
  /** Added to the final score only when the entry matched at all — nudges, for
   *  example, pages above objects on a tied match. */
  priorityBonus?: number
}

const WORD_BOUNDARIES = new Set([' ', '/', '-', '.'])

/**
 * Scores one string against the query, case-insensitively: exact 150, prefix
 * 100, a match starting at a word boundary (after space, `/`, `-` or `.`) 75,
 * any other substring 50, and 0 for no match. Within a tier a coverage bonus of
 * up to +20 (query length / text length) favours the shorter text.
 */
export function scoreMatch(text: string, query: string): number {
  const lower = text.toLowerCase()
  const q = query.toLowerCase()
  if (!q || !lower.includes(q)) return 0
  let base: number
  if (lower === q) base = 150
  else if (lower.startsWith(q)) base = 100
  else {
    const at = lower.indexOf(q)
    base = at > 0 && WORD_BOUNDARIES.has(lower[at - 1]) ? 75 : 50
  }
  return base + (q.length / lower.length) * 20
}

/**
 * The entry's score: the best of its label, 0.6 × the better of its sublabel
 * and category (floored), and each search term — plus its priority bonus when
 * anything matched. 0 means the entry does not match.
 */
export function bestScore(entry: ScoredEntry, query: string): number {
  let best = scoreMatch(entry.label, query)
  const secondary = Math.floor(
    Math.max(scoreMatch(entry.sublabel ?? '', query), scoreMatch(entry.category, query)) * 0.6,
  )
  best = Math.max(best, secondary)
  for (const term of entry.searchTerms ?? []) best = Math.max(best, scoreMatch(term, query))
  return best > 0 ? best + (entry.priorityBonus ?? 0) : 0
}

/**
 * Matching entries for a non-empty query, best first; ties keep input order
 * (Array.prototype.sort is stable). A blank query returns no ranking — what an
 * empty palette shows is the caller's decision, not a score.
 */
export function rankEntries<T extends ScoredEntry>(entries: readonly T[], query: string): T[] {
  const q = query.trim()
  if (!q) return []
  return entries
    .map(entry => ({ entry, score: bestScore(entry, q) }))
    .filter(x => x.score > 0)
    .sort((a, b) => b.score - a.score)
    .map(x => x.entry)
}
