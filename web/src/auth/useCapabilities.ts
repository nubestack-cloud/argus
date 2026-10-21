import { useQuery } from '@tanstack/react-query'
import { getEffectivePermissions } from '../api/client'
import { useAuth } from './useAuth'

// lld/11-ui-design.md §6's rule: fetch effective permissions once per view
// (not persisted beyond it, re-fetched on navigation/re-mount — there's no
// ScopeNarrowed push event to invalidate on yet, since no WebSocket exists
// in this codebase). TanStack Query's default cache (no explicit staleTime
// override) already gives "fetch once, share across everything mounted on
// this page, refetch on next navigation that remounts the hook" for free.
function useEffectivePermissions() {
  const { accessToken, userId, identityStatus } = useAuth()
  return useQuery({
    // The identity is part of the key, not decoration: this is the one query
    // whose answer decides whether controls render enabled, so a cache hit
    // belonging to a *different* user is the worst possible miss. AuthContext
    // already clears the whole cache when a session ends, which is the real
    // fix for that (see clearSession); keying by identity makes a cross-user
    // hit structurally impossible rather than merely prevented, which matters
    // because the QueryClient is a module-level singleton shared by every
    // session in the tab. It costs nothing in refetches — the identity is
    // stable for a session's whole life, unlike accessToken, which rotates
    // every ~12 minutes and would therefore be wrong to key on.
    //
    // The key is the user ID rather than the email, and the query does not run
    // until the identity is 'ready' (PROJECT.md B165). Both halves matter:
    //
    //   - A user ID is assigned by this hub and never changes; an email is a
    //     display attribute an identity provider can reassign on any login
    //     (provisionFederatedUser re-syncs it every time, and matches on
    //     issuer/subject specifically BECAUSE email is not stable).
    //   - Running while the identity is still unknown would key an entry under
    //     `undefined` — and the next session to pass through that same
    //     unknown-identity moment would hit it, which is precisely the
    //     cross-user cache hit this key exists to prevent. Waiting costs a few
    //     milliseconds of controls rendering deny-by-default, which is the
    //     documented posture below for anything unresolved anyway.
    queryKey: ['effective-permissions', userId],
    queryFn: () => getEffectivePermissions(accessToken!),
    enabled: !!accessToken && identityStatus === 'ready' && !!userId,
  })
}

// Deny-by-default while the check is unresolved (loading or errored) or the
// capability isn't present in the grant list — matches this codebase's
// server-side default (argus-context's authorization non-negotiable: "deny
// by default"). Never treat "haven't checked yet" as "allowed."
export function useHasCapability(capability: string): boolean {
  const { data } = useEffectivePermissions()
  return data?.grants.some((g) => g.capability === capability) ?? false
}

// useMissingCapabilities is useHasCapability for a SET of capabilities, plus
// the one extra fact a nav marker needs and a disabled control does not:
// whether the answer is actually known yet.
//
// useHasCapability above is deny-by-default while the permissions query is
// unresolved, which is right for a control — a button that is briefly disabled
// and then enables is safe, and the reverse is not. It is wrong for a marker
// that SAYS something, though: rendering "No access" against every nav
// destination for the few hundred milliseconds before the grants land would be
// a claim about the viewer's role that is false, on every screen, on every
// first load. `resolved` is what lets a caller say nothing until it knows.
//
// `missing` is deliberately the capabilities the viewer LACKS rather than the
// ones the destination requires, so the message built from it names only what
// is actually being asked for.
export function useMissingCapabilities(capabilities: string[]): { resolved: boolean; missing: string[] } {
  const { data, isSuccess } = useEffectivePermissions()
  if (!isSuccess || !data) return { resolved: false, missing: [] }
  const held = new Set(data.grants.map((g) => g.capability))
  return { resolved: true, missing: capabilities.filter((c) => !held.has(c)) }
}
