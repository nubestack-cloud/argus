import { useSyncExternalStore } from 'react'

// The width at which the app switches to its phone layout: the sidebar becomes
// a menu behind the burger, and list rows carry facts their off-screen columns
// hold. Must match the `@media (max-width: 720px)` blocks in index.css, which
// do the visual half of the same switch.
export const PHONE_LAYOUT_QUERY = '(max-width: 720px)'

function subscribe(onChange: () => void) {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return () => {}
  const mq = window.matchMedia(PHONE_LAYOUT_QUERY)
  mq.addEventListener('change', onChange)
  return () => mq.removeEventListener('change', onChange)
}

function snapshot(): boolean {
  return typeof window !== 'undefined' && typeof window.matchMedia === 'function' && window.matchMedia(PHONE_LAYOUT_QUERY).matches
}

// True while the viewport is phone-narrow; false where matchMedia does not
// exist (jsdom, server render).
export function usePhoneLayout(): boolean {
  return useSyncExternalStore(subscribe, snapshot, () => false)
}
