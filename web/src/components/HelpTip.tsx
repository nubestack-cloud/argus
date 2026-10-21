import { useEffect, useId, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { InfoIcon } from './icons'

// A small, reusable "why does this matter" affordance — the open idea from
// this round's feedback ("question bubble explaining roles on hover, maybe
// other things too"). Deliberately not hover-only: the explanatory text is
// the trigger button's own `aria-label`, announced to a screen reader the
// moment the button receives focus regardless of whether the visual bubble
// is showing.
//
// One HelpTip per non-obvious label, not one per label — see call sites
// (UsersPage's role badges, AuditLogPage's capability filter, SettingsPage's
// LLM base URL, IncidentDetailPage's confidence score) for the "would a
// first-time user plausibly be confused here" bar this was held to.
//
// Rewritten this round to fix a real, reported bug: hovering a HelpTip
// showed what looked like two overlapping tooltips, one of them visibly
// cut off. Root causes, both structural, not per-instance:
//
//  1. The trigger carried *both* a native `title` attribute and this
//     component's own styled `.help-tip-bubble` — a browser shows its own
//     plain tooltip from `title` on hover independently of anything this
//     component renders, so the two literally overlapped. Fixed by
//     dropping `title` entirely; `aria-label` alone already covers
//     accessibility (screen readers announce it on focus; sighted mouse
//     users get the same text from the bubble below).
//  2. The bubble was `position: absolute` inside `.help-tip` (a plain
//     inline element with no special overflow), so it inherited whatever
//     the *nearest ancestor with non-visible overflow* did — and on
//     UsersPage, that ancestor is `.cluster-table` (overflow: hidden, for
//     its own rounded corners). A bubble that pops up *above* its trigger
//     inside a table row gets its top sliced off by the table's own
//     clipping, exactly the "one truncated" symptom reported. There's no
//     way to fix this from inside `.help-tip`/`.cluster-table` without
//     giving every possible ancestor `overflow: visible` forever (fragile,
//     and would undo the deliberate rounded-corner clipping) — so the
//     bubble is now portaled straight to `document.body` and positioned
//     with `position: fixed` from the trigger's own
//     getBoundingClientRect(), which is never inside any clipping
//     ancestor by construction.
const BUBBLE_MAX_WIDTH = 260
const EDGE_MARGIN = 8

type TipPosition = { top: number; left: number; placement: 'above' | 'below'; maxWidth: number }

// `label` (optional) names WHAT the tip explains — "Checks", "Coverage". With
// it, the trigger's accessible name is "About Checks" and the explanation is
// its accessible DESCRIPTION (aria-describedby on a visually-hidden copy), so
// a screen reader announces a short control name followed by the text rather
// than a 40-word button name. Without it the older shape stands — the text is
// the name — so the call sites that predate the prop read exactly as before.
//
// Dismissible without moving the pointer or focus (WCAG 1.4.13): Escape closes
// an open bubble. A click opens it if it is not already showing — focus and
// hover usually got there first — which is how a touch user, who has no
// hover, re-opens it after dismissing it.
export function HelpTip({ text, label }: { text: string; label?: string }) {
  const triggerRef = useRef<HTMLButtonElement>(null)
  const [tip, setTip] = useState<TipPosition | null>(null)
  const descId = useId()

  function show() {
    const el = triggerRef.current
    if (!el) return
    const rect = el.getBoundingClientRect()
    const maxWidth = Math.min(BUBBLE_MAX_WIDTH, window.innerWidth - EDGE_MARGIN * 2)
    let left = rect.left + rect.width / 2 - maxWidth / 2
    left = Math.max(EDGE_MARGIN, Math.min(left, window.innerWidth - maxWidth - EDGE_MARGIN))
    // Prefer opening above the trigger (this app's original placement);
    // flip below only when there plainly isn't room, so a HelpTip near the
    // very top of the viewport (e.g. a table's first header row) doesn't
    // just get clipped by the viewport edge instead of the table.
    const placement: TipPosition['placement'] = rect.top > 80 ? 'above' : 'below'
    setTip({
      top: placement === 'above' ? rect.top - EDGE_MARGIN : rect.bottom + EDGE_MARGIN,
      left,
      placement,
      maxWidth,
    })
  }

  function hide() {
    setTip(null)
  }

  // A fixed-position tooltip that's open during a page scroll would
  // visually detach from its trigger (the trigger moves, the tooltip
  // doesn't) — same fix every native tooltip already gets for free: close
  // it, rather than tracking position continuously for what's meant to be
  // a brief hover/focus glance.
  useEffect(() => {
    if (!tip) return
    const close = () => setTip(null)
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setTip(null)
    }
    window.addEventListener('scroll', close, { passive: true, capture: true })
    window.addEventListener('resize', close)
    document.addEventListener('keydown', onKey)
    return () => {
      window.removeEventListener('scroll', close, { capture: true })
      window.removeEventListener('resize', close)
      document.removeEventListener('keydown', onKey)
    }
  }, [tip])

  return (
    <span className="help-tip" onMouseEnter={show} onMouseLeave={hide}>
      <button
        ref={triggerRef}
        type="button"
        className="help-tip-trigger"
        aria-label={label ? `About ${label}` : text}
        aria-describedby={label ? descId : undefined}
        aria-expanded={label ? tip !== null : undefined}
        onFocus={show}
        onBlur={hide}
        onClick={() => { if (!tip) show() }}
      >
        <InfoIcon />
      </button>
      {/* The description lives outside this component's own DOM position,
          portaled to <body> and `hidden`. A HelpTip usually sits INSIDE a
          form <label>, and a visually-hidden span there became part of the
          label's text — the input's accessible name grew the whole
          explanation ("Reason required Why this destination is trusted…").
          aria-describedby still reads a hidden element it points at
          directly, so the description is unchanged; only the label stops
          swallowing it. */}
      {label &&
        typeof document !== 'undefined' &&
        createPortal(
          <span id={descId} hidden>
            {text}
          </span>,
          document.body,
        )}
      {tip &&
        createPortal(
          // Purely decorative — aria-hidden, same as before this rewrite:
          // the trigger's aria-label is the single source of truth for
          // what a screen reader announces, so this never needs its own
          // (contradictory alongside aria-hidden) tooltip role.
          <span
            aria-hidden="true"
            // Spelled out, not templated: the "above" rule lifts the bubble
            // its own height clear of the trigger, and a class name built
            // from a string looked unused and its rule was once deleted —
            // every tip then opened over the cell it explained.
            className={tip.placement === 'above' ? 'help-tip-bubble help-tip-bubble-above' : 'help-tip-bubble help-tip-bubble-below'}
            style={{ top: tip.top, left: tip.left, maxWidth: tip.maxWidth }}
          >
            {text}
          </span>,
          document.body,
        )}
    </span>
  )
}
