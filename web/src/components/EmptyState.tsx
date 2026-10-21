import type { ReactNode } from 'react'
import { EmptyIllustration } from './icons'
import type { EmptyIllustrationVariant } from './icons'

// Wraps a page's existing "nothing here yet" copy with a small illustration
// (see icons.tsx's EmptyIllustration) so a brand-new install's zero-cluster/
// zero-incident/zero-user/zero-audit-event screens look intentional rather
// than broken — additive only: every call site keeps its original message
// text verbatim, this just gives it a frame. Not a replacement for the
// plain `.empty-state` <p> used inline elsewhere (e.g. "No active grants"
// inside a table cell) — that stays a bare muted sentence on purpose, since
// an illustration there would be noise, not signal.
export function EmptyState({
  variant,
  children,
}: {
  variant: EmptyIllustrationVariant
  children: ReactNode
}) {
  return (
    <div className="empty-state-block">
      <EmptyIllustration variant={variant} />
      <p className="empty-state">{children}</p>
    </div>
  )
}
