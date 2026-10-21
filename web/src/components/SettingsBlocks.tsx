import type { ReactNode } from 'react'
import { HelpTip } from './HelpTip'

// Every settings card opens the same way: its title, ONE line saying what the
// card controls, and the full explanation behind a HelpTip beside the title.
// The cards used to open with a paragraph each — four to six lines of
// mechanism before the first control — which made the page read as a manual
// rather than a form (anti-patterns.md, document-shaped UI). Anything a reader
// must not miss — a consequence, an unenforced guardrail — stays visible as a
// banner or notice in the card body; only the explanation moves.
export function PanelHead({ title, lede, help, aside }: { title: string; lede?: ReactNode; help?: string; aside?: ReactNode }) {
  return (
    <div className="settings-head">
      <div className="settings-head-text">
        <h2>
          {title}
          {help && <HelpTip label={title} text={help} />}
        </h2>
        {lede && <p className="settings-lede">{lede}</p>}
      </div>
      {aside && <div className="settings-head-aside">{aside}</div>}
    </div>
  )
}

// The values the hub is actually running with, as label/value pairs rather
// than a sentence ("Currently in effect: 8 iterations, 180s…"). A blank field
// means "the default", so without this a reader cannot tell what a blank
// field resolves to without hovering its placeholder.
export function InEffect({ items, note }: { items: Array<[string, ReactNode]>; note?: string }) {
  return (
    <div className="settings-effective">
      <span className="settings-effective-label">
        In effect now
        {note && <HelpTip label="the values in effect" text={note} />}
      </span>
      <dl>
        {items.map(([k, v]) => (
          <div key={k}>
            <dt>{k}</dt>
            <dd>{v}</dd>
          </div>
        ))}
      </dl>
    </div>
  )
}
