import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { HelpTip } from './HelpTip'

describe('HelpTip', () => {
  it('names the trigger "About X" and describes it with the text', () => {
    render(<HelpTip label="Reason" text="Why this destination is trusted." />)
    const trigger = screen.getByRole('button', { name: 'About Reason' })
    const desc = document.getElementById(trigger.getAttribute('aria-describedby') ?? '')
    expect(desc?.textContent).toBe('Why this destination is trusted.')
  })

  // Live QA 2026-10-11 (found while standardising every tip on the label
  // pattern): the description used to sit inside the tip, and a tip usually
  // sits inside a form <label>, so the input's accessible name grew the whole
  // explanation.
  it('keeps its description out of an enclosing <label>, so the field keeps its own name', () => {
    render(
      <>
        <label htmlFor="reason">
          Reason <HelpTip label="Reason" text="Why this destination is trusted." />
        </label>
        <input id="reason" />
      </>,
    )
    expect(document.querySelector('label')?.textContent).not.toMatch(/destination/)
    expect(screen.queryByLabelText(/destination/, { selector: 'input' })).toBeNull()
    expect(screen.getByLabelText(/^Reason/, { selector: 'input' })).toBeTruthy()
  })
})
