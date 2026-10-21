import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { Analysis } from '../api/types'
import { ConclusionBlock, SuggestedNextSteps } from './AnalysisConclusion'

// BACKLOG F22 piece 5. Before this, a "complete" analysis's suggestedNextSteps
// was declared `null` on the CompleteAnalysis type and ConclusionBlock's
// `status === 'complete'` branch never rendered the field at all — so even
// though internal/api/analyze.go has set it on a guidance-route "complete"
// result since lld/08 §12.7 (BUGS.md 107), nothing on the page ever showed it.
// The prompt fix (toolloop_test.go's TestSystemPromptGuidanceRouteAsksForConcreteSteps)
// asks the model for concrete steps; these tests are the other half — that a
// populated list actually reaches the screen, for both statuses that can carry
// one, and that a step written as a kubectl command renders in <code> so it
// reads as something to copy-paste rather than prose.

function completeAnalysis(over: Partial<Analysis>): Analysis {
  return {
    id: 'an_test',
    status: 'complete',
    causalChain: [],
    ruledOut: [],
    rootCause: { statement: 'the readiness probe fails on startup' },
    confidence: 0.8,
    partialReason: null,
    suggestedNextSteps: null,
    plan: null,
    ...over,
  } as unknown as Analysis
}

function partialAnalysis(over: Partial<Analysis>): Analysis {
  return {
    id: 'an_test',
    status: 'partial',
    causalChain: [],
    ruledOut: [],
    rootCause: null,
    confidence: null,
    partialReason: 'iteration_limit',
    suggestedNextSteps: null,
    plan: null,
    ...over,
  } as unknown as Analysis
}

describe('ConclusionBlock — suggestedNextSteps on a complete (guidance-route) analysis', () => {
  it('renders nothing extra when suggestedNextSteps is null (the ordinary complete case)', () => {
    render(<ConclusionBlock analysis={completeAnalysis({})} />)
    expect(screen.queryByText('Suggested next steps')).toBeNull()
  })

  // MOVED, not dropped (2026-08-30). This used to assert ConclusionBlock renders
  // the steps on a complete analysis. It no longer does, deliberately: the steps
  // are a FIX and this card answers "why it broke", so they render in the
  // incident page's stage 3 ("how do I fix it") next to the sentence that tells
  // the operator to apply the change themselves. Rendering them in both places
  // would be the same content twice on one screen.
  //
  // The rendering itself is still pinned, one level down on the shared
  // SuggestedNextSteps component, so the <code> treatment cannot regress just
  // because its call site moved.
  it('does not render steps on a complete analysis — stage 3 owns them now', () => {
    render(
      <ConclusionBlock
        analysis={completeAnalysis({
          suggestedNextSteps: ['kubectl -n payments-prod delete pod/checkout-api-abc'],
        })}
      />,
    )
    expect(screen.queryByText('Suggested next steps')).toBeNull()
  })
})

describe('SuggestedNextSteps — the shared renderer, wherever it is mounted', () => {
  it('renders each step, and shows the exact kubectl command in <code>', () => {
    render(
      <SuggestedNextSteps
        steps={[
          'kubectl -n payments-prod scale deployment/checkout-api --replicas=3',
          'Set spec.template.spec.containers[0].readinessProbe.initialDelaySeconds to 30 on deployment/checkout-api in payments-prod (currently 2)',
        ]}
      />,
    )

    expect(screen.getByText('Suggested next steps')).toBeTruthy()

    const command = screen.getByText(
      'kubectl -n payments-prod scale deployment/checkout-api --replicas=3',
    )
    expect(command.tagName).toBe('CODE')

    const fieldChange = screen.getByText(/Set spec\.template\.spec\.containers/)
    expect(fieldChange.tagName).not.toBe('CODE')
  })

  it('renders nothing at all for an empty or absent list', () => {
    const { container } = render(<SuggestedNextSteps steps={[]} />)
    expect(container.textContent).toBe('')
  })
})

describe('ConclusionBlock — suggestedNextSteps on a partial analysis (unchanged path)', () => {
  it('still renders steps for a bound-hit investigation', () => {
    render(
      <ConclusionBlock
        analysis={partialAnalysis({
          suggestedNextSteps: ['Check the events for the crashlooping pod manually'],
        })}
      />,
    )
    expect(screen.getByText('Suggested next steps')).toBeTruthy()
    expect(screen.getByText('Check the events for the crashlooping pod manually')).toBeTruthy()
  })
})
