import { Component } from 'react'
import type { ErrorInfo, ReactNode } from 'react'

// The app's only render-error backstop. Until this existed, a single
// unexpected shape in one server row took the *entire* UI down: React
// unmounts the whole tree when a render throws and nothing catches it, so
// the user got a blank white page with no nav, no message, and no way
// forward — and because the offending row is still there on the next load,
// reloading crashed again. That was live: IncidentDetailPage dereferenced
// analysis.rootCause.statement on a "complete" analysis whose rootCause is
// null (a shape the hub really returns — see CompleteAnalysis in
// api/types.ts). That specific dereference is fixed, but the class of bug
// isn't fixable one field at a time, which is what this is for: any future
// null, any missing enum case, any bad Date stays contained to the part of
// the screen that threw.
//
// A class component on purpose — `getDerivedStateFromError`/
// `componentDidCatch` are the only way to catch a render error in React;
// there is no hook equivalent (React 19 included). This is the one place in
// this codebase that isn't a function component.
//
// Deliberately NOT a place to report telemetry: this app has no error-
// reporting backend, and inventing one here would be scope creep. The error
// goes to the console (where a developer or a support session can find it),
// and the user gets an honest, actionable message instead of a white page.

interface ErrorBoundaryProps {
  children: ReactNode
  // What the user was looking at, for the message ("this page" vs "ARGUS").
  // Optional so the outermost boundary can stay generic.
  label?: string
}

interface ErrorBoundaryState {
  // A separate flag rather than testing `error !== null`: JavaScript lets a
  // component throw anything, including null or undefined, and keying "did we
  // catch something" off truthiness would then fall straight back to
  // re-rendering the child that just threw — forever.
  caught: boolean
  error: unknown
}

// Whatever was thrown, reduced to one line of display text. `unknown`, not
// `Error`, because `throw` accepts any value and this must not itself throw.
function describeError(error: unknown): string {
  if (error instanceof Error) {
    return error.message || error.name || 'unknown error'
  }
  if (typeof error === 'string' && error) {
    return error
  }
  return 'unknown error'
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { caught: false, error: null }

  static getDerivedStateFromError(error: unknown): ErrorBoundaryState {
    return { caught: true, error }
  }

  componentDidCatch(error: unknown, info: ErrorInfo) {
    console.error('ARGUS UI: render failed and was caught by an ErrorBoundary', error, info.componentStack)
  }

  // "Try again" re-renders the same subtree from scratch. Worth offering
  // even though a deterministic data problem will just throw again — a
  // transient one (a mid-flight refetch, a race) really does recover, and
  // the button costs nothing. It is not presented as a fix, only as a retry.
  private retry = () => {
    this.setState({ caught: false, error: null })
  }

  render() {
    const { caught, error } = this.state
    if (!caught) {
      return this.props.children
    }

    // A `label` means this is the per-page boundary inside AppShell, so the
    // nav really is still there to use. The unlabelled outermost boundary
    // caught something above the shell, and promising a working app around it
    // would be false — so it doesn't.
    const label = this.props.label
    return (
      <div className="page">
        <header className="page-header">
          <h1>Something went wrong</h1>
        </header>
        <p className="banner banner-warning" role="alert">
          ARGUS couldn't display {label ?? 'this screen'}. Nothing was changed — this is a display
          problem, not a failed action
          {label ? ', and the rest of the app is still usable' : ''}.
        </p>
        <div className="card">
          <p className="field-hint">
            {/* The raw message, not a paraphrase: it's the only concrete thing
                the person reading this can pass on to whoever fixes it. Plain
                JSX interpolation, same rule as any other untrusted string in
                this app. */}
            Error: {describeError(error)}
          </p>
          <div className="settings-actions-row">
            <button type="button" onClick={this.retry}>
              Try again
            </button>
            {/* A real navigation, not a router Link: this boundary can sit
                above the router (see App.tsx), and if the router itself is
                what threw, a Link would render into the same broken tree.
                Styled as a plain link (this app's default anchor styling) —
                no new CSS for one recovery affordance. */}
            <a href="/overview">Back to fleet overview</a>
          </div>
        </div>
      </div>
    )
  }
}
