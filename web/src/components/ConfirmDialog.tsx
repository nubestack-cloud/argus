import type { ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { ApiError } from '../api/client'
import { Dialog } from './Dialog'

// The confirmation step for an access-affecting action — disabling, removing,
// revoking, resetting — in the app's own Dialog rather than window.confirm().
//
// The native prompt was the wrong tool for every one of those: it cannot name
// its target in anything but a run-on sentence, cannot carry the server's
// refusal back to the place the decision was made, looks like a browser
// warning rather than part of the product, and blocks the whole page. This
// stays open while the request runs, shows the hub's error inside itself if it
// fails, and closes only when the caller says the action succeeded.
//
// Portaled to <body>: callers open it from inside a table row (a per-row
// action), and rendered there it inherited the cell's nowrap and ran its own
// sentence off the edge of the dialog.
//
// Focus goes to the dialog's close control on open (Dialog's own rule), never
// to the confirming button, so an Enter carried over from the click that
// opened it cannot confirm a destructive action by accident.
export function ConfirmDialog({
  title,
  children,
  confirmLabel,
  pendingLabel,
  tone = 'danger',
  pending,
  error,
  onConfirm,
  onCancel,
}: {
  title: string
  children: ReactNode
  confirmLabel: string
  pendingLabel: string
  tone?: 'danger' | 'default'
  pending: boolean
  error?: unknown
  onConfirm: () => void
  onCancel: () => void
}) {
  return createPortal(
    <Dialog title={title} onClose={() => (pending ? undefined : onCancel())}>
      {children}
      {error != null && (
        <p className="form-error" role="alert">
          {error instanceof ApiError
            ? error.detail
              ? `${error.message} — ${error.detail}`
              : error.message
            : 'Something went wrong. Please try again.'}
        </p>
      )}
      <div className="modal-actions">
        <button type="button" className="secondary" onClick={onCancel} disabled={pending}>
          Cancel
        </button>
        <button type="button" className={tone === 'danger' ? 'danger' : undefined} onClick={onConfirm} disabled={pending}>
          {pending ? pendingLabel : confirmLabel}
        </button>
      </div>
    </Dialog>,
    document.body,
  )
}
