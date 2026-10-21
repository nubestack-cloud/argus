import { useState } from 'react'
import type { FormEvent } from 'react'
import { useMutation } from '@tanstack/react-query'
import { ApiError } from '../api/client'
import { useAuth } from '../auth/useAuth'
import { Dialog } from './Dialog'

// Reachable from two places (AppShell.tsx): the account area's "Change
// password" button, always available, and the mustChangePassword banner's
// own action, for the account that's being nagged about it — same modal
// either way, no second implementation of this form.
export function ChangePasswordModal({ onClose }: { onClose: () => void }) {
  // minPasswordLength is the org's CONFIGURED floor (Settings > General,
  // migration 000131), read from AuthContext rather than a hardcoded
  // constant — it used to be one, a client-side echo of a value that could
  // actually change underneath it. Still purely a client-side pre-check: the
  // server re-validates this on every request regardless of what this value
  // says (internal/api/auth.go's handleChangePassword resolves its own copy
  // fresh from the same settings row).
  const { changePassword, minPasswordLength } = useAuth()
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [validationError, setValidationError] = useState<string | null>(null)
  const [done, setDone] = useState(false)

  const mutation = useMutation({
    mutationFn: () => changePassword(currentPassword, newPassword),
    onSuccess: () => setDone(true),
  })

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setValidationError(null)
    if (newPassword.length < minPasswordLength) {
      setValidationError(`New password must be at least ${minPasswordLength} characters.`)
      return
    }
    if (newPassword !== confirmPassword) {
      setValidationError('New password and confirmation do not match.')
      return
    }
    if (newPassword === currentPassword) {
      setValidationError('New password must be different from your current password.')
      return
    }
    mutation.mutate()
  }

  return (
    <Dialog title="Change password" onClose={onClose}>
        {!done && (
          <form onSubmit={handleSubmit}>
            <label htmlFor="currentPassword">Current password</label>
            <input
              id="currentPassword"
              type="password"
              autoComplete="current-password"
              required
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
            />

            <label htmlFor="newPassword">New password</label>
            <input
              id="newPassword"
              type="password"
              autoComplete="new-password"
              required
              minLength={minPasswordLength}
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
            />

            <label htmlFor="confirmNewPassword">Confirm new password</label>
            <input
              id="confirmNewPassword"
              type="password"
              autoComplete="new-password"
              required
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
            />
            <p className="field-hint">At least {minPasswordLength} characters.</p>

            {(validationError || mutation.isError) && (
              <p className="form-error" role="alert">
                {validationError ??
                  (mutation.error instanceof ApiError
                    ? mutation.error.detail
                      ? `${mutation.error.message} — ${mutation.error.detail}`
                      : mutation.error.message
                    : 'Something went wrong. Please try again.')}
              </p>
            )}

            <div className="modal-actions">
              <button type="button" className="secondary" onClick={onClose} disabled={mutation.isPending}>
                Cancel
              </button>
              <button type="submit" disabled={mutation.isPending}>
                {mutation.isPending ? 'Changing…' : 'Change password'}
              </button>
            </div>
          </form>
        )}

        {done && (
          <div className="token-result">
            <p>Your password has been changed.</p>
            <p className="field-hint">
              Every other signed-in session for your account has been ended. This one continues —
              no need to sign in again.
            </p>
            <button type="button" onClick={onClose}>
              Done
            </button>
          </div>
        )}
    </Dialog>
  )
}
