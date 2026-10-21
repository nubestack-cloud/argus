import { useState } from 'react'
import { copyToClipboard } from '../utils/clipboard'

// Shared by every "here's a secret, shown once" panel (EnrollTokenModal,
// CreateUserModal's/ResetPasswordResultModal's temporary-password reveal
// in UsersPage.tsx) — previously three separate, slightly different
// inline implementations, none of which had copyToClipboard's insecure-
// context fallback (see that module's own doc comment for the real,
// user-reported bug this closes: the button did nothing, silently, on
// any non-HTTPS/non-"localhost" origin).
// Secondary, like every Copy control (argus-design-system components.md, "One
// primary button per screen"): copying is never the action a screen exists
// for, and a filled Copy beside a form's real submit made two primaries.
export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle')

  return (
    <button
      type="button"
      className="copy-button secondary"
      onClick={() => {
        copyToClipboard(text)
          .then(() => setState('copied'))
          .catch(() => setState('failed'))
          .finally(() => {
            setTimeout(() => setState('idle'), 1500)
          })
      }}
    >
      {state === 'copied' ? 'Copied!' : state === 'failed' ? 'Copy failed — select manually' : label}
    </button>
  )
}
