// Copies text to the clipboard, real user-report fix: the Clipboard API
// (navigator.clipboard.writeText) only exists in a secure context — HTTPS,
// or the literal hostname "localhost" — so any other way of reaching this
// app (a plain http:// URL by IP/hostname, common for an internal/dev
// deployment) has `navigator.clipboard` simply undefined. Every copy button
// in this app used to call `navigator.clipboard?.writeText(...)` directly:
// with clipboard undefined, `?.writeText(...)` evaluates to `undefined`,
// and `.then()` on that throws inside the click handler — a silent failure
// from the user's point of view (no error shown, "Copied!" never appears).
//
// Falls back to the legacy `document.execCommand('copy')` technique (via a
// temporary, offscreen, focused, selected textarea) whenever the Clipboard
// API is unavailable or itself throws (e.g. a permissions-policy denial) —
// deprecated, but it still works in an insecure context, which is exactly
// the case the Clipboard API can't cover.
export async function copyToClipboard(text: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text)
      return
    } catch {
      // Fall through to the legacy fallback below.
    }
  }

  const textarea = document.createElement('textarea')
  textarea.value = text
  // Off-screen but still focusable/selectable — execCommand('copy') only
  // acts on the current selection, so the element has to actually receive
  // focus and a real selection, not just exist in the DOM.
  textarea.style.position = 'fixed'
  textarea.style.top = '0'
  textarea.style.left = '-9999px'
  textarea.setAttribute('readonly', '')
  document.body.appendChild(textarea)

  let succeeded = false
  try {
    textarea.focus()
    textarea.select()
    succeeded = document.execCommand('copy')
  } catch {
    succeeded = false
  } finally {
    document.body.removeChild(textarea)
  }

  if (!succeeded) {
    throw new Error('Copy to clipboard failed')
  }
}
