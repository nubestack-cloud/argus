/* eslint-disable */
import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import type { SSOProvider } from '../../api/types'
import './fonts.css'
import s from './ApertureLogin.module.css'

// Screen 02 — "Aperture", transcribed from argus-login-02-aperture.html.
//
// The source builds the 72 tick marks and 8 diaphragm blades with innerHTML;
// here they are JSX .map()s producing the identical DOM — the one place a
// faithful port necessarily looks different in code. Everything else is the
// source's: the four rotation speeds (78s / 52s / 26s / 7.5s), the iris open,
// the core pulse, the pupil that tracks the focused field with its 1.1s
// ease-expo transition, and the contract-on-error.
//
// The DOM order in each `.field` is input -> label -> bar, exactly as written,
// because `.field input:focus + label` and `.field input:focus ~ .bar` depend
// on it. `.filled` is applied from state, since CSS cannot ask whether an
// input has a value (these fields carry `placeholder=" "`, not real
// placeholder text, so `:placeholder-shown` would always match).

type Props = {
  providers: SSOProvider[]
  destination: string
  onLogin: (email: string, password: string) => Promise<void>
  ssoErrorMessage: string | null
  /** This hub build's version (buildinfo.Version), for the footer. */
  version?: string
}

const TICKS = Array.from({ length: 72 }, (_, i) => i)
const BLADES = Array.from({ length: 8 }, (_, i) => i)

export function ApertureLogin({ providers, destination, onLogin, ssoErrorMessage, version }: Props) {
  const [email, setEmail] = useState('')
  const [pw, setPw] = useState('')
  const [showPw, setShowPw] = useState(false)
  const [err, setErr] = useState<string | null>(ssoErrorMessage)
  // One flag, one label. The staged sequence that used to drive these is gone —
  // see onSubmit.
  const [busy, setBusy] = useState(false)
  const [look, setLook] = useState<{ dx: number; dy: number }>({ dx: 0, dy: 0 })


  useEffect(() => {
    if (ssoErrorMessage) setErr(ssoErrorMessage)
  }, [ssoErrorMessage])

  // ---- submit (source lines 295-316) ----
  // THE SUBMIT, AND WHY IT NO LONGER PERFORMS.
  //
  // Each supplied design shipped a staged sequence on a timer — "Authenticating"
  // -> "Verifying device trust" -> "Establishing tunnel" -> "Loading 247
  // clusters" -> a success state — with a progress bar or fill animating
  // alongside it. In the .html mockups that was the whole point: there was no
  // server, so the button had to act one out.
  //
  // Wired to a real hub it became a lie, and the owner caught it in the way
  // that matters: signing in from a laptop with NO CONNECTIVITY to Argus still
  // walked through every stage and still arrived at "signed in", because the
  // timers know nothing about the request. A login screen that reports success
  // while the network is down is worse than one that looks plain.
  //
  // So there are no timers here at all. The button disables, says "Signing
  // in…", and then exactly one of two things happens: the route navigates
  // (success), or the hub's own error appears in this screen's error box. That
  // is all a login screen should claim.
  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setErr(null)
    
    if (!email.trim()) {
      setErr('Enter your work email to continue.')
      return
    }
    setBusy(true)
    try {
      await onLogin(email, pw)
      // No success branch: onLogin navigates away on success, which unmounts
      // this screen. Anything drawn here would be a frame nobody sees.
    } catch (err) {
      setBusy(false)
      setErr(err instanceof Error ? err.message : "We couldn't verify those credentials.")
    }
  }


  return (
    <div className={s.root}>
      <div className={s.tag}>aperture</div>
      <div className={s.grid}>

        {/* No `.err` class any more: submitting an empty field used to add it
            and run `@keyframes contract`, scaling the whole iris down and back
            — the "flip" the owner reported. The error box says what is wrong;
            the screen does not need to lurch. */}
        <section className={s.visual}>
          <div className={s.eye}>
            <svg viewBox="0 0 280 280" aria-hidden="true">
              <g className={s.iris}>
                <circle className={s.glow} cx="140" cy="140" r="132" fill="#3C7D7D" opacity=".18"/>
                <g className={s.spinA}>
                  {TICKS.map((i) => {
                    const long = i % 6 === 0
                    return (
                      <line
                        key={i}
                        x1="140"
                        y1={long ? 8 : 12}
                        x2="140"
                        y2={long ? 20 : 18}
                        stroke="#3C7D7D"
                        strokeWidth={long ? 1.6 : 1}
                        opacity={long ? 0.8 : 0.35}
                        transform={`rotate(${i * 5} 140 140)`}
                      />
                    )
                  })}
                </g>
                <circle className={s.spinB} cx="140" cy="140" r="122" fill="none" stroke="#3C7D7D" strokeWidth="1" strokeDasharray="3 14" opacity=".65"/>
                <g className={s.scan}>
                  <path d="M140,140 L140,26 A114,114 0 0,1 236,88 Z" fill="#3C7D7D" opacity=".07"/>
                  <line x1="140" y1="140" x2="140" y2="26" stroke="#6FB3B3" strokeWidth="1" opacity=".5"/>
                </g>
                <g>
                  {BLADES.map((i) => (
                    <path key={i} className={s.blade} d="M140,140 L228,96 L228,184 Z" fill="#14322F" opacity=".35" transform={`rotate(${i * 45} 140 140)`}/>
                  ))}
                </g>
                <circle className={s.spinC} cx="140" cy="140" r="104" fill="none" stroke="#3C7D7D" strokeWidth="2.5" strokeDasharray="52 26" opacity=".5"/>
                <g className={s.pupil} style={{ transform: `translate(${look.dx}px,${look.dy}px)` }}>
                  <circle cx="140" cy="140" r="86" fill="none" stroke="#3C7D7D" strokeWidth="17"/>
                  <circle cx="140" cy="140" r="62" fill="#F0975B"/>
                  <circle cx="140" cy="140" r="58" fill="#0A1516" opacity=".18"/>
                  <circle cx="140" cy="140" r="38" fill="#14322F"/>
                  <circle className={s.corepulse} cx="140" cy="140" r="14" fill="#EAF7F5"/>
                  <circle cx="132" cy="131" r="4.5" fill="#EAF7F5" opacity=".55"/>
                </g>
              </g>
            </svg>
          </div>
          <div className={s.overlay}></div>
          {/* The design's "clusters watched / issues resolved / median MTTR"
              counters are gone. They were invented, and real ones would not be
              safe here either: this screen is shown before authentication, so
              it must not tell an anonymous visitor how big the fleet is or how
              many incidents it has. */}
          <div className={s.caption}>
            <h2>Argus never <em>blinks</em>.</h2>
            <p>A hundred eyes across every cluster — detecting, diagnosing and repairing before your pager does.</p>
          </div>
        </section>

        <section className={s.panel}>
          <div className={s.form}>
            {/* The same greeting as the other two screens. The lockup has
                moved to the visual panel's top left. */}
            <h1>Welcome back.</h1>
            <p className={s.sub}>Sign in to manage your fleet.</p>

            <div
              className={`${s.err}${err ? ' ' + s.show : ''}`}
              {...(err ? { role: 'alert' as const } : {})}
            >
              {err ?? "We couldn't verify those credentials."}
            </div>

            <form onSubmit={onSubmit} noValidate>
              <div className={`${s.field}${email ? ' ' + s.filled : ''}`}>
                <input
                  id="email"
                  type="email"
                  autoComplete="username"
                  placeholder=" "
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  onFocus={() => setLook({ dx: 16, dy: -8 })}
                  onBlur={() => setLook({ dx: 0, dy: 0 })}
                />
                <label htmlFor="email">Work email</label>
                <span className={s.bar}></span>
              </div>
              <div className={`${s.field}${pw ? ' ' + s.filled : ''}`}>
                <input
                  id="pw"
                  type={showPw ? 'text' : 'password'}
                  autoComplete="current-password"
                  placeholder=" "
                  value={pw}
                  onChange={(e) => setPw(e.target.value)}
                  onFocus={() => setLook({ dx: 16, dy: 10 })}
                  onBlur={() => setLook({ dx: 0, dy: 0 })}
                />
                <label htmlFor="pw">Password</label>
                <button
                  type="button"
                  className={s.peek}
                  aria-label={showPw ? 'Hide password' : 'Show password'}
                  aria-pressed={showPw}
                  onClick={() => setShowPw((v) => !v)}
                >
                  {showPw ? 'HIDE' : 'SHOW'}
                </button>
                <span className={s.bar}></span>
              </div>
              <div className={s.row}>
                <label className={s.check}><input type="checkbox" defaultChecked/> Trust this device</label>
                {/* The design's "Forgot password?" link is gone: there is no
                    password-reset flow in this product and none planned — a
                    local password is set by an administrator — and a dead link
                    on the one screen someone reaches when they cannot get in is
                    worse than no link. The row keeps its checkbox. */}
              </div>
              {/* The design's `.fill` — an amber bar sweeping across the button
                  over 2.4s — is gone with the staged sequence. It was a progress
                  indicator for progress nobody was measuring. */}
              <button className={s.btn} type="submit" disabled={busy}>
                <span className={s.lbl}>{busy && <span className={s.spinner}></span>}{busy ? 'Signing in…' : 'Sign in'}</span>
              </button>
            </form>

            {/* Only the identity providers this hub actually has configured. The
                design drew disabled Google / Entra ID / SAML buttons when there were
                none: controls with nothing behind them, suggesting built-in logins
                ARGUS does not have (it federates over OIDC, configured in Settings). */}
            {providers.length > 0 && (
              <>
                <div className={s.sep}><span>single sign-on</span></div>
                <div className={s.sso}>
                  {providers.map((p) => (
                    <button
                      key={p.id}
                      type="button"
                      onClick={() => window.location.assign(`/api/v1/auth/sso/start?provider=${encodeURIComponent(p.id)}&returnTo=${encodeURIComponent(destination)}`)}
                    >
                      <span className={s.k}>{p.displayName.slice(0, 1).toUpperCase()}</span>{p.displayName}<span className={s.arrow}>→</span>
                    </button>
                  ))}
                </div>
              </>
            )}

            {/* The design had "NUBESTACK ARGUS v2.4.1" and "SOC 2 · ISO 27001".
                The version is now the real build; the compliance line is gone —
                asserting certifications on a login page is a claim this repo
                cannot verify. */}
            {/* One format on both screens: "ARGUS v<version>". The version is
                the build's own — see internal/buildinfo — never a literal. */}
            <div className={s.foot}>
              <span>{version ? `ARGUS v${version}` : 'ARGUS'}</span>
              <span>
                powered by{' '}
                <a href="https://nubestack.com" target="_blank" rel="noreferrer noopener">
                  nubestack.com
                </a>
              </span>
            </div>
          </div>
        </section>
      </div>
    </div>
  )
}
