/* eslint-disable */
import { useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import type { SSOProvider } from '../../api/types'
import './fonts.css'
import s from './SentinelFieldLogin.module.css'

// Screen 01 — "Sentinel Field", transcribed from
// argus-login-01-sentinel-field.html. The DOM order, nesting and attributes are
// the source's; the canvas particle system below is its <script> moved into an
// effect, with the mutable state (nodes, pulses, mode, px/py, t) in closure
// variables rather than useState, so nothing re-renders at 60fps.
//
// `onLogin` is the real sign-in call. The source's staged submit is theatre on
// a timer; here the timers run exactly as written AND the real login runs
// alongside — on success the route navigates away (unmounting mid-sequence,
// which is correct: nobody should wait 5.6s of animation to get into the app),
// on failure the design's own `.msg` element shows the hub's error and the
// sequence unwinds. The source's final reset timer stays as the fallback.

type Props = {
  providers: SSOProvider[]
  destination: string
  onLogin: (email: string, password: string) => Promise<void>
  ssoErrorMessage: string | null
  /** This hub build's version (buildinfo.Version), for the footer. */
  version?: string
}

export function SentinelFieldLogin({ providers, destination, onLogin, ssoErrorMessage, version }: Props) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null)

  const [showPw, setShowPw] = useState(false)
  const [msg, setMsg] = useState<string | null>(ssoErrorMessage)
  // One flag, one label. The staged sequence that used to drive these is gone —
  // see onSubmit.
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (ssoErrorMessage) setMsg(ssoErrorMessage)
  }, [ssoErrorMessage])

  // ---- the particle field (source lines 250-349) ----
  useEffect(() => {
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    const cv = canvasRef.current
    if (!cv) return
    const ctx = cv.getContext('2d')
    if (!ctx) return

    let W = 0,
      H = 0,
      DPR = 1,
      nodes: { x: number; y: number; vx: number; vy: number; r: number; hot: boolean; ox: number; oy: number }[] = [],
      pulses: { x: number; y: number; t: number; hot: boolean }[] = [],
      mx = 0.5,
      my = 0.5,
      px = 0,
      py = 0,
      t = 0
    let raf = 0
    let pulseTimer = 0

    function build() {
      const n = Math.max(38, Math.min(90, Math.round((W * H) / 20000)))
      nodes = []
      for (let i = 0; i < n; i++) {
        nodes.push({
          x: Math.random() * W,
          y: Math.random() * H,
          vx: (Math.random() - 0.5) * 0.16,
          vy: (Math.random() - 0.5) * 0.16,
          r: Math.random() * 1.8 + 1.3,
          hot: Math.random() < 0.07,
          ox: 0,
          oy: 0,
        })
      }
    }
    function resize() {
      DPR = Math.min(window.devicePixelRatio || 1, 2)
      W = cv!.clientWidth
      H = cv!.clientHeight
      cv!.width = W * DPR
      cv!.height = H * DPR
      ctx!.setTransform(DPR, 0, 0, DPR, 0, 0)
      build()
    }

    function pulse() {
      const n = nodes[Math.floor(Math.random() * nodes.length)]
      pulses.push({ x: n.x, y: n.y, t: 0, hot: n.hot })
      if (pulses.length > 8) pulses.shift()
    }

    function frame() {
      t += 0.016
      px += ((mx - 0.5) * 26 - px) * 0.045
      py += ((my - 0.5) * 20 - py) * 0.045
      ctx!.clearRect(0, 0, W, H)

      // The source had a 'converge' mode that pulled every node toward the
      // centre while the fake submit sequence ran. Nothing sets it now, so it
      // is gone rather than left as an unreachable branch.
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i]
        a.x += a.vx
        a.y += a.vy
        if (a.x < -40) a.x = W + 40
        if (a.x > W + 40) a.x = -40
        if (a.y < -40) a.y = H + 40
        if (a.y > H + 40) a.y = -40
      }

      ctx!.lineWidth = 0.9
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i],
            b = nodes[j]
          const dx = a.x - b.x,
            dy = a.y - b.y,
            d2 = dx * dx + dy * dy
          if (d2 < 24000) {
            const al = (1 - d2 / 24000) * 0.55
            ctx!.strokeStyle = 'rgba(90,165,165,' + al.toFixed(3) + ')'
            ctx!.beginPath()
            ctx!.moveTo(a.x + px, a.y + py)
            ctx!.lineTo(b.x + px, b.y + py)
            ctx!.stroke()
          }
        }
      }

      for (let i = 0; i < pulses.length; i++) {
        const p = pulses[i]
        p.t += 0.011
        if (p.t >= 1) {
          pulses.splice(i, 1)
          i--
          continue
        }
        const rr = p.t * 150,
          al = (1 - p.t) * 0.65
        ctx!.strokeStyle = p.hot
          ? 'rgba(240,151,91,' + al.toFixed(3) + ')'
          : 'rgba(111,179,179,' + al.toFixed(3) + ')'
        ctx!.lineWidth = 1.4 * (1 - p.t) + 0.4
        ctx!.beginPath()
        ctx!.arc(p.x + px, p.y + py, rr, 0, 6.2832)
        ctx!.stroke()
      }

      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i]
        const tw = 0.6 + Math.sin(t * 1.4 + i) * 0.22
        ctx!.fillStyle = a.hot
          ? 'rgba(240,151,91,' + Math.min(1, tw * 1.2).toFixed(3) + ')'
          : 'rgba(130,200,200,' + tw.toFixed(3) + ')'
        ctx!.beginPath()
        ctx!.arc(a.x + px, a.y + py, a.r, 0, 6.2832)
        ctx!.fill()
        if (a.hot) {
          ctx!.fillStyle = 'rgba(240,151,91,.16)'
          ctx!.beginPath()
          ctx!.arc(a.x + px, a.y + py, a.r * 6, 0, 6.2832)
          ctx!.fill()
        }
      }
      raf = requestAnimationFrame(frame)
    }

    const onMove = (e: MouseEvent) => {
      mx = e.clientX / window.innerWidth
      my = e.clientY / window.innerHeight
    }

    window.addEventListener('resize', resize)
    window.addEventListener('mousemove', onMove)
    resize()
    if (reduce) {
      // one static frame
      ctx.clearRect(0, 0, W, H)
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i]
        ctx.fillStyle = a.hot ? 'rgba(240,151,91,.95)' : 'rgba(130,200,200,.75)'
        ctx.beginPath()
        ctx.arc(a.x, a.y, a.r, 0, 6.2832)
        ctx.fill()
      }
    } else {
      frame()
      pulseTimer = window.setInterval(pulse, 1400)
    }

    return () => {
      cancelAnimationFrame(raf)
      clearInterval(pulseTimer)
      window.removeEventListener('resize', resize)
      window.removeEventListener('mousemove', onMove)
    }
  }, [])

  // ---- submit flow (source lines 371-393) ----
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
    setMsg(null)
    const email = (document.getElementById('email') as HTMLInputElement | null)?.value ?? ''
    const pw = (document.getElementById('pw') as HTMLInputElement | null)?.value ?? ''
    if (!email.trim()) {
      setMsg('Enter your work email to continue.')
      return
    }
    setBusy(true)
    try {
      await onLogin(email, pw)
      // No success branch: onLogin navigates away on success, which unmounts
      // this screen. Anything drawn here would be a frame nobody sees.
    } catch (err) {
      setBusy(false)
      setMsg(err instanceof Error ? err.message : 'Those credentials didn’t match.')
    }
  }


  return (
    <div className={s.root}>
      <canvas ref={canvasRef} className={s.fieldCanvas} aria-hidden="true"></canvas>
      <div className={s.vignette} aria-hidden="true"></div>
      <div className={s.tag}>sentinel field</div>

      <main className={s.stage}>
        <div className={s.wrap}>
          <section className={s.card}>
            {/* The same greeting as the other two screens. The lockup is no
                longer in this card — it sits on the page, top left. */}
            <div className={s.head}>
              <h1>Welcome back.</h1>
              <p>Sign in to manage your fleet.</p>
            </div>

            <div
              className={`${s.msg}${msg ? ' ' + s.show : ''}`}
              {...(msg ? { role: 'alert' as const } : {})}
            >
              {msg ?? 'Those credentials didn’t match. Check your email and try again.'}
            </div>

            <form onSubmit={onSubmit} noValidate>
              <div className={s.field}>
                <label htmlFor="email">Work email</label>
                <div className={s.inputwrap}>
                  <input id="email" type="email" autoComplete="username" placeholder="you@company.com" required/>
                </div>
              </div>
              <div className={s.field}>
                <label htmlFor="pw">Password</label>
                <div className={s.inputwrap}>
                  <input id="pw" type={showPw ? 'text' : 'password'} autoComplete="current-password" placeholder="••••••••••••" required/>
                  <button
                    type="button"
                    className={s.peek}
                    aria-label={showPw ? 'Hide password' : 'Show password'}
                    aria-pressed={showPw}
                    onClick={() => setShowPw((v) => !v)}
                  >
                    {showPw ? 'HIDE' : 'SHOW'}
                  </button>
                </div>
              </div>
              <div className={s.row}>
                <label className={s.check}><input type="checkbox" defaultChecked/> Keep me signed in</label>
                {/* The design's "Forgot password?" link is gone: there is no
                    password-reset flow in this product and none planned — a
                    local password is set by an administrator — and a dead link
                    on the one screen someone reaches when they cannot get in is
                    worse than no link. The row keeps its checkbox. */}
              </div>
              <button className={s.btn} type="submit" disabled={busy}>
                <span className={s.sheen}></span>
                <span>{busy && <span className={s.spinner}></span>}{busy ? 'Signing in…' : 'Sign in'}</span>
              </button>
            </form>

            {/* Only the identity providers this hub actually has configured. The
                design drew disabled Google / Entra ID / SAML buttons when there were
                none: controls with nothing behind them, suggesting built-in logins
                ARGUS does not have (it federates over OIDC, configured in Settings). */}
            {providers.length > 0 && (
              <>
                <div className={s.sep}><span>or continue with</span></div>
                <div className={s.sso}>
                  {providers.map((p, i) => (
                    <button
                      key={p.id}
                      type="button"
                      className={i === providers.length - 1 && providers.length % 2 === 1 ? s.wide : undefined}
                      onClick={() => window.location.assign(`/api/v1/auth/sso/start?provider=${encodeURIComponent(p.id)}&returnTo=${encodeURIComponent(destination)}`)}
                    >
                      <span className={s.dot}></span>{p.displayName}
                    </button>
                  ))}
                </div>
              </>
            )}

            {/* The design's second cell read "1,284 clusters online", counted
                up from zero. Removed: it is a fleet reading, and this screen is
                shown before anyone has authenticated. */}
            {/* One format on both screens: "ARGUS v<version>". The version is
                the build's own — see internal/buildinfo — never a literal. */}
            <div className={s.cardfoot}>
              <span>{version ? `ARGUS v${version}` : 'ARGUS'}</span>
            </div>

            {/* The design's "Fleet connected / 247 clusters reporting" overlay
                is gone with the staged submit that showed it. It appeared 2.7s
                after the click regardless of whether anything had connected —
                which, offline, meant announcing a fleet nobody had reached. */}
          </section>

          {/* Was "Protected by Nubestack SSO. By signing in you agree to the
              acceptable use policy." — the policy link went nowhere, and there
              is no such document to point it at. */}
          <p className={s.legal}>
            powered by{' '}
            <a href="https://nubestack.com" target="_blank" rel="noreferrer noopener">
              nubestack.com
            </a>
          </p>
        </div>
      </main>
    </div>
  )
}
