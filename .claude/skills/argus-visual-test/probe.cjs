// Visual sweep of the ARGUS UI: signs in, visits each page at each width in
// each theme, saves a screenshot, and reports what a person would otherwise
// have to spot by eye — the page scrolling sideways, text clipped inside a
// box that hides its overflow, and console errors.
//
// Run from the repository root (it loads Playwright from web/node_modules):
//
//   ARGUS_PW=... BASE=http://hub.example OUT=/abs/shots \
//     node .claude/skills/argus-visual-test/probe.cjs
//
// Environment:
//   BASE     the hub's URL (or Vite's dev server, which proxies /api)  [required]
//   ARGUS_PW the password for ARGUS_USER; read from the environment and never printed
//   ARGUS_USER                                    default admin@localhost
//   OUT      absolute directory for screenshots   default ./visual-test/<timestamp>
//   PAGES    comma-separated paths                default: every top-level route
//   WIDTHS   comma-separated pixel widths         default 1440,1024,768,375
//   THEMES   light,dark                           default light,dark
//   WAIT     ms to let data settle after load     default 2500
//   FULL     1 for full-page screenshots          default viewport only
const { createRequire } = require('module')
const path = require('path')
const fs = require('fs')

const req = createRequire(path.join(process.cwd(), 'web', 'package.json'))
const { chromium } = req('playwright')

const BASE = (process.env.BASE || '').replace(/\/$/, '')
if (!BASE || !process.env.ARGUS_PW) {
  console.error('BASE and ARGUS_PW are required')
  process.exit(2)
}
const PAGES = (process.env.PAGES ||
  '/overview,/clusters,/incidents,/signals,/tolerations,/approvals,/changes,/audit-log,/insights,/search,/compare,/users,/settings').split(',')
const WIDTHS = (process.env.WIDTHS || '1440,1024,768,375').split(',').map(Number)
const THEMES = (process.env.THEMES || 'light,dark').split(',')
const WAIT = Number(process.env.WAIT || 2500)
const OUT = process.env.OUT || path.resolve('visual-test', new Date().toISOString().replace(/[:.]/g, '-'))
fs.mkdirSync(OUT, { recursive: true })

const slug = (p) => p.replace(/^\//, '').replace(/[^A-Za-z0-9]+/g, '-').replace(/-$/, '') || 'root'

// Elements that hide their overflow and are hiding real text. Ellipsis is a
// deliberate truncation and visually-hidden text is meant to be invisible.
function clippedText() {
  const out = []
  for (const el of document.querySelectorAll('main *')) {
    const cs = getComputedStyle(el)
    if (cs.overflowX !== 'hidden' && cs.overflowX !== 'clip') continue
    if (el.clientWidth === 0 || el.scrollWidth <= el.clientWidth + 1) continue
    if (cs.textOverflow === 'ellipsis' || el.closest('.visually-hidden')) continue
    // A deliberately hidden element (the 1px clip pattern) is not clipped text.
    if (el.clientWidth <= 1 || el.clientHeight <= 1) continue
    const text = (el.textContent || '').trim()
    if (!text) continue
    const cls = typeof el.className === 'string' ? el.className.trim().split(/\s+/).slice(0, 2).join('.') : ''
    out.push(`${el.tagName.toLowerCase()}${cls ? '.' + cls : ''} +${el.scrollWidth - el.clientWidth}px "${text.slice(0, 40)}"`)
  }
  return out.slice(0, 5)
}

// The outermost elements wider than the viewport, when the page scrolls sideways.
function widestOffenders() {
  const vw = document.documentElement.clientWidth
  const out = []
  for (const el of document.querySelectorAll('body *')) {
    const r = el.getBoundingClientRect()
    if (r.right <= vw + 1 || r.width === 0) continue
    if (el.parentElement && el.parentElement.getBoundingClientRect().right > vw + 1) continue
    const cls = typeof el.className === 'string' ? el.className.trim().split(/\s+/).slice(0, 2).join('.') : ''
    out.push(`${el.tagName.toLowerCase()}${cls ? '.' + cls : ''} right=${Math.round(r.right)}`)
  }
  return out.slice(0, 5)
}

;(async () => {
  const browser = await chromium.launch()
  const ctx = await browser.newContext({ viewport: { width: WIDTHS[0], height: 900 } })
  const page = await ctx.newPage()
  const errors = []
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()) })
  page.on('pageerror', (e) => errors.push(String(e)))

  await page.goto(BASE + '/login')
  await page.locator('input[type=email]').first().fill(process.env.ARGUS_USER || 'admin@localhost')
  await page.locator('input[type=password]').first().fill(process.env.ARGUS_PW)
  await page.keyboard.press('Enter')
  await page.waitForURL((u) => !u.pathname.startsWith('/login'), { timeout: 20000 })

  let shots = 0
  let findings = 0
  for (const theme of THEMES) {
    // The app reads its explicit theme choice from localStorage (web/src/theme.ts).
    await page.evaluate((t) => localStorage.setItem('argus.theme', t), theme)
    for (const width of WIDTHS) {
      await page.setViewportSize({ width, height: 900 })
      for (const p of PAGES) {
        errors.length = 0
        await page.goto(BASE + p)
        await page.waitForLoadState('networkidle').catch(() => {})
        await page.waitForTimeout(WAIT)
        const file = path.join(OUT, `${slug(p)}-${width}-${theme}.png`)
        await page.screenshot({ path: file, fullPage: process.env.FULL === '1' })
        shots++
        const sideways = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
        const notes = []
        if (sideways > 0) notes.push(`page scrolls sideways +${sideways}px: ${(await page.evaluate(widestOffenders)).join('; ')}`)
        for (const c of await page.evaluate(clippedText)) notes.push(`clipped ${c}`)
        for (const e of errors.slice(0, 3)) notes.push(`console ${e.slice(0, 160)}`)
        if (notes.length) {
          findings += notes.length
          console.log(`${p} @${width} ${theme}`)
          for (const n of notes) console.log(`  ${n}`)
        }
      }
    }
  }
  await browser.close()
  console.log(`\n${shots} screenshots, ${findings} findings`)
  console.log(`shots: ${OUT}`)
})().catch((e) => { console.error(e); process.exit(1) })
