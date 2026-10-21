#!/usr/bin/env node
/**
 * design-lint — the mechanically checkable subset of ARGUS's design system.
 *
 * WHY THIS EXISTS, AND WHAT IT DELIBERATELY DOES NOT DO
 *
 * The design rules live in .claude/skills/argus-design-system/reference/*.md and most of them need
 * judgement: whether a screen answers the four questions in order, whether a number is fabricated,
 * whether a mark encodes anything. A model reviews those (argus-design-review). None of it can run
 * in GitHub Actions.
 *
 * This script is the honest remainder: the rules that are genuinely decidable by reading text, so
 * that drift gets caught automatically rather than when somebody remembers to ask. The governing
 * principle is PRECISION OVER VOLUME. Running the naive versions of these checks against this
 * codebase produced 12 false positives and 0 true positives — the brand logo and a ticket number
 * that looks like a hex colour. A linter that cries wolf gets disabled, which is worse than no
 * linter. So every check here is narrowed until its false-positive rate is ~0, and the ones that
 * could not be narrowed (spacing literals, which have far more legitimate variance than type sizes)
 * were left out rather than shipped noisy.
 *
 * ANTI-DRIFT: the type scale is not hardcoded here. It is parsed out of index.css at runtime, so
 * this check cannot disagree with the tokens it is enforcing. Editing a token updates the check.
 *
 * BASELINE: introducing a linter to an existing codebase either means a big-bang refactor or a
 * baseline. index.css already carries 19 font-size literals that predate this check; changing all 19
 * is a visual-regression risk that cannot be verified without a browser. They are recorded in
 * design-lint-baseline.json and tracked as PROJECT.md UX12. The build fails on anything NEW, which is
 * what "catch drift" means — pre-existing debt is not drift. Do not add to the baseline to make a
 * new finding go away.
 *
 * Usage:
 *   node scripts/design-lint.mjs                    # check; exit 1 on any non-baselined finding
 *   node scripts/design-lint.mjs --update-baseline   # re-record current findings as the baseline
 */

import { readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const webRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const srcRoot = join(webRoot, 'src')
const cssPath = join(srcRoot, 'index.css')
const baselinePath = join(webRoot, 'scripts', 'design-lint-baseline.json')

const updateBaseline = process.argv.includes('--update-baseline')

/** Files whose literal colours are sanctioned, with the reason. Keep this list tiny and justified. */
const LITERAL_COLOUR_EXEMPT = new Map([
  [
    'src/components/icons.tsx',
    'the ARGUS logo — a brand mark must not recolour with the theme, and its gradient is identity ' +
      'rather than decoration (see reference/tokens.md)',
  ],
  // The three sign-in screens are VERBATIM TRANSCRIPTIONS of supplied design
  // files (argus-login-0{1,2,3}-*.html), ported on the explicit instruction
  // that the rendered result be indistinguishable from the originals. Their
  // literals are inline SVG fills in hand-drawn artwork — an aperture
  // mechanism, a vignette, a tick ring — and swapping any of them for a token
  // changes the drawing. Each screen's palette is declared as custom
  // properties at the top of its own .module.css, which is where a future
  // retheme would happen; these are the artwork's own colours, not surface
  // styling that leaked.
  [
    'src/pages/login/SentinelFieldLogin.tsx',
    'verbatim transcription of a supplied design file — inline SVG artwork colours',
  ],
  [
    'src/pages/login/ApertureLogin.tsx',
    'verbatim transcription of a supplied design file — inline SVG artwork colours',
  ],
  [
    'src/pages/login/TelemetryLogin.tsx',
    'verbatim transcription of a supplied design file — inline SVG artwork colours',
  ],
])

const findings = []
const add = (file, line, rule, value, message) =>
  findings.push({ file, line, rule, value, message })

// ---------------------------------------------------------------------------
// Read the type scale out of index.css rather than restating it.
// ---------------------------------------------------------------------------

const css = readFileSync(cssPath, 'utf8')
const cssLines = css.split('\n')

const scale = new Map() // "0.85rem" -> "--font-size-sm"
for (const m of css.matchAll(/^\s*(--font-size-[a-z0-9]+):\s*([^;]+);/gm)) {
  scale.set(m[2].trim(), m[1])
}
if (scale.size === 0) {
  console.error('design-lint: parsed zero --font-size-* tokens out of index.css — refusing to run.')
  console.error('If the token block moved, fix this parser rather than deleting the check.')
  process.exit(2)
}

/**
 * The token block is the one place literal values are correct — that is where tokens are DEFINED.
 * Everything after it should be referencing them. The boundary is the last line that defines a
 * custom property inside a :root/media block near the top of the file.
 */
const lastTokenDefLine = (() => {
  let last = 0
  cssLines.forEach((l, i) => {
    if (/^\s*--[a-z][a-z0-9-]*:/.test(l)) last = i + 1
  })
  return last
})()

// ---------------------------------------------------------------------------
// CSS checks
// ---------------------------------------------------------------------------

// Strips CSS comments, INCLUDING multi-line blocks, so documented literals
// ("the mockup's #8b929e is --text-muted here") and rules explained by name in
// prose are never findings. Comments are not rules.
//
// This is a state machine rather than a per-line regex because a per-line one is
// subtly wrong and it bit immediately: it stripped `/* … */` on one line and
// `/* …` to end-of-line, but every line in the MIDDLE of a block comment looked
// like code. The first comment written to explain why glassmorphism is banned
// flagged itself as glassmorphism. Every banned pattern named in prose anywhere
// in this 7000-line file was a latent false positive.
function stripCssComments(lines) {
  let inBlock = false
  return lines.map((raw) => {
    let out = ''
    let i = 0
    while (i < raw.length) {
      if (inBlock) {
        const end = raw.indexOf('*/', i)
        if (end === -1) return out // rest of the line is comment
        inBlock = false
        i = end + 2
        continue
      }
      const start = raw.indexOf('/*', i)
      if (start === -1) {
        out += raw.slice(i)
        break
      }
      out += raw.slice(i, start)
      inBlock = true
      i = start + 2
    }
    return out
  })
}

const strippedCss = stripCssComments(cssLines)

strippedCss.forEach((line, i) => {
  const lineNo = i + 1
  if (!line.trim()) return

  // 1. font-size literals. On-scale ones should use their token; off-scale ones are drift.
  //
  // `rem` and `px` only — `em` is deliberately NOT flagged. em is *relative* sizing, where being
  // proportional to the container is the correct intent rather than a scale bypass: inline code at
  // 0.9em scales with whatever text surrounds it, and a monospace face needs exactly that because it
  // renders optically larger than the body face at the same nominal size. Flagging em produced 2
  // false positives here (a `dt` label and a `var(--font-mono)` block), which is why the unit is
  // part of the rule.
  const fs = line.match(/font-size:\s*([0-9][0-9.]*(?:rem|px))\b/)
  if (fs) {
    const value = fs[1]
    const token = scale.get(value)
    if (token) {
      add('src/index.css', lineNo, 'font-size-literal-on-scale', value,
        `${value} duplicates ${token} → use var(${token})`)
    } else {
      add('src/index.css', lineNo, 'font-size-off-scale', value,
        `${value} is not on the type scale → use a var(--font-size-*) or add a token with a reason`)
    }
  }

  // 2. transition: all — animates layout and paint you did not intend.
  if (/transition:\s*all\b/.test(line)) {
    add('src/index.css', lineNo, 'transition-all', 'all', 'transition: all → name the properties')
  }

  // 2b. Glassmorphism, which anti-patterns.md bans BY NAME and this script could
  // not see until a design review found a live instance (`.settings-save-bar`,
  // a translucent blurred bar over page content). A rule the ruleset preaches
  // with no gate behind it is a latent bug — that is how this one survived.
  //
  // Keyed on backdrop-filter alone. `color-mix(… transparent)` is deliberately
  // NOT flagged: it appears a dozen times legitimately here for border tints and
  // box-shadow alphas, so it would be almost all false positives. The blur is
  // the part that reduces contrast on the text underneath, and it is the part
  // with no legitimate use in this UI.
  if (/backdrop-filter\s*:/.test(line)) {
    add('src/index.css', lineNo, 'glassmorphism', 'backdrop-filter',
      'backdrop-filter → glassmorphism is banned; use an opaque var(--surface) with --shadow-md')
  }

  // 3. outline removal. Reported wherever it appears; :focus-visible must replace it, and that is
  //    a judgement the reviewer makes — this just surfaces every instance.
  if (/outline:\s*(none|0)\b/.test(line)) {
    add('src/index.css', lineNo, 'outline-none', 'outline:none',
      'outline removed → needs a visible :focus-visible replacement')
  }

  // 4. Colour literals outside the token block. Inside it, literals ARE the definition.
  if (lineNo > lastTokenDefLine) {
    const hex = line.match(/#[0-9a-fA-F]{3,8}\b/)
    if (hex && !/--[a-z]/.test(line)) {
      add('src/index.css', lineNo, 'colour-literal-outside-tokens', hex[0],
        `${hex[0]} outside the token block → use a custom property`)
    }
  }
})

// ---------------------------------------------------------------------------
// Row state encoded in colour alone
//
// Added after an external review found `.incident-row-attention` carrying the
// single most important fact on the incidents list — "this one needs a human" —
// as a 25% amber background and NOTHING else. No word, no glyph, no aria. That
// is the first entry on this ruleset's never-downgrade list, it is invisible to
// anyone who cannot separate the tint from the surface, and it vanishes in a
// screenshot. This script passed clean over it, because every check above is
// per-line and per-property: none of them can see that a whole rule block sets
// background and only background.
//
// The check cannot prove the companion text exists — that lives in TSX, in a
// different cell of the same row, and matching them reliably is beyond a
// regex. So it does the next best thing and the same thing this file already
// does for sanctioned colour literals: it demands the author SAY where the word
// is. A new row-state class that tints and nothing else fails until it is
// listed here with the place its text mark is rendered. Answering that question
// is the whole point; a wrong answer is visible in review, an unasked one was
// not.
const ROW_STATE_TEXT_MARK = new Map([
  ['.incident-row-attention td',
    "IncidentsPage.tsx renders a 'Needs you' badge beside StateBadge in the state cell"],
  ['.cluster-row-pending td',
    'ClustersPage.tsx renders <ClusterStateBadge> in the state cell of the same row'],
  ['.list-table tr.fleet-row-active > td',
    "index.css draws a '›' glyph before the first cell (td:first-child::before) and the row carries aria-current"],
])

{
  const withoutComments = strippedCss.join('\n')
  const blockRe = /([^{}]+)\{([^{}]*)\}/g
  let m
  while ((m = blockRe.exec(withoutComments)) !== null) {
    const selector = m[1].trim().replace(/\s+/g, ' ')
    if (!selector.includes('-row-')) continue
    // A :hover/:focus variant is a pointer affordance, not the state signal.
    if (/:(hover|focus|active|disabled|focus-visible)/.test(selector)) continue
    const props = m[2]
      .split(';')
      .map((d) => d.split(':')[0].trim())
      .filter(Boolean)
    if (props.length === 0) continue
    if (!props.every((prop) => prop.startsWith('background'))) continue
    if (ROW_STATE_TEXT_MARK.has(selector)) continue
    const lineNo = withoutComments.slice(0, m.index).split('\n').length
    add('src/index.css', lineNo, 'row-state-colour-only', selector,
      `${selector} conveys row state with background alone → render a word or glyph in the row, ` +
      'then list the selector in ROW_STATE_TEXT_MARK saying where that mark is')
  }
}

// ---------------------------------------------------------------------------
// TSX / HTML checks
// ---------------------------------------------------------------------------

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) walk(full, out)
    else out.push(full)
  }
  return out
}

// Status-bearing glyphs. Decoration beside real text with aria-hidden is fine and common; a bare
// glyph carrying state is not. The aria-hidden test on the same line is what separates them, and it
// was verified to flag the one real case in this codebase and skip the one legitimate one.
const STATUS_GLYPH = /[✓✔✗✘⚠⛔✅❌❗⁉]|[\u{1F300}-\u{1FAFF}]/u

for (const full of walk(srcRoot)) {
  const file = relative(webRoot, full).split(/[\\/]/).join('/')
  if (!/\.(tsx|ts)$/.test(file)) continue
  if (/\.test\./.test(file)) continue

  const text = readFileSync(full, 'utf8')
  const lines = text.split('\n')
  const exemptReason = LITERAL_COLOUR_EXEMPT.get(file)

  lines.forEach((line, i) => {
    const lineNo = i + 1

    // 5. Colour literals in components. Narrowed to a colour-bearing context, because a bare
    //    /#[0-9a-f]{3,8}/ match hits ticket numbers in placeholder strings ("ticket #4412").
    if (!exemptReason) {
      const inColourContext =
        /(?:color|colour|background|backgroundColor|borderColor|fill|stroke|stopColor|boxShadow|outlineColor)\s*[:=]/i.test(
          line,
        )
      const hex = line.match(/#[0-9a-fA-F]{6}\b|#[0-9a-fA-F]{3}\b/)
      if (inColourContext && hex) {
        add(file, lineNo, 'colour-literal-in-component', hex[0],
          `${hex[0]} in a component → use a var(--*) token`)
      }
    }

    // 6. transition: all in an inline style or CSS-in-JS string.
    if (/transition:\s*(?:'|")?all\b/.test(line)) {
      add(file, lineNo, 'transition-all', 'all', 'transition: all → name the properties')
    }

    // 7b. (below, per file) An unstyled table.
    // 7. A status glyph with no aria-hidden on the same line.
    if (STATUS_GLYPH.test(line) && !/aria-hidden/.test(line)) {
      const glyph = line.match(STATUS_GLYPH)[0]
      add(file, lineNo, 'status-glyph-unlabelled', glyph,
        `"${glyph}" carries status as a glyph → use an inline SVG icon, or aria-hidden beside real text`)
    }
  })
}

// 9. A <table> with none of the house table classes. The owner's review
//    (2026-10-10, PROJECT.md UX1) found panel tables rendering with browser
//    defaults — centred bold headers on grey, 90px rows — beside the house
//    style. components.md: `.data-table` for tables inside panels and cards,
//    `.cluster-table`/`.list-table` for page-level lists. Decidable from the
//    opening tag alone, so it is checked here; whether the RIGHT one of the
//    allowed classes was chosen is the review skill's judgement.
const TABLE_CLASSES = /\b(data-table|cluster-table|list-table|unified-diff-body)\b/
for (const full of walk(srcRoot)) {
  const file = relative(webRoot, full).split(/[\\/]/).join('/')
  if (!/\.tsx$/.test(file) || /\.test\./.test(file)) continue
  const text = readFileSync(full, 'utf8')
  const re = /<table(?=[\s>])[^>]*>/g
  let m
  while ((m = re.exec(text)) !== null) {
    if (TABLE_CLASSES.test(m[0])) continue
    const lineNo = text.slice(0, m.index).split('\n').length
    // A `<table>` named in a comment is prose, not markup.
    if (/^\s*(\/\/|\*|\/\*)/.test(text.split('\n')[lineNo - 1])) continue
    add(file, lineNo, 'table-unstyled', '<table>',
      '<table> without a house table class → className="data-table" in a panel or card, cluster-table/list-table for a page list')
  }
}

// 10. A prose block: a contiguous run of static JSX text over PROSE_LIMIT
//     characters. The owner's complaint (2026-10-11) was UI work that "just
//     dumps a lot of text" — data written as sentences and how-it-works
//     explanation printed in the layout (anti-patterns.md, "Document-shaped
//     UI"). ~160 characters is two lines of a card body, the budget there.
//
//     Narrowed for precision: only text between a `>` and a `<` with no `{`
//     in it, so a JSX comment, an expression or code inside braces is never
//     read as copy, and runs with code punctuation or no three consecutive
//     words are skipped. That misses prose split by `{expr}` interpolations
//     and copy held in string constants — the review skill catches those. The
//     sign-in screens are verbatim transcriptions (see LITERAL_COLOUR_EXEMPT).
//     The escape is a `prose-ok: <reason>` comment within the three lines
//     above, for the cases the ruleset exempts (an irreversible dialog's
//     consequence statement); the review skill checks that the reason holds.
const PROSE_LIMIT = 160
for (const full of walk(srcRoot)) {
  const file = relative(webRoot, full).split(/[\\/]/).join('/')
  if (!/\.tsx$/.test(file) || /\.test\./.test(file) || file.startsWith('src/pages/login/')) continue
  // Comments blanked to spaces (newlines kept, so line numbers hold): a tag
  // named inside a comment, like "<details>", is not markup around copy.
  const raw = readFileSync(full, 'utf8')
  const text = raw.replace(/\/\*[\s\S]*?\*\//g, (c) => c.replace(/[^\n]/g, ' '))
  const lines = raw.split('\n')
  const re = />([^<>{}]*?)</gs
  let m
  while ((m = re.exec(text)) !== null) {
    const run = m[1].replace(/\s+/g, ' ').trim()
    if (run.length <= PROSE_LIMIT) continue
    if (/[;=]|=>|\breturn\b|\bconst\b|\/\/|\/\*|\*\//.test(run)) continue
    if (!/[a-z]{3,} [a-z]{3,} [a-z]{3,}/i.test(run)) continue
    const lineNo = text.slice(0, m.index).split('\n').length
    if (lines.slice(Math.max(0, lineNo - 4), lineNo).some((l) => /prose-ok:\s*\S/.test(l))) continue
    // Keyed on the run's opening words, not its line, so the baseline survives edits elsewhere.
    add(file, lineNo, 'prose-block', run.slice(0, 48),
      `${run.length} characters of static copy → draw the data (components.md "Choosing the encoding"), or move the explanation behind a HelpTip/<details>`)
  }
}

// 8. Zoom disabling, in index.html.
try {
  const html = readFileSync(join(webRoot, 'index.html'), 'utf8')
  html.split('\n').forEach((line, i) => {
    if (/user-scalable\s*=\s*no|maximum-scale\s*=\s*1(?![0-9.])/.test(line)) {
      add('index.html', i + 1, 'zoom-disabled', 'viewport',
        'zoom disabled → remove user-scalable=no / maximum-scale=1')
    }
  })
} catch {
  // No index.html is not a design finding.
}

// ---------------------------------------------------------------------------
// Baseline comparison
//
// Keyed on file+rule+value, NOT line number, so ordinary edits that shift lines do not spuriously
// "fix" or "break" the baseline. Counted, so a second identical violation in the same file is still
// caught. Known limit, stated rather than hidden: a new violation with the same value in the same
// file as a baselined one is masked.
// ---------------------------------------------------------------------------

const key = (f) => `${f.file}|${f.rule}|${f.value}`

if (updateBaseline) {
  const counts = {}
  for (const f of findings) counts[key(f)] = (counts[key(f)] ?? 0) + 1
  writeFileSync(
    baselinePath,
    JSON.stringify(
      {
        _comment:
          'Pre-existing design-system violations, recorded so design-lint fails only on NEW drift. ' +
          'Do not add entries to silence a new finding — fix it instead. ' +
          'Regenerate only when genuinely paying debt down: node scripts/design-lint.mjs --update-baseline',
        counts,
      },
      null,
      2,
    ) + '\n',
  )
  console.log(`design-lint: baseline written with ${Object.keys(counts).length} entries (${findings.length} findings)`)
  process.exit(0)
}

let baseline = { counts: {} }
try {
  baseline = JSON.parse(readFileSync(baselinePath, 'utf8'))
} catch {
  console.log('design-lint: no baseline file; treating every finding as new.')
}

const remaining = { ...(baseline.counts ?? {}) }
const fresh = []
for (const f of findings) {
  const k = key(f)
  if (remaining[k] > 0) remaining[k] -= 1
  else fresh.push(f)
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

const baselinedCount = findings.length - fresh.length

if (fresh.length === 0) {
  console.log(`design-lint: ✓ pass — no new findings (${baselinedCount} baselined in design-lint-baseline.json)`)
  const stale = Object.entries(remaining).filter(([, n]) => n > 0)
  if (stale.length) {
    console.log(
      `design-lint: ${stale.length} baseline entr${stale.length === 1 ? 'y' : 'ies'} no longer ` +
        'triggered — debt was paid down. Re-run with --update-baseline to shrink the baseline.',
    )
  }
  process.exit(0)
}

const byFile = new Map()
for (const f of fresh) {
  if (!byFile.has(f.file)) byFile.set(f.file, [])
  byFile.get(f.file).push(f)
}

console.log('')
for (const [file, items] of [...byFile.entries()].sort()) {
  console.log(`## ${file}`)
  console.log('')
  for (const f of items.sort((a, b) => a.line - b.line)) {
    console.log(`${f.file}:${f.line} - ${f.message}`)
  }
  console.log('')
}

console.log(
  `design-lint: ${fresh.length} new finding${fresh.length === 1 ? '' : 's'} ` +
    `(${baselinedCount} pre-existing, baselined).`,
)
console.log('Rules: .claude/skills/argus-design-system/reference/ — fix the cause, do not extend the baseline.')
process.exit(1)
