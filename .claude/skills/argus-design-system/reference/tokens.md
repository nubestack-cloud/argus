# Tokens — the rules, not a second copy of the values

**`web/src/index.css` is the only source of truth for values.** This file deliberately does not
restate the ~100 hex values in it. A copy here would be a second source of truth that drifts the
first time somebody edits a token, and nothing would detect the divergence — so what lives here is
the *rules about* the tokens, plus the handful of **measured findings** you cannot re-derive by eye.

Read the top ~200 lines of `index.css` before designing. That is the token block, and it is
commented with the reasoning behind specific values.

---

## The scales, by name

Every value in a design comes from one of these. If you need something not on a scale, add a token
with a comment saying why — never a literal at the call site.

| Scale | Tokens | Notes |
|---|---|---|
| Surfaces | `--bg`, `--surface`, `--surface-sunken` | Three levels. There is no fourth; a "card on a card on a card" is a layout problem, not a missing token. |
| Text | `--text`, `--text-muted` | Two. A third greyer level is how illegible small type happens. |
| Borders | `--border`, `--border-strong` | |
| Action | `--accent`, `--accent-hover`, `--accent-text`, `--focus-ring` | `--accent-text` is **not** white — it is `#ffffff` in light and near-black in dark. Hardcoding white breaks dark mode. |
| Danger | `--danger`, `--danger-bg` | |
| Status hues | `--color-{green,amber,blue,gray,orange}` + matching `-bg` | Text/label colours, deliberately dark for legibility at small sizes. |
| Chart fills | `--chart-{critical,high,medium,low,neutral,info}` | Marks and fills, spread by **lightness**. That spacing keeps each severity apart from its immediate neighbour in the ordinal ramp (critical/high/medium/low are each ≥1.4:1 apart from the next), but it is **not** a greyscale or colour-vision-deficiency guarantee across the whole set: measured pairwise (WCAG relative luminance), four dark-mode pairs sit under 1.1:1 — `--chart-high`/`--chart-info` 1.02:1, `--chart-high`/`--chart-low` 1.04:1, `--chart-critical`/`--chart-neutral` 1.07:1, `--chart-low`/`--chart-info` 1.06:1 — indistinguishable in greyscale and close to it under most colour-vision deficiencies, since those are luminance-based failures. Two light-mode pairs are likewise under 1.1:1. Do not rely on lightness alone to tell any two of these fills apart. The rule below — colour is never the sole carrier of severity — holds everywhere a severity is shown as a mark, with **one deliberate exception the owner decided on 2026-09-19**: the per-day segments of Overview's "Incidents opened" chart. A segment there carries no text and cannot be given one (a critical band is ~19px on the tallest bar; a one-incident day is ~10px in total), so a reader who cannot separate these fills loses which DAY a severity fell on. They do not lose the counts: every bar prints its total, the chart's legend gives each severity's window total as word + dot + count, and the per-day split is in the hover title and the accessible description. Treat that chart as the exception it is — do not cite it as precedent for a second one, and do not silently "fix" it back. |
| Spacing | `--space-1` … `--space-6` | Padding, gaps between text and controls, everything that is not box-to-box. |
| Box spacing | `--gap-box` (16px), `--gap-row` (8px) | **The only two gaps between boxes, on every page** (owner, 2026-10-12). Boxes laid out on a page — cards, tiles, panels, side by side or stacked — are `--gap-box` apart, whether the gap comes from a container's `gap` or a box's margin. Boxes stacked inside another box (queue rows, list entries, finding groups) are `--gap-row` apart. A measured sweep of 44 pages had found 6, 12, 14 and 16px for the same relationship. A `--space-*` value, or a literal, between two boxes is a finding. |
| Type | `--font-size-xs` … `--font-size-2xl`, `--font-mono` | |
| Radii | `--radius-sm`, `--radius-md`, `--radius-lg`, `--radius-full` | |
| Shadows | `--shadow-sm`, `--shadow-md` | Two. Depth is not a hierarchy device here — see `anti-patterns.md`. |
| Layout | `--sidebar-width`, `--sidebar-collapsed-width`, `--page-max`, `--page-gutter` | |

**Text colours and chart fills are not interchangeable.** `--color-*` is for type; `--chart-*` is for
marks and fills. Using one for the other's job is the specific mistake index.css's own comments were
written to prevent.

---

## Both themes are first-class; light is the default

`:root` is light. Dark is applied by a `prefers-color-scheme` block guarded
`:root:not([data-theme="light"])`, plus an unconditional `:root[data-theme="dark"]` block so an
explicit user choice wins in both directions (`web/src/theme.ts`). Both token sets are
first-class rather than dark being a layer on top, and that is what the rule below protects.

**The rule:** every colour resolves to a token, and you check your work in dark mode. A hardcoded
white or a literal hex is invisible in light mode and obviously broken in dark, which is why it ships.
HLD §15.3 calls dark mode "non-negotiable for a 3am tool."

---

## Severity — the safety-critical decision, and the one to get right

Severity is carried by a class on a **container**, which sets two custom properties the children
read. The class goes on the container, not the mark:

```
.sev-critical → --sev-fill: var(--chart-critical); --sev-tint: var(--danger-bg)
.sev-high     → --chart-high    / --color-orange-bg
.sev-medium   → --chart-medium  / --color-amber-bg
.sev-low      → --chart-low     / --color-green-bg
.sev-neutral  → --chart-neutral / --color-gray-bg
```

`--sev-neutral` is **not a fifth level.** It is "severity not computed yet" — an incident that still
needs a dot. Rendering an uncomputed severity as `low` is a fabricated fact of exactly the kind
`anti-patterns.md` bans.

### Severity may never be carried by colour alone

WCAG 2.1 AA. A coloured rule, dot or halo is an
**addition to the word**, never a replacement for it. Two consequences people miss:

1. It keeps the column sortable and readable as text.
2. It is what makes the `--chart-medium` trade below acceptable.

**When checking this rule, read the whole row or component, not the single element.** A coloured
left rule with the severity named in an adjacent cell is compliant. `web/src/pages/UsersPage.tsx:956`
is the worked example: a `borderLeft` coloured by highest role, with the role named in text by
`GrantBadge` in the same row. Flagging that is a false positive.

---

## Three measured findings — do not re-derive these by eye

Each was established with a validator, not judgement. They are findings, not preferences.

1. **`--chart-medium` sits at 1.67:1 against a light surface.** This is a known, accepted trade, not
   an oversight. Every darker yellow tested collapsed its separation from `--chart-high` — ΔE 14.6
   falling as low as 0.8 under deuteranopia. The compensation is mandatory: **anything using
   `--chart-medium` carries a direct label or count**, never colour alone.

   *"Direct" means readable without an interaction, and attached to the mark or its row* — a value on
   the segment, or a legend entry naming and counting that series. A `title` tooltip does **not**
   satisfy it (hover-only, unreachable by keyboard and touch). A legend that totals the whole window
   satisfies the rule for the window, not for an individual segment whose own value is unstated.
2. **Series order changes colourblind separation — for *categorical* palettes.** Green adjacent to
   orange fails at ΔE 6.7 under protanopia; reordering to **green / blue / orange** moves the worst
   adjacent pair to 27. Order there is a design decision, not an accident of iteration order.

   **This does not apply to the severity ramp.** critical → high → medium → low is *ordinal* and its
   order is semantic — reordering it to improve ΔE would be worse, not better, because the sequence
   itself is the information. The severity ramp is spread by lightness for exactly this reason, so it
   survives greyscale without needing a hue reshuffle. Apply finding 2 only where the series have no
   inherent order.
3. **`system-ui` here resolves to roughly two usable weights.** *(Updated 2026-10-10: the UI face is
   now IBM Plex Sans with real 400/500/600 statics, so headings are 600 and the weights DO render
   differently — but the system stack is still the fallback when the font files are absent, so the
   rule below still holds: weight is never the only thing separating two states.)* A design that separates states with
   500 / 600 / 650 / 700 will render two of them identically. Carry state with **colour and
   position**; use weight only for the coarse split between furniture and prose.

If you add a categorical palette, validate it — the `dataviz` skill ships a runnable checker. Do not
eyeball it.

---

## Type

- The scale is `--font-size-xs` … `--font-size-2xl`. Nothing between the steps.
- **Numbers that get compared are `font-variant-numeric: tabular-nums`.** A column of counts that
  jitters is harder to scan, which is the one thing this UI exists to be good at.
- `--font-mono` for identifiers, object names, versions, diffs, and anything a user might copy.
- **The typeface is IBM Plex Sans (`--font-sans`) and IBM Plex Mono (`--font-mono`)**, self-hosted
  from the pinned `@fontsource/ibm-plex-sans` / `@fontsource/ibm-plex-mono` packages via `@import` at
  the top of `index.css` (Sans 400/500/600, Mono 400/500). **Never link Google Fonts or any CDN** —
  ARGUS runs air-gapped and the hub must render with no outbound network. A new weight is a new
  `@import` line, not a `<link>`.

**No off-scale `font-size` remains.** The 13 literals once baselined as debt were snapped to the
scale, so `design-lint` fails on any new one outright. What `web/scripts/design-lint-baseline.json`
still holds is `prose-block` debt (`PROJECT.md` `UX12`). **Do not add to the baseline to silence a
finding.**

`em` is not on this scale and is not meant to be — it is *relative* sizing, correct for inline code
and labels that should scale with their container. The linter only flags `rem` and `px`.

---

## Declared exceptions — how a literal is allowed to exist

There is a mechanism for this, and using it is not cheating. `design-lint`'s
`LITERAL_COLOUR_EXEMPT` map takes a file path and a **reason string**; a file in it may carry literal
colours. The rule is that the reason has to be a real one, and the list stays short.

What is in it today:

- **`web/src/components/icons.tsx`** — the ARGUS mark. A brand mark must **not** recolour with the
  theme, and its geometry is identity rather than decoration.
- **`web/src/pages/login/*.tsx`** — the three sign-in screens, verbatim transcriptions of supplied
  design files. Their literals are inline SVG fills in hand-drawn artwork (an aperture mechanism, a
  tick ring, a vignette), and swapping any of them for a token changes the drawing.

The distinction that makes this a rule rather than a loophole: **artwork versus surface styling.** A
literal inside a drawing is the drawing. A literal on a panel, a border, a label or a chip is drift,
and no reason string will make it otherwise — put that in a scoped custom property instead, which is
how the three login modules declare their own palettes.

Two things that are *not* exceptions and do not need one:

- **A scoped palette.** `--x: #abc` is legal anywhere, including in a `.module.css`: the linter's
  colour rule only reads `src/index.css`, and a custom-property *declaration* is where literals are
  supposed to live.
- **Verbatim design CSS** in a co-located `.module.css`. The linter does not read those files at
  all. That is deliberate, not an oversight — see `anti-patterns.md`'s note on glassmorphism.

Do not generalise from the artwork exception to decoration: a gradient used as surface treatment on
an operational screen is still a finding.
