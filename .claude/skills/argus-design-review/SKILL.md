---
name: argus-design-review
description: Audits already-written ARGUS frontend code against the design system, reporting findings as file:line. Use after ANY change under web/ that a user will see — building or restyling a page, component or chart, adding or editing a control, badge, table, empty state or error state, changing how a value is rendered, or fixing a small frontend bug. Also use when the user asks for a UI/UX review, design QA or accessibility pass, asks to check a screen against the design system, or says a screen "looks off", is too wordy, or reads like a document and you need to find out why. Scale the pass to the change: a one-line fix needs the safety-critical set and design-lint, not a full audit.
---

# Reviewing ARGUS frontend code against the design system

**This skill deliberately contains no design rules.** The ruleset lives in
[`argus-design-system/reference/`](../argus-design-system/reference/) and is shared with the skill
that generates the UI, so the checker cannot drift from the generator. Update rules there; update
check *logic* here.

Visual counterpart to [`argus-review`](../argus-review/SKILL.md) (build/test/status hygiene). Run
both — neither covers the other.

**This review reports; it does not block.** Findings go to a human to weigh. The mechanically
checkable subset *is* enforced, by `web/scripts/design-lint.mjs` in CI — see step 1.

## Before anything: which surface is this?

`argus-design-system/SKILL.md` splits the app into **operational** and **presentation** surfaces, and
half this skill's rules only apply to the first kind. Get this wrong and the review is worse than
useless — a pass over the three sign-in screens that treats them as operational screens produces
dozens of findings, every one of which is the design the owner chose.

- **Operational** (incident detail and list, clusters, approvals, insights, audit, settings): the
  full ruleset, austerity included.
- **Presentation** (login, first-run, onboarding, pre-data empty states): review **only** the
  never-relax set — honesty, access, accessibility, colour-alone status, real data — plus whether the
  screen does what the owner asked. Ornament, density and "does this earn its place" are not findings
  here. Say in your report which surface you assessed as what.
- **A verbatim transcription of a supplied design** is not reviewable as a design at all. Review the
  never-relax set and the *fidelity* of the port. "This card is translucent" is not a finding when
  the source file is translucent and the owner picked it.

## How it works

1. **Run the deterministic linter first:** `cd web && npm run design-lint`. It covers what is
   genuinely mechanical (off-scale sizes, literals outside the token block, `transition: all`,
   `outline:none` without `:focus-visible`, zoom-disabling, status-bearing glyphs, unstyled tables,
   and `prose-block`: a contiguous run of static JSX text over ~160 characters). Report its actual
   output — never a remembered or reasoned number. Everything it catches is already caught, so spend
   your attention on what it cannot see.
2. **Load the ruleset.** Read the reference files relevant to the diff — all four for a whole-screen
   review:
   - `../argus-design-system/reference/tokens.md` — scales, severity mapping, the three measured findings
   - `../argus-design-system/reference/components.md` — vocabulary, the four states, approval gates, charts, layout resilience
   - `../argus-design-system/reference/screens.md` — the six modes, the four-question standard, verified data gaps
   - `../argus-design-system/reference/anti-patterns.md` — the named bans
3. **Read the changed files.** If none were named, ask which, or diff against `main`.
4. **Check each rule against the code**, not against what you remember intending.
5. **Report as `file:line`.**

## Output format

Group by file. `file:line` is required, and the reason is that it is clickable in the editor — do not
"improve" it into prose. Terse fragments, not sentences. State the issue and where; skip the
explanation unless the fix is non-obvious. No preamble.

```
## web/src/pages/OverviewPage.tsx

web/src/pages/OverviewPage.tsx:412 - severity dot with no text label (tokens.md: never colour alone)
web/src/pages/OverviewPage.tsx:517 - tile count over capped list, window unstated (anti-patterns.md)
web/src/pages/OverviewPage.tsx:688 - no distinct empty state; filtered-empty reads as never-had-data

## web/src/components/RemediationPlanCard.tsx

web/src/components/RemediationPlanCard.tsx:96 - blocked action hidden, not disabled (anti-patterns.md)

## web/src/components/Skeleton.tsx

✓ pass
```

Every rule cited by file, so a finding is arguable rather than a matter of taste. **A clean file is
still listed, with `✓ pass`** — silence is not an allowed output, because "I did not look at it" and
"it was fine" must be distinguishable.

Order findings most serious first, in these bands:

1. **Safety-critical** — the five below.
2. **Structure** — the four-question order, wrong mode, a missing or undistinguished empty state.
   This band exists because it was learned the hard way: a review that lumped structure into "layout
   and polish" buried *the single most consequential finding on the core screen* (closing controls
   rendered above the causal chain) beneath a tooltip nit. Structural faults are invisible to any
   element-level check — every individual component can be well-built while the page is assembled in
   the wrong order — so they outrank everything except the safety-critical set. **A document-shaped
   screen is a structural finding**, not polish: data written as sentences, explanation printed
   in the layout, no dominant element. It is the failure the owner has named most often, and it
   survives every element-level check.
3. **Honesty** — fabricated zeroes, unlabelled partials, overstated labels, contradictory claims.
4. **System-forking** — literals, off-scale values, pre-refresh namesakes, hand-rolled primitives.
5. **Polish** — spacing, hover-only text, wording.

## Precision beats volume — the traps that produce false positives

**These were established by running the naive checks against this codebase, where they produced 12
false positives and 0 true ones.** A review that cries wolf gets ignored, which is worse than no
review. Check each of these before reporting:

| Looks like a violation | Why it usually is not |
|---|---|
| Hex literals in `components/icons.tsx` | The ARGUS **logo**. A brand mark must *not* recolour with the theme, and its gradient is identity, not decoration. Sanctioned exception (`tokens.md`). |
| A hex-shaped string anywhere | Check it is a colour. `#4412` in `UsersPage.tsx` is a ticket number in placeholder text. |
| A coloured `borderLeft` / rule / dot with no adjacent label | **Read the whole row or component, not the element.** `UsersPage.tsx:956` colours a rule by highest role and names the role in text via `GrantBadge` in the same row — compliant. Colour *plus* text is the required pattern; colour alone is the violation. |
| A `✓` or similar glyph | Decorative with `aria-hidden="true"` beside real text is fine (`OverviewPage.tsx:1241`). Carrying status in a bare unlabelled glyph is the finding (`RepositoriesCard.tsx:145`). |
| Hex values inside CSS comments | index.css documents which mockup literal each token replaced. Comments are not rules. |
| An inline `style={{}}` | Legitimate for computed geometry — positions, percentage widths, grid spans. A finding only when it carries a *colour or size* that should be a token. |
| A gradient | Data-bearing ramps (heatmaps) and the logo are fine. Surface decoration on an *operational* screen is not. On a presentation surface a gradient may be the design — check the surface class first. |
| Literal colours in `web/src/pages/login/*` | Verbatim transcriptions of supplied design files; the literals are inline SVG artwork. Sanctioned in the linter's `LITERAL_COLOUR_EXEMPT` with a reason (`tokens.md`). |
| A `.module.css` full of values that are not tokens | Co-located design CSS, moved verbatim on purpose. The linter does not read these files by design. Retyping those values as tokens is the bug, not the fix. |
| A `prose-block` lint hit, or a long run of text | Check what the text *is*. AI-authored content (`AiClaim`), log/YAML views, and server-provided reasons are the data itself. A confirmation dialog's consequence statement for an irreversible action is allowed to three sentences when marked `prose-ok:` with a reason. Explanation of how a feature works is never exempt, whatever the comment says. |
| `backdrop-filter`, a vignette, a full-bleed canvas, a display face | On a presentation surface, check for a **declared exception** comment at the point of use. If it says it is deliberate and whose call it was, it is compliant. |
| A shared app class on a dark-committed screen, overridden locally | `.app-header-brand` sets `color: var(--text)` — near-black in light mode, invisible on a dark card. A two-class local override is the correct fix, not a smell. |

When unsure whether something is a violation, say so and cite what you checked — a hedged finding
with evidence is useful; a confident wrong one costs the review its credibility.

## What the linter cannot see — where to actually spend attention

The mechanical subset is automated. These need judgement, and they are where the real findings are:

- **Is it a document?** (`anti-patterns.md`, "Document-shaped UI"; `components.md`, "Choosing the
  encoding"). Do this before the element checks, because it changes what the other findings are
  about:
  1. **Inventory the facts.** List every fact the screen shows and the form it is shown in. Each
     fact written as a sentence that has a shape in the encoding table is one finding, phrased as
     the fix: `ClusterDetailPage.tsx:512 - "3 of 5 replicas ready" in prose → .replica-bar`.
  2. **Count the static prose.** Static copy above ~160 characters in a card body, a page subtitle
     over one line, or an empty state over one sentence. The `prose-block` lint catches the
     contiguous case; you catch the runs split by `{expr}` interpolations, string constants rendered
     as copy, and several short `<p>`s stacked into one essay.
  3. **Find what explains rather than labels.** It moves behind a `HelpTip` or a `<details>`. Copy
     that names an endpoint, a table, an internal mechanism, or says "deliberate" / "by design" /
     "note that" is a code comment that escaped into the UI.
  4. **Name the dominant element**, from `screens.md`'s per-mode table. Report it if the screen has
     none, or a uniform card wall (the same `h3` + paragraph + list repeated), or a dominant element
     that is not the one answering the screen's question.

  With a screenshot, do the blur test: squint, or look at the thumbnail. Say what the eye lands on
  first. If it is a block of grey text, that is the headline finding of the review.
- **The four-question order** (`screens.md`). Does the screen answer what's broken → why → how to fix
  → what happened, *in that order*? Closing controls above the explanation is backwards.
- **The mode.** Is a worklist behaving like a dashboard? Is a triage list leading with pills instead
  of identity? Is a first-run empty state written for someone who already knows the product?
- **Honesty.** Fabricated zeroes, unlabelled partials, overstated labels ("verified" where one field
  was re-read), an empty chart implying zero, a refusal rendered smaller than a success.
- **The four states.** A populated and loading state with no *distinct* empty state is the most common
  half-built case here — "no results for this filter" vs "nothing exists yet".
- **Invented data.** Every number should trace to a real field. If you cannot name the endpoint, it is
  fiction — and check `screens.md`'s gaps table, because several plausible metrics (MTTR,
  time-in-state, resolved-this-week) genuinely cannot be computed today.
- **Earning its place.** Repetition, near-identical rows that should collapse to a count, marks that
  encode nothing.
- **Dark mode**, at 1440 / 1024 / 768 / 375, and long unbroken values (`v1.31.4+rke2r1`) not spilling.

## Two things to be honest about in your own report

**You cannot verify a rendered result by reading code.** The dark-mode and responsive checks above
need a browser, and a frontend change is not even servable until the hub is rebuilt (`go:embed`).
Reading CSS finds a missing `min-width: 0` or a grid with no breakpoint below it; it does not find a
visual break. **Say which checks you performed by reading and which you did not perform at all** —
that is the same honesty standard this ruleset imposes on the UI, applied to the review. Do not report
"checked at 375" if you did not look at 375.

**A code comment asserting compliance is evidence of intent, not of compliance.** This codebase is
written in a style where comments cite the very rules you are checking ("never a fabricated 0", "a
skeleton matching the eventual layout"). Read them for *why* the code is shaped that way — they often
contain a sanctioned exception you would otherwise misreport — but verify the claim against the code.
A comment saying the skeleton matches the layout does not mean it still does.

## The safety-critical set — never downgrade these to nits

**These apply on every surface, including the unauthenticated one.**

1. Severity, state or status carried by colour alone.
2. A capability-gated control hidden rather than disabled with the missing capability named.
3. A fabricated zero or an unlabelled partial presented as a fact.
4. Anything using `--chart-medium` without a direct label (it is 1.67:1 by accepted trade).
5. An asserted root cause with no path to the evidence beneath it.
6. **A number, chart, feed or status on a screen that cannot know it.** Counters animating to
   "1,284 clusters watched", a `Math.random()` sparkline labelled "last 60 min", an invented incident
   stream, a compliance badge. Pre-authentication this is also a disclosure rule: the hub must not
   reveal a cluster name, a count or a heartbeat to an anonymous visitor.
7. **A control with no flow behind it** — a reset link with no reset, a checkbox with no setting.
8. **Progress that is not measured.** A staged label sequence or progress bar on a timer rather than
   on the request. One of these reported a successful sign-in while the host was unreachable.
9. **Body text below its contrast floor on a dark-committed surface.** Two supplied designs shipped
   at roughly 2.2:1 and 3:1. A committed palette does not exempt a contrast check; it removes the
   theme that would otherwise have caught it.

## Before reporting done

`cd web && npm run build` (the authoritative typecheck here — **not** `npx tsc --noEmit`, which has
missed real errors in this repo), plus `npm run lint`, `npm test` and `npm run design-lint`, all clean.

Then the one that gets skipped: **a frontend change is not servable until the hub container is
rebuilt**, because the UI is compiled in with `go:embed`. `npm run build` alone changes nothing a
browser will see. Either rebuild and look at it, or say plainly that you did not — this repo has
shipped fully-tested UI that did nothing in the running configuration.
