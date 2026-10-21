---
name: argus-design-system
description: ARGUS's visual and interaction design language — the tokens, component vocabulary, per-screen layout modes and named anti-patterns this codebase has already established. Use for ANY change under web/ that a user will see, not only redesigns: designing, restyling, modernising or improving a screen, page, dashboard, chart, layout or component; adding or editing a control, badge, table, empty state or error state; changing what a screen displays or how a value is rendered; asking for a mockup; or saying the UI looks dated, cluttered, generic, boring, text-heavy or like a document. Drives data-first layouts: a fact with a shape is drawn (rings, bars, rails, maps, timelines), not written. Also use when fixing a small frontend bug, since the same rules decide whether the fix is right. Pairs with argus-add-screen for the plumbing (routing, RBAC, data fetching) and argus-design-review for the pre-delivery check.
---

# Designing an ARGUS screen

**When to use which skill.** This one is for *what it looks like and what belongs on it*.
[`argus-add-screen`](../argus-add-screen/SKILL.md) is the plumbing — routing, RBAC, TanStack Query,
error rendering. [`argus-design-review`](../argus-design-review/SKILL.md) is the check you run before
calling the work done; it reads the same four reference files this skill does, so it cannot disagree
with it. Apply [`argus-context`](../argus-context/SKILL.md) first for the architectural rules.

## First: which surface are you on?

**This used to be one doctrine applied to every pixel in the app, and that was wrong in a way that
cost real work.** Read this section before the rest of the file; it decides which of the rules below
bind you.

### Operational surfaces — the reason this design system exists
Incident detail, incident list, cluster list and detail, the approval queue, insights, audit log,
settings. Someone is reading dense data under time pressure and deciding whether to let a machine
change production.

Here the austerity is the whole point: **do not take an aesthetic risk, do not look for a signature
element, spend nothing on distinctiveness — spend all of it on information design.** What earns
space, what order the questions come in, what the screen refuses to claim. Visual boldness is a cost
here, not a virtue, and the bar for any element is *"what decision does this support?"* — never *"does
this fill the space?"*

**Austerity is not the same as text.** Removing ornament does *not* leave a page of paragraphs. The
information design is the graphics: rings, bars, rails, chains, maps, timelines, tables with
severity on the edge. The most common way UI work here has failed is the opposite of ornament: a
screen built as a document. Each section was an `h3` and a paragraph explaining what the operator
was looking at, and the data was written out in sentences instead of drawn. The owner's words
(2026-10-11) were "just dump a lot of texts in ui and no real thinking behind on how to well structure
and how to graphically represent data without making it a document". On an operational surface:

- **Data that has a shape is drawn.** A part of a whole, a used/limit ratio, a position in a flow, a
  cause and effect, a connection, a time series. `reference/components.md`'s "Choosing the encoding"
  table maps each shape to the primitive that draws it.
- **Explanation goes behind a `HelpTip` or a disclosure**, never into the layout. The operator reads
  it once and scans past it on every later visit.
- **Text is the residue**: names, status words, a one-line reason, a consequence. Over two lines of
  static copy in a card is a finding (`reference/anti-patterns.md`, "Document-shaped UI";
  `design-lint`'s `prose-block`).

### Presentation surfaces — where that inverts
The sign-in screen, first-run and onboarding, empty states someone meets before they have data, and
any page whose job is to introduce the product rather than to be operated.

**There is no 3am operator on these screens, so the reasoning above does not reach them.** Nobody is
scanning for the one row that matters; often there is no data at all, and on the unauthenticated
surface there is no data the hub is *permitted* to show. Applying operator austerity there produces a
screen that is plain for no reason, and the owner will say so — they did, twice, in the session that
prompted this section being written.

On a presentation surface, expressiveness is legitimate: motion, a hero graphic, a committed dark
palette, a typeface the app bar would never use. What does **not** relax is the second list below.

### The rules that never relax, on any surface
Everything in `anti-patterns.md` under **Honesty** and **Access and interaction**, plus:
accessibility (contrast floors, `prefers-reduced-motion`, focus-visible, no zoom-disabling), never
carrying severity or status by colour alone, and never inventing a number. A pretty screen that
fabricates a figure is a worse bug than an ugly one, and a presentation surface is exactly where
invented data creeps in — a supplied mockup will happily count up to "1,284 clusters watched" on a
page shown to anyone who can reach the login URL.

## Extending versus generating versus transcribing

**On operational surfaces: extend the system, do not generate one.** `web/src/index.css` holds a full
token set and a ~60-class component vocabulary, heavily commented, with a complete dark mode. Some of
its values encode **measurements you cannot re-derive by eye** (`reference/tokens.md`, the three
findings). A new palette, a new type scale or a hex literal on one of those screens is wrong even if
it is pretty.

**On presentation surfaces: a new palette may be exactly the deliverable.** Scope it — a
`.module.css` or a class-scoped block, not the global token set — and say in a comment that it is
scoped and why. The three sign-in styles each commit to their own dark palette this way, declared as
custom properties at the top of their own module, and the app's authenticated surface is untouched.

**When the owner supplies a design, the job is TRANSCRIPTION, not design.** This is the case this
skill previously had nothing to say about, and the silence was expensive: given three finished HTML
mockups, the sensible-looking move is to read them, form a mental summary, and rebuild them out of
ARGUS parts. That produces three screens that compile, look plausible, and are a different design —
which is what happened, and it was rejected twice before the files were transcribed properly.

If a design arrives as working HTML/CSS:
- Move the CSS **verbatim** into a co-located `.module.css`. Do not retype values, substitute easing
  curves, round numbers, or swap literals for tokens whose hex differs.
- Convert markup structurally only — `class`→`className`, `for`→`htmlFor`. Keep the DOM order and
  nesting: sibling selectors (`input:focus + label`, `:focus-within`, `.tile:nth-child(3)`) break
  silently when the tree is "tidied".
- Port imperative animation as imperative animation. A canvas particle field does not become CSS.
- Then apply the never-relax list above, and **declare every deviation** — which is where the
  honesty work lands: the invented metrics, the fabricated log feed, the "SOC 2 · ISO 27001" footer,
  the staged fake progress bar that reported success while the host was unreachable.

## This applies to small changes too — scaled, not skipped

UI cohesion work is limited to concrete operator workflow problems rather than broad visual churn.
That bounds how much gets rebuilt. It does not lower the bar for a change you make on one of those pages today, and it is not permission
to fabricate a zero, hide a control the viewer lacks capability for, carry severity in colour alone,
or invent a class instead of reusing the vocabulary. **Scope is how much you change; quality is how
you change it.**

So the two passes below **scale with the change** rather than being all-or-nothing — a rule nobody can
follow on a one-line fix is a rule that gets skipped entirely, which is worse than a smaller one that
gets followed:

| Change | What is actually required |
|---|---|
| A new **operational** screen, or one restyled | Both passes in full, written down. |
| A new control, card, chart, table or state on an existing screen | Slots 3, 4 and 6 (primitives by name, the four states, and the fact → shape list), plus the decoration and document tests. |
| A one-line fix, a copy change, a value rendering | No plan. Just the failure modes at the end of this file (a copy change is where failure mode 8, the document, creeps in a sentence at a time), and `npm run design-lint`. |
| **Transcribing a supplied design** | No plan — the plan is the source file. Read it in full first, then the never-relax list and your declared deviations. A design critique of someone else's finished design is not the assignment. |
| **A visual iteration the owner is driving** ("make it bigger", "that colour is unreadable", "move the logo") | No plan, no critique pass. Make the change, check contrast and both themes if colour moved, ship it. The owner is the review loop; adding a written gate to each round just slows the round. |

That last row matters more than it looks. A long back-and-forth on a presentation surface is
*dozens* of one-line changes, and running a two-pass design gate on each one converts a ten-minute
loop into an afternoon. The gate exists to stop a screen accumulating cards nobody asked for — it
has nothing useful to say about "the byline should left-align to the A".

The one thing that never scales down: if the change touches a **number, a status, or a control the
viewer may not use**, check the honesty and access rules in `reference/anti-patterns.md` before
shipping it. Those are where this codebase's real bugs have been.

## Before you write any code: commit, then critique

Two passes. The critique happens *before* the code, and skipping it is how a screen accumulates cards
nobody asked for.

**Pass 1 — commit, in writing.** Short, but every slot filled:

1. **Mode.** Which of the six in `reference/screens.md` (triage scan / single-object argument /
   worklist / fleet aggregate / configuration / first-run-empty). Modes want different things; a
   screen with no named mode defaults to a tile row and a table.
2. **The one question this screen answers.** One sentence. If it takes three, it is three screens or
   you have not decided.
3. **Tokens and primitives you will use**, by name, from `reference/tokens.md` and
   `reference/components.md`. Naming them is how you notice you were about to invent one.
4. **What each element is doing there** — and the four states (populated / loading / empty / error)
   for anything data-bearing.
5. **What you cannot build honestly**, from `reference/screens.md`'s verified gaps table.
6. **The fact → shape list.** Every fact the screen shows, one per line, with the primitive that
   draws it, from the "Choosing the encoding" table in `reference/components.md`. Example:
   `pods by phase → Ring`, `CPU used vs allocatable per node → resource-usage bar`,
   `incident chronology → .tl-* timeline`. Any fact whose shape is "paragraph" needs a reason
   (it is a reason, a name or a consequence), or it is a figure you have not drawn yet.
7. **The sketch.** A wireframe of the layout at desktop width: ASCII boxes are enough. It shows
   where the dominant element sits (the one that answers slot 2, drawn largest), what is secondary,
   and what sits behind a tab, a disclosure or a `HelpTip`. A layout you cannot sketch in a few boxes
   is one you have not decided. Writing the JSX first and seeing what it looks like is how card walls
   are made.

   ```
   ┌ header: name · state word · freshness ─────────────── [primary action] ┐
   ├ ◯ Pods ring ┬ ◯ Workloads ring ┬ ◯ Nodes ring ┬ Resource use bars ─────┤  ← dominant row
   ├ Needs attention (severity edges) ──────┬ Changes histogram (1h) ───────┤
   └ Nodes table: name · role · CPU bar · memory bar · status word ─────────┘
   ```

**Pass 2 — critique the plan against three tests, then build.**

- *The invariance test* — **operational surfaces only.** Would a row's or panel's own content
  transfer unchanged to a project-management tool, a CRM, or a fitness app? If yes, it is a default
  rather than a decision.

  **Do not run this test on a presentation surface.** A credential form is *supposed* to be
  transferable — email, password, a submit button, providers below it. There is no ARGUS-specific
  insight to encode in a password field, and "make the login form less generic" is how you arrive at
  a login form with fabricated fleet statistics on it. What must not transfer is anything *claiming*
  to be this install's data.
  Work through what you would produce for a generic dashboard; if you arrive somewhere similar, revise
  that part and say what you changed.

  Test the **content**, not the silhouette — that distinction is load-bearing. Some ARGUS screens are
  legitimately shaped like their generic cousins: a queue of items awaiting a yes/no, ordered by
  priority, is a shape Jira also has, and condemning the shape would condemn the right answer. What
  does not transfer is what a row *carries* — a signed patch against a live object whose
  `resourceVersion` can move while you read it. If a row would survive a copy-paste into a CRM, it is
  not using its subject.
- *The decoration test:* every dot, rule, halo, chip and bar encodes severity, position in a flow, or
  what was checked. Anything that encodes nothing goes. Also check: is anything repeated? is any
  number invented? is the same count in two places?
- *The document test* — **operational surfaces only**, and the inverse of the decoration test.
  Read the sketch with the text blurred out, then answer three questions:
  1. Can you still tell what is wrong and where?
  2. Is there one dominant shape?
  3. Would the page make sense printed as an A4 handout?

  "No, no, yes" means it is a document. Then:
  - count the static sentences;
  - move every one that explains rather than labels behind a `HelpTip` or a `<details>`;
  - redraw every one that carries a number, a ratio, a sequence or a state, using the encoding
    table.

  Also look for a uniform card wall, the same `h3` + paragraph + list repeated down the page. That
  is the shape this test most often catches.

Only then write code, following the revised plan and deriving every colour and size from it.

## Reference files — read the one you need, not all four

| File | Read it when |
|---|---|
| [`reference/tokens.md`](reference/tokens.md) | Any colour, type, spacing or severity decision. Contains the three measured findings and the never-colour-alone rule. |
| [`reference/components.md`](reference/components.md) | Choosing or adding a primitive; the four states; the approval control's two gates; chart choice; layout resilience. |
| [`reference/screens.md`](reference/screens.md) | Picking the mode; the four-question standard; what cannot be computed today. |
| [`reference/anti-patterns.md`](reference/anti-patterns.md) | Before finalising anything. The named bans, and the calm-vs-dense resolution. |

## The things most likely to go wrong

Stated here because they are the actual observed failure modes, not hypotheticals:

1. **A hex literal, or a size between the scale's steps.** The off-scale `font-size` debt was paid
   down; `design-lint` now fails on any new one (`reference/tokens.md`).
2. **Severity carried by colour alone.** A coloured rule is an addition to the word, never a
   replacement (WCAG 2.1 AA, `reference/tokens.md`). This is the most safety-critical visual rule in the
   product.
3. **A hidden control** where capability is missing. Disabled with the missing capability named
   (`reference/anti-patterns.md`). Watch for this being "tidied" into a conditional render during a refactor.
4. **A fabricated zero, or an unlabelled partial.** `—`, never `0` or `$0.00`; a number over a capped
   list states its window.
5. **Dark mode unchecked.** A hardcoded white only shows up there, which is why it ships.

Two more, added after they each cost a rebuild:

6. **A shared class dragged onto a dark-committed surface.** `.app-header-brand` sets
   `color: var(--text)` — correct in the app bar, and near-**black** under the light theme, so the
   lockup vanished on a dark sign-in card. Reusing an app class on a surface that does not follow the
   theme means overriding the tokens it reads, at two-class specificity so stylesheet order cannot
   decide it.
7. **A fake progress affordance.** A staged label sequence or a progress bar driven by `setTimeout`
   rather than by the request. It reads as polish and it is a lie: with the host unreachable, one of
   these walked through "Authenticating → Establishing tunnel → Loading 247 clusters" and arrived at
   *signed in*. A submit control may show one honest in-flight state and then exactly one of success
   or the server's error. If the timing is not measured, do not draw it.

And the one the owner has had to name most often:

8. **A screen built as a document.** An `h3` and an explanatory paragraph per section, data written
   as sentences, every card the same weight, no dominant shape. It passes every check above,
   because each sentence is true and each card is built from house classes. Catch it with
   slots 6 and 7 and the document test. Do not catch it by trimming adjectives after the fact.

## Output

**Only when a plan was required** (see the table above — a transcription or an owner-driven
iteration does not need one): the pass-1 plan (short, **including the fact → shape list and the
sketch**), **then what pass 2 changed**, then the change itself.

Pass 2's findings are a required artifact, not an internal step — at minimum one line per test saying
what it caught, or "nothing" if it genuinely caught nothing. Without that, a silent pass 2 and a
skipped pass 2 produce an identical deliverable, which makes the gate unenforceable. Naming what you
cut is the most useful line in the whole output: the usual result is that most of what you first
drafted was a generic default.

Also say which tokens and primitives you used, anything you could not build honestly and why, and any
primitive that was **missing** — reporting a gap in the vocabulary is more useful than a page-local
workaround the next screen cannot reuse.

Then run [`argus-design-review`](../argus-design-review/SKILL.md). A frontend change is also not
servable until the hub container is rebuilt (`go:embed`) — `npm run build` alone changes nothing a
browser will see.
