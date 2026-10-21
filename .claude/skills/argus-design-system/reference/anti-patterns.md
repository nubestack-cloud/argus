# Anti-patterns — the specific defaults to refuse

This list exists because "make it clean and modern" is satisfiable by a generic AI dashboard, and a
rule that a generic dashboard satisfies is not a rule. Everything here is banned by name, with the
reason attached — the reason is what stops the ban being paraphrased away later.

---

## Which of these bans apply to you

**Read `SKILL.md`'s "First: which surface are you on?" before this file.** The bans below are not one
list at one strength:

- **Ornament**, **Structure** and **Document-shaped UI** are scoped to **operational surfaces** — the screens an operator
  works. They are about protecting scan speed, and they have no jurisdiction on the sign-in screen,
  first-run, onboarding, or any surface whose job is to introduce the product. Each of those sections
  now says so at the top.
- **Honesty** and **Access and interaction** are **absolute, on every surface, with no exceptions.**
  They are not taste; they are correctness. A presentation surface is where they get violated most
  easily, because a supplied mockup is full of plausible-looking numbers nobody computed.

## The test that catches the rest — operational surfaces

Before shipping an operational screen, ask: **would I have produced this same layout for a
project-management tool, a CRM, or a fitness app?** If yes, it is a default rather than a decision,
and the tell is *invariance to the subject* — not ugliness. ARGUS's subject is a broken Kubernetes
cluster at 3am. A screen that could belong to any product is not using its subject.

The corollary, and the reason this file is not just "avoid clichés": **on those screens, spend
nothing on visual flourish, because scan speed is the entire product.** An on-call engineer is
reading them under time pressure, deciding whether to approve a machine-authored change to
production. Every mark either encodes severity, position in a flow, or what was checked — or it goes.

Do not run this test on a credential form or a first-run screen. See `SKILL.md`; a login form is
*supposed* to be transferable, and the only thing that must not transfer is a claim about this
install's data.

---

## Named bans

### Ornament — *operational surfaces*

**Scope.** Every ban in this section protects an operator's scan. On a presentation surface, the
owner may choose any of them deliberately and the choice stands; what you owe then is a **declared
exception**, not a refusal — a comment at the point of use saying it is deliberate, whose call it
was, and what keeps it narrow. `web/src/pages/login/*.module.css` carries several: a translucent
card, a vignette gradient, a full-bleed canvas field.

- **Decorative gradients.** Any `linear-gradient` / `radial-gradient` used as surface treatment.
  Data-bearing gradients (a heatmap ramp) are fine. The ARGUS logo is the one sanctioned exception
  (see `tokens.md`).
- **Glassmorphism** — `backdrop-filter: blur`, translucent panels over content. It reduces contrast
  on exactly the text that matters and costs GPU on a page that may hold a thousand rows. **Both
  reasons are about operational screens**, and `design-lint` enforces this one mechanically, which
  makes it the ban most likely to block an owner-approved design. If you hit it on a presentation
  surface: the linter only reads `src/index.css`, so verbatim design CSS belongs in a
  `.module.css`, where the rule does not reach and where scoping is honest rather than a dodge.
  Translucency without a blur is usually enough anyway — over a field of 1.5px dots a blur has
  nothing to resolve.
- **Animated hero sections, marketing-style landing layouts, centered single-column heroes** — on
  operational screens. Those are worklists, tables and arguments, and a hero on one is space taken
  from the work.

  **This used to read "there is no marketing surface in this product", and that is simply not true
  any more.** The sign-in screen is a presentation surface with three selectable visual styles
  (`org_settings.login_style`), one of which is a centred card over an animated canvas. Stating the
  ban as a fact about the product, rather than as a rule about a class of screen, is what made an
  earlier pass argue the owner out of their own design. See `screens.md` mode G.
- **Depth as hierarchy.** Elevation is not how importance is expressed here — scale, weight, spacing
  and position are. Concretely: cards are `border` + `background`, and `--shadow-md` is for genuinely
  floating layers (modals, dropdowns, popovers). `--shadow-sm` on a resting card is not a finding —
  it is already used that way — but a *ladder* of shadows meant to rank sibling cards is.
- **Novelty charts** — radial bar, chord, sunburst, 3D anything, animated counters. These are
  anti-goals. Chart choice is answered in `components.md`.
- **AI-sparkle aesthetics** — glow, shimmer, gradient borders, wand/sparkle iconography around
  machine-generated output. The product's claim is that its diagnosis is *inspectable*, and dressing
  it as magic argues the opposite of what the UI needs to argue.
- **Emoji as iconography.** Icons are inline SVG with `stroke="currentColor"` so they recolour with
  their chip. A glyph like `✓` is acceptable *only* as decoration with `aria-hidden="true"` beside
  real text; carrying status in a bare glyph is a finding.

### Structure
- **The four-KPI tile row** at the top of every screen because dashboards have one. A tile earns its
  place by answering a question someone actually asks. `PRODUCT_DIRECTION.md`'s framing: show what is
  *stuck*, not what merely exists.
- **Tile walls.** Fourteen tiles reading "healthy" is noise dressed as information. Show the few that
  need attention and count the rest.

  **Precedence, since these two rules look like they collide:** `.pipeline-strip` showing eight cells
  where most read `0` is *not* a tile wall. Its cells are fixed stages of one flow, so an empty stage
  is information — "nothing is stuck awaiting approval" is a fact worth seeing, and collapsing it
  would break the sequence that gives the strip its meaning. The ban is on repeating the *same*
  status across many interchangeable objects. Fixed stages of a pipeline: keep. Fourteen equivalent
  clusters: collapse.
- **A sparkline or donut because the space looked empty.** Empty space is cheaper than a chart nobody
  reads, and an empty chart implies zero — see the honesty rules below.
- **Leading a row with a coloured pill.** The leading cell says *what is broken* — object name, kind,
  namespace, fault. A scan down the left edge should be a scan of identity, not of colours. This is
  what `.identity-block` exists for.
- **The same count in two places on one screen.** A header total and a card total that must agree by
  hand will eventually disagree.
- **Two numbers with the same visual form and different meanings**, unlabelled. "×84" meaning
  events-for-this-reason beside "occurred 12×" meaning the detector's own count, in one block, is two
  facts wearing one costume.
- **Page-scoped classes borrowed from another screen.** `ApprovalsPage` renders `clusters-page`,
  `clusters-page-header` and `clusters-live-status`, two of which set `max-width`. A shared pattern
  should be promoted to a shared class; borrowing a neighbour's page class couples two screens that
  will diverge.

- **More than one filled button on a screen.** One primary per page, tab panel, side panel or dialog
  — see `components.md`, "One primary button per screen". A row of equally loud buttons hides the
  one that matters.
- **A browser-default table.** Every `<table>` carries `.data-table` (panels, cards) or
  `.cluster-table`/`.list-table` (page lists). Linted (`table-unstyled`).
- **An essay above the work.** A multi-sentence explainer card above a list or a panel is space taken
  from the scan on every visit, to help on the first. One line plus a `HelpTip`, or a disclosure for
  server-provided rule text (Signals' promotion boundary is the worked example).
- **Blanket help bubbles.** A `HelpTip` beside "Nodes" or "CPU used" is noise; they go beside
  ARGUS-specific terms only (`components.md`, "Help bubbles").
- **A redesign that drops a figure.** Re-laying out a screen must keep every number, meter, table
  column and status it showed, on the same screen or one disclosure/tab away — owner rule,
  2026-10-10. A roll-up may MOVE (the cluster page's CPU/memory tiles became the Resource use card's
  "used" rows); it may not vanish. List the before → after location of each item when you change one.

### Document-shaped UI — *operational surfaces*

**The failure this section exists for** (owner, 2026-10-11): UI work on ARGUS kept "just dumping a
lot of text in the UI with no real thinking behind how to structure it and how to represent data
graphically without making it a document". A prototype check found ~60 static paragraphs of two
lines or more across the components at the time, a dozen of them on the Settings page alone. Every one
compiled, passed review against the rest of this file, and made its screen read like a manual.

The tell is simple: **if the screen would make sense printed and read top to bottom like a page of
documentation, it is not designed.** An operational screen is scanned, not read. Its first glance
must land on a shape (a ring, a bar, a chain, a map, a strip, a column of severity edges) that
answers the screen's question before a single sentence is read.

- **A sentence carrying data that has a shape.** If a sentence contains a count of a whole, a
  comparison, a ratio, a sequence of steps, a time span, or a state per item, it is a figure written
  out as prose. "3 of 5 replicas ready, 2 waiting on node-7" is a `.replica-bar`. "Detected 14 min
  ago, analysed, awaiting approval" is a `.lifecycle-rail`. "CPU is at 82% of requests" is a
  `.resource-usage-fill` bar with the percentage beside it. The table in `components.md` ("Choosing the
  encoding") names the primitive for each shape. Prose is for the residue: a reason, a name, one
  sentence of consequence.
- **Explaining the system on the screen.** How a feature works, why ARGUS behaves as it does, what a
  setting means in general: none of this is the screen's content. It is the same on every visit, so
  it is a tax on every visit after the first. One line of subtitle at most, then a `HelpTip` beside
  the ARGUS-specific term, or a `<details>` disclosure for rule text the operator sometimes needs.
  The real cases are the "ARGUS refuses outbound connections to private, internal, loopback…"
  paragraph and the four-sentence "A toleration stops a real, already-triaged, accepted condition…"
  card. Both are documentation printed in the UI.
- **Implementation rationale in UI copy.** Copy that says "this is deliberate", "by design", "note
  that", "that is", or names an endpoint, a table, a file or an internal mechanism is a code comment
  that escaped into the product. The reasoning belongs in the comment beside the code. The operator
  needs the consequence ("Saving replaces every rule at once"), not the architecture behind it.
- **A static prose budget, per element.** As a working limit on an operational surface:
  - a page subtitle is one line;
  - a card body is at most **two lines (~160 characters) of static copy**;
  - an empty state is one sentence plus the action that changes it;
  - a section with no data is one line (`.card.status-line`).

  Over budget means the copy is either data that should be drawn, or explanation that belongs behind
  a disclosure. `design-lint`'s `prose-block` rule enforces the card-body limit mechanically on new
  code. **Exempt**, because the text *is* the data: AI-authored content (`AiClaim`), log and YAML
  views, server-provided messages and reasons. **Exempt too:** the consequence statement in a
  confirmation dialog for an irreversible action. Keep it to three sentences, and mark it with a
  `prose-ok:` comment naming why.
- **The uniform card wall.** Every section is the same card: an `h3`, a paragraph, then a list. Six of
  them in a column have no hierarchy, so nothing tells the eye where to land. Each screen has **one
  dominant element**, the thing that answers its question, drawn larger or wider than the rest.
  Supporting cards are visibly secondary (`.card-compact`, a narrower column, a preview row). If you
  cannot say which element dominates, the screen has not been designed yet.
- **Key/value rows for values that compare.** A `.kv-list` of "CPU requested 4.2 / CPU limit 8 /
  Memory requested 6Gi / Memory limit 12Gi" hides the only thing worth seeing, the ratio. Values on
  one scale are bars on one axis. A `.kv-list` is for identity facts that do not compare: image,
  node, service account, creation time.
- **A caption that repeats its chart.** A ring that shows 151 running / 13 completed / 2 failed does
  not also need the sentence "151 pods are running, 13 have completed and 2 have failed". Say what
  the graphic cannot: the window, the source, or what is missing.
- **Status sentences for many items.** "node-1 is Ready. node-2 is Ready. node-3 is NotReady because
  the kubelet stopped posting status." is a table or a list of `.preview-row`s. Give it a status word
  per row, the reason only on the row that has one, and healthy rows collapsed to a count when they
  are the majority.

### Honesty — the bans specific to this product
**Absolute. Every surface, including the unauthenticated one — especially that one.** A generic UI
review will not catch these, and they matter most here.

Presentation surfaces are where these fail, because a supplied mockup has no server and invents
whatever it needs to look finished. Real instances removed from three supplied sign-in designs:
counters animating to "1,284 clusters watched" and "37k issues resolved"; a four-KPI row including a
**median MTTR**, which `screens.md` records as not computable in this product at all; a sparkline fed
by `Math.random()` captioned "incidents detected · last 60 min"; a scrolling "live remediation
stream" of invented incident IDs and PR numbers under the sentence *"this is what's happening while
you sign in"*; and a "SOC 2 · ISO 27001" footer asserting certifications this repo cannot verify.

Two rules that follow specifically for the unauthenticated surface:

- **Before anyone authenticates, the hub must not reveal a cluster name, a count, or a heartbeat.**
  It is not merely dishonest to invent them there, it is the one place where showing the *real*
  numbers would also be wrong. Anything on that screen is generative, self-referential, or a
  statement about the software.
- **Never draw progress you are not measuring.** See `SKILL.md`'s failure mode 7.

- **No fabricated zero.** A missing count renders `—` or "not reported", never `0`. A missing cost
  renders `—`, never `$0.00`. This has bitten the codebase before, which is why `analyses.cost_basis`
  distinguishes measured spend from a subscription's notional figure.
- **No unlabelled partial.** The incidents endpoint caps at 500 (max 1000). A number computed over a
  capped list either states its window or comes from a server-side aggregate. A truncated count that
  looks total is worse than no count. **"View all 500 incidents"** where 500 is the cap is the exact
  shape of this failure.
- **A truncation caveat travels with the number, not with the card.** One "results were truncated"
  sentence per *section*, while every figure on the page derives from the same capped fetch, leaves
  most of the page silently partial. Attach the caveat to every number derived from that fetch — or
  compute it server-side and remove the need. Observed on the fleet overview, where the pipeline strip
  and activity chart carry the caveat and the donut's centre total does not.
- **One fact, one claim.** Where two components derive a status from the same underlying state, they
  must agree in *strength*. A green "done" step beside prose that qualifies the same fact is a
  contradiction, and the reader resolves it in favour of the green. Compute the status once and pass it
  down. Real instances: a lifecycle rail painting step 2 "done" while the conclusion block below calls
  the same run "Investigation incomplete"; a rail reading "Confirmed resolved" where the page's own
  summary says "not a positive re-check, only an absence of new findings". Each sentence passes on its
  own — the violation exists only in the pair, which is why every local rule misses it.
- **Capability-gated *data*, not just gated controls.** The disabled-not-hidden rule covers buttons.
  A **number** the viewer may not see must render `Restricted` (or the capability it needs) in the slot
  — never `0`, and never omitted so the row looks complete. This is already the best pattern on the
  fleet overview; it is written down here so the next screen does not render a reassuring zero instead.
- **Pass the filter the endpoint already accepts.** If a screen scopes by cluster, state or fleet group
  and the endpoint takes that parameter, pass it. Filtering a capped page client-side shows the
  selection's share of the *global* most-recent-N, which is a different and smaller answer — a finding
  even when a truncation note is present. `GET /approvals` is one of these endpoints as of PROJECT.md
  B167 (`?clusterId=`/`?actionType=`/`?riskLevel=`/`?sort=`/`?cursor=`, internal/api/approvals.go) —
  it used to return its whole set unpaginated, which was the one endpoint this rule didn't yet cover;
  it is not an exception any more, and ApprovalsPage.tsx sends every one of those as a request
  parameter rather than filtering a fetched array.
- **Absence is stated, not implied.** An empty chart reads as zero; a grey "not measured yet" chip
  reads as unknown. Prefer the second, and check `screens.md` for what genuinely cannot be computed.
- **No overstated label.** "Verified" where the code re-read one field. "Resolved" where nothing
  checked the symptom cleared. If the backend distinguishes two things, the label must too.
- **State a refusal at the same size as a success.** `.verification-chip-neutral` exists for this:
  "Not verified: the symptom itself" sits in the same row, same weight, as the green checks.
  The refusals are part of the product, and the UI should look like it believes that.

### Access and interaction
**Absolute. Every surface.**

- **A control that does nothing.** If there is no flow behind it, it does not ship — a
  "Forgot password?" link with no reset flow, or a "Keep me signed in" checkbox with no
  session-lifetime setting, is a promise the product does not keep, and the login screen is the worst
  place to make one. Supplied designs are full of these; cut them and say you did.
- **Hidden controls for missing capability.** Render `disabled` with a tooltip naming the missing
  capability and scope — never omit from the DOM. Hiding is not authorization, and it
  removes a screen-reader user's only way to discover the control exists. Watch for this being
  "tidied" into a conditional render during a refactor.
- **`transition: all`.** Name the properties; `all` animates layout and paint you did not intend.
- **`outline: none` without a `:focus-visible` replacement.**
- **Disabling zoom** — `user-scalable=no`, `maximum-scale=1`.
- **Motion that ignores `prefers-reduced-motion`.**
- **Client-side filtering or sorting of a paginated list.** Sorting the current page and labelling it
  a sort of the whole set is a lie about the data. **Check whether the endpoint is actually
  paginated** before citing this — it is not universal, despite HLD §15.3's aspiration, though the
  set of exceptions is shrinking: `GET /incidents` caps at 500, and `GET /approvals` (PROJECT.md
  B167) now caps and filters/sorts server-side too (`?limit=`/`?cursor=`/`?clusterId=`/`?actionType=`/
  `?riskLevel=`/`?sort=`, internal/api/approvals.go) — it used to have no `LIMIT` and return
  everything, which was this rule's one standing exception; it no longer is one. On a genuinely
  unpaginated endpoint, client-side partitioning is still honest — but re-verify a "this endpoint
  returns its whole set" claim against the code before relying on it, the way this entry's own
  history should now make you. A *sort or filter control* can still be wrong even on a real
  server-side page for a different reason — on a worklist whose premise is "the server ordered this,
  work top-down", a filter lets an operator hide criticals behind a view and call the queue empty; the
  fix is a query parameter plus a distinct "filtered to nothing" state (ApprovalsPage.tsx), never a
  client-side re-derivation.

---

## Where "calm" and "dense" meet

`PRODUCT_DIRECTION.md` asks for a "calm operational UI, dense where the user is triaging, quiet
everywhere else", and D7 lists the anti-goals above. These are not in tension once stated correctly:

**Density at triage is fine; decoration never is.**

"Calm" is not an argument against graphics. A causal chain drawn as a chain is *calmer* than the four
paragraphs it replaces. It is an argument against ornament — which is why every ban above is about a
mark that encodes nothing, not about information volume.

The two failure directions are symmetric, and both have happened here. **Ornament** is a mark that
encodes nothing: the decorative gradient, the sparkline put there to fill space. **Prose** is data
that was never encoded at all: the paragraph that describes a ratio instead of drawing it. A
well-designed ARGUS screen has neither. Every mark encodes something, and everything that has a shape
is drawn.

### Inconsistent box spacing
Two cards 12px apart on one page and 16px on the next, a band of boxes 6px from the one below it,
a box whose own margin adds to its container's gap. Each looks fine alone; together the app looks
assembled from parts. Every box-to-box gap is `--gap-box`, every row-box inside a box is
`--gap-row` (`tokens.md`). When a box sits inside a stack whose gap is for something else (an
`.insight-stack` holds fields), override the gap on that container rather than adding a margin to
the box. Measure, do not eyeball: the check is the rendered gap between neighbouring boxes.

