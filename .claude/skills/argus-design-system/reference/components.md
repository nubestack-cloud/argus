# Components — what is built, what it expects, and its four states

Two inventories matter and they are not the same: the **CSS vocabulary** already in `index.css`
(reuse it), and the **React components** in `web/src/components/` (compose them). Reaching for a new
primitive when one of these exists is how a second design system starts.

`index.css`'s own § "D7/D8 visual vocabulary" carries the authoritative markup each primitive
expects, plus a naming-collision table. Read that section before adding a class.

---

## The built CSS vocabulary

Grouped by the job it does. All of these resolve to tokens, which is what makes them work in dark
mode — the `.design/*.dc.html` mockups they came from used light-mode hex literals and would not.

| Primitive | Job |
|---|---|
| `.identity-block` (+ `-name`, `-kind`, `-fault`) | The leading cell of a row: what is broken, before any status colour. |
| `.severity-rule`, `.sev-*` | Severity as a rule on the row edge. Class on the container; children read `--sev-fill` / `--sev-tint`. |
| `.chain-list`, `.chain-node` (+ `-dot`, `-track`, `-body`, `-text`, `-evidence`) | The causal chain, drawn as a chain. Connector lines are drawn by the list, so a node is the same markup whether or not it is last. |
| `.lifecycle-rail`, `.lifecycle-step` (+ `-done`, `-current`, `-blocked`, `-locked`, `-unreachable`) | Detection → analysis → recommendation → approval → execution → validation. Green behind you, the accent (with a halo ring) where you are, outlined ahead. The halo is load-bearing, not decoration: since the accent became teal, `--color-green` and `--accent` are too close in hue and lightness for a fill alone to separate done from current. |
| `.verification-chip`, `.verification-chip-neutral`, `.verification-chip-row` | What was checked — and, at the same weight, what was **not**. |
| `.route-badge` (+ `-amber`, `-blue`) | Which channel a fix takes (pull request vs in-place). |
| `.evidence-chip` | A pointer to the evidence behind a claim. |
| `.diff-pair` (+ `-before`, `-after`) | Before/after for a proposed change. |
| `.metric-tile` (+ `-label`, `-value`, `-figure`, `-delta`), `.tile-grid` | A number that answers a question someone asks. |
| `.pipeline-strip`, `.pipeline-cell` (+ `-count`, `-label`, `-meta`, severity variants) | Where work is *stuck* across the loop. |
| `.overview-*` (donut rows, chart bars, legends, activity card) | Fleet-overview specifics. |

### Cluster-insight primitives (added 2026-10-10, docs/CLUSTER_INSIGHT_SPECS.md)

| Primitive | Job |
|---|---|
| `SidePanel` + `.side-panel*` | Right-anchored inspector over a list or page; open state in the URL (`?panel=`) so the list keeps its place (CI-U7). Esc closes, focus returns to the opener. |
| `Tabs` + `.tabs*` | WAI-ARIA tablist, active tab in the URL; a tab the viewer cannot use is disabled with the reason, never hidden. |
| `Quantity` + `.quantity*` | A number whose certainty is part of the value: `≥ 12`, `≤ 12`, `—` + "unknown". Required wherever a count comes from a capped list, a partial scan, or a source that may be unavailable (CI-U1). |
| `VerdictBadge` / `toVerdict` | The closed check vocabulary Passed / Review / Warning / Blocked / Incomplete / Not applicable. "Could not check" is Incomplete, never Passed (CI-U2). |
| `AiClaim` + `.ai-claim*` | Words a model wrote, marked with a visible "AI" label and a muted accent rule — never a severity hue (CI-U3). |
| `Freshness` + `.freshness*` | How old agent-sourced data is; turns into a stale statement when the cluster is not connected (CI-U10). |
| `Reproducer` + `.reproducer*` | A copyable command that re-derives a piece of evidence outside ARGUS (CI-U9). |
| `.code-view`, `.redacted-marker`, `.kv-list` | Read-only YAML/log view (scrolls inside itself); a capture-redacted value, visibly marked; key/value facts. |
| `.row-group-count`, `.row-fresh` | Look-alike rows collapsed to one with a true count (CI-U4); a just-changed row, no animation under reduced motion (CI-U8). |
| `GraphCanvas` + `.graph-*` | Node/edge graphs (relationship map, traffic). Health is a word on every node; the border colour repeats it; every edge type is named in the legend. |
| `TimeSeriesChart` + `.ts-chart*` | Line chart for metrics over time: a missing sample breaks the line (never drops to zero), labelled reference lines and event markers, keyboard readout of the nearest sample, and a "View as table" fallback. |
| `.insight-section`, `.insight-range` | A collapsible incident-page section that fetches nothing until opened; a small range picker. |
| `.path-trace*` | A path diagnosis: the first broken hop as the headline, then the hop chain with each hop's state in words (CI-U11). |
| `.code-view-line`, `.code-view-lineno` | Numbered lines inside `.code-view`. |
| `.tl-*` (`fleet/ClusterTimeline.tsx`, `fleet/timelineModel.ts`) | A time axis with one row per object (PROJECT.md AD1): a label column (kind tag, full name, namespace, counts, every incident's severity **as words**) beside a track. Incident spans are focusable bands above the row's time line (the band prints its severity when it fits; the label always does); changes are dots, findings hollow diamonds with a line while re-reported; marks too close to draw apart bin into one button with a count; roving focus per row (arrows, Home/End, Up/Down between rows). Sticky axis, no horizontal scroll; below 640px the same rows render as an event list. The tab opens with `.tl-leads` (`.tl-lead`, severity on the edge and as a word): incidents opened in the window, each with what changed on its own object and elsewhere in the 30 minutes before — offered as a lead, never a cause; incidents already open at the window start are counted, not led with. Use the `.activity` strip for a small preview card instead. |

### Redesign primitives (added 2026-10-10, PROJECT.md UX1 — cluster page and object panel)

| Primitive | Job |
|---|---|
| `.card.card-compact` + `.card-head` (+ `-meta`), `.card-foot-links` | A small preview card at 12×16 padding: an `h3` title, an optional `HelpTip`, a muted count/window on the right, and its onward links on one line at the foot. Use it for cards that sit several to a row. |
| `.overview-pair`, `.checks-card` | Preview cards on a summary page: pair cards of similar height side by side at equal height (foot links pinned to the bottom), and give a long list of short rows (`.check-rows`) the full width in two columns. Never a 2×2 grid of unequal cards: a grid row is as tall as its taller card and leaves a hole beside the shorter one. |
| `Ring` (`fleet/Ring.tsx`) + `.ring*` | A part-to-whole ring whose legend is glyph + count + **word** per slice (`✓ 151 running · ◐ 13 completed · ✕ 2 failed`). The glyph is `aria-hidden`; the word carries the state. An unreported total draws `—` with the reason, never an empty ring. The cluster Overview's top row is three of these plus the Resource use card (owner's choice, 2026-10-11, after a single-card "health ledger" was tried and withdrawn). |
| `.inventory-groups` (+ `.inventory-group`, `.inventory-problem`) | Every object count grouped by purpose (Workloads, Batch, Networking, Config and storage) in the Objects card under the rings; problem parts in the danger text colour, beside a word. |
| `.meter-row` (+ `-head`, `-figure`, `-note`) | A labelled bar (watch coverage). The figure and percentage are always text beside the bar; no bar is drawn for an unknown value. `.coverage-fill` where more is better. |
| `.count-strip` (+ `-row`, `-item`, `-more`) | A one-line strip of object counts with their detail in parentheses (the GitOps tab). |
| `.attention-row` (+ `-identity`, `-name`, `-meta`, `-status`, `-severity`, `-state`; `[data-closed]`), `.attention-subhead` | An incident in a preview card: severity on the row's edge AND as a word with its chip, the subject's name, kind · namespace — fault, and where it is in ARGUS's loop (state) · age. A quiet card fills with "Recently closed" rows (neutral edge) instead of a hole. |
| `.activity` (+ `-bars`, `-bin`, `-bar`, `-peak`, `-incidents`, `-incident`, `-axis`, `-caption`), `.changed-row` | The Overview's change preview: changes per 5 minutes over the hour with incidents opened in it marked under the same axis (severity fill, each named in the caption), then the changed owning objects with what was done to them and an "incident open on it" link when one matches. |
| `.preview-list` / `.preview-row` (+ `.preview-dot`, `-name`, `-context`, `-status`, `.preview-kind`) | The short-list row: dot · kind · name · context · status word · age. Every short list on a preview card uses it. The dot repeats the status word; it is never the only carrier. |
| `.card.status-line` | A card whose answer is "nothing to see" (not available, not measured, switched off) shrinks to one line, at the same position the full card would take. Prefer a row inside a related card when one exists (the cluster Overview's Helm row lives in Checks). |
| `.check-rows` | Label/answer rows inside a card (a Checks card): the label links to the tab that holds the full view. |
| `.status-banner[data-tone]` | An object's health word as a badge plus one line of reason ("Degraded — Progressing is False: ProgressDeadlineExceeded"). Drawn only when the object reports a health signal. |
| `.replica-bar` (+ `-seg`) | Ready vs not-ready replicas; each segment prints its count and word. |
| `.check-list` (+ `-item[data-verdict]`, `-mark`, `-state`, `-message`) | Conditions as a checklist, failing first; the `✕`/`✓` mark is `aria-hidden` and "is False"/"is True" is the readable state. |
| `.connected-chip` | A clickable related-object chip (kind, name, health word in visually-hidden text, tone on the left rule). |
| `Tabs` + `.tabs-bar`, `.tabs-scroll*` | Every tab stays on one row; when the row is wider than its container it scrolls sideways, with a ‹ / › button at whichever end has hidden tabs, and the active tab is scrolled into view. **No "More" menu** (owner, 2026-10-11: it made people think a tab had gone). Order tabs by importance so the ones that scroll out of sight are the least needed. |

 — `.metric-tile`/`.stat-tile`,
`.chain-node`/`.causal-step`, `.lifecycle-rail`/`.resolution-stages`, `.identity-block`/`.incident-identity`,
`.route-badge`/`.resolution-route`. Use the new name. Retiring an old one is the job of the page that
stops rendering it, not of a drive-by edit.

*Corrected 2026-08-25 — this table itself had drifted:* `.stat-tile`'s remaining callers are
`OverviewPage` and `Skeleton`, **not** Insights. `InsightsPage` already renders `.metric-tile` (and its
own comment quotes this table's stale claim back at it). Re-check a namesake against the code before
reporting one as unmigrated.

**Three of the five are built and have zero uses on the incident screen** — `.identity-block`,
`.route-badge`, `.verification-chip-row`. That is most of why that page reads as two vocabularies at
once, and it is what `BACKLOG` D8 A2/A6 fixes. `.metric-tile-delta` is likewise built and unused
anywhere. Prefer applying one of these over adding anything new.

---

### Cluster-page primitives (added 2026-10-12, owner-approved cluster-pages design)

| Primitive | Job |
|---|---|
| `SplitBar` (`components/SplitBar.tsx`) + `.split-bar`, `.split-seg[data-tone]`, `.split-legend` | One whole split into parts, with a legend of swatch + count + **word** per part. Tones: `critical`, `high`, `medium`, `ok`, `info`, `neutral`, `accent`, `unknown` (hatched: "could not tell"). `showZero` keeps a 0 part in the legend ("0 out of sync" is a fact). The accessible name lists every part in words. |
| `BarList` + `.bar-list*` | One bar per name on a shared scale, total at the right; rows with `onSelect` are pressed-state buttons, so a bar list can be the filter (posture by namespace). |
| `FilterChips` + `.filter-chip[aria-pressed]`, `.filter-chip-count` | A few choices, each with its count. A chip whose count is 0 stays enabled — choosing it shows the honest empty state. The timeline's source chips are also its legend. |
| `Segmented` + `.segmented` | 2–5 exclusive options (a window, a category) instead of a full-width select. |
| `.panel-toolbar` (+ `-meta`) | One row of a tab's controls, its scope meta pushed right. |
| `.chart-card-grid` | Two chart cards side by side above a tab's table (category / namespace, severity / loop stage). |
| `TabLabel` / `useClusterTabBadges` (`fleet/clusterTabBadges.tsx`) + `.tab-badge[data-tone]`, `TabDef.groupStart` | A tab's problem count on the tab itself, read from the query the tab already makes; absent when unknown, never 0. `groupStart` draws a thin rule before a group of tabs. |
| `.cluster-header-line`, `.cluster-header-facts` | The cluster page's identity and liveness on one wrapping line (state, heartbeat · facts age, Kubernetes, agent + compatibility, enrolled · reachability) in place of a tile strip. |
| `.cert-runway*` | Every certificate on one expiry axis (linear to a year, later at the end), the agent's own unhealthy/degraded thresholds as zones; pins that would overlap merge with a count. |
| `.upgrade-strip` (+ `-cell[data-verdict]`) | Every check of a scan as one cell, worst first, each cell's title and verdict in visually-hidden text. |
| `.upgrade-fgroup` | Look-alike findings as one group: impact and fix said once, the objects one click away. |
| `MetricsSourceLine` (`fleet/MetricsSourceLine.tsx`) | Traffic/Cost unavailable state: one status line and, when the agent found a Prometheus, the exact chart values with a copy button. |
| `.tl-activity*` | The timeline's whole-cluster strip: drawn changes and findings per bin, stacked, with a flag where each incident opened. Change marks are upright ticks, findings filled diamonds, bursts filled bubbles sized by count. |
| `.nsmap-rail*`, `.nsmap-chain`, `.nsmap-mini*`, `.nsmap-dots`, `.nsmap-guard` | The Map: namespaces as a rail (pods bar + open incidents), workloads needing attention as connected chains with an incident line beside live health, healthy ones as one line with a chain glyph, a dot per pod and guard badges. |
| `.check-cells` | Overview Checks as five cells, each a label that opens its tab and a drawn answer. |

### Incident lifecycle primitives (added 2026-10-12, owner-approved "Incident Lifecycle Redesign")

| Primitive | Use it for |
|---|---|
| `phaseModel` (`pages/incidentPhases.ts`) | The four phases (Detected, Diagnosed, Fix, Holding), the outcome, and "whose move". It only regroups the stage functions in `incidentLifecycle.ts`; it never decides a state itself, so their honesty rules carry over. |
| `LifecycleSpine` + `.lc-spine`, `.lc-phase.lc-{done,current,next,skipped,failed}`, `.lc-pip-*`, `.lc-endcap-*` | A lifecycle as four nodes and an outcome cap. Time between phases on the segment; the Fix phase's route-specific sub-steps as pills. A phase that cannot happen is `skipped` (dashed), never an empty step. Status in the mark, the detail line and a visually-hidden word. |
| `NowLineBar` + `.lc-now-{you,argus,team,watch,closed}` | One line naming whose move it is and what it is, with a link to where the move is made. Replaces a state badge plus an explanation sentence. |
| `.lc-body` (`.lc-main` + `.lc-rail`) | A single object's argument with facts and history in a right rail, stacking below 1080px. |
| `FixSection` + `.fix-option(-primary)` | One option card per way to fix (ARGUS runs it, pull request, you do it), the route stated once above them, the recommended one outlined. |
| `ApprovalDecisionCard embedded` | The approval queue's decision core inside another page that already shows "what is broken": change and decision columns only. One component, two shells. |
| `HistoryRail` / `milestonesFrom` (`pages/incidentHistory.ts`) | A timeline as milestones: an investigation and its results are one, identical back-to-back runs collapse to "Investigated N×", gaps between milestones drawn. |
| `EvidenceTabs` | Evidence sections under a diagnosis as tabs, each mounted on first view. |

### Settings primitives (added 2026-10-12, owner request: settings grouping and layout)

| Primitive | Use it for |
|---|---|
| `PanelHead` (`components/SettingsBlocks.tsx`) + `.settings-head`, `.settings-lede`, `.settings-head-aside` | Every settings card's head: title, ONE line saying what the card controls, the full explanation as the title's `HelpTip`, and the card's state chip on the right. Never open a card with a paragraph. |
| `InEffect` + `.settings-effective` | The values the hub is running with, as label/value pairs under the fields — what a blank "default" field resolves to. Not a sentence ("Currently in effect: …"). |
| `.settings-fields` / `.settings-field` | Related fields side by side in a grid that spans the card (retention days, caps, prices). Inputs share a baseline even when labels wrap. |
| `.settings-facts` | One-line consequences a reader cannot infer from the controls — bold claim, short clause, each a list item. Replaces a multi-paragraph `.consequence-notice` on configuration cards. |
| `.settings-inline-add` | A collection's add row: its fields and the submit button on one wrapping row. |
| `.settings-subhead` | A titled block inside one card (Blast-radius caps, Destinations), with a hairline above. |
| `.settings-switch-row`, `.settings-chip-row` | The one consequential on/off switch in a card, set apart; a few multi-select options as chips in a row rather than a vertical list. |
| `.role-matrix` | Entities compared over the same attributes (builtin roles × capabilities): one row per attribute, a column per entity, granted/not in words for assistive tech. Never one card of bullets per entity. |

## The React components

`web/src/components/` — compose these rather than re-implementing:

`AppShell` (nav, theme toggle), `Dialog`, `EmptyState`, `Skeleton`, `ErrorBoundary`,
`TablePagination`, `UnifiedDiff`, `CopyButton`, `HelpTip`, `ActionMenu`, `IncidentBadges`,
`AnalysisConclusion`, `RemediationPlanCard`, `ApprovalDecisionCard`, `PreflightPanel`,
`RepositoryChangePanel`, `IncidentFeedbackCard`, `CircuitBreakerCard`, `AutomationWindowsCard`,
`AIProvidersCard`, `RepositoriesCard`, `EnrollTokenModal`, `ChangePasswordModal`,
`ConfirmDecommissionModal`, `icons.tsx`.

**Chronology and evidence are served, not as standalone components.** `GET /incidents/{id}/timeline`
and `GET /incidents/{id}/evidence/{evId}` are live (`internal/api/timeline.go`, `evidence.go`); the
incident page renders them through the `.tl-*` timeline classes and the causal chain's per-step tool
chips, and `web/src/fleet/ClusterTimeline.tsx` draws a cluster's history. There is no
`.../plans` endpoint. Check `screens.md`'s gaps table before assuming any other drill-down exists.

---

## The four states, for every data-bearing component

All four exist or the component is unfinished — and two of them are the
ones that get skipped:

| State | Rule |
|---|---|
| **Populated** | The normal case. |
| **Loading** | A `Skeleton` matching the eventual layout. **Not** a centred spinner — it causes a layout jump on load, and every list here is server-paginated. |
| **Empty** | **"No results for these filters" and "nothing exists yet" are different states and must read differently.** A fleet with zero incidents ever is reassuring; a filter matching nothing is a dead end with an obvious fix. Collapsing them loses the distinction. |
| **Error** | Render the RFC 9457 problem-detail `title`/`detail` where it is user-actionable — a scope denial should say which capability and scope is missing. Where it is not actionable (a 500), a generic message. Every problem body carries a real `requestId` (and every response an `X-Request-Id` header), so an error surface may show it for an operator to quote — read it from the response, never generate one client-side. |

A component with a populated and a loading state but no distinct empty state is the most common
half-built case here. Check for it specifically.

**A loading skeleton that omits the tallest element on the page is not a skeleton** — it guarantees
the layout jump it exists to prevent. Match the real height, not a nominal placeholder.

**Never render a raw API identifier as a user-facing value.** `ScaleDeployment` and `NeedsApproval` are
wire values; the UI shows the readable label. `IncidentBadges.tsx` established this ("always the
readable label, never the raw enum value") after it was a real bug — the rule is written down here so
it applies beyond that one component.

**`EmptyState` vs a bare `<p className="empty-state">`:** compose the component for a *screen- or
section-level* empty state. The bare paragraph is sanctioned only for an inline empty slot inside a
larger populated view (`EmptyState.tsx`'s own comment carves this out). If it is the only thing in a
section, use the component.

---

## Component rules (owner-approved 2026-10-10, PROJECT.md UX1)

These apply to every screen, not only the ones the redesign rebuilt. The mechanically decidable part
is enforced by `design-lint` (noted per rule); the rest is the review skill's job.

### One primary button per screen
A **screen** here is a page, a tab panel, a side panel's active tab, or a dialog. It has at most
**one** filled button (the bare `<button>` style): the next step in the lifecycle, or the one action
the screen exists for (Apply filters, Run scan, Enroll a cluster, Approve). Every other action is
`className="secondary"`; destructive ones are `className="danger"`; rarely used ones go in an
`ActionMenu` ("More ▾"). Paging controls (Previous/Next), Refresh, Copy and Clear are always
secondary. Three filled buttons at three sizes in one header — the review's incident-page finding —
tell the reader nothing about which one matters.

*Not linted:* "screen" is not visible in a file (tabs, dialogs and conditional branches share one
component), so a per-file count would be wrong in both directions. Check it in review.

### The disclosure
Every `<details>` reads as a control: the global `details > summary` rule draws one chevron that
rotates when open and tints the whole summary row on hover, so the whole row is the click target.
Put a count or one-line summary on the right of the summary text ("Labels · 4", "More filters · 2
set"). Never restyle a summary back to plain text, and never put a button inside a `<summary>`
(clicking it toggles the disclosure) — put a `HelpTip` beside the disclosure, not in it.

### Tables
- Tables inside a panel or card use `.data-table`: uppercase xs headers left-aligned with their
  cells, compact rows, numbers right-aligned with `.col-numeric`, `—` for an empty cell.
- Page-level lists keep `.cluster-table` / `.list-table` (mode A's scan tables).
- **Linted:** a `<table>` with none of `data-table`, `cluster-table`, `list-table`
  (or the diff view's `unified-diff-body`) fails `design-lint` (`table-unstyled`). Browser-default
  tables — centred bold headers on grey, 90px rows — were the review's finding.

### Help bubbles (`HelpTip`)
- A card, tile, section or column header whose title is an **ARGUS-specific term** gets a `HelpTip`
  beside it: Signals, Promotion boundary ("What opens an incident"), Tolerations, Route, Confidence,
  Class/Impact, Posture, Upgrade verdict, Watch coverage, Detection coverage/timing, Remediation
  authority, Agent compatibility, Resource use (used vs requested), Checks, Changes, Connected.
- Its text is one or two plain-English sentences: **what this contains and where the numbers come
  from**. Not a restatement of the title, and not policy prose.
- **Self-explanatory labels get none** — Nodes, Pods, CPU used, Containers, Labels. No blanket
  bubbles: a tip on every title trains the reader to ignore all of them.
- A long visible explainer paragraph on an operational screen collapses to **one line plus a
  HelpTip** holding the full text, unchanged. Data-dependent sentences (a verdict, a caveat about
  *this* value, "Not reported by this agent") are not explainers and stay visible.
- Pass `label` ("Checks"): the trigger is then named "About Checks" and the text is its
  aria-description, so a screen reader hears a short name, then the explanation. Escape dismisses
  the bubble; focus, hover and tap open it. **Never put a HelpTip inside a `<label>`** with the
  `label` prop — its hidden description would become part of the field's name; place it beside the
  label in a `.filter-label-row`.

## Two components with rules of their own

### The approval control and its two gates
An approval is not a button that submits. It binds actor, time, `planHash`, target UID(s)/
resourceVersion and expiry, is single-use, and **any change to the plan or target invalidates it**
(non-negotiable 7). The UI consequences:

- The two gates are distinct and must read distinctly: **may this user approve** (capability/scope)
  and **may this plan execute** (policy gates — confidence, risk, window, freeze, budget, breaker,
  blast radius). A control blocked by the second is not a permissions problem and must not say it is.
- **`gateReason` is rendered adjacent to a blocked option**, taken from the field the backend already
  computed. The UI never reconstructs "why wasn't this auto-fixed" from separate signals.
- A blocked control is `disabled` with the reason, never hidden.
- Honest warnings belong beside the action, not in a footnote — "in-place will be reverted by Argo
  self-heal in ~5s" is the single most decision-relevant sentence on that screen when it applies.

### Settings-page form fields
A form-bearing Settings section fills its card, not just a strip down the middle of it
(`.settings-page .settings-panel > form { max-width: none }`, BACKLOG D7l) — and that includes the
**fields** inside it, not only the prose beside them. Every text, password and `<select>` field (and a
checkbox's own row) inside a `.settings-page` form defaults to the full width of its immediate
container: `.settings-page input:not([type='checkbox']):not([type='radio']):not([type='number']),
.settings-page select { max-width: none }` (BACKLOG D7t). This is the standing rule, not a
page-specific fix — a newly added settings field inherits full width for free from this selector and
needs no extra styling to get it.

**A narrower field is the exception, and needs a comment stating why**, the way the two existing
exceptions do:
- `type='number'` inputs stay capped at 960px — unbounded, a short digit string reads as an empty box
  with a floating caret past ~1000px wide, a problem a `<select>` (shows its full chosen text) or a
  free-text field (can hold a long value) doesn't share.
- `.breaker-trip-reset input` (a free-text "why is it safe to resume" note) is explicitly re-widened
  back to `max-width: none` despite being a plain text input, because it holds a full sentence, not a
  short value.

Treat "full width of its container" as the default for any new settings field-entry box (text, select,
checkbox-adjacent). Where related fields sit in a `.settings-fields` grid, "its container" is its grid
cell: the row of cells spans the card, so the edges still line up with the prose — what the owner asked
for was no ragged right edge, not one full-width box per number.

### Choosing the encoding — what shape is this fact?

Before laying anything out, list the facts the screen shows and give each one a shape. The shape
picks the primitive. Prose is the *last* row of this table, not the default. Text-dumping
(`anti-patterns.md`, "Document-shaped UI") happens when this step is skipped.

| The fact is… | Draw it as | Not as |
|---|---|---|
| A whole split into states (pods running/completed/failed) | `Ring` with glyph + count + word per slice | "151 running, 13 completed, 2 failed" in a sentence |
| A used amount against a capacity or request (CPU, memory, quota, PVC) | `.resource-usage-fill` bar, colour by band, figure and % as text beside it | a `.kv-list` of "requested / limit / used" |
| Ready vs desired (replicas, nodes Ready) | `.replica-bar`, each segment printing its count and word | "3/5 ready" buried in a paragraph |
| Coverage, or progress toward complete | `.meter-row` (+ `.coverage-fill`) | a percentage in prose |
| A flow with a position in it (incident loop, rollout) | `.lifecycle-rail` / `.pipeline-strip` | "detected, analysed, now awaiting approval" |
| A cause and its effects | `.chain-list` with evidence chips | paragraphs of "because…" |
| Objects and how they connect (ownership, traffic, blast radius) | `GraphCanvas` map, health as a word on each node | a nested bullet list |
| Events over time | `.tl-*` timeline, `.activity` histogram, `TimeSeriesChart` for a metric | a reverse-chronological paragraph list |
| Many items, each with a status | `.data-table` / `.preview-row` list: identity first, status word, healthy majority collapsed to a count | one sentence per item |
| Checks that passed or failed | `.check-list` / `.check-rows` / `VerdictBadge`, failing first | "All checks passed except…" |
| A before/after change | `.diff-pair`, `UnifiedDiff` | "changes X from A to B" |
| A number someone asks for | `.metric-tile` with its window, or `Quantity` when it is partial | a number inside a sentence |
| Identity facts that do not compare (image, node, SA, created) | `.kv-list` | (this is what `.kv-list` is for) |
| A reason, a consequence, a name | **one line of text**, or a `HelpTip` / `<details>` when it is explanation | a paragraph |

Two consequences of using this table honestly:

- **A screen has one dominant element**, normally the row of this table that answers the screen's
  question, drawn largest. Everything else is visibly secondary. Without one, the screen becomes a
  uniform card wall.
- **A fact with no reliable source gets no shape.** A ring over an unreported total draws `—` with
  the reason, a chart over a capped list states its window, and an unmeasured bar is not drawn.
  The honesty rules outrank the urge to make the screen graphical.

### Charts
Chart choice is a data question, and the wrong answer is usually "a donut".

- **Trend over time** → line. Below ~4 points, a stat figure is more honest than a chart.
- **Compare categories** → bar. Past ~15 categories, a searchable table.
- **Part-to-whole** → donut, *only* with direct labels and counts. Colour-only slices are the
  accessibility failure mode here, not the shape.
- **Where work is stuck** → `.pipeline-strip`, not a chart.
- Never distinguish series by hue alone — use labels, and order series **green / blue / orange**
  (see `tokens.md`, finding 2).
- A chart over a capped list states its window (`anti-patterns.md`, "no unlabelled partial").

---

## Layout resilience — the things that break with real data

Cluster names, namespaces, object names and version strings (`v1.31.4+rke2r1`) are long, unbroken and
user-controlled.

- Grid and flex children need `min-width: 0` to be *allowed* to shrink. Without it they force
  horizontal overflow on the whole page.
- Wide content — tables, diffs, code, the causal chain — scrolls inside its own `overflow-x: auto`
  container. **The page body never scrolls sideways.**
- Never truncate essential meaning to make cards uniform. An object name, a primary action label or
  an error is not a candidate for a clamp.
- A chip collection wraps, or offers an operable "+n" disclosure. It does not clip to a fixed height.
- Full text must be reachable by keyboard and touch, not hover only.
- Cards sharing a row have the same anatomy so they sit level. If one is shorter, let its content
  absorb the slack rather than padding the card.
- Check 1440, 1024, 768 and 375.
