# Screen modes — name the mode before you lay anything out

ARGUS has ten screens (HLD §15.1) but only **six design postures**. Naming the mode first is what
stops every screen converging on the same tile-row-plus-table shape, because the modes want
genuinely different things — one optimises for scan speed, another for clarity to someone who has
never seen the product.

**State which mode you are in, in your plan, before laying anything out.** If a screen seems to be
two modes, it is usually one mode plus an empty state — see mode F.

**Each mode has a dominant element: the shape the eye should land on first.** Name it in the
sketch (`SKILL.md`, plan slot 7) and draw it largest. A screen whose first glance lands on a
paragraph has no dominant element (`anti-patterns.md`, "Document-shaped UI").

| Mode | Dominant element | Text's job |
|---|---|---|
| A. Triage scan | The table: identity column, severity edge + word | Names and status words; no prose above the table |
| B. Single-object argument | The argument's graphic: affected-objects map, causal chain, lifecycle rail; health rings for a cluster | One-line headline per question; AI-written text marked as `AiClaim` |
| C. Worklist | The queue rows, each carrying its diff | The gate reason, one line |
| D. Fleet aggregate | The `.pipeline-strip` / where-stuck chart | Window and source captions only |
| E. Configuration | The controls, grouped, with current values visible | One consequence clause per control; the rest behind `HelpTip` / `<details>` |
| F. First-run and empty | The single next action | One sentence on what will appear and what makes it appear |

---

## A. Triage scan — *optimise for scan speed*
**Screens:** Incident list, Cluster list, Audit log.

The user is looking for the one row that matters among hundreds. Everything serves the vertical scan.

- **Leading cell is identity, not status.** `.identity-block`: object name, kind, namespace, fault.
  A scan down the left edge is a scan of what is broken. Never lead with a coloured pill.
- Severity is a rule on the row edge (`.severity-rule` + `.sev-*`) **plus the word**.
- Densest mode in the product. Tight row height, `tabular-nums` on every compared number, `--font-mono`
  for identifiers.
- **Server-paginated, always** (`TablePagination`). Never sort or filter the current page client-side
  and present it as a sort of the whole set — the list caps at 500 (max 1000).
- Collapse near-identical rows to the interesting few plus a count.
- Filters are visible and their active state is obvious, because "no results" must be attributable to
  a filter (mode F).

## B. Single-object argument — *optimise for inspectable trust*
**Screens:** Incident detail (the core screen), Cluster detail.

This is where an engineer decides whether to believe a machine-authored diagnosis and let it change
production. The layout is an argument, and **it must answer the four questions in order.**

### The four-question standard (HLD §15.2) — a layout rule, not a suggestion
1. **What is broken?** Symptom, affected object, blast radius, user-facing yes/no, first/last seen,
   occurrence count. The `<h1>` is the affected object — *not* an opaque fingerprint.
2. **Why?** The causal chain, each link expandable to the evidence beneath it, plus `ruledOut` — what
   was disproved. **Never assert a root cause without letting the user open the evidence.** A
   conclusion with no drill-down is not auditable and will not be trusted twice.
3. **How do I fix it?** Options per channel with risk, reversibility, confidence, a rendered diff or
   action list, rollback plan, validation intent, and honest warnings. The primary control with its
   gate reason if blocked (see `components.md`).
4. **What happened?** The chronology, with durations.

**Check any new or restyled screen against this order.** Closing controls above the explanation is
backwards; so is a remediation panel above the causal chain. If a section cannot be built honestly
(see the gaps table below), say so in place — do not reorder around the gap and do not leave the
question unanswered silently.

## C. Worklist — *optimise for "what do I do next"*
**Screen:** Approval queue.

HLD §15.1 is explicit: **a worklist, not a dashboard.** No tiles, no charts, no summary row.

- Every item is actionable by this user, sorted server-side by severity then age.
- Each row carries enough to decide without navigating away: object, fault, proposed change, risk,
  route, and the gate state.
- The two gates read differently (`components.md`): "you cannot approve this" and "this cannot
  execute yet" are different sentences.
- Live-updating. An approval queue that needs a refresh is useless during an incident (HLD §15.3).
- Empty is the **good** state here and should read as success, not as absence.

**The density tension this mode actually has, and how to resolve it.** "Carries enough to decide
without navigating away" pushes rows *taller* — a real approval card is ~9 stacked blocks — so twenty
pending items is a long scroll. Mode A's density rules do not apply here. Resolve it by **collapsing
what is not actionable, never what is**: rows already approved or superseded may collapse, because
there is no decision left in them; a row awaiting this user's decision never collapses, since
collapsing it hides exactly the diff that stops approval being rubber-stamping. The long scroll on
actionable work is an accepted cost, not a problem to design away.

**A worklist may still count itself.** The mode bans a *summary row* of tiles, not a header that says
how much work is waiting — and that count must cover only rows that are actually actionable, or it
overstates the queue.

## D. Fleet aggregate — *optimise for "where is work stuck"*
**Screens:** Fleet overview, Insights.

The failure mode is a wall of tiles reading "healthy". A count of open incidents is inert; **where
they are stuck in the loop is actionable** — that is what `.pipeline-strip` is for.

- Lead with what is stuck or needs attention; collapse the healthy remainder to a count.
- A tile earns its place by answering a question someone actually asks. Four tiles because dashboards
  have four is the default this whole file exists to refuse.
- Cross-cluster correlation is the most valuable thing on the overview — fleet-wide issue groups
  surface above per-cluster detail.
- Aggregates are server-computed. Bucketing a capped list client-side undercounts (see gaps below).

## E. Configuration — *optimise for consequence visibility*
**Screens:** Policies, Repositories, Admin (users/roles/grants/IdP/integrations/spend caps).

Nobody visits these to browse. They arrive to change one thing and need to know what it will do.

- **State the consequence next to the control**, not in a help panel. A toggle that enables
  unattended execution says what that permits — **in one clause** ("Plans the policy auto-approves
  run without a human"), not a paragraph about how the policy engine works. That paragraph is the
  failure mode on these screens: the Settings page carried a dozen two-to-four-sentence blocks when
  this was written. Consequence beside the control; mechanism behind a `HelpTip` or `<details>`.
- Prefer a visible current state over a description of it: a chip row of what is allowlisted, a
  count of rules with the first few listed, a ceiling drawn as a bar against current spend. "Nothing
  is allowlisted, which is the default and the secure state: every private…" is a status chip
  ("None allowed · default") plus a `HelpTip`.
- Destructive and privilege-granting actions carry confirmation naming the specific target.
- **Disabled, not hidden**, with the missing capability and scope named — every sub-panel gated by
  its own capability, never one blanket "admin" check.
- Defaults are stated, so "unset" is distinguishable from "set to the default value".
- Policies wants dry-run-against-history to be tractable to author; **it is not built** — do not
  design as though it is.

## G. Presentation surface — *optimise for one action, a truthful failure, and the product's first impression*
**Screens:** Login (three selectable styles), first-run, onboarding, pre-data empty states.

Added 2026-08-25 as "unauthenticated gate"; **widened 2026-09-17**, because the narrow version did
real damage. The original carve-out was one sentence permitting "a centred single-column card", and
when the owner supplied three finished sign-in designs — a canvas particle field, a rotating camera
iris, an operations console — that sentence was used to argue each of them back into a plain card.
Two rebuilds later, the lesson is written down here instead:

**On this mode, the austerity of the operational modes does not apply, and the owner's visual
direction outranks this file.** Motion, a hero graphic, a committed dark palette, a display face the
app bar would never use, a full-bleed canvas — all legitimate. `SKILL.md`'s "which surface are you
on?" is the authority; this entry is the detail.

What still binds, and binds hardest here:

- **No data, invented or real.** Pre-authentication the hub must not reveal a cluster name, a count
  or a heartbeat, so every graphic is generative, self-referential, or a statement about the
  software. This is the rule supplied mockups break first — see `anti-patterns.md`'s Honesty
  section for the list of what was cut from the three designs.
- **No control without a flow behind it.** No reset link without a reset flow.
- **No fake progress.** One honest in-flight state, then success or the server's error.
- **Accessibility does not relax**, and dark-committed surfaces still need their contrast checked —
  two of the supplied designs had body text at roughly 2.2:1 and 3:1 against their own panels, which
  the owner reported as simply unreadable before any linter caught it.

- **The old note about `anti-patterns.md`'s "centered single-column heroes" ban:** it stands, for
  worklists. A centred card is correct here — and so is a two-panel split, and so is a hero graphic
  bleeding off the edge. The ban is about marketing-shaped layouts on screens that are being worked,
  not about this mode.
- **The four-state contract does not describe a credential form.** This screen never has data.
  Its real states are *bootstrapping* (checking whether an org exists yet), *ready*, *submitting* and
  *rejected* — and bootstrapping still owes a skeleton rather than a centred spinner, for the same
  layout-jump reason as everywhere else.
- **The credential standard**, which attaches to the FORM and not to the layout — so it survives a
  restyle, and so three visual styles can share one implementation: correct `autoComplete` tokens
  (`email` / `current-password`), a password reveal that is a real `<button type="button">` with
  `aria-pressed` and the words Show/Hide rather than a bare glyph, failure announced via
  `role="alert"`, the submit control disabled with a label rather than hidden, and federated sign-in
  rendered BELOW the password path so a break-glass super-admin is not hunting for it during an
  identity-provider outage.

  **`role="alert"` goes on the element only while it is showing a message.** A design that keeps a
  hidden error box in the DOM with placeholder text will otherwise announce the placeholder on load,
  and — found by a test — return it to any code looking for the live region, so the server's real
  error never surfaces.

  If the three styles' markup genuinely differs (one uses `input:focus + label` for a floating
  label, another wraps the input in a prefix row), **do not force a shared form component**. Three
  honest copies beat one abstraction that breaks the sibling selectors the CSS depends on.

Everything else applies unchanged: no fabricated state, no invented correlation id (there isn't one),
and the submit control disabled with a label rather than hidden.

## F. First-run and empty — *optimise for clarity to someone new*
**Applies to:** any screen with no data yet. This is a real mode, not a leftover.

Here the usual density rules **invert**: space and prose are correct, because the reader does not yet
know what the product does or what should appear.

- **"No results for these filters" and "nothing exists yet" are different states** and must read
  differently. The first offers a way back; the second explains what will appear here
  and how to make it happen ("enroll a cluster").
- An empty chart implies zero. A grey "not measured yet" chip implies unknown. Prefer the second.
- Empty is not always failure — an empty approval queue is success (mode C).

---

## What cannot be computed today

Inventing a number is the fastest way to produce a design nobody can build. Each of these was
re-checked against the code today. **Two rows below were themselves stale and actively suppressing
work** — a designer reading the old text was told not to build question 4 ("what happened") when the
data to build it had existed since 2026-08-25/28. Re-verify a claim in this table against the running
code before trusting it; this table has been wrong before.

| Wanted | Reality |
|---|---|
| "Resolved this week", time-to-resolution, MTTR | `resolved_at` (migration 000065) is real and populated — **625 incidents** carry it, verified against the dev database today. `last_seen` is still the last *finding*, not closure, so keep using the right column for the right fact; the column itself is no longer missing. **Now served, 2026-09-23:** `IncidentQuickViewCounts` carries `resolvedLast7Days` and `open` alongside the existing figures — whole-set counts scoped like the request, so a "resolved this week" tile no longer has to bucket the capped list (see the histogram row below). Rolling seven days from `now()`, not a calendar week. Time-to-resolution and MTTR are still NOT served; they would need `resolved_at - first_seen` aggregated server-side, which nothing computes. |
| "Stuck for 3 days", age-in-state | **Partially available, not absent.** `timeline_events` is written from real call sites (`orchestrator`, `gateway`, `api`) across **15 event types** (11 verified live today, plus `PullRequestMerged`/`PullRequestClosed`/`IncidentResolved`/`IncidentDismissed` added by D9's B7 fix) and **2,112+ real rows** exist. `GET /incidents/{id}/timeline` is live and returns them, oldest first. What is still genuinely missing is a fleet-wide *aggregate* over that history (age-in-state across every open incident, in one query) — the per-incident chronology itself is not the gap any more. |
| A 14-day histogram from the incident list | The list caps at **500** (`defaultIncidentPageLimit`, max 1000), ordered `last_seen DESC`. Bucketing it client-side undercounts. Needs a server-side aggregate, or label the window honestly. Still true for a *histogram*; the four headline figures on the overview stopped doing this on 2026-09-23 by reading `IncidentQuickViewCounts` instead (`open`, `requiresAction`, `resolvedLast7Days`, plus the cluster list, which is not paginated). Per-day buckets remain a client-side count over a capped list. |
| An incident timeline (question 4) | **Exists and is live.** `GET /incidents/{id}/timeline` is real (`internal/api/timeline.go`), rendered on the incident detail page inside the "What happened" disclosure (`IncidentDetailPage.tsx`'s `WhatHappenedDisclosure`/`TimelineEventNode`) — this was the other stale claim in this table. `.../plans` still does not exist. |
| Evidence drill-down (question 2 — per tool call) | **Exists for one tool call at a time.** `GET /incidents/{id}/evidence/{evId}` is real (`internal/api/evidence.go`) and each causal-chain step's `ToolCallChip` fetches it lazily when opened, falling back to the inline `causal_chain` copy for a pre-migration row or a `cli`-backend self-reported call. What is still missing is a path from the ROOT-CAUSE STATEMENT, the plan, or the next steps back to this evidence as a whole — only the per-step chips linked to it before D9's fix added one link from stage 3 back to the causal chain (`#causal-chain`). |
| A `requestId` / correlation id on an error | **Now exists, 2026-09-24 (`T23`).** Every RFC 9457 problem body carries a `requestId` extension member (`internal/api/server.go`'s `writeProblemWithExtras`), the same value is on the `X-Request-Id` response header of every response, and it is stamped on the `analyses` row a request produced (migration 000117). It is in `docs/openapi.yaml`'s `Problem` schema and in `generated.ts`, so rendering it is no longer inventing it — show it on an error surface so an operator can quote one string in a support request. A caller-supplied `X-Request-Id` is adopted only if it is ≤64 chars of `[A-Za-z0-9_-]`, so an echoed id is always safe to display. |
| AwaitingApproval vs AwaitingMerge, told apart in the approval queue | `approvalQueueItem` carries no `state` field, though the query selects both states. The queue can derive "waiting on a pull request" from `alreadyApproved`, which is a proxy, not the distinction. Report the gap rather than designing around it silently. |
| Time-in-queue / time-to-decision for an approval | Same missing state history. `plan.createdAt` is an honest proxy for "waiting for a decision" **if labelled as that** — note the queue's current "Waiting {firstSeen}" shows *incident* age, which is a different fact. |

**This table is not exhaustive, and it is weighted toward incident detail and the overview.** Before
claiming a number, check the field exists on the payload you actually read — several plausible metrics
on other screens are missing for the same underlying reason (no state-transition history).

When the data is not there, **say so in the design**. This codebase already learned it: `cost_basis`
renders `—` rather than `$0.00` precisely so a fabricated zero cannot look like a fact.
