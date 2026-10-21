---
name: argus-visual-test
description: Look at an ARGUS UI change in a real browser — Playwright against a running hub, a sweep of widths from 375 to 2560 in light and dark, screenshots saved to an absolute path, and an automatic check for sideways scroll, clipped text and console errors. Use after a change adds or reworks a rendered surface (page, tab, panel, dialog, chart, layout), when the owner reports something "looks off" or overflows, or when argus-qa calls for the visual check. Complements argus-design-review, which reads the code; this one looks at the result.
argument-hint: [pages or tabs to check — defaults to what the diff touches]
---

# Look at the rendered UI

`argus-design-review` reads the code and cannot see a rendered break. This skill looks at the
result. Both are needed for a real UI change, and neither replaces the other.

## 1. Scope it from the diff

`git diff --stat -- web/` and decide which routes and tabs render the changed code. Name them before
starting; "check everything" produces a hundred screenshots nobody reads.

Routes are in `web/src/App.tsx`. The cluster page's tabs are URL state, so each is directly
reachable: `/clusters/<id>?tab=<tab>` with tab ids from `ClusterDetailPage.tsx`'s tab list
(`overview`, `timeline`, `incidents`, `map`, `gitops`, `helm`, `certificates`, `upgrade`, `posture`,
`traffic`, `netpol`, `cost`, `agent`). Use real IDs from `GET /api/v1/clusters` and
`GET /api/v1/incidents`.

## 2. Make sure the browser will see the new code

The UI is compiled into the hub (`go:embed` from `internal/api/static`), so there are two honest
targets:

- **The live hub after a rollout** ([`argus-live-test`](../argus-live-test/SKILL.md) steps 1–2),
  with the served bundle confirmed to contain a string only the new code has. This is what the owner
  will see, against real data.
- **Vite's dev server** (`cd web && npm run dev`) proxying `/api` to a running hub. It is fast for
  layout iteration, but it is not the embedded build, so finish on the hub for anything you report
  as done.

`npm run build` alone does not change what a hub serves.

## 3. Run the probe

[`probe.cjs`](probe.cjs) signs in, walks pages × widths × themes, saves a screenshot of each, and
prints only what it found: the page scrolling sideways (with the outermost elements responsible),
text clipped inside an `overflow: hidden` box, and console errors.

```
ARGUS_PW=<from the bootstrap Secret, via a variable, never echoed> \
BASE=<hub or Vite URL> OUT=<absolute scratchpad dir> \
PAGES=/incidents,/clusters/<id>?tab=netpol WIDTHS=375,768,1024,1440,2560 \
node .claude/skills/argus-visual-test/probe.cjs
```

Widths, and why each one is there:

- **375**: a phone, where grids that never collapse and fixed `min-width`s break.
- **768 and 1024**: the breakpoints, where two-column layouts fold.
- **1440**: the common desktop.
- **2560**: a wide monitor, where a root missing `min-width: 0` or a flex fill leaves a panel stranded
  at content width, and a capped `max-width` leaves a strip of nothing.

Run both themes whenever a colour, token or surface changed. A hard-coded white only shows up in dark
mode, which is why it ships.

## 4. Look at the screenshots

The probe finds geometry, not quality. Open the shots for the changed surface and check:

- data renders: not blank, not `undefined`, not a skeleton that never resolved;
- the empty state reads as empty (a filtered-empty and a never-had-data state are different);
- severity and status carry a word, not only a colour;
- long unbroken values (image references, `v1.31.4+rke2r1`, UIDs) wrap or truncate with a full
  value on hover, never spill;
- controls the viewer lacks capability for are disabled with the reason, not missing;
- nothing sits under the app bar, a sticky footer or a floating control;
- dark mode text meets its contrast floor.

For a flow (a drawer, a disclosure, a dialog, a bulk action), drive it with a short Playwright
script of your own: click, then screenshot the element (`locator.screenshot()`) rather than the
whole page. Click the control that is actually wired: in tables that is usually the name link, not
the row.

## 5. Gotchas specific to this app

- **The change-password banner** shows for the bootstrap admin and pushes everything down; it is
  expected, not a layout bug.
- **Data on the lab hub is real.** Do not paste cluster names, namespaces or object names from
  screenshots into anything that leaves this machine.
- **The cluster page lazy-loads its tabs.** Give a tab time to fetch (`WAIT`) before judging it
  empty; a skeleton in the first screenshot is not a finding.
- **Selected cluster and filters persist in the URL and local storage.** A page that looks empty may
  be filtered; check the filter bar before reporting missing data.

## 6. Report

```
visual: ran · 40 shots · /abs/path/to/shots/
  ✓ /incidents at 375–2560, light and dark
  ✗ /clusters/<id>?tab=netpol @375 dark: page scrolls sideways +112px (table.netpol-matrix) — shot: clusters-…-375-dark.png
  – /approvals not checked: no pending approvals to render
console errors: none
```

An absolute path (never `~/` or relative) so the terminal links it. Say what you could not check
and why. Keep the screenshots; the owner may want them.
