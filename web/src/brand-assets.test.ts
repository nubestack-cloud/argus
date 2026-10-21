// Guards on the two brand assets that no other test can see.
//
// public/favicon.svg is not imported by any module, is not type-checked, and
// is not rendered by any component test — Vite copies it verbatim and the hub
// embeds it. So the ONLY thing standing between a malformed favicon and
// production is a human looking at a browser tab, and a browser tab is exactly
// where nobody looks: a broken SVG favicon fails silently, with a 200 and a
// correct Content-Type on the wire, no console error, and a blank or generic
// icon that looks like ordinary favicon caching.
//
// That is not hypothetical. This file exists because the favicon shipped
// malformed for a day: a comment inside it referred to a CSS custom property by
// name, and the leading double hyphen is illegal inside an XML comment, so
// every browser refused to parse the document. `curl` looked perfect
// throughout.
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

// `process.cwd()`, not `import.meta.url`: under Vitest's jsdom environment the
// module URL is an http:// one and `readFileSync` rejects it ("The URL must be
// of scheme file"). Vitest runs from the package root, so this resolves to
// web/public/favicon.svg.
const favicon = readFileSync(resolve(process.cwd(), 'public/favicon.svg'), 'utf-8')

// The markup with comments stripped. Content assertions run against THIS, not
// the raw file: the comments in that file discuss the colour it must not use
// and the mechanisms it must not depend on, by name, so a raw-text check
// reports its own documentation as a violation. (It did, on the first run.)
const drawing = favicon.replace(/<!--[\s\S]*?-->/g, '')

describe('public/favicon.svg', () => {
  it('is well-formed XML', () => {
    const doc = new DOMParser().parseFromString(favicon, 'application/xml')
    const error = doc.querySelector('parsererror')
    expect(error?.textContent ?? null).toBeNull()
    expect(doc.documentElement.tagName).toBe('svg')
  })

  // The specific trap that broke it, called out separately from the parse check
  // so the failure message names the cause instead of an XML line number.
  it('has no double hyphen inside a comment', () => {
    const comments = favicon.match(/<!--[\s\S]*?-->/g) ?? []
    expect(comments.length).toBeGreaterThan(0)
    for (const comment of comments) {
      expect(comment.slice(4, -3)).not.toContain('--')
    }
  })

  // Geometry parity with ArgusLogoMark — of the PROPORTIONS, not the numbers.
  //
  // This drawing is deliberately hinted: at 16px the component's 3.4-wide
  // blade is 0.85 of a device pixel and renders as fuzz, so the favicon's
  // blades are wider and reach further out. Pinning its literal numbers to the
  // component's would therefore be pinning the wrong thing, and "fixing" the
  // mismatch would break the icon at the only sizes it is ever seen at.
  //
  // What must hold is the relationship that makes it read as the same mark: a
  // sleeping blade is HALF a waking one, measured from the inner end at radius
  // 9 — which is exactly what the component's `scaleY(0.5)` about y=23
  // computes, and the one thing a careless edit to either file would silently
  // break.
  it('draws twelve blades whose sleeping three are half length about the inner end', () => {
    const doc = new DOMParser().parseFromString(favicon, 'application/xml')
    const blades = [...doc.querySelectorAll('rect')].map((r) => ({
      y: Number(r.getAttribute('y')),
      height: Number(r.getAttribute('height')),
      width: Number(r.getAttribute('width')),
      transform: r.getAttribute('transform'),
    }))
    expect(blades).toHaveLength(12)

    // Every blade is a rounded bar of one width, and every blade's inner end
    // sits on radius 9 (y = 23) whether it is retracted or not.
    for (const b of blades) {
      expect(b.width).toBe(blades[0].width)
      expect(b.y + b.height).toBeCloseTo(23, 5)
    }

    const lengths = [...new Set(blades.map((b) => b.height))].sort((a, b) => b - a)
    expect(lengths).toHaveLength(2)
    const [waking, sleeping] = lengths
    expect(sleeping).toBeCloseTo(waking / 2, 5)

    expect(blades.filter((b) => b.height === waking)).toHaveLength(9)
    const asleep = blades.filter((b) => b.height === sleeping)
    expect(asleep).toHaveLength(3)
    // The three that sleep in the still mark are phase 0 in the component, and
    // they sit 120 degrees apart so the closed blades are never a dark wedge.
    expect(asleep.map((b) => b.transform).sort()).toEqual([
      'rotate(210 32 32)',
      'rotate(330 32 32)',
      'rotate(90 32 32)',
    ])

    expect(doc.querySelectorAll('circle')).toHaveLength(1)
  })

  // A tab renders this into a box about 16 pixels on a side and adds no padding
  // of its own, so every unit of margin inside the file is size the icon can
  // never get back. The viewBox is therefore cropped to the ink exactly, and
  // this is the test that keeps it that way: the failure it exists to catch is
  // a redraw that changes the outer radius and leaves the viewBox behind, which
  // shows up as an icon that is quietly smaller than it could be — the kind of
  // thing nobody notices in a tab strip.
  it('fills the whole canvas: the viewBox is the ink, with no margin', () => {
    const doc = new DOMParser().parseFromString(favicon, 'application/xml')
    const [minX, minY, width, height] = (doc.documentElement.getAttribute('viewBox') ?? '')
      .split(/\s+/)
      .map(Number)
    expect([minX, minY, width, height].some(Number.isNaN)).toBe(false)
    expect(width).toBe(height)

    // Square and centred on the point every radius in the file is measured
    // from, so the mark cannot sit off-centre in the tab.
    const CENTRE = 32
    expect(minX + width / 2).toBeCloseTo(CENTRE, 5)
    expect(minY + height / 2).toBeCloseTo(CENTRE, 5)

    // The blades at 0/90/180/270 degrees reach the edges. Their tips are the
    // drawing's extreme points, so `min(y) === minY` means zero dead margin,
    // and any tighter crop would clip them.
    const tips = [...doc.querySelectorAll('rect')].map((r) => Number(r.getAttribute('y')))
    expect(Math.min(...tips)).toBeCloseTo(minY, 5)

    // With that crop, a blade is over a device pixel wide at 16px rather than
    // the 0.85 the component's own geometry would give — ink, not fuzz.
    const bladeWidth = Number(doc.querySelector('rect')?.getAttribute('width'))
    expect((bladeWidth * 16) / width).toBeGreaterThan(1)
  })

  // The mark holds one colour on every ground; the type beside it is what
  // follows the theme. A dark-mode override here would contradict that, and did
  // once (#6aada9).
  it('states the brand colour once and does not recolour with the theme', () => {
    const literals = new Set(drawing.match(/#[0-9a-fA-F]{3,8}/g) ?? [])
    expect([...literals]).toEqual(['#3c7d7d'])
    expect(drawing).not.toContain('prefers-color-scheme')
    // No stylesheet at all: nothing to inherit from outside a page, and no
    // guarantee the rasterizer supports one.
    expect(drawing).not.toContain('<style')
    expect(drawing).not.toContain('currentColor')
  })
})
