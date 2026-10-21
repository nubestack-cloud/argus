import { describe, expect, it } from 'vitest'

import { CAPABILITY_INFO, capabilityAction, missingCapabilityMessage } from './capabilityInfo'

// Item 13(a). The message an operator sees when a control is disabled used to
// be the raw wire constant the hub checks — "Missing capability:
// remediation:execute:inplace" — which named the identifier and answered
// nothing they asked. These tests hold both halves of the replacement: it reads
// as a sentence, AND it still names the constant, because the constant is what
// makes a support request actionable.

describe('missingCapabilityMessage', () => {
  it('reads as a sentence and still names the capability', () => {
    const message = missingCapabilityMessage(['remediation:rollback'])
    expect(message).toBe(
      'You do not have permission to roll back a remediation that was already applied (remediation:rollback). Ask an administrator to grant it.',
    )
  })

  it('joins two capabilities without producing a comma-separated list of constants', () => {
    const message = missingCapabilityMessage(['remediation:rollback', 'remediation:execute:inplace'])
    expect(message).toMatch(/roll back a remediation that was already applied \(remediation:rollback\)/)
    expect(message).toMatch(/or to apply a remediation directly to a live cluster \(remediation:execute:inplace\)/)
    expect(message).toMatch(/grant them\.$/)
    // The old shape, which is what this replaces.
    expect(message).not.toContain('remediation:rollback, remediation:execute:inplace')
  })

  it('renders an unknown capability verbatim rather than inventing a description of it', () => {
    // A capability just added to permissions.go and not yet in the map. Naming
    // it is honest; describing what it permits would be a guess.
    const message = missingCapabilityMessage(['policy:simulate'])
    expect(message).toContain('policy:simulate')
    expect(message).toMatch(/use "policy:simulate"/)
  })

  it('returns nothing for an empty list — a caller with nothing missing must not be given a refusal', () => {
    expect(missingCapabilityMessage([])).toBe('')
  })
})

describe('capabilityAction', () => {
  // The sentence above reads "permission to <action>", so every label in the
  // map has to survive having its first letter lowered and still be a verb
  // phrase. A label rewritten as a noun ("Audit log access") would produce
  // "permission to audit log access", which is why this is checked over the
  // whole map rather than on one example.
  it('turns every catalogued label into a phrase that can follow "permission to"', () => {
    for (const [capability, info] of Object.entries(CAPABILITY_INFO)) {
      const action = capabilityAction(capability)
      expect(action).toBe(info.label.charAt(0).toLowerCase() + info.label.slice(1))
      expect(`You do not have permission to ${action}.`).toMatch(/^You do not have permission to [a-z]/)
    }
  })
})
