import { describe, expect, it } from 'vitest'
import { agentInstallCommand, HUB_URL_PLACEHOLDER } from './agentInstall'

const ref = 'oci://registry-1.docker.io/nubestack/argus-agent-chart'

describe('agentInstallCommand', () => {
  it('pins the chart released with the hub and uses the hub address it was given', () => {
    const cmd = agentInstallCommand('tok_1', { chartRef: ref, chartVersion: '0.2.0', hubApiUrl: 'https://argus.example.com' })
    expect(cmd).toContain(`helm install argus-agent ${ref}`)
    expect(cmd).toContain('--version 0.2.0')
    expect(cmd).toContain('--set hub.apiUrl=https://argus.example.com')
    // The token goes into a Secret first and never into the release's values (AD9).
    expect(cmd).toContain('--from-literal=token=tok_1')
    expect(cmd).toContain('--set enrollment.tokenSecretRef.name=argus-enrollment-token')
    expect(cmd).not.toContain('enrollment.token=')
    expect(cmd.indexOf('create secret')).toBeLessThan(cmd.indexOf('helm install'))
    // The namespace exists before helm runs, so the chart must not create it.
    expect(cmd).toContain('--set namespace.create=false')
  })

  it('prints a placeholder, never a guessed localhost, when the hub was not told its address', () => {
    const cmd = agentInstallCommand('tok_1', { chartRef: ref, chartVersion: '0.2.0', hubApiUrl: null })
    expect(cmd).toContain(`--set hub.apiUrl=${HUB_URL_PLACEHOLDER}`)
    expect(cmd).not.toContain('localhost')
  })

  it('leaves the version out for a development hub rather than inventing one', () => {
    expect(agentInstallCommand('tok_1', { chartRef: ref, chartVersion: null, hubApiUrl: null })).not.toContain('--version')
  })
})
