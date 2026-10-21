import type { CreateEnrollmentTokenResponse } from '../api/types'

// The agent install: one `helm install` of the published agent chart against
// the target cluster's own kubeconfig, running as the least-privilege
// argus-investigate ServiceAccount (lld/04-rbac-profiles.md §4). Everything
// cluster-independent comes from the hub
// (`agentInstall`): which chart, which version was released with this hub,
// and the address agents reach it at. What the hub was not told is a visible
// placeholder, never a guess — both screens that print this used to default
// the address to localhost:8080 and point helm at a local chart directory.

export type AgentInstall = CreateEnrollmentTokenResponse['agentInstall']

export const HUB_URL_PLACEHOLDER = '<hub-api-url>'

export const TOKEN_SECRET = 'argus-enrollment-token'

/**
 * The install as three commands: the namespace, the token in a Secret, then
 * the chart pointed at that Secret — so the token is never stored in the
 * Helm release's values (PROJECT.md AD9).
 */
export function agentInstallCommand(token: string, install: AgentInstall): string {
  return [
    'kubectl create namespace argus-system --dry-run=client -o yaml | kubectl apply -f -',
    `kubectl create secret generic ${TOKEN_SECRET} -n argus-system \\`,
    `  --from-literal=token=${token} --dry-run=client -o yaml | kubectl apply -f -`,
    `helm install argus-agent ${install.chartRef} \\`,
    ...(install.chartVersion ? [`  --version ${install.chartVersion} \\`] : []),
    '  --namespace argus-system \\',
    '  --set namespace.create=false \\',
    `  --set hub.apiUrl=${install.hubApiUrl ?? HUB_URL_PLACEHOLDER} \\`,
    `  --set enrollment.tokenSecretRef.name=${TOKEN_SECRET}`,
  ].join('\n')
}
