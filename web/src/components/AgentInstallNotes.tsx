import { HUB_URL_PLACEHOLDER, type AgentInstall } from '../utils/agentInstall'

/** What the printed agent install command could not fill in, said plainly
 *  under it: the hub's address, and the pinned chart version. */
export function AgentInstallNotes({ install }: { install: AgentInstall }) {
  return (
    <>
      {!install.hubApiUrl && (
        <p className="banner banner-warning" role="note">
          This hub was not told the address clusters reach it at, so the command has{' '}
          <code>{HUB_URL_PLACEHOLDER}</code> in its place. Replace it with this hub&apos;s URL as seen from
          the target cluster — or set <code>publicApiUrl</code> in the hub&apos;s Helm values and this command
          fills it in.
        </p>
      )}
      {!install.chartVersion && (
        <p className="field-hint">
          This hub is a development build, so no agent chart version is pinned: Helm installs the newest
          published one.
        </p>
      )}
    </>
  )
}
