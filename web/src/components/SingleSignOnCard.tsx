import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ApiError,
  addIdentityGroupMapping,
  deleteIdentityGroupMapping,
  deleteIdentityProvider,
  getIdentityProviders,
  getRoles,
  saveIdentityProvider,
} from '../api/client'
import type { IdentityProvider } from '../api/types'
import { useAuth } from '../auth/useAuth'
import { PanelHead } from './SettingsBlocks'
import { HelpTip } from './HelpTip'

// Settings → Single sign-on (PROJECT.md S2). Until this existed a provider was
// configured by calling the admin API directly, which is the last thing the S2
// "done when" was waiting on.
//
// Configuration mode, and it deliberately reuses the list primitives
// RepositoriesCard already borrowed for a non-AI subject (`.ai-provider*`)
// rather than adding a third near-identical vocabulary. Zero new classes.
//
// Two things here are NOT generic admin-panel furniture, and they are why this
// card carries prose at all:
//   - a group mapping is re-synchronised on EVERY login, so removing somebody
//     from a directory group removes their access here on their next sign-in.
//     It only ever touches grants ARGUS created from an IdP; a manual grant is
//     left alone. An admin who does not know that will not understand why a
//     grant vanished.
//   - password login keeps working for an account holding super-admin, so an
//     IdP outage cannot lock every operator out.
// Both are decisions recorded on S2, and both change what an admin does here.
const DEFAULT_SCOPES = 'openid, email, profile, groups'

type FormState = {
  id?: string
  displayName: string
  issuer: string
  clientId: string
  clientSecret: string
  scopes: string
  groupsClaim: string
  redirectUri: string
  enabled: boolean
  hasClientSecret: boolean
}

const blank = (origin: string): FormState => ({
  displayName: '',
  issuer: '',
  clientId: '',
  clientSecret: '',
  scopes: DEFAULT_SCOPES,
  groupsClaim: 'groups',
  redirectUri: `${origin}/api/v1/auth/sso/callback`,
  enabled: true,
  hasClientSecret: false,
})

const fromProvider = (p: IdentityProvider): FormState => ({
  id: p.id,
  displayName: p.displayName,
  issuer: p.issuer,
  clientId: p.clientId,
  clientSecret: '',
  // internal/api/idp_admin.go declares scopes as a plain []string with no
  // omitempty, so a provider stored with no extra scopes arrives as JSON null,
  // not []. An empty field is the honest rendering of that.
  scopes: (p.scopes ?? []).join(', '),
  groupsClaim: p.groupsClaim,
  redirectUri: p.redirectUri,
  enabled: p.enabled,
  hasClientSecret: p.hasClientSecret,
})

export function SingleSignOnCard({ canWrite, disabledReason }: { canWrite: boolean; disabledReason?: string }) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const [form, setForm] = useState<FormState | null>(null)
  const [mapping, setMapping] = useState<{ providerId: string; groupName: string; roleId: string } | null>(null)

  const providersQuery = useQuery({
    queryKey: ['identity-providers'],
    queryFn: () => getIdentityProviders(accessToken!),
    enabled: !!accessToken,
  })
  const rolesQuery = useQuery({
    queryKey: ['roles'],
    queryFn: () => getRoles(accessToken!),
    enabled: !!accessToken,
  })
  const refresh = () => queryClient.invalidateQueries({ queryKey: ['identity-providers'] })

  const saveMutation = useMutation({
    mutationFn: (f: FormState) =>
      saveIdentityProvider(
        {
          displayName: f.displayName.trim(),
          issuer: f.issuer.trim(),
          clientId: f.clientId.trim(),
          scopes: f.scopes.split(',').map((s) => s.trim()).filter(Boolean),
          groupsClaim: f.groupsClaim.trim(),
          redirectUri: f.redirectUri.trim(),
          enabled: f.enabled,
          // Blank means "keep the stored secret" on an edit, and "no secret"
          // on a create — never an empty string overwriting a real one.
          clientSecret: f.clientSecret ? f.clientSecret : null,
        },
        accessToken!,
        f.id,
      ),
    onSuccess: () => { setForm(null); refresh() },
  })
  const removeMutation = useMutation({
    mutationFn: (id: string) => deleteIdentityProvider(id, accessToken!),
    onSuccess: refresh,
  })
  const addMappingMutation = useMutation({
    mutationFn: (m: { providerId: string; groupName: string; roleId: string }) =>
      addIdentityGroupMapping(m.providerId, { groupName: m.groupName.trim(), roleId: m.roleId }, accessToken!),
    onSuccess: () => { setMapping(null); refresh() },
  })
  const removeMappingMutation = useMutation({
    mutationFn: (m: { providerId: string; mappingId: string }) =>
      deleteIdentityGroupMapping(m.providerId, m.mappingId, accessToken!),
    onSuccess: refresh,
  })

  const providers = providersQuery.data?.providers ?? []
  const roleNames = Object.keys(rolesQuery.data?.roles ?? {})
  const origin = typeof window === 'undefined' ? '' : window.location.origin

  return (
    <div className="settings-section card settings-panel" role="tabpanel">
      <PanelHead
        title="Single sign-on"
        lede="Sign in through your own OpenID Connect provider."
        help="ARGUS speaks OpenID Connect and nothing else — LDAP, Active Directory and SAML reach it through a broker that presents them as an OIDC provider, so there is one flow to configure rather than one per vendor."
      />
      <p className="consequence-notice">
        Password sign-in keeps working for an account holding super-admin, so an outage at your
        identity provider cannot lock every operator out.
      </p>

      {providersQuery.isLoading && <p className="field-hint">Loading providers…</p>}
      {providersQuery.isError &&
        (providersQuery.error instanceof ApiError && providersQuery.error.status === 403 ? (
          // The same "no access" statement every other settings section makes,
          // naming the capability, rather than the bare refusal title.
          <p className="banner banner-warning" role="alert">
            You don't have access to view or change single sign-on. {disabledReason}
          </p>
        ) : (
          <p className="form-error inline-error" role="alert">
            {providersQuery.error instanceof ApiError
              ? providersQuery.error.message
              : 'Could not load identity providers.'}
          </p>
        ))}

      {!providersQuery.isLoading && !providersQuery.isError && providers.length === 0 && (
        <p className="ai-provider-empty">
          No identity provider configured. Everyone signs in with a password.
        </p>
      )}

      {providers.length > 0 && (
        <ul className="ai-provider-list">
          {providers.map((p) => (
            <li key={p.id} className="ai-provider">
              <div className="ai-provider-identity">
                <strong>{p.displayName}</strong>{' '}
                {/* The word, not the colour: an enabled/disabled state carried by a
                    tint alone is the rule this codebase breaks least willingly. */}
                <span className={p.enabled ? 'badge badge-gray' : 'badge badge-amber'}>
                  {p.enabled ? 'Enabled' : 'Disabled'}
                </span>
                <p className="field-hint wrap-anywhere">{p.issuer}</p>
                <p className="field-hint">
                  Groups read from <code>{p.groupsClaim}</code> ·{' '}
                  {p.hasClientSecret ? 'client secret stored' : 'no client secret'}
                </p>
              </div>

              <div className="ai-provider-actions">
                <button type="button" className="secondary" disabled={!canWrite} title={disabledReason}
                  onClick={() => setForm(fromProvider(p))}>
                  Edit…
                </button>
                <button type="button" className="secondary" disabled={!canWrite || removeMutation.isPending}
                  title={disabledReason} onClick={() => removeMutation.mutate(p.id)}>
                  Remove…
                </button>
              </div>

              <div>
                <p className="field-hint">
                  <strong>Group mappings</strong>{' '}
                  <HelpTip
                    label="group mappings"
                    text="Re-checked at every sign-in: someone removed from a group here loses the matching access on their next login. Only grants ARGUS created from this provider are touched — a grant you made by hand is left alone. Every mapping applies to all clusters."
                  />
                </p>
                {p.groupMappings.length === 0 ? (
                  <p className="field-hint">
                    No groups mapped, so a successful sign-in grants nothing yet.
                  </p>
                ) : (
                  <ul>
                    {p.groupMappings.map((m) => (
                      <li key={m.id}>
                        <code>{m.groupName}</code> → {m.roleId}{' '}
                        <button type="button" className="secondary" disabled={!canWrite}
                          title={disabledReason}
                          onClick={() => removeMappingMutation.mutate({ providerId: p.id, mappingId: m.id })}>
                          Remove
                        </button>
                      </li>
                    ))}
                  </ul>
                )}

                {mapping?.providerId === p.id ? (
                  <div className="settings-actions-row">
                    <label htmlFor={`grp-${p.id}`}>Group</label>
                    <input id={`grp-${p.id}`} value={mapping.groupName}
                      onChange={(e) => setMapping({ ...mapping, groupName: e.target.value })} />
                    <label htmlFor={`role-${p.id}`}>Role</label>
                    <select id={`role-${p.id}`} value={mapping.roleId}
                      onChange={(e) => setMapping({ ...mapping, roleId: e.target.value })}>
                      {roleNames.map((r) => <option key={r} value={r}>{r}</option>)}
                    </select>
                    <button type="button" disabled={!canWrite || !mapping.groupName.trim() || addMappingMutation.isPending}
                      title={disabledReason} onClick={() => addMappingMutation.mutate(mapping)}>
                      {addMappingMutation.isPending ? 'Adding…' : 'Add mapping'}
                    </button>
                    <button type="button" className="secondary" onClick={() => setMapping(null)}>Cancel</button>
                  </div>
                ) : (
                  <button type="button" className="secondary" disabled={!canWrite} title={disabledReason}
                    onClick={() => setMapping({ providerId: p.id, groupName: '', roleId: roleNames[0] ?? 'viewer' })}>
                    Map a group…
                  </button>
                )}
                {addMappingMutation.isError && mapping?.providerId === p.id && (
                  <p className="form-error inline-error" role="alert">
                    {addMappingMutation.error instanceof ApiError
                      ? addMappingMutation.error.message : 'Could not add the mapping.'}
                  </p>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}

      {form ? (
        <form
          onSubmit={(e) => { e.preventDefault(); saveMutation.mutate(form) }}
        >
          <h3>{form.id ? 'Edit provider' : 'Add a provider'}</h3>
          <label htmlFor="idp-name">Display name</label>
          <input id="idp-name" value={form.displayName} required
            onChange={(e) => setForm({ ...form, displayName: e.target.value })} />
          <p className="field-hint">What the button on the sign-in page will say.</p>

          <label htmlFor="idp-issuer">Issuer URL</label>
          <input id="idp-issuer" value={form.issuer} required placeholder="https://dex.example.com"
            onChange={(e) => setForm({ ...form, issuer: e.target.value })} />
          <p className="field-hint">
            ARGUS fetches this issuer's OpenID configuration when you save, so a wrong or unreachable
            URL is refused here rather than at somebody's first sign-in.
          </p>

          <label htmlFor="idp-client">Client ID</label>
          <input id="idp-client" value={form.clientId} required
            onChange={(e) => setForm({ ...form, clientId: e.target.value })} />

          <label htmlFor="idp-secret">
            Client secret {form.hasClientSecret && <span className="field-optional">leave blank to keep</span>}
          </label>
          <input id="idp-secret" type="password" value={form.clientSecret}
            autoComplete="new-password"
            onChange={(e) => setForm({ ...form, clientSecret: e.target.value })} />

          <label htmlFor="idp-redirect">Redirect URI</label>
          <input id="idp-redirect" value={form.redirectUri} required
            onChange={(e) => setForm({ ...form, redirectUri: e.target.value })} />
          <p className="field-hint">
            Register this exact value with your provider. For this hub it is{' '}
            <code className="wrap-anywhere">{origin}/api/v1/auth/sso/callback</code>.
          </p>

          <label htmlFor="idp-scopes">Scopes</label>
          <input id="idp-scopes" value={form.scopes}
            onChange={(e) => setForm({ ...form, scopes: e.target.value })} />

          <label htmlFor="idp-groups">Groups claim</label>
          <input id="idp-groups" value={form.groupsClaim}
            onChange={(e) => setForm({ ...form, groupsClaim: e.target.value })} />
          <p className="field-hint">
            The claim carrying group membership. Group mappings are matched against it.
          </p>

          <label htmlFor="idp-enabled">
            <input id="idp-enabled" type="checkbox" checked={form.enabled}
              onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />{' '}
            Offer this provider on the sign-in page
          </label>

          {saveMutation.isError && (
            <p className="form-error inline-error" role="alert">
              {saveMutation.error instanceof ApiError ? saveMutation.error.message : 'Could not save the provider.'}
            </p>
          )}
          <div className="settings-actions-row">
            <button type="submit" disabled={!canWrite || saveMutation.isPending} title={disabledReason}>
              {saveMutation.isPending ? 'Saving…' : 'Save provider'}
            </button>
            <button type="button" className="secondary" onClick={() => setForm(null)}>Cancel</button>
          </div>
        </form>
      ) : (
        <div className="settings-actions-row">
          {/* Disabled, never hidden, with the missing capability named. */}
          <button type="button" disabled={!canWrite} title={disabledReason}
            onClick={() => setForm(blank(origin))}>
            Add a provider
          </button>
        </div>
      )}
      {removeMutation.isError && (
        <p className="form-error inline-error" role="alert">
          {removeMutation.error instanceof ApiError ? removeMutation.error.message : 'Could not remove the provider.'}
        </p>
      )}
    </div>
  )
}
