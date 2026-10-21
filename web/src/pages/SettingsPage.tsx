import { useState } from 'react'
import type { FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { getSettings, getRoles, updateSettings, dryRunDetectionSettings, getDiagnosticsBundle, ApiError } from '../api/client'
import type {
  BuiltinRole,
  DetectionDryRunResponse,
  IncidentSeverity,
  OutboundPrivateDestination,
  Settings,
  UpdateSettingsRequest,
} from '../api/types'
import { BUILTIN_ROLES, ROLE_LABELS, ROLE_NOTES } from '../api/types'
import { CAPABILITY_GROUP_LABELS, CAPABILITY_GROUP_ORDER, CAPABILITY_INFO, missingCapabilityMessage } from '../api/capabilityInfo'
import { CAP_IDENTITY_MANAGE, CAP_ORG_SETTINGS_WRITE, CAP_REPO_READ, CAP_REPO_WRITE, CAP_ROLE_MANAGE, CAP_CLUSTER_GROUP_MANAGE } from '../api/capabilities'
import { useAuth } from '../auth/useAuth'
import { useHasCapability } from '../auth/useCapabilities'
import { applyAccent } from '../theme'
import { SkeletonLines } from '../components/Skeleton'
import { HelpTip } from '../components/HelpTip'
import { InEffect, PanelHead } from '../components/SettingsBlocks'
import { Segmented } from '../components/SplitBar'
import { AIProvidersCard } from '../components/AIProvidersCard'
import { AutomationWindowsCard } from '../components/AutomationWindowsCard'
import { CircuitBreakerCard } from '../components/CircuitBreakerCard'
import { SingleSignOnCard } from '../components/SingleSignOnCard'
import { RepositoriesCard } from '../components/RepositoriesCard'
import { PersonalTokensSection } from '../components/PersonalTokensSection'
import { CustomRolesCard } from '../components/CustomRolesCard'
import { ClusterGroupsCard } from '../components/ClusterGroupsCard'
import { NotificationRoutingCard } from '../components/NotificationRoutingCard'
import { OutboundAllowlistCard } from '../components/OutboundAllowlistCard'
import { ChipMark, SaveIcon, SearchIcon } from '../components/icons'
import { DETECTOR_OPTIONS } from '../utils/detectors'

// A masked secret field's placeholder communicates "set" vs "not set"
// without ever round-tripping the real value — the API never returns one
// (see api/types.ts's Settings doc comment). Typing here means "replace
// it"; leaving it blank and not checking "Clear" means "leave unchanged."
function secretPlaceholder(isSet: boolean): string {
  return isSet ? '•••••••• (unchanged)' : 'Not set'
}

// The page's navigable sections. Related groups of the settings payload stay
// separate cards/forms inside one section, so saving and secret-field semantics
// are unchanged; only the navigation moved.
//
// "General" was removed once before, for a good reason that no longer applies:
// it was an EMPTY placeholder, and the backend exposes no general organization
// settings, so it would have been a heading over invented controls. It is back
// holding two things that already existed and were filed under "Operations"
// with the detector checkboxes — data retention. That is not about
// detection, both are install-wide housekeeping, and that mismatch is what made
// "Operations" the section nobody could predict the contents of. No control here
// is new; nothing was invented to fill it.
type SettingsSection =
  | 'general'
  | 'detectors'
  | 'analysis'
  | 'automation'
  | 'providers'
  | 'pricing'
  | 'repositories'
  | 'notifications'
  | 'routing'
  | 'outbound'
  | 'appearance'
  | 'access'
  | 'sso'
  | 'ai-tools'
  | 'diagnostics'

// A LIST DOWN THE LEFT, grouped, rather than six tabs across the top. Two
// reasons the tab strip stopped working: a horizontal strip has to stay on one
// line, so it caps how many sections there can be and forces broad labels
// ("Operations") that end up holding unrelated things; and a tab strip is flat,
// so it cannot say that AI providers and model pricing are the same subject
// while Git repositories is a different one. A vertical list has room to grow
// and room for headings.
//
// `settings` says whether the section renders GET /admin/settings at all. The
// ones that do not are rendered without asking for it (standaloneSections in
// SettingsPage), so opening them neither waits on that request nor is blocked
// by a viewer's 403 from it.
//
// `form` says whether the section is backed by the page-level settings form, and
// therefore whether the "Save settings" bar belongs at the bottom of it. It used
// to be an inline `activeTab !== 'access' && activeTab !== 'providers'`, which
// left the bar on the Git repositories section — where every change goes through
// a per-repository dialog, so it was a Save button with nothing to save.
const SETTINGS_SECTIONS: Array<{ id: SettingsSection; label: string; form: boolean; settings: boolean }> = [
  { id: 'general', settings: true, label: 'General', form: true },
  { id: 'detectors', settings: true, label: 'Detectors', form: true },
  { id: 'analysis', settings: true, label: 'Investigation', form: true },
  // Split out of Investigation: deciding what ARGUS may CHANGE without a person
  // is a different question from how it investigates, and the two shared one
  // section four cards deep, with the unattended switch below the fold.
  { id: 'automation', settings: true, label: 'Automation', form: true },
  { id: 'providers', settings: true, label: 'AI providers', form: false },
  { id: 'pricing', settings: true, label: 'Model pricing', form: true },
  { id: 'repositories', settings: false, label: 'Git repositories', form: false },
  { id: 'notifications', settings: true, label: 'Notifications', form: true },
  // form: false — this section owns its own endpoint (GET/PUT
  // /admin/notification-routing) and its own Save, so the page's "Save
  // settings" bar would be a second save button with nothing to save.
  { id: 'routing', settings: false, label: 'Notification routing', form: false },
  { id: 'outbound', settings: true, label: 'Outbound access', form: true },
  { id: 'appearance', settings: true, label: 'Appearance', form: true },
  { id: 'access', settings: false, label: 'Roles & access', form: false },
  { id: 'sso', settings: false, label: 'Single sign-on', form: false },
  // PROJECT.md AD3. Personal, not organisation policy: every signed-in person
  // sees their own tokens here, whatever settings capability they hold.
  { id: 'ai-tools', settings: false, label: 'AI tools & tokens', form: false },
  { id: 'diagnostics', settings: false, label: 'Diagnostics', form: false },
]

// The grouping. `General` is deliberately outside any group and first — it is
// the landing section, and a heading over a single item is noise. The three
// labelled groups answer "what is this setting about": what ARGUS looks at and
// concludes, what it connects out to, and who may do what.
const SETTINGS_GROUPS: Array<{ label: string | null; ids: SettingsSection[] }> = [
  // Appearance sits in the unlabelled top block beside General: it is not
  // about what ARGUS looks at, what it may change, or who may do what — it is
  // what the product looks like before anyone signs in. Two items need no
  // heading.
  //
  // A SECTION MISSING FROM HERE IS UNREACHABLE. This list, not
  // SETTINGS_SECTIONS, is what the nav renders; adding to that one alone gets
  // you a section with a label, a panel and a skeleton entry that nothing can
  // navigate to. Which is exactly what happened when Appearance was added.
  { label: null, ids: ['general', 'appearance'] },
  // The incident pipeline in the order an incident meets it: what is detected,
  // how it is investigated, and what may then be changed without a person.
  { label: 'Detection & response', ids: ['detectors', 'analysis', 'automation'] },
  // The model ARGUS calls and what that costs — reference data edited when a
  // vendor or a price changes, not a knob turned while tuning the pipeline.
  { label: 'AI', ids: ['providers', 'pricing'] },
  { label: 'Integrations', ids: ['repositories', 'notifications', 'routing', 'outbound'] },
  { label: 'Access', ids: ['access', 'sso'] },
  // The one section about the viewer rather than the organisation — their own
  // access tokens — so it gets a heading that says whose it is.
  { label: 'Your account', ids: ['ai-tools'] },
  // A downloadable support artifact (PROJECT.md T18).
  { label: 'Support', ids: ['diagnostics'] },
]

// `?section=` values from before the regrouping. Bookmarks and links in the
// docs use them, and silently falling through to the default section would take
// a reader somewhere they did not ask for with no indication why. `operations`
// held three unrelated panels and was split, so it maps to the one a reader
// following an old link is most likely after.
const LEGACY_SECTION_ALIASES: Record<string, SettingsSection> = {
  ai: 'analysis',
  autonomy: 'automation',
  operations: 'detectors',
}

// ONE nav, rendered by the three branches this page has (loading, settings
// forbidden, loaded). It was three near-identical copies of the strip markup —
// the forbidden branch's copy exists only so that a viewer holding repo:write
// but not org_settings:write can still reach Git repositories (BACKLOG D7d), and
// keeping that reachable meant keeping the nav duplicated. One component instead.
//
// Still `role="tablist"`/`tab`/`tabpanel`, with `aria-orientation="vertical"`:
// the interaction is unchanged — one of N panels shows at a time and the choice
// lives in `?section=` — only the strip's axis moved. A vertical tablist is a
// tablist; swapping the roles for a plain list of links would lose the arrow-key
// behaviour a reader already has here.
function SettingsNav({
  activeSection,
  onSelect,
  interactive = true,
}: {
  activeSection: SettingsSection
  onSelect?: (id: SettingsSection) => void
  interactive?: boolean
}) {
  return (
    <nav className="settings-nav" aria-label="Settings sections">
      {SETTINGS_GROUPS.map((group) => (
        <div className="settings-nav-group" key={group.label ?? 'ungrouped'}>
          {group.label && <p className="settings-nav-heading">{group.label}</p>}
          <div className="settings-nav-list" role="tablist" aria-orientation="vertical">
            {group.ids.map((id) => {
              const className = id === activeSection ? 'settings-nav-link active' : 'settings-nav-link'
              // The loading branch renders the same list unclickable rather than
              // a placeholder: the sections are known before the data is, so a
              // skeleton here would replace real, correct labels with grey bars.
              if (!interactive) {
                return <span key={id} className={className}>{sectionLabel(id)}</span>
              }
              return (
                <button
                  key={id}
                  type="button"
                  role="tab"
                  aria-selected={id === activeSection}
                  className={className}
                  onClick={() => onSelect?.(id)}
                >
                  {sectionLabel(id)}
                </button>
              )
            })}
          </div>
        </div>
      ))}
    </nav>
  )
}

// How many `.settings-panel` cards each section renders, and roughly how many
// lines each holds — read off the panels below rather than guessed, so the
// loading state is the same shape as what replaces it.
const SECTION_SKELETON: Record<SettingsSection, number[]> = {
  // Data retention (heading + 3 fields), then Account security (heading + 2 fields).
  general: [4, 3],
  // Detectors, Rules, Storm protection (with the preview), Resend cooldown.
  detectors: [3, 6, 4, 1],
  analysis: [2, 4],
  // The autonomy form, then the windows and breaker cards.
  automation: [6, 5, 2],
  providers: [5],
  // LLM pricing, then the daily spend ceiling.
  pricing: [4, 3],
  repositories: [5],
  notifications: [3],
  // One panel, and the tallest in this group: an intro, a three-paragraph
  // consequence notice, the destinations table (or its empty state) with its
  // two-field add form, and the rules table — which always renders, because
  // the default rule is a row in it even when there are no rules. Measured
  // against the rendered panel rather than guessed.
  routing: [12],
  // One panel, and one of the taller ones: an intro paragraph, a
  // three-paragraph consequence notice, the entry table (or its empty state)
  // and a two-field add form. Measured against the rendered panel rather than
  // guessed — a skeleton shorter than what replaces it reintroduces the
  // layout jump it exists to prevent.
  outbound: [8],
  // Three panels: Sign-in screen (heading, two radio rows, hint), Primary
  // colour (heading, swatch row, hint), Overview default window (heading,
  // segmented control).
  appearance: [3, 3, 2],
  access: [8],
  sso: [5],
  // Two panels: the token list with its create form, then the connect card
  // (endpoint, snippet tabs, the four reach rows).
  'ai-tools': [7, 10],
  // One panel: a heading/description, a checkbox row, the download button
  // and its result slot.
  diagnostics: [3],
}

function resolveSection(value: string | null): SettingsSection {
  if (SETTINGS_SECTIONS.some((section) => section.id === value)) return value as SettingsSection
  if (value && value in LEGACY_SECTION_ALIASES) return LEGACY_SECTION_ALIASES[value]
  return 'general'
}

function sectionLabel(id: SettingsSection): string {
  return SETTINGS_SECTIONS.find((section) => section.id === id)?.label ?? 'Settings'
}

// The sections of the PUT /admin/settings BODY this page can write. Dirty state
// is tracked per section (not as one page-wide boolean) because the PUT body
// omits what wasn't edited — see the mutation below for the lost update that
// forced this. 'llm' is deliberately absent: provider configuration moved to
// AIProvidersCard and its own endpoints, so this page never sends it.
//
// Renamed from `SettingsSection` when the page's navigation grew real sections
// of its own (`SettingsSection` above). Two different things were called the
// same thing: one is a group of fields in a request body, the other is a place a
// reader navigates to, and they do not line up — the General section holds
// `retention`, and the Investigation section holds three of these at once.
type SettingsPatchSection =
  | 'notify'
  | 'analysis'
  | 'automation'
  | 'retention'
  | 'detection'
  | 'autonomy'
  | 'cost'
  | 'appearance'
  | 'general'
  | 'outbound'
  | 'posture'

// Prose for the sign-in styles. Names and one line each, kept here rather than
// served from the hub because it is copy, not configuration — and because a
// style the hub offers that this map has never heard of must still be
// selectable (it renders with its bare id). The ids come from
// internal/settings/settings.go's LoginStyles.
const STYLE_DESCRIPTIONS: Record<string, { name: string; desc: string }> = {
  aperture: {
    name: 'Aperture',
    desc: 'The mark at full scale in its own panel, blades turning, with the form beside it.',
  },
  sentinel: {
    name: 'Sentinel',
    desc: 'A single card floating over a slow field of linked points.',
  },
}

// Prose for the primary-colour presets, same reasoning as STYLE_DESCRIPTIONS
// above — copy, not configuration, and an id this map has never heard of
// still renders (with its bare id and no swatch preview). The ids, and the
// actual colour values each one renders, come from
// internal/settings/settings.go's PrimaryColorIDs and web/src/index.css's
// `[data-accent=...]` blocks respectively — never hardcoded here.
const PRIMARY_COLOR_DESCRIPTIONS: Record<string, string> = {
  teal: 'The shipped default.',
  blue: 'A royal blue.',
  violet: 'A muted violet.',
  slate: 'A neutral graphite.',
  forest: 'A deep green.',
}

// DETECTOR_OPTIONS moved to utils/detectors.ts (PROJECT.md item 14) — the
// incident screen needs the same three ids resolved to the same three labels,
// and a second copy of this map there would be two label maps for one closed
// set of ids. That module keeps this array's order, shapes and strings
// verbatim, and carries the cross-reference to internal/api/settings.go's
// knownDetectorIDs that used to live here; it adds a detection-source
// classification alongside, which Settings does not read.

// RULE_IDS is BUGS.md 111's rule-level catalogue — every declarative rule id
// internal/agent/rules/default-rules.yaml defines, ALL of which share the
// SAME "k8s-sweep" entry in DETECTOR_OPTIONS above with each other and with
// every hand-written Go check in that detector (sweep_detector.go). That
// sharing is exactly the bug this control fixes: disabling "k8s-sweep" above
// silences all 33 of these at once; checking one of these silences only
// that one rule.
//
// Must exactly match internal/api/settings.go's knownRuleIDs, which is in
// turn checked against the real internal/agent/rules/default-rules.yaml by
// TestKnownRuleIDsMatchesDefaultRulesYAML — there is no API this page can
// call to fetch the live catalogue instead (rule ids are agent-local,
// embedded-YAML config, not a hub-side list), so this is a hand-maintained
// literal, same as DETECTOR_OPTIONS' ids already are, with no equivalent
// automated drift check on the frontend side.
//
// Rendered as raw ids (in <code>, not a hand-written label per entry): at 3
// detectors a curated label/description pair each is cheap; at 33 rules,
// and growing, a second hand-authored prose layer would both be a lot of
// upkeep and a second place to drift from the real id — the id itself is
// already a descriptive kebab-case phrase, and it's also the exact value
// that appears anywhere else this rule is ever named (audit records, hub
// logs), so showing it verbatim is the more honest choice here.
const RULE_IDS: string[] = [
  'pdb-blocks-all-disruptions',
  'networkpolicy-selects-no-pods',
  'resourcequota-at-hard-limit',
  'certificate-expiry-imminent',
  'pdb-selector-matches-no-pods',
  'persistentvolume-released-stuck',
  'persistentvolume-stuck-terminating',
  'persistentvolumeclaim-stuck-terminating',
  'pod-stuck-terminating',
  'hpa-pegged-at-max-replicas',
  'flux-kustomization-reconciliation-stalled',
  'flux-helmrelease-reconciliation-stalled',
  'namespace-stuck-terminating',
  'velero-backup-partially-failed',
  'argo-application-health-degraded',
  'flux-gitrepository-reconciliation-stalled',
  'deployment-paused',
  'deployment-observedgeneration-behind',
  'daemonset-rollout-stalled',
  'statefulset-rollout-stalled',
  'persistentvolume-failed',
  'deployment-rollout-stalled',
  'deployment-scaled-to-zero',
  'deployment-revision-history-limit-zero',
  'pod-evicted-not-cleaned-up',
  'node-cordoned-sustained',
  'argo-application-out-of-sync',
  'argo-application-sync-unknown',
  'flux-kustomization-suspended',
  'flux-helmrelease-suspended',
  'flux-gitrepository-suspended',
  'velero-backup-failed',
  'velero-restore-partially-failed',
  'velero-restore-failed',
  'statefulset-partition-blocks-rollout',
]

// The AI & automation area's severity checkboxes, rendered in this fixed
// ascending order regardless of which are checked — the same four-value
// enum every severity control elsewhere in this app already uses
// (api/types.ts's IncidentSeverity).
const SEVERITY_OPTIONS: IncidentSeverity[] = ['low', 'medium', 'high', 'critical']

// The AI & automation area's risk-ceiling dropdown, rendered in this fixed
// low-to-high order. internal/remediation.RiskLevel's actual Go-level closed
// enum (low/medium/high) — deliberately NOT the fuller four-tier table
// DESIGN.md §9.3 describes: "forbidden" has no
// representative action type in this codebase's closed ActionType set yet
// (internal/remediation/plan.go's own comment), so it stays unmodeled here
// too, matching the backend's validAutoApproveMaxRiskLevels exactly.
const AUTO_APPROVE_MAX_RISK_OPTIONS: Array<'low' | 'medium' | 'high'> = ['low', 'medium', 'high']

// ============================================================================
// Roles & access reference area — plain-language, grouped display of what each
// builtin role can do. The actual capability LIST per role always comes
// live from GET /api/v1/roles (api/client.ts's getRoles), which is itself a
// thin wrapper around internal/authz/permissions.go's builtinRoleCapabilities
// — the real authorization source of truth — so that part can never drift.
//
// The group/label MAP itself (which is hand-maintained, and could drift —
// see api/capabilityInfo.ts's own doc comment for the full reasoning) moved
// there (BACKLOG.md S3) so CustomRolesCard.tsx's capability checklist can
// share it rather than hand-copying a third version of nearly the same map.
// ============================================================================

// One-line orientation per role, calling out the deliberate exclusions
// internal/authz/permissions.go's own comments explain, so this reference
// doesn't just show a bare list and leave the reader to notice the pattern
// themselves — tenant-admin's missing audit:read/org:settings:write and
// viewer's one write-shaped exception (breakglass:request) are both easy to
// miss in a flat capability list.
//
// ROLE_NOTES itself now lives in api/types.ts, beside ROLE_LABELS and
// UsersPage's ROLE_DESCRIPTIONS (BACKLOG D7f remainder) — this screen and
// UsersPage each held their own hand-maintained copy of "what a role does"
// and had already diverged in emphasis even before the fifth role
// (pr-approver) doubled the chance of one of the two copies being forgotten.
// See that file's doc comment for why the two stayed separate exports rather
// than one merged string.

// The five builtin roles as ONE role-by-capability matrix. It was five cards of
// bulleted lists, ~3000px of mostly identical text, where the only thing a
// reader wants — what does role B have that role A lacks — meant comparing two
// lists by eye. Rows are every capability any builtin role holds, grouped by
// area; a column per role. The capability lists are read live from the hub's
// authorization catalogue, never hand-copied. A capability CAPABILITY_INFO has
// no label for still appears, by its raw key, under "Other".
function RoleMatrix({ roles }: { roles: Partial<Record<BuiltinRole, { capabilities: string[] }>> }) {
  const granted = new Map(BUILTIN_ROLES.map((role) => [role, new Set(roles[role]?.capabilities ?? [])]))
  const all = Array.from(new Set(BUILTIN_ROLES.flatMap((role) => roles[role]?.capabilities ?? [])))
  const byGroup = new Map<string, string[]>()
  for (const cap of all) {
    const group = CAPABILITY_INFO[cap]?.group ?? 'other'
    byGroup.set(group, [...(byGroup.get(group) ?? []), cap])
  }
  const groups: Array<{ id: string; label: string; caps: string[] }> = [
    ...CAPABILITY_GROUP_ORDER.filter((g) => byGroup.has(g)).map((g) => ({
      id: g as string,
      label: CAPABILITY_GROUP_LABELS[g],
      caps: byGroup.get(g)!,
    })),
    ...(byGroup.has('other') ? [{ id: 'other', label: 'Other', caps: byGroup.get('other')! }] : []),
  ]
  return (
    <div className="table-scroll">
      {all.length === 0 && (
        <p className="empty-state">The hub's catalogue lists no capabilities for any builtin role.</p>
      )}
      <table className="cluster-table role-matrix">
        <thead>
          <tr>
            <th scope="col">Capability</th>
            {BUILTIN_ROLES.map((role) => (
              <th scope="col" key={role} className="role-matrix-role">
                <span className="role-matrix-role-name">
                  {ROLE_LABELS[role]}
                  <HelpTip label={ROLE_LABELS[role]} text={ROLE_NOTES[role]} />
                </span>
                <span className="role-matrix-count">{granted.get(role)!.size} capabilities</span>
              </th>
            ))}
          </tr>
        </thead>
        {groups.map((g) => (
          <tbody key={g.id}>
            <tr className="role-matrix-group">
              <th scope="rowgroup" colSpan={BUILTIN_ROLES.length + 1}>
                {g.label}
              </th>
            </tr>
            {g.caps.map((cap) => (
              <tr key={cap}>
                <th scope="row">{CAPABILITY_INFO[cap]?.label ?? <code>{cap}</code>}</th>
                {BUILTIN_ROLES.map((role) =>
                  granted.get(role)!.has(cap) ? (
                    <td key={role} className="role-matrix-yes">
                      <ChipMark mark="granted" />
                      <span className="visually-hidden">Granted</span>
                    </td>
                  ) : (
                    <td key={role} className="role-matrix-no">
                      <span aria-hidden="true">—</span>
                      <span className="visually-hidden">Not granted</span>
                    </td>
                  ),
                )}
              </tr>
            ))}
          </tbody>
        ))}
      </table>
    </div>
  )
}

// DetectionDryRunResult renders POST /api/v1/detection/dry-run's response
// — the Detection tab's "Preview against history" result. Mirrors this
// task's own example narrative ("12 of the last 200 findings would have
// been filtered, and 3 incidents that were created would have been
// suppressed by storm protection instead") as the lead sentence, with the
// per-cluster/detector breakdown underneath for anyone who wants the detail
// rather than just the headline. Renders nothing conditionally hidden —
// every section always explains what it found, including "none," so a
// candidate with no real-world effect is a legible result, not a blank
// panel.
function DetectionDryRunResult({ result }: { result: DetectionDryRunResponse }) {
  const { disabledDetectorFilter, stormProtection } = result
  return (
    <div className="card dry-run-result" role="status">
      <p>
        Against the last <strong>{result.windowDays} days</strong> of real history (
        {result.totalFindingsInWindow} finding{result.totalFindingsInWindow === 1 ? '' : 's'}
        ): <strong>{disabledDetectorFilter.filteredCount}</strong> finding
        {disabledDetectorFilter.filteredCount === 1 ? '' : 's'} would have been filtered by the
        disabled-detector rule above
        {stormProtection.candidateConfigured ? (
          <>
            , and of {stormProtection.eligibleOpportunities} new-incident decision
            {stormProtection.eligibleOpportunities === 1 ? '' : 's'} still eligible for storm
            protection, <strong>{stormProtection.newlySuppressedCount}</strong> incident
            {stormProtection.newlySuppressedCount === 1 ? '' : 's'} that were actually created
            would have been suppressed instead
            {stormProtection.newlyAllowedCount > 0 && (
              <>
                {' '}
                (and {stormProtection.newlyAllowedCount} that were actually suppressed would have
                been allowed)
              </>
            )}
            .
          </>
        ) : (
          <>. Storm protection isn't configured in this candidate, so nothing here would be suppressed.</>
        )}
      </p>

      {disabledDetectorFilter.byClusterDetector.length > 0 && (
        <>
          <h4>By cluster / detector — disabled-detector filter</h4>
          <div className="table-scroll">
            <table className="cluster-table">
              <thead>
                <tr>
                  <th>Cluster</th>
                  <th>Detector</th>
                  <th>Findings in window</th>
                  <th>Would be filtered?</th>
                </tr>
              </thead>
              <tbody>
                {disabledDetectorFilter.byClusterDetector.map((b) => (
                  <tr key={`${b.clusterId}-${b.detectorId}`}>
                    <td>{b.clusterName}</td>
                    <td>{DETECTOR_OPTIONS.find((d) => d.id === b.detectorId)?.label ?? b.detectorId}</td>
                    <td>{b.findingCount}</td>
                    <td>
                      <span className={b.filteredUnderCandidate ? 'badge badge-gray' : 'badge badge-green'}>
                        {b.filteredUnderCandidate ? 'filtered' : 'kept'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {stormProtection.byClusterDetector.length > 0 && (
        <>
          <h4>By cluster / detector — storm protection</h4>
          <div className="table-scroll">
            <table className="cluster-table">
              <thead>
                <tr>
                  <th>Cluster</th>
                  <th>Detector</th>
                  <th>Opportunities</th>
                  <th>Actually created / suppressed</th>
                  <th>Would create / suppress</th>
                </tr>
              </thead>
              <tbody>
                {stormProtection.byClusterDetector.map((b) => (
                  <tr key={`${b.clusterId}-${b.detectorId}`}>
                    <td>{b.clusterName}</td>
                    <td>{DETECTOR_OPTIONS.find((d) => d.id === b.detectorId)?.label ?? b.detectorId}</td>
                    <td>{b.opportunities}</td>
                    <td>
                      {b.actual.createdCount} / {b.actual.suppressedCount}
                    </td>
                    <td>
                      {b.candidate.createdCount} / {b.candidate.suppressedCount}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  )
}

export function SettingsPage() {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const [searchParams, setSearchParams] = useSearchParams()
  const activeSection = resolveSection(searchParams.get('section'))
  // `replace`, not a push: flipping between sections is not navigation a reader
  // wants Back to walk through one at a time. Unchanged from the tab strip; it
  // is a named function now because three branches call it.
  const selectSection = (id: SettingsSection) => {
    const next = new URLSearchParams(searchParams)
    next.set('section', id)
    setSearchParams(next, { replace: true })
  }
  // Which sections the admin has actually edited this visit. Replaces a
  // single page-wide `isDirty` boolean, which was only ever used to decide
  // *whether* to save — never *what* to save, which is where the bug was.
  const [dirtySections, setDirtySections] = useState<ReadonlySet<SettingsPatchSection>>(() => new Set())
  // The sign-in style, primary colour and Overview default window. Seeded
  // from the server on load (see the effect that syncs the other fields) and
  // sent only when touched, like every other section here — all three travel
  // together as one "appearance" PUT section (settings.AppearanceUpdate).
  const [loginStyle, setLoginStyle] = useState<string>('')
  const [primaryColorId, setPrimaryColorId] = useState<string>('')
  const [overviewDefaultWindowDays, setOverviewDefaultWindowDays] = useState<14 | 30>(14)
  // The two General > Account security fields — a separate PUT section
  // (settings.GeneralUpdate) from Data retention's "general" nav entry,
  // despite sharing a nav id; see the render below for why.
  const [minPasswordLength, setMinPasswordLength] = useState('')
  const [sessionIdleTimeoutMinutes, setSessionIdleTimeoutMinutes] = useState('')
  const hasUnsavedChanges = dirtySections.size > 0

  // Same super-admin-only capability gates both reading and writing this
  // screen's contents (no separate read capability exists) — see
  // api/capabilities.ts's CAP_ORG_SETTINGS_WRITE doc comment. Per
  // lld/11-ui-design.md §6, lacking it disables the form rather than
  // hiding the page — see the render below for the GET-also-403 case,
  // which is the one situation this screen has nothing real to show.
  const canWrite = useHasCapability(CAP_ORG_SETTINGS_WRITE)
  // Identity management is its own capability, deliberately NOT folded into
  // org:settings:write: editing a group mapping re-authorises everyone in a
  // directory group at once, which is a bigger act than any other setting on
  // this page.
  const canManageIdentity = useHasCapability(CAP_IDENTITY_MANAGE)
  const disabledReason = canWrite ? undefined : missingCapabilityMessage([CAP_ORG_SETTINGS_WRITE])
  // Git repositories are gated on their OWN capability, not on org:settings:write
  // (BACKLOG D7d). This screen used to drive every panel from the one blanket
  // gate, which locked out exactly the person entitled to the panel: tenant-admin
  // holds repo:read/repo:write while org:settings:write is deliberately withheld
  // from it (internal/authz/permissions.go, reserved to super-admin per
  // lld/02-authz-spec.md §5). So a tenant-admin could not reach the only
  // repositories UI in the product, and was told they were missing
  // org:settings:write when the routes enforce repo:write. capabilities.ts has
  // said which capability belongs here since it was written.
  const canReadRepos = useHasCapability(CAP_REPO_READ)
  const canWriteRepos = useHasCapability(CAP_REPO_WRITE)
  const reposDisabledReason = canWriteRepos ? undefined : missingCapabilityMessage([CAP_REPO_WRITE])

  // Custom roles / cluster groups (BACKLOG.md S3) — same disabled-not-hidden
  // pattern as repos above: CustomRolesCard/ClusterGroupsCard always render
  // (their own list is read-only-visible to anyone who can see this tab at
  // all), only their write controls disable with a named reason.
  const canManageRoles = useHasCapability(CAP_ROLE_MANAGE)
  const rolesManageDisabledReason = canManageRoles ? undefined : missingCapabilityMessage([CAP_ROLE_MANAGE])
  const canManageClusterGroups = useHasCapability(CAP_CLUSTER_GROUP_MANAGE)
  const clusterGroupsManageDisabledReason = canManageClusterGroups
    ? undefined
    : missingCapabilityMessage([CAP_CLUSTER_GROUP_MANAGE])

  const needsSettings = SETTINGS_SECTIONS.find((section) => section.id === activeSection)?.settings ?? true
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['settings'],
    queryFn: () => getSettings(accessToken!),
    // Only for the sections that render it — see standaloneSections.
    enabled: !!accessToken && needsSettings,
  })

  // Backs the "Roles & access" area below. A separate query from `settings` above —
  // GET /api/v1/roles carries no org:settings:write requirement of its own
  // (see api/client.ts's getRoles doc comment) — fetched unconditionally
  // alongside it rather than only once that area is selected, the same
  // "every area's data loads regardless of which is active" approach this
  // page already takes for its other fields.
  const rolesQuery = useQuery({
    queryKey: ['roles'],
    queryFn: () => getRoles(accessToken!),
    enabled: !!accessToken,
  })

  // Diagnostics bundle (PROJECT.md T18) — a support artifact, not a query:
  // nothing here should be fetched on mount or refetched on an interval, so
  // this is a useMutation the download button triggers explicitly, matching
  // testAIProvider's own "only ever from a click" rule for the same reason
  // (probe=true spends money and makes a live outbound call).
  const [includeConnectivityProbe, setIncludeConnectivityProbe] = useState(false)
  const diagnosticsMutation = useMutation({
    mutationFn: () => getDiagnosticsBundle(accessToken!, includeConnectivityProbe),
    onSuccess: ({ raw, filename }) => {
      // Saves the EXACT bytes the hub returned — the manifest below is read
      // from the same response, so what the summary describes and what
      // lands on disk can never drift apart.
      const blob = new Blob([raw], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
    },
  })

  // Plain-text fields are seeded from the server response and freely
  // editable; the two secret fields (below) never are. `hydratedFrom` holds
  // the exact response object the fields were last seeded from, so a refetch
  // re-seeds every section the admin has NOT edited while never stomping on
  // one they have. It used to be a one-shot `initialized` boolean, which
  // pinned the form to whatever the very first load returned for the whole
  // visit — so someone else's concurrent change never appeared, and (before
  // the per-section PUT below) got silently reverted on the next save.
  // TanStack Query's structural sharing means an unchanged refetch returns
  // the *same* object, so this only does work when something really changed.
  const [hydratedFrom, setHydratedFrom] = useState<Settings | null>(null)

  // The investigation loop's two bounds (internal/llm/toolloop.go's
  // Investigate). Plain, always-submitted number fields, not secret-style
  // omit-vs-clear fields like apiKey/webhookUrl below — kept as strings
  // here (not numbers) so the input can be legitimately blank while being
  // edited, distinct from "0"; blank on submit means "send null," i.e.
  // clear the override back to the env-var/hardcoded-default fallback.
  const [maxIterations, setMaxIterations] = useState('')
  const [timeLimitSeconds, setTimeLimitSeconds] = useState('')

  // The automatic-investigation toggle and its severity checklist
  // (internal/autoanalyze). Unlike the single ordered "minimum severity"
  // this replaced, autoAnalysisSeverities is a genuine set: any combination
  // of the four checkboxes is valid, including e.g. "high" and "critical"
  // checked with "medium" deliberately left unchecked — a selection no
  // single threshold could ever express. An empty array (every box
  // unchecked) is a real, valid state too — see the backend's
  // AutoAnalysisSeverities doc comment (internal/settings/settings.go) for
  // why that deliberately means "nothing gets auto-analyzed," not "every
  // severity qualifies."
  const [autoAnalysisEnabled, setAutoAnalysisEnabled] = useState(false)
  const [autoAnalysisSeverities, setAutoAnalysisSeverities] = useState<IncidentSeverity[]>([])

  // Toggles one severity's checkbox on/off within the set above, preserving
  // SEVERITY_OPTIONS' ascending order regardless of check/uncheck order —
  // purely cosmetic (the backend treats the array as a set, order doesn't
  // affect eligibility), but keeps the PUT body and the next GET's echo
  // visually stable rather than reordering on every edit.
  function toggleAutoAnalysisSeverity(severity: IncidentSeverity, checked: boolean) {
    setAutoAnalysisSeverities((prev) => {
      const next = checked ? [...prev, severity] : prev.filter((s) => s !== severity)
      return SEVERITY_OPTIONS.filter((s) => next.includes(s))
    })
  }

  // The three retention windows (internal/partition), one per data type.
  // Kept as strings, not numbers, for the same reason maxIterations/
  // timeLimitSeconds above are: an input needs to be legitimately blank
  // while being edited, distinct from "0" — blank on submit means "send
  // null," i.e. explicitly keep this data type forever, matching the null
  // semantics data.retention.*RetentionDays already uses.
  const [auditRetentionDays, setAuditRetentionDays] = useState('')
  const [incidentRetentionDays, setIncidentRetentionDays] = useState('')
  const [findingRetentionDays, setFindingRetentionDays] = useState('')

  // The detection layer's live-editable config (internal/gateway/finding.go).
  // disabledDetectorIds is a genuine set, same shape as
  // autoAnalysisSeverities above — any subset of DETECTOR_OPTIONS' ids is
  // valid, including all or none. The two storm-protection fields follow
  // the same blank-means-null string-input pattern as the retention fields
  // above: kept as strings so an input can be legitimately blank while
  // being edited, distinct from "0"; blank on submit means "send null,"
  // i.e. no ceiling.
  const [disabledDetectorIds, setDisabledDetectorIds] = useState<string[]>([])
  const [stormProtectionMaxNewIncidents, setStormProtectionMaxNewIncidents] = useState('')
  const [stormProtectionWindowSeconds, setStormProtectionWindowSeconds] = useState('')

  // BUGS.md 111: disabledRuleIds is the narrower, rule-level sibling of
  // disabledDetectorIds above — same genuine-set shape, but over RULE_IDS
  // (33 entries, all sharing the "k8s-sweep" DetectorID with each other and
  // with every hand-written check in that detector, per RULE_IDS' own
  // comment) instead of DETECTOR_OPTIONS' three. ruleFilter is UI-only state
  // (never sent to the hub): with 33 checkboxes, a plain unfiltered list is
  // the wrong shape for finding one rule quickly, so it narrows which
  // checkboxes are rendered by substring match on the rule id — the same
  // "search narrows a list" pattern IncidentsPage/ClustersPage/UsersPage
  // already use, applied here to a static id list instead of a server query.
  const [disabledRuleIds, setDisabledRuleIds] = useState<string[]>([])
  const [ruleFilter, setRuleFilter] = useState('')
  const filteredRuleIds = RULE_IDS.filter((id) => id.includes(ruleFilter.trim().toLowerCase()))

  // Toggles one detector's checkbox on/off within disabledDetectorIds,
  // preserving DETECTOR_OPTIONS' display order — mirrors
  // toggleAutoAnalysisSeverity above exactly, just over detector ids instead
  // of severities. Note the checkbox reads "disabled" (checked = this
  // detector's findings are dropped), the opposite sense of
  // autoAnalysisSeverities' "checked = included" — see the section's
  // render for how that's labeled unambiguously.
  function toggleDetectorDisabled(detectorId: string, disabled: boolean) {
    setDisabledDetectorIds((prev) => {
      const next = disabled ? [...prev, detectorId] : prev.filter((id) => id !== detectorId)
      return DETECTOR_OPTIONS.map((d) => d.id).filter((id) => next.includes(id))
    })
  }

  // toggleDetectorDisabled's exact same pattern, over RULE_IDS/disabledRuleIds
  // instead of DETECTOR_OPTIONS/disabledDetectorIds.
  function toggleRuleDisabled(ruleId: string, disabled: boolean) {
    setDisabledRuleIds((prev) => {
      const next = disabled ? [...prev, ruleId] : prev.filter((id) => id !== ruleId)
      return RULE_IDS.filter((id) => next.includes(id))
    })
  }

  // "Preview against history" (POST /api/v1/detection/dry-run) — a
  // separate mutation from the settings PUT above, deliberately: it must
  // never save anything, so it's wired to its own button
  // (type="button", not the form's submit) rather than sharing `mutation`.
  // Sends whatever is CURRENTLY entered in the Detectors/Storm protection
  // fields above, unsaved, exactly like this task's brief describes ("takes
  // whatever's currently entered in the form before saving"). A fresh click
  // clears any previous result so a stale preview from a since-edited form
  // can never be mistaken for the current one.
  const dryRunMutation = useMutation({
    mutationFn: () =>
      dryRunDetectionSettings(
        {
          disabledDetectorIds,
          stormProtectionMaxNewIncidents:
            stormProtectionMaxNewIncidents.trim() === '' ? null : Number(stormProtectionMaxNewIncidents),
          stormProtectionWindowSeconds:
            stormProtectionWindowSeconds.trim() === '' ? null : Number(stormProtectionWindowSeconds),
          // Deliberately NOT disabledRuleIds — the dry-run replay this
          // endpoint runs was not extended to simulate the rule-level
          // control (BUGS.md 111 scoped that out; see
          // UpdateDetectionSettingsRequest's doc comment), so sending
          // whatever is currently checked here would be silently ignored by
          // the hub rather than actually previewed. Always `[]` rather than
          // omitted, matching this type's "every field always present"
          // contract.
          disabledRuleIds: [],
        },
        accessToken!,
      ),
  })

  // The autonomy policy — internal/orchestrator.DefaultAutonomyPolicy's
  // DB-backed override (internal/remediation.Evaluate's confidence x risk
  // gate). autoApproveMaxRisk mirrors DisabledDetectorIds' pattern: '' means
  // "not set here," distinct from a real selection, so it's kept as a
  // string rather than the narrower risk-level union directly.
  // minConfidenceForAutoApprove follows the same blank-means-null
  // string-input pattern as the retention/storm-protection fields above:
  // kept as a string so the input can be legitimately blank while being
  // edited, distinct from "0"; blank on submit means "send null," i.e. fall
  // back to internal/orchestrator.DefaultAutonomyPolicy's own value.
  // requireReversibleForAutoApprove defaults true to match
  // DefaultAutonomyPolicy's own safer choice, in case this ever renders
  // before the first successful load seeds it for real. The wire value
  // itself is now nullable (BUGS.md 97, migration 000085) — seeded below
  // from effectiveRequireReversibleForAutoApprove, not the raw field, so a
  // genuinely unconfigured install still shows (and, on save, round-trips)
  // the real true rather than a stale/default false.
  const [autoApproveMaxRisk, setAutoApproveMaxRisk] = useState<'' | 'low' | 'medium' | 'high'>('')
  const [minConfidenceForAutoApprove, setMinConfidenceForAutoApprove] = useState('')
  const [requireReversibleForAutoApprove, setRequireReversibleForAutoApprove] = useState(true)

  // Unattended execution and its blast-radius caps. The switch defaults FALSE
  // to match the column and, more importantly, so that a render before the
  // first successful load can never show this as on — the one field on this
  // page where an optimistic default would misrepresent whether ARGUS is
  // currently allowed to touch a cluster unsupervised. The three caps are
  // blank-means-null strings like every other numeric field here, for the same
  // reason: blank has to stay distinguishable from "0" while being typed.
  const [unattendedExecutionEnabled, setUnattendedExecutionEnabled] = useState(false)
  const [maxUnattendedPerCluster, setMaxUnattendedPerCluster] = useState('')
  const [maxUnattendedFleetWide, setMaxUnattendedFleetWide] = useState('')
  const [unattendedWindowMinutes, setUnattendedWindowMinutes] = useState('')

  // The operator-configured LLM pricing table and the daily spend ceiling
  // (CostSettings). All four kept as strings, not numbers, for the same
  // blank-is-legitimately-distinct-from-"0" reason every other numeric
  // field on this page is: blank on submit means "send null" for all four —
  // "no pricing configured" (the three price fields together) or "no
  // ceiling" (the fourth). The three price fields must be saved either
  // all-blank or all-filled — the hub rejects a partial table with a 400,
  // rendered via mutationFeedback like any other validation error.
  const [pricePerMillionInputTokens, setPricePerMillionInputTokens] = useState('')
  const [pricePerMillionCachedTokens, setPricePerMillionCachedTokens] = useState('')
  const [pricePerMillionOutputTokens, setPricePerMillionOutputTokens] = useState('')
  const [dailySpendCeilingUsd, setDailySpendCeilingUsd] = useState('')

  // The webhook secret: an input (empty by default — never pre-filled with a
  // fake value) plus its own "Clear" checkbox. Only one of "typed something" /
  // "checked Clear" can apply at a time, enforced by disabling each control
  // while the other is in use, so the PUT body never has to guess which the
  // admin meant.
  //
  // This comment used to describe "the two secret fields" and the AI provider's
  // kind/CLI fields alongside it. Those moved to components/AIProvidersCard.tsx
  // when provider configuration became multi-provider, and the comment stayed —
  // describing state this component no longer declares. Left as a note because
  // it actively misled a review into reporting the AI provider as
  // unconfigurable from the UI, which it is not.
  const [webhookInput, setWebhookInput] = useState('')
  const [clearWebhook, setClearWebhook] = useState(false)

  // The outbound allowlist's STAGED list (migration 000115). Held whole rather
  // than as an add/remove delta because the PUT section is whole-list by
  // design: there is no per-entry merge on the hub, and removing an exception
  // is the operation that matters most on a list of security exceptions. The
  // card renders this against data.outbound.privateDestinations so a row can
  // say whether it is in effect or only staged.
  const [privateDestinations, setPrivateDestinations] = useState<OutboundPrivateDestination[]>([])
  // Posture exceptions for every cluster (CI-P9 d), edited as comma lists.
  const [postureDisabledChecks, setPostureDisabledChecks] = useState('')
  const [postureIgnoredNamespaces, setPostureIgnoredNamespaces] = useState('')

  // Seeds every field from the server response, re-running whenever a
  // genuinely different response arrives. This adjusts state during render
  // (React's documented pattern for this — see "Adjusting state based on a
  // prop" in the React docs) rather than in a useEffect: the effect version
  // would commit an extra, visible render with stale (empty) fields before
  // the effect ran, and would need `data`/`hydratedFrom` in its dependency
  // array anyway.
  //
  // Each section is re-seeded only while it is NOT dirty. That's the whole
  // safety property: a section the admin is editing keeps their text, and
  // every other section tracks the server — including changes another admin
  // made since this tab was opened, which used to stay invisible here
  // forever. A dirty section is intentionally left alone rather than
  // merged: silently replacing something someone is mid-way through typing
  // is worse than showing it slightly behind.
  if (data && data !== hydratedFrom) {
    if (!dirtySections.has('analysis')) {
      setMaxIterations(data.analysis.maxIterations != null ? String(data.analysis.maxIterations) : '')
      setTimeLimitSeconds(data.analysis.timeLimitSeconds != null ? String(data.analysis.timeLimitSeconds) : '')
    }
    if (!dirtySections.has('automation')) {
      setAutoAnalysisEnabled(data.automation.autoAnalysisEnabled)
      setAutoAnalysisSeverities(data.automation.autoAnalysisSeverities)
    }
    if (!dirtySections.has('retention')) {
      setAuditRetentionDays(data.retention.auditRetentionDays != null ? String(data.retention.auditRetentionDays) : '')
      setIncidentRetentionDays(
        data.retention.incidentRetentionDays != null ? String(data.retention.incidentRetentionDays) : '',
      )
      setFindingRetentionDays(
        data.retention.findingRetentionDays != null ? String(data.retention.findingRetentionDays) : '',
      )
    }
    if (!dirtySections.has('appearance')) {
      setLoginStyle(data.appearance.loginStyle)
      setPrimaryColorId(data.appearance.primaryColorId)
      setOverviewDefaultWindowDays(data.appearance.overviewDefaultWindowDays)
    }
    if (!dirtySections.has('general')) {
      setMinPasswordLength(String(data.general.minPasswordLength))
      setSessionIdleTimeoutMinutes(
        data.general.sessionIdleTimeoutMinutes != null ? String(data.general.sessionIdleTimeoutMinutes) : '',
      )
    }
    if (!dirtySections.has('outbound')) {
      setPrivateDestinations(data.outbound.privateDestinations)
    }
    if (!dirtySections.has('posture')) {
      setPostureDisabledChecks((data.posture?.disabledChecks ?? []).join(', '))
      setPostureIgnoredNamespaces((data.posture?.ignoredNamespaces ?? []).join(', '))
    }
    if (!dirtySections.has('detection')) {
      setDisabledDetectorIds(data.detection.disabledDetectorIds)
      setStormProtectionMaxNewIncidents(
        data.detection.stormProtectionMaxNewIncidents != null
          ? String(data.detection.stormProtectionMaxNewIncidents)
          : '',
      )
      setStormProtectionWindowSeconds(
        data.detection.stormProtectionWindowSeconds != null
          ? String(data.detection.stormProtectionWindowSeconds)
          : '',
      )
      setDisabledRuleIds(data.detection.disabledRuleIds)
    }
    if (!dirtySections.has('autonomy')) {
      setAutoApproveMaxRisk(data.autonomy.autoApproveMaxRisk ?? '')
      setMinConfidenceForAutoApprove(
        data.autonomy.minConfidenceForAutoApprove != null
          ? String(data.autonomy.minConfidenceForAutoApprove)
          : '',
      )
      setRequireReversibleForAutoApprove(
        data.autonomy.requireReversibleForAutoApprove ??
          data.autonomy.effectiveRequireReversibleForAutoApprove,
      )
      setUnattendedExecutionEnabled(data.autonomy.unattendedExecutionEnabled)
      setMaxUnattendedPerCluster(
        data.autonomy.maxUnattendedPerCluster != null
          ? String(data.autonomy.maxUnattendedPerCluster)
          : '',
      )
      setMaxUnattendedFleetWide(
        data.autonomy.maxUnattendedFleetWide != null
          ? String(data.autonomy.maxUnattendedFleetWide)
          : '',
      )
      // Seconds on the wire, minutes in the input. The API speaks seconds
      // because every other duration setting does; an operator thinking about
      // "how many changes per hour" should not have to multiply by 3600.
      setUnattendedWindowMinutes(
        data.autonomy.unattendedWindowSeconds != null
          ? String(data.autonomy.unattendedWindowSeconds / 60)
          : '',
      )
    }
    if (!dirtySections.has('cost')) {
      setPricePerMillionInputTokens(
        data.cost.pricePerMillionInputTokens != null ? String(data.cost.pricePerMillionInputTokens) : '',
      )
      setPricePerMillionCachedTokens(
        data.cost.pricePerMillionCachedTokens != null ? String(data.cost.pricePerMillionCachedTokens) : '',
      )
      setPricePerMillionOutputTokens(
        data.cost.pricePerMillionOutputTokens != null ? String(data.cost.pricePerMillionOutputTokens) : '',
      )
      setDailySpendCeilingUsd(data.cost.dailySpendCeilingUsd != null ? String(data.cost.dailySpendCeilingUsd) : '')
    }
    // No 'notify' branch: the webhook field is a secret, never seeded from
    // the response (the API doesn't return one) — see secretPlaceholder.
    setHydratedFrom(data)
  }

  // One shared mutation for the whole page: whichever "Save settings" button
  // is on screen commits every pending edit, so switching areas mid-edit
  // never loses one.
  //
  // What it sends is only the sections the admin actually touched. It used to
  // send all seven unconditionally, built from local state that was seeded
  // once and never re-synced — a textbook lost update: admin A opens
  // Settings, admin B changes auditRetentionDays, admin A edits only the
  // webhook and saves, and A's months-old copy of the retention fields
  // silently overwrites B's change. Omitting an untouched section leaves the
  // server's current value alone, which is the only correct answer when this
  // page cannot know what it is. (PUT /admin/settings treats an absent
  // section as "leave alone" — internal/api/settings.go — which is exactly
  // the same "omit means unchanged" contract the secret fields below already
  // rely on, applied one level up.)
  const mutation = useMutation({
    mutationFn: () => {
      // No "llm" section: provider configuration lives in AIProvidersCard,
      // which writes through the /admin/ai-providers endpoints. PUT
      // /admin/settings' own llm section still exists and still edits the
      // active provider — kept for API consumers (scripts/smoke-test.sh,
      // scripts/eval-harness) — but this page no longer sends it, so saving
      // general settings can never quietly overwrite a provider's config.
      const body: UpdateSettingsRequest = {}

      // Omitting webhookUrl entirely means "leave unchanged" to the API —
      // building this object with `?? ''` or similar would silently turn
      // that into "clear," so the key is only ever added when the admin
      // actually asked for a change.
      if (dirtySections.has('appearance')) {
        body.appearance = { loginStyle, primaryColorId, overviewDefaultWindowDays }
      }

      // minPasswordLength has no "leave unchanged" blank state — unlike the
      // retention/analysis fields below, it is always a concrete number the
      // hub validates as 8-128 (a blank or out-of-range submission comes back
      // as a 400, rendered via mutationFeedback, the same as every other
      // validated field on this page). sessionIdleTimeoutMinutes DOES have a
      // blank state: it means "no idle limit," sent as null.
      if (dirtySections.has('general')) {
        body.general = {
          minPasswordLength: Number(minPasswordLength),
          sessionIdleTimeoutMinutes:
            sessionIdleTimeoutMinutes.trim() === '' ? null : Number(sessionIdleTimeoutMinutes),
        }
      }

      // The staged list, sent verbatim — including an empty array, which is a
      // real and meaningful value here ("clear every exception, back to plain
      // default-deny") and must never be omitted or turned into a sentinel.
      // Every entry is re-validated by the hub with the same code that decides
      // whether a dial is permitted; a refusal comes back as a 400 whose
      // detail names the specific problem, rendered by mutationFeedback.
      if (dirtySections.has('outbound')) {
        body.outbound = { privateDestinations }
      }
      if (dirtySections.has('posture')) {
        const list = (v: string) => v.split(',').map((x) => x.trim()).filter(Boolean)
        body.posture = { disabledChecks: list(postureDisabledChecks), ignoredNamespaces: list(postureIgnoredNamespaces) }
      }

      if (dirtySections.has('notify')) {
        const notify: UpdateSettingsRequest['notify'] = {}
        if (clearWebhook) {
          notify.webhookUrl = ''
        } else if (webhookInput) {
          notify.webhookUrl = webhookInput
        }
        body.notify = notify
      }

      // Blank means "clear the override, fall back to the env var/hardcoded
      // default" (sent as null); anything else is parsed as a number and
      // sent as-is — the hub validates it's a positive number and returns a
      // 400 (rendered via mutationFeedback below) if not.
      if (dirtySections.has('analysis')) {
        body.analysis = {
          maxIterations: maxIterations.trim() === '' ? null : Number(maxIterations),
          timeLimitSeconds: timeLimitSeconds.trim() === '' ? null : Number(timeLimitSeconds),
        }
      }

      // The checked boxes, sent verbatim — including an empty array when
      // every box is unchecked, itself a real, valid selection (see
      // autoAnalysisSeverities' own doc comment above), never omitted or
      // translated into some other sentinel.
      if (dirtySections.has('automation')) {
        body.automation = { autoAnalysisEnabled, autoAnalysisSeverities }
      }

      // Blank means "keep forever" (sent as null, which is also this
      // feature's shipped default — see RetentionSettings' doc comment);
      // anything else is parsed as a number of days and sent as-is — the
      // hub validates it's positive and returns a 400 (rendered via
      // mutationFeedback below) if not.
      if (dirtySections.has('retention')) {
        body.retention = {
          auditRetentionDays: auditRetentionDays.trim() === '' ? null : Number(auditRetentionDays),
          incidentRetentionDays: incidentRetentionDays.trim() === '' ? null : Number(incidentRetentionDays),
          findingRetentionDays: findingRetentionDays.trim() === '' ? null : Number(findingRetentionDays),
        }
      }

      // Blank on either storm-protection field means "send null" (no
      // ceiling) — the hub rejects one set without the other, surfaced via
      // mutationFeedback below like any other validation error.
      if (dirtySections.has('detection')) {
        body.detection = {
          disabledDetectorIds,
          stormProtectionMaxNewIncidents:
            stormProtectionMaxNewIncidents.trim() === '' ? null : Number(stormProtectionMaxNewIncidents),
          stormProtectionWindowSeconds:
            stormProtectionWindowSeconds.trim() === '' ? null : Number(stormProtectionWindowSeconds),
          disabledRuleIds,
        }
      }

      // Blank autoApproveMaxRisk/minConfidenceForAutoApprove mean "clear the
      // override, fall back to internal/orchestrator.DefaultAutonomyPolicy's
      // own value" (sent as null) — NOT "never auto-approve," unlike
      // detection's null-means-off fields above (see AutonomySettings' own
      // doc comment in api/types.ts). requireReversibleForAutoApprove is
      // sent verbatim, like automation.autoAnalysisEnabled above.
      if (dirtySections.has('autonomy')) {
        body.autonomy = {
          autoApproveMaxRisk: autoApproveMaxRisk === '' ? null : autoApproveMaxRisk,
          minConfidenceForAutoApprove:
            minConfidenceForAutoApprove.trim() === '' ? null : Number(minConfidenceForAutoApprove),
          requireReversibleForAutoApprove,
          unattendedExecutionEnabled,
          maxUnattendedPerCluster:
            maxUnattendedPerCluster.trim() === '' ? null : Number(maxUnattendedPerCluster),
          maxUnattendedFleetWide:
            maxUnattendedFleetWide.trim() === '' ? null : Number(maxUnattendedFleetWide),
          unattendedWindowSeconds:
            unattendedWindowMinutes.trim() === ''
              ? null
              : Math.round(Number(unattendedWindowMinutes) * 60),
        }
      }

      // Blank on any of the three price fields means "send null" for all
      // three — the hub rejects a partial table (some blank, some filled)
      // with a 400, rendered via mutationFeedback below. Blank
      // dailySpendCeilingUsd means "no ceiling."
      if (dirtySections.has('cost')) {
        body.cost = {
          pricePerMillionInputTokens:
            pricePerMillionInputTokens.trim() === '' ? null : Number(pricePerMillionInputTokens),
          pricePerMillionCachedTokens:
            pricePerMillionCachedTokens.trim() === '' ? null : Number(pricePerMillionCachedTokens),
          pricePerMillionOutputTokens:
            pricePerMillionOutputTokens.trim() === '' ? null : Number(pricePerMillionOutputTokens),
          dailySpendCeilingUsd: dailySpendCeilingUsd.trim() === '' ? null : Number(dailySpendCeilingUsd),
        }
      }

      return updateSettings(body, accessToken!)
    },
    onSuccess: () => {
      // Apply the new accent to THIS tab immediately, rather than waiting
      // for AuthContext's next GET /users/me (a reload, the next proactive
      // token renewal, or a fresh sign-in) — those are what every OTHER
      // tab/user is already relying on to pick up an appearance change
      // (same "from their next page load" contract loginStyle has always
      // had), but the admin who just clicked Save is looking at the screen
      // right now and the colour saved is already known locally without
      // waiting on a round trip.
      if (dirtySections.has('appearance')) {
        applyAccent(primaryColorId)
      }
      // The secret inputs/checkboxes always reset after a successful save
      // — whatever was just submitted has already taken effect, and
      // leaving e.g. "Clear" checked would make the next unrelated save
      // silently wipe the secret again.
      setWebhookInput('')
      setClearWebhook(false)
      // Everything pending has been committed, so nothing is dirty any more
      // — which also re-arms the hydration block above to adopt the fresh
      // response the invalidation below is about to fetch.
      setDirtySections(new Set())
      queryClient.invalidateQueries({ queryKey: ['settings'] })
    },
  })

  function submit(e: FormEvent) {
    e.preventDefault()
    if (hasUnsavedChanges) mutation.mutate()
  }

  // Each form below passes its own section, so a save can send exactly what
  // was edited. A form maps to exactly one PUT section by construction — see
  // the render for the one-form-per-section layout.
  function markDirty(section: SettingsPatchSection) {
    setDirtySections((prev) => (prev.has(section) ? prev : new Set(prev).add(section)))
    if (mutation.isSuccess || mutation.isError) mutation.reset()
  }

  const mutationFeedback = (
    <>
      {mutation.isError && (
        <p className="form-error" role="alert">
          {mutation.error instanceof ApiError
            ? mutation.error.detail
              ? `${mutation.error.message} — ${mutation.error.detail}`
              : mutation.error.message
            : 'Something went wrong. Please try again.'}
        </p>
      )}
      {mutation.isSuccess && <p className="field-hint">Settings saved.</p>}
    </>
  )

  // The sections that do not read organisation settings: each fetches its own
  // data behind its own capability (or none — AI tools & tokens is the
  // viewer's own). Rendered outside the settings query entirely, so opening one
  // neither waits on nor asks for GET /admin/settings — which a viewer without
  // org:settings:write is refused, and which used to block Roles & access and
  // Single sign-on behind a "no access" banner that was not about them.
  const standaloneSections = (
    <>
          {activeSection === 'repositories' && (
            <div className="settings-section" role="tabpanel">
              {canReadRepos ? (
                <RepositoriesCard canWrite={canWriteRepos} disabledReason={reposDisabledReason} />
              ) : (
                <p className="banner banner-warning" role="alert">
                  You don't have access to view connected Git repositories.{' '}
                  {missingCapabilityMessage([CAP_REPO_READ])}
                </p>
              )}
            </div>
          )}

          {/* Notification routing is its own section rather than more fields
              under Notifications, because it is backed by its own endpoint
              (GET/PUT /admin/notification-routing) rather than by this page's
              settings payload — and because the two answer different
              questions: Notifications sets the ONE webhook this install falls
              back to, and this sets which notifications go somewhere else
              instead. The default rule on this screen is that webhook, which
              is why the card names the section to change it on.

              Outside a page <form>: the card owns its own Save, and a nested
              <form> is invalid markup. SETTINGS_SECTIONS marks this section
              form: false so the page's Save bar stays off it. */}
          {activeSection === 'routing' && (
            <div className="settings-section" role="tabpanel">
              <NotificationRoutingCard />
            </div>
          )}

          {activeSection === 'sso' && (
            <SingleSignOnCard
              canWrite={canManageIdentity}
              disabledReason={canManageIdentity ? undefined : missingCapabilityMessage([CAP_IDENTITY_MANAGE])}
            />
          )}

          {activeSection === 'ai-tools' && <PersonalTokensSection />}

          {activeSection === 'access' && (
            <div className="settings-section card settings-panel" role="tabpanel">
              <PanelHead
                title="Builtin roles"
                lede="What each of the five fixed roles can do. Read live from the hub's authorization catalogue."
                help="The capability list per role is read live from the hub's own authorization catalogue — never hand-copied — so it cannot drift out of sync with what a role is actually granted. Every builtin role's bundle is fixed; a custom role below composes a different bundle from the same catalogue instead."
              />

              {rolesQuery.isLoading && <SkeletonLines count={6} />}

              {rolesQuery.isError && (
                <p className="form-error" role="alert">
                  {rolesQuery.error instanceof ApiError
                    ? rolesQuery.error.detail
                      ? `${rolesQuery.error.message} — ${rolesQuery.error.detail}`
                      : rolesQuery.error.message
                    : 'Failed to load roles.'}
                </p>
              )}

              {rolesQuery.data && <RoleMatrix roles={rolesQuery.data.roles} />}

              <h3 className="settings-subhead">
                Custom roles
                <HelpTip label="custom roles" text="A named bundle composed from the same capability catalogue above — never a new permission, only a different combination of the existing ones. Assigned to a user exactly the way a builtin role is, via Users → Add grant." />
              </h3>
              <p className="field-hint">A named bundle of existing capabilities, granted like a builtin role.</p>
              <CustomRolesCard
                canManage={canManageRoles}
                disabledReason={rolesManageDisabledReason}
              />

              <h3 className="settings-subhead">
                Cluster groups
                <HelpTip label="cluster groups" text="A named set of clusters. Granting a role scoped to a group — rather than to one cluster or to every cluster — is how a team's access follows the clusters it owns as the fleet grows, without re-granting one by one." />
              </h3>
              <p className="field-hint">A named set of clusters, so a grant can follow a team's clusters as the fleet grows.</p>
              <ClusterGroupsCard
                canManage={canManageClusterGroups}
                disabledReason={clusterGroupsManageDisabledReason}
              />
            </div>
          )}

          {activeSection === 'diagnostics' && (
            <div className="settings-section card settings-panel" role="tabpanel">
              <PanelHead
                title="Diagnostics bundle"
                lede="A size-bounded troubleshooting file you can hand to someone else. Secret values never leave the hub."
                help="Hub and agent versions, cluster connection state, the applied migration version, per-cluster detector health, and AI-provider/repository configuration presence. Every configured secret — an AI provider's API key, a CLI runner token, a repository credential — is reported only as configured or not. The bundle includes a manifest listing exactly what was included and what was deliberately left out. A support artifact, not a log dump — raw workload logs and Kubernetes Secret contents are never collected."
              />

              <div className="checkbox-row checkbox-row-with-hint">
                <input
                  id="diagnosticsProbe"
                  type="checkbox"
                  checked={includeConnectivityProbe}
                  onChange={(e) => setIncludeConnectivityProbe(e.target.checked)}
                  disabled={!canWrite || diagnosticsMutation.isPending}
                  title={disabledReason}
                />
                <label htmlFor="diagnosticsProbe">Include live connectivity checks</label>
                <p className="field-hint">
                  Also tests every AI provider and Git repository live. Spends a little AI usage and
                  calls each Git host.
                </p>
              </div>

              <button
                type="button"
                onClick={() => diagnosticsMutation.mutate()}
                disabled={!canWrite || diagnosticsMutation.isPending}
                title={disabledReason}
              >
                {diagnosticsMutation.isPending ? 'Building bundle…' : 'Download diagnostics bundle'}
              </button>

              {/* Pending / success / failure, all rendered in the same slot the
                  button sits above, matching AIProvidersCard's own "the verdict
                  appears where the action that produced it is" convention. */}
              {diagnosticsMutation.isPending && (
                <p className="banner banner-info" role="status">
                  Building the bundle{includeConnectivityProbe ? ' and running live connectivity checks' : ''}…
                </p>
              )}
              {diagnosticsMutation.isError && (
                <p className="banner banner-warning" role="alert">
                  {diagnosticsMutation.error instanceof ApiError
                    ? diagnosticsMutation.error.detail
                      ? `${diagnosticsMutation.error.message} — ${diagnosticsMutation.error.detail}`
                      : diagnosticsMutation.error.message
                    : 'Could not build the diagnostics bundle.'}
                </p>
              )}
              {diagnosticsMutation.isSuccess && (
                <div className="banner banner-success" role="status">
                  <strong>Downloaded {diagnosticsMutation.data.filename}</strong>
                  <p>
                    {diagnosticsMutation.data.bundle.clusters.length} cluster(s),{' '}
                    {diagnosticsMutation.data.bundle.aiProviders.length} AI provider(s),{' '}
                    {diagnosticsMutation.data.bundle.repositories.length} repository binding(s),{' '}
                    {/* Null, not [], on a hub with no recorded internal errors:
                        fetchDiagnosticsRecentErrors builds its result with
                        `var out []diagnosticsInternalError`, so zero rows reach
                        the wire as JSON null. The list is present and empty —
                        this 0 is the real count, not a stand-in for a missing
                        one. */}
                    {(diagnosticsMutation.data.bundle.recentInternalErrors ?? []).length} recent internal
                    error(s) — {diagnosticsMutation.data.bundle.manifest.bundleSizeBytes.toLocaleString()}{' '}
                    of {diagnosticsMutation.data.bundle.manifest.maxBundleBytes.toLocaleString()} bytes.
                    {diagnosticsMutation.data.bundle.manifest.truncated && ' Some sections were truncated at their bound.'}
                  </p>
                </div>
              )}
            </div>
          )}

    </>
  )

  return (
    <div className="page list-page settings-page">
      <header className="page-header list-page-header">
        <div>
          <h1>Settings</h1>
        </div>
      </header>

      {needsSettings && isLoading && (
        <div className="settings-layout" aria-busy="true">
          <SettingsNav activeSection={activeSection} interactive={false} />
          {/* BACKLOG D7g. The skeleton has to match the section actually being
              loaded, not a fixed shape — the sections hold between one and three
              panels of very different heights, and a single generic placeholder
              guaranteed the layout jump a skeleton exists to prevent. General is
              one panel (retention); Investigation is three (bounds,
              automatic investigation, auto-approval). */}
          <div className="settings-sections">
            {SECTION_SKELETON[activeSection].map((lines, i) => (
              <div key={i} className="settings-section card settings-panel">
                <SkeletonLines count={lines} />
              </div>
            ))}
          </div>
        </div>
      )}

      {!needsSettings && (
        <div className="settings-layout">
          <SettingsNav activeSection={activeSection} onSelect={selectSection} />
          <div className="settings-sections">{standaloneSections}</div>
        </div>
      )}

      {needsSettings && isError && (
        error instanceof ApiError && error.status === 403 ? (
          // A 403 on the settings GET means this viewer cannot see the SETTINGS —
          // it says nothing about the other sections, which render without this
          // query (standaloneSections). The list stays, so they stay reachable.
          <div className="settings-layout">
            <SettingsNav activeSection={activeSection} onSelect={selectSection} />
            <div className="settings-sections">
              <div className="settings-section card settings-panel" role="tabpanel">
                <p className="banner banner-warning" role="alert">
                  You don't have access to view or change these settings.{' '}
                  {missingCapabilityMessage([CAP_ORG_SETTINGS_WRITE])}
                </p>
              </div>
            </div>
          </div>
        ) : (
          <p className="form-error" role="alert">
            {error instanceof ApiError
              ? error.detail
                ? `${error.message} — ${error.detail}`
                : error.message
              : 'Failed to load settings.'}
          </p>
        )
      )}

      {needsSettings && !isLoading && data && (() => {
        // Derived here rather than inline in the JSX so the two conditions have
        // names and one place to be read. Both mean "this optional limit is
        // unset", which is the DEFAULT for both — see the warning block below
        // for why that combination matters only when automation is on.
        const unboundedSpend = data.cost.dailySpendCeilingUsd == null
        const unboundedIncidentRate =
          data.detection.stormProtectionMaxNewIncidents == null ||
          data.detection.stormProtectionWindowSeconds == null
        // PROJECT.md T8. The enforcement state of the ceiling control the
        // Model pricing section renders, derived once for the badge on the
        // input and the badge on today's figure so the two cannot disagree
        // (anti-patterns.md "One fact, one claim" — a green chip beside prose
        // that qualifies the same fact is resolved by the reader in favour of
        // the green, which is what this screen did).
        //
        // Reads the LIVE input value, not data.cost.dailySpendCeilingUsd, so
        // an operator typing a ceiling is told what it will and won't do
        // before saving it, not after. The two reasons it can't fire are both
        // server-computed (data.cost.spendCountable / .pricingConfigured); the
        // only thing derived here is "is there a value in the field at all",
        // which is the one fact the server cannot know.
        //
        // Order matters: when spend isn't countable, configuring pricing
        // changes nothing, so naming the missing price table would send an
        // operator to do work that cannot help.
        //
        // spendFigureMeasured is the same two conditions the figure itself is
        // rendered on, named once so the sentence built around it cannot
        // disagree with it.
        const spendFigureMeasured = data.cost.spendCountable && data.cost.pricingConfigured
        const ceilingFieldSet = dailySpendCeilingUsd.trim() !== ''
        const ceilingEnforcement = !ceilingFieldSet
          ? null
          : !data.cost.spendCountable
            ? { tone: 'badge-gray', label: 'not enforced — provider spend not measured' }
            : !data.cost.pricingConfigured
              ? { tone: 'badge-gray', label: 'not enforced — no price table' }
              : { tone: 'badge-green', label: 'enforced' }
        return (
        <div className="settings-layout">
          <SettingsNav activeSection={activeSection} onSelect={selectSection} />
          <div className="settings-sections">

          {activeSection === 'analysis' && (
            <div className="settings-section card settings-panel" role="tabpanel">
              <form onSubmit={submit} onChange={() => markDirty('analysis')}>
                {/* Provider configuration moved to its own component when a
                    deployment could have several providers (migration 000034):
                    this form edits one thing's settings, that one edits a
                    collection and a selection, so they do not share a submit
                    button. Investigation bounds stay here — they apply to
                    whichever provider is active, not to any one of them. */}
                <PanelHead
                  title="Investigation bounds"
                  lede="When an investigation stops and reports what it found so far."
                  help="Bounds on the AI investigation loop: at most this many model round-trips, and at most this much wall-clock time. Leave a field blank to fall back to the ARGUS_ANALYSIS_MAX_ITERATIONS / ARGUS_ANALYSIS_TIME_LIMIT_SECONDS env var or the hardcoded default. A saved value takes effect on the very next analysis, no hub restart required."
                />
                <div className="settings-fields">
                  <div className="settings-field">
                    <label htmlFor="maxIterations">Max model round-trips</label>
                    <input
                      id="maxIterations"
                      type="number"
                      min={1}
                      step={1}
                      placeholder={`Default: ${data.analysis.effectiveMaxIterations}`}
                      value={maxIterations}
                      onChange={(e) => setMaxIterations(e.target.value)}
                      disabled={!canWrite}
                      title={disabledReason}
                    />
                  </div>
                  <div className="settings-field">
                    <label htmlFor="timeLimitSeconds">Time limit (seconds)</label>
                    <input
                      id="timeLimitSeconds"
                      type="number"
                      min={1}
                      step={1}
                      placeholder={`Default: ${data.analysis.effectiveTimeLimitSeconds}`}
                      value={timeLimitSeconds}
                      onChange={(e) => setTimeLimitSeconds(e.target.value)}
                      disabled={!canWrite}
                      title={disabledReason}
                    />
                  </div>
                </div>
                <InEffect
                  items={[
                    ['Round-trips', data.analysis.effectiveMaxIterations],
                    ['Time limit', `${data.analysis.effectiveTimeLimitSeconds}s`],
                  ]}
                />
              </form>
            </div>
          )}

          {activeSection === 'analysis' && (
            <div className="settings-section card settings-panel" role="tabpanel">
              <form onSubmit={submit} onChange={() => markDirty('automation')}>
                <PanelHead
                  title="Automatic investigation"
                  lede="Investigate new incidents without anyone clicking Analyze."
                  help={'When on, a background process periodically runs the same AI investigation as the "Analyze" button against any qualifying incident that does not have an analysis yet. Each incident is investigated at most once, ever. When off (the default), every incident still requires a person to click "Analyze."'}
                  aside={
                    <span className={autoAnalysisEnabled ? 'badge badge-green' : 'badge badge-gray'}>
                      {autoAnalysisEnabled ? 'on' : 'off'}
                    </span>
                  }
                />

                <div className="checkbox-row settings-switch-row">
                  <input
                    id="autoAnalysisEnabled"
                    type="checkbox"
                    checked={autoAnalysisEnabled}
                    onChange={(e) => setAutoAnalysisEnabled(e.target.checked)}
                    disabled={!canWrite}
                    title={disabledReason}
                  />
                  <label htmlFor="autoAnalysisEnabled">Automatically investigate new incidents</label>
                </div>

                {/* Connects three controls that are each documented in isolation
                    and only matter together (BUGS.md item 31). Automatic
                    investigation is bounded to at most ONE attempt per incident
                    ever, so a single incident whose occurrence count climbs can
                    never re-spend — that part is unconditional and needs no
                    setting. What is NOT bounded by default is the number of
                    distinct incidents: a fleet-wide event opens many, and each
                    gets its one analysis. The two controls that bound that are
                    both optional and both default to unset. Shown only when
                    automation is actually on, so it is a warning and not a
                    permanent lecture. */}
                {autoAnalysisEnabled && (unboundedSpend || unboundedIncidentRate) && (
                  <div className="consequence-notice" role="status">
                    <strong>Automatic investigation is on, and its cost is not bounded.</strong>
                    <p>
                      Each incident is investigated at most once, but the number of <em>distinct</em>{' '}
                      incidents is unlimited, and one fleet-wide event can open many at once.
                    </p>
                    <ul>
                      {unboundedSpend && (
                        <li>
                          <strong>No daily spend ceiling.</strong>{' '}
                          {data.cost.pricingConfigured
                            ? 'Automatic investigation will keep spending all day. Set one under Model pricing.'
                            : 'No model pricing is configured either, so a ceiling has nothing to compare against — set the price table under Model pricing.'}
                        </li>
                      )}
                      {unboundedIncidentRate && (
                        <li>
                          <strong>Storm protection is off.</strong> One cluster can open an unlimited
                          number of new incidents in a burst. Set a cap under Detectors.
                        </li>
                      )}
                    </ul>
                  </div>
                )}

                <fieldset className="checkbox-group settings-chip-group" disabled={!canWrite || !autoAnalysisEnabled}>
                  <legend>
                    Severities to auto-investigate
                    <HelpTip label="Severities to auto-investigate" text="Check every severity that should be investigated automatically. Any combination is valid — e.g. checking 'High' and 'Critical' while leaving 'Medium' unchecked auto-investigates only the two you checked, not a range." />
                  </legend>
                  <div className="settings-chip-row">
                    {SEVERITY_OPTIONS.map((s) => (
                      <div className="checkbox-row settings-chip" key={s}>
                        <input
                          id={`autoAnalysisSeverity-${s}`}
                          type="checkbox"
                          checked={autoAnalysisSeverities.includes(s)}
                          onChange={(e) => toggleAutoAnalysisSeverity(s, e.target.checked)}
                          disabled={!canWrite || !autoAnalysisEnabled}
                          title={disabledReason}
                        />
                        <label htmlFor={`autoAnalysisSeverity-${s}`}>
                          {s.charAt(0).toUpperCase() + s.slice(1)}
                        </label>
                      </div>
                    ))}
                  </div>
                </fieldset>
                <p className="field-hint">
                  {autoAnalysisEnabled
                    ? autoAnalysisSeverities.length === 0
                      ? 'No severities are checked, so no incident is investigated automatically yet — check at least one above.'
                      : autoAnalysisSeverities.length === SEVERITY_OPTIONS.length
                        ? 'Every new incident, of any severity, is investigated automatically.'
                        : `Only incidents with severity ${autoAnalysisSeverities.map((s) => `"${s}"`).join(' or ')} are investigated automatically; every other severity still requires a manual "Analyze" click.`
                    : 'Turn on automatic investigation above to choose which severities qualify.'}
                </p>
              </form>
            </div>
          )}

          {activeSection === 'automation' && (
            <div className="settings-section card settings-panel" role="tabpanel">
              <form onSubmit={submit} onChange={() => markDirty('autonomy')}>
                <PanelHead
                  title="Unattended execution"
                  lede="Whether an auto-approved plan runs without waiting for a person."
                  help="This only affects plans the auto-approval policy below already approves. Everything else still queues for a human, and every unattended execution goes through the same rehearsal against the live cluster, the same signed plan and the same audit trail as an approved one — the only thing removed is the person. What bounds it: the blast-radius caps, freeze and maintenance windows, the circuit breaker, and a recorded undo for every change. The undo is a human action — nothing reverses a change automatically when validation fails."
                  aside={
                    <span className={unattendedExecutionEnabled ? 'badge badge-red' : 'badge badge-green'}>
                      {unattendedExecutionEnabled ? 'on — clusters change unsupervised' : 'off'}
                    </span>
                  }
                />
                {unattendedExecutionEnabled ? (
                  <p className="banner banner-warning">
                    <strong>Unattended execution is on. ARGUS can change your clusters with nobody
                    watching.</strong>{' '}
                    A plan that clears every condition below executes as soon as the investigation
                    finishes, unless a window or cap stops it. Undo is offered but never automatic.
                  </p>
                ) : (
                  <p className="banner banner-info">
                    <strong>Nothing here executes anything.</strong> While unattended execution is
                    off, an auto-approvable plan still waits in the approval queue for a person; the
                    policy below only sets the verdict the gate records.
                  </p>
                )}
                <div className="checkbox-row settings-switch-row">
                  <input
                    id="unattendedExecutionEnabled"
                    type="checkbox"
                    checked={unattendedExecutionEnabled}
                    onChange={(e) => setUnattendedExecutionEnabled(e.target.checked)}
                    disabled={!canWrite}
                    title={disabledReason}
                  />
                  <label htmlFor="unattendedExecutionEnabled">
                    Execute auto-approved plans without waiting for a person
                  </label>
                </div>

                <h3 className="settings-subhead">
                  Blast-radius caps
                  <HelpTip label="the blast-radius caps" text="Counted over the window, successes and failures alike — a failed execution still touched a live cluster. When a cap is reached the plan is not discarded: it waits in the approval queue with the reason recorded on the incident. A blank field means the default, never 'unlimited' — and 0 is refused rather than read as 'never', because it would resolve to the default and do the opposite of what you meant." />
                </h3>
                <div className="settings-fields">
                  <div className="settings-field">
                    <label htmlFor="maxUnattendedPerCluster">
                      Per cluster
                      <HelpTip label="the per-cluster cap" text="Once a cluster reaches this many unattended changes in the window, further auto-approved plans there wait for a human instead. Leave blank for the conservative default." />
                    </label>
                    <input
                      id="maxUnattendedPerCluster"
                      type="number"
                      min={1}
                      step={1}
                      placeholder={`Default: ${data.autonomy.effectiveMaxUnattendedPerCluster}`}
                      value={maxUnattendedPerCluster}
                      onChange={(e) => setMaxUnattendedPerCluster(e.target.value)}
                      disabled={!canWrite}
                      title={disabledReason}
                    />
                  </div>
                  <div className="settings-field">
                    <label htmlFor="maxUnattendedFleetWide">
                      Across the fleet
                      <HelpTip label="the fleet-wide cap" text="The limit that matters most. Thirty clusters each executing once is only one per cluster, so no per-cluster limit would ever notice — but a burst across many clusters usually means one shared cause, which is exactly when a person should look before more changes land. Leave blank for the conservative default." />
                    </label>
                    <input
                      id="maxUnattendedFleetWide"
                      type="number"
                      min={1}
                      step={1}
                      placeholder={`Default: ${data.autonomy.effectiveMaxUnattendedFleetWide}`}
                      value={maxUnattendedFleetWide}
                      onChange={(e) => setMaxUnattendedFleetWide(e.target.value)}
                      disabled={!canWrite}
                      title={disabledReason}
                    />
                  </div>
                  <div className="settings-field">
                    <label htmlFor="unattendedWindowMinutes">
                      Window (minutes)
                      <HelpTip label="the cap window" text="A rolling window, not a reset-on-the-hour budget: both counts look back this far from the moment a plan is ready to execute. Leave blank for the default." />
                    </label>
                    <input
                      id="unattendedWindowMinutes"
                      type="number"
                      min={1}
                      step={1}
                      placeholder={`Default: ${data.autonomy.effectiveUnattendedWindowSeconds / 60}`}
                      value={unattendedWindowMinutes}
                      onChange={(e) => setUnattendedWindowMinutes(e.target.value)}
                      disabled={!canWrite}
                      title={disabledReason}
                    />
                  </div>
                </div>
                <InEffect
                  items={[
                    ['Per cluster', data.autonomy.effectiveMaxUnattendedPerCluster],
                    ['Fleet-wide', data.autonomy.effectiveMaxUnattendedFleetWide],
                    ['Window', `${data.autonomy.effectiveUnattendedWindowSeconds / 60} min`],
                  ]}
                />

                <h3 className="settings-subhead">
                  Auto-approval policy
                  <HelpTip label="the auto-approval policy" text="The policy is a ceiling only — it can never override the one rule that is not configurable anywhere in this product: a high-risk action with no known undo path always requires a human to approve it, regardless of confidence or any setting on this page. A saved change takes effect on the very next AI investigation, no hub restart required." />
                </h3>
                <div className="settings-fields">
                  <div className="settings-field">
                    <label htmlFor="autoApproveMaxRisk">
                      Maximum risk
                      <HelpTip label="Maximum risk for auto-approval" text="A proposed plan riskier than this ceiling can never get an auto-approve verdict, regardless of confidence. Leave unset to fall back to the conservative shipped default (low)." />
                    </label>
                    <select
                      id="autoApproveMaxRisk"
                      value={autoApproveMaxRisk}
                      onChange={(e) => setAutoApproveMaxRisk(e.target.value as typeof autoApproveMaxRisk)}
                      disabled={!canWrite}
                      title={disabledReason}
                    >
                      <option value="">Default ({data.autonomy.effectiveAutoApproveMaxRisk})</option>
                      {AUTO_APPROVE_MAX_RISK_OPTIONS.map((level) => (
                        <option key={level} value={level}>
                          {level.charAt(0).toUpperCase() + level.slice(1)}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="settings-field">
                    <label htmlFor="minConfidenceForAutoApprove">
                      Minimum confidence (0–1)
                      <HelpTip label="Minimum confidence for auto-approval" text="The AI investigation's self-reported confidence must meet or exceed this threshold for a plan to be marked auto-approvable. A null/unknown confidence never qualifies, however low this is set. Leave blank to fall back to the conservative shipped default." />
                    </label>
                    <input
                      id="minConfidenceForAutoApprove"
                      type="number"
                      min={0}
                      max={1}
                      step={0.01}
                      placeholder={`Default: ${data.autonomy.effectiveMinConfidenceForAutoApprove}`}
                      value={minConfidenceForAutoApprove}
                      onChange={(e) => setMinConfidenceForAutoApprove(e.target.value)}
                      disabled={!canWrite}
                      title={disabledReason}
                    />
                  </div>
                </div>
                <div className="checkbox-row">
                  <input
                    id="requireReversibleForAutoApprove"
                    type="checkbox"
                    checked={requireReversibleForAutoApprove}
                    onChange={(e) => setRequireReversibleForAutoApprove(e.target.checked)}
                    disabled={!canWrite}
                    title={disabledReason}
                  />
                  <label htmlFor="requireReversibleForAutoApprove">
                    Require the plan to be reversible{' '}
                    <span
                      className={
                        requireReversibleForAutoApprove ? 'badge badge-green' : 'badge badge-gray'
                      }
                    >
                      {requireReversibleForAutoApprove ? 'required' : 'not required'}
                    </span>
                  </label>
                </div>
                <InEffect
                  items={[
                    ['Max risk', data.autonomy.effectiveAutoApproveMaxRisk],
                    ['Min confidence', data.autonomy.effectiveMinConfidenceForAutoApprove],
                  ]}
                />
              </form>
            </div>
          )}

          {/* The time gate and the outcome gate on unattended execution,
              directly below the switch they constrain — sibling cards outside
              the settings <form>, because each has its own create/delete/reset
              round-trips and must not be submitted by the Save bar. */}
          {activeSection === 'automation' && (
            <div className="settings-section" role="tabpanel">
              <AutomationWindowsCard canWrite={canWrite} disabledReason={disabledReason} />
            </div>
          )}
          {activeSection === 'automation' && (
            <div className="settings-section" role="tabpanel">
              <CircuitBreakerCard canWrite={canWrite} disabledReason={disabledReason} />
            </div>
          )}

          {activeSection === 'providers' && (
            <div className="settings-section card settings-panel" role="tabpanel">
              <AIProvidersCard
                canWrite={canWrite}
                disabledReason={disabledReason}
                cliBackendAvailable={data.llm.cliBackendAvailable}
              />
            </div>
          )}

          {/* Retention is under General, not with Detectors as it used to be.
              "How long ARGUS keeps what it recorded" is an install-wide
              housekeeping policy — it has nothing to do with which detectors
              run, and grouping the two is what produced the broad "Operations"
              label that made this page hard to navigate. (A "Demo data" panel
              sat here too until 2026-09-09; PROJECT.md D14 records why it was
              removed rather than moved.) */}
          {activeSection === 'general' && (
            <div className="settings-section card settings-panel" role="tabpanel">
              <form onSubmit={submit} onChange={() => markDirty('retention')}>
                <PanelHead
                  title="Data retention"
                  lede="Blank keeps history forever. A window permanently deletes anything older."
                  help="Leave a field blank to keep that data type forever — the default for all three, and nothing is ever deleted unless a window is set here explicitly. Setting a window causes a daily background job to permanently drop history older than that window; this cannot be undone. A saved change takes effect on the next daily maintenance run, not immediately."
                />
                <div className="settings-fields">
                  <div className="settings-field">
                    <label htmlFor="auditRetentionDays">
                      Audit log (days)
                      <HelpTip label="Audit log retention" text="How long to keep audit log entries (sign-ins, admin actions, cluster enrollment, etc.) before old history is permanently dropped. Leave blank to keep audit history forever." />
                    </label>
                    <input
                      id="auditRetentionDays"
                      type="number"
                      min={1}
                      step={1}
                      placeholder="Keep forever"
                      value={auditRetentionDays}
                      onChange={(e) => setAuditRetentionDays(e.target.value)}
                      disabled={!canWrite}
                      title={disabledReason}
                    />
                  </div>
                  <div className="settings-field">
                    <label htmlFor="incidentRetentionDays">
                      Incidents (days)
                      <HelpTip label="Incident retention" text="How long to keep incidents (and their analyses) before old history is permanently dropped. Leave blank to keep incident history forever." />
                    </label>
                    <input
                      id="incidentRetentionDays"
                      type="number"
                      min={1}
                      step={1}
                      placeholder="Keep forever"
                      value={incidentRetentionDays}
                      onChange={(e) => setIncidentRetentionDays(e.target.value)}
                      disabled={!canWrite}
                      title={disabledReason}
                    />
                  </div>
                  <div className="settings-field">
                    <label htmlFor="findingRetentionDays">
                      Findings (days)
                      <HelpTip label="Finding retention" text="How long to keep raw findings (the detector output incidents are built from) before old history is permanently dropped. Leave blank to keep finding history forever." />
                    </label>
                    <input
                      id="findingRetentionDays"
                      type="number"
                      min={1}
                      step={1}
                      placeholder="Keep forever"
                      value={findingRetentionDays}
                      onChange={(e) => setFindingRetentionDays(e.target.value)}
                      disabled={!canWrite}
                      title={disabledReason}
                    />
                  </div>
                </div>
              </form>
            </div>
          )}

          {activeSection === 'general' && (
            <div className="settings-section card settings-panel" role="tabpanel">
              <form onSubmit={submit} onChange={() => markDirty('general')}>
                <PanelHead
                  title="Account security"
                  lede="The password floor and the idle session limit, applied fleet-wide."
                  help="minPasswordLength applies the next time anyone changes their own password (PUT /users/me/password) — it does not retroactively invalidate an existing password that was set under a looser rule. The idle timeout ends a session that goes this long without a background renewal; leave it blank for no limit, today's behaviour."
                />
                <div className="settings-fields">
                  <div className="settings-field">
                    <label htmlFor="minPasswordLength">
                      Minimum password length
                      <HelpTip
                        label="Minimum password length"
                        text="How many characters a self-chosen password must be at minimum. Does not apply to a temporary password an admin generates when creating or resetting an account — those are always long, random, and already clear this floor by a wide margin."
                      />
                    </label>
                    <input
                      id="minPasswordLength"
                      type="number"
                      min={8}
                      max={128}
                      step={1}
                      value={minPasswordLength}
                      onChange={(e) => setMinPasswordLength(e.target.value)}
                      disabled={!canWrite}
                      title={disabledReason}
                    />
                  </div>
                  <div className="settings-field">
                    <label htmlFor="sessionIdleTimeoutMinutes">
                      Max session idle time (minutes)
                      <HelpTip
                        label="Session idle timeout"
                        text="A signed-in session ends once this many minutes pass with no background renewal — the same server-side check that already refuses a reused or expired refresh token, so a captured or forgotten session cannot outlive this limit even if the browser tab is left open. Leave blank for no limit, today's behaviour."
                      />
                    </label>
                    <input
                      id="sessionIdleTimeoutMinutes"
                      type="number"
                      min={5}
                      max={10080}
                      step={1}
                      placeholder="No limit"
                      value={sessionIdleTimeoutMinutes}
                      onChange={(e) => setSessionIdleTimeoutMinutes(e.target.value)}
                      disabled={!canWrite}
                      title={disabledReason}
                    />
                  </div>
                </div>
              </form>
            </div>
          )}

          {activeSection === 'detectors' && (
            <div className="settings-section card settings-panel" role="tabpanel">
              <form onSubmit={submit} onChange={() => markDirty('detection')}>
                <PanelHead
                  title="Detectors"
                  lede="Check a detector to stop its findings from opening incidents."
                  help={'A hub-side filter, not a switch the agent itself sees: the agent keeps running a "disabled" detector and keeps sending its findings exactly as before — there is no mechanism yet to push this setting down to a running agent, so disabling a detector here only stops the hub from acting on what it already received. Fully live, no restart needed on either side.'}
                  aside={<span className="badge badge-gray">hub-side filter</span>}
                />

                {DETECTOR_OPTIONS.map((d) => (
                  <div className="checkbox-row checkbox-row-with-hint" key={d.id}>
                    <input
                      id={`detectorDisabled-${d.id}`}
                      type="checkbox"
                      checked={disabledDetectorIds.includes(d.id)}
                      onChange={(e) => toggleDetectorDisabled(d.id, e.target.checked)}
                      disabled={!canWrite}
                      title={disabledReason}
                    />
                    <label htmlFor={`detectorDisabled-${d.id}`}>
                      Disable "{d.label}"{' '}
                      <span
                        className={
                          disabledDetectorIds.includes(d.id) ? 'badge badge-gray' : 'badge badge-green'
                        }
                      >
                        {disabledDetectorIds.includes(d.id) ? 'disabled' : 'enabled'}
                      </span>
                    </label>
                    <p className="field-hint">{d.description}</p>
                  </div>
                ))}
              </form>
            </div>
          )}

          {activeSection === 'detectors' && (
            <div className="settings-section card settings-panel" role="tabpanel">
              <form onSubmit={submit} onChange={() => markDirty('detection')}>
                <PanelHead
                  title="Rules"
                  lede={
                    <>
                      The sweep detector's declarative checks.{' '}
                      {disabledRuleIds.length === 0
                        ? `All ${RULE_IDS.length} enabled.`
                        : `${disabledRuleIds.length} of ${RULE_IDS.length} disabled.`}
                    </>
                  }
                  help={'Every rule here is one of the declarative checks the sweep detector evaluates — all of them share that one detector\'s ID, so disabling "Sweep detector" above silences all of them, and every hand-written check in the same detector, at once. Check a rule here to stop just that one rule\'s findings from becoming incidents, leaving the other rules and the hand-written checks untouched. Same hub-side filter as above — not a switch the agent sees, fully live.'}
                  aside={
                    <label className="list-search-field settings-head-search">
                      <span className="visually-hidden">Filter rules</span>
                      <SearchIcon />
                      <input
                        type="search"
                        placeholder="Filter rules by id"
                        value={ruleFilter}
                        onChange={(e) => {
                          // Stops this purely-local, never-submitted filter
                          // text from bubbling into the enclosing <form>'s
                          // onChange, which marks the whole "detection"
                          // section dirty on any change — typing a filter
                          // query is not an edit to any setting and must not
                          // be treated like one.
                          e.stopPropagation()
                          setRuleFilter(e.target.value)
                        }}
                        // Deliberately NOT disabled={!canWrite}: this filters
                        // what's rendered rather than changing any setting, so
                        // a viewer who lacks org:settings:write can still
                        // browse the full rule list — only the checkboxes
                        // themselves are gated.
                      />
                    </label>
                  }
                />

                {filteredRuleIds.length === 0 ? (
                  <p className="field-hint">No rules match &ldquo;{ruleFilter}&rdquo;.</p>
                ) : (
                  <div className="settings-rule-grid">
                    {filteredRuleIds.map((ruleId) => (
                      <div className="checkbox-row" key={ruleId}>
                        <input
                          id={`ruleDisabled-${ruleId}`}
                          type="checkbox"
                          checked={disabledRuleIds.includes(ruleId)}
                          onChange={(e) => toggleRuleDisabled(ruleId, e.target.checked)}
                          disabled={!canWrite}
                          title={disabledReason}
                        />
                        <label htmlFor={`ruleDisabled-${ruleId}`}>
                          <span className="visually-hidden">Disable </span>
                          <code>{ruleId}</code>
                          {/* Only the exception is marked: thirty-odd green
                              "enabled" chips said nothing the unchecked box
                              and the head's count did not already say. */}
                          {disabledRuleIds.includes(ruleId) && (
                            <>
                              {' '}
                              <span className="badge badge-gray">disabled</span>
                            </>
                          )}
                        </label>
                      </div>
                    ))}
                  </div>
                )}
              </form>
            </div>
          )}

          {activeSection === 'detectors' && (
            <div className="settings-section card settings-panel" role="tabpanel">
              <form onSubmit={submit} onChange={() => markDirty('detection')}>
                <PanelHead
                  title="Storm protection"
                  lede="Cap how many new incidents one cluster may open in a burst."
                  help="Caps how many brand-new incidents a single cluster may open within a rolling window. This bounds a flood of genuinely distinct new problems — it is separate from the per-fingerprint dedup that already collapses repeats of the same problem into one incident. Once a cluster hits the ceiling, further findings that would have opened a new incident are still recorded but stop creating incidents until the window passes; existing incidents keep updating normally. Leave both fields blank to disable storm protection (the default). Fully live, no restart needed."
                  aside={
                    unboundedIncidentRate ? (
                      <span className="badge badge-gray">off</span>
                    ) : (
                      <span className="badge badge-green">on</span>
                    )
                  }
                />
                <div className="settings-fields">
                  <div className="settings-field">
                    <label htmlFor="stormProtectionMaxNewIncidents">Max new incidents per cluster</label>
                    <input
                      id="stormProtectionMaxNewIncidents"
                      type="number"
                      min={1}
                      step={1}
                      placeholder="No ceiling"
                      value={stormProtectionMaxNewIncidents}
                      onChange={(e) => setStormProtectionMaxNewIncidents(e.target.value)}
                      disabled={!canWrite}
                      title={disabledReason}
                    />
                  </div>
                  <div className="settings-field">
                    <label htmlFor="stormProtectionWindowSeconds">
                      Rolling window (seconds)
                      <HelpTip label="the rolling window" text="How far back to count a cluster's new incidents when checking the ceiling — e.g. 300 means 'at most N new incidents in any trailing 5 minutes.' Must be set together with the ceiling; leave both blank to disable." />
                    </label>
                    <input
                      id="stormProtectionWindowSeconds"
                      type="number"
                      min={1}
                      step={1}
                      placeholder="No ceiling"
                      value={stormProtectionWindowSeconds}
                      onChange={(e) => setStormProtectionWindowSeconds(e.target.value)}
                      disabled={!canWrite}
                      title={disabledReason}
                    />
                  </div>
                </div>

                <div className="settings-preview">
                  <div className="settings-preview-text">
                    <h3 className="settings-subhead">
                      Preview against history
                      <HelpTip label="the history preview" text="Replays the exact same decision logic the hub uses live (the detector-disable filter and the storm-protection ceiling) against real recorded findings/incidents from the last several days. Never saves anything, and never touches a live cluster — pure simulation over already-recorded history." />
                    </h3>
                    <p className="field-hint">
                      What the detector and storm settings as entered — saved or not — would have done
                      to real history.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => dryRunMutation.mutate()}
                    disabled={!canWrite || dryRunMutation.isPending}
                    title={disabledReason}
                  >
                    {dryRunMutation.isPending ? 'Simulating…' : 'Preview against history'}
                  </button>
                </div>

                {dryRunMutation.isError && (
                  <p className="form-error" role="alert">
                    {dryRunMutation.error instanceof ApiError
                      ? dryRunMutation.error.detail
                        ? `${dryRunMutation.error.message} — ${dryRunMutation.error.detail}`
                        : dryRunMutation.error.message
                      : 'Something went wrong. Please try again.'}
                  </p>
                )}

                {dryRunMutation.data && <DetectionDryRunResult result={dryRunMutation.data} />}
              </form>
            </div>
          )}

          {activeSection === 'detectors' && (
            <div className="settings-section card settings-panel" role="tabpanel">
              <form onSubmit={submit} onChange={() => markDirty('posture')}>
                <PanelHead
                  title="Posture"
                  lede="Checks and namespaces every cluster's posture leaves out."
                  help="Applied to every cluster on top of each agent's own chart values (posture.disabledChecks and posture.ignoredNamespaces): the Posture tab, the fleet posture card and posture signals all leave them out. Check IDs are the ones on the Posture tab; namespaces may start or end with * (team-*, *-sandbox). A team can also set aside a check on one object or namespace with the argus.io/ignore-checks annotation, which keeps it visible as excepted."
                  aside={
                    postureDisabledChecks || postureIgnoredNamespaces ? (
                      <span className="badge badge-amber">exceptions set</span>
                    ) : (
                      <span className="badge badge-gray">none</span>
                    )
                  }
                />
                <div className="settings-fields">
                  <div className="settings-field">
                    <label htmlFor="postureDisabledChecks">Disabled checks</label>
                    <input
                      id="postureDisabledChecks"
                      value={postureDisabledChecks}
                      onChange={(e) => setPostureDisabledChecks(e.target.value)}
                      placeholder="hostNetwork, runAsRoot"
                      disabled={!canWrite}
                      title={disabledReason}
                    />
                  </div>
                  <div className="settings-field">
                    <label htmlFor="postureIgnoredNamespaces">Ignored namespaces</label>
                    <input
                      id="postureIgnoredNamespaces"
                      value={postureIgnoredNamespaces}
                      onChange={(e) => setPostureIgnoredNamespaces(e.target.value)}
                      placeholder="team-*, *-sandbox"
                      disabled={!canWrite}
                      title={disabledReason}
                    />
                  </div>
                </div>
              </form>
            </div>
          )}

          {/* Not a control: the resend cooldown is an agent-side, restart-
              required environment variable because the hub has no mechanism to
              push config down to a connected agent. Stated here so a reader
              looking for it on the page that tunes detection finds where it
              lives, rather than concluding it does not exist. */}
          {activeSection === 'detectors' && (
            <div className="settings-section card settings-panel settings-note" role="tabpanel">
              <PanelHead
                title="Resend cooldown"
                lede={
                  <>
                    Set per agent by <code>ARGUS_FINDING_RESEND_COOLDOWN_SECONDS</code> (default 5
                    minutes) — not a field here.
                  </>
                }
                help="How often the same detected problem may be re-sent by an agent. There is no mechanism yet for the hub to push a config change down to an already-connected agent, so unlike every other control here this one is a real, working, but agent-side, restart-required environment variable, set when each agent is deployed."
                aside={<span className="badge badge-gray">agent-side · restart required</span>}
              />
            </div>
          )}


          {/* Its own section rather than the tail of the investigation form: a
              per-model rate card is reference data an operator edits when a
              vendor changes its prices, not a knob they turn while tuning how
              investigation behaves. Same argument that split AI providers out. */}
          {activeSection === 'pricing' && (
            <div className="settings-section card settings-panel" role="tabpanel">
              <form onSubmit={submit} onChange={() => markDirty('cost')}>
                <PanelHead
                  title="LLM pricing"
                  lede="US dollars per million tokens, for the model configured under AI providers."
                  help="Intentionally not pre-filled with any vendor's rate — pricing changes, and a hardcoded number would go stale silently. With all three blank, an API-provider analysis records no cost at all; an agent-CLI analysis still records the notional figure its runner reports. The three must be set together; saving with just one or two filled in is rejected. Analyses recorded earlier keep whatever they recorded — nothing is retroactively recomputed."
                />

                <div className={data.cost.pricingConfigured ? 'banner banner-success' : 'banner banner-warning'}>
                  {data.cost.pricingConfigured ? (
                    <>
                      <strong>Pricing is configured.</strong> New analyses compute a real cost from
                      here on; earlier ones keep what they recorded.
                    </>
                  ) : (
                    <>
                      <strong>No pricing configured — this is the current, unconfigured state.</strong>{' '}
                      Until all three prices are set, an API-provider analysis computes no cost.
                    </>
                  )}
                </div>

                <div className="settings-fields">
                  <div className="settings-field">
                    <label htmlFor="pricePerMillionInputTokens">
                      Input tokens ($ / million)
                      <HelpTip label="Input token price" text="Price per million billed-input tokens — the full prompt size sent on a model round-trip, cached or not (see analysis's own tokensBilledIn)." />
                    </label>
                    <input
                      id="pricePerMillionInputTokens"
                      type="number"
                      min={0}
                      step="0.01"
                      placeholder="Not configured"
                      value={pricePerMillionInputTokens}
                      onChange={(e) => setPricePerMillionInputTokens(e.target.value)}
                      disabled={!canWrite}
                      title={disabledReason}
                    />
                  </div>
                  <div className="settings-field">
                    <label htmlFor="pricePerMillionCachedTokens">
                      Cached-read input tokens ($ / million)
                      <HelpTip label="Cached-read token price" text="Price per million prompt-cache-read tokens — usually much cheaper than a full input token, which is why this is a separate price rather than folded into the input price." />
                    </label>
                    <input
                      id="pricePerMillionCachedTokens"
                      type="number"
                      min={0}
                      step="0.01"
                      placeholder="Not configured"
                      value={pricePerMillionCachedTokens}
                      onChange={(e) => setPricePerMillionCachedTokens(e.target.value)}
                      disabled={!canWrite}
                      title={disabledReason}
                    />
                  </div>
                  <div className="settings-field">
                    <label htmlFor="pricePerMillionOutputTokens">
                      Output tokens ($ / million)
                      <HelpTip label="Output token price" text="Price per million completion (output) tokens the model generated." />
                    </label>
                    <input
                      id="pricePerMillionOutputTokens"
                      type="number"
                      min={0}
                      step="0.01"
                      placeholder="Not configured"
                      value={pricePerMillionOutputTokens}
                      onChange={(e) => setPricePerMillionOutputTokens(e.target.value)}
                      disabled={!canWrite}
                      title={disabledReason}
                    />
                  </div>
                </div>
              </form>
            </div>
          )}

          {activeSection === 'pricing' && (
            <div className="settings-section card settings-panel" role="tabpanel">
              <form onSubmit={submit} onChange={() => markDirty('cost')}>
                <PanelHead
                  title="Daily spend ceiling"
                  lede="Stops automatic investigation for the rest of the UTC day once reached."
                  help={'Once pricing is configured, a background check compares today\'s real, already-accumulated spend against this ceiling before starting any automatic investigation. If the ceiling is reached, automatic investigation stops for the rest of the day, logged clearly, and resumes on its own once spend resets or the ceiling is raised. A manual "Analyze" click on one incident is a deliberate, bounded human action and is never blocked by this ceiling, by design. Leave blank for no ceiling. A ceiling with no pricing configured does nothing, since cost is always $0.00 without a price table to compute it from.'}
                />

                <div className="settings-fields">
                  <div className="settings-field">
                    <label htmlFor="dailySpendCeilingUsd">
                      Daily spend ceiling ($){' '}
                      {/* PROJECT.md T8. The control itself has to carry its own
                          enforcement state: an enabled number input beside no
                          state reads as a live guardrail. The badge is not
                          colour-only — the word carries the meaning and the
                          tone follows it (tokens.md's never-colour-alone rule). */}
                      {ceilingEnforcement && (
                        <span className={`badge ${ceilingEnforcement.tone}`}>{ceilingEnforcement.label}</span>
                      )}
                      <HelpTip label="Daily spend ceiling" text="A positive dollar amount, or leave blank for no ceiling. Compared against the real sum of today's recorded investigation spend, by UTC calendar day." />
                    </label>
                    <input
                      id="dailySpendCeilingUsd"
                      type="number"
                      min={0}
                      step="0.01"
                      placeholder="No ceiling"
                      value={dailySpendCeilingUsd}
                      onChange={(e) => setDailySpendCeilingUsd(e.target.value)}
                      disabled={!canWrite}
                      title={disabledReason}
                    />
                  </div>
                  {/* BACKLOG D7b / PROJECT.md T8. Today's figure is only a
                      measurement when spend is countable AND a price table
                      exists; otherwise it says which of the two is missing
                      rather than showing $0.0000 — a fabricated zero wearing
                      the word "real" (anti-patterns.md). */}
                </div>
                <div className="settings-effective">
                  <span className="settings-effective-label">Today's real spend so far</span>
                  <p className="settings-effective-text">
                      <strong>
                        {!data.cost.spendCountable
                          ? '— not measured, the active provider bills by subscription'
                          : data.cost.pricingConfigured
                            ? `$${data.cost.todaySpendUsd.toFixed(4)}`
                            : '— not measured, no price table configured'}
                      </strong>
                      {data.cost.dailySpendCeilingUsd != null && (
                        <>
                          {spendFigureMeasured ? (
                            <> of a ${data.cost.dailySpendCeilingUsd.toFixed(2)} daily ceiling</>
                          ) : (
                            <>. Configured ceiling ${data.cost.dailySpendCeilingUsd.toFixed(2)}</>
                          )}{' '}
                          {/* Three states, not two: "under ceiling" claims a
                              guardrail is holding, so it needs the hub's own
                              enforceability answer; breached wins where true. */}
                          {data.cost.ceilingBreached ? (
                            <span className="badge badge-red">ceiling reached</span>
                          ) : data.cost.ceilingEnforceable ? (
                            <span className="badge badge-green">under ceiling</span>
                          ) : (
                            <span className="badge badge-gray">not enforced</span>
                          )}
                        </>
                      )}
                      . Resets at the next UTC calendar day.
                  </p>
                </div>

                {/* BACKLOG H5 / PROJECT.md T8. Under a subscription provider every
                    real analysis persists cost_basis 'subscription', which the
                    ceiling's sum deliberately excludes — so the ceiling can never
                    fire however low it is set. Gated on data.cost.spendCountable,
                    the same server answer the badges above read, so the notice
                    and the badge it explains cannot disagree. Shown only when a
                    ceiling is actually configured. */}
                {!data.cost.spendCountable && data.cost.dailySpendCeilingUsd != null && (
                  <div className="consequence-notice" role="status">
                    <strong>This ceiling can't actually be reached right now.</strong>{' '}
                    <HelpTip
                      label="the unreachable ceiling"
                      text="The active AI provider is an Agent CLI on a subscription, whose cost is recorded on a notional basis this ceiling does not count — so real activity can never breach it while that provider is active. A known, accepted tradeoff of subscription billing, not a bug."
                    />
                    <p>The active provider bills by subscription, which this ceiling does not count.</p>
                  </div>
                )}
              </form>
            </div>
          )}

          {activeSection === 'notifications' && (
            <div className="settings-section card settings-panel" role="tabpanel">
              <form onSubmit={submit} onChange={() => markDirty('notify')}>
                <PanelHead
                  title="Notifications"
                  lede="The organization webhook — the default route's destination. Per-destination rules are under Notification routing."
                />

                <label htmlFor="webhookUrl">
                  Notification webhook URL{' '}
                  <span
                    className={data.notify.webhookConfigured ? 'badge badge-green' : 'badge badge-gray'}
                  >
                    {data.notify.webhookConfigured ? 'configured' : 'not configured'}
                  </span>
                </label>
                <input
                  id="webhookUrl"
                  type="password"
                  autoComplete="new-password"
                  placeholder={secretPlaceholder(data.notify.webhookConfigured)}
                  value={webhookInput}
                  onChange={(e) => setWebhookInput(e.target.value)}
                  disabled={!canWrite || clearWebhook}
                  title={disabledReason}
                />
                {/* Offered only when there is a webhook to clear. With none set the
                    control has nothing to act on — that is a state, not a missing
                    capability, so it is left out rather than shown disabled. */}
                {data.notify.webhookConfigured ? (
                  <>
                    <div className="checkbox-row">
                      <input
                        id="clearWebhook"
                        type="checkbox"
                        checked={clearWebhook}
                        onChange={(e) => setClearWebhook(e.target.checked)}
                        disabled={!canWrite || !!webhookInput}
                        title={disabledReason}
                      />
                      <label htmlFor="clearWebhook">Clear the webhook URL</label>
                    </div>
                    <p className="field-hint">
                      Leave blank to keep the current webhook unchanged. Type a new value to replace it,
                      or check "Clear" to remove it entirely.
                    </p>
                  </>
                ) : (
                  <p className="field-hint">No webhook is set. Type a URL to start sending notifications to it.</p>
                )}

              </form>
            </div>
          )}

          {/* Outbound access sits under Integrations, beside the two things it
              constrains: the Git providers ARGUS dials and (through AI
              providers) the model endpoint it dials. Its own section rather
              than a field on either, because the list is a property of the
              hub's egress posture and nesting it under one consumer would
              imply it applies only to that one — the same reasoning
              internal/api/settings.go gives for making it a top-level
              section of the payload.

              The card is outside a page <form>: it owns a small add form of
              its own, and a nested <form> is invalid markup. The page's Save
              bar still commits it — SETTINGS_SECTIONS marks this section
              form-backed, and the card's edits mark the 'outbound' patch
              section dirty. */}
          {activeSection === 'outbound' && (
            <div className="settings-section" role="tabpanel">
              <OutboundAllowlistCard
                entries={privateDestinations}
                savedEntries={data.outbound.privateDestinations}
                onChange={(next) => {
                  setPrivateDestinations(next)
                  markDirty('outbound')
                }}
                canWrite={canWrite}
                disabledReason={disabledReason}
              />
            </div>
          )}

          {activeSection === 'appearance' && (
            <div className="settings-section card settings-panel" role="tabpanel">
              <form onSubmit={submit} onChange={() => markDirty('appearance')}>
                <PanelHead
                  title="Sign-in screen"
                  lede="Applies to everyone signing in to this install, from their next page load."
                  help="The sign-in screen is shown before there is a user to have a preference, so this is install-wide rather than per person. Anyone with the screen already open keeps the old one until they reload."
                />

                {/* Radios, not a <select>. Three options that each need a
                    sentence of explanation do not fit in a dropdown, and this
                    choice is made once and rarely revisited — the vertical
                    space costs less than making someone open a menu to find
                    out what the options are.

                    The list comes from `data.appearance.styles` — the hub's
                    own — rather than from a constant here, so a style added or
                    removed server-side changes this list with no frontend
                    release. STYLE_DESCRIPTIONS only supplies the prose, and an
                    id it has never heard of still renders and is still
                    selectable. */}
                <fieldset className="settings-choice-set">
                  <legend>Style</legend>
                  {data.appearance.styles.map((id) => {
                    const meta = STYLE_DESCRIPTIONS[id]
                    return (
                      <label key={id} className="settings-choice">
                        <input
                          type="radio"
                          name="loginStyle"
                          value={id}
                          checked={loginStyle === id}
                          onChange={() => setLoginStyle(id)}
                          disabled={!canWrite}
                          title={disabledReason}
                        />
                        <span className="settings-choice-text">
                          <span className="settings-choice-name">{meta?.name ?? id}</span>
                          {meta && <span className="settings-choice-desc">{meta.desc}</span>}
                        </span>
                      </label>
                    )
                  })}
                </fieldset>

              </form>
            </div>
          )}

          {activeSection === 'appearance' && (
            <div className="settings-section card settings-panel" role="tabpanel">
              <form onSubmit={submit} onChange={() => markDirty('appearance')}>
                <PanelHead
                  title="Primary colour"
                  lede="The accent colour used for buttons, links and the active nav item, everywhere in the app."
                  help="Applies to this admin's own screen immediately on save; every other signed-in user picks it up from their next page load — this is an install-wide choice, not a per-person preference. Each preset is pre-checked for contrast in both light and dark mode; there is no free-form colour picker because an uncalibrated choice could fail to read against its own text."
                />
                <div className="settings-swatch-row" role="radiogroup" aria-label="Colour">
                  {data.appearance.primaryColorOptions.map((id) => {
                    const name = id.charAt(0).toUpperCase() + id.slice(1)
                    return (
                      <label key={id} className="settings-swatch" title={canWrite ? name : disabledReason}>
                        <input
                          type="radio"
                          name="primaryColorId"
                          value={id}
                          checked={primaryColorId === id}
                          onChange={() => setPrimaryColorId(id)}
                          disabled={!canWrite}
                          aria-label={name}
                        />
                        {/* data-accent scopes --accent to this one swatch via
                            index.css's preset blocks, so it always shows the
                            preset's real rendered colour in the CURRENT
                            theme — see .settings-color-swatch's own comment.
                            The selected state is a structural ring (CSS, on
                            :checked), never colour alone, and the name is
                            also printed as text below the row. */}
                        <span className="settings-color-swatch" data-accent={id} aria-hidden="true" />
                      </label>
                    )
                  })}
                </div>
                <p className="field-hint">
                  {primaryColorId.charAt(0).toUpperCase() + primaryColorId.slice(1)}
                  {primaryColorId === 'teal' && ' (default)'}
                  {PRIMARY_COLOR_DESCRIPTIONS[primaryColorId] && ` — ${PRIMARY_COLOR_DESCRIPTIONS[primaryColorId]}`}
                </p>
              </form>
            </div>
          )}

          {activeSection === 'appearance' && (
            <div className="settings-section card settings-panel" role="tabpanel">
              <form onSubmit={submit} onChange={() => markDirty('appearance')}>
                <PanelHead
                  title="Overview default window"
                  lede="The time window the Overview page's incident chart opens to."
                  help="Anyone can still switch between 14 and 30 days once on the page — this only decides which one it starts on."
                />
                <Segmented
                  label="Overview default window"
                  options={[{ id: '14', label: '14 days' }, { id: '30', label: '30 days' }]}
                  value={String(overviewDefaultWindowDays) as '14' | '30'}
                  onChange={(v) => {
                    // Segmented renders <button onClick>, not a form input —
                    // a button click never fires a native `change` event, so
                    // this form's own onChange={() => markDirty('appearance')}
                    // (which every native <input>/<select> field on this page
                    // relies on to bubble up) never sees it. Marking dirty
                    // explicitly here is what makes Save actually light up.
                    setOverviewDefaultWindowDays(Number(v) as 14 | 30)
                    markDirty('appearance')
                  }}
                  disabled={!canWrite}
                  disabledReason={disabledReason}
                />
              </form>
            </div>
          )}

          {/* Only on sections the page-level form actually backs — see `form` on
              SETTINGS_SECTIONS. Read-only catalogues (Roles & access) and
              collections whose items each save through their own dialog (AI
              providers, Git repositories) get no bar, because it would be a Save
              button with nothing to save. Git repositories used to get one: the
              old inline check named only two exceptions and missed it. */}
          {SETTINGS_SECTIONS.find((section) => section.id === activeSection)?.form && (
            <div className="settings-save-bar" role="region" aria-label="Save settings">
              <div className="settings-save-status" aria-live="polite">
                {mutationFeedback}
                {!mutation.isError && !mutation.isSuccess && (
                  <span className={hasUnsavedChanges ? 'settings-dirty' : 'field-hint'}>
                    {hasUnsavedChanges ? 'Unsaved changes' : 'No unsaved changes'}
                  </span>
                )}
              </div>
              <button
                type="button"
                className="button-with-icon"
                onClick={() => mutation.mutate()}
                disabled={!canWrite || !hasUnsavedChanges || mutation.isPending}
                title={disabledReason}
              >
                <SaveIcon />
                {mutation.isPending ? 'Saving…' : 'Save settings'}
              </button>
            </div>
          )}
          </div>
        </div>
        )
      })()}
    </div>
  )
}
