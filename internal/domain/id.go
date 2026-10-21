// Package domain holds shared types used across hub services.
package domain

import (
	"crypto/rand"
	"strings"

	"github.com/oklog/ulid/v2"
)

// NewID generates a prefixed ULID, formalizing the convention already implicit in
// the HLD's own JSON examples ("inc_01J...", "cl_...", "plan_...") — see
// lld/05-data-model.md §2. ULIDs sort lexicographically by creation time, so
// ORDER BY id is a free proxy for ORDER BY created_at on every table.
func NewID(prefix string) string {
	id := ulid.MustNew(ulid.Now(), rand.Reader)
	return prefix + "_" + strings.ToLower(id.String())
}

// ID prefixes, per lld/05-data-model.md §2.
const (
	PrefixOrganisation     = "org"
	PrefixUser             = "usr"
	PrefixIdentity         = "idn"
	PrefixServicePrincipal = "svc"
	PrefixGrant            = "grt"
	PrefixIdentityMapping  = "idm"
	PrefixCluster          = "cl"
	PrefixClusterGroup     = "clg"
	PrefixLocalGuardrailSS = "lgs"
	PrefixPolicy           = "pol"
	PrefixPolicyVersion    = "polv"
	PrefixFinding          = "fnd"
	PrefixIncident         = "inc"
	PrefixAnalysis         = "an"
	PrefixEvidence         = "ev"
	// PrefixResourceChange / PrefixResourceChangeGap: resource_changes rows
	// (docs/CLUSTER_INSIGHT_SPECS.md CI-S2).
	PrefixResourceChange    = "chg"
	PrefixResourceChangeGap = "chgap"
	// PrefixUpgradeScan: upgrade_scans rows (CI-S5).
	PrefixUpgradeScan       = "ups"
	PrefixTimelineEvent     = "tle"
	PrefixPlan              = "plan"
	PrefixPlanAction        = "pla"
	PrefixApproval          = "appr"
	PrefixExecution         = "exec"
	PrefixActionResult      = "ar"
	PrefixPullRequest       = "pr"
	PrefixValidation        = "val"
	PrefixRepositoryBinding = "rp"
	// PrefixAutomationWindow is a maintenance or freeze window (migration
	// 000051). One prefix for both kinds: they are the same kind of object with
	// opposite effects, and a reader who has the id already has the row.
	PrefixAutomationWindow  = "awin"
	PrefixIntegration       = "itg"
	PrefixNotificationRoute = "nr"
	PrefixAuditEvent        = "aud"
	PrefixTokenUsage        = "tok"
	// PrefixFleetGroup was not in lld/05-data-model.md §2's original table —
	// incidents.fleet_group_id (migration 000005) predates any code that
	// actually wrote it. Added here the same shape as every other prefix in
	// this list the day internal/fleetgroup.Recompute became the first thing
	// to generate one, per that package's own doc comment.
	PrefixFleetGroup = "fgrp"

	// PrefixAIProvider is also not in lld/05-data-model.md §2's table — that
	// document predates the AI provider being a first-class configurable
	// object at all (it was a set of columns on org_settings until migration
	// 000034 made several of them coexist).
	PrefixAIProvider = "aip"

	// PrefixEncryptedSecret is not in lld/05-data-model.md §2's table either:
	// that document predates ARGUS storing any secret under envelope encryption
	// at all. Migration 000045 introduced encrypted_secrets when
	// REMEDIATION_ROADMAP.md D-R9 settled that a Git token is stored encrypted
	// rather than in a plaintext column the way llm_api_key still is.
	PrefixEncryptedSecret = "sec"

	// PrefixMCPToolCall likewise postdates lld/05-data-model.md §2: that
	// document predates the MCP boundary existing at all (ADR-17), so it has
	// no row for "one tool call a CLI-driven investigation made back through
	// the hub." Migration 000037's table is the first thing to need one.
	PrefixMCPToolCall = "mtc"

	// PrefixMCPToolCallContent is migration 000099's own row prefix
	// (PROJECT.md B151) — deliberately distinct from PrefixMCPToolCall
	// rather than reused, even though the two tables are siblings, so a
	// grep or a log line can never confuse a content row's id for a
	// count-only mcp_tool_calls row's id.
	PrefixMCPToolCallContent = "mtcc"

	// PrefixWorkloadGroup was not in lld/05-data-model.md §2's original
	// table either — internal/replicagroup.Recompute (migration 000042) is
	// the first thing to generate one. Mirrors PrefixFleetGroup's own
	// after-the-fact addition above, for the identical reason: a display-
	// only grouping id invented after the original schema table, not an
	// entity lld/05 ever enumerated.
	PrefixWorkloadGroup = "wgrp"

	// PrefixToleration is also not in lld/05-data-model.md §2 — that document
	// predates CapIncidentSilence having any implementation behind it.
	// Migration 000041's incident_tolerations table is the first thing to
	// need one. See BACKLOG.md A5 / internal/gateway/toleration.go for why
	// this exists: a suppression rule, scoped to one object, that stops a
	// recurring-but-accepted fault from opening new incidents at all, rather
	// than closing incidents one at a time as they reappear.
	PrefixToleration = "tol"

	// PrefixCircuitBreakerTrip is likewise absent from lld/05-data-model.md §2:
	// migration 000052's circuit_breaker_trips is the first table to need one.
	// See internal/orchestrator/breaker.go for why the trip is a persisted row
	// rather than in-memory state — a hub restart would otherwise silently
	// re-arm unattended execution after it had been deliberately stopped.
	PrefixCircuitBreakerTrip = "cbt"

	// PrefixObjectGroup is also absent from lld/05-data-model.md §2 —
	// internal/objectgroup.Recompute (migration 000070, BACKLOG.md A3b) is
	// the first thing to generate one. Mirrors PrefixFleetGroup/
	// PrefixWorkloadGroup's own after-the-fact addition: a display-only
	// grouping id joining incidents that reference each other's object
	// (a Service's selector, a Pod's volume reference) rather than sharing
	// an owner or a fingerprint.
	PrefixObjectGroup = "ogrp"

	// PrefixUnattendedBatch and PrefixUnattendedBatchMember are also absent
	// from lld/05-data-model.md §2 — migration 000073 (BACKLOG.md R3) is the
	// first thing to need them. A batch coordinates staged unattended
	// execution across the incidents sharing one fleet_group_id (internal/
	// fleetgroup) and one remediation action_type: wave 1 (a small,
	// deliberately conservative subset) executes and is watched by the
	// existing ValidationSweeper before wave 2 (the rest) is released. See
	// internal/orchestrator/batch.go for why this is a separate mechanism
	// from blastradius.go's cap rather than a replacement for it — the cap
	// refuses; this one deliberately stages.
	PrefixUnattendedBatch       = "ubatch"
	PrefixUnattendedBatchMember = "ubm"

	// PrefixCustomRole is also absent from lld/05-data-model.md §2 — migration
	// 000077 (BACKLOG.md S3) is the first thing to need one. internal/api/
	// custom_roles.go is the first thing to generate one: a tenant-defined
	// named bundle of existing capabilities, distinct from the five fixed
	// builtin role names authz.IsBuiltinRole recognises.
	PrefixCustomRole = "crole"

	// PrefixClusterGroupMember is likewise absent from lld/05-data-model.md
	// §2 — migration 000078 (BACKLOG.md S3) is the first thing to need one.
	// cluster_groups itself (migration 000002) predates any code that wrote
	// to it; this is the row recording one cluster's explicit membership in
	// one group. See that migration's own comment for why membership is an
	// explicit, audited row rather than dynamic label_selector evaluation.
	PrefixClusterGroupMember = "cgm"

	// PrefixExecutionAttempt is also absent from lld/05-data-model.md §2 —
	// migration 000093 is the first thing to need one. Deliberately its own
	// prefix rather than a reuse of PrefixExecution: an attempt and an
	// execution are different facts (one says "a cluster is about to be
	// changed", the other says "here is what the cluster did"), they live in
	// different tables, and a shared prefix would make an id alone ambiguous
	// about which of the two a reader is holding — exactly the confusion this
	// codebase's prefixed-ULID convention exists to prevent.
	PrefixExecutionAttempt = "exat"

	// PrefixIdentityProvider and PrefixIdentityGroupMapping are migration
	// 000103's (PROJECT.md S2, external identity providers). Neither is in
	// lld/05-data-model.md §2's table, which predates federated login.
	//
	// Two prefixes rather than one for the same reason PrefixExecutionAttempt
	// is not PrefixExecution: a provider and a group mapping are different
	// facts in different tables, and one of them — the mapping — is the more
	// dangerous object, since editing it re-authorises everyone in a
	// directory group at once. An id that cannot be misread as the other is
	// worth the extra constant.
	PrefixIdentityProvider     = "idp"
	PrefixIdentityGroupMapping = "idpg"

	// PrefixHelmLinkDecline is BACKLOG.md F30 decision 4's "do not re-ask"
	// memory — migration 000104's helm_link_declines, one row per
	// (cluster, release, namespace) an operator has explicitly declined a
	// discovered repository link for.
	PrefixHelmLinkDecline = "hld"

	// PrefixSpendReservation is migration 000109's spend_reservations —
	// PROJECT.md T10 / lld/01-threat-model.md SR-13's atomic
	// reserve-before-work row, one per automatic investigation that reserved
	// projected spend against the daily ceiling. See internal/api.ReserveSpend.
	PrefixSpendReservation = "spr"

	// PrefixPersonalToken is migration 000128's mcp_personal_tokens
	// (PROJECT.md AD3) — a person's own credential for the user-facing MCP
	// endpoint. The id is also embedded in the presented token
	// (argus_pat_<ulid>_<secret>) so authentication is a primary-key lookup.
	PrefixPersonalToken = "pat"
)
