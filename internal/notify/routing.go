// This file is PROJECT.md F32: the one global webhook becomes a routing
// table. Until it existed, notifier.go resolved exactly one URL per tick
// (internal/settings.Resolve) and every notification for every cluster, every
// severity and every transition went to it. At the 200+ cluster target that is
// one channel receiving everything, which in practice gets muted — and a muted
// channel is worse than none, because everyone believes they are covered.
//
// What this adds is ROUTING, deliberately and only: rules that match on
// cluster group, severity and transition, and select which configured
// destination a notification goes to. It adds no second transport. Email,
// PagerDuty and Opsgenie are named in F32 as absent and stay absent; a
// destination is still a URL that notifier.go POSTs the same Slack-shaped
// {"text": …} body to, and migration 000121's `kind` CHECK lists 'webhook'
// alone so that a destination nothing can deliver to cannot be stored.
// Interactive approval callbacks are explicitly out of scope — a chat callback
// is a claim, not an authorisation (lld/01-threat-model.md, and this
// repository's non-negotiable 7).
//
// # The default rule, and why upgrading changes nothing
//
// F32's acceptance is that the existing single URL becomes the default rule so
// that no deployment changes behaviour on upgrade. That rule is SYNTHETIC: it
// is appended by LoadRouting, not stored by migration 000121, and its
// destination is whatever internal/settings.Resolve says the effective webhook
// URL is on this tick — org_settings.notify_webhook_url, or the
// ARGUS_NOTIFY_WEBHOOK_URL environment variable when that column is null.
//
// A migration cannot read an environment variable, so seeding the default as a
// real row would have silently dropped every deployment that configures the
// webhook by env var alone: exactly the deployments that would then "change
// behaviour on upgrade". Keeping it synthetic also keeps the existing
// live-editability — a URL changed through PUT /api/v1/admin/settings still
// takes effect on the very next 30-second tick, because the default rule is
// rebuilt from that value every time.
//
// So an install that has never configured a rule has a routing table of
// exactly one rule, matching everything, pointing at the URL it already used.
//
// # The default rule is UNCONDITIONAL and always last
//
// Every notification matches at least the default rule. That is a property, not
// an accident, and it is what stops a routing table from becoming a way to lose
// notifications: there is no "matched nothing, so dropped" path, because
// "matched nothing" cannot happen. This package exists because "nobody saw it"
// is a product failure (DESIGN.md §13.3), so a notification that reaches a
// channel the operator no longer reads is a smaller error than one that reaches
// nowhere and is never retried.
//
// The cost is that pure filtering — "only tell me about high-severity
// Reopened, discard the rest" — is not expressible. It is not in F32's
// acceptance, and adding it means adding a way to silently drop an incident
// notification, which is a decision with an owner, not a detail.
//
// # First match wins, rather than fan-out to every matching rule
//
// Rules are evaluated in (priority, id) order and the FIRST match selects the
// destination. The alternative — every matching rule fires — was rejected
// because of what F32 is actually about: with fan-out, the fleet-wide default
// still receives every notification no matter how many team rules exist, so the
// firehose channel stays a firehose and stays muted. First-match-wins is what
// lets traffic MOVE off it: a rule naming the platform group wins over the
// default, and the default then sees only what no team claimed.
//
// The honest cost is the mirror image: a central channel that wants a copy of
// everything cannot have one. That is the trade F32's problem statement asks
// for, and it is reversible — a `continue` flag on a rule would add fan-out
// later without changing any of the matching below.
package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"argus/internal/domain"
)

// DestinationKindWebhook is the only destination kind, matching migration
// 000121's CHECK constraint on integrations.kind. Both exist: the constant so
// Go code never spells the string inline, the CHECK so a direct SQL edit cannot
// store a kind no transport implements.
const DestinationKindWebhook = "webhook"

// TransitionNewIncident is the transition token for the "a new incident
// happened" queue (incidents.notified_at, migration 000017), which is not a
// state transition at all and therefore has no state name to derive one from.
//
// Deliberately NOT "Detected", even though a brand-new incident's state
// usually is Detected: an incident that re-enters Detected later would then be
// indistinguishable from a first sighting, and the two queues are separate
// precisely because "this is the first anyone has heard of it" is a different
// operator event from "its state changed".
const TransitionNewIncident = "NewIncident"

// KnownTransitions is every transition token a rule may name, in the order the
// admin UI should list them: the new-incident queue first, then the state
// transitions alphabetically.
//
// This list is a VALIDATION aid, not the matcher's authority. The authority is
// internal/orchestrator's notifiableStates (the states SetState queues a
// notification for) plus the fixed key prefixes its escalation sweepers use
// ("AwaitingApproval:Stale…" from approvalwatch.go, "AwaitingMerge:StalePR…"
// from mergewatch.go). That package imports this one, so this one cannot import
// it back to derive the list — hence a second copy, and hence this comment
// saying where the first one is.
//
// The drift this could cause is bounded in the safe direction on purpose:
//
//   - A token that exists in orchestrator but is missing here is REJECTED at
//     configure time, so an operator cannot write a rule for it until this list
//     is updated. Meanwhile every such notification still matches the default
//     rule and is delivered. A visible, one-line gap.
//   - Match() never consults this list. It compares strings, so a token stored
//     before this list changed keeps behaving exactly as it did.
//
// The opposite arrangement — no validation, free-text tokens — was rejected
// because a typo would store cleanly and produce a rule that looks configured
// and is permanently dead, which is the failure mode this codebase already has
// a lesson about (a fabricated zero looks like a fact).
var KnownTransitions = []string{
	TransitionNewIncident,
	"AwaitingApproval",
	"AwaitingMerge",
	"ExecutionUnknown",
	"Failed",
	"Reopened",
	"ValidationUnknown",
}

// Severities is the severity ladder, weakest first — the same closed set
// internal/api/incidents.go's severityOrder and internal/tunnel's Finding
// documentation carry, and the same four values migration 000121's CHECK on
// notification_routes.min_severity pins.
var Severities = []string{"low", "medium", "high", "critical"}

// severityRank returns a severity's position on the ladder, or -1 for a value
// that is not on it.
//
// An unrecognised severity ranking below everything is the fail-open direction
// and is chosen: such a notification matches no min_severity rule, falls
// through to the default rule, and is still delivered. Ranking it at the top
// instead would route an unparseable value to whichever team claimed
// "critical", which is a worse kind of wrong than "it went to the default
// channel".
func severityRank(severity string) int {
	for i, s := range Severities {
		if s == severity {
			return i
		}
	}
	return -1
}

// TransitionOf derives a rule-matchable transition token from an
// incident_notifications.notify_key.
//
// The stored keys have two shapes, both of which begin with the state name and
// then add something that must NOT take part in matching:
//
//	"Reopened@2026-09-25T12:00:00.123456789Z"  (orchestrator.SetState — the
//	                                            instant suffix that makes a
//	                                            second entry into a state a
//	                                            distinct event)
//	"AwaitingMerge:StalePR:48h"                (mergewatch.go's escalation
//	"AwaitingApproval:Stale:96d"                and approvalwatch.go's, where
//	                                            the tier suffix is what lets a
//	                                            long-open condition re-notify)
//
// So the token is everything before the first '@' or ':'. A key with neither is
// returned whole, which is the right fallback: an unrecognised shape matches no
// transition-scoped rule and falls through to the default rule, rather than
// being silently attributed to some state it never named.
func TransitionOf(notifyKey string) string {
	cut := len(notifyKey)
	if i := strings.IndexAny(notifyKey, "@:"); i >= 0 {
		cut = i
	}
	return notifyKey[:cut]
}

// Destination is one configured place a notification can be sent.
//
// URL is a secret in the same sense org_settings.notify_webhook_url is — a
// Slack incoming-webhook URL embeds a bearer-equivalent token in its path — so
// it is never rendered into an API response, a log line or a notification
// payload. Migration 000121 says the same thing about the column.
type Destination struct {
	ID   string
	Name string
	Kind string
	URL  string
}

// DefaultDestinationID is the id carried by the synthetic default rule's
// destination. It is not an `itg_` ULID and names no row in `integrations`,
// which is the point: nothing can reference it, edit it or delete it through
// the routing API, because it is not configuration — it is whatever
// internal/settings resolved this tick.
const DefaultDestinationID = "default"

// DefaultRuleID is the synthetic default rule's id, on the same footing as
// DefaultDestinationID.
const DefaultRuleID = "default"

// Rule is one row of the routing table. An empty ClusterGroupID, MinSeverity or
// Transition means that dimension is not matched on — the three are ANDed, so a
// rule with all three empty matches everything (which is exactly what the
// synthetic default rule is).
type Rule struct {
	ID       string
	Name     string
	Priority int

	ClusterGroupID string
	// ClusterGroupName is carried for the admin API's benefit only; matching
	// never reads it. Populated by LoadRouting's LEFT JOIN so the API does not
	// need a second query to render a rule.
	ClusterGroupName string

	// MinSeverity matches this severity AND ANYTHING ABOVE IT on the ladder —
	// see migration 000121 for why a minimum rather than an equality matcher.
	MinSeverity string
	Transition  string

	Destination Destination
	Enabled     bool
}

// IsDefault reports whether this is the synthetic default rule rather than a
// stored one. The admin API uses it to render the default distinctly and to
// refuse edits to it.
func (r Rule) IsDefault() bool { return r.ID == DefaultRuleID }

// Notification is what one queued notification offers the routing table to
// match on.
type Notification struct {
	ClusterID string
	Severity  string
	// Transition is a token from TransitionOf, or TransitionNewIncident for the
	// new-incident queue.
	Transition string
}

// RoutingTable is one tick's resolved routing configuration: the stored rules
// in evaluation order, the synthetic default rule last, and the cluster-group
// memberships needed to evaluate them.
//
// Resolved fresh every sweep tick alongside the webhook URL (see
// WebhookNotifier.resolveSettings), so a rule added through the admin API takes
// effect on the very next tick with no hub restart — the property the
// live-editable webhook URL already had, extended to the rules.
type RoutingTable struct {
	rules []Rule
	// destinations is every stored destination, in name order — including any
	// no rule currently points at, which is why it is a field rather than
	// something derived from rules. The admin API lists these; matching never
	// reads them (a rule carries its own resolved Destination).
	destinations []Destination
	// members maps a cluster id to the groups it belongs to. Loaded ONLY for
	// the groups some enabled rule actually names, so an install with no
	// group-scoped rules — every install immediately after upgrading — loads
	// zero rows here rather than the whole fleet's membership on every tick.
	members map[string]map[string]bool
}

// Destinations returns every stored destination in name order. The synthetic
// default rule's destination is deliberately absent: it is not configuration
// and cannot be edited or deleted through the routing API.
func (t RoutingTable) Destinations() []Destination { return t.destinations }

// Rules returns the stored rules in evaluation order, without the synthetic
// default. The admin API renders these as the editable set.
func (t RoutingTable) Rules() []Rule {
	if len(t.rules) == 0 {
		return nil
	}
	return t.rules[:len(t.rules)-1]
}

// Default returns the synthetic default rule — the last entry, always present.
func (t RoutingTable) Default() Rule {
	if len(t.rules) == 0 {
		return Rule{}
	}
	return t.rules[len(t.rules)-1]
}

// Deliverable reports whether any rule in this table has a destination with a
// URL to POST to.
//
// This is the successor to notifier.go's old `if !cfg.NotifyWebhookConfigured`
// early return and keeps its exact meaning: "nothing on this install can
// receive a notification, so this tick has nothing to do." Checked BEFORE
// anything is claimed, so an unconfigured install never stamps a claim it
// cannot honour — the same reason the old check sat where it did.
func (t RoutingTable) Deliverable() bool {
	for _, r := range t.rules {
		if r.Enabled && r.Destination.URL != "" {
			return true
		}
	}
	return false
}

// Match returns the rule that routes n — the first enabled rule, in
// (priority, id) order, whose three matchers all accept it.
//
// Always returns a rule: the synthetic default is last and matches everything.
// The bool is false only for a zero-value RoutingTable, which no caller
// constructs (LoadRouting always appends the default) and which is handled
// rather than panicking because a nil map dereference in a notification sweep
// would take the poller down with it.
func (t RoutingTable) Match(n Notification) (Rule, bool) {
	for _, r := range t.rules {
		if !r.Enabled {
			continue
		}
		if r.Transition != "" && r.Transition != n.Transition {
			continue
		}
		if r.MinSeverity != "" && severityRank(n.Severity) < severityRank(r.MinSeverity) {
			continue
		}
		if r.ClusterGroupID != "" && !t.members[n.ClusterID][r.ClusterGroupID] {
			continue
		}
		return r, true
	}
	return Rule{}, false
}

// LoadRouting reads the stored destinations, rules and the memberships those
// rules need, and appends the synthetic default rule pointing at defaultURL.
//
// tx must already be scoped (data.InFleetScope or data.InScope): all three
// tables carry tenant_id-keyed RLS, so an unscoped transaction reads zero rows
// and produces a table containing only the default rule. That degrades to
// today's behaviour rather than to silence, which is the correct direction, but
// it is not a substitute for scoping the transaction.
//
// defaultURL may be empty (no webhook configured anywhere). The default rule is
// still appended, with an empty destination URL — Deliverable is what callers
// use to decide whether there is anything to do, so that "unconfigured" is one
// question asked in one place rather than a nil check threaded through the
// sweep.
func LoadRouting(ctx context.Context, tx pgx.Tx, defaultURL string) (RoutingTable, error) {
	var table RoutingTable
	destinations := map[string]Destination{}
	rows, err := tx.Query(ctx, `SELECT id, name, kind, url FROM integrations ORDER BY name`)
	if err != nil {
		return RoutingTable{}, fmt.Errorf("notify: load notification destinations: %w", err)
	}
	for rows.Next() {
		var d Destination
		if err := rows.Scan(&d.ID, &d.Name, &d.Kind, &d.URL); err != nil {
			rows.Close()
			return RoutingTable{}, fmt.Errorf("notify: scan notification destination: %w", err)
		}
		destinations[d.ID] = d
		table.destinations = append(table.destinations, d)
	}
	if err := rows.Err(); err != nil {
		return RoutingTable{}, fmt.Errorf("notify: iterate notification destinations: %w", err)
	}

	// ORDER BY (priority, id) is the evaluation order first-match-wins depends
	// on, and it is total: id is a ULID, so two rules sharing a priority still
	// have one deterministic order rather than whichever the executor felt like
	// — the same hazard claimIncidents' own sort exists for, here solved in SQL
	// because this is a plain SELECT with no RETURNING.
	rows, err = tx.Query(ctx, `
		SELECT r.id, r.name, r.priority, COALESCE(r.cluster_group_id, ''), COALESCE(g.name, ''),
		       COALESCE(r.min_severity, ''), COALESCE(r.transition, ''), r.destination_id, r.enabled
		  FROM notification_routes r
		  LEFT JOIN cluster_groups g ON g.id = r.cluster_group_id
		 ORDER BY r.priority, r.id`)
	if err != nil {
		return RoutingTable{}, fmt.Errorf("notify: load notification rules: %w", err)
	}
	for rows.Next() {
		var r Rule
		var destinationID string
		if err := rows.Scan(&r.ID, &r.Name, &r.Priority, &r.ClusterGroupID, &r.ClusterGroupName,
			&r.MinSeverity, &r.Transition, &destinationID, &r.Enabled); err != nil {
			rows.Close()
			return RoutingTable{}, fmt.Errorf("notify: scan notification rule: %w", err)
		}
		// A destination_id with no row cannot happen — it is a foreign key with
		// ON DELETE RESTRICT — so this is not a recovery path, it is a refusal
		// to invent a destination if the constraint is ever weakened. The rule
		// is dropped from the table entirely, so traffic that would have
		// matched it falls through to the next rule and ultimately to the
		// default. Keeping it with an empty URL would be worse: it would match,
		// fail to POST, and retry forever while shadowing every rule below it.
		destination, ok := destinations[destinationID]
		if !ok {
			logger.ErrorContext(ctx, "a notification rule names a destination that does not exist; skipping the rule",
				slog.String("rule", r.Name), slog.String("destination_id", destinationID))
			continue
		}
		r.Destination = destination
		table.rules = append(table.rules, r)
	}
	if err := rows.Err(); err != nil {
		return RoutingTable{}, fmt.Errorf("notify: iterate notification rules: %w", err)
	}

	// Memberships, restricted to the groups some enabled rule names. The IN
	// subquery is evaluated by Postgres against the same RLS-scoped view, and
	// returns nothing at all on an install with no group-scoped rules — which
	// is every install until someone writes one.
	if err := loadMembers(ctx, tx, &table); err != nil {
		return RoutingTable{}, err
	}

	table.rules = append(table.rules, defaultRule(defaultURL))
	return table, nil
}

// defaultRule builds the synthetic, unconditional, always-last rule described
// in this file's doc comment.
//
// Its position carries no priority number on purpose: it is appended after the
// ORDER BY has already run, so being last is structural and no stored rule can
// tie with it or beat it by choosing a large enough integer.
func defaultRule(defaultURL string) Rule {
	return Rule{
		ID:      DefaultRuleID,
		Name:    "Default",
		Enabled: true,
		Destination: Destination{
			ID:   DefaultDestinationID,
			Name: "Default webhook",
			Kind: DestinationKindWebhook,
			URL:  defaultURL,
		},
	}
}

// loadMembers fills table.members with the cluster-group memberships the
// already-loaded rules actually match on.
func loadMembers(ctx context.Context, tx pgx.Tx, table *RoutingTable) error {
	wanted := map[string]bool{}
	for _, r := range table.rules {
		if r.Enabled && r.ClusterGroupID != "" {
			wanted[r.ClusterGroupID] = true
		}
	}
	if len(wanted) == 0 {
		return nil
	}
	ids := make([]string, 0, len(wanted))
	for id := range wanted {
		ids = append(ids, id)
	}
	rows, err := tx.Query(ctx,
		`SELECT cluster_id, cluster_group_id FROM cluster_group_members WHERE cluster_group_id = ANY($1)`, ids)
	if err != nil {
		return fmt.Errorf("notify: load cluster group membership: %w", err)
	}
	defer rows.Close()
	table.members = map[string]map[string]bool{}
	for rows.Next() {
		var clusterID, groupID string
		if err := rows.Scan(&clusterID, &groupID); err != nil {
			return fmt.Errorf("notify: scan cluster group membership: %w", err)
		}
		if table.members[clusterID] == nil {
			table.members[clusterID] = map[string]bool{}
		}
		table.members[clusterID][groupID] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("notify: iterate cluster group membership: %w", err)
	}
	return nil
}

// --- configuration ---------------------------------------------------------

// DestinationInput is one destination in a routing configuration.
//
// Identified by Name, not by id: a rule in the same request has to be able to
// reference a destination the request is creating, and the id for that is not
// minted until the INSERT runs. Migration 000121's UNIQUE (tenant_id, name)
// index is what makes the name a usable key rather than a label.
type DestinationInput struct {
	Name string
	// URL nil means "keep whatever is already stored under this name" — the
	// same shape the settings API uses for llm_api_key, and for the same
	// reason: the GET never returns a webhook URL, so an admin UI doing
	// read-modify-write does not have the value to send back and must not be
	// forced to re-type it in order to rename a destination.
	//
	// nil for a name that does not exist yet is an error, not an empty URL: a
	// destination with nowhere to POST is a rule that silently never delivers.
	URL *string
}

// RuleInput is one rule in a routing configuration. Empty ClusterGroupID,
// MinSeverity or Transition mean "match anything on this dimension".
type RuleInput struct {
	Name           string
	Priority       int
	ClusterGroupID string
	MinSeverity    string
	Transition     string
	// Destination names a DestinationInput in the SAME RoutingUpdate. A
	// destination that exists in the database but is absent from the update is
	// being deleted by it, so referencing one would be a rule pointing at
	// something the same request removes.
	Destination string
	Enabled     bool
}

// RoutingUpdate is a complete routing configuration — the whole table, not a
// patch.
//
// Whole-set replacement rather than per-row CRUD, deliberately: a routing table
// is ordered and its rows are only meaningful relative to each other, so a
// sequence of per-row edits has intermediate states in which notifications are
// genuinely mis-routed (the general rule deleted, the specific one not yet
// added). One PUT is one transaction and has no such window. It is also what
// keeps this feature's footprint to two handlers instead of ten.
type RoutingUpdate struct {
	Destinations []DestinationInput
	Rules        []RuleInput
}

// InvalidRoutingError is a rejected RoutingUpdate — a caller's mistake, not a
// failure. The API layer maps it to a 400 with this message; anything else
// ReplaceRouting returns is a 500.
type InvalidRoutingError struct{ Message string }

func (e *InvalidRoutingError) Error() string { return e.Message }

func invalid(format string, args ...any) error {
	return &InvalidRoutingError{Message: fmt.Sprintf(format, args...)}
}

// ValidateRoutingUpdate checks everything about an update that can be decided
// without the database, and is exported so the shape rules are testable without
// one. ReplaceRouting calls it first and then adds the checks that do need a
// database (does this destination already have a stored URL, does this cluster
// group exist).
func ValidateRoutingUpdate(upd RoutingUpdate) error {
	names := map[string]bool{}
	for _, d := range upd.Destinations {
		if strings.TrimSpace(d.Name) == "" {
			return invalid("every destination needs a name")
		}
		if names[d.Name] {
			return invalid("duplicate destination name %q", d.Name)
		}
		names[d.Name] = true
		if d.URL == nil {
			continue
		}
		if err := validateWebhookURL(*d.URL); err != nil {
			return invalid("destination %q: %s", d.Name, err)
		}
	}

	ruleNames := map[string]bool{}
	for _, r := range upd.Rules {
		if strings.TrimSpace(r.Name) == "" {
			return invalid("every rule needs a name")
		}
		if ruleNames[r.Name] {
			return invalid("duplicate rule name %q", r.Name)
		}
		ruleNames[r.Name] = true
		if !names[r.Destination] {
			return invalid("rule %q names destination %q, which is not in this configuration", r.Name, r.Destination)
		}
		if r.MinSeverity != "" && severityRank(r.MinSeverity) < 0 {
			return invalid("rule %q: minSeverity must be one of %s", r.Name, strings.Join(Severities, ", "))
		}
		if r.Transition != "" && !knownTransition(r.Transition) {
			return invalid("rule %q: transition must be one of %s", r.Name, strings.Join(KnownTransitions, ", "))
		}
	}
	return nil
}

func knownTransition(t string) bool {
	for _, k := range KnownTransitions {
		if k == t {
			return true
		}
	}
	return false
}

// validateWebhookURL rejects a destination URL that could never be POSTed to.
//
// Deliberately shallow. internal/outbound is what actually decides whether a
// destination may be dialled — cloud metadata is refused unconditionally there,
// and that is the control that matters (non-advertisement is not enforcement).
// This check exists so that an obvious mistake comes back as a 400 naming the
// field instead of as a delivery failure in a log line nobody is reading.
func validateWebhookURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("url must not be empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("url is not a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("url must be http or https")
	}
	if u.Host == "" {
		return fmt.Errorf("url must include a host")
	}
	return nil
}

// ReplaceRouting writes upd as the complete routing configuration for tenantID,
// in the caller's transaction.
//
// tx must already be scoped — every statement below relies on RLS to confine it
// to one tenant, and none of them carries a tenant_id predicate of its own for
// exactly that reason (writing one would make the policy look optional).
//
// Order is forced by the schema and is not rearrangeable: rules reference
// destinations with ON DELETE RESTRICT, so every rule goes before any
// destination is removed.
func ReplaceRouting(ctx context.Context, tx pgx.Tx, tenantID string, upd RoutingUpdate) error {
	if err := ValidateRoutingUpdate(upd); err != nil {
		return err
	}

	existing := map[string]string{} // name -> id
	stored := map[string]bool{}     // name -> has a stored URL
	rows, err := tx.Query(ctx, `SELECT id, name, url FROM integrations`)
	if err != nil {
		return fmt.Errorf("notify: read existing notification destinations: %w", err)
	}
	for rows.Next() {
		var id, name, storedURL string
		if err := rows.Scan(&id, &name, &storedURL); err != nil {
			rows.Close()
			return fmt.Errorf("notify: scan existing notification destination: %w", err)
		}
		existing[name] = id
		stored[name] = storedURL != ""
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("notify: iterate existing notification destinations: %w", err)
	}

	// Every rule is replaced, so ids are not preserved across a PUT. That is
	// deliberate: a rule has no identity of its own beyond its position and its
	// matchers, nothing references one, and the audited event is the
	// configuration change as a whole (internal/api records it), not a row's
	// history.
	if _, err := tx.Exec(ctx, `DELETE FROM notification_routes`); err != nil {
		return fmt.Errorf("notify: clear notification rules: %w", err)
	}

	keep := make([]string, 0, len(upd.Destinations))
	byName := map[string]string{}
	for _, d := range upd.Destinations {
		id, ok := existing[d.Name]
		switch {
		case ok:
			if d.URL != nil {
				if _, err := tx.Exec(ctx,
					`UPDATE integrations SET url = $2, kind = $3, updated_at = now() WHERE id = $1`,
					id, *d.URL, DestinationKindWebhook); err != nil {
					return fmt.Errorf("notify: update notification destination %q: %w", d.Name, err)
				}
			} else if !stored[d.Name] {
				// Cannot happen through the API today (a destination is only
				// ever created with a URL), but a stored empty URL would make
				// every rule pointing at it fail delivery forever, so it is
				// refused rather than carried forward silently.
				return invalid("destination %q has no stored url; send one", d.Name)
			}
		case d.URL == nil:
			return invalid("destination %q is new, so it needs a url", d.Name)
		default:
			id = domain.NewID(domain.PrefixIntegration)
			if _, err := tx.Exec(ctx,
				`INSERT INTO integrations (id, tenant_id, kind, name, url) VALUES ($1, $2, $3, $4, $5)`,
				id, tenantID, DestinationKindWebhook, d.Name, *d.URL); err != nil {
				return fmt.Errorf("notify: create notification destination %q: %w", d.Name, err)
			}
		}
		keep = append(keep, id)
		byName[d.Name] = id
	}

	// Destinations absent from the update are removed. Safe at this point
	// because every rule was deleted above and the new ones are not inserted
	// until below, so nothing references them; the ON DELETE RESTRICT foreign
	// key is still what enforces that, rather than this ordering being trusted.
	if _, err := tx.Exec(ctx, `DELETE FROM integrations WHERE NOT (id = ANY($1))`, keep); err != nil {
		return fmt.Errorf("notify: remove notification destinations: %w", err)
	}

	for _, r := range upd.Rules {
		if _, err := tx.Exec(ctx, `
			INSERT INTO notification_routes
			       (id, tenant_id, name, priority, cluster_group_id, min_severity, transition, destination_id, enabled)
			VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''), $8, $9)`,
			domain.NewID(domain.PrefixNotificationRoute), tenantID, r.Name, r.Priority,
			r.ClusterGroupID, r.MinSeverity, r.Transition, byName[r.Destination], r.Enabled); err != nil {
			// A cluster group id that names nothing is the one foreign-key
			// failure a caller can cause here, and it is a request error rather
			// than a server fault, so it is reported as one. Detected by
			// attempting the insert rather than by a prior SELECT, so the
			// answer cannot change between the check and the write — and
			// narrowed to the actual constraint, so a genuine database fault
			// is not laundered into a 400 that blames the operator.
			// "23503" is foreign_key_violation, spelled as a literal for the
			// same reason internal/api/enroll.go's isUniqueViolation spells
			// 23505 that way: github.com/jackc/pgerrcode is not a direct
			// dependency of this module.
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23503" &&
				strings.Contains(pgErr.ConstraintName, "cluster_group_id") {
				return invalid("rule %q names cluster group %q, which does not exist", r.Name, r.ClusterGroupID)
			}
			return fmt.Errorf("notify: create notification rule %q: %w", r.Name, err)
		}
	}
	return nil
}

// SortRulesForDisplay orders rules the way the routing table evaluates them, for
// a caller that has built a slice rather than read one back from LoadRouting.
// Kept here so the ordering rule — (priority, id), total and deterministic —
// has exactly one definition in Go as well as one in SQL.
func SortRulesForDisplay(rules []Rule) {
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority < rules[j].Priority
		}
		return rules[i].ID < rules[j].ID
	})
}
