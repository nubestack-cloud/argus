package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/logging"
	"argus/internal/notify"
	"argus/internal/settings"
)

// Notification routing (PROJECT.md F32) — the admin surface for the rules that
// decide WHICH destination a notification goes to. The rules themselves, their
// matching and their storage all live in internal/notify (routing.go); this
// file is only the HTTP shape, deliberately, so the package that owns the
// behaviour also owns its SQL.
//
// # Two handlers, not ten
//
// A routing table is ordered, and its rows are only meaningful relative to each
// other: "critical anywhere pages the on-call, everything else goes to the team
// channel" is one statement about three rules, not three independent facts. A
// per-row CRUD surface would have intermediate states in which notifications
// are genuinely mis-routed — the general rule deleted, the specific one not yet
// created — and there is no way for a client to avoid them. One GET and one
// whole-set PUT has no such window, because one PUT is one transaction.
//
// # What the GET never returns
//
// A destination's URL. A Slack incoming-webhook URL embeds a bearer-equivalent
// token in its path, which is why org_settings.notify_webhook_url has never
// been echoed either (migration 000018 records that reasoning, and
// handleGetSettings returns only a boolean for it). A destination is identified
// to the caller by its NAME, and `urlConfigured` is the only thing said about
// its URL — so this response is safe to render, log and screenshot.
//
// The PUT's matching affordance is DestinationInput.URL being nullable: an
// admin UI that read this response back can rename a destination or repoint a
// rule at it without having the URL to send.

// notificationDestinationResponse is one configured destination. No url field
// exists on purpose — see this file's doc comment.
type notificationDestinationResponse struct {
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	URLConfigured bool   `json:"urlConfigured"`
}

// notificationRuleResponse is one rule. The three matchers are nullable rather
// than empty-string so that "matches any severity" is visibly different from
// "matches the empty severity" in the JSON, which an empty string would not be.
type notificationRuleResponse struct {
	Name             string  `json:"name"`
	Priority         int     `json:"priority"`
	ClusterGroupID   *string `json:"clusterGroupId"`
	ClusterGroupName *string `json:"clusterGroupName"`
	MinSeverity      *string `json:"minSeverity"`
	Transition       *string `json:"transition"`
	Destination      string  `json:"destination"`
	Enabled          bool    `json:"enabled"`
}

// notificationDefaultRuleResponse describes the synthetic default rule, which
// is reported separately from `rules` because it is not editable here: it is
// whatever internal/settings resolves the webhook URL to, set through
// PUT /api/v1/admin/settings or ARGUS_NOTIFY_WEBHOOK_URL.
//
// Reported at all — rather than left implicit — because an operator looking at
// a routing table needs to see that there IS a catch-all and whether it has
// anywhere to send: a table whose default has no URL delivers nothing that no
// rule claimed, and that is exactly the state worth showing rather than
// leaving to be discovered from a log line.
type notificationDefaultRuleResponse struct {
	Name          string `json:"name"`
	URLConfigured bool   `json:"urlConfigured"`
	// Source names where the default rule's URL comes from, so the reader
	// knows which screen to go and change it on.
	Source string `json:"source"`
}

type notificationRoutingResponse struct {
	Destinations []notificationDestinationResponse `json:"destinations"`
	Rules        []notificationRuleResponse        `json:"rules"`
	DefaultRule  notificationDefaultRuleResponse   `json:"defaultRule"`
	// Transitions and Severities are the closed sets a rule may name, served
	// with the configuration so a client builds its selects from what this
	// build actually accepts rather than from a list copied into a frontend
	// that then drifts.
	Transitions []string `json:"transitions"`
	Severities  []string `json:"severities"`
}

// handleGetNotificationRouting returns the effective routing configuration.
func (s *Server) handleGetNotificationRouting(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()

	cfg, err := settings.Resolve(ctx, rc.Tx)
	if err != nil {
		logger.ErrorContext(ctx, "resolving settings for the notification routing view failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not read notification routing", "")
		return
	}
	table, err := notify.LoadRouting(ctx, rc.Tx, cfg.NotifyWebhookURL)
	if err != nil {
		logger.ErrorContext(ctx, "loading the notification routing table failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not read notification routing", "")
		return
	}

	// Built from the rules rather than from a second query, so the
	// destinations shown are exactly the ones the matcher would use.
	destinations := []notificationDestinationResponse{}
	seen := map[string]bool{}
	for _, d := range table.Destinations() {
		if seen[d.Name] {
			continue
		}
		seen[d.Name] = true
		destinations = append(destinations, notificationDestinationResponse{
			Name: d.Name, Kind: d.Kind, URLConfigured: d.URL != "",
		})
	}

	rules := []notificationRuleResponse{}
	for _, rule := range table.Rules() {
		rules = append(rules, notificationRuleResponse{
			Name:             rule.Name,
			Priority:         rule.Priority,
			ClusterGroupID:   nullableString(rule.ClusterGroupID),
			ClusterGroupName: nullableString(rule.ClusterGroupName),
			MinSeverity:      nullableString(rule.MinSeverity),
			Transition:       nullableString(rule.Transition),
			Destination:      rule.Destination.Name,
			Enabled:          rule.Enabled,
		})
	}

	writeJSON(w, http.StatusOK, notificationRoutingResponse{
		Destinations: destinations,
		Rules:        rules,
		DefaultRule: notificationDefaultRuleResponse{
			Name:          table.Default().Name,
			URLConfigured: table.Default().Destination.URL != "",
			Source:        "settings.notify.webhookUrl",
		},
		Transitions: notify.KnownTransitions,
		Severities:  notify.Severities,
	})
}

type putNotificationRoutingRequest struct {
	Destinations []struct {
		Name string `json:"name"`
		// Absent or null keeps the URL already stored under this name — see
		// notify.DestinationInput.URL for why that is the only workable shape
		// when the GET never returns one.
		URL *string `json:"url"`
	} `json:"destinations"`
	Rules []struct {
		Name           string  `json:"name"`
		Priority       int     `json:"priority"`
		ClusterGroupID *string `json:"clusterGroupId"`
		MinSeverity    *string `json:"minSeverity"`
		Transition     *string `json:"transition"`
		Destination    string  `json:"destination"`
		// Absent means enabled. A rule an operator did not say anything about
		// should be in force; the alternative default would silently disable
		// every rule written by a client that has not learned this field yet.
		Enabled *bool `json:"enabled"`
	} `json:"rules"`
}

// handlePutNotificationRouting replaces the whole routing configuration.
func (s *Server) handlePutNotificationRouting(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	var req putNotificationRoutingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}

	upd := notify.RoutingUpdate{}
	for _, d := range req.Destinations {
		upd.Destinations = append(upd.Destinations, notify.DestinationInput{Name: d.Name, URL: d.URL})
	}
	for _, rule := range req.Rules {
		enabled := true
		if rule.Enabled != nil {
			enabled = *rule.Enabled
		}
		upd.Rules = append(upd.Rules, notify.RuleInput{
			Name:           rule.Name,
			Priority:       rule.Priority,
			ClusterGroupID: derefString(rule.ClusterGroupID),
			MinSeverity:    derefString(rule.MinSeverity),
			Transition:     derefString(rule.Transition),
			Destination:    rule.Destination,
			Enabled:        enabled,
		})
	}

	ctx := r.Context()
	if err := notify.ReplaceRouting(ctx, rc.Tx, rc.TenantID, upd); err != nil {
		var invalid *notify.InvalidRoutingError
		if errors.As(err, &invalid) {
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/validation",
				"Invalid notification routing", invalid.Message)
			return
		}
		logger.ErrorContext(ctx, "replacing the notification routing configuration failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not update notification routing", "")
		return
	}

	// Counts and rule shapes, never a destination URL — the same rule
	// handlePutSettings follows for the webhook URL it records as a boolean.
	// Rule names and matchers ARE recorded: "who changed where critical
	// incidents get sent" is precisely the question an audit of this setting
	// has to answer, and none of it is secret.
	capability := authz.CapOrgSettingsWrite
	routed := make([]map[string]any, 0, len(upd.Rules))
	for _, rule := range upd.Rules {
		routed = append(routed, map[string]any{
			"name":           rule.Name,
			"priority":       rule.Priority,
			"clusterGroupId": rule.ClusterGroupID,
			"minSeverity":    rule.MinSeverity,
			"transition":     rule.Transition,
			"destination":    rule.Destination,
			"enabled":        rule.Enabled,
		})
	}
	destinationNames := make([]string, 0, len(upd.Destinations))
	for _, d := range upd.Destinations {
		destinationNames = append(destinationNames, d.Name)
	}
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		Outcome:         audit.OutcomeSuccess,
		Details: map[string]any{
			"notificationDestinations": destinationNames,
			"notificationRules":        routed,
		},
	}); err != nil {
		logger.ErrorContext(ctx, "recording the notification routing audit event failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	s.handleGetNotificationRouting(w, r, rc)
}

// nullableString renders "not set" as JSON null rather than "" — see
// notificationRuleResponse for why the distinction is worth the pointer.
func nullableString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
