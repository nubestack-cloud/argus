package gitopsinsight

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// MaxHeadlineRunes bounds one headline or cause, so an inventory of hundreds
// of applications stays well inside a tool frame even when a controller
// embeds a whole manifest in its message.
const MaxHeadlineRunes = 300

// stuckDriftReconcileWindow is how recent status.reconciledAt must be for a
// "last sync succeeded, but it's out of sync again" reading to mean Argo CD
// actively looked and still sees drift, rather than meaning the data is
// merely stale (2026-10-13 parity review, PG1). Wider than Argo's default
// three-minute reconciliation timeout, so a single missed tick does not
// flip the reading.
const stuckDriftReconcileWindow = 10 * time.Minute

// Headline is the one plain-language sentence saying why a GitOps object
// needs attention, and the suggested next steps behind it. Text is empty
// when the controller reports nothing wrong; it is never a reassurance.
type Headline struct {
	Text   string   `json:"headline,omitempty"`
	Causes []string `json:"causes,omitempty"`
	// Stuck is set when the controller has stopped retrying on its own
	// (Argo's retry budget exhausted, or Flux Stalled).
	Stuck bool `json:"stuck,omitempty"`
}

// HeadlineFor derives the headline from facts Summarize and FailureFor
// already extract: a failed or stuck sync first, then a controller error
// condition, then drift, then degraded health. Every clause names where it
// came from (the sync result, a condition, managed-object counts), so the
// sentence is a reading of the controller's own status, not a guess.
func HeadlineFor(obj *unstructured.Unstructured, s Summary, now time.Time) Headline {
	if obj == nil {
		return Headline{}
	}
	var h Headline
	switch s.Tool {
	case ToolArgoCD:
		h = argoHeadline(obj, s, now)
	case ToolFlux:
		h = fluxHeadline(s)
	}
	if s.Terminating {
		lead := "Being deleted"
		if len(s.Finalizers) > 0 {
			lead += "; waiting on finalizers " + strings.Join(s.Finalizers, ", ")
		}
		if h.Text == "" {
			h.Text = lead + "."
		} else {
			h.Text = lead + ". " + h.Text
		}
	}
	h.Text = capHeadline(h.Text)
	for i := range h.Causes {
		h.Causes[i] = capHeadline(h.Causes[i])
	}
	return h
}

func argoHeadline(obj *unstructured.Unstructured, s Summary, now time.Time) Headline {
	if f := FailureFor(obj); f != nil {
		h := Headline{Text: "The last sync failed", Stuck: f.Stuck}
		if f.Stuck && f.RetryCount > 0 {
			h.Text += fmt.Sprintf(" and Argo CD stopped retrying after %d attempts", f.RetryCount)
		}
		if msg := firstLine(s.OperationMessage); msg != "" {
			h.Text += ": " + msg
		} else {
			h.Text += "."
		}
		if f.Cause != "" {
			h.Causes = append(h.Causes, f.Cause)
		}
		return h
	}
	for _, c := range s.Conditions {
		if !strings.HasSuffix(c.Type, "Error") {
			continue
		}
		h := Headline{Text: argoConditionLead(c.Type)}
		if msg := firstLine(c.Message); msg != "" {
			h.Text += ": " + msg
		} else {
			h.Text += "."
		}
		if c.Action != "" {
			h.Causes = append(h.Causes, c.Action)
		}
		return h
	}
	if s.OperationPhase == "Running" {
		return Headline{Text: "A sync is in progress."}
	}
	if s.Sync == "OutOfSync" {
		out, names := 0, []string{}
		for _, r := range s.ManagedResources {
			if r.Status == "OutOfSync" {
				out++
				if len(names) < 3 {
					names = append(names, r.Kind+" "+r.Name)
				}
			}
		}
		// PG1 (2026-10-13 parity review): two drift shapes operators misread
		// as plain "waiting to sync." Checked in this order because Manual is
		// unambiguous regardless of the last operation's own outcome, and the
		// stuck-loop reading only means something once Manual is ruled out.
		lead, causes := "Live state differs from Git", []string(nil)
		switch {
		case s.AutoSync == "Manual":
			lead = "Drift with auto-sync off: nothing will reconcile until someone syncs"
			causes = []string{"Sync it from Argo CD, or turn on spec.syncPolicy.automated if this application should reconcile on its own going forward."}
		case s.OperationPhase == "Succeeded" && strings.HasPrefix(s.AutoSync, "Auto") && reconciledRecently(s.LastReconcile, now):
			lead = "Stuck in a drift loop: the last sync succeeded and auto-sync is on, but it is out of sync again"
			causes = []string{"Something is changing these objects after every apply — check for a mutating webhook, a second controller, or an HPA fighting spec.replicas."}
		}
		h := Headline{Text: lead}
		if out > 0 {
			h.Text += fmt.Sprintf(": %d of %d managed objects out of sync (%s)", out, s.ManagedResourcesTotal, strings.Join(names, ", "))
			if out > len(names) {
				h.Text = strings.TrimSuffix(h.Text, ")") + ", …)"
			}
		}
		h.Text += "."
		h.Causes = causes
		return h
	}
	switch s.Health {
	case "Degraded", "Missing":
		bad, names := 0, []string{}
		for _, r := range s.ManagedResources {
			if r.Health == "Degraded" || r.Health == "Missing" {
				bad++
				if len(names) < 3 {
					names = append(names, r.Kind+" "+r.Name)
				}
			}
		}
		h := Headline{Text: s.Health}
		if bad > 0 {
			h.Text += fmt.Sprintf(": %d managed %s not healthy (%s)", bad, plural(bad, "object is", "objects are"), strings.Join(names, ", "))
			if bad > len(names) {
				h.Text = strings.TrimSuffix(h.Text, ")") + ", …)"
			}
		}
		h.Text += "."
		h.Causes = append(h.Causes, "Open the unhealthy managed objects for their events and status.")
		return h
	case "Progressing":
		return Headline{Text: "Progressing: managed objects are still rolling out."}
	}
	if s.Sync == "Unknown" {
		return Headline{Text: "Sync status is unknown: Argo CD has not compared this application with Git."}
	}
	return Headline{}
}

// argoConditionLead names what an Argo error condition means for the
// application, in front of the controller's own message.
func argoConditionLead(condType string) string {
	switch condType {
	case "ComparisonError":
		return "Argo CD cannot build the desired state from Git, so whether the cluster matches it is unknown"
	case "InvalidSpecError":
		return "The Application spec is invalid"
	case "SyncError":
		return "The last sync reported an error"
	default:
		return condType
	}
}

func fluxHeadline(s Summary) Headline {
	if s.Health == "Suspended" {
		return Headline{
			Text:   "Suspended: Flux is not applying changes from the source until it is resumed.",
			Causes: []string{"Resuming is a change to spec.suspend in the source repository or via the flux CLI."},
		}
	}
	for _, c := range s.Conditions {
		if c.Type == "Stalled" && c.Status == "True" {
			h := Headline{Text: "Stalled — Flux has stopped retrying", Stuck: true}
			if c.Reason != "" {
				h.Text += " (" + c.Reason + ")"
			}
			if msg := firstLine(c.Message); msg != "" {
				h.Text += ": " + msg
			} else {
				h.Text += "."
			}
			if c.Action != "" {
				h.Causes = append(h.Causes, c.Action)
			}
			return h
		}
	}
	for _, c := range s.Conditions {
		if c.Type == "Ready" && c.Status == "False" {
			h := Headline{Text: "Not ready"}
			if c.Reason != "" {
				h.Text += " (" + c.Reason + ")"
			}
			if msg := firstLine(c.Message); msg != "" {
				h.Text += ": " + msg
			} else {
				h.Text += "."
			}
			if c.Action != "" {
				h.Causes = append(h.Causes, c.Action)
			}
			return h
		}
	}
	if s.Sync == "Reconciling" {
		return Headline{Text: "Reconciling: the controller has not yet applied the latest spec."}
	}
	if s.Health == "Degraded" {
		return Headline{Text: "Applied, but the controller reports it unhealthy.", Causes: []string{ActionForFluxReason("HealthCheckFailed")}}
	}
	return Headline{}
}

// reconciledRecently reports whether reconciledAt (RFC3339, Argo's own
// status.reconciledAt format) falls within stuckDriftReconcileWindow of now,
// in either direction — a small amount of clock skew between the agent host
// and the apiserver must not flip "actively watched" to "stale" or back. An
// unparsable or empty value is never recent: the stuck-drift-loop reading
// requires positive evidence Argo looked recently, not the absence of a
// reason to doubt it.
func reconciledRecently(reconciledAt string, now time.Time) bool {
	t, err := time.Parse(time.RFC3339, reconciledAt)
	if err != nil {
		return false
	}
	d := now.Sub(t)
	if d < 0 {
		d = -d
	}
	return d <= stuckDriftReconcileWindow
}

// firstLine keeps a message's first line; controllers sometimes append a
// whole rendered diff below it.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}

func capHeadline(s string) string {
	if utf8.RuneCountInString(s) <= MaxHeadlineRunes {
		return s
	}
	r := []rune(s)
	return string(r[:MaxHeadlineRunes]) + "…"
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
