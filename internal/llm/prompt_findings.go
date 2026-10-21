package llm

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// BuildFindingsPrompt renders an incident's findings into the user prompt the
// investigation runs on — BOUNDED, which is the entire point of this file.
//
// # The bug this replaces
//
// Two copies of this loop existed (internal/api/analyze.go's handler and
// internal/autoanalyze's buildUserPrompt), both running
// `SELECT ... FROM findings WHERE incident_id = $1` with NO LIMIT and
// concatenating one line per row. Found live on inc_01m0xfwwjjgk1hexrsnqc00m7e:
// 2405 finding rows produced an 824,647-byte prompt, and every re-analyze
// returned 502 "Could not complete the AI investigation" for a reason nothing
// surfaced:
//
//	fork/exec /usr/local/bin/claude: argument list too long
//
// cmd/cli-runner passes the prompt as a single argv element ("-p", UserPrompt).
// Linux caps ONE argument at MAX_ARG_STRLEN — 32 pages, 131,072 bytes — quite
// separately from the ~2MB total ARG_MAX, so a prompt past 128 KiB fails on exec
// no matter how much room the rest of the command line has. That incident's
// prompt was 6.3x over.
//
// It is not an edge case and it does not heal: findings only accumulate, so
// every long-lived incident crosses the line and is then PERMANENTLY
// un-analysable. Measured across the dev fleet at the time of the fix: 8 of 444
// incidents already over, 11 more past half. At ~343 bytes a line the threshold
// is roughly 380 findings.
//
// # Why a per-reason cap rather than only a total byte cap
//
// A byte cap alone would truncate mid-history and hand the model whatever
// happened to be newest — which on this incident is 2000 repetitions of one
// message. Capping per REASON keeps one example of every distinct thing that is
// wrong, which is the signal, and drops the repetition, which is not. That is
// the same reasoning (and the same bound) internal/api's incident detail already
// applies to what it returns to the browser.
//
// The total byte cap stays as a backstop, because "few reasons" is not something
// this function can promise: an incident with hundreds of distinct reasons would
// still blow past exec's limit with a per-reason cap alone. Belt and braces, and
// the guarantee is then explicit rather than emergent.
//
// # Honesty
//
// Every omission is stated in the prompt itself, with the true totals. The model
// is told "showing 20 of 2364" rather than being handed 20 lines that look like
// the whole history — the same rule the UI follows for a capped list, applied
// here because a model reasoning from a silently truncated history will state
// conclusions about a fault volume it was never shown.
const (
	// maxFindingsPerReason bounds the repetition. 20 is generous for
	// establishing a pattern and small enough that even a pathological reason
	// count stays inside the total cap below.
	maxFindingsPerReason = 20
	// maxFindingsPromptBytes is the hard backstop, well under the 131,072-byte
	// exec limit so the rest of the prompt (system prompt is passed separately;
	// this is the user prompt's own header plus these lines) cannot push it
	// over.
	maxFindingsPromptBytes = 48 << 10
)

// FindingsPromptHeader is the caller-supplied preamble — the two callers word
// their incident header slightly differently (cluster display name vs cluster
// id) and neither should be forced to change to share the bounded part.
type FindingsPromptHeader = string

// BuildFindingsPrompt appends the bounded findings section to header and returns
// the complete user prompt.
func BuildFindingsPrompt(ctx context.Context, tx pgx.Tx, incidentID string, header FindingsPromptHeader) (string, error) {
	// ORDER BY occurred_at DESC is kept from both originals so "newest first"
	// still holds within each reason; the per-reason counter below is what
	// bounds it. The COUNT comes from the same scan rather than a second query,
	// so the totals reported cannot disagree with what was shown.
	rows, err := tx.Query(ctx,
		`SELECT detector_id, gvk, namespace, object_name, reason, message, severity, occurrence_count
		   FROM findings WHERE incident_id = $1 ORDER BY occurred_at DESC`, incidentID)
	if err != nil {
		return "", fmt.Errorf("query findings for incident %s: %w", incidentID, err)
	}
	defer rows.Close()

	var b strings.Builder
	b.WriteString(header)

	shownPerReason := map[string]int{}
	totalPerReason := map[string]int{}
	var reasonOrder []string
	var shown, total, droppedForBytes int
	capped := false

	for rows.Next() {
		var detectorID, gvk, severity string
		var namespace, objectName, reason, message *string
		var occurrenceCount int
		if err := rows.Scan(&detectorID, &gvk, &namespace, &objectName, &reason, &message, &severity, &occurrenceCount); err != nil {
			return "", fmt.Errorf("scan finding for incident %s: %w", incidentID, err)
		}
		total++
		key := derefString(reason)
		if _, seen := totalPerReason[key]; !seen {
			reasonOrder = append(reasonOrder, key)
		}
		totalPerReason[key]++

		if shownPerReason[key] >= maxFindingsPerReason {
			capped = true
			continue
		}
		line := fmt.Sprintf("- [%s] %s/%s reason=%q message=%q (detector=%s, x%d)\n",
			severity, gvk, derefString(namespace)+"/"+derefString(objectName), key, derefString(message), detectorID, occurrenceCount)
		if b.Len()+len(line) > maxFindingsPromptBytes {
			// The backstop. Counted and reported rather than silently stopping,
			// so the prompt never implies it showed everything.
			droppedForBytes++
			capped = true
			continue
		}
		b.WriteString(line)
		shownPerReason[key]++
		shown++
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("iterate findings for incident %s: %w", incidentID, err)
	}

	if capped {
		fmt.Fprintf(&b, "\nShowing %d of %d findings — at most %d per reason, newest first. Per-reason totals:\n",
			shown, total, maxFindingsPerReason)
		for _, key := range reasonOrder {
			label := key
			if label == "" {
				label = "(no reason recorded)"
			}
			fmt.Fprintf(&b, "- %s: %d total\n", label, totalPerReason[key])
		}
		if droppedForBytes > 0 {
			fmt.Fprintf(&b, "A further %d finding(s) were omitted to keep this prompt within its size budget.\n", droppedForBytes)
		}
		b.WriteString("Reason for the cap: the repetition carries no extra signal, and an unbounded list of findings previously made long-lived incidents impossible to investigate at all. Treat the per-reason totals above as the real volume.\n")
	}
	return b.String(), nil
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
