package orchestrator

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Maintenance and freeze windows: automatic remediation gated by time.
//
// DESIGN.md §7.2 specifies both, §9.4's autonomy predicate includes
// `now ∈ policy.maintenanceWindows AND now ∉ freezeWindows`, and §10.5 lists them
// among the things that must exist before automatic mode. Unattended execution
// shipped without them (WORKLOG §139), so until now a change freeze or a release
// window was invisible to the sweeper — the Settings warning said so, which was
// honest but not a substitute.
//
// # Why there is no cron library here
//
// The obvious move is to pull in a cron package and ask it for the next firing
// time. This code needs a different and much smaller answer: **is now inside a
// window?** With DESIGN.md's schedule-plus-duration model (a bare cron denotes an
// instant, not a window — Argo CD's sync-window model, which §11.6 says this must
// interoperate with, uses the same pair for the same reason), that question is
//
//	∃ firing F such that F ≤ now < F + duration
//
// and since duration is bounded, the only candidate firings are the minutes in
// [now-duration, now]. So this is a field-MATCHING problem — "does this cron
// expression match this minute?" — not a scheduling one. Matching needs no
// next-fire arithmetic, which is where cron implementations get DST and
// month-length edge cases wrong.
//
// Daylight saving is handled by construction rather than by care: the walk is
// over UTC instants, and each candidate is converted into the window's own
// location before its fields are tested. A "0 9 * * 1-5" window opens at 9am
// local on both sides of a DST boundary because that is what the fields say about
// the local time, and no arithmetic is done on local times at all.
//
// Cost is trivial and worth stating so nobody optimises it: one minute per
// candidate, so an 8-hour window is 480 field tests and a 72-hour freeze is 4320,
// once per sweep.

// WindowKind is which of the two lists a window belongs to. They are not
// symmetric — see CheckWindows.
type WindowKind string

const (
	// WindowMaintenance permits automation while it is open. DESIGN.md §7.2:
	// "automatic mode only inside these".
	WindowMaintenance WindowKind = "maintenance"
	// WindowFreeze forbids automation while it is open. DESIGN.md §7.2:
	// "nothing automatic, ever".
	WindowFreeze WindowKind = "freeze"
)

// Window is one configured window.
type Window struct {
	ID   string
	Kind WindowKind
	// Schedule is a 5-field cron expression naming the window's START.
	Schedule string
	Duration time.Duration
	// Timezone is an IANA name. Empty means UTC, which is stated rather than
	// defaulted silently: a window whose timezone was lost would open at the
	// wrong time of day, and being explicit is what makes that visible.
	Timezone string
	// Reason is why this window exists, shown wherever the window blocks
	// something. Required for a freeze in practice — "nothing automatic happened
	// and nobody said why" is the failure mode that makes an operator distrust
	// the whole feature.
	Reason string
}

// WindowDecision is whether automation may run now, and which window decided.
type WindowDecision struct {
	Allowed bool
	// Reason is written for a human and is what gets recorded on the incident.
	Reason string
	// BlockedBy names the freeze window that closed the door, when one did. Empty
	// when a missing maintenance window is the cause, since there is then no
	// specific window to point at.
	BlockedBy string
}

// CheckWindows applies DESIGN.md §9.4's time predicate.
//
// # The two lists are deliberately not symmetric, and this is the decision worth
// # reading
//
// A **freeze** window is purely restrictive: if any freeze is open, nothing
// automatic runs, whatever else is configured. Adding one can only ever make the
// system safer, so it needs no default and no interaction with anything else.
//
// A **maintenance** window is a permission, and that creates a null-semantics
// question with a genuinely bad wrong answer. Read literally, "automatic mode
// only inside these" means an empty list forbids everything. That reading would
// take every installation that currently runs unattended execution and silently
// stop it on upgrade — the worst class of change, because nothing fails, work
// just quietly stops happening.
//
// So an empty maintenance list means **no time restriction**, and the settings UI
// says exactly that rather than leaving it to be discovered. The asymmetry is
// defensible on its own terms too: a maintenance window is an opt-in restriction
// an operator adds when they want one, while a freeze is a prohibition that must
// bite the moment it exists. Note this differs from the blast-radius caps, where
// a blank field falls back to a conservative default rather than to "unlimited" —
// there, a default number is meaningful; here, a default *schedule* would be
// invented policy.
func CheckWindows(now time.Time, windows []Window) WindowDecision {
	// Freeze first. It wins outright, so evaluating it first means a freeze
	// inside a maintenance window behaves the way both names imply.
	for _, w := range windows {
		if w.Kind != WindowFreeze {
			continue
		}
		open, err := w.IsOpen(now)
		if err != nil {
			// A window that cannot be evaluated is treated as OPEN, which for a
			// freeze means "block". Failing closed is the only safe reading: a
			// malformed freeze window must not become a window in which anything
			// is permitted, and the operator gets a reason naming the window.
			return WindowDecision{
				Reason:    fmt.Sprintf("freeze window %s could not be evaluated (%v), and a freeze that cannot be read is treated as in force", w.ID, err),
				BlockedBy: w.ID,
			}
		}
		if open {
			reason := w.Reason
			if reason == "" {
				reason = "no reason recorded"
			}
			return WindowDecision{
				Reason:    fmt.Sprintf("a change freeze is in force (%s), so nothing runs automatically until it ends", reason),
				BlockedBy: w.ID,
			}
		}
	}

	var maintenance []Window
	for _, w := range windows {
		if w.Kind == WindowMaintenance {
			maintenance = append(maintenance, w)
		}
	}
	if len(maintenance) == 0 {
		return WindowDecision{Allowed: true, Reason: "no maintenance windows are configured, so automation is not restricted by time"}
	}
	for _, w := range maintenance {
		open, err := w.IsOpen(now)
		if err != nil {
			// The mirror image of the freeze case: a maintenance window that
			// cannot be evaluated does NOT grant permission. Same principle —
			// an unreadable rule never widens what is allowed.
			continue
		}
		if open {
			return WindowDecision{Allowed: true, Reason: fmt.Sprintf("inside maintenance window %s", w.ID)}
		}
	}
	return WindowDecision{Reason: "outside every configured maintenance window, so this waits for the next one rather than running now"}
}

// IsOpen reports whether now falls inside this window.
//
// Walks candidate start minutes backwards from now, oldest-possible first, and
// returns on the first match. See this file's header for why matching rather than
// scheduling.
func (w Window) IsOpen(now time.Time) (bool, error) {
	fields, err := parseCron(w.Schedule)
	if err != nil {
		return false, err
	}
	if w.Duration <= 0 {
		return false, fmt.Errorf("window duration must be positive, got %s", w.Duration)
	}
	loc := time.UTC
	if w.Timezone != "" {
		loc, err = time.LoadLocation(w.Timezone)
		if err != nil {
			return false, fmt.Errorf("unknown timezone %q: %w", w.Timezone, err)
		}
	}

	// Truncate to the minute: cron resolution is minutes, so a start at 09:00:30
	// is not a thing, and comparing seconds would make a window's final minute
	// behave differently from every other one.
	cursor := now.Truncate(time.Minute)
	earliest := now.Add(-w.Duration)
	for !cursor.Before(earliest) {
		if fields.matches(cursor.In(loc)) {
			// cursor is a firing time; the window it opened runs to
			// cursor+duration, and cursor ≤ now by construction.
			if now.Before(cursor.Add(w.Duration)) {
				return true, nil
			}
		}
		cursor = cursor.Add(-time.Minute)
	}
	return false, nil
}

// Opening is one interval during which a window is open: [Start, End).
type Opening struct {
	Start, End time.Time
}

// Openings lists the intervals this window is open during [from, from+horizon),
// earliest first, at most max of them. An interval already open at `from` is
// included with its real start, which is before `from`.
//
// The same minute-matching walk as IsOpen, run forward: every minute whose local
// fields match the schedule is a firing, and a firing opens [F, F+Duration).
// Overlapping or touching intervals are merged, so "* 9 * * *" with a 30-minute
// duration reads as one 9:00–10:29 window rather than sixty. A 90-day horizon is
// 129,600 field tests per window — trivial next to the round trip that asks.
//
// It exists for display (the Overview's runway), and the scheduling rule is still
// IsOpen's: nothing that decides whether automation runs reads this.
func (w Window) Openings(from time.Time, horizon time.Duration, max int) ([]Opening, error) {
	fields, err := parseCron(w.Schedule)
	if err != nil {
		return nil, err
	}
	if w.Duration <= 0 {
		return nil, fmt.Errorf("window duration must be positive, got %s", w.Duration)
	}
	loc := time.UTC
	if w.Timezone != "" {
		loc, err = time.LoadLocation(w.Timezone)
		if err != nil {
			return nil, fmt.Errorf("unknown timezone %q: %w", w.Timezone, err)
		}
	}
	var out []Opening
	end := from.Add(horizon)
	// Start one duration back so a window that opened before `from` and is still
	// open is found at its real firing minute.
	for cursor := from.Add(-w.Duration).Truncate(time.Minute); cursor.Before(end); cursor = cursor.Add(time.Minute) {
		if !fields.matches(cursor.In(loc)) {
			continue
		}
		o := Opening{Start: cursor, End: cursor.Add(w.Duration)}
		if !o.End.After(from) {
			continue
		}
		if n := len(out); n > 0 && !o.Start.After(out[n-1].End) {
			if o.End.After(out[n-1].End) {
				out[n-1].End = o.End
			}
			continue
		}
		if len(out) == max {
			break
		}
		out = append(out, o)
	}
	return out, nil
}

// cronFields is one parsed expression: a set per field.
type cronFields struct {
	minute, hour, dom, month, dow map[int]bool
	// domRestricted/dowRestricted record whether each was written as "*". Cron's
	// day fields are OR'd when both are restricted and AND'd otherwise, which is
	// the one genuinely surprising rule in the format and the one most
	// hand-rolled implementations get wrong.
	domRestricted, dowRestricted bool
}

func (f cronFields) matches(t time.Time) bool {
	if !f.minute[t.Minute()] || !f.hour[t.Hour()] || !f.month[int(t.Month())] {
		return false
	}
	dom := f.dom[t.Day()]
	dow := f.dow[int(t.Weekday())]
	switch {
	case f.domRestricted && f.dowRestricted:
		// Vixie cron's rule: when BOTH day fields are restricted, a match on
		// either is a match. "0 0 13 * 5" is the 13th OR any Friday, not
		// Friday the 13th — which is what a naive AND would give, and would
		// make a window fire roughly never.
		return dom || dow
	default:
		return dom && dow
	}
}

// parseCron parses a 5-field expression: minute hour day-of-month month
// day-of-week. Supports *, n, a-b, a-b/s, */s and comma lists of those.
//
// Deliberately does NOT support the extensions (@daily, L, W, #, ?, names like
// MON): a window schedule an operator writes is compared against Argo CD's own
// sync windows by whoever configures both, and quietly accepting a syntax one
// side does not is worse than refusing it. Every refusal names what was wrong.
func parseCron(expr string) (cronFields, error) {
	parts := strings.Fields(strings.TrimSpace(expr))
	if len(parts) != 5 {
		return cronFields{}, fmt.Errorf("a schedule needs exactly 5 fields (minute hour day-of-month month day-of-week), got %d in %q", len(parts), expr)
	}
	var f cronFields
	var err error
	if f.minute, _, err = parseField(parts[0], 0, 59, "minute"); err != nil {
		return cronFields{}, err
	}
	if f.hour, _, err = parseField(parts[1], 0, 23, "hour"); err != nil {
		return cronFields{}, err
	}
	if f.dom, f.domRestricted, err = parseField(parts[2], 1, 31, "day-of-month"); err != nil {
		return cronFields{}, err
	}
	if f.month, _, err = parseField(parts[3], 1, 12, "month"); err != nil {
		return cronFields{}, err
	}
	if f.dow, f.dowRestricted, err = parseField(parts[4], 0, 7, "day-of-week"); err != nil {
		return cronFields{}, err
	}
	// Cron allows 7 for Sunday as well as 0. Normalised here so matches() can
	// compare against time.Weekday directly.
	if f.dow[7] {
		f.dow[0] = true
	}
	return f, nil
}

// parseField returns the matching values, plus whether the field was restricted
// (anything other than a bare "*").
func parseField(spec string, min, max int, name string) (map[int]bool, bool, error) {
	out := map[int]bool{}
	restricted := spec != "*"
	for _, term := range strings.Split(spec, ",") {
		term = strings.TrimSpace(term)
		if term == "" {
			return nil, false, fmt.Errorf("empty term in the %s field", name)
		}
		step := 1
		if slash := strings.Index(term, "/"); slash >= 0 {
			var err error
			if step, err = strconv.Atoi(term[slash+1:]); err != nil || step < 1 {
				return nil, false, fmt.Errorf("invalid step %q in the %s field", term[slash+1:], name)
			}
			term = term[:slash]
		}
		lo, hi := min, max
		switch {
		case term == "*":
			// full range
		case strings.Contains(term, "-"):
			bounds := strings.SplitN(term, "-", 2)
			var err error
			if lo, err = strconv.Atoi(strings.TrimSpace(bounds[0])); err != nil {
				return nil, false, fmt.Errorf("invalid range start %q in the %s field", bounds[0], name)
			}
			if hi, err = strconv.Atoi(strings.TrimSpace(bounds[1])); err != nil {
				return nil, false, fmt.Errorf("invalid range end %q in the %s field", bounds[1], name)
			}
			if lo > hi {
				return nil, false, fmt.Errorf("range %d-%d in the %s field is backwards", lo, hi, name)
			}
		default:
			v, err := strconv.Atoi(term)
			if err != nil {
				return nil, false, fmt.Errorf("invalid value %q in the %s field (names like MON and extensions like @daily are not supported)", term, name)
			}
			lo, hi = v, v
		}
		if lo < min || hi > max {
			return nil, false, fmt.Errorf("%d-%d is outside the %s field's range %d-%d", lo, hi, name, min, max)
		}
		for v := lo; v <= hi; v += step {
			out[v] = true
		}
	}
	if len(out) == 0 {
		return nil, false, fmt.Errorf("the %s field %q matches nothing", name, spec)
	}
	return out, restricted, nil
}

// ValidateWindow checks one window at configuration time, so a bad schedule is
// refused when it is typed rather than discovered when it fails to open.
func ValidateWindow(w Window) error {
	if w.Kind != WindowMaintenance && w.Kind != WindowFreeze {
		return fmt.Errorf("window kind must be %q or %q, got %q", WindowMaintenance, WindowFreeze, w.Kind)
	}
	if _, err := parseCron(w.Schedule); err != nil {
		return err
	}
	if w.Duration <= 0 {
		return fmt.Errorf("duration must be positive")
	}
	// A window longer than a week cannot be reasoned about against a schedule
	// that repeats more often than that: overlapping instances of the same window
	// would be permanently open, which is a configuration mistake rather than an
	// intent worth honouring silently.
	if w.Duration > 7*24*time.Hour {
		return fmt.Errorf("duration %s is longer than a week; a window that long is almost certainly a mistake, and it would overlap its own next opening", w.Duration)
	}
	if w.Timezone != "" {
		if _, err := time.LoadLocation(w.Timezone); err != nil {
			return fmt.Errorf("unknown timezone %q — use an IANA name such as Europe/London or UTC", w.Timezone)
		}
	}
	if w.Kind == WindowFreeze && strings.TrimSpace(w.Reason) == "" {
		// Required for a freeze specifically: it is the text an operator reads
		// when automation did not happen, and "nothing ran and nobody said why"
		// is what makes people switch a safety feature off.
		return fmt.Errorf("a freeze window needs a reason — it is what gets shown when automation is blocked")
	}
	return nil
}
