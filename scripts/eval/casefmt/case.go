// Package casefmt is the one definition of a golden eval case: the JSON
// fixture shape, its loader, and its tool-response lookup.
//
// It exists as a package rather than staying inside scripts/eval-harness
// because there are now two programs that have to agree on that shape byte
// for byte — the harness that RUNS a case (scripts/eval-harness) and the
// generator that WRITES one from the issue catalogue (scripts/eval/gen).
// Two hand-maintained copies of one format agree right up until the day one
// of them is edited, which is the same reasoning
// .github/workflows/nightly-failure-issue.yml gives for being a reusable
// workflow instead of forty pasted lines.
//
// Format (this is the "a person could add a case by hand without writing
// Go" contract; scripts/eval/gen exists so they mostly don't have to):
//
//	{
//	  "id": "...",                      // unique; used to build the fixture's incident/finding IDs
//	  "description": "...",             // what this case tests and why
//	  "provenance": "hand-written" | "synthesized-from-catalog",
//	  "catalogId": "SVC-001",           // catalogue entry this was generated from (generated cases only)
//	  "category": "N",                  // catalogue category code (generated cases only)
//	  "categoryName": "...",            // catalogue category name (generated cases only)
//	  "limitation": "...",              // what this case does NOT prove (generated cases only) — see below
//	  "finding": { ... },               // exactly one v1/Pod finding, the shape a real detector produces
//	  "toolResponses": { "<tool>": [ {"match": {...}, "data": <raw JSON>} ] },
//	  "expected": {
//	    "type": "definite" | "insufficient",
//	    "requiredKeywords": ["..."],       // "definite": ALL must appear in the concluded statement
//	    "anyOfKeywords": ["..."],          // "definite": at least ONE must appear
//	    "forbiddenKeywords": ["..."],      // "definite": none may appear (the red-herring guard)
//	    "minConfidence": 0.5,
//	    "maxConfidenceForInsufficient": 0.4,
//	    "minIterations": 3, "maxIterations": 5
//	  }
//	}
//
// # The honesty field
//
// Limitation is not decoration and it is not a TODO. A case generated from
// catalogue metadata tests whether the investigation reasons correctly over
// the signals the catalogue STATES, not over real recorded cluster output:
// its toolResponses are synthesized from an entry's own `signals` string,
// they are not a capture of anything kubectl ever printed. A corpus that
// looked like real cluster output while being nothing of the kind would let
// a green score imply coverage it does not have — so every generated case
// carries the sentence saying so, in the file itself, where someone reading
// the fixture cannot miss it, and the harness reprints it above every
// report that includes such a case.
package casefmt

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Provenance values. A case is one or the other; there is no default,
// because "where did this fixture's evidence come from" is exactly the
// question a reader of a green score needs answered.
const (
	// ProvenanceHandWritten: a human wrote the toolResponses to mirror what
	// the real agent would have returned for a scenario they had in mind.
	ProvenanceHandWritten = "hand-written"
	// ProvenanceCatalog: scripts/eval/gen synthesized the toolResponses from
	// an issue-catalog entry's stated signals. See the package doc.
	ProvenanceCatalog = "synthesized-from-catalog"
)

// Finding is the one finding fixture a case's incident carries.
//
// GVK is deliberately absent (always "v1/Pod"): the harness's own finding
// line parser is pinned to that prefix, which is a limit of the harness, not
// of this format — teaching it a second pattern would not require touching
// this struct or any existing case file.
type Finding struct {
	DetectorID      string `json:"detectorId"`
	Severity        string `json:"severity"`
	Namespace       string `json:"namespace"`
	ObjectName      string `json:"objectName"`
	Reason          string `json:"reason"`
	Message         string `json:"message"`
	OccurrenceCount int    `json:"occurrenceCount"`
}

// ToolResponseEntry is one candidate answer for one tool, tried in the order
// it appears in its Case.ToolResponses[tool] list. Exactly one of Data/Error.
type ToolResponseEntry struct {
	Match map[string]string `json:"match,omitempty"`
	Data  json.RawMessage   `json:"data,omitempty"`
	Error string            `json:"error,omitempty"`
}

// Expected outcome types.
const (
	ExpectDefinite     = "definite"
	ExpectInsufficient = "insufficient"
)

// ExpectedOutcome is the case's known-correct answer.
//
// The three keyword lists are three different questions, and a generated
// case usually only answers the middle one:
//
//   - RequiredKeywords (ALL of): the statement is about the right thing.
//     Hand-written cases use it; generated cases deliberately leave it empty,
//     because an auto-derived conjunction is brittle in the direction that
//     fails a correct answer.
//   - AnyOfKeywords (at least ONE of): the statement commits to one of the
//     candidate root causes the catalogue lists for this issue. This is what
//     actually grades a generated case — the catalogue's `root_causes` list
//     is already an "any one of these is the right answer" set.
//   - ForbiddenKeywords (NONE of): the red-herring guard. A statement that
//     hedges by naming the decoy AND the real cause still fails.
type ExpectedOutcome struct {
	Type                         string   `json:"type"`
	RequiredKeywords             []string `json:"requiredKeywords,omitempty"`
	AnyOfKeywords                []string `json:"anyOfKeywords,omitempty"`
	ForbiddenKeywords            []string `json:"forbiddenKeywords,omitempty"`
	MinConfidence                float64  `json:"minConfidence,omitempty"`
	MaxConfidenceForInsufficient float64  `json:"maxConfidenceForInsufficient,omitempty"`
	MinIterations                int      `json:"minIterations"`
	MaxIterations                int      `json:"maxIterations"`
	// RequiredRoute/RequiredActionType (PG9, 2026-10-13 parity review): for a
	// case proving a recognised GitOps failure reaches a real fix, not just a
	// correct root cause — the resolution route (internal/resolution.Route)
	// and/or the proposed plan's actionType the investigation must actually
	// reach. Empty means not checked, same convention as every other
	// optional field here. Checking these needs a subject that actually
	// reports a route — a real model (offline or stack), never the
	// deterministic stand-in — see scripts/eval-harness/score.go's
	// fixReachedCheck for how an incapable subject is told apart from a
	// capable one that genuinely got it wrong.
	RequiredRoute      string `json:"requiredRoute,omitempty"`
	RequiredActionType string `json:"requiredActionType,omitempty"`
}

// Case is one fixture file's fully parsed content.
type Case struct {
	ID          string `json:"id"`
	Description string `json:"description"`

	// Provenance is one of the Provenance* constants. Older hand-written
	// files predate the field; LoadDir fills it in as ProvenanceHandWritten
	// rather than leaving it empty, so no caller has to treat "" as a third
	// state it must guess about.
	Provenance string `json:"provenance,omitempty"`
	// CatalogID/Category/CategoryName are set on generated cases only.
	CatalogID    string `json:"catalogId,omitempty"`
	Category     string `json:"category,omitempty"`
	CategoryName string `json:"categoryName,omitempty"`
	// Limitation is the sentence saying what this fixture does not prove.
	// See the package doc comment; it is mandatory on a generated case and
	// reprinted by the harness above every report that includes one.
	Limitation string `json:"limitation,omitempty"`

	Finding       Finding                        `json:"finding"`
	ToolResponses map[string][]ToolResponseEntry `json:"toolResponses"`
	Expected      ExpectedOutcome                `json:"expected"`

	// SourcePath is set by the loader, not read from the file — purely so a
	// malformed case is easy to find on disk.
	SourcePath string `json:"-"`
}

// Synthesized reports whether this case's evidence was generated from
// catalogue metadata rather than written against observed cluster output.
func (c *Case) Synthesized() bool { return c.Provenance == ProvenanceCatalog }

// RequiresWorldKnowledge reports whether grading this case demands that the
// subject supply something the evidence does not contain.
//
// It is a derived property, not a flag anybody sets: a definite case requires
// world knowledge exactly when none of its grading keywords appears anywhere
// in its own fixture — finding text, tool responses, all of it. The keyword
// has to come from the subject's knowledge of Kubernetes, because it is not
// in what the subject was shown.
//
// Why the harness needs to know: a run whose subject is the deterministic
// stand-in has no world knowledge at all, by construction. Scoring those
// cases against it would record a constant zero that no regression could ever
// move, which is worse than not scoring them — a gate pinned to the floor is
// a gate that cannot detect anything. They are reported as not evaluated,
// with the reason, and evaluated for real the moment a model backend is
// configured.
//
// Cases that do NOT require world knowledge are the ones whose answer is
// present in the evidence and has to be found: "OOMKilled" is in the events,
// "database connection" is in the logs behind a readiness-probe decoy. Those
// grade any subject, including a stand-in that can only follow instructions.
// A case whose Expected also sets RequiredRoute/RequiredActionType (PG9,
// 2026-10-13 parity review) grades the same way for root cause — those two
// fields are a second, independent dimension the scorer checks only when
// the subject actually reported a route, which the deterministic stand-in
// never does (see scripts/eval-harness/score.go's fixReachedCheck).
func (c *Case) RequiresWorldKnowledge() bool {
	if c.Expected.Type != ExpectDefinite {
		return false
	}
	keywords := make([]string, 0, len(c.Expected.RequiredKeywords)+len(c.Expected.AnyOfKeywords))
	keywords = append(keywords, c.Expected.RequiredKeywords...)
	keywords = append(keywords, c.Expected.AnyOfKeywords...)
	if len(keywords) == 0 {
		return false
	}
	hay := strings.ToLower(c.evidenceText())
	for _, kw := range keywords {
		if strings.Contains(hay, strings.ToLower(kw)) {
			return false
		}
	}
	return true
}

// evidenceText is everything the subject is shown: the finding line's own
// text plus every byte of every tool response the fixture can answer with.
func (c *Case) evidenceText() string {
	var b strings.Builder
	b.WriteString(c.Finding.Reason)
	b.WriteString(" ")
	b.WriteString(c.Finding.Message)
	for _, entries := range c.ToolResponses {
		for _, e := range entries {
			b.WriteString(" ")
			b.Write(e.Data)
			b.WriteString(" ")
			b.WriteString(e.Error)
		}
	}
	return b.String()
}

// LoadDir reads every *.json file in dir (non-recursive) as a Case, sorted by
// filename for a stable, reproducible run order. It fails loudly on the first
// unparseable file rather than skipping it: a golden-set member that cannot
// be read is a bug worth stopping for, not a case to quietly drop.
func LoadDir(dir string) ([]Case, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read golden set directory %s: %w", dir, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, fmt.Errorf("no *.json golden case files found in %s", dir)
	}

	cases := make([]Case, 0, len(names))
	for _, name := range names {
		path := filepath.Join(dir, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read golden case %s: %w", path, err)
		}
		var gc Case
		if err := json.Unmarshal(raw, &gc); err != nil {
			return nil, fmt.Errorf("parse golden case %s: %w", path, err)
		}
		if err := gc.validate(path); err != nil {
			return nil, err
		}
		gc.SourcePath = path
		cases = append(cases, gc)
	}
	return cases, nil
}

// LoadDirs loads several corpus directories in the order given and returns
// them as one set, rejecting a duplicate ID across directories. The harness
// runs the hand-written corpus and the generated corpus together: they are
// scored the same way and reported the same way, and only their provenance
// (and the limitation banner it triggers) differs.
func LoadDirs(dirs []string) ([]Case, error) {
	var all []Case
	seen := map[string]string{}
	for _, dir := range dirs {
		cases, err := LoadDir(dir)
		if err != nil {
			return nil, err
		}
		for _, gc := range cases {
			if prev, dup := seen[gc.ID]; dup {
				return nil, fmt.Errorf("duplicate golden case id %q in %s (already loaded from %s)", gc.ID, gc.SourcePath, prev)
			}
			seen[gc.ID] = gc.SourcePath
			all = append(all, gc)
		}
	}
	return all, nil
}

func (c *Case) validate(path string) error {
	if c.ID == "" {
		return fmt.Errorf("golden case %s: \"id\" is required", path)
	}
	if c.Expected.Type != ExpectDefinite && c.Expected.Type != ExpectInsufficient {
		return fmt.Errorf("golden case %s: expected.type must be %q or %q, got %q", path, ExpectDefinite, ExpectInsufficient, c.Expected.Type)
	}
	switch c.Provenance {
	case "":
		// Predates the field. Hand-written is the only thing it can be: the
		// generator has always written its own provenance.
		c.Provenance = ProvenanceHandWritten
	case ProvenanceHandWritten:
	case ProvenanceCatalog:
		if strings.TrimSpace(c.Limitation) == "" {
			return fmt.Errorf("golden case %s: a %q case must carry a non-empty \"limitation\" — that sentence is the only thing standing between a synthesized fixture and a reader who assumes it is a real capture", path, ProvenanceCatalog)
		}
	default:
		return fmt.Errorf("golden case %s: unrecognized provenance %q", path, c.Provenance)
	}
	if c.Expected.Type == ExpectDefinite && len(c.Expected.RequiredKeywords) == 0 && len(c.Expected.AnyOfKeywords) == 0 {
		return fmt.Errorf("golden case %s: a %q case with neither requiredKeywords nor anyOfKeywords cannot be graded — any statement at all would pass it", path, ExpectDefinite)
	}
	return nil
}

// synthesizedDefault returns a well-formed empty/negative response for a tool
// a case never mentions, so a model that calls a tool the fixture author did
// not anticipate gets a clean "found nothing" answer instead of a crash or an
// empty json.RawMessage that fails to unmarshal on the toolloop side. This
// mirrors the real agent's "an empty result is normal evidence" posture.
func synthesizedDefault(tool string) json.RawMessage {
	switch tool {
	case "get_events", "get_owner_chain", "list_resources", "list_nodeport_allocations":
		return json.RawMessage(`[]`)
	case "get_logs":
		return json.RawMessage(`{"lines":[]}`)
	case "describe_resource":
		return json.RawMessage(`{"object":{},"events":[]}`)
	case "get_gitops_ownership":
		return json.RawMessage(`{"managed_by":"none"}`)
	default:
		return json.RawMessage(`{}`)
	}
}

// ToolResponse resolves what the fake cluster should answer for one
// ToolRequest{tool, args}: the first entry (in file order) whose Match fully
// agrees with the call's own decoded arguments, else the first entry with an
// empty/absent Match (the fixture's designated default for that tool), else a
// synthesizedDefault. Returns exactly one of (data, "") or (nil, errMsg),
// mirroring internal/tunnel.ToolResult's own contract.
func (c *Case) ToolResponse(tool string, argsRaw json.RawMessage) (data json.RawMessage, errMsg string) {
	entries := c.ToolResponses[tool]
	if len(entries) == 0 {
		return synthesizedDefault(tool), ""
	}

	var args map[string]any
	_ = json.Unmarshal(argsRaw, &args) // best-effort: a decode failure just means no non-empty Match can match

	var fallback *ToolResponseEntry
	for i := range entries {
		e := &entries[i]
		if len(e.Match) == 0 {
			if fallback == nil {
				fallback = e
			}
			continue
		}
		if matchesAll(e.Match, args) {
			return e.Data, e.Error
		}
	}
	if fallback != nil {
		return fallback.Data, fallback.Error
	}
	return synthesizedDefault(tool), ""
}

// matchesAll reports whether every key/value in match is present in args with
// an equal string representation — deliberately loose, since a case's match
// values are written as plain strings regardless of the real argument's JSON
// type (e.g. matching a boolean `previous` against the string "true").
func matchesAll(match map[string]string, args map[string]any) bool {
	for k, want := range match {
		got, ok := args[k]
		if !ok {
			return false
		}
		if fmt.Sprintf("%v", got) != want {
			return false
		}
	}
	return true
}
