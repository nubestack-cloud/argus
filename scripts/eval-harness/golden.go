// golden.go used to hold this harness's own copy of the golden-case fixture
// format. It no longer does: the format now lives in
// scripts/eval/casefmt, because scripts/eval/gen writes cases and this
// harness reads them, and a format defined twice is a format that will
// eventually be defined two different ways.
//
// What is left here is the aliasing that keeps the rest of this package
// (main.go, fakeagent.go, score.go and their tests) reading the way it always
// did, plus the corpus-loading entry point the harness actually calls.
package main

import (
	"fmt"
	"sort"
	"strings"

	"argus/scripts/eval/casefmt"
)

// The fixture types, aliased rather than wrapped: these are the same types,
// so a casefmt.Case can be passed anywhere a GoldenCase is expected and the
// generator and the harness cannot drift.
type (
	GoldenCase        = casefmt.Case
	GoldenFinding     = casefmt.Finding
	ToolResponseEntry = casefmt.ToolResponseEntry
	ExpectedOutcome   = casefmt.ExpectedOutcome
)

// LoadGoldenCases loads one corpus directory. Kept as a named function rather
// than an alias so the harness's own call sites and tests read unchanged.
func LoadGoldenCases(dir string) ([]GoldenCase, error) { return casefmt.LoadDir(dir) }

// LoadGoldenCaseDirs loads several corpus directories as one set — the
// hand-written corpus (scripts/eval/golden) and the catalogue-generated one
// (scripts/eval/generated) are run together, scored together, and differ only
// in provenance and in the limitation banner that provenance triggers.
func LoadGoldenCaseDirs(dirs []string) ([]GoldenCase, error) { return casefmt.LoadDirs(dirs) }

// SelectCases narrows a loaded corpus to a named list of case IDs, in the
// order the corpus itself is in (not the order they were named, so two runs
// that list the same cases differently are still directly comparable).
//
// It exists for one situation and says so in its errors: a real-model run
// costs real money per case, so the whole corpus may be too expensive to
// repeat often enough to measure a spread. An unknown ID is a hard error
// rather than a silent omission — a typo that quietly shrinks the denominator
// is exactly how a subset gets mistaken for the corpus later.
func SelectCases(cases []GoldenCase, ids string) ([]GoldenCase, error) {
	want := map[string]bool{}
	for _, id := range strings.Split(ids, ",") {
		if id = strings.TrimSpace(id); id != "" {
			want[id] = true
		}
	}
	if len(want) == 0 {
		return nil, fmt.Errorf("-case-ids was set but named no case")
	}
	var out []GoldenCase
	for _, gc := range cases {
		if want[gc.ID] {
			out = append(out, gc)
			delete(want, gc.ID)
		}
	}
	if len(want) > 0 {
		missing := make([]string, 0, len(want))
		for id := range want {
			missing = append(missing, id)
		}
		sort.Strings(missing)
		return nil, fmt.Errorf("-case-ids named %d case(s) that are not in the loaded corpus: %s", len(missing), strings.Join(missing, ", "))
	}
	return out, nil
}
