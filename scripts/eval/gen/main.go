// Command gen writes the catalogue-generated half of the golden eval corpus.
//
// The corpus has to be able to grow to 50–100 cases and full category
// coverage without anyone hand-editing JSON, which is why this is a program
// and not twenty files someone typed. Raising Phase 1's size is `-count`;
// the selection rule, the signal mapping and the grading derivation are all
// in select.go and fixture.go where they can be argued with.
//
// Usage, from the repo root:
//
//	go run ./scripts/eval/gen                 # rewrite scripts/eval/generated
//	go run ./scripts/eval/gen -check          # fail if the checked-in corpus has drifted
//	go run ./scripts/eval/gen -explain        # print the selection table and the derived grading terms
//	go run ./scripts/eval/gen -count 50       # Phase 2
//
// -check is what the nightly runs. The corpus is checked in rather than
// generated at run time so that a change to the generator shows up as a
// reviewable diff of the actual cases — a corpus that regenerates silently
// on every run would let a selection-rule change move the score with nothing
// in the history saying it had.
//
// # Logging: deliberately NOT converted to internal/logging (PROJECT.md T22)
//
// T22 converts the hub's and agent's log.Printf call sites to structured slog
// records. The programs under scripts/ are excluded from that, permanently and
// on purpose — this is a decision, not a gap:
//
//   - They are dev/CI tooling, `go run` and `go build` throwaways. Nothing
//     under deploy/ or the Dockerfile builds them into a shipped image, so
//     none of their output ever reaches a support bundle or a log shipper,
//     which is the operability defect T22 exists to fix.
//   - None of them calls logging.Setup(), so their output is plain text read
//     by the person who just ran them. Converting would make it JSON, which
//     is strictly worse at a terminal, and the structured fields it would buy
//     (request_id, incident_id, cluster_id, actor_id) do not exist here:
//     there is no request, no actor, and no hub-side correlation to join to.
//   - CI reads some of this output as text (.github/workflows/eval.yml tees
//     and greps the eval harness's), so the format is an interface.
//
// The standard `log` package is the right tool for a terminal program. Use it
// here; use internal/logging under cmd/ and internal/.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"argus/scripts/eval/casefmt"
)

// DefaultCount is Phase 1: roughly twenty cases over the highest-frequency
// categories. Small enough to actually start, big enough that a real
// regression moves the number.
const DefaultCount = 20

func main() {
	catalogPath := flag.String("catalog", "issue-catalog/k8s-issue-catalog.yaml", "path to the issue catalogue")
	outDir := flag.String("out", "scripts/eval/generated", "directory to write generated cases into")
	count := flag.Int("count", DefaultCount, "how many categories to draw a case from (one case per category)")
	check := flag.Bool("check", false, "do not write; exit non-zero if the checked-in corpus differs from what this generator would produce")
	explain := flag.Bool("explain", false, "print the selection table and each case's derived grading terms")
	flag.Parse()

	entries, err := LoadCatalog(*catalogPath)
	if err != nil {
		log.Fatalf("eval-gen: %v", err)
	}

	selections := SelectPhase1(entries, *count, Gradable)
	if len(selections) == 0 {
		log.Fatalf("eval-gen: selection produced no cases from %d catalogue entries", len(entries))
	}

	files := map[string][]byte{}
	cases := make([]casefmt.Case, 0, len(selections))
	for _, sel := range selections {
		gc := BuildCase(sel)
		body, err := renderCase(gc)
		if err != nil {
			log.Fatalf("eval-gen: render %s: %v", gc.ID, err)
		}
		files[gc.ID+".json"] = body
		cases = append(cases, gc)
	}

	if *explain {
		fmt.Print(explainReport(selections, cases, len(entries)))
	}

	if *check {
		if diff := checkCorpus(*outDir, files); diff != "" {
			fmt.Fprint(os.Stderr, diff)
			os.Exit(1)
		}
		fmt.Printf("eval-gen: %s is in sync with the generator (%d cases)\n", *outDir, len(files))
		return
	}

	if err := writeCorpus(*outDir, files); err != nil {
		log.Fatalf("eval-gen: %v", err)
	}
	fmt.Printf("eval-gen: wrote %d case(s) to %s from %d catalogue entries\n", len(files), *outDir, len(entries))
}

// renderCase marshals a case with stable key order and a trailing newline, so
// a regeneration that changed nothing produces no diff at all.
func renderCase(gc casefmt.Case) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(gc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCorpus(dir string, files map[string][]byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	// Remove cases this run did not produce. A generated corpus directory is
	// owned entirely by the generator: a stale file left behind from an
	// earlier -count or an earlier selection rule would keep scoring, and
	// nothing would say where it came from.
	existing, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read %s: %w", dir, err)
	}
	for _, e := range existing {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if _, keep := files[e.Name()]; !keep {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
				return fmt.Errorf("remove stale case %s: %w", e.Name(), err)
			}
		}
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}

// checkCorpus returns a human-readable description of every difference
// between the checked-in corpus and what this generator would write now, or
// "" when they agree.
func checkCorpus(dir string, files map[string][]byte) string {
	var b strings.Builder
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		path := filepath.Join(dir, name)
		got, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(&b, "MISSING  %s — the generator would produce this case and it is not checked in\n", path)
			continue
		}
		if !bytes.Equal(got, files[name]) {
			fmt.Fprintf(&b, "DIFFERS  %s — the checked-in case is not what the generator produces\n", path)
		}
	}

	if existing, err := os.ReadDir(dir); err == nil {
		for _, e := range existing {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			if _, want := files[e.Name()]; !want {
				fmt.Fprintf(&b, "EXTRA    %s — checked in but the generator would not produce it\n", filepath.Join(dir, e.Name()))
			}
		}
	}

	if b.Len() > 0 {
		b.WriteString("\nRun `go run ./scripts/eval/gen` and commit the result. The corpus is checked in\n")
		b.WriteString("deliberately: a selection-rule change has to show up as a reviewable diff of the\n")
		b.WriteString("actual cases, not move the score silently.\n")
	}
	return b.String()
}

func explainReport(selections []Selection, cases []casefmt.Case, catalogSize int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n=== Phase 1 selection (%d cases from %d catalogue entries) ===\n\n", len(selections), catalogSize)
	fmt.Fprintf(&b, "%-5s %-4s %-5s %-9s %-11s %s\n", "rank", "cat", "size", "entry", "polarity", "grading terms (anyOf)")
	definite, silent := 0, 0
	for i, sel := range selections {
		polarity := "definite"
		terms := strings.Join(cases[i].Expected.AnyOfKeywords, ", ")
		if sel.Entry.Silent {
			polarity = "silent"
			terms = "(honest-negative: graded on confidence, not wording)"
			silent++
		} else {
			definite++
		}
		fmt.Fprintf(&b, "%-5d %-4s %-5d %-9s %-11s %s\n", sel.Rank, sel.Entry.Category, sel.CatSize, sel.Entry.ID, polarity, terms)
	}
	fmt.Fprintf(&b, "\nroot-cause-match corpus: %d case(s)\nhonest-negative corpus:  %d case(s)\n", definite, silent)
	fmt.Fprintf(&b, "\nEvery case above is %s. %s\n", casefmt.ProvenanceCatalog, LimitationSentence)
	return b.String()
}
