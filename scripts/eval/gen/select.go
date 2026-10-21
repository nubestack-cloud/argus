// select.go decides WHICH of the catalogue's 1,032 entries Phase 1 runs.
//
// The brief for this phase is "roughly 20 cases over the highest-frequency
// categories, picked for coverage spread rather than by convenience." Those
// two halves pull in different directions and the code below is where the
// trade is made explicit:
//
//  1. FREQUENCY picks the categories. The catalogue's own category sizes are
//     the only frequency signal available in this repo — nobody has fleet
//     incident counts to rank by — so a category with 48 cataloged faults is
//     treated as a bigger slice of the real fault space than one with 10.
//     That is an assumption, not a measurement, and it is written down here
//     rather than buried: if fleet data ever exists, re-rank on it.
//
//  2. SPREAD picks the entry inside each category. Taking each category's
//     first entry would be exactly the convenience the brief rules out — the
//     catalogue is ordered by subsection, so the first entry of every
//     category is the most textbook one in it. Instead the selector fills a
//     coverage matrix greedily: it walks the chosen categories in rank order
//     and, within each, takes the candidate that covers the
//     (risk, channel-class) combination seen least often so far, breaking
//     ties on catalogue order so the result is deterministic.
//
//  3. POLARITY is assigned before either of those. Two scores are reported
//     separately and both need a corpus, so a fixed fraction of the chosen
//     categories is assigned the "silent" polarity — the catalogue's
//     `silent: true` entries, which are the natural corpus for grading
//     whether "could not determine" is reached when it is the right answer.
//     Assigned by rank position (every Nth category) rather than by which
//     categories happen to have silent entries, so the honest-negative
//     corpus is not quietly drawn from one corner of the fault space.
package main

import (
	"sort"
)

// SilentEveryNth: one in every N selected categories contributes a silent
// (honest-negative) case rather than a definite one. 3 gives ~33% of Phase 1
// to the honest-negative corpus against the catalogue's own 44% silent rate —
// deliberately under-weighted, because a definite case grades both that the
// product reached AN answer and that it reached the RIGHT one, while a silent
// case grades only that it declined.
const SilentEveryNth = 3

// Selection is one chosen entry plus why it was chosen, so a reader of the
// corpus can reconstruct the decision without re-running the selector.
type Selection struct {
	Entry      Entry
	Rank       int    // the category's frequency rank, 1 = largest category
	CatSize    int    // how many catalogue entries that category has
	WantSilent bool   // the polarity this slot was assigned
	Why        string // the coverage cell this entry filled
}

type categoryRank struct {
	Code string
	Name string
	Size int
}

// RankCategories orders categories by entry count descending, breaking ties
// on the category code ascending so the ranking is total and stable.
func RankCategories(entries []Entry) []categoryRank {
	size := map[string]int{}
	name := map[string]string{}
	for _, e := range entries {
		size[e.Category]++
		if name[e.Category] == "" {
			name[e.Category] = e.CategoryName
		}
	}
	out := make([]categoryRank, 0, len(size))
	for code, n := range size {
		out = append(out, categoryRank{Code: code, Name: name[code], Size: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Size != out[j].Size {
			return out[i].Size > out[j].Size
		}
		return out[i].Code < out[j].Code
	})
	return out
}

// channelClass collapses an entry's permitted channels onto the three
// resolution routes ARGUS actually has (internal/resolution), so the spread
// dimension means something to this product rather than being a string set.
func channelClass(e Entry) string {
	var pr, inPlace bool
	for _, c := range e.Channels {
		switch c {
		case "pullRequest":
			pr = true
		case "inPlace":
			inPlace = true
		}
	}
	switch {
	case pr && inPlace:
		return "paired"
	case pr:
		return "pullRequest"
	case inPlace:
		return "inPlace"
	default:
		// "external" only, or nothing: no channel ARGUS can execute — the
		// guidance route.
		return "guidance"
	}
}

// SelectPhase1 chooses one entry from each of the top `count` categories.
//
// gradable is the generator's own "can this entry be turned into a case that
// is actually scorable" predicate (see fixture.go) — an entry whose root
// causes yield no distinguishing term cannot grade a definite answer, so it
// is skipped here rather than emitted as a case that any statement would
// pass. A category with no gradable candidate of the polarity its slot was
// assigned falls back to the other polarity before being dropped entirely.
func SelectPhase1(entries []Entry, count int, gradable func(Entry) bool) []Selection {
	ranks := RankCategories(entries)
	if count > len(ranks) {
		count = len(ranks)
	}

	byCategory := map[string][]Entry{}
	for _, e := range entries {
		byCategory[e.Category] = append(byCategory[e.Category], e)
	}

	// coverage counts how many times each (risk, channelClass) cell has been
	// filled; the greedy pick below always prefers the emptiest cell.
	coverage := map[string]int{}
	cell := func(e Entry) string { return e.Risk + "/" + channelClass(e) }

	out := make([]Selection, 0, count)
	for i := 0; i < count; i++ {
		cr := ranks[i]
		wantSilent := (i+1)%SilentEveryNth == 0

		pick, why := pickFromCategory(byCategory[cr.Code], wantSilent, gradable, coverage, cell)
		if pick == nil {
			// Neither polarity produced a gradable candidate. Skip the
			// category rather than emit an ungradable case — a corpus entry
			// that cannot fail is worse than a missing one.
			continue
		}
		coverage[cell(*pick)]++
		out = append(out, Selection{
			Entry:      *pick,
			Rank:       i + 1,
			CatSize:    cr.Size,
			WantSilent: wantSilent,
			Why:        why,
		})
	}
	return out
}

func pickFromCategory(candidates []Entry, wantSilent bool, gradable func(Entry) bool, coverage map[string]int, cell func(Entry) string) (*Entry, string) {
	for _, silent := range []bool{wantSilent, !wantSilent} {
		var best *Entry
		bestCount := -1
		for i := range candidates {
			e := candidates[i]
			if e.Silent != silent {
				continue
			}
			if !gradable(e) {
				continue
			}
			c := coverage[cell(e)]
			if bestCount == -1 || c < bestCount {
				best = &candidates[i]
				bestCount = c
			}
		}
		if best != nil {
			why := "filled the least-covered (risk, channel) cell " + cell(*best)
			if silent != wantSilent {
				why += "; polarity fell back to silent=" + boolStr(silent) + " — the category had no gradable entry of the assigned polarity"
			}
			return best, why
		}
	}
	return nil, ""
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
