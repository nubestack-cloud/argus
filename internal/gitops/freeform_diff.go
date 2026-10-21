package gitops

import (
	"fmt"
	"strings"
)

// freeformUnifiedDiff computes a full, honest unified diff between two whole
// files. It is THE diff mechanism for a repository change (files.go): a
// whole-file edit can insert, delete and reorder any number of lines, so this
// is a real line-level diff — computed with Myers' shortest-edit-script
// algorithm
// (Myers, "An O(ND) Difference Algorithm and Its Variations", 1986), the same
// algorithm `diff`/`git diff` use, rather than anything that assumes a
// particular shape of change. This IS the diff that goes in the pull request
// body and the API response — there is no second, display-only derivation
// downstream to disagree with it, the same discipline UnifiedDiff.tsx's own
// comment states for the frontend half of this.
const (
	// diffContextLines is how many unchanged lines surround each hunk, matching
	// the convention `git diff` uses.
	diffContextLines = 3
	// maxMyersOps bounds the O((N+M)) space the algorithm needs and roughly
	// bounds its worst-case time. Above this, freeformLineDiff falls back to a
	// common-prefix/common-suffix diff (below) rather than either paying an
	// unbounded cost or refusing outright — a preview or a pull request should
	// not hang because someone edited an unusually large file.
	maxMyersOps = 20000
)

type diffOpKind int

const (
	diffEqual diffOpKind = iota
	diffDelete
	diffInsert
)

type diffOp struct {
	Kind diffOpKind
	Text string
}

// freeformUnifiedDiff is the entry point: split into lines, diff, render.
func freeformUnifiedDiff(before, after []string) (diff string, added, removed int) {
	ops := freeformLineDiff(before, after)
	return renderUnifiedHunks(ops, diffContextLines)
}

// freeformLineDiff returns the edit script turning before into after, as a
// sequence of per-line operations IN ORDER — replaying them against before
// (keep on equal, skip on delete, splice in on insert) reproduces after
// exactly. That reconstruction property is what every test of this function
// checks, rather than checking for one specific (of possibly several
// equally-short) edit script, because Myers' algorithm only guarantees
// shortest, not unique.
func freeformLineDiff(before, after []string) []diffOp {
	if len(before) == 0 && len(after) == 0 {
		return nil
	}
	if len(before)+len(after) > maxMyersOps {
		return commonAffixDiff(before, after)
	}
	return myersLineDiff(before, after)
}

// myersLineDiff implements the algorithm's "greedy" forward pass (finding the
// shortest edit distance D and, along the way, a trace of every round) and
// then walks the trace backward to recover the actual edit script — the
// standard two-phase shape the algorithm is always presented in, since the
// forward pass alone only produces the distance, not the script.
func myersLineDiff(a, b []string) []diffOp {
	n, m := len(a), len(b)
	maxD := n + m
	if maxD == 0 {
		return nil
	}
	offset := maxD
	v := make([]int, 2*maxD+1)
	trace := make([][]int, 0, maxD+1)

	finalD := -1
outer:
	for d := 0; d <= maxD; d++ {
		snapshot := make([]int, len(v))
		copy(snapshot, v)
		trace = append(trace, snapshot)

		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || (k != d && v[k-1+offset] < v[k+1+offset]) {
				x = v[k+1+offset]
			} else {
				x = v[k-1+offset] + 1
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
			}
			v[k+offset] = x
			if x >= n && y >= m {
				finalD = d
				break outer
			}
		}
	}
	if finalD < 0 {
		// Unreachable given maxD == n+m always suffices to reach (n,m), but a
		// bounded, correct fallback beats a panic if this invariant is ever
		// wrong.
		return commonAffixDiff(a, b)
	}
	return backtrackMyers(a, b, trace, finalD, offset)
}

// backtrackMyers walks the trace produced by myersLineDiff's forward pass from
// (len(a), len(b)) back to (0, 0), one round at a time, recovering which
// snake (run of equal lines) and which single insert-or-delete step joined
// each round to the last — see Myers 1986 §4b, or James Coglan's "The Myers
// diff algorithm" (2017) for a worked walkthrough of exactly this shape of
// trace and backtrack.
func backtrackMyers(a, b []string, trace [][]int, d, offset int) []diffOp {
	x, y := len(a), len(b)
	// Built back-to-front (this walk runs from the END of the files to the
	// START), then reversed once at the end.
	var reversed []diffOp

	for dd := d; dd >= 0; dd-- {
		v := trace[dd]
		k := x - y
		var prevK int
		if k == -dd || (k != dd && v[k-1+offset] < v[k+1+offset]) {
			prevK = k + 1
		} else {
			prevK = k - 1
		}
		prevX := v[prevK+offset]
		prevY := prevX - prevK

		for x > prevX && y > prevY {
			reversed = append(reversed, diffOp{Kind: diffEqual, Text: a[x-1]})
			x--
			y--
		}
		if dd > 0 {
			if x == prevX {
				reversed = append(reversed, diffOp{Kind: diffInsert, Text: b[prevY]})
			} else {
				reversed = append(reversed, diffOp{Kind: diffDelete, Text: a[prevX]})
			}
		}
		x, y = prevX, prevY
	}

	ops := make([]diffOp, len(reversed))
	for i, op := range reversed {
		ops[len(reversed)-1-i] = op
	}
	return ops
}

// commonAffixDiff is the bounded fallback for a pair of files too large for
// myersLineDiff's O((N+M)*D) cost to be worth paying: strip the common prefix
// and common suffix (both O(N+M), no worse than reading the files once) and
// report everything in between as wholesale deleted-then-inserted. This is
// never a MINIMAL diff — it can report a change as touching more lines than a
// human editing one line in the middle of a huge file actually touched — but
// it is always an HONEST one: every line the two files actually disagree on is
// shown, and nothing outside the reported span is claimed to differ. For the
// file sizes this ever triggers on (over maxMyersOps combined lines), that
// tradeoff is the right one for a preview that must still return quickly.
func commonAffixDiff(a, b []string) []diffOp {
	n, m := len(a), len(b)
	prefix := 0
	for prefix < n && prefix < m && a[prefix] == b[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < n-prefix && suffix < m-prefix && a[n-1-suffix] == b[m-1-suffix] {
		suffix++
	}

	ops := make([]diffOp, 0, n+m-prefix-suffix+prefix+suffix)
	for i := 0; i < prefix; i++ {
		ops = append(ops, diffOp{Kind: diffEqual, Text: a[i]})
	}
	for i := prefix; i < n-suffix; i++ {
		ops = append(ops, diffOp{Kind: diffDelete, Text: a[i]})
	}
	for i := prefix; i < m-suffix; i++ {
		ops = append(ops, diffOp{Kind: diffInsert, Text: b[i]})
	}
	for i := n - suffix; i < n; i++ {
		ops = append(ops, diffOp{Kind: diffEqual, Text: a[i]})
	}
	return ops
}

// lineInfo pairs one edit-script operation with its 1-based position in the
// old file, the new file, or both (whichever apply to its kind) — what
// renderUnifiedHunks needs to print "@@ -oldStart,oldCount +newStart,newCount
// @@" headers.
type lineInfo struct {
	op      diffOp
	oldLine int // 1-based; 0 for an insert (no old-file position)
	newLine int // 1-based; 0 for a delete (no new-file position)
}

// renderUnifiedHunks turns an edit script into `git diff`-shaped unified-diff
// text: one or more "@@ ... @@" hunks, each carrying up to `context` unchanged
// lines of padding on either side, with adjacent change-runs merged into one
// hunk when fewer than 2*context unchanged lines separate them (the standard
// unified-diff hunk-merging rule).
func renderUnifiedHunks(ops []diffOp, context int) (string, int, int) {
	infos := make([]lineInfo, len(ops))
	oldN, newN, added, removed := 0, 0, 0, 0
	for i, op := range ops {
		li := lineInfo{op: op}
		switch op.Kind {
		case diffEqual:
			oldN++
			newN++
			li.oldLine, li.newLine = oldN, newN
		case diffDelete:
			oldN++
			li.oldLine = oldN
			removed++
		case diffInsert:
			newN++
			li.newLine = newN
			added++
		}
		infos[i] = li
	}

	var b strings.Builder
	n := len(infos)
	i := 0
	for i < n {
		if infos[i].op.Kind == diffEqual {
			i++
			continue
		}

		start := i
		for start > 0 && i-start < context && infos[start-1].op.Kind == diffEqual {
			start--
		}

		end := i
		for end < n {
			if infos[end].op.Kind != diffEqual {
				end++
				continue
			}
			j := end
			for j < n && infos[j].op.Kind == diffEqual {
				j++
			}
			if j < n && j-end <= 2*context {
				// A close-enough next change: absorb this whole equal run and
				// keep extending the hunk to include it, rather than closing
				// this hunk and immediately reopening a new one three lines
				// later.
				end = j
				continue
			}
			extra := context
			if j-end < extra {
				extra = j - end
			}
			end += extra
			break
		}

		writeHunk(&b, infos, start, end)
		i = end
	}
	return b.String(), added, removed
}

// writeHunk renders infos[start:end] as one "@@ ... @@" hunk.
func writeHunk(b *strings.Builder, infos []lineInfo, start, end int) {
	oldStart, newStart, oldCount, newCount := 0, 0, 0, 0
	for k := start; k < end; k++ {
		if infos[k].oldLine > 0 {
			if oldStart == 0 {
				oldStart = infos[k].oldLine
			}
			oldCount++
		}
		if infos[k].newLine > 0 {
			if newStart == 0 {
				newStart = infos[k].newLine
			}
			newCount++
		}
	}
	// A hunk that is a pure insertion (no old-file lines at all) or a pure
	// deletion (no new-file lines at all) has no old/new line number of its
	// own to anchor on — git's convention is the line AFTER which the
	// insertion/deletion happens, found by looking at the nearest preceding
	// line that does have that side's position.
	if oldStart == 0 {
		oldStart = precedingLine(infos, start, func(li lineInfo) int { return li.oldLine }) + 1
	}
	if newStart == 0 {
		newStart = precedingLine(infos, start, func(li lineInfo) int { return li.newLine }) + 1
	}

	fmt.Fprintf(b, "@@ -%d,%d +%d,%d @@\n", oldStart, oldCount, newStart, newCount)
	for k := start; k < end; k++ {
		switch infos[k].op.Kind {
		case diffEqual:
			fmt.Fprintf(b, " %s\n", infos[k].op.Text)
		case diffDelete:
			fmt.Fprintf(b, "-%s\n", infos[k].op.Text)
		case diffInsert:
			fmt.Fprintf(b, "+%s\n", infos[k].op.Text)
		}
	}
}

func precedingLine(infos []lineInfo, idx int, pos func(lineInfo) int) int {
	for k := idx - 1; k >= 0; k-- {
		if v := pos(infos[k]); v > 0 {
			return v
		}
	}
	return 0
}
