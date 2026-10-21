// Package health classifies the health of individual Kubernetes objects —
// pods, replica workloads, batch objects, PVCs and nodes — from their status
// alone. It is pure: every function takes a typed object (and, where age
// matters, an injected clock) and returns a verdict, so the agent's tools,
// detectors and the relationship map grade the same object the same way.
//
// Health LEVEL here ("how is this object doing") is distinct from finding
// SEVERITY, which is owned by the detectors and the hub. This package never
// ranks findings.
package health

// Level is how an object is doing, in one of five words ordered by Rank.
// The words are wire values the web UI matches on.
type Level string

// The levels, from benign to worst.
const (
	LevelHealthy Level = "healthy" // known to be fine
	// Off or finished on purpose (scaled to zero, suspended, completed,
	// idle): as benign as healthy, so it trips no filter or rollup.
	LevelNeutral Level = "neutral"
	// Nothing to judge by. Above healthy, so missing data never rolls up as
	// fine; below every real impairment.
	LevelUnknown   Level = "unknown"
	LevelDegraded  Level = "degraded"  // partly impaired, or a passing problem past its grace
	LevelUnhealthy Level = "unhealthy" // failing: a crash loop, an OOM, a fatal wait, nothing ready
)

// levelRank is each level's place, worst highest. Healthy and neutral share
// the bottom: a set of things all off on purpose is benign.
var levelRank = map[Level]int{LevelHealthy: 0, LevelNeutral: 0, LevelUnknown: 1, LevelDegraded: 2, LevelUnhealthy: 3}

// Rank orders levels for worst-of aggregation. A word not in the vocabulary
// ranks as unknown: quieter than any impairment, never passed off as
// healthy.
func Rank(l Level) int {
	if r, ok := levelRank[l]; ok {
		return r
	}
	return levelRank[LevelUnknown]
}

// WorseOf is the more severe of two levels, whichever order they come in. An
// empty level has no opinion and the other wins. Healthy and neutral rank
// alike, and between them healthy wins, so that running beside switched-off
// reads healthy and only all switched-off reads neutral; every other rank
// belongs to one level.
func WorseOf(a, b Level) Level {
	switch ra, rb := Rank(a), Rank(b); {
	case a == "":
		return b
	case b == "":
		return a
	case ra != rb:
		if rb > ra {
			return b
		}
		return a
	case ra == 0 && (a == LevelHealthy || b == LevelHealthy):
		return LevelHealthy
	}
	return a
}

// Verdict is a classification: the Level; a short machine Reason
// ("CrashLoopBackOff", "Completed") unless plainly healthy; and the
// kubelet's or controller's own Message behind it, when there is one.
type Verdict struct {
	Level   Level  `json:"level"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}
