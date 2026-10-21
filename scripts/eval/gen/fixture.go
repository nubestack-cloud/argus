// fixture.go is the mapping: one catalogue entry in, one golden eval case
// out. Every field of the fixture is derived here, and every derivation is
// named, because the corpus is only as trustworthy as this file is honest.
//
// # What a generated case actually tests
//
// A catalogue entry records the SIGNAL you observe and the SET of root causes
// that signal can have. It does not record a cluster. So the fixture this
// file builds presents the stated signal through the real tool surface
// (an Event, the object's own status) and grades whether the investigation
// commits to one of the catalogue's candidate root causes for it.
//
// That is a knowledge-and-reasoning test over STATED signals. It is NOT a
// test over real recorded cluster output, and it cannot be, because no
// recording exists: the toolResponses below are synthesized from an entry's
// own `signals` string. They are deliberately not dressed up to look like a
// kubectl capture — the object and namespace names say "eval", the Event
// carries the catalogue's signal text verbatim, and every emitted file
// carries the limitation sentence in a top-level field. A green score on
// this corpus means "the investigation still maps known signals to known
// causes"; it does not mean "the investigation still works on a real
// cluster," and nothing in this pipeline should be allowed to imply that it
// does.
//
// # What is deliberately NOT derived
//
//   - forbiddenKeywords stays empty. A red-herring case needs a decoy that a
//     human chose to be plausible-but-wrong; synthesizing one would mean
//     inventing evidence, which is the one thing this generator must not do.
//     The hand-written corpus carries the red-herring case.
//   - requiredKeywords (the ALL-of list) stays empty. An auto-derived
//     conjunction fails correct answers for phrasing reasons, which would
//     make the score move for reasons that have nothing to do with the
//     product.
//   - severity is not a catalogue field at all. It is mapped from `risk`
//     below, and that mapping is a convention of this generator, not a fact
//     from the catalogue.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"argus/scripts/eval/casefmt"
)

// LimitationSentence is reproduced into every generated case file and
// reprinted by the harness above any report that includes one. Kept as one
// exported constant so the wording cannot drift between the two places a
// reader meets it.
const LimitationSentence = "Synthesized from issue-catalog metadata, not from recorded cluster output: the toolResponses below present this entry's STATED signals through the real tool surface. This case grades whether the investigation maps a known signal to one of the catalogue's candidate root causes. It does not prove anything about behaviour on a real cluster, and a green score on it must not be read as cluster coverage."

// fixedTimestamp keeps regeneration byte-identical. A real timestamp would
// make every regeneration a diff, which would make a `-check` run useless as
// a drift detector.
const fixedTimestamp = "2026-09-23T00:00:00Z"

// candidateToken is any word that could be a Kubernetes reason string;
// kubernetesReason decides whether it actually is one.
var candidateToken = regexp.MustCompile(`\b[A-Z][A-Za-z0-9]+\b`)

// kubernetesReason finds a Kubernetes-reason-shaped token inside a catalogue
// signal string — FailedScheduling, OOMKilled, EndpointSlice.
//
// Shaped like one, not verified to be one: the token is lifted from the
// catalogue's own prose, so it is usually a real Event reason and sometimes
// (e.g. "GatewayClass" out of "GatewayClass Accepted=False") an object kind
// the sentence happened to start with. That is a known imprecision of a
// generated corpus and it is left visible rather than papered over with a
// hardcoded per-issue reason table, which would make the corpus a list of
// answers someone typed instead of a mapping anyone can re-derive.
//
// The test is deliberately strict: at least five characters, at least two
// capitals, and at least one lowercase. A looser one scraped acronyms out of
// prose ("IP", "LB", "CRD", "NOSPACE", "RSS") and put them in an Event's
// reason field, which no cluster would ever produce — an invented signal
// dressed as a real one, which is exactly what this generator must not emit.
// A signal with no such token gets no Event at all; see BuildCase.
func kubernetesReason(text string) string {
	for _, w := range candidateToken.FindAllString(text, -1) {
		if len([]rune(w)) < 5 {
			continue
		}
		uppers, lowers := 0, 0
		for _, r := range w {
			switch {
			case r >= 'A' && r <= 'Z':
				uppers++
			case r >= 'a' && r <= 'z':
				lowers++
			}
		}
		if uppers >= 2 && lowers >= 1 {
			return w
		}
	}
	return ""
}

var wordToken = regexp.MustCompile(`[A-Za-z][A-Za-z0-9./-]*`)

// stopwords are words that carry no diagnostic content. A term drawn from a
// root cause that survives this list is a term a correct statement about that
// root cause would plausibly contain.
var stopwords = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`
a an the and or but not no nor so yet for of in on at to from by with without
is are was were be been being has have had do does did can could may might
must shall should will would this that these those it its their there here
as if then than when while where which who whom whose what why how
above below other others another same different both each every any some all
more most less least many much few several via per into onto over under
genuinely really simply often actually likely probably possibly usually
still already never always sometimes recently recent new newer old older
set sets setting sett get gets got make makes made take takes taken
too very just only even also rather instead e.g i.e etc vs
wrong bad good large small high low big long short slow fast
issue issues problem problems failure failures error errors fault faults
cause causes reason reasons result results due
one two three first second third
`) {
		stopwords[w] = true
	}
	// Near-universal Kubernetes nouns. A term this generic appears in almost
	// any root-cause statement about almost any fault, so grading on it would
	// pass an answer that is about entirely the wrong thing. Excluded from
	// term derivation only — they remain perfectly good words for a statement
	// to contain, they are just worthless as discriminators.
	for _, w := range strings.Fields(`
cluster clusters kubernetes k8s node nodes pod pods container containers
namespace namespaces workload workloads object objects resource resources
system deployment deployments
`) {
		stopwords[w] = true
	}
}

// technicalVocabulary are terms whose presence in a statement is strong
// evidence the statement is about the right mechanism. Scored above a plain
// content word so that "Pool too small" yields "pool" rather than "small".
var technicalVocabulary = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`
selector selectors label labels annotation annotations taint taints toleration
tolerations affinity anti-affinity topology zone quota limitrange limit limits
request requests replica replicas revision rollout image tag digest registry
secret configmap volume mount mounts pvc pv storageclass provisioner attach
detach filesystem inode webhook admission policy rbac role rolebinding
serviceaccount token certificate cert expiry expired renewal ca tls sni
ingress gateway route httproute listener backend endpoint endpointslice
port nodeport targetport probe liveness readiness startup timeout deadline
dns ndots resolv search upstream cidr mtu netpol networkpolicy iptables ipvs
conntrack finalizer crd controller operator reconcile sync drift prune
helm chart values kustomize overlay patch manifest repository commit
autoscaler hpa vpa keda metrics utilization scale scaling capacity headroom
memory cpu oom oomkilled throttle throttling ephemeral disk pressure eviction
evicted preemption priority pdb disruption budget
kubelet containerd runtime cgroup cgroups sandbox cni csi device plugin
pool connection connections leak leaks pool-size backlog queue concurrency
schema version deprecated removed api apiversion field spec status condition
typo mismatch mismatched missing absent duplicate conflict conflicting
leak leaks stale drift paused cordon cordoned orphaned unbounded
permission permissions denied forbidden unauthorized credentials auth
fragmentation bin-packing scheduling scheduler unschedulable pending
`) {
		technicalVocabulary[w] = true
	}
}

// DistinguishingTerms derives the anyOf keyword set for an entry: one term per
// candidate root cause, each a word a statement naming that cause would
// plausibly use, and none of them a word the investigation was already handed
// in the finding itself.
//
// The last clause is the point. If a term also appears in the signal text the
// fixture shows the model, then echoing the finding back would score as a
// correct diagnosis — the corpus would be grading transcription, not
// reasoning. Terms already present in the prompt are dropped for that reason,
// even when they are the most natural word for the cause.
func DistinguishingTerms(e Entry) []string {
	// Substring, not word equality: the scorer matches keywords as
	// substrings (so that "oom" catches "OOMKilled"), so a term has to be
	// absent from the handed text the same way. Word equality let "replica"
	// through against a finding that said "under-replicated", which the
	// scorer would then have matched on the echo.
	handed := strings.ToLower(e.Issue + " " + e.Signals)

	var out []string
	seen := map[string]bool{}
	for _, rc := range e.RootCauses {
		term := bestTerm(rc, handed)
		if term == "" || seen[term] {
			continue
		}
		seen[term] = true
		out = append(out, term)
	}
	sort.Strings(out)
	return out
}

// bestTerm picks the single most diagnostic word out of one root-cause
// phrase: technical vocabulary first, then an identifier-shaped token
// (hyphenated, dotted, or originally capitalised), then the longest plain
// content word. Words already handed to the model, stopwords, and anything
// under four characters are excluded.
func bestTerm(phrase, handed string) string {
	type scored struct {
		word  string
		tier  int
		runes int
	}
	var best *scored
	for _, token := range wordToken.FindAllString(phrase, -1) {
		// A slash in a catalogue phrase is an "or" between two alternatives
		// ("NFS/CSI unmount blocked", "no compaction/defrag"), never part of
		// one word. Keeping it whole would produce a term no real statement
		// could ever contain, which is a case that fails every answer.
		for _, raw := range strings.Split(token, "/") {
			w := strings.ToLower(strings.Trim(raw, ".,;:"))
			// Length floors by how discriminating the shape of the word is.
			// A plain content word has to be long enough not to be an
			// accident: "down", "full" and "loss" are all real words from
			// real root causes, and all three would pass a statement about
			// something else entirely (and, since the scorer matches on
			// substrings so that "oom" catches "OOMKilled", "down" would also
			// pass on "downstream"). An all-caps acronym (NFS, OOM, CSI, RSS)
			// or a known technical term carries its meaning at three.
			minLen := 5
			switch {
			case technicalVocabulary[w], raw == strings.ToUpper(raw) && raw != strings.ToLower(raw):
				minLen = 3
			case strings.ContainsAny(raw, "-."):
				minLen = 4
			}
			if len(w) < minLen || stopwords[w] || strings.Contains(handed, w) {
				continue
			}
			tier := 1
			switch {
			case technicalVocabulary[w]:
				tier = 3
			case strings.ContainsAny(raw, "-.") || (raw != strings.ToLower(raw) && raw != strings.ToUpper(raw)) || raw == strings.ToUpper(raw):
				tier = 2
			}
			cand := scored{word: w, tier: tier, runes: len([]rune(w))}
			if best == nil || cand.tier > best.tier || (cand.tier == best.tier && cand.runes > best.runes) {
				c := cand
				best = &c
			}
		}
	}
	if best == nil {
		return ""
	}
	return best.word
}

// declarativeStateSignal matches a signal that simply STATES the object's
// configured field ("spec.paused: true", "unschedulable: true",
// "failurePolicy=Fail"). See Gradable for why that disqualifies an entry from
// the honest-negative corpus.
var declarativeStateSignal = regexp.MustCompile(`[A-Za-z][A-Za-z0-9.]*\s*[:=]\s*(true|false|[0-9]+)\b`)

// Gradable reports whether an entry can become a case that is actually
// scorable — and, for a silent entry, whether declining is unambiguously the
// RIGHT answer, which is a stronger requirement than it first looks.
//
// A non-silent entry needs at least two distinguishing terms. One term makes
// the anyOf check a coin-flip on phrasing, which would move the score for
// reasons that are not the product's.
//
// A silent entry needs its signal to be a SYMPTOM rather than a statement of
// the object's own configured state. "Steadily rising RSS, periodic OOMKill"
// is a symptom: the catalogue's candidate causes for it (unbounded cache,
// listener leak, native allocation) are not reachable from any read-only tool
// this product has, so declining is correct. "spec.paused: true" is not a
// symptom — reading that field IS the diagnosis, and an investigation that
// declined on it would be wrong. Grading the second kind as an
// honest-negative would punish the right answer, so those entries are
// excluded from the corpus rather than quietly mis-graded.
func Gradable(e Entry) bool {
	if strings.TrimSpace(e.Signals) == "" || strings.TrimSpace(e.Issue) == "" {
		return false
	}
	if e.Silent {
		return len(e.RootCauses) > 0 && !declarativeStateSignal.MatchString(e.Signals)
	}
	return len(DistinguishingTerms(e)) >= 2
}

// recurrenceMarker is the catalogue's own "⟳" glyph, which it appends to a
// signal that repeats rather than fires once. It is a notation for a human
// reader, not something that would ever appear in an Event message, so it is
// stripped out of the text the fixture presents and carried instead where it
// actually belongs: the finding's occurrence count.
const recurrenceMarker = "⟳"

func signalText(e Entry) (text string, recurring bool) {
	recurring = strings.Contains(e.Signals, recurrenceMarker)
	text = strings.TrimSpace(strings.ReplaceAll(e.Signals, recurrenceMarker, ""))
	text = strings.TrimRight(text, " ;,")
	return text, recurring
}

// reasonToken is the Event `reason` the fixture presents. Taken from the
// catalogue's own signal text where it contains a Kubernetes-shaped reason,
// which is most of the time; otherwise from the issue name; otherwise a
// token that says plainly what it is, because an invented-but-plausible
// reason string would be exactly the fabrication this generator refuses.
// sweepReason is the reason on a finding that no Event announced: the
// periodic sweep noticed the object's state directly. Used for every silent
// entry, and for a non-silent entry whose catalogue signal contains no
// Kubernetes reason string — in both cases inventing one would be worse than
// saying plainly which detector saw this.
const sweepReason = "SweepObservation"

func reasonToken(e Entry) string {
	if e.Silent {
		return sweepReason
	}
	if m := kubernetesReason(e.Signals); m != "" {
		return m
	}
	if m := kubernetesReason(e.Issue); m != "" {
		return m
	}
	return sweepReason
}

// severityForRisk maps the catalogue's `risk` (how dangerous the FIX is) onto
// an incident severity (how bad the FAULT is). Those are not the same axis
// and the catalogue records only the first, so this is a convention of this
// generator: it exists so the corpus spans severities rather than pinning
// every case to one, and nothing downstream should read it as a catalogue
// fact.
func severityForRisk(risk string) string {
	switch risk {
	case "forbidden", "high":
		return "critical"
	case "medium":
		return "high"
	default:
		return "medium"
	}
}

// detectorFor picks which of the agent's real detector IDs would plausibly
// have raised this finding (internal/agent): the warning-events watch when
// the signal is event-shaped, the periodic sweep otherwise — a silent fault
// is, by definition, one no event announces.
func detectorFor(e Entry) string {
	if reasonToken(e) == sweepReason {
		return "k8s-sweep"
	}
	return "k8s-warning-events"
}

func slug(s string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// objectSuffix is a deterministic five-hex-character tail so the fixture's
// object name has the shape of a real pod name without pretending to be one.
func objectSuffix(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])[:5]
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("gen: marshal fixture payload: %v", err))
	}
	return b
}

// BuildCase is the mapping proper.
func BuildCase(sel Selection) casefmt.Case {
	e := sel.Entry
	id := "catalog-" + strings.ToLower(e.ID)
	namespace := "eval-" + strings.ToLower(e.Category)
	object := strings.ToLower(e.ID) + "-" + objectSuffix(e.ID)
	reason := reasonToken(e)
	signals, recurring := signalText(e)
	message := e.Issue + " — " + signals
	occurrences := 1
	if recurring {
		occurrences = 6
	}

	gitops := json.RawMessage(`{"managed_by":"none"}`)
	if cc := channelClass(e); cc == "pullRequest" || cc == "paired" {
		gitops = mustJSON(map[string]any{
			"managed_by": "argocd",
			"app_ref":    map[string]any{"name": slug(e.Category) + "-app", "namespace": "argocd"},
		})
	}

	podObject := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": object, "namespace": namespace},
	}

	tools := map[string][]casefmt.ToolResponseEntry{}

	if e.Silent {
		// A silent fault is one the seven read-only tools do not surface.
		// The fixture models that observability, not the fault: every probe
		// comes back clean, and the correct answer is to decline rather than
		// to pick a candidate cause off the catalogue's list that nothing in
		// the evidence supports.
		podObject["status"] = map[string]any{"phase": "Running"}
		tools["get_events"] = []casefmt.ToolResponseEntry{{Data: json.RawMessage(`[]`)}}
		tools["get_logs"] = []casefmt.ToolResponseEntry{{Data: json.RawMessage(`{"lines":[]}`)}}
		tools["describe_resource"] = []casefmt.ToolResponseEntry{{Data: mustJSON(map[string]any{"object": podObject, "events": []any{}})}}
		tools["get_owner_chain"] = []casefmt.ToolResponseEntry{{Data: json.RawMessage(`[]`)}}
		tools["list_resources"] = []casefmt.ToolResponseEntry{{Data: json.RawMessage(`[]`)}}
		tools["get_gitops_ownership"] = []casefmt.ToolResponseEntry{{Data: gitops}}
	} else {
		hasEvent := reason != sweepReason
		event := map[string]any{
			"namespace":          namespace,
			"involvedObjectKind": "Pod",
			"involvedObjectName": object,
			"reason":             reason,
			"message":            signals,
			"type":               "Warning",
			"count":              occurrences,
			"lastTimestamp":      fixedTimestamp,
		}
		podObject["status"] = map[string]any{
			"phase": "Pending",
			"conditions": []any{map[string]any{
				"type":    "Ready",
				"status":  "False",
				"reason":  reason,
				"message": signals,
			}},
		}
		// No Kubernetes reason string in the catalogue's signal means no
		// Event: the sweep detector saw the object's own state, and the
		// object's status is where that evidence belongs. Emitting an Event
		// with a made-up reason would be a fabricated capture.
		events := []any{}
		if hasEvent {
			events = append(events, event)
		}
		tools["get_events"] = []casefmt.ToolResponseEntry{{Data: mustJSON(events)}}
		tools["describe_resource"] = []casefmt.ToolResponseEntry{{Data: mustJSON(map[string]any{"object": podObject, "events": events})}}
		// No log lines. The catalogue records a signal and a set of candidate
		// causes; it does not record what the container printed, and writing
		// a plausible log line here would be inventing the evidence the case
		// is supposed to test reasoning over.
		tools["get_logs"] = []casefmt.ToolResponseEntry{{Data: json.RawMessage(`{"lines":[]}`)}}
		tools["get_owner_chain"] = []casefmt.ToolResponseEntry{{Data: json.RawMessage(`[]`)}}
		tools["list_resources"] = []casefmt.ToolResponseEntry{{Data: json.RawMessage(`[]`)}}
		tools["get_gitops_ownership"] = []casefmt.ToolResponseEntry{{Data: gitops}}
	}

	expected := casefmt.ExpectedOutcome{
		// [2, 8]: 8 is internal/llm.DefaultMaxIterations, and the lower bound
		// only catches a conclusion drawn with no evidence gathered at all.
		// Deliberately wide — a generated case is a correctness fixture, not
		// an efficiency fixture, and a tight band here would make the
		// efficiency rate a measure of the band rather than of the product.
		MinIterations: 2,
		MaxIterations: 8,
	}
	if e.Silent {
		expected.Type = casefmt.ExpectInsufficient
		expected.MaxConfidenceForInsufficient = 0.4
	} else {
		expected.Type = casefmt.ExpectDefinite
		expected.AnyOfKeywords = DistinguishingTerms(e)
		expected.MinConfidence = 0.5
	}

	where := e.CategoryName
	if e.Subsection != "" {
		where += " / " + e.Subsection
	}
	description := fmt.Sprintf(
		"%s: %s. Catalogue entry %s (category %s, rank %d of the catalogue's categories by size, %d entries; silent=%t, risk=%s, channels=%s). Selected because it %s. Correct answer: %s.",
		where, e.Issue, e.ID, e.Category, sel.Rank, sel.CatSize, e.Silent, e.Risk, strings.Join(e.Channels, "+"), sel.Why,
		correctAnswerSummary(e),
	)

	return casefmt.Case{
		ID:           id,
		Description:  description,
		Provenance:   casefmt.ProvenanceCatalog,
		CatalogID:    e.ID,
		Category:     e.Category,
		CategoryName: e.CategoryName,
		Limitation:   LimitationSentence,
		Finding: casefmt.Finding{
			DetectorID:      detectorFor(e),
			Severity:        severityForRisk(e.Risk),
			Namespace:       namespace,
			ObjectName:      object,
			Reason:          reason,
			Message:         message,
			OccurrenceCount: occurrences,
		},
		ToolResponses: tools,
		Expected:      expected,
	}
}

func correctAnswerSummary(e Entry) string {
	if e.Silent {
		return "an honest \"could not determine\" at low confidence — every probe this fixture answers comes back clean, which is what makes this a silent fault, and naming a cause off the catalogue's list anyway would be a guess the evidence does not support"
	}
	return "a statement naming one of the catalogue's candidate root causes for this signal (" + strings.Join(e.RootCauses, "; ") + ")"
}
