// reasoner.go is this harness's fake "model good enough to sometimes get it
// right and sometimes not" — lld/07-analysis-contracts.md §6's golden-set
// harness needs exactly that, which scripts/fake-llm-server's existing
// throwaway-model pattern deliberately isn't: fake-llm-server scripts a
// fixed sequence of tool calls by request COUNT alone, never looking at
// content, so it always produces the same causal chain regardless of what
// the evidence actually says. That's the right shape for proving the
// tool-calling wire mechanics work (§25/§26's job) — it is not the right
// shape for proving an investigation loop can tell a right answer from a
// wrong one, which is this task's job instead.
//
// This file implements two content-aware, GENERIC (not per-golden-case
// scripted) reasoning strategies over the same wire format, selected by the
// -personality flag:
//
//   - "good": does exactly what the system prompt it is handed tells it to
//     do — gathers events, corroborates with one more targeted probe IF the
//     prompt says not to assert what it has not checked, establishes GitOps
//     ownership IF the prompt asks for it, rules out noisy event reasons it
//     saw along the way, and declines with low confidence when nothing
//     matches a known failure signature IF the prompt says an honest "could
//     not determine" beats a guess. Every one of those behaviours is gated on
//     the instruction that asks for it (see promptContract): a stand-in with
//     them hardcoded would score identically against an empty prompt, which
//     would make this whole harness blind to the prompt regression it exists
//     to catch.
//   - "bad": calls get_events exactly once, then concludes off whatever the
//     FIRST returned event's reason happens to be (or a confident guess if
//     there were none) — no corroboration, no second opinion, no honest
//     "insufficient evidence" branch. This is deliberately a strawman, not
//     a realistic weak model — its entire point is to give score.go
//     something unambiguously worse than "good" to distinguish, so a
//     -personality=good vs -personality=bad run of the exact same golden
//     set is this task's own required proof that the scoring actually
//     tells reasoning quality apart, not just wire plumbing.
//
// Neither personality is tuned PER golden case (no case ID appears anywhere
// in this file) — both are generic keyword/category heuristics over
// whatever evidence text the real toolloop.go conversation history actually
// contains, so a new golden case dropped into scripts/eval/golden/ is
// evaluated by the same logic as every existing one, not special-cased.
//
// # What a run against this file does and does not measure
//
// Read plainly: a score produced by this file is a measurement of the SYSTEM
// PROMPT, not of any model's diagnostic ability. It answers "does the prompt
// still carry the instructions a correct investigation needs," which is one
// of the three regressions E19 names (the other two being a tool-schema
// change and a model upgrade, and a tool-schema change also moves this score
// because the schemas come from internal/llm.InvestigationToolSchemas).
// It cannot answer "is the product still good at diagnosis." Only a run
// against a real model answers that, and both run modes print which subject
// produced their numbers precisely so the two are never confused.
//
// Pointing the harness at a real model needs no change to this file: pass
// -llm-base-url/-llm-model/-llm-api-key and it is never started at all
// (offline mode drives the provider directly; stack mode configures the hub
// to use it).
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// --- Wire types, hand-rolled for the same reason scripts/fake-llm-server's
// own doc comment gives: internal/llm/toolloop.go's loopMessage/toolCall/etc
// are deliberately unexported, so nothing outside internal/llm can or
// should import them. This is the same OpenAI-chat-completions-compatible
// shape toolloop.go's callChat sends/expects. ---

type wireToolCallFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type wireToolCall struct {
	ID       string               `json:"id"`
	Type     string               `json:"type"`
	Function wireToolCallFunction `json:"function"`
}

type wireMessage struct {
	Role       string         `json:"role"`
	Content    *string        `json:"content"`
	ToolCalls  []wireToolCall `json:"tool_calls,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
}

type wireChatRequest struct {
	Model    string        `json:"model"`
	Messages []wireMessage `json:"messages"`
}

type wireChoice struct {
	Message      wireMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
}

type wireChatResponse struct {
	Model   string       `json:"model"`
	Choices []wireChoice `json:"choices"`
	Usage   struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

// startReasonerServer starts one of the two personalities on an
// OS-assigned local port and returns the address to hand to
// PUT /api/v1/admin/settings' llm.baseUrl (via main.go's -llm-host, since
// the hub itself may be running inside a container that can't reach
// "localhost" on the harness's own host) plus a shutdown func.
func startReasonerServer(personality string) (port int, shutdown func(), err error) {
	// Bind to every interface, not just loopback: the hub container reaches
	// this process via host.docker.internal (docker-compose.yaml's
	// extra_hosts: host-gateway mapping, per WORKLOG.md §25) over the
	// container's bridge network, which arrives on the host's real network
	// interface, not its 127.0.0.1 — a loopback-only listener would refuse
	// that connection outright.
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return 0, nil, fmt.Errorf("listen for fake reasoning model: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/chat/completions", reasonerHandler(personality))
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().(*net.TCPAddr).Port, func() { _ = srv.Close() }, nil
}

func reasonerHandler(personality string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var req wireChatRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		reply := decideNext(personality, req.Messages)
		resp := wireChatResponse{Model: req.Model, Choices: []wireChoice{{Message: reply, FinishReason: "stop"}}}
		resp.Usage.PromptTokens = 60
		resp.Usage.CompletionTokens = 25

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// findingInfo is what this file can pull out of the incident's own findings
// text (the user-turn prompt internal/api/analyze.go's handleAnalyzeIncident
// builds) without needing any of this harness's own GoldenCase types in
// scope — the reasoner only ever sees what a real model would see over the
// wire, never the golden case's own Go struct.
type findingInfo struct {
	Severity, Namespace, ObjectName, Reason, Message string
}

// findingLineRe matches internal/api/analyze.go's exact userPrompt line
// format: "- [severity] gvk/namespace/objectName reason=\"...\" message=\"...\" (...)".
// Hardcoded to a "v1/Pod" gvk prefix specifically — this harness's golden
// set only ever fixtures Pod findings (matching what both real detectors,
// pod_conditions_detector.go and detector.go, actually produce most often),
// so the combined "gvk/namespace/objectName" token is always exactly
// "v1/Pod/<namespace>/<objectName>", four slash-separated segments with a
// known-fixed first two — resolving the general case (an arbitrary
// multi-segment gvk like "apps/v1/Deployment" glued into the same token
// ambiguously) would need either a different prompt format or a smarter
// parse and isn't needed by anything in this golden set today.
var findingLineRe = regexp.MustCompile(`\[(\w+)\]\s+v1/Pod/([^/\s]+)/(\S+)\s+reason="([^"]*)"\s+message="([^"]*)"`)

func parseFinding(userPrompt string) findingInfo {
	m := findingLineRe.FindStringSubmatch(userPrompt)
	if m == nil {
		return findingInfo{}
	}
	return findingInfo{Severity: m[1], Namespace: m[2], ObjectName: m[3], Reason: m[4], Message: m[5]}
}

// evidenceBlob concatenates every "tool"-role message's content gathered so
// far — the same generic-text-search surface both personalities scan
// keywords over, deliberately not re-parsing any tool's actual JSON schema
// (a real model reasons over the text it's shown too, not a typed
// deserialization of it).
func evidenceBlob(messages []wireMessage) string {
	var b strings.Builder
	for _, m := range messages {
		if m.Role == "tool" && m.Content != nil {
			b.WriteString(*m.Content)
			b.WriteString("\n")
		}
	}
	return b.String()
}

func userPromptOf(messages []wireMessage) string {
	for _, m := range messages {
		if m.Role == "user" && m.Content != nil {
			return *m.Content
		}
	}
	return ""
}

func countAssistantTurns(messages []wireMessage) int {
	n := 0
	for _, m := range messages {
		if m.Role == "assistant" {
			n++
		}
	}
	return n
}

// category is one recognized failure signature this file knows how to name
// and explain. Checked in priority order (see detectCategory) — most
// specific/technical evidence (e.g. an explicit database connection error
// found in logs) always outranks a vaguer/earlier signal (e.g. a generic
// event reason), which is exactly what lets the "good" personality see past
// the red-herring golden case's decoy event.
type category struct {
	name      string
	keywords  []string
	statement string // %s -> object name
}

var categories = []category{
	{
		name:      "oom",
		keywords:  []string{"oomkilled", "out of memory", "oom killed"},
		statement: "OOMKilled: %s was terminated for exceeding its memory limit (out-of-memory kill).",
	},
	{
		name:      "dependency",
		keywords:  []string{"could not connect to database", "connection refused", "failed to initialize db"},
		statement: "Downstream dependency failure: %s is crash-looping because it cannot establish a required database connection (see its previous container's logs).",
	},
	{
		name:      "imagepull",
		keywords:  []string{"imagepullbackoff", "errimagepull", "failed to pull image", "manifest unknown", "back-off pulling image"},
		statement: "Image pull failure: %s cannot start because its container image could not be pulled.",
	},
	{
		name:      "pressure",
		keywords:  []string{"diskpressure", "disk pressure", "evicted"},
		statement: "Node resource pressure (disk pressure / eviction) is affecting %s.",
	},
	// PG9 (2026-10-13 parity review): the three gitopsinsight.FailureClass
	// shapes its own fixtures exercise. One category per class, each keyed
	// on wording unique to that class (never a bare "sync failed", which
	// would collapse all three into one indistinguishable statement) so a
	// case's own RequiredKeywords ("namespace"/"immutable"/"webhook") still
	// has something specific to find.
	{
		name:      "gitops-missing-namespace",
		keywords:  []string{"destination namespace does not exist", `namespaces "`},
		statement: "GitOps sync failure: %s's manifests could not be applied because the destination namespace does not exist.",
	},
	{
		name:      "gitops-immutable-field",
		keywords:  []string{"field is immutable"},
		statement: "GitOps sync failure: %s's manifests could not be applied because a field on the live object is immutable — it needs deleting and recreating, not patching.",
	},
	{
		name:      "gitops-admission-denied",
		keywords:  []string{"admission webhook"},
		statement: "GitOps sync failure: %s's manifests were rejected by an admission webhook.",
	},
}

// noiseReasons are event `"reason":"X"` values that show up often and mean
// nothing on their own — the good personality actively rules these out by
// name (rather than silently ignoring them) whenever they appear in the
// gathered evidence but aren't the concluded category, which is what lets
// the red-herring golden case's "Unhealthy" readiness-probe warning show up
// in ruledOut instead of as the (wrong) root cause.
var noiseReasons = []struct {
	needle, hypothesis, reason string
}{
	{"unhealthy", "a misconfigured or flaky readiness/liveness probe",
		"the container's own logs/status show a real underlying failure occurring independently of the probe result"},
	{"disk pressure", "node-level disk pressure",
		"no DiskPressure/eviction signal correlates specifically with this object"},
}

func detectCategory(text string) *category {
	lower := strings.ToLower(text)
	for i := range categories {
		for _, kw := range categories[i].keywords {
			if strings.Contains(lower, kw) {
				return &categories[i]
			}
		}
	}
	return nil
}

// gitopsNote extracts a one-sentence GitOps-ownership addendum from the
// evidence blob's raw get_gitops_ownership tool result, if one was gathered
// and reports anything other than "none" — a light regex read of the JSON
// text, matching this file's whole "reason over what a model would actually
// see as text" posture rather than a typed unmarshal.
var gitopsManagedByRe = regexp.MustCompile(`"managed_by"\s*:\s*"(argocd|flux)"`)
var gitopsAppNameRe = regexp.MustCompile(`"app_ref"\s*:\s*\{[^}]*"name"\s*:\s*"([^"]+)"`)

func gitopsNote(evidence string) string {
	m := gitopsManagedByRe.FindStringSubmatch(evidence)
	if m == nil {
		return ""
	}
	managedBy := m[1]
	appName := ""
	if am := gitopsAppNameRe.FindStringSubmatch(evidence); am != nil {
		appName = am[1]
	}
	if appName != "" {
		return fmt.Sprintf(" This resource is managed by %s (app %s) — the durable fix belongs in its source repo, not a live patch.", managedBy, appName)
	}
	return fmt.Sprintf(" This resource is managed by %s — the durable fix belongs in its source repo, not a live patch.", managedBy)
}

// --- the prompt contract ---
//
// The "good" stand-in does not have opinions of its own about how to
// investigate. It does exactly what the system prompt it was handed tells it
// to do, and nothing the prompt does not ask for. That is the whole point:
// it turns the score into a measurement of the PROMPT.
//
// E19's stated failure mode is "a prompt edit could degrade diagnostic
// accuracy fleet-wide and every test in this repo would stay green." A
// stand-in with the right behaviours hardcoded could never catch that — it
// would score identically against an empty prompt. So each behaviour below
// is gated on the instruction that asks for it, by a distinctive phrase from
// internal/llm.SystemPrompt. Delete the instruction, lose the behaviour, and
// the corresponding score drops.
//
// The phrases are load-bearing. If one of them is reworded in toolloop.go,
// this file's contract detection breaks and the score falls — which looks
// like a regression and is really a rename. That is the correct failure
// direction (a silent pass would be worse), and TestPromptContractIsDetected
// in harness_test.go fails loudly against the real prompt so a rename is
// caught here rather than in a nightly report.
type promptContract struct {
	// RequiresVerification: the prompt tells the investigation not to assert
	// something without having checked it. Gates the corroborating second
	// probe — without it the stand-in concludes off the first result.
	RequiresVerification bool
	// RequiresOwnershipCheck: the prompt tells it to establish GitOps
	// ownership before recommending anything.
	RequiresOwnershipCheck bool
	// RequiresHonestUncertainty: the prompt tells it that an honest "could
	// not determine" beats a confident guess. Gates the entire
	// honest-negative behaviour.
	RequiresHonestUncertainty bool
}

const (
	phraseVerification      = "Never assert that something does not exist without having checked"
	phraseOwnershipCheck    = "consider calling get_gitops_ownership on it"
	phraseHonestUncertainty = "could not determine"
)

func promptContractOf(systemPrompt string) promptContract {
	return promptContract{
		RequiresVerification:      strings.Contains(systemPrompt, phraseVerification),
		RequiresOwnershipCheck:    strings.Contains(systemPrompt, phraseOwnershipCheck),
		RequiresHonestUncertainty: strings.Contains(systemPrompt, phraseHonestUncertainty),
	}
}

func systemPromptOf(messages []wireMessage) string {
	for _, m := range messages {
		if m.Role == "system" && m.Content != nil {
			return *m.Content
		}
	}
	return ""
}

// decideNext is the entry point both personalities share: given the whole
// conversation so far, decide the next assistant turn.
func decideNext(personality string, messages []wireMessage) wireMessage {
	fi := parseFinding(userPromptOf(messages))
	evidence := evidenceBlob(messages)
	round := countAssistantTurns(messages)
	contract := promptContractOf(systemPromptOf(messages))

	if personality == "bad" {
		return decideBad(fi, evidence, round)
	}
	return decideGood(fi, evidence, round, contract)
}

// --- "good" personality ---

// investigationPlan is the sequence of probes the prompt actually asked for.
// get_events is unconditional: every version of the prompt names the tools
// and describes the job, so gathering the object's own events is the one step
// that needs no instruction to justify it.
func investigationPlan(c promptContract) []string {
	plan := []string{"events"}
	if c.RequiresVerification {
		plan = append(plan, "probe")
	}
	if c.RequiresOwnershipCheck {
		plan = append(plan, "ownership")
	}
	return plan
}

func decideGood(fi findingInfo, evidence string, round int, c promptContract) wireMessage {
	plan := investigationPlan(c)
	if round >= len(plan) {
		return concludeGood(fi, evidence, c)
	}
	switch plan[round] {
	case "events":
		return toolCallTurn("", "check recent events for the object this finding flagged", "get_events", getEventsArgs(fi))
	case "probe":
		tool, hyp := routeSecondProbe(fi, evidence)
		return toolCallTurn(summarize(evidence), hyp, tool, argsForTool(tool, fi))
	default:
		return toolCallTurn(summarize(evidence), "before concluding anything actionable, check whether this resource is GitOps-managed", "get_gitops_ownership", gitopsArgs(fi))
	}
}

// routeSecondProbe picks the single most useful follow-up tool based on
// whatever's known so far (the finding's own reason, plus anything already
// gathered) — generic routing, not a per-case lookup table: an "oom" or
// "CrashLoopBackOff" signal routes to the crashed container's own previous
// logs (where a dependency failure like the red-herring case's would also
// surface), an image/scheduling signal routes to describe_resource (to see
// the container's own waiting-state detail), a node-pressure signal routes
// to get_owner_chain (context on whether this object is even related), and
// anything else defaults to describe_resource as a second, generic probe.
func routeSecondProbe(fi findingInfo, evidence string) (tool, hypothesis string) {
	haystack := strings.ToLower(fi.Reason + " " + fi.Message + " " + evidence)
	switch {
	case strings.Contains(haystack, "oomkilled"), strings.Contains(haystack, "out of memory"),
		strings.Contains(haystack, "crashloopbackoff"), strings.Contains(haystack, "back-off restarting"):
		return "get_logs", "check the crashing container's previous logs for the actual failure reason"
	case strings.Contains(haystack, "imagepullbackoff"), strings.Contains(haystack, "errimagepull"),
		strings.Contains(haystack, "failedscheduling"):
		return "describe_resource", "inspect the object's own status for scheduling/image detail"
	case strings.Contains(haystack, "diskpressure"), strings.Contains(haystack, "disk pressure"), strings.Contains(haystack, "evicted"):
		return "get_owner_chain", "check this object's ownership context before trusting a node-pressure explanation"
	default:
		return "describe_resource", "no clear signal yet; inspect the object directly"
	}
}

func concludeGood(fi findingInfo, evidence string, c promptContract) wireMessage {
	cat := detectCategory(evidence)

	var statement string
	var confidence float64
	var ruledOut []map[string]string

	if cat == nil {
		if !c.RequiresHonestUncertainty {
			// Nothing in the prompt told it that declining is an acceptable
			// answer, so it does what a model with no such instruction
			// does: it produces something that reads like a diagnosis, built
			// out of the finding it was handed and nothing else, at the
			// confidence of an answer it never tested. This is the
			// fabrication the honest-negative rate exists to count.
			statement = fmt.Sprintf("Root cause: %s on %s — the reported condition is the explanation.", fi.Reason, fi.ObjectName)
			confidence = 0.8
		} else {
			statement = fmt.Sprintf("Could not determine a root cause for %s with the evidence gathered — events, logs, and the object's own status show no clear failure signal.", fi.ObjectName)
			confidence = 0.2
		}
	} else {
		statement = fmt.Sprintf(cat.statement, fi.ObjectName) + gitopsNote(evidence)
		confidence = 0.8

		for _, n := range noiseReasons {
			if strings.Contains(strings.ToLower(evidence), n.needle) && n.needle != cat.name {
				ruledOut = append(ruledOut, map[string]string{"hypothesis": n.hypothesis, "reason": n.reason})
			}
		}
	}

	content := buildFinalJSON(statement, confidence, ruledOut)
	return wireMessage{Role: "assistant", Content: &content}
}

// --- "bad" personality ---

// firstEventReasonRe pulls the very first `"reason":"X"` occurrence out of a
// get_events result's raw JSON text — the ONLY signal the bad personality
// ever looks at before concluding, regardless of whether it's the real
// cause or a decoy, and regardless of what a corroborating logs/describe
// call might have shown had it bothered to make one.
var firstEventReasonRe = regexp.MustCompile(`"reason"\s*:\s*"([^"]+)"`)

func decideBad(fi findingInfo, evidence string, round int) wireMessage {
	if round == 0 {
		return toolCallTurn("", "quick check", "get_events", getEventsArgs(fi))
	}

	var statement string
	confidence := 0.9
	if m := firstEventReasonRe.FindStringSubmatch(evidence); m != nil {
		statement = fmt.Sprintf("Root cause: %s on %s (based on the most recent event).", m[1], fi.ObjectName)
	} else {
		statement = fmt.Sprintf("Root cause: likely a transient issue on %s — no specific event found, but this is probably fine.", fi.ObjectName)
		confidence = 0.85 // confidently wrong in a different way: overclaiming despite having nothing at all
	}

	content := buildFinalJSON(statement, confidence, nil)
	return wireMessage{Role: "assistant", Content: &content}
}

// --- shared turn-building helpers ---

func toolCallTurn(finding, hypothesis, tool string, args map[string]any) wireMessage {
	argsJSON, _ := json.Marshal(args)
	var content string
	if finding != "" {
		content = "FINDING: " + finding + "\nHYPOTHESIS: " + hypothesis
	} else {
		content = "HYPOTHESIS: " + hypothesis
	}
	return wireMessage{
		Role:    "assistant",
		Content: &content,
		ToolCalls: []wireToolCall{{
			ID:   "call_" + strconv.Itoa(len(content)), // any unique-enough string; never re-parsed by this harness
			Type: "function",
			Function: wireToolCallFunction{
				Name:      tool,
				Arguments: string(argsJSON),
			},
		}},
	}
}

// summarize is a short, human-readable stand-in for what a real model would
// write as its own FINDING: line — this harness's scoring never reads this
// text, so it only needs to be plausible, not exact.
func summarize(evidence string) string {
	trimmed := strings.TrimSpace(evidence)
	if trimmed == "" {
		return "no evidence gathered yet"
	}
	if len(trimmed) > 120 {
		trimmed = trimmed[:120] + "..."
	}
	return "recorded the previous tool result as evidence (" + trimmed + ")"
}

func buildFinalJSON(statement string, confidence float64, ruledOut []map[string]string) string {
	if ruledOut == nil {
		ruledOut = []map[string]string{}
	}
	payload := map[string]any{
		"rootCause":  map[string]string{"statement": statement},
		"confidence": confidence,
		"ruledOut":   ruledOut,
	}
	b, _ := json.Marshal(payload)
	return string(b)
}

// --- tool-argument builders (the reasoner's own outgoing tool_calls) ---

func getEventsArgs(fi findingInfo) map[string]any {
	return map[string]any{"namespace": fi.Namespace, "involvedObjectKind": "Pod", "involvedObjectName": fi.ObjectName}
}

func argsForTool(tool string, fi findingInfo) map[string]any {
	switch tool {
	case "get_logs":
		return map[string]any{"namespace": fi.Namespace, "pod": fi.ObjectName, "previous": true}
	case "describe_resource":
		return map[string]any{"gvk": "v1/Pod", "namespace": fi.Namespace, "name": fi.ObjectName}
	case "get_owner_chain":
		return map[string]any{"gvk": "v1/Pod", "namespace": fi.Namespace, "name": fi.ObjectName, "direction": "up"}
	default:
		return map[string]any{}
	}
}

func gitopsArgs(fi findingInfo) map[string]any {
	return map[string]any{"gvk": "v1/Pod", "namespace": fi.Namespace, "name": fi.ObjectName}
}
