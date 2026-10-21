// Command fake-llm-server is a throwaway test-support tool, not a product
// binary (hence living under scripts/, not cmd/ — same convention as
// scripts/simulate-finding) — it exists so scripts/smoke-test.sh (and this
// task's own live-stack verification) can exercise
// internal/llm.Provider.Investigate's real bounded tool-calling loop end to
// end against something that actually speaks the OpenAI-chat-completions
// tool-calling wire format, without needing a real hosted or self-hosted
// model.
//
// Unlike simulate-finding, this can't import internal/llm's wire types
// directly — they're deliberately unexported (internal/llm/toolloop.go's
// loopMessage/toolCall/etc.), since nothing outside that package is meant to
// depend on their exact shape. This file hand-rolls the same wire shape
// instead, which is the correct posture for a tool standing in for an
// external system anyway: a real self-hosted model server wouldn't import
// this repo's Go types either.
//
// Two scripted modes:
//
//   - "toolloop" (default): requests get_events, then get_owner_chain, then
//     get_logs — three real tool calls, each routed by the hub over the
//     real mTLS tunnel to whatever real agent is connected — before
//     concluding with a low-confidence root cause (this sandbox has no real
//     Kubernetes cluster behind the agent, so the honest thing for a real
//     model to do with three "no reachable cluster"/empty tool results is
//     say so, not fabricate confidence).
//   - "never-conclude": always requests another get_events call, no matter
//     what came back — used to drive internal/llm's iteration bound and
//     confirm the resulting PartialAnalysis shape.
//
// Usage:
//
//	go run ./scripts/fake-llm-server -addr :9091 -mode toolloop
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
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sync"
)

type toolCallFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type toolCall struct {
	ID       string           `json:"id"`
	Type     string           `json:"type"`
	Function toolCallFunction `json:"function"`
}

// chatRequest only decodes enough of the real request to log it usefully —
// this server's responses are scripted by request count, not by inspecting
// message content, so nothing here needs the full shape.
type chatRequest struct {
	Model    string `json:"model"`
	Messages []struct {
		Role string `json:"role"`
	} `json:"messages"`
}

type assistantMessage struct {
	Role      string     `json:"role"`
	Content   *string    `json:"content"`
	ToolCalls []toolCall `json:"tool_calls,omitempty"`
}

type choice struct {
	Message      assistantMessage `json:"message"`
	FinishReason string           `json:"finish_reason"`
}

type chatResponse struct {
	Model   string   `json:"model"`
	Choices []choice `json:"choices"`
	Usage   struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		// PromptTokensDetails.CachedTokens is the standard OpenAI extension
		// field internal/llm's chatUsageWire parses to populate
		// analyses.tokens_cache_read — included here (rather than an
		// omitted/all-zero usage block) so this fake server actually
		// exercises that parsing path end to end, the way a real hosted
		// provider's response would once the stable system+facts prefix
		// starts getting cache-hit on the 2nd+ call of an investigation.
		PromptTokensDetails *struct {
			CachedTokens int `json:"cached_tokens"`
		} `json:"prompt_tokens_details,omitempty"`
	} `json:"usage"`
}

func strPtr(s string) *string { return &s }

func main() {
	addr := flag.String("addr", ":9091", "listen address")
	mode := flag.String("mode", "toolloop", `"toolloop" (3 real tool calls then conclude), "never-conclude" (always request another tool call — drives the iteration bound), or "toolloop-plan" (same 3 tool calls as "toolloop", but concludes with a proposedPlan — drives the plan-authoring/orchestrator/approval-queue path)`)
	// -plan lets a caller drive ANY action type, against a real object, without a
	// paid model call. The built-in plan below is a ScaleDeployment against a
	// fixture that only exists in smoke-test.sh, which is fine for that script and
	// useless for exercising an action type end to end on a real cluster.
	//
	// This is what made PatchResourceLimits testable in place: it was the only one
	// of the four executable action types that had never actually run against a
	// live object, and reaching its execution path needs a plan naming a real
	// target — which previously meant paying a real model to author one.
	plan := flag.String("plan", "", `JSON object to use as proposedPlan in "toolloop-plan" mode, e.g. '{"actionType":"PatchResourceLimits","targetGvk":"apps/v1/Deployment","targetNamespace":"ns","targetName":"web","params":{"container":"app","memoryLimit":"128Mi"},"reversible":true,"riskLevel":"medium"}'. Empty uses the built-in ScaleDeployment plan.`)
	// The three scripted tool calls hardcode default/smoketest-pod. Against a real
	// cluster those simply error and are recorded as evidence, which does not stop
	// the run — but pointing them at the real object under test makes the recorded
	// evidence real rather than three not-found errors.
	namespace := flag.String("namespace", "default", "namespace the scripted tool calls target")
	pod := flag.String("pod", "smoketest-pod", "pod name the scripted tool calls target")
	flag.Parse()

	var mu sync.Mutex
	count := 0

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var req chatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		mu.Lock()
		count++
		n := count
		mu.Unlock()

		log.Printf("fake-llm-server: request #%d (model=%q, %d messages so far)", n, req.Model, len(req.Messages))

		var msg assistantMessage
		msg.Role = "assistant"

		if *mode == "never-conclude" {
			msg.Content = strPtr(fmt.Sprintf("HYPOTHESIS: probe #%d\nFINDING: nothing conclusive from the previous probe", n))
			msg.ToolCalls = []toolCall{{
				ID:   fmt.Sprintf("call_%d", n),
				Type: "function",
				Function: toolCallFunction{
					Name:      "get_events",
					Arguments: fmt.Sprintf(`{"namespace":%q}`, *namespace),
				},
			}}
		} else {
			switch n {
			case 1:
				msg.Content = strPtr("HYPOTHESIS: check recent warning events for this incident's namespace")
				msg.ToolCalls = []toolCall{{ID: "call_1", Type: "function", Function: toolCallFunction{
					Name: "get_events", Arguments: fmt.Sprintf(`{"namespace":%q}`, *namespace),
				}}}
			case 2:
				msg.Content = strPtr("FINDING: recorded the get_events result as evidence\nHYPOTHESIS: check the object's owner chain for context")
				msg.ToolCalls = []toolCall{{ID: "call_2", Type: "function", Function: toolCallFunction{
					Name: "get_owner_chain", Arguments: fmt.Sprintf(`{"gvk":"v1/Pod","namespace":%q,"name":%q,"direction":"up"}`, *namespace, *pod),
				}}}
			case 3:
				msg.Content = strPtr("FINDING: recorded the get_owner_chain result as evidence\nHYPOTHESIS: check the pod's own logs for a crash reason")
				msg.ToolCalls = []toolCall{{ID: "call_3", Type: "function", Function: toolCallFunction{
					Name: "get_logs", Arguments: fmt.Sprintf(`{"namespace":%q,"pod":%q}`, *namespace, *pod),
				}}}
			default:
				if *mode == "toolloop-plan" {
					// A deliberately medium-risk plan (not low-risk) so it
					// falls outside internal/orchestrator.DefaultAutonomyPolicy's
					// low-risk-only auto-approve ceiling regardless of
					// confidence — the gate must return NeedsApproval here,
					// driving the incident to AwaitingApproval and giving
					// smoke-test.sh's approval-queue section a real,
					// non-auto-approved plan to approve/reject.
					proposed := `{"actionType": "ScaleDeployment", "targetGvk": "apps/v1/Deployment", "targetNamespace": "default", "targetName": "smoketest-deploy", "params": {"replicas": 4}, "reversible": true, "riskLevel": "medium"}`
					if *plan != "" {
						proposed = *plan
					}
					msg.Content = strPtr(fmt.Sprintf(`{"rootCause": {"statement": "fake-llm-server: %s is crash-looping due to undersized memory limits on its owning Deployment"}, "confidence": 0.75, "ruledOut": [{"hypothesis": "node-level disk pressure", "reason": "no DiskPressure events found"}], "proposedPlan": %s}`, *pod, proposed))
				} else {
					msg.Content = strPtr(`{"rootCause": {"statement": "fake-llm-server: could not confirm a real root cause in this environment (get_events/get_owner_chain/get_logs all came back empty or erroring, consistent with no reachable Kubernetes cluster behind the connected agent), but all three tool calls round-tripped correctly over the real mTLS tunnel"}, "confidence": 0.15, "ruledOut": [{"hypothesis": "a live workload crash", "reason": "no evidence available to confirm or deny in this sandbox"}]}`)
				}
			}
		}

		resp := chatResponse{Model: req.Model, Choices: []choice{{Message: msg, FinishReason: "stop"}}}
		resp.Usage.PromptTokens = 50
		resp.Usage.CompletionTokens = 20
		if n > 1 {
			// The system prompt + cluster-facts prefix is stable turn to
			// turn (lld/07-analysis-contracts.md §3) — a real provider with
			// prompt caching would report a growing cache hit on every call
			// after the first. Simulated here so a real analysis run
			// exercises a genuinely non-zero tokens_cache_read end to end,
			// not just in the unit tests.
			resp.Usage.PromptTokensDetails = &struct {
				CachedTokens int `json:"cached_tokens"`
			}{CachedTokens: 30}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	log.Printf("fake-llm-server: listening on %s (mode=%s)", *addr, *mode)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
