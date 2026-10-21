package api

import (
	"context"
	"errors"
	"strings"
	"unicode"

	"argus/internal/gateway"
)

// maxAgentReasonRunes bounds how much of an agent's own failure reason is
// shown. The reasons the read-only tools give are one sentence ("container
// app in pod apps/web-1 has not started yet (ContainerCreating), so it has no
// logs"); anything longer is cut rather than echoed.
const maxAgentReasonRunes = 300

// agentToolFailureDetail is the problem detail for a person's tool call that
// failed, saying WHY wherever the reason is known. A tool the agent ran and
// answered with an error carries the agent's own reason, which the agent has
// already put through capture-time redaction (ToolExecutor.Execute) — the
// same treatment as the tool's successful output this caller would have been
// shown — so it is passed on, tidied and bounded. Every other failure (the
// call never arrived, the agent never answered) is described by its kind,
// never by the raw transport error text, which can carry internal addresses.
func agentToolFailureDetail(err error) string {
	var te *gateway.ToolError
	if errors.As(err, &te) {
		if reason := tidyAgentReason(te.Message); reason != "" {
			return "The agent reported: " + reason
		}
		return "The agent reported a failure but gave no reason."
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "The agent did not answer in time; it may be busy or the connection may be slow. Try again."
	}
	return "The request did not reach the agent, or the agent's answer did not arrive."
}

// isAgentNotFound reports whether the agent ran the tool and answered that
// the object it was asked about does not exist. The tunnel carries a tool
// failure as one sentence, and every read-only tool words this case the same
// way — the insight tools' "<Kind> <ns>/<name> not found" and the sanitised
// API-server NotFound "resource not found" (internal/agent sanitizeK8sErr) —
// so the sentence's ending is the signal. A transport failure (the call never
// arrived, no answer) is never a ToolError, so it can never read as not-found.
func isAgentNotFound(err error) bool {
	var te *gateway.ToolError
	if !errors.As(err, &te) {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(te.Message))
	msg = strings.TrimRight(msg, ".")
	return strings.HasSuffix(msg, " not found") || msg == "not found"
}

// tidyAgentReason makes an agent's reason safe to put in a sentence: control
// characters dropped, whitespace collapsed, length bounded, and a trailing
// full stop guaranteed.
func tidyAgentReason(msg string) string {
	var b strings.Builder
	space := false
	n := 0
	for _, r := range msg {
		if unicode.IsSpace(r) {
			space = b.Len() > 0
			continue
		}
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			continue
		}
		if space {
			b.WriteByte(' ')
			n++
			space = false
		}
		if n >= maxAgentReasonRunes {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
		n++
	}
	out := b.String()
	if out == "" {
		return ""
	}
	if !strings.HasSuffix(out, ".") && !strings.HasSuffix(out, "…") {
		out += "."
	}
	return out
}
