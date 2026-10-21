// Package policyreports looks up the policy-report findings that apply to one
// object. The reports — wgpolicyk8s.io PolicyReport and ClusterPolicyReport,
// written by Kyverno and other engines — come from the agent's object cache;
// nothing here calls the API server.
//
// A report holds results[], one per policy rule evaluated. A result names
// the objects it is about in resources[], or the whole report is about one
// object, named in its scope.
package policyreports

// Finding is one result as it applies to one object: which policy and rule,
// the outcome, and the producer's message.
//
// Result is the reporting API's word: pass, fail, warn (flagged but not
// blocked), error (the engine failed to evaluate) or skip (did not apply).
// Severity and Category are passed through as the producer wrote them.
//
// Source is the producer type, verbatim — kyverno, KyvernoValidatingPolicy,
// ValidatingAdmissionPolicy, "Trivy Vulnerability" — which is what an
// operator sees in `kubectl get policyreport -o yaml`. Policy is the
// producer's to define and need not name a policy object: Kyverno puts the
// policy's name there, falcosidekick a Falco detection source (syscall,
// k8s_audit) with the rule in Rule.
//
// Message is free text that can quote values from the object; a caller
// putting it in a tool result runs it through redaction first.
type Finding struct {
	Policy   string `json:"policy,omitempty"`
	Rule     string `json:"rule,omitempty"`
	Result   string `json:"result,omitempty"`
	Severity string `json:"severity,omitempty"`
	Category string `json:"category,omitempty"`
	Message  string `json:"message,omitempty"`
	Source   string `json:"source,omitempty"`
}
