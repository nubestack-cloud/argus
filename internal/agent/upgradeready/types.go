// Package upgradeready answers one question for an operator about to upgrade
// a cluster's control plane to Kubernetes 1.N: what, in what the agent can
// see, would break or needs a decision first. Scan runs the checks that
// apply between the current and target minors, each ending passed, blocked,
// warning, review, not applicable or unknown.
//
// Some evidence an upgrade review would want is out of the agent's reach by
// design: kubelet configuration and metrics need nodes/proxy, rendered Helm
// manifests live in release Secrets, and API usage lives in the API server's
// own metrics. The checks that need it still run and report unknown, saying
// what the operator has to verify themselves, so a scan never reports "no
// known blockers" on evidence nobody looked at.
package upgradeready

import (
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	policyv1 "k8s.io/api/policy/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Verdict is the scan's overall answer.
type Verdict string

const (
	VerdictBlocked         Verdict = "blocked"
	VerdictWarning         Verdict = "warning"
	VerdictReview          Verdict = "review"
	VerdictNoKnownBlockers Verdict = "no_known_blockers"
	VerdictUnknown         Verdict = "unknown"
)

// CheckStatus is one check's outcome.
type CheckStatus string

const (
	CheckPassed        CheckStatus = "passed"
	CheckBlocked       CheckStatus = "blocked"
	CheckWarning       CheckStatus = "warning"
	CheckReview        CheckStatus = "review"
	CheckUnknown       CheckStatus = "unknown"
	CheckNotApplicable CheckStatus = "not_applicable"
)

// Level is how serious one finding is: a blocker stops the upgrade, a
// warning will hurt, a review needs a human decision.
type Level string

const (
	LevelBlocker Level = "blocker"
	LevelWarning Level = "warning"
	LevelReview  Level = "review"
)

// Input is the evidence a scan reads. For every slice, nil means the source
// could not be read, and the checks needing it say so; empty means it was
// read and held nothing.
type Input struct {
	Pods         []*corev1.Pod
	Deployments  []*appsv1.Deployment
	ReplicaSets  []*appsv1.ReplicaSet
	StatefulSets []*appsv1.StatefulSet
	DaemonSets   []*appsv1.DaemonSet
	Jobs         []*batchv1.Job
	CronJobs     []*batchv1.CronJob
	Services     []*corev1.Service
	// WebhookServices are the Services webhook backends are looked up in.
	// They are given separately because they need cluster-wide reach even
	// where Services are collected more narrowly.
	WebhookServices []*corev1.Service
	// ConfigMaps arrive with every value replaced by "sha256:<hex>", so a
	// check that would parse one reports unknown instead.
	ConfigMaps             []*corev1.ConfigMap
	PersistentVolumeClaims []*corev1.PersistentVolumeClaim
	PersistentVolumes      []*corev1.PersistentVolume
	Nodes                  []*corev1.Node
	Events                 []*corev1.Event
	PodDisruptionBudgets   []*policyv1.PodDisruptionBudget
	EndpointSlices         []*discoveryv1.EndpointSlice
	CSIDrivers             []*storagev1.CSIDriver

	// AdmissionWebhookConfigurations holds both configuration kinds; it is
	// nil only when neither could be listed, and
	// AdmissionWebhookUnavailableKinds names a kind that could not be.
	AdmissionWebhookConfigurations   []*unstructured.Unstructured
	AdmissionWebhookUnavailableKinds []string
	CustomResourceDefinitions        []*unstructured.Unstructured
	APIServices                      []*unstructured.Unstructured

	// PrometheusRules: PrometheusRulesDiscoveryAvailable says whether the
	// agent could tell if the CRD exists, PrometheusRulesInstalled whether
	// it does, and the slice is nil when it does but could not be read.
	PrometheusRules                   []*unstructured.Unstructured
	PrometheusRulesInstalled          bool
	PrometheusRulesDiscoveryAvailable bool

	// Platform is DetectPlatform's answer; "" is unknown.
	Platform string
}

// ResourceRef names the object a finding is about.
type ResourceRef struct {
	Group     string `json:"group,omitempty"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// Evidence is where a finding was read: a source ("live", "event", a
// policy), a path within the object, and the value found there.
type Evidence struct {
	Source string `json:"source"`
	Path   string `json:"path"`
	Detail string `json:"detail,omitempty"`
}

// Reference is a document backing a check or finding.
type Reference struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// Finding is one thing in the cluster a check objects to.
type Finding struct {
	RuleID      string       `json:"ruleID"`
	Title       string       `json:"title"`
	Level       Level        `json:"level"`
	Resource    *ResourceRef `json:"resource,omitempty"`
	ManagedBy   *ResourceRef `json:"managedBy,omitempty"`
	Evidence    Evidence     `json:"evidence"`
	AppliesFrom string       `json:"appliesFrom,omitempty"`
	Impact      string       `json:"impact"`
	Remediation string       `json:"remediation"`
	References  []Reference  `json:"references"`
}

// FindingGroup counts a check's findings that share a title.
type FindingGroup struct {
	Title       string `json:"title"`
	Count       int    `json:"count"`
	Impact      string `json:"impact,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// Check is one check's result.
type Check struct {
	ID           string      `json:"id"`
	Category     string      `json:"category"`
	Title        string      `json:"title"`
	Status       CheckStatus `json:"status"`
	Summary      string      `json:"summary"`
	EvidenceNote string      `json:"evidenceNote,omitempty"`
	// Caveat says what the check could not see; any caveat makes the
	// scan's coverage partial.
	Caveat      string    `json:"caveat,omitempty"`
	Scope       string    `json:"scope"`
	Inspected   int       `json:"inspected,omitempty"`
	AppliesFrom string    `json:"appliesFrom,omitempty"`
	Findings    []Finding `json:"findings"`
	// FindingsTotal counts every finding; Findings holds at most
	// MaxFindingsPerCheck of them, most serious first, and Truncated says
	// when some were cut. Groups count all of them, cut or not.
	FindingsTotal int            `json:"findingsTotal,omitempty"`
	Truncated     bool           `json:"truncated,omitempty"`
	Groups        []FindingGroup `json:"groups,omitempty"`
	References    []Reference    `json:"references,omitempty"`
}

// Summary counts checks by status, and findings over all of them.
type Summary struct {
	Blocked       int `json:"blocked"`
	Warnings      int `json:"warnings"`
	Reviews       int `json:"reviews"`
	Passed        int `json:"passed"`
	Unknown       int `json:"unknown"`
	NotApplicable int `json:"notApplicable"`
	Findings      int `json:"findings"`
}

// Coverage says whether the scan saw everything it would have liked to.
type Coverage struct {
	Source           string   `json:"source"`
	State            string   `json:"state"`
	UnavailableKinds []string `json:"unavailableKinds,omitempty"`
}

// ScanResults is one scan.
type ScanResults struct {
	CurrentVersion  string   `json:"currentVersion"`
	TargetVersion   string   `json:"targetVersion"`
	ReviewedThrough string   `json:"reviewedThrough"`
	Verdict         Verdict  `json:"verdict"`
	Summary         Summary  `json:"summary"`
	Checks          []Check  `json:"checks"`
	Coverage        Coverage `json:"coverage"`
}
