// Package agentversion is the hub's single, server-owned policy for what
// counts as a current, upgrade-recommended, or too-old cluster agent build.
//
// PROJECT.md T16. `clusters` (migration 000002) has carried an
// 'IncompatibleVersion' state value since its very first CREATE TABLE, but
// nothing in this codebase has ever set it — internal/gateway/health.go
// transitions Active/Degraded/Disconnected off heartbeat gaps, and
// internal/gateway/server.go records agent_version on every heartbeat, but
// neither compares it against anything. This package is what computes a
// verdict, and it is deliberately NOT wired into that state column: a
// feature-limited-but-otherwise-healthy agent should keep heartbeating and
// stay Active (a live, reachable, merely-old agent is not the same failure
// as a dead tunnel), so the verdict computed here is carried as its own
// field on the cluster API response instead of overloading `state`. See
// Compatibility and internal/api/clusters.go's clusterSummary.
//
// Every caller MUST evaluate against the package-level Policy var, never a
// hand-rolled comparison — that is what "one server-owned policy" (the T16
// acceptance criterion) means in code: change Policy, and every verdict
// anywhere in ARGUS changes with it, in one place, in Go. The frontend never
// compares a version; it only renders what this package decided.
package agentversion

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"argus/internal/tunnel"
)

// Verdict is the fleet- and detail-page-visible compatibility state of one
// cluster's agent build. Never inferred from colour alone on any screen that
// renders it — see VerdictLabel.
type Verdict string

const (
	// VerdictUnknown means the hub cannot say. Either the agent has never
	// reported a version (a cluster that hasn't completed enrollment) or it
	// reported something Evaluate could not parse against this policy.
	// Deliberately NOT the same as VerdictUpgradeRequired: an unparsed or
	// absent version is not evidence of an old build, only of missing
	// information, and rendering it as "incompatible" would be exactly the
	// fabricated-confidence failure this package exists to avoid.
	VerdictUnknown Verdict = "unknown"
	// VerdictCurrent means the agent is at or above Policy.RecommendedVersion.
	VerdictCurrent Verdict = "current"
	// VerdictUpgradeRecommended means the agent is at or above
	// Policy.MinSupportedVersion but below Policy.RecommendedVersion — fully
	// supported today, but possibly missing a feature named in
	// Policy.Features, and worth upgrading opportunistically.
	VerdictUpgradeRecommended Verdict = "upgrade_recommended"
	// VerdictUpgradeRequired means the agent is below
	// Policy.MinSupportedVersion. This is the condition
	// clusters.state='IncompatibleVersion' names but has never had code to
	// reach; nothing in this package writes that column (see the package
	// comment) — this verdict is the read-side answer to the same question.
	VerdictUpgradeRequired Verdict = "upgrade_required"
)

// VerdictLabel is the one human-facing string for each Verdict — the
// counterpart to web/src/api/types.ts's CLUSTER_STATE_LABEL, kept server-side
// so the hub's audit log and any future non-web caller get the same words
// the UI does. The frontend has its own copy in api/types.ts
// (COMPATIBILITY_VERDICT_LABEL) because the wire carries the Verdict string,
// not this map — but both name the same four values, and a fifth Verdict
// added here without a matching frontend label is a build-time TS error,
// not a silent gap (see types.ts's exhaustiveness note).
var VerdictLabel = map[Verdict]string{
	VerdictUnknown:            "Unknown",
	VerdictCurrent:            "Current",
	VerdictUpgradeRecommended: "Upgrade recommended",
	VerdictUpgradeRequired:    "Upgrade required",
}

// Feature is one capability or fact this policy knows is gated on the
// agent's build. MinVersion is the oldest agent version that sends/supports
// it; an agent below that version simply omits the wire field or cannot do
// the thing — see WireContract below for what that omission must be read as.
type Feature struct {
	Name        string `json:"name"`
	MinVersion  string `json:"minVersion"`
	Description string `json:"description"`
	// WireContract states how an agent below MinVersion presents on the
	// wire, so a caller cannot accidentally read "absent" as "denied" or
	// "false" for a feature it never had the chance to report. Required,
	// non-empty for every entry in Policy.Features (checked by this
	// package's own tests) — a feature gate with nothing here is exactly
	// the kind of "plausible but unverified" entry T16 asked not to
	// fabricate.
	WireContract string `json:"wireContract"`
}

// VersionPolicy is the shape of the hub's supported-agent-range policy.
// Policy below is the one instance every caller in this codebase evaluates
// against; VersionPolicy is exported only so a test can construct an
// alternate one and prove that changing it changes the verdict (see
// policy_test.go and internal/api/clusters_test.go).
type VersionPolicy struct {
	// MinSupportedVersion is the oldest agent build this hub still accepts
	// as compatible. An agent below it gets VerdictUpgradeRequired.
	MinSupportedVersion string
	// RecommendedVersion is the version this hub currently expects a
	// healthy fleet to run. An agent at or above it gets VerdictCurrent.
	RecommendedVersion string
	// Features this policy knows to gate by version. Independent of the
	// three-way verdict above: an VerdictUpgradeRecommended agent may be
	// missing zero, one, or several of these; an VerdictUpgradeRequired one
	// is missing everything gated above its own version.
	Features []Feature
}

// Policy is the ONE server-owned policy every verdict in ARGUS is derived
// from — internal/api/clusters.go's scanClusterSummary evaluates every
// cluster against exactly this variable, and nothing else in this codebase
// may compute a competing answer. Change a threshold here (or, in a test,
// swap the whole variable) and every caller's verdict changes with it.
//
// RecommendedVersion is tunnel.AgentBuildVersion — the same constant cmd/agent
// stamps into every Heartbeat, referenced rather than copied, so a release that
// bumps the agent build moves the recommendation with it. MinSupportedVersion
// is the oldest agent release this hub still works with; raise it when a
// release drops support for an older agent. Bump AgentBuildVersion on every
// release.
//
// ConfigureFromEnv (env.go, PROJECT.md P22) overrides either threshold at hub
// startup via ARGUS_AGENT_MIN_SUPPORTED_VERSION / ARGUS_AGENT_RECOMMENDED_VERSION,
// so an operator can move the fleet's expected version without a rebuild —
// see that function's own comment for why this is an env var today rather
// than a DB-backed internal/settings field.
var Policy = VersionPolicy{
	// The previous release: a hub accepts its agents, so a fleet keeps
	// working while it is upgraded one cluster at a time (docs/UPGRADING.md).
	MinSupportedVersion: "0.1.0",
	RecommendedVersion:  tunnel.AgentBuildVersion,
	Features: []Feature{
		{
			Name:       "Per-namespace remediation-authority breakdown",
			MinVersion: "0.1.0-mvp",
			Description: "The per-namespace write-authority breakdown behind the " +
				"fleet-wide remediation summary (which namespaces hold their own " +
				"argus-remediate Role, and what it can do) — internal/tunnel/" +
				"protocol.go's ClusterRemediation.Namespaces, gathered by " +
				"internal/agent/facts.go.",
			WireContract: "An agent built before this field existed omits " +
				"`remediation.namespaces` entirely. Absence is indistinguishable " +
				"on the wire from \"checked, found no namespace-scoped Role\" — " +
				"both read as \"no per-namespace breakdown available,\" and MUST " +
				"NOT be rendered as a denial for any namespace (ClusterRemediation " +
				"doc comment, internal/tunnel/protocol.go).",
		},
	},
}

// Compatibility is one cluster's evaluated verdict, carrying enough of the
// policy it was evaluated against that a reader never has to look elsewhere
// to understand why. This is exactly the JSON shape
// internal/api/clusters.go attaches to every cluster in both
// GET /api/v1/clusters and GET /api/v1/clusters/{id} — one evaluation, one
// wire shape, read by both the fleet list and the detail page so they
// cannot disagree.
type Compatibility struct {
	Verdict Verdict `json:"verdict"`
	// Label is VerdictLabel[Verdict], carried on the wire so nothing
	// downstream needs its own copy of that map.
	Label string `json:"label"`
	// AgentVersion mirrors the cluster's own agentVersion field — carried
	// here too so a component rendering only this struct never needs a
	// second prop to explain its own verdict.
	AgentVersion        *string `json:"agentVersion"`
	MinSupportedVersion string  `json:"minSupportedVersion"`
	RecommendedVersion  string  `json:"recommendedVersion"`
	Reason              string  `json:"reason"`
	// MissingFeatures is only ever non-empty when Verdict is
	// VerdictUpgradeRecommended or VerdictUpgradeRequired — never populated
	// for VerdictUnknown, because naming a feature gap requires knowing the
	// version, and Unknown means we don't.
	MissingFeatures []Feature `json:"missingFeatures,omitempty"`
	// Upgrade is only populated for VerdictUpgradeRecommended and
	// VerdictUpgradeRequired — see UpgradeCommand's own comment for why an
	// Unknown verdict gets no guidance at all (guidance implies a confident
	// "upgrade from X," and X is exactly what's missing).
	Upgrade *UpgradeGuidance `json:"upgrade,omitempty"`
}

// Evaluate is the one place a Compatibility verdict is computed anywhere in
// ARGUS. agentVersion is exactly the wire value from Heartbeat.AgentVersion,
// persisted as clusters.agent_version and passed through unchanged — nil for
// a cluster that has never heartbeated.
func (p VersionPolicy) Evaluate(agentVersion *string) Compatibility {
	c := Compatibility{
		AgentVersion:        agentVersion,
		MinSupportedVersion: p.MinSupportedVersion,
		RecommendedVersion:  p.RecommendedVersion,
	}

	if agentVersion == nil || strings.TrimSpace(*agentVersion) == "" {
		c.Verdict = VerdictUnknown
		c.Reason = "This cluster has not reported an agent version yet, so no compatibility verdict can be given."
		c.Label = VerdictLabel[VerdictUnknown]
		return c
	}

	v, ok := parseVersion(*agentVersion)
	if !ok {
		c.Verdict = VerdictUnknown
		c.Reason = fmt.Sprintf("Agent-reported version %q could not be parsed against the hub's version policy.", *agentVersion)
		c.Label = VerdictLabel[VerdictUnknown]
		return c
	}

	// Both are policy constants, not attacker- or agent-controlled, so an
	// unparseable Min/RecommendedVersion is this package's own bug, not
	// input to guard against — surfaced loudly rather than silently treated
	// as "no policy."
	minV, minOK := parseVersion(p.MinSupportedVersion)
	recV, recOK := parseVersion(p.RecommendedVersion)
	if !minOK || !recOK {
		panic(fmt.Sprintf("agentversion: Policy has an unparseable version (min=%q, recommended=%q)", p.MinSupportedVersion, p.RecommendedVersion))
	}

	switch {
	case v.less(minV):
		c.Verdict = VerdictUpgradeRequired
		c.Reason = fmt.Sprintf("Agent version %s is older than %s, the oldest version this hub still accepts.", *agentVersion, p.MinSupportedVersion)
	case v.less(recV):
		c.Verdict = VerdictUpgradeRecommended
		c.Reason = fmt.Sprintf("Agent version %s is supported, but older than the recommended %s.", *agentVersion, p.RecommendedVersion)
	default:
		c.Verdict = VerdictCurrent
		c.Reason = fmt.Sprintf("Agent version %s meets the recommended version %s.", *agentVersion, p.RecommendedVersion)
	}
	c.Label = VerdictLabel[c.Verdict]

	if c.Verdict != VerdictCurrent {
		for _, f := range p.Features {
			fv, fOK := parseVersion(f.MinVersion)
			if fOK && v.less(fv) {
				c.MissingFeatures = append(c.MissingFeatures, f)
			}
		}
		guidance := UpgradeCommand(ReleaseContext{}, "")
		c.Upgrade = &guidance
	}

	return c
}

// ReleaseContext is what the hub knows about how a cluster's agent was
// installed, so UpgradeCommand can target the real release instead of a
// guess. Every field is optional because, as of this package, nothing in
// ARGUS's enrollment or heartbeat protocol ever populates one — see
// UpgradeCommand's own comment.
type ReleaseContext struct {
	ReleaseName string
	Namespace   string
}

// UpgradeGuidance is a copyable command an operator can run, plus whether it
// is unambiguous (a NAMED release/namespace) or generic (placeholders the
// operator must fill in themselves). Never claims ARGUS ran the upgrade —
// it is guidance for a human to execute, matching every other "here is the
// command" surface in this codebase (see web/src/components/
// EnrollTokenModal.tsx's shellSnippet, the same posture for enrollment).
type UpgradeGuidance struct {
	Command             string `json:"command"`
	ReleaseContextKnown bool   `json:"releaseContextKnown"`
	Note                string `json:"note,omitempty"`
}

// defaultChartRef is the published agent chart, as the hub's enroll command
// also installs it (internal/api's defaultAgentChartRef). ARGUS_AGENT_CHART_REF
// and ARGUS_AGENT_CHART_VERSION, set by the hub chart, override it with the
// chart and version released alongside this hub.
const defaultChartRef = "oci://registry-1.docker.io/nubestack/argus-agent-chart"

func agentChart() (ref, version string) {
	ref = strings.TrimSpace(os.Getenv("ARGUS_AGENT_CHART_REF"))
	if ref == "" {
		ref = defaultChartRef
	}
	return ref, strings.TrimSpace(os.Getenv("ARGUS_AGENT_CHART_VERSION"))
}

// UpgradeCommand renders a copyable `helm upgrade` for one cluster.
//
// As of this package, every caller passes an empty ReleaseContext: the hub
// has no way to learn a cluster's Helm release name or install namespace.
// internal/tunnel's Heartbeat and InventoryDelta carry neither (see
// protocol.go); the install command the hub prints names the release
// "argus-agent" but nothing reports that back, and a hand-written
// `helm install` can use any release name or namespace at all. Guessing
// "argus-agent" here would be right for the most common path and silently
// wrong — targeting an unrelated release, or failing outright on a name
// mismatch — for anyone who didn't take it. So this always renders the
// generic form today: placeholders instead of a guessed name, plus a note
// naming the printed install's convention as a hint, not a fact about THIS
// cluster.
//
// ReleaseContext exists as a parameter anyway — not because anything
// populates it yet, but so that if a future source ever does (a facts field
// the agent reports from its own downward-API namespace), Evaluate's call site is the only thing that
// needs to change; every existing caller of Compatibility keeps working
// unchanged, and callers stop seeing the generic-form note automatically
// once ReleaseContext is non-empty.
func UpgradeCommand(ctx ReleaseContext, chartPath string) UpgradeGuidance {
	version := ""
	if chartPath == "" {
		chartPath, version = agentChart()
	}

	releaseName := ctx.ReleaseName
	namespace := ctx.Namespace
	known := releaseName != "" && namespace != ""

	if !known {
		releaseName = "<release-name>"
		namespace = "<namespace>"
	}

	lines := []string{fmt.Sprintf("helm upgrade %s %s \\", releaseName, chartPath)}
	if version != "" {
		lines = append(lines, fmt.Sprintf("  --version %s \\", version))
	}
	lines = append(lines,
		"  --kube-context <cluster-context> \\",
		fmt.Sprintf("  --namespace %s \\", namespace),
		"  --reset-then-reuse-values",
	)
	command := strings.Join(lines, "\n")

	guidance := UpgradeGuidance{Command: command, ReleaseContextKnown: known}
	if !known {
		guidance.Note = "ARGUS does not have a recorded Helm release name or install namespace for this cluster — " +
			"replace the placeholders above with the ones used at install time (and <cluster-context> with the " +
			"kubeconfig context that reaches it; ARGUS never holds cluster credentials, so it cannot fill that in " +
			"either). The install command ARGUS prints names the release `argus-agent` in `argus-system`. " +
			"This command upgrades the chart release — ARGUS only prints it; running it is on you."
	}
	return guidance
}

// semver is a deliberately small, permissive parse of the major.minor.patch
// prefix of a version string — enough to order "0.1.0-mvp"-shaped strings
// (this codebase's only real agent version, and the only shape
// cmd/agent/main.go's const has ever produced), without pulling in a strict
// semver dependency for a comparison this narrow. Any pre-release/build
// suffix (anything from the first '-' or '+' onward) is stripped before
// parsing and never affects ordering — two versions differing only in that
// suffix compare equal.
type semver struct {
	major, minor, patch int
}

func (a semver) less(b semver) bool {
	if a.major != b.major {
		return a.major < b.major
	}
	if a.minor != b.minor {
		return a.minor < b.minor
	}
	return a.patch < b.patch
}

// parseVersion parses the major[.minor[.patch]] numeric prefix of raw,
// tolerating a leading "v" and any trailing "-"/"+" suffix. Returns ok=false
// for anything with no parseable leading integer at all — that is this
// package's only definition of "unparseable," and it is what routes an
// agent-reported version to VerdictUnknown rather than a guess.
func parseVersion(raw string) (semver, bool) {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return semver{}, false
	}
	parts := strings.Split(s, ".")
	var v semver
	nums := [3]*int{&v.major, &v.minor, &v.patch}
	parsedAny := false
	for i := 0; i < len(parts) && i < 3; i++ {
		if parts[i] == "" {
			break
		}
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			if i == 0 {
				return semver{}, false
			}
			break
		}
		*nums[i] = n
		parsedAny = true
	}
	if !parsedAny {
		return semver{}, false
	}
	return v, true
}
