package sandbox

import "time"

// DefaultImage is a public, widely-used image bundling helm, kubectl (whose
// `kubectl kustomize` subcommand is this package's Kustomize renderer — no
// separate `kustomize` binary is needed), tar and sh — exactly what the
// render container execs.
//
// Pinned by DIGEST, not by tag — a mutable tag is exactly T13's supply-chain
// threat (a registry-side tag repoint changing what a render pod executes
// without any change on ARGUS's side to review), and this is a container
// whose whole job is to run untrusted, model-influenced content, so a
// mutable reference here is a materially worse choice than it would be for
// an ordinary dependency. Verified once against Docker Hub
// (`docker pull alpine/k8s:1.31.1` -> this exact digest) when this default
// was set; bump deliberately, not by re-pulling ":1.31.1" and copying
// whatever it resolves to that day.
//
// A production deployment should build and pin ARGUS's OWN image instead of
// depending on a third party's content for something that executes
// untrusted input — this default exists so Config has a usable value out of
// the box and so this package's own tests could run against a real cluster
// before ARGUS has published an image anywhere.
const DefaultImage = "alpine/k8s@sha256:dfe8c7a06c41d0b6e8757da99531f8f302e9a2687fa0155af4c4087df585c9c8"

// Config is one render sandbox's isolation and resource posture. Every field
// here maps directly to an lld/09-repo-gitops-design.md §2 requirement — see
// pod.go's BuildPod for exactly which field produces which PodSpec property,
// and pod_test.go for the mechanical proof that it does.
type Config struct {
	// Namespace is where render pods and their NetworkPolicy are created.
	// Must be a namespace dedicated to this purpose — never a namespace that
	// also holds anything else, because the NetworkPolicy this package
	// writes is scoped by pod label, not by namespace, and a shared
	// namespace is one more thing a reviewer has to reason about when
	// deciding whether "no host mounts, network disabled" is actually true
	// for this pod and not just for the ones this package created.
	Namespace string
	// Image is the render container's image. Empty uses DefaultImage.
	Image string
	// RuntimeClassName, when set, is requested for the pod
	// (spec.runtimeClassName) — lld/09 §2 specifies gVisor (`runsc`) here.
	// Empty (the default, and what this package ships with because no
	// gVisor RuntimeClass exists on the cluster this was built and tested
	// against) means the pod runs under whatever the cluster's default
	// runtime is — see this package's doc comment for why that gap is
	// disclosed rather than silently accepted.
	RuntimeClassName string
	// PodTimeout is the wall-clock budget for one render pod
	// (spec.activeDeadlineSeconds) — lld/09 §2's default is 2 minutes.
	// Zero uses that default.
	PodTimeout time.Duration
	// CPULimit/MemoryLimit are BOTH the request and the limit — lld/09 §2:
	// "no burst headroom for a workload this untrusted". Empty uses
	// conservative defaults sized for a single chart/overlay render.
	CPULimit    string
	MemoryLimit string
	// ScratchSizeLimit bounds the tmpfs-backed scratch volume — a
	// Memory-medium emptyDir counts against the pod's memory limit, so this
	// must not exceed MemoryLimit, and BuildPod refuses to build a Config
	// where it does.
	ScratchSizeLimit string
}

func (c Config) withDefaults() Config {
	if c.Image == "" {
		c.Image = DefaultImage
	}
	if c.PodTimeout <= 0 {
		c.PodTimeout = 2 * time.Minute
	}
	if c.CPULimit == "" {
		c.CPULimit = "500m"
	}
	if c.MemoryLimit == "" {
		c.MemoryLimit = "256Mi"
	}
	if c.ScratchSizeLimit == "" {
		c.ScratchSizeLimit = "128Mi"
	}
	return c
}
