package upgradeready

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	utilversion "k8s.io/apimachinery/pkg/util/version"
)

// The errors Scan returns for a version it cannot plan between.
var (
	ErrInvalidCurrentVersion = errors.New("invalid current Kubernetes version")
	ErrInvalidTargetVersion  = errors.New("invalid target Kubernetes version")
	ErrNonForwardTarget      = errors.New("target Kubernetes version must be newer than the current version")
)

// minor is a Kubernetes major.minor.
type minor = *utilversion.Version

// readMinor reads "1.36", "v1.36.4" or "1.36.4-gke.100" as 1.36.
func readMinor(s string) (minor, error) {
	v, err := utilversion.ParseGeneric(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "v")))
	if err != nil || v.Major() == 0 {
		return nil, fmt.Errorf("not a Kubernetes version: %q", s)
	}
	return utilversion.MajorMinor(v.Major(), v.Minor()), nil
}

// A target names a minor and nothing more: "1.37" or "v1.37".
var targetShape = regexp.MustCompile(`^v?\d{1,4}\.\d{1,4}$`)

// plan reads the two versions of an upgrade. An empty target means the next
// minor.
func plan(current, target string) (from, to minor, err error) {
	if from, err = readMinor(current); err != nil {
		return nil, nil, fmt.Errorf("%w: %q", ErrInvalidCurrentVersion, current)
	}
	if target == "" {
		target = from.AddMinor(1).String()
	}
	if t := strings.TrimSpace(target); targetShape.MatchString(t) {
		to, err = readMinor(t)
	} else {
		err = ErrInvalidTargetVersion
	}
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %q", ErrInvalidTargetVersion, target)
	}
	if !to.GreaterThan(from) {
		return nil, nil, ErrNonForwardTarget
	}
	return from, to, nil
}

func label(v minor) string { return fmt.Sprintf("%d.%d", v.Major(), v.Minor()) }

func release(s string) minor { return utilversion.MustParseGeneric(s) }

// crosses reports whether upgrading from one minor to another passes
// through the given release.
func crosses(from, to minor, at string) bool {
	r := release(at)
	return from.LessThan(r) && to.AtLeast(r)
}

// kubeProxyModeWindow is the stretch of releases over which kube-proxy's
// mode matters to an upgrade: 1.37 begins warning about an implicit mode,
// and 1.40 changes the Linux default.
func kubeProxyModeWindow(from, to minor) bool {
	return to.AtLeast(release("1.37")) && from.LessThan(release("1.40"))
}

// oldestSupported is the oldest kubelet or kube-proxy a control plane at v
// supports: three minors back.
func oldestSupported(v minor) minor {
	return utilversion.MajorMinor(v.Major(), uint(max(int(v.Minor())-3, 0)))
}
