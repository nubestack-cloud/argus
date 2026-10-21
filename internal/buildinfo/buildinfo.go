// Package buildinfo answers one question: what build is this?
//
// It exists because the sign-in screens print a version, and a version printed
// on a login page has to be the software's own or it is worse than printing
// nothing — the supplied designs carried a hardcoded "v2.4.1", which was true
// of no build that has ever existed.
//
// Two sources, in order:
//
//  1. `version`, set at link time. The Dockerfile passes
//     -ldflags "-X argus/internal/buildinfo.version=$VERSION" from a build
//     arg, which is how a real release gets a real tag.
//  2. Go's own embedded build info, as a fallback for `go build` and
//     `go run` with no flags: the module version if the binary was installed
//     from one, otherwise the VCS revision Go stamps in automatically, short
//     and suffixed "-dirty" when the tree had uncommitted changes.
//
// If neither is available it reports "dev" rather than inventing something.
// That string is deliberately unglamorous: a login page reading "dev" is
// information, where one reading "v2.4.1" on an untagged build is a lie.
package buildinfo

import (
	"runtime/debug"
	"strings"
	"sync"
)

// version is set at link time; see the package comment.
var version string

var resolved = sync.OnceValue(func() string {
	if v := strings.TrimSpace(version); v != "" {
		return v
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	// A module version, when the binary was built from one ("(devel)" is Go's
	// placeholder for a local build and tells a reader nothing).
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	// Otherwise the VCS stamp Go adds for a build inside a repository. Absent
	// in the container build, which copies sources without .git — which is
	// exactly why the ldflags path above is the primary one.
	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return "dev"
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if dirty {
		return rev + "-dirty"
	}
	return rev
})

// Version reports this build's version. Never empty.
func Version() string { return resolved() }
