package api

import (
	"os"
	"strings"
	"testing"

	"argus/internal/scm"
)

// liveRepo is the GitHub repository the GitOps live proofs run against,
// named "owner/name" by ARGUS_GITOPS_REPO. The proofs skip without it; the
// repository is expected to hold the fixtures each proof describes.
func liveRepo(t *testing.T) scm.Repo {
	t.Helper()
	owner, name, ok := strings.Cut(os.Getenv("ARGUS_GITOPS_REPO"), "/")
	if !ok || owner == "" || name == "" {
		t.Skip("set ARGUS_GITOPS_REPO=owner/name to the GitOps fixture repository")
	}
	return scm.Repo{Owner: owner, Name: name}
}

func liveRepoURL(t *testing.T) string {
	t.Helper()
	r := liveRepo(t)
	return "https://github.com/" + r.Owner + "/" + r.Name
}
