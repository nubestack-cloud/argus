package api

import (
	"encoding/json"
	"testing"

	"argus/internal/fleetchecks"
)

func TestBuildApplications(t *testing.T) {
	snap := func(v any) fleetchecks.Snapshot { b, _ := json.Marshal(v); return fleetchecks.Snapshot{Summary: b} }
	argo := func(name, repo, rev string) fleetchecks.GitOpsApp {
		return fleetchecks.GitOpsApp{Tool: "argocd", Kind: "Application", Name: name, Namespace: "argocd", RepoURL: repo, Path: "apps/web", Revision: rev}
	}
	snaps := map[string]map[string]fleetchecks.Snapshot{
		"c1": {
			fleetchecks.CheckGitOps: snap(fleetchecks.GitOpsSummary{Apps: []fleetchecks.GitOpsApp{argo("web-staging", "https://github.com/acme/deploy.git", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")}}),
			fleetchecks.CheckHelm:   snap(fleetchecks.HelmSummary{Releases: []fleetchecks.HelmApp{{Name: "ingress", Namespace: "kube", Revision: 3}}}),
		},
		"c2": {
			// Same source written differently, different revision: one app, skewed.
			fleetchecks.CheckGitOps: snap(fleetchecks.GitOpsSummary{Apps: []fleetchecks.GitOpsApp{argo("web-prod", "git@github.com:acme/deploy", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")}}),
			fleetchecks.CheckHelm:   snap(fleetchecks.HelmSummary{Releases: []fleetchecks.HelmApp{{Name: "ingress", Namespace: "kube", Revision: 9}}}),
		},
	}
	out := buildApplications(map[string]string{"c1": "staging", "c2": "prod"}, snaps)
	if len(out.Applications) != 2 {
		t.Fatalf("applications = %+v", out.Applications)
	}
	web := out.Applications[0]
	if web.MatchedBy != "source" || len(web.Instances) != 2 || !web.Skew || web.Source != "github.com/acme/deploy//apps/web" {
		t.Fatalf("web = %+v; the same repository and path must fold, with skew", web)
	}
	ingress := out.Applications[1]
	if ingress.MatchedBy != "name" || len(ingress.Instances) != 2 || ingress.Skew {
		t.Fatalf("ingress = %+v; Helm revision numbers are per cluster and never skew", ingress)
	}
}
