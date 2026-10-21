package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"argus/internal/gitopsinsight"
	"argus/internal/redact"
)

// Field-level drift for Argo CD-managed objects that carry no last-applied
// configuration — applied server-side, or rendered by Helm (PROJECT.md
// CI-P9 b). Argo CD already holds, per managed resource, the state it would
// apply (predictedLiveState) and the live state normalised the way it
// compares them (normalizedLiveState); its API serves both. Opt-in: the agent
// chart's gitops.argocd sets the API URL and a read-only token (a
// project-scoped `applications, get` role is enough), mounted from a Secret.
// Nothing here changes anything in Argo CD.

type argoAPI struct {
	base  *url.URL
	token string
	http  *http.Client
}

func argoAPIFromEnv() *argoAPI {
	raw := strings.TrimSpace(os.Getenv("ARGUS_ARGOCD_URL"))
	tokenFile := os.Getenv("ARGUS_ARGOCD_TOKEN_FILE")
	if raw == "" || tokenFile == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil
	}
	tok, err := os.ReadFile(tokenFile)
	if err != nil || len(strings.TrimSpace(string(tok))) == 0 {
		return nil
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if ca := os.Getenv("ARGUS_ARGOCD_CA_FILE"); ca != "" {
		if pem, err := os.ReadFile(ca); err == nil {
			pool, _ := x509.SystemCertPool()
			if pool == nil {
				pool = x509.NewCertPool()
			}
			pool.AppendCertsFromPEM(pem)
			tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		}
	}
	return &argoAPI{base: u, token: strings.TrimSpace(string(tok)), http: &http.Client{Timeout: 15 * time.Second, Transport: tr}}
}

// managedResourceDrift asks Argo CD for one managed resource's desired and
// live state and diffs them with the same comparison last-applied drift uses.
func (a *argoAPI) managedResourceDrift(ctx context.Context, appNamespace, app, group, kind, namespace, name string) (*gitopsinsight.Drift, error) {
	u := *a.base
	u.Path = strings.TrimSuffix(u.Path, "/") + "/api/v1/applications/" + url.PathEscape(app) + "/managed-resources"
	q := url.Values{"group": {group}, "kind": {kind}, "namespace": {namespace}, "name": {name}}
	if appNamespace != "" {
		q.Set("appNamespace", appNamespace)
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Argo CD API: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Argo CD API answered HTTP %d", resp.StatusCode)
	}
	var out struct {
		Items []struct {
			PredictedLiveState  string `json:"predictedLiveState"`
			NormalizedLiveState string `json:"normalizedLiveState"`
			TargetState         string `json:"targetState"`
			LiveState           string `json:"liveState"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode Argo CD managed resources: %w", err)
	}
	if len(out.Items) == 0 {
		return nil, fmt.Errorf("Argo CD does not list %s %s/%s under Application %s", kind, namespace, name, app)
	}
	it := out.Items[0]
	desiredJSON, liveJSON := it.PredictedLiveState, it.NormalizedLiveState
	if desiredJSON == "" {
		desiredJSON = it.TargetState
	}
	if liveJSON == "" {
		liveJSON = it.LiveState
	}
	var desired, live map[string]any
	if err := json.Unmarshal([]byte(desiredJSON), &desired); err != nil || desired == nil {
		return nil, fmt.Errorf("Argo CD returned no desired state for this object")
	}
	if err := json.Unmarshal([]byte(liveJSON), &live); err != nil || live == nil {
		return nil, fmt.Errorf("Argo CD returned no live state for this object")
	}
	entries, truncated := gitopsinsight.DiffObjects(desired, live)
	for i := range entries {
		if sensitiveDriftPath.MatchString(entries[i].Path) {
			if entries[i].Desired != "" {
				entries[i].Desired = redact.Marker
			}
			if entries[i].Live != "" {
				entries[i].Live = redact.Marker
			}
		}
	}
	return &gitopsinsight.Drift{Source: gitopsinsight.DriftSource("argoDiff"), Entries: entries, Truncated: truncated}, nil
}
