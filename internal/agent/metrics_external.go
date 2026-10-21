package agent

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"argus/internal/agent/cost"
	"argus/internal/tunnel"
)

// A Prometheus-compatible endpoint that is not a Service in this cluster
// (PROJECT.md PG17): Amazon Managed Prometheus behind a signing proxy, Grafana
// Cloud, a central Thanos or Mimir. Configured on the agent chart as
// metrics.external: the URL, request headers from a mounted Secret (an auth
// token, X-Scope-OrgID for a multi-tenant backend), and an optional
// extraLabel.
//
// extraLabel is sent as the `extra_label` query parameter, which
// VictoriaMetrics and prom-label-proxy enforce on every series a query
// touches. Plain Prometheus and Thanos ignore it, so on a shared endpoint
// without one of those in front, every query sees every cluster's series; the
// chart says so, and the facts report which mode is in use.

const maxExternalMetricsBody = 16 << 20

type externalMetricsClient struct {
	base       *url.URL
	headers    http.Header
	extraLabel string
	http       *http.Client
}

func newExternalMetricsClientFromEnv() (*externalMetricsClient, error) {
	raw := strings.TrimSpace(os.Getenv("ARGUS_METRICS_EXTERNAL_URL"))
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("metrics.external.url %q is not an http(s) URL", raw)
	}
	headers := http.Header{}
	if path := os.Getenv("ARGUS_METRICS_EXTERNAL_HEADERS_FILE"); path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("read metrics.external headers: %w", err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				return nil, errors.New("metrics.external headers: each line must be `Name: value`")
			}
			headers.Add(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if ca := os.Getenv("ARGUS_METRICS_EXTERNAL_CA_FILE"); ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			return nil, fmt.Errorf("read metrics.external CA: %w", err)
		}
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		pool.AppendCertsFromPEM(pem)
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &externalMetricsClient{
		base:       u,
		headers:    headers,
		extraLabel: strings.TrimSpace(os.Getenv("ARGUS_METRICS_EXTERNAL_EXTRA_LABEL")),
		http:       &http.Client{Timeout: 30 * time.Second, Transport: tr},
	}, nil
}

func (c *externalMetricsClient) Get(ctx context.Context, endpoint string, params map[string]string) ([]byte, error) {
	u := *c.base
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + strings.TrimPrefix(endpoint, "/")
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	if c.extraLabel != "" {
		q.Set("extra_label", c.extraLabel)
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	for k, vs := range c.headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &promUnreachableError{err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxExternalMetricsBody))
	if err != nil {
		return nil, &promUnreachableError{err}
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, &promUnreachableError{fmt.Errorf("the metrics endpoint refused the request (HTTP %d) — check the headers", resp.StatusCode)}
	}
	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnprocessableEntity {
		return nil, &promUnreachableError{fmt.Errorf("the metrics endpoint answered HTTP %d", resp.StatusCode)}
	}
	return body, nil
}

// externalMetricsAuthority asks the endpoint a trivial query: reachable and
// authorised, or not, and why.
func externalMetricsAuthority(ctx context.Context, c *externalMetricsClient) *tunnel.ClusterMetrics {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	m := &tunnel.ClusterMetrics{External: true}
	if _, err := c.Get(ctx, "api/v1/query", map[string]string{"query": "vector(1)"}); err != nil {
		m.Checked, m.Error = true, err.Error()
		return m
	}
	m.Checked, m.Allowed = true, true
	if c.extraLabel != "" {
		m.ScopedByLabel = labelEnforced(ctx, c)
		m.LabelIgnored = !m.ScopedByLabel
	}
	return m
}

// labelEnforced asks whether the endpoint applies extra_label rather than
// ignoring it: with the label sent, `up` must return series, and `up` with the
// label negated must return none. Anything else, including a label that is
// not `name=value` or an endpoint with no `up` series, is not enforcement.
func labelEnforced(ctx context.Context, c *externalMetricsClient) bool {
	name, value, ok := strings.Cut(c.extraLabel, "=")
	name, value = strings.TrimSpace(name), strings.Trim(strings.TrimSpace(value), `"`)
	if !ok || name == "" || !promLabelName.MatchString(name) {
		return false
	}
	count := func(query string) (int, bool) {
		body, err := c.Get(ctx, "api/v1/query", map[string]string{"query": query})
		if err != nil {
			return 0, false
		}
		var resp struct {
			Status string `json:"status"`
			Data   struct {
				Result []json.RawMessage `json:"result"`
			} `json:"data"`
		}
		if json.Unmarshal(body, &resp) != nil || resp.Status != "success" {
			return 0, false
		}
		return len(resp.Data.Result), true
	}
	own, ok1 := count("count(up)")
	other, ok2 := count(fmt.Sprintf(`count(up{%s!=%q})`, name, value))
	return ok1 && ok2 && own > 0 && other == 0
}

var promLabelName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// kubecostGetterFromEnv reaches Kubecost's API (cost.kubecost on the chart,
// PROJECT.md PG22): an in-cluster Service URL or an external one, with
// headers from a mounted Secret. Nil when not configured.
func kubecostGetterFromEnv() cost.KubecostGetter {
	raw := strings.TrimSpace(os.Getenv("ARGUS_KUBECOST_URL"))
	if raw == "" {
		return nil
	}
	base, err := url.Parse(raw)
	if err != nil || base.Host == "" {
		return nil
	}
	headers := http.Header{}
	if path := os.Getenv("ARGUS_KUBECOST_HEADERS_FILE"); path != "" {
		if b, err := os.ReadFile(path); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if k, v, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && !strings.HasPrefix(k, "#") {
					headers.Add(strings.TrimSpace(k), strings.TrimSpace(v))
				}
			}
		}
	}
	client := &http.Client{Timeout: 30 * time.Second}
	return func(ctx context.Context, path string, params url.Values) ([]byte, error) {
		u := *base
		u.Path = strings.TrimSuffix(u.Path, "/") + "/" + strings.TrimPrefix(path, "/")
		u.RawQuery = params.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header = headers.Clone()
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("kubecost answered HTTP %d", resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, maxExternalMetricsBody))
	}
}
