// Package pathprobe sends one round of real traffic along a Service's
// declared path (PROJECT.md PG16): a DNS lookup of the Service name, a TCP
// connect to its cluster IP on each port, a TCP connect to a few ready
// endpoints, and an HTTP GET where the port looks like HTTP. It confirms or
// escalates the static trace (internal/agent/pathtrace), which reasons from
// declared state alone.
//
// Every result speaks from the agent pod's vantage point: a NetworkPolicy
// that admits the real caller but not the agent, or the reverse, makes the
// probe disagree with what that caller sees, and the result says so. Nothing
// read is returned but status: no response body, no headers.
package pathprobe

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
)

const (
	stepTimeout   = 3 * time.Second
	maxPorts      = 4
	maxEndpoints  = 5
	VantageNotice = "Probed from the ARGUS agent's own pod: a NetworkPolicy or mesh rule that treats the agent differently from the real caller makes this result differ from what that caller sees."
)

// Step is one probe and what it found.
type Step struct {
	Kind   string `json:"kind"`   // dns, tcp-service, tcp-endpoint, http
	Target string `json:"target"` // what was contacted
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	Millis int64  `json:"millis"`
}

// Result is one probe run.
type Result struct {
	Vantage string `json:"vantage"`
	Steps   []Step `json:"steps"`
	// Verdict is reachable (every step answered), partial, or unreachable.
	Verdict string `json:"verdict"`
}

// Dialer and HTTP are swappable for tests.
type Dialer func(ctx context.Context, network, address string) (net.Conn, error)
type Resolver func(ctx context.Context, host string) ([]string, error)

type Prober struct {
	Dial    Dialer
	Resolve Resolver
	HTTP    *http.Client
}

func Default() Prober {
	d := &net.Dialer{Timeout: stepTimeout}
	return Prober{
		Dial:    d.DialContext,
		Resolve: net.DefaultResolver.LookupHost,
		HTTP: &http.Client{Timeout: stepTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // report the redirect, never follow it
		}},
	}
}

func httpish(p corev1.ServicePort) bool {
	n := strings.ToLower(p.Name)
	if strings.HasPrefix(n, "http") && !strings.HasPrefix(n, "https") || n == "web" {
		return true
	}
	if p.AppProtocol != nil && strings.EqualFold(*p.AppProtocol, "http") {
		return true
	}
	return p.Port == 80 || p.Port == 8080 || p.Port == 8000
}

// Probe runs the steps for svc, using slices for its ready endpoints.
func (pr Prober) Probe(ctx context.Context, svc *corev1.Service, slices []*discoveryv1.EndpointSlice) Result {
	res := Result{Vantage: VantageNotice}
	add := func(s Step) { res.Steps = append(res.Steps, s) }
	host := svc.Name + "." + svc.Namespace + ".svc"

	start := time.Now()
	addrs, err := pr.Resolve(ctx, host)
	if err != nil {
		add(Step{Kind: "dns", Target: host, Detail: "did not resolve: " + shortErr(err), Millis: since(start)})
	} else {
		add(Step{Kind: "dns", Target: host, OK: true, Detail: "resolved to " + strings.Join(addrs, ", "), Millis: since(start)})
	}

	ip := svc.Spec.ClusterIP
	headless := ip == "" || ip == corev1.ClusterIPNone
	ports := svc.Spec.Ports
	if len(ports) > maxPorts {
		ports = ports[:maxPorts]
	}
	for _, p := range ports {
		if p.Protocol != "" && p.Protocol != corev1.ProtocolTCP {
			continue
		}
		if !headless {
			addr := net.JoinHostPort(ip, strconv.Itoa(int(p.Port)))
			add(pr.tcp(ctx, "tcp-service", addr))
			if httpish(p) {
				add(pr.get(ctx, "http://"+addr+"/"))
			}
		}
	}

	n := 0
	for _, sl := range slices {
		for _, ep := range sl.Endpoints {
			if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
				continue
			}
			for _, a := range ep.Addresses {
				for _, sp := range sl.Ports {
					if n >= maxEndpoints || sp.Port == nil || (sp.Protocol != nil && *sp.Protocol != corev1.ProtocolTCP) {
						continue
					}
					add(pr.tcp(ctx, "tcp-endpoint", net.JoinHostPort(a, strconv.Itoa(int(*sp.Port)))))
					n++
				}
			}
		}
	}
	if n == 0 {
		add(Step{Kind: "tcp-endpoint", Target: svc.Namespace + "/" + svc.Name, Detail: "no ready endpoint to contact"})
	}

	// Decided by what answered a connection. A name that resolves to an
	// address nobody answers on is unreachable, not partly reachable.
	ok, connOK := 0, 0
	for _, s := range res.Steps {
		if s.OK {
			ok++
		}
		if s.Kind != "dns" && s.OK {
			connOK++
		}
	}
	switch {
	case ok == len(res.Steps):
		res.Verdict = "reachable"
	case connOK == 0:
		res.Verdict = "unreachable"
	default:
		res.Verdict = "partial"
	}
	return res
}

func (pr Prober) tcp(ctx context.Context, kind, addr string) Step {
	start := time.Now()
	c, err := pr.Dial(ctx, "tcp", addr)
	if err != nil {
		return Step{Kind: kind, Target: addr, Detail: "connect failed: " + shortErr(err), Millis: since(start)}
	}
	_ = c.Close()
	return Step{Kind: kind, Target: addr, OK: true, Detail: "connected", Millis: since(start)}
}

func (pr Prober) get(ctx context.Context, url string) Step {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Step{Kind: "http", Target: url, Detail: err.Error()}
	}
	req.Header.Set("User-Agent", "argus-path-probe")
	resp, err := pr.HTTP.Do(req)
	if err != nil {
		return Step{Kind: "http", Target: url, Detail: "no HTTP answer: " + shortErr(err), Millis: since(start)}
	}
	_ = resp.Body.Close()
	// Any HTTP status is an answer: the path delivered the request to a
	// process. A 5xx is reported, and counted as not OK.
	return Step{Kind: "http", Target: url, OK: resp.StatusCode < 500, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode), Millis: since(start)}
}

func since(t time.Time) int64 { return time.Since(t).Milliseconds() }

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && i+2 < len(s) {
		s = s[i+2:]
	}
	return s
}
