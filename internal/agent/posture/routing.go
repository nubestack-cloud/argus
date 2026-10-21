package posture

import (
	"fmt"

	"k8s.io/apimachinery/pkg/labels"
)

// names is a set of namespace/name pairs.
type names map[NamespacedRef]bool

func (in *CheckInput) serviceNames() names {
	out := names{}
	for _, svc := range in.Services {
		out[NamespacedRef{svc.Namespace, svc.Name}] = true
	}
	return out
}

func (in *CheckInput) middlewareNames() names {
	out := names{}
	for _, mw := range in.TraefikMiddlewares {
		out[NamespacedRef{mw.Namespace, mw.Name}] = true
	}
	return out
}

func (r NamespacedRef) String() string { return r.Namespace + "/" + r.Name }

// emptyServices flags selector Services no pod in their namespace matches.
// Services without a selector, and ExternalName Services, have no pods to
// match and are not judged.
func (s *scan) emptyServices() {
	pods := map[string][]labels.Set{}
	for _, p := range s.in.Pods {
		pods[p.Namespace] = append(pods[p.Namespace], p.Labels)
	}
	for _, svc := range s.in.Services {
		if len(svc.Spec.Selector) == 0 || svc.Spec.Type == "ExternalName" {
			continue
		}
		s.evaluated(svc.Namespace, "serviceNoMatchingPods")
		sel := labels.SelectorFromSet(svc.Spec.Selector)
		matched := false
		for _, l := range pods[svc.Namespace] {
			if sel.Matches(l) {
				matched = true
				break
			}
		}
		if !matched {
			s.flag(object("Service", svc.Namespace, svc.Name), "serviceNoMatchingPods", SeverityWarning,
				fmt.Sprintf("no pod in %s has the labels %s", svc.Namespace, sel))
		}
	}
}

// ingressBackends flags Ingress paths whose backend Service is missing. An
// Ingress with no Service backends has nothing to judge.
func (s *scan) ingressBackends() {
	services := s.in.serviceNames()
	for _, ing := range s.in.Ingresses {
		judged := false
		for _, rule := range ing.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}
			for _, path := range rule.HTTP.Paths {
				backend := path.Backend.Service
				if backend == nil {
					continue
				}
				judged = true
				if !services[NamespacedRef{ing.Namespace, backend.Name}] {
					s.flag(object("Ingress", ing.Namespace, ing.Name), "ingressNoMatchingService", SeverityWarning,
						fmt.Sprintf("path %q sends traffic to Service %q, which does not exist", path.Path, backend.Name))
				}
			}
		}
		if judged {
			s.evaluated(ing.Namespace, "ingressNoMatchingService")
		}
	}
}

// traefik runs the four Traefik reference checks when its CRDs are served.
// Having none of its objects is then a real "nothing wrong".
func (s *scan) traefik() {
	if !s.in.TraefikCRDsPresent {
		return
	}
	services, middlewares := s.in.serviceNames(), s.in.middlewareNames()
	dangling := func(at subject, checkID, what string, refs []NamespacedRef, known names) {
		for _, r := range refs {
			if !known[r] {
				s.flag(at, checkID, SeverityDanger, fmt.Sprintf("%s %s does not exist", what, r))
			}
		}
	}
	for _, r := range s.in.TraefikRoutes {
		at := subject{"traefik.io", "IngressRoute", r.Namespace, r.Name}
		s.evaluated(r.Namespace, "traefikIngressRouteMissingService")
		dangling(at, "traefikIngressRouteMissingService", "routed Service", r.Services, services)
		s.evaluated(r.Namespace, "traefikIngressRouteMissingMiddleware")
		dangling(at, "traefikIngressRouteMissingMiddleware", "Middleware", r.Middlewares, middlewares)
	}
	for _, m := range s.in.TraefikMiddlewares {
		at := subject{"traefik.io", "Middleware", m.Namespace, m.Name}
		if m.ErrorsService != nil {
			s.evaluated(m.Namespace, "traefikErrorsMiddlewareMissingService")
			dangling(at, "traefikErrorsMiddlewareMissingService", "error-page Service", []NamespacedRef{*m.ErrorsService}, services)
		}
		if len(m.ChainMiddlewares) > 0 {
			s.evaluated(m.Namespace, "traefikMiddlewareChainMissingMember")
			dangling(at, "traefikMiddlewareChainMissingMember", "chained Middleware", m.ChainMiddlewares, middlewares)
		}
	}
}
