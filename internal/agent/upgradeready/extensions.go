package upgradeready

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// backends knows which webhook Services exist and have a ready endpoint.
type backends struct {
	known       bool // Services and EndpointSlices were both read
	services    map[string]bool
	ready       map[string]bool
	unknownSaid bool
}

func (s *scan) backends() *backends {
	b := &backends{known: s.in.WebhookServices != nil && s.in.EndpointSlices != nil, services: map[string]bool{}, ready: map[string]bool{}}
	for _, svc := range s.in.WebhookServices {
		if svc != nil {
			b.services[svc.Namespace+"/"+svc.Name] = true
		}
	}
	for _, es := range s.in.EndpointSlices {
		if es == nil || es.Labels[discoveryv1.LabelServiceName] == "" {
			continue
		}
		if slices.ContainsFunc(es.Endpoints, func(e discoveryv1.Endpoint) bool { return e.Conditions.Ready == nil || *e.Conditions.Ready }) {
			b.ready[es.Namespace+"/"+es.Labels[discoveryv1.LabelServiceName]] = true
		}
	}
	return b
}

func (b *backends) up(key string) bool { return b.services[key] && b.ready[key] }

// unknown notes once, on the report, that backends could not be judged.
func (b *backends) unknown(r *report, what string) {
	if !b.unknownSaid {
		b.unknownSaid = true
		r.caveat("Services or EndpointSlices could not be read, so " + what + " could not be checked.")
	}
}

func str(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

func strs(v any) []string {
	var out []string
	list, _ := v.([]any)
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func hasAny(list []string, want ...string) bool {
	return slices.ContainsFunc(list, func(s string) bool { return slices.Contains(want, s) })
}

// interceptsAuth reports whether a webhook's rules catch the TokenReview or
// SubjectAccessReview creations authentication and authorization rely on.
func interceptsAuth(hook map[string]any) bool {
	rules, _, _ := unstructured.NestedSlice(hook, "rules")
	for _, raw := range rules {
		rule, _ := raw.(map[string]any)
		ops := strs(rule["operations"])
		if len(ops) > 0 && !slices.ContainsFunc(ops, func(o string) bool { return strings.EqualFold(o, "*") || strings.EqualFold(o, "CREATE") }) {
			continue
		}
		groups, resources := strs(rule["apiGroups"]), strs(rule["resources"])
		everything := hasAny(resources, "*", "*/*")
		if hasAny(groups, "*", "authentication.k8s.io") && (everything || hasAny(resources, "tokenreviews")) {
			return true
		}
		if hasAny(groups, "*", "authorization.k8s.io") && (everything || hasAny(resources, "subjectaccessreviews", "selfsubjectaccessreviews")) {
			return true
		}
	}
	return false
}

func (s *scan) admissionWebhooks() Check {
	r := newReport("admission-webhook-readiness", "Admission control", "Admission webhook readiness",
		"Admission webhook configurations, Services, and EndpointSlices",
		"Every admission webhook has a reachable backend and matches API versions safely.").citing(docAdmission)
	in := s.in
	unread := "Admission webhook configurations could not be read."
	if len(in.AdmissionWebhookUnavailableKinds) > 0 {
		unread = "Admission webhook configurations could not be read for " + strings.Join(in.AdmissionWebhookUnavailableKinds, ", ") + "."
	}
	if in.AdmissionWebhookConfigurations == nil {
		r.caveat(unread)
		return r.unknown("Admission webhook configurations could not be read.")
	}
	if len(in.AdmissionWebhookUnavailableKinds) > 0 {
		r.caveat(unread)
	}
	r.Inspected = len(in.AdmissionWebhookConfigurations)
	bk := s.backends()
	for _, cfg := range in.AdmissionWebhookConfigurations {
		if cfg == nil {
			continue
		}
		hooks, found, err := unstructured.NestedSlice(cfg.Object, "webhooks")
		if err != nil {
			r.caveat(cfg.GetName() + "'s webhooks could not be read.")
			continue
		}
		if !found {
			continue
		}
		at := &ResourceRef{Group: "admissionregistration.k8s.io", Kind: cfg.GetKind(), Name: cfg.GetName()}
		for i, raw := range hooks {
			hook, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			flag := func(level Level, title, field, detail, impact, fix string, cite []Reference) {
				f := r.flag(level, title, at, live(fmt.Sprintf("webhooks[%d].%s", i, field), detail), impact, fix)
				f.References = refs(cite)
			}
			if strings.EqualFold(str(hook, "matchPolicy"), "Exact") {
				flag(LevelReview, "Webhook matches API versions exactly", "matchPolicy", "Exact",
					"Exact matching can miss a request made through an equivalent API version during the upgrade.",
					"Use matchPolicy: Equivalent unless exact matching is deliberate.", docMatchPolicy)
			}
			if svc, found, _ := unstructured.NestedMap(hook, "clientConfig", "service"); found {
				key := str(svc, "namespace") + "/" + str(svc, "name")
				switch {
				case !bk.known:
					bk.unknown(r, "webhook backends")
				case bk.up(key):
				case strings.EqualFold(str(hook, "failurePolicy"), "Ignore"):
					flag(LevelWarning, "Fail-open webhook has no backend", "clientConfig.service", key,
						"Requests this webhook matches currently skip it, so the policy it enforces is bypassed while its backend is down.",
						"Restore the Service and a ready endpoint, or decide deliberately that bypassing the policy is acceptable.", docWebhookBackends)
				default:
					flag(LevelBlocker, "Fail-closed webhook has no backend", "clientConfig.service", key,
						"Requests this webhook matches are rejected while its backend is down.",
						"Restore the Service and a ready endpoint, or change failurePolicy after weighing the bypass it allows.", docWebhookBackends)
				}
			}
			if url, _, _ := unstructured.NestedString(hook, "clientConfig", "url"); url != "" {
				flag(LevelReview, "Webhook backend outside the cluster", "clientConfig.url", url,
					"ARGUS cannot tell whether a backend outside the cluster is up.",
					"Make sure the URL stays reachable and highly available through the control-plane upgrade, above all for fail-closed webhooks.", docWebhookBackends)
			}
			if interceptsAuth(hook) {
				flag(LevelReview, "Webhook intercepts authentication reviews", "rules", str(hook, "name"),
					"The webhook can catch the TokenReview or SubjectAccessReview requests authentication and authorization depend on.",
					"Keep the webhook available, and exclude the authentication and authorization review APIs unless it needs them.", docWebhookScope)
			}
		}
	}
	if r.Caveat != "" {
		r.Status = CheckUnknown
	}
	return r.finish(func(n int) string {
		return count(n, "admission webhook condition needs", "admission webhook conditions need") + " action or review."
	},
		"No admission risk was found, but some webhook evidence could not be read.")
}

// conversionNeeded reports whether the API server can be asked to convert
// this CRD's objects: it serves a version besides the storage version, or
// objects are still stored under another version.
func conversionNeeded(crd *unstructured.Unstructured) bool {
	versions, _, _ := unstructured.NestedSlice(crd.Object, "spec", "versions")
	storage := ""
	for _, raw := range versions {
		v, _ := raw.(map[string]any)
		stored, _ := v["storage"].(bool)
		served, _ := v["served"].(bool)
		if stored {
			storage = str(v, "name")
		} else if served {
			return true
		}
	}
	stored, _, _ := unstructured.NestedStringSlice(crd.Object, "status", "storedVersions")
	return storage != "" && slices.ContainsFunc(stored, func(v string) bool { return v != storage })
}

func (s *scan) conversionWebhooks() Check {
	r := newReport("crd-conversion-webhook-readiness", "API extensions", "CRD conversion webhook readiness",
		"CustomResourceDefinitions, Services, and EndpointSlices", "Every CRD conversion webhook has a ready backend.").citing(docCRDConversion)
	if s.in.CustomResourceDefinitions == nil {
		return r.unknown("CustomResourceDefinitions could not be read, so conversion webhooks were not looked at.")
	}
	bk := s.backends()
	for _, crd := range s.in.CustomResourceDefinitions {
		if crd == nil {
			continue
		}
		if strategy, _, _ := unstructured.NestedString(crd.Object, "spec", "conversion", "strategy"); strategy != "Webhook" {
			continue
		}
		r.Inspected++
		at := &ResourceRef{Group: "apiextensions.k8s.io", Kind: "CustomResourceDefinition", Name: crd.GetName()}
		const title = "CRD conversion webhook needs attention before the upgrade"
		client, found, err := unstructured.NestedMap(crd.Object, "spec", "conversion", "webhook", "clientConfig")
		if err != nil || !found {
			r.caveat(crd.GetName() + "'s conversion configuration could not be read.")
			continue
		}
		if url := str(client, "url"); url != "" {
			r.flag(LevelReview, title, at, live("spec.conversion.webhook.clientConfig.url", url),
				"A backend outside the cluster is beyond what Service readiness can show.",
				"Check the external endpoint's DNS, TLS, reachability and availability through the upgrade.")
			continue
		}
		svc, found, _ := unstructured.NestedMap(client, "service")
		ns, name := str(svc, "namespace"), str(svc, "name")
		valid := found && ns != "" && name != ""
		if valid && !bk.known {
			bk.unknown(r, "conversion backends")
			continue
		}
		if valid && bk.up(ns+"/"+name) {
			continue
		}
		level := LevelBlocker
		if !conversionNeeded(crd) {
			level = LevelWarning
		}
		r.flag(level, title, at, live("spec.conversion.webhook.clientConfig.service", ns+"/"+name),
			"While the backend is down the API server may be unable to convert stored custom resources.",
			"Restore the conversion Service and at least one ready endpoint before upgrading.")
	}
	if r.Inspected == 0 {
		return r.notApplicable("No CRD converts through a webhook.")
	}
	if r.Caveat != "" {
		r.Status = CheckUnknown
	}
	return r.finish(func(n int) string {
		return count(n, "conversion webhook condition needs", "conversion webhook conditions need") + " action or review."
	},
		"No conversion backend failure was found, but some CRD evidence could not be read.")
}

// condition reads a status condition from status.v1beta2.conditions or
// status.conditions.
func condition(o *unstructured.Unstructured, kind string) (status, reason, message string, found bool) {
	for _, path := range [][]string{{"status", "v1beta2", "conditions"}, {"status", "conditions"}} {
		conds, _, _ := unstructured.NestedSlice(o.Object, path...)
		for _, raw := range conds {
			c, ok := raw.(map[string]any)
			if ok && str(c, "type") == kind {
				return str(c, "status"), str(c, "reason"), str(c, "message"), true
			}
		}
	}
	return "", "", "", false
}

// conditionText renders a condition as "False (Reason): message", with the
// message on one line and at most 180 characters.
func conditionText(status, reason, message string) string {
	out := status
	if reason != "" {
		out += " (" + reason + ")"
	}
	if m := strings.Join(strings.Fields(message), " "); m != "" {
		if utf8.RuneCountInString(m) > 180 {
			m = string([]rune(m)[:179]) + "…"
		}
		out += ": " + m
	}
	return out
}

func (s *scan) aggregatedAPIs() Check {
	r := newReport("aggregated-apiservice-readiness", "API extensions", "Aggregated APIService readiness",
		"Delegated APIService availability conditions", "Every delegated APIService reports Available.").citing(docAPIServices)
	if s.in.APIServices == nil {
		return r.unknown("APIServices could not be read, so aggregated APIs were not looked at.")
	}
	for _, api := range s.in.APIServices {
		if api == nil {
			continue
		}
		if _, delegated, _ := unstructured.NestedMap(api.Object, "spec", "service"); !delegated {
			continue
		}
		r.Inspected++
		status, reason, message, found := condition(api, "Available")
		if !found || !slices.Contains([]string{"True", "False", "Unknown"}, status) {
			r.caveat(api.GetName() + " has no readable Available condition.")
			continue
		}
		if status == "True" {
			continue
		}
		r.flag(LevelWarning, "Aggregated API unavailable", &ResourceRef{Group: "apiregistration.k8s.io", Kind: "APIService", Name: api.GetName()},
			live("status.conditions[type=Available]", conditionText(status, reason, message)),
			"The API server cannot reach this delegated API, which can upset discovery, and the clients relying on it, during control-plane work.",
			"Restore the backing Service and its endpoints and clear any aggregation or TLS errors until Available is True.")
	}
	if r.Inspected == 0 {
		return r.notApplicable("No delegated APIService is registered.")
	}
	if r.Caveat != "" {
		r.Status = CheckUnknown
	}
	return r.finish(func(n int) string {
		return count(n, "delegated APIService is", "delegated APIServices are") + " unavailable."
	},
		"No unavailable aggregated API was found, but some APIService evidence could not be read.")
}
