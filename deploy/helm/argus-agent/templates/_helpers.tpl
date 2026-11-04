{{/*
Common labels applied to every resource this chart creates.
*/}}
{{- define "argus-agent.labels" -}}
app.kubernetes.io/name: argus-agent
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: argus
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{/*
Selector labels — a stable subset of the above, safe to use in a
Deployment's spec.selector.matchLabels (which is immutable after creation).
Never add anything here that might change across upgrades (e.g. version).
*/}}
{{- define "argus-agent.selectorLabels" -}}
app.kubernetes.io/name: argus-agent
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Selector labels for the REMEDIATION agent Deployment (PROJECT.md E11).

A DIFFERENT app.kubernetes.io/name, not the investigation agent's plus an
extra label. Found live: with a shared name/instance pair, the investigation
Deployment's own selector (which is exactly those two labels, and is
immutable after creation) MATCHES the remediation agent's pods. Kubernetes
tolerates the overlap at the ReplicaSet level because a ReplicaSet's
generated selector also carries pod-template-hash, but everything that
resolves a Deployment to its pods by selector does not — `kubectl logs
deploy/argus-agent` returned the REMEDIATION agent's log, which is exactly
the kind of confusion that costs an hour during an incident.

Distinguishing the remediation agent by name rather than adding a label to
the investigation agent's selector is deliberate: spec.selector is immutable
after creation, so narrowing the existing Deployment's selector would break
`helm upgrade` on every cluster that already has one.
*/}}
{{- define "argus-agent.remediateSelectorLabels" -}}
app.kubernetes.io/name: argus-agent-remediate
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Builds a CEL list literal that projects a fixed set of named fields off one
root expression — e.g. for root "c" and fields (image, env):

    [(has(c.image) ? [c.image] : []), (has(c.env) ? [c.env] : [])]

Used by templates/validatingadmissionpolicy.yaml to express "these two
objects are equal EXCEPT at one field" without naming that field: compare the
projections instead of the objects, and leave the exempt field out of the
projection. CEL cannot say it any more directly — a Kubernetes object is a
schema-typed value, not a map, so its keys cannot be enumerated or subtracted
at runtime and "everything except X" has to be spelled out. Generating the
list from a Helm list means the reviewable artifact is that list of field
names, not 40 lines of near-identical CEL, and updating it for a new
Kubernetes minor is a one-line edit.

Each term is wrapped in a single-element list on purpose. The obvious
alternative, `has(c.image) ? c.image : null`, asks CEL to unify a string with
null in a conditional; `[c.image]` vs `[]` are both lists, which always
type-checks, never throws on an absent field, and still distinguishes "absent"
from "present but empty" ([] vs [[]]).
*/}}
{{- define "argus-agent.celFieldProjection" -}}
{{- $root := .root -}}
{{- $terms := list -}}
{{- range $f := .fields -}}
{{- $terms = append $terms (printf "(has(%s.%s) ? [%s.%s] : [])" $root $f $root $f) -}}
{{- end -}}
[{{ join ", " $terms }}]
{{- end -}}

{{/*
Resolves which Secret name the Deployment should read ARGUS_ENROLLMENT_TOKEN
from: the operator-supplied enrollment.tokenSecretRef if set, otherwise the
chart-generated Secret backed by enrollment.token (templates/secret.yaml).
Fails the render outright if neither is configured, rather than shipping a
Deployment that would only fail later, opaquely, inside the cluster
(CreateContainerConfigError against a Secret name that was never created).
*/}}
{{- define "argus-agent.enrollmentSecretName" -}}
{{- if .Values.enrollment.tokenSecretRef.name -}}
{{ .Values.enrollment.tokenSecretRef.name }}
{{- else if .Values.enrollment.token -}}
{{ .Values.enrollment.generatedSecretName }}
{{- else -}}
{{ fail "argus-agent: set either enrollment.tokenSecretRef.name (preferred - an existing Secret you create yourself) or enrollment.token (dev/testing only) so the agent has an enrollment token. Neither is set." }}
{{- end -}}
{{- end -}}

{{/*
Resolves which key within that Secret holds the raw token string.
*/}}
{{- define "argus-agent.enrollmentSecretKey" -}}
{{- if .Values.enrollment.tokenSecretRef.name -}}
{{ .Values.enrollment.tokenSecretRef.key | default "token" }}
{{- else -}}
token
{{- end -}}
{{- end -}}

{{/*
The ServiceAccount the investigation agent Deployment runs as. ALWAYS
argus-investigate — read-only, no create/update/patch/delete of anything,
whether or not remediation is enabled on this cluster.

PROJECT.md E11 changed this. It used to resolve to argus-remediate whenever
remediate.enabled was set, because the chart ran ONE agent process bound to
the UNION of both ClusterRoles — so the model's read-only tool loop ran under
an identity that could also write, and was merely not TOLD to write. That is
what non-negotiable 1 exists to forbid ("a compromised investigation path
must never gain write access by itself"), and the union ClusterRoleBinding
that made it true (argus-remediate-investigate) is gone.

Remediation now runs as its own Deployment under its own ServiceAccount, on
its own tunnel connection — see templates/remediate-deployment.yaml.
*/}}
{{- define "argus-agent.serviceAccountName" -}}
{{ .Values.serviceAccount.name }}
{{- end -}}

{{/*
Same digest-preferred image reference as argus-hub.image — see
values.yaml's image.digest comment for how this gets updated (a real
maintenance action, not a one-time pin).
*/}}
{{- define "argus-agent.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag }}
{{- end -}}
{{- end -}}

{{/*
PROJECT.md K2: an extra CA the agent trusts for HTTPS to hub.apiUrl, from
hub.caBundle (a PEM string the chart puts in a ConfigMap — CA certificates are
public) or hub.caSecretRef (an existing Secret you manage). Appended to the
image's system roots by the agent (internal/agent.NewHubHTTPClient), never a
replacement for them. Setting both is a render error rather than a silent
precedence rule. `dig` keeps a release upgraded with plain --reuse-values,
whose stored values predate hub.caSecretRef, rendering instead of failing on
a nil map.
*/}}
{{- define "argus-agent.hubCAEnabled" -}}
{{- $bundle := dig "caBundle" "" .Values.hub -}}
{{- $secret := dig "caSecretRef" "name" "" .Values.hub -}}
{{- if and $bundle $secret -}}
{{- fail "argus-agent: set hub.caBundle OR hub.caSecretRef.name, not both — the agent trusts one extra CA bundle for hub.apiUrl, and the chart will not guess which you meant." -}}
{{- end -}}
{{- if or $bundle $secret -}}true{{- end -}}
{{- end -}}

{{- define "argus-agent.hubCAMountPath" -}}/etc/argus/hub-ca{{- end -}}

{{- define "argus-agent.hubCAEnv" -}}
{{- if include "argus-agent.hubCAEnabled" . -}}
# PROJECT.md K2: appended to the system roots for HTTPS to hub.apiUrl.
- name: ARGUS_HUB_CA_FILE
  value: {{ printf "%s/ca.crt" (include "argus-agent.hubCAMountPath" .) | quote }}
{{- end }}
{{- end -}}

{{- define "argus-agent.hubCAVolumeMount" -}}
{{- if include "argus-agent.hubCAEnabled" . -}}
- name: hub-ca
  mountPath: {{ include "argus-agent.hubCAMountPath" . }}
  readOnly: true
{{- end }}
{{- end -}}

{{/*
A Secret volume is mounted by kubelet, not read through the agent's
ServiceAccount, so hub.caSecretRef widens neither identity's API access —
argus-investigate still holds no Secret read.
*/}}
{{- define "argus-agent.hubCAVolume" -}}
{{- if include "argus-agent.hubCAEnabled" . -}}
- name: hub-ca
{{- if dig "caBundle" "" .Values.hub }}
  configMap:
    name: argus-agent-hub-ca
{{- else }}
  secret:
    secretName: {{ .Values.hub.caSecretRef.name }}
    items:
      - key: {{ .Values.hub.caSecretRef.key | default "ca.crt" }}
        path: ca.crt
{{- end }}
{{- end }}
{{- end -}}

{{/*
PROJECT.md K2: persistence.storageClass is the name the hub chart uses
(postgres.bundled.persistence.storageClass). persistence.storageClassName is
this chart's old name, still honoured as a deprecated alias; the new key wins
when both are set, and NOTES.txt warns whenever the old one is in use.
*/}}
{{- define "argus-agent.storageClass" -}}
{{- with coalesce .Values.persistence.storageClass .Values.persistence.storageClassName }}{{ . }}{{ end -}}
{{- end -}}

{{/*
Embedded: the hub chart installs this chart as its localAgent, for the hub's
own cluster. The agent then reaches the hub at the hub's in-cluster Service,
for enrollment and for the tunnel, never through the Ingress. The Service
name follows the hub chart's argus-hub.fullname (a release named *argus-hub*
is used as is, unless it predates that rule); a hub with fullnameOverride or
nameOverride sets localAgent.hub.apiUrl instead, which the hub chart enforces.
*/}}
{{- define "argus-agent.embeddedHub" -}}
{{- $legacy := printf "%s-argus-hub" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- $svc := .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- if not (contains "argus-hub" .Release.Name) -}}
{{- $svc = $legacy -}}
{{- else if lookup "apps/v1" "Deployment" .Release.Namespace $legacy -}}
{{- $svc = $legacy -}}
{{- end -}}
{{- printf "%s.%s.svc:8080" $svc .Release.Namespace -}}
{{- end -}}

{{- define "argus-agent.hubApiUrl" -}}
{{- if .Values.hub.apiUrl -}}
{{- .Values.hub.apiUrl -}}
{{- else if .Values.embedded -}}
{{- printf "http://%s" (include "argus-agent.embeddedHub" .) -}}
{{- else -}}
{{- required "hub.apiUrl is required: set it to the ARGUS hub's URL (e.g. https://argus.example.com)" "" -}}
{{- end -}}
{{- end -}}

{{- define "argus-agent.tunnelEndpoint" -}}
{{- if .Values.hub.tunnelEndpoint -}}
{{- .Values.hub.tunnelEndpoint -}}
{{- else if and .Values.embedded (not .Values.hub.apiUrl) -}}
{{- printf "ws://%s/api/v1/agent/tunnel" (include "argus-agent.embeddedHub" .) -}}
{{- end -}}
{{- end -}}

{{/*
"true" when the hub chart's localAgent should render nothing: the hub is not
in this chart's namespace (argus-system), or this cluster already runs an
agent installed by another release (an install that predates the local agent,
or one installed by hand), whose fixed-name objects it would collide with.
*/}}
{{- define "argus-agent.skip" -}}
{{- if .Values.embedded -}}
{{- $existing := lookup "apps/v1" "Deployment" .Values.namespace.name "argus-agent" -}}
{{- if ne .Release.Namespace .Values.namespace.name -}}
true
{{- else if and $existing (ne (dig "metadata" "annotations" "meta.helm.sh/release-name" "" $existing) .Release.Name) -}}
true
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
"true" on OpenShift, where the restricted security policy assigns each pod a
user and group from the namespace's range and refuses fixed ones: every pod
then leaves runAsUser, runAsGroup and fsGroup out and keeps the rest of its
security context. `openshift: auto` (the default) detects it from the
security.openshift.io API; true or false forces it. global.openshift, when
set, wins, so one setting reaches the hub and the agent it installs.
*/}}
{{- define "argus-agent.openshift" -}}
{{- $v := toString (dig "openshift" .Values.openshift (.Values.global | default dict)) -}}
{{- if or (eq $v "true") (and (has $v (list "auto" "" "<nil>")) (.Capabilities.APIVersions.Has "security.openshift.io/v1")) -}}true{{- end -}}
{{- end -}}

{{/*
OpenShift's own cluster monitoring, as the URL query_metrics uses, or "" when
it does not apply. On OpenShift (and OKD) the platform Prometheus listens on
127.0.0.1 inside its pod: prometheus-operated:9090, which the Service
detection below would otherwise pick, accepts no connection from anywhere
else, so every query through the services/proxy path failed. What OpenShift
does serve is the Thanos querier's kube-rbac-proxy on the "web" port
(9091), over the service-CA certificate, authenticating the caller's own
ServiceAccount token. The agent's existing cluster-wide read already
satisfies its authorisation, so no extra RBAC is granted for it.

Applies only when nothing was configured by hand (prometheusService,
external.url), autoDetect is on, the cluster is OpenShift, and the Service
exists. Under `helm template` there is no cluster to look at, and it is "".
*/}}
{{- define "argus-agent.openshiftMetricsURL" -}}
{{- $m := .Values.metrics -}}
{{- if and $m.autoDetect (not $m.external.url) (not (and $m.prometheusService.namespace $m.prometheusService.name)) (include "argus-agent.openshift" .) -}}
{{- with (lookup "v1" "Service" "openshift-monitoring" "thanos-querier") -}}
{{- $port := 9091 -}}
{{- range .spec.ports -}}{{- if eq (.name | default "") "web" -}}{{- $port = int .port -}}{{- end -}}{{- end -}}
{{- printf "https://thanos-querier.openshift-monitoring.svc:%d" $port -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
The Prometheus Service query_metrics uses, as JSON {namespace, name, port,
source}, or {} for none. metrics.prometheusService wins when set; otherwise,
with metrics.autoDetect (the default) and no metrics.external.url, the chart
looks the cluster's Services up at install and upgrade and picks one by the
agent's own rules (internal/agent/tools_insight_more.go's
detectMetricsService), so it connects the Service the Traffic tab would have
suggested: a Prometheus server, a Thanos query or a VictoriaMetrics single
node, never an exporter, operator or Alertmanager. Under `helm template` or a
client dry run there is no cluster to look at, and nothing is detected.
*/}}
{{- define "argus-agent.prometheusService" -}}
{{- $m := .Values.metrics -}}
{{- if and $m.prometheusService.namespace $m.prometheusService.name -}}
{{- dict "namespace" $m.prometheusService.namespace "name" $m.prometheusService.name "port" (int $m.prometheusService.port) "source" "set" | toJson -}}
{{- else if or $m.external.url (not $m.autoDetect) (not (lookup "v1" "Namespace" "" "kube-system")) (include "argus-agent.openshiftMetricsURL" .) -}}
{{- dict | toJson -}}
{{- else -}}
{{- $excludes := list "exporter" "operator" "adapter" "alertmanager" "pushgateway" "blackbox" "kube-state" "webhook" "vmagent" "vminsert" "vmalert" "sidecar" "store" "compact" "receive" "rule" -}}
{{- $best := dict -}}
{{- range (lookup "v1" "Service" "" "").items -}}
{{- $name := lower .metadata.name -}}
{{- $lbl := .metadata.labels | default dict -}}
{{- $appName := lower (printf "%s %s" (index $lbl "app.kubernetes.io/name" | default "") (index $lbl "app" | default "")) -}}
{{- $flavour := "" -}}
{{- if or (contains "prometheus" $appName) (contains "prometheus" $name) -}}
{{- $flavour = "prometheus" -}}
{{- else if or (contains "thanos-quer" $name) (contains "thanos-quer" $appName) (and (eq (index $lbl "app.kubernetes.io/component" | default "") "query") (contains "thanos" $appName)) -}}
{{- $flavour = "thanos" -}}
{{- else if or (contains "vmsingle" $name) (contains "vmsingle" $appName) (contains "victoria-metrics-single" $name) -}}
{{- $flavour = "victoriametrics" -}}
{{- end -}}
{{- $excluded := false -}}
{{- range $excludes -}}{{- if contains . $name -}}{{- $excluded = true -}}{{- end -}}{{- end -}}
{{- if and $flavour (not $excluded) -}}
{{- $port := 0 -}}
{{- range .spec.ports -}}
{{- if eq $port 0 -}}
{{- if or (and (eq $flavour "victoriametrics") (eq (int .port) 8428)) (and (ne $flavour "victoriametrics") (or (eq (int .port) 9090) (and (eq $flavour "thanos") (eq (int .port) 10902)))) -}}
{{- $port = int .port -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if eq $port 0 -}}
{{- range .spec.ports -}}
{{- if and (eq $port 0) (or (eq (.name | default "") "web") (eq (.name | default "") "http-web") (and (eq $flavour "thanos") (eq (.name | default "") "http"))) -}}
{{- $port = int .port -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if ne $port 0 -}}
{{- $headless := eq (.spec.clusterIP | default "") "None" -}}
{{- $rank := 3 -}}
{{- if eq $flavour "thanos" -}}{{- $rank = 4 -}}
{{- else if eq $flavour "victoriametrics" -}}{{- $rank = 5 -}}
{{- else if and (or (eq $name "prometheus") (hasSuffix "-prometheus" $name)) (not $headless) -}}{{- $rank = 0 -}}
{{- else if eq $name "prometheus-operated" -}}{{- $rank = 1 -}}
{{- else if or (eq (index $lbl "app.kubernetes.io/name" | default "") "prometheus") (eq (index $lbl "app" | default "") "prometheus") -}}{{- $rank = 2 -}}
{{- end -}}
{{- $key := printf "%s/%s" .metadata.namespace .metadata.name -}}
{{- if or (not $best) (lt $rank (int $best.rank)) (and (eq $rank (int $best.rank)) (lt $key $best.key)) -}}
{{- $best = dict "rank" $rank "key" $key "namespace" .metadata.namespace "name" .metadata.name "port" $port -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if $best -}}
{{- dict "namespace" $best.namespace "name" $best.name "port" $best.port "source" "detected" | toJson -}}
{{- else -}}
{{- dict | toJson -}}
{{- end -}}
{{- end -}}
{{- end -}}
