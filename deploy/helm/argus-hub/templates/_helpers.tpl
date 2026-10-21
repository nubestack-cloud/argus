{{/*
The logical name, fixed rather than read from .Chart.Name: the published
chart is called argus-hub-chart (so it does not share a Docker Hub repository
with the argus-hub image), and resource names must not change with it.
*/}}
{{- define "argus-hub.name" -}}
{{- default "argus-hub" .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
The base of every object name. A release whose name already contains
"argus-hub" (the usual `helm install argus-hub ...`) is used as is, so objects
are argus-hub, argus-hub-postgres and so on. A release installed before that
rule named them <release>-argus-hub; its existing Deployment is looked up and
the old names kept, because renaming the Postgres StatefulSet would leave its
data behind.
*/}}
{{- define "argus-hub.fullname" -}}
{{- $name := include "argus-hub.name" . -}}
{{- $legacy := printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else if not (contains $name .Release.Name) -}}
{{- $legacy -}}
{{- else if lookup "apps/v1" "Deployment" .Release.Namespace $legacy -}}
{{- $legacy -}}
{{- else -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "argus-hub.labels" -}}
app.kubernetes.io/name: {{ include "argus-hub.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "argus-hub.selectorLabels" -}}
app.kubernetes.io/name: {{ include "argus-hub.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "argus-hub.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "argus-hub.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "argus-hub.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}
{{- end -}}

{{/*
Same digest-preferred pattern as argus-hub.image above, for the separate
cliRunner image (see values.yaml's cliRunner.image.digest comment for how
this digest gets updated).
*/}}
{{- define "argus-hub.cliRunnerImage" -}}
{{- if .Values.cliRunner.image.digest -}}
{{ .Values.cliRunner.image.repository }}@{{ .Values.cliRunner.image.digest }}
{{- else -}}
{{ .Values.cliRunner.image.repository }}:{{ .Values.cliRunner.image.tag }}
{{- end -}}
{{- end -}}

{{- define "argus-hub.postgresService" -}}
{{ include "argus-hub.fullname" . }}-postgres
{{- end -}}

{{/*
Validation, gathered in one place so a bad install fails at `helm template`
with a sentence an operator can act on, rather than at runtime as a TLS name
mismatch or a hub that cannot reach its database.
*/}}
{{- define "argus-hub.validate" -}}
{{- if and .Values.tunnel.ingress.enabled (not .Values.tunnel.publicEndpoint) -}}
{{- fail "\n\ntunnel.ingress (SNI passthrough) needs tunnel.publicEndpoint set to <tunnel.ingress.host>:443.\n\nMost installs need neither: with both unset, agents tunnel through the ordinary Ingress at ingress.host.\n" -}}
{{- end -}}
{{- if gt (int .Values.replicaCount) 1 -}}
{{- fail "\n\nreplicaCount must be 1.\n\nThe hub holds every agent's tunnel in memory, so a second replica would make agents flap between pods and send their requests to a pod that does not hold the connection. Multi-replica hubs are on the roadmap (docs/SUPPORT.md, Known Limits).\n" -}}
{{- end -}}
{{- if and (eq .Values.postgres.mode "external") (not .Values.postgres.external.existingSecret) -}}
{{- fail "\n\npostgres.external.existingSecret is required when postgres.mode=external.\n\nIt must hold the app connection string and a migration connection string (keys: postgres.external.urlKey / migrateUrlKey).\n" -}}
{{- end -}}
{{- if not (has (toString .Values.cliRunner.enabled) (list "true" "false" "auto" "" "<nil>")) -}}
{{- fail (printf "cliRunner.enabled must be true, false or auto, got %q" (toString .Values.cliRunner.enabled)) -}}
{{- end -}}
{{- if not (has .Values.postgres.mode (list "bundled" "external")) -}}
{{- fail (printf "postgres.mode must be \"bundled\" or \"external\", got %q" .Values.postgres.mode) -}}
{{- end -}}
{{- if and (eq (toString .Values.cliRunner.enabled) "true") (not (include "argus-hub.cliRunnerCredentialSupplied" .)) -}}
{{- fail "\n\ncliRunner.enabled=true needs a model credential.\n\nARGUS never ships one. Set cliRunner.modelCredential.anthropicApiKey, .claudeCodeOauthToken for a Claude subscription, .openaiApiKey for Codex, or point .existingSecret at a Secret holding the needed key.\n" -}}
{{- end -}}
{{- end -}}

{{/*
The Secret name holding Postgres connection strings, whichever mode is in use —
so the Deployment and its migrate init container reference one thing.
*/}}
{{- define "argus-hub.dbSecretName" -}}
{{- if eq .Values.postgres.mode "external" -}}
{{ .Values.postgres.external.existingSecret }}
{{- else -}}
{{ include "argus-hub.fullname" . }}-db
{{- end -}}
{{- end -}}

{{- define "argus-hub.dbUrlKey" -}}
{{- if eq .Values.postgres.mode "external" }}{{ .Values.postgres.external.urlKey }}{{ else }}url{{ end -}}
{{- end -}}

{{- define "argus-hub.dbMigrateUrlKey" -}}
{{- if eq .Values.postgres.mode "external" }}{{ .Values.postgres.external.migrateUrlKey }}{{ else }}migrateUrl{{ end -}}
{{- end -}}

{{/*
Whether the database outlives `helm uninstall`: always for external Postgres,
and for bundled Postgres when its PVC is retained (the default). When it does,
every Secret whose value the database has already absorbed must survive too —
the Postgres password (baked into the data directory by initdb), the bootstrap
password (the admin row already exists), the runner token (stored in the AI
provider row) and the metrics token (in someone's scrape config). Otherwise a
reinstall mints new values the retained data has never seen and the operator
is locked out of their own install. The templates' lookup-then-generate logic
reuses a surviving Secret, so keeping it is all that is needed.
*/}}
{{- define "argus-hub.keepGeneratedSecrets" -}}
{{- if or (eq .Values.postgres.mode "external") (and .Values.postgres.bundled.persistence.enabled .Values.postgres.bundled.persistence.retainOnDelete) -}}
true
{{- end -}}
{{- end -}}

{{- define "argus-hub.keepAnnotation" -}}
{{- if include "argus-hub.keepGeneratedSecrets" . }}
annotations:
  # See argus-hub.keepGeneratedSecrets in _helpers.tpl.
  "helm.sh/resource-policy": keep
{{- end }}
{{- end -}}

{{/*
Whether a model credential was supplied in any of the forms the runner reads.
*/}}
{{- define "argus-hub.cliRunnerCredentialSupplied" -}}
{{- $m := .Values.cliRunner.modelCredential -}}
{{- if or $m.existingSecret $m.anthropicApiKey $m.claudeCodeOauthToken $m.openaiApiKey -}}
true
{{- end -}}
{{- end -}}

{{/*
Whether the CLI runner is deployed — the ONE place that decides it; every
template that renders or wires the runner asks this, never
.Values.cliRunner.enabled directly.

  true   always (and argus-hub.validate refuses to render without a credential)
  false  never, even with a credential supplied
  auto   (the default) exactly when a model credential is supplied

Upgrade safety: the old default was `false`, so a release could only be
running the runner because someone set enabled=true, and a value someone set
is reapplied by `--reset-then-reuse-values`, by `--reuse-values` and by a
values file alike. An explicit `false` stays off the same way. The one
behaviour change is a release that supplied a credential but never enabled
the runner: auto now deploys it. That adds a component on upgrade; it never
removes one.
*/}}
{{- define "argus-hub.cliRunnerEnabled" -}}
{{- $e := toString .Values.cliRunner.enabled -}}
{{- if eq $e "true" -}}
true
{{- else if and (has $e (list "auto" "" "<nil>")) (include "argus-hub.cliRunnerCredentialSupplied" .) -}}
true
{{- end -}}
{{- end -}}

{{/*
Whether the Ingress is rendered: ingress.enabled (true by default) and a host
to serve. Setting ingress.host is all an install needs to do.
*/}}
{{- define "argus-hub.ingressEnabled" -}}
{{- if and .Values.ingress.enabled .Values.ingress.host -}}true{{- end -}}
{{- end -}}

{{/*
Whether the Ingress serves HTTPS: asked for, or implied by a cert-manager
issuer.
*/}}
{{- define "argus-hub.ingressTLS" -}}
{{- if or .Values.ingress.tls.enabled .Values.ingress.clusterIssuer -}}true{{- end -}}
{{- end -}}

{{/*
The address agents use for the hub, for enrolling and (unless
tunnel.publicEndpoint says otherwise) for the tunnel: publicApiUrl, else the
ingress host, else the hub's in-cluster Service, which serves agents in this
cluster only.
*/}}
{{- define "argus-hub.publicApiUrl" -}}
{{- if .Values.publicApiUrl -}}
{{- .Values.publicApiUrl -}}
{{- else if include "argus-hub.ingressEnabled" . -}}
{{- printf "%s://%s" (ternary "https" "http" (eq (include "argus-hub.ingressTLS" .) "true")) .Values.ingress.host -}}
{{- else if .Values.httpRoute.host -}}
{{- printf "%s://%s" (ternary "https" "http" .Values.httpRoute.https) .Values.httpRoute.host -}}
{{- else -}}
{{- printf "http://%s.%s.svc:%v" (include "argus-hub.fullname" .) .Release.Namespace .Values.api.service.port -}}
{{- end -}}
{{- end -}}


{{/*
"true" when this release deploys its own cluster's agent (localAgent): it is
enabled, the hub is in argus-system (where the agent's fixed-name identities
live), and the cluster does not already run an agent from another release (an
install that predates the local agent, or one added by hand), whose objects
the local agent would collide with. The agent chart's argus-agent.skip makes
the same decision for the agent's own objects; NOTES.txt says when it skipped.
*/}}
{{- define "argus-hub.localAgent" -}}
{{- if .Values.localAgent.enabled -}}
{{- $existing := lookup "apps/v1" "Deployment" "argus-system" "argus-agent" -}}
{{- if and (eq .Release.Namespace "argus-system") (not (and $existing (ne (dig "metadata" "annotations" "meta.helm.sh/release-name" "" $existing) .Release.Name))) -}}
{{- if and (or .Values.fullnameOverride .Values.nameOverride (ne (int .Values.api.service.port) 8080)) (not (dig "hub" "apiUrl" "" .Values.localAgent)) -}}
{{- fail (printf "localAgent: with fullnameOverride, nameOverride or a non-default api.service.port, set localAgent.hub.apiUrl to the hub's in-cluster URL (http://<service>.%s.svc:<port>)." .Release.Namespace) -}}
{{- end -}}
true
{{- end -}}
{{- end -}}
{{- end -}}
