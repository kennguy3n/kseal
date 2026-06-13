{{/*
Expand the name of the chart.
*/}}
{{- define "kseal.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified app name.
*/}}
{{- define "kseal.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "kseal.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels applied to every object.
*/}}
{{- define "kseal.labels" -}}
helm.sh/chart: {{ include "kseal.chart" . }}
app.kubernetes.io/name: {{ include "kseal.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: kseal
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/*
Server selector labels (stable across upgrades).
*/}}
{{- define "kseal.server.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kseal.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: server
{{- end -}}

{{/*
Console selector labels.
*/}}
{{- define "kseal.console.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kseal.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: console
{{- end -}}

{{- define "kseal.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "kseal.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Name of the Secret holding server secrets (KEK, DSN, Redis).
*/}}
{{- define "kseal.secretName" -}}
{{- if .Values.externalSecrets.existingSecret -}}
{{- .Values.externalSecrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "kseal.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Resolve the server image reference (digest wins over tag).
*/}}
{{- define "kseal.server.image" -}}
{{- $repo := .Values.server.image.repository | default (printf "%s/%s" .Values.image.registry .Values.image.repository) -}}
{{- if .Values.server.image.digest -}}
{{- printf "%s@%s" $repo .Values.server.image.digest -}}
{{- else -}}
{{- printf "%s:%s" $repo (.Values.server.image.tag | default .Chart.AppVersion) -}}
{{- end -}}
{{- end -}}

{{/*
Resolve the console image reference (defaults to "<repo>-console").
*/}}
{{- define "kseal.console.image" -}}
{{- $repo := .Values.console.image.repository | default (printf "%s/%s-console" .Values.image.registry .Values.image.repository) -}}
{{- if .Values.console.image.digest -}}
{{- printf "%s@%s" $repo .Values.console.image.digest -}}
{{- else -}}
{{- printf "%s:%s" $repo (.Values.console.image.tag | default .Chart.AppVersion) -}}
{{- end -}}
{{- end -}}

{{/*
Server pod anti-affinity from a preset (soft|hard).
*/}}
{{- define "kseal.podAntiAffinity" -}}
{{- $preset := index . 0 -}}
{{- $labels := index . 1 -}}
{{- if eq $preset "hard" }}
podAntiAffinity:
  requiredDuringSchedulingIgnoredDuringExecution:
    - topologyKey: kubernetes.io/hostname
      labelSelector:
        matchLabels:
{{ $labels | indent 10 }}
{{- else if eq $preset "soft" }}
podAntiAffinity:
  preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        topologyKey: kubernetes.io/hostname
        labelSelector:
          matchLabels:
{{ $labels | indent 12 }}
{{- end -}}
{{- end -}}

{{/*
Render topologySpreadConstraints from values, injecting the component selector
as the labelSelector for any constraint that doesn't define its own. Keeps every
other field the user sets (maxSkew, topologyKey, minDomains, ...) intact.
Args: (dict "constraints" <list> "selector" <selectorLabels-yaml>).
*/}}
{{- define "kseal.topologySpreadConstraints" -}}
{{- $selector := fromYaml (index . "selector") -}}
{{- $out := list -}}
{{- range (index . "constraints") -}}
{{- $c := deepCopy . -}}
{{- if not $c.labelSelector -}}
{{- $_ := set $c "labelSelector" (dict "matchLabels" $selector) -}}
{{- end -}}
{{- $out = append $out $c -}}
{{- end -}}
{{- toYaml $out -}}
{{- end -}}
