{{- define "iceberg-ebs.name" -}}
{{- .Chart.Name }}
{{- end }}

{{- define "iceberg-ebs.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Name of the resources the bundled Bitnami postgresql subchart creates.

NOT "iceberg-ebs.fullname" + "-postgresql". A subchart's `common.names.fullname`
uses its OWN chart name, so Bitnami creates `<release>-postgresql` while our
fullname is `<release>-iceberg-ebs` — the chart referenced
`<release>-iceberg-ebs-postgresql`, a Secret and Service that never exist, so
the app pod died in CreateContainerConfigError and could not have resolved the
DB host either (#276).

Release-scoped like the subchart's own default, so two releases in a namespace
don't collide; honours `postgresql.fullnameOverride` if set, exactly as
`common.names.fullname` does.
*/}}
{{- define "iceberg-ebs.postgresql.fullname" -}}
{{- if .Values.postgresql.fullnameOverride -}}
{{- .Values.postgresql.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-postgresql" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end }}

{{/*
Selector labels for the bundled Postgres pods.

`app.kubernetes.io/name: postgresql` is deliberate: it is what the Bitnami
subchart used, and the allow-postgres-from-app NetworkPolicy selects on it. A
StatefulSet's selector is immutable, so changing these labels later means
deleting and recreating the StatefulSet.
*/}}
{{- define "iceberg-ebs.postgresql.selectorLabels" -}}
app.kubernetes.io/name: postgresql
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "iceberg-ebs.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/name: {{ include "iceberg-ebs.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "iceberg-ebs.selectorLabels" -}}
app.kubernetes.io/name: {{ include "iceberg-ebs.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
