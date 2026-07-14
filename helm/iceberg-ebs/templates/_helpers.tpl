{{- define "iceberg-ebs.name" -}}
{{- .Chart.Name }}
{{- end }}

{{- define "iceberg-ebs.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}
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
