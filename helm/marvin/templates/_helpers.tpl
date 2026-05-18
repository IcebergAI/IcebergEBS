{{- define "marvin.name" -}}
{{- .Chart.Name }}
{{- end }}

{{- define "marvin.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "marvin.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/name: {{ include "marvin.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "marvin.selectorLabels" -}}
app.kubernetes.io/name: {{ include "marvin.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
