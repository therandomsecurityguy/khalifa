{{- define "khalifa.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "khalifa.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 44 | trimSuffix "-" }}
{{- else if contains (include "khalifa.name" .) .Release.Name }}
{{- .Release.Name | trunc 44 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "khalifa.name" .) | trunc 44 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "khalifa.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "khalifa.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "khalifa.selectorLabels" -}}
app.kubernetes.io/name: {{ include "khalifa.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{- define "khalifa.serviceAccountName" -}}
{{- $serviceAccount := index .root.Values.serviceAccounts .key -}}
{{- if $serviceAccount.create -}}
{{- default (printf "%s-%s" (include "khalifa.fullname" .root) .suffix) $serviceAccount.name -}}
{{- else -}}
{{- required (printf "serviceAccounts.%s.name is required when create is false" .key) $serviceAccount.name -}}
{{- end -}}
{{- end }}

{{- define "khalifa.topologySpreadConstraints" -}}
{{- if .root.Values.topologySpread.enabled }}
- maxSkew: {{ .root.Values.topologySpread.maxSkew }}
  topologyKey: {{ .root.Values.topologySpread.topologyKey | quote }}
  whenUnsatisfiable: {{ .root.Values.topologySpread.whenUnsatisfiable }}
  labelSelector:
    matchLabels:
      {{- include "khalifa.selectorLabels" (dict "root" .root "component" .component) | nindent 6 }}
{{- end }}
{{- end }}

{{- define "khalifa.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
fsGroup: 65532
fsGroupChangePolicy: OnRootMismatch
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{- define "khalifa.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
runAsUser: 65532
capabilities:
  drop:
    - ALL
{{- end }}

{{- define "khalifa.collectorSecretName" -}}
{{- required "externalSecrets.targetName is required" .Values.externalSecrets.targetName -}}
{{- end }}

{{- define "khalifa.graphWriterTokenSecretName" -}}
{{- required "externalSecrets.targetName is required" .Values.externalSecrets.targetName -}}
{{- end }}

{{- define "khalifa.collectionEnvSecrets" -}}
{{- $collector := include "khalifa.collectorSecretName" . -}}
{{- $token := include "khalifa.graphWriterTokenSecretName" . -}}
- secretRef:
    name: {{ $collector }}
{{- if ne $collector $token }}
- secretRef:
    name: {{ $token }}
{{- end }}
{{- end }}

{{- define "khalifa.extraExternalSecretRef" -}}
{{- $component := .component -}}
{{- $already := .already -}}
{{- if and .root.Values.externalSecrets.enabled (has $component .root.Values.externalSecrets.mountIn) (not (has .root.Values.externalSecrets.targetName $already)) }}
- secretRef:
    name: {{ .root.Values.externalSecrets.targetName }}
{{- end }}
{{- end }}
