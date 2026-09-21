---
schema: ego.secrets/1
family: cloud
title: Cloud provider credentials
detectors:
  - id: cloud.aws.access-key
    name: AWS access key id
    pattern: '\b(AKIA|ASIA)[A-Z0-9]{16}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:aws-access-key]'
  - id: cloud.aws.secret-key
    name: AWS secret access key (context keyed)
    pattern: '((?:aws[_-]?secret[_-]?access[_-]?key|SecretAccessKey)["'']?\s*[:=]\s*["'']?)([A-Za-z0-9/+=]{40})'
    group: 2
    severity: block
    locked: true
    replacement: '[REDACTED:aws-secret-key]'
  - id: cloud.aws.session-token
    name: AWS session token (context keyed)
    pattern: '(aws[_-]?session[_-]?token\s*[:=]\s*["'']?)([A-Za-z0-9/+=]{16,})'
    group: 2
    severity: block
    locked: true
    replacement: '[REDACTED:aws-session-token]'
  - id: cloud.gcp.service-account
    name: GCP service account private key JSON
    pattern: '"type"\s*:\s*"service_account"'
    severity: block
    locked: true
    replacement: '[REDACTED:gcp-service-account]'
    whole_document: true
  - id: cloud.gcp.api-key
    name: Google API key
    pattern: '\bAIza[0-9A-Za-z_-]{35}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:google-api-key]'
  - id: cloud.azure.client-secret
    name: Azure client secret (context keyed)
    pattern: '(azure[_-]?client[_-]?secret\s*[:=]\s*["'']?)([A-Za-z0-9._~-]{20,})'
    group: 2
    severity: block
    locked: true
    replacement: '[REDACTED:azure-client-secret]'
  - id: cloud.azure.storage-key
    name: Azure storage account key (connection string)
    pattern: '((?:AccountKey|SharedAccessKey)=)([A-Za-z0-9+/=]{40,})'
    group: 2
    severity: block
    locked: true
    replacement: '[REDACTED:azure-storage-key]'
  - id: cloud.digitalocean.token
    name: DigitalOcean API token
    pattern: '\b(?:dop|doo|dor)_v1_[0-9a-f]{64}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:digitalocean-token]'
  - id: cloud.signed-url
    name: Cloud signed URL parameters
    pattern: '([?&](?:X-Amz-Signature|X-Goog-Signature|sig|Signature)=)([A-Za-z0-9%._~+/=-]{16,})'
    group: 2
    severity: warn
    locked: true
    replacement: '[REDACTED:signature]'
---
# Cloud provider credentials
