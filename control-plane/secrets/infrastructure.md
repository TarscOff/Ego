---
schema: ego.secrets/1
family: infrastructure
title: Infrastructure credentials and private keys
detectors:
  - id: infra.dockerhub.pat
    name: Docker Hub personal access token
    pattern: '\bdckr_(pat|oat)_[A-Za-z0-9_-]{20,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:dockerhub-pat]'
  - id: infra.private-key-block
    name: PEM private key block
    pattern: '-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----'
    severity: block
    locked: true
    replacement: '[REDACTED:private-key]'
  - id: infra.putty-private-key
    name: PuTTY private key file
    pattern: 'PuTTY-User-Key-File-\d+:[\s\S]*?Private-MAC:\s*\S+'
    severity: block
    locked: true
    replacement: '[REDACTED:putty-private-key]'
  - id: infra.kube.token
    name: Kubernetes service account or kubeconfig token
    pattern: '(\btoken\s*:\s*)([A-Za-z0-9._-]{20,})'
    group: 2
    severity: block
    locked: true
    replacement: '[REDACTED:kube-token]'
  - id: infra.kube.client-key-data
    name: kubeconfig client-key-data
    pattern: '(client-key-data\s*:\s*)([A-Za-z0-9+/=]{40,})'
    group: 2
    severity: block
    locked: true
    replacement: '[REDACTED:kube-client-key]'
  - id: infra.vault.token
    name: HashiCorp Vault token
    pattern: '\b(?:hvs|hvb|s)\.[A-Za-z0-9]{24,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:vault-token]'
  - id: infra.argocd.token
    name: ArgoCD token (context keyed)
    pattern: '(argocd[_-]?(?:auth[_-]?)?token\s*[:=]\s*["'']?)([A-Za-z0-9._-]{20,})'
    group: 2
    severity: block
    locked: true
    replacement: '[REDACTED:argocd-token]'
  - id: infra.helm.registry-password
    name: Helm or OCI registry password
    pattern: '((?:helm|registry|docker)[_-]?(?:password|pass|token)\s*[:=]\s*["'']?)([^"''\s]{6,})'
    group: 2
    severity: block
    locked: true
    replacement: '[REDACTED:registry-password]'
---
# Infrastructure credentials and private keys
