---
schema: ego.secrets/1
family: files
title: Secret-bearing files
sensitive_files:
  - '.env'
  - '.env.*'
  - '.npmrc'
  - '.pypirc'
  - '.netrc'
  - '_netrc'
  - 'credentials'
  - 'credentials.json'
  - 'service-account*.json'
  - 'id_rsa'
  - 'id_ed25519'
  - 'id_ecdsa'
  - '*.pem'
  - '*.p12'
  - '*.pfx'
  - '*.key'
  - '*.ppk'
  - 'kubeconfig'
  - 'config' 
  - 'secrets.yaml'
  - 'secrets.yml'
  - 'secret*.yaml'
  - '*.secret'
detectors:
  - id: file.env-line
    name: KEY=value line in a .env-style document
    pattern: '^(\s*[A-Z][A-Z0-9_]*\s*=\s*["'']?)([^"''\r\n]{6,})'
    flags: 'gm'
    group: 2
    severity: warn
    locked: true
    replacement: '[REDACTED:env-value]'
    only_for_files: true
---
# Secret-bearing files

`sensitive_files` lists file name patterns whose content is treated as secret-bearing: reading them is `fs.env-file.read`
or `fs.credential-store.read` per the capability table, and any content that does enter context passes the `file.*`
detectors line by line. `config` is only sensitive under `~/.kube/`; the matcher handles the path.
