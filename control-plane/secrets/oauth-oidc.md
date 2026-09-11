---
schema: ego.secrets/1
family: oauth-oidc
title: OAuth, OIDC and session tokens
detectors:
  - id: oauth.jwt
    name: JSON Web Token
    pattern: '\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:jwt]'
  - id: oauth.client-secret
    name: client_secret parameter
    pattern: '(client[_-]?secret["'']?\s*[:=]\s*["'']?)(?!(?:string|number|null|undefined|true|false|None)\b)(?![$%{<]|process\.|os\.|env\.)([A-Za-z0-9._~+/=-]{8,})'
    group: 2
    severity: block
    locked: true
    replacement: '[REDACTED:client-secret]'
  - id: oauth.tokens
    name: access, refresh, id and session tokens
    pattern: '((?:access|refresh|id|session)[_-]?token["'']?\s*[:=]\s*["'']?)(?!(?:string|number|null|undefined|true|false|None)\b)(?![$%{<]|process\.|os\.|env\.)([A-Za-z0-9._~+/=-]{12,})'
    group: 2
    severity: block
    locked: true
    replacement: '[REDACTED:token]'
  - id: oauth.authorization-code
    name: authorization code parameter
    pattern: '([?&]code=)([A-Za-z0-9._~+/=-]{16,})'
    group: 2
    severity: warn
    locked: true
    replacement: '[REDACTED:code]'
---
# OAuth, OIDC and session tokens
