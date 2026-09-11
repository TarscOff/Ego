---
schema: ego.secrets/1
family: http
title: HTTP authentication headers and cookies
detectors:
  - id: http.authorization.bearer
    name: Authorization Bearer token
    pattern: '(authorization\s*[:=]\s*["'']?bearer\s+)([A-Za-z0-9._~+/=-]{8,})'
    group: 2
    severity: block
    locked: true
    replacement: '[REDACTED:bearer]'
  - id: http.authorization.basic
    name: Authorization Basic credentials
    pattern: '(authorization\s*[:=]\s*["'']?basic\s+)([A-Za-z0-9+/=]{8,})'
    group: 2
    severity: block
    locked: true
    replacement: '[REDACTED:basic]'
  - id: http.authorization.generic
    name: Authorization header with any scheme
    pattern: '((?:proxy-)?authorization\s*[:=]\s*["'']?)([A-Za-z0-9._~+/=-]{12,})'
    group: 2
    severity: block
    locked: true
    replacement: '[REDACTED:authorization]'
  - id: http.api-key-header
    name: X-API-Key and custom key headers
    pattern: '((?:x-api-key|x-auth-token|x-access-token|api-key|apikey|x-token)\s*[:=]\s*["'']?)([A-Za-z0-9._~+/=-]{8,})'
    group: 2
    severity: block
    locked: true
    replacement: '[REDACTED:api-key]'
  - id: http.cookie
    name: Cookie and Set-Cookie values
    pattern: '((?:set-)?cookie\s*[:=]\s*["'']?)([^"''\r\n;]{8,})'
    group: 2
    severity: warn
    locked: true
    replacement: '[REDACTED:cookie]'
---
# HTTP authentication headers and cookies
