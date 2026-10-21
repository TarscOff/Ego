---
schema: ego.secrets/1
family: application
title: Application secrets
detectors:
  - id: app.password-kv
    name: Password key-value
    pattern: '(\b(?:password|passwd|pwd|passphrase)["'']?\s*[:=]\s*["'']?)(?!(?:string|number|boolean|null|undefined|true|false|None|str|int|bool|required|optional)\b)(?![$%{<]|process\.|os\.|env\.)([^"''\s,;}]{4,})'
    group: 2
    severity: block
    locked: true
    replacement: '[REDACTED:password]'
  - id: app.secret-kv
    name: Secret, signing, encryption, session and CSRF keys
    pattern: '(\b(?:webhook[_-]?secret|signing[_-]?(?:key|secret)|encryption[_-]?key|session[_-]?secret|csrf[_-]?secret|jwt[_-]?secret|app[_-]?secret|secret[_-]?key|api[_-]?secret)["'']?\s*[:=]\s*["'']?)(?!(?:string|number|boolean|null|undefined|true|false|None|str|int|bool)\b)(?![$%{<]|process\.|os\.|env\.)([A-Za-z0-9._~+/=-]{8,})'
    group: 2
    severity: block
    locked: true
    replacement: '[REDACTED:secret]'
  - id: app.generic-secret-assignment
    name: Generic *_SECRET or *_TOKEN assignment
    pattern: '(\b[A-Z][A-Z0-9_]*(?:SECRET|TOKEN|PRIVATE_KEY|API_KEY)\s*=\s*["'']?)(?!-----BEGIN)([^"''\s]{8,})'
    flags: 'g'
    group: 2
    severity: warn
    locked: true
    replacement: '[REDACTED:secret]'
---
# Application secrets
