---
schema: ego.secrets/1
family: database
title: Database connection strings
detectors:
  - id: db.url-credentials
    name: Credentials embedded in database URLs
    pattern: '\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|jdbc:[a-z]+|mssql|sqlserver):\/\/[^:\/\s@]*:)([^@\/\s]+)(@)'
    group: 2
    severity: block
    locked: true
    replacement: '[REDACTED:db-password]'
  - id: db.password-kv
    name: Database password key-value
    pattern: '((?:db|database|pg|mysql|mongo|redis)[_-]?(?:password|passwd|pwd)["'']?\s*[:=]\s*["'']?)(?!(?:string|number|boolean|null|undefined|true|false|None|str|int|bool)\b)(?![$%{]|process\.|os\.|env\.)([^"''\s;,}]{4,})'
    group: 2
    severity: block
    locked: true
    replacement: '[REDACTED:db-password]'
  - id: db.jdbc-password
    name: JDBC password parameter
    pattern: '([?&;]password=)([^&;\s"'']+)'
    group: 2
    severity: block
    locked: true
    replacement: '[REDACTED:db-password]'
---
# Database connection strings
