---
schema: ego.secrets/1
family: urls
title: Credentials and sensitive parameters in URLs
detectors:
  - id: url.embedded-credentials
    name: user:password@ in URLs
    pattern: '\b((?:https?|ftp|sftp|ssh|git|cloudinary|redis|rediss|amqp|amqps|mongodb|mongodb\+srv|postgres|postgresql|mysql|mssql|clickhouse|s3|smtp|smtps|imap|imaps)://[^:/\s@]+:)([^@/\s]+)(@)'
    group: 2
    severity: block
    locked: true
    replacement: '[REDACTED:url-password]'
  - id: url.sensitive-query
    name: Sensitive query parameters
    pattern: '([?&](?:token|access_token|api_key|apikey|key|secret|password|auth|session|sig|signature)=)([^&\s"'']{8,})'
    group: 2
    severity: warn
    locked: true
    replacement: '[REDACTED:query]'
---
# Credentials and sensitive parameters in URLs
