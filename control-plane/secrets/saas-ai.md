---
schema: ego.secrets/1
family: saas-ai
title: SaaS, AI provider and CI/CD secrets
detectors:
  - id: saas.stripe
    name: Stripe keys
    pattern: '\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:stripe-key]'
  - id: saas.twilio
    name: Twilio auth token or SID key
    pattern: '\bSK[a-f0-9]{32}\b|(twilio[_-]?auth[_-]?token\s*[:=]\s*["'']?)([a-f0-9]{32})'
    severity: block
    locked: true
    replacement: '[REDACTED:twilio]'
  - id: saas.sendgrid
    name: SendGrid API key
    pattern: '\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:sendgrid-key]'
  - id: saas.slack
    name: Slack tokens and webhooks
    pattern: '\b(xox[abeoprs]|xapp)-[A-Za-z0-9-]{10,}\b|https://hooks\.slack\.com/services/[A-Za-z0-9/]+'
    severity: block
    locked: true
    replacement: '[REDACTED:slack]'
  - id: saas.discord
    name: Discord bot token or webhook
    pattern: '\b[MN][A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b|https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+'
    severity: block
    locked: true
    replacement: '[REDACTED:discord]'
  - id: saas.telegram
    name: Telegram bot token
    pattern: '\b\d{8,10}:[A-Za-z0-9_-]{35}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:telegram]'
  - id: ai.openai
    name: OpenAI API key
    pattern: '\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:openai-key]'
  - id: ai.anthropic
    name: Anthropic API key
    pattern: '\bsk-ant-[A-Za-z0-9_-]{20,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:anthropic-key]'
  - id: ai.huggingface
    name: Hugging Face token
    pattern: '\bhf_[A-Za-z0-9]{20,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:hf-token]'
  - id: ai.generic-provider-key
    name: Mistral, Gemini, gateway and observability keys (context keyed)
    pattern: '((?:mistral|gemini|google[_-]?ai|litellm|openrouter|datadog|dd|sentry|newrelic|grafana|honeycomb)[_-]?(?:api[_-]?)?(?:key|token|dsn)\s*[:=]\s*["'']?)([A-Za-z0-9._~+/=:-]{16,})'
    group: 2
    severity: block
    locked: true
    replacement: '[REDACTED:provider-key]'
  - id: ci.secret-kv
    name: CI/CD secret variables (context keyed)
    pattern: '((?:ci|cd|github|gitlab|azure)[_-]?(?:secret|token)\s*[:=]\s*["'']?)([A-Za-z0-9._~+/=-]{12,})'
    group: 2
    severity: block
    locked: true
    replacement: '[REDACTED:ci-secret]'
---
# SaaS, AI provider and CI/CD secrets
