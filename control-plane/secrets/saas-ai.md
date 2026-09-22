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
  - id: saas.npm-token
    name: npm registry access token
    pattern: '\bnpm_[A-Za-z0-9]{36}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:npm-token]'
  - id: saas.pypi-token
    name: PyPI upload token
    pattern: '\bpypi-[A-Za-z0-9_-]{16,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:pypi-token]'
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
  - id: saas.xai
    name: xAI API key
    pattern: '\bxai-[A-Za-z0-9]{60,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:xai-key]'
  - id: saas.perplexity
    name: Perplexity API key
    pattern: '\bpplx-[A-Za-z0-9]{40,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:perplexity-key]'
  - id: saas.langsmith
    name: LangSmith API key
    pattern: '\blsv2_(pt|sk)_[A-Za-z0-9]{32}_[A-Za-z0-9]{10}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:langsmith-key]'
  - id: saas.pinecone
    name: Pinecone API key
    pattern: '\bpcsk_[A-Za-z0-9_]{40,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:pinecone-key]'
  - id: saas.notion-internal
    name: Notion internal integration token
    pattern: '\bsecret_[A-Za-z0-9]{43}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:notion-token]'
  - id: saas.linear-oauth
    name: Linear OAuth token
    pattern: '\blin_oauth_[A-Za-z0-9]{40,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:linear-oauth]'
  - id: saas.newrelic-license
    name: New Relic license key
    pattern: '\b[a-f0-9]{35}NRAL\b'
    severity: block
    locked: true
    replacement: '[REDACTED:newrelic-license]'
  - id: saas.hubspot
    name: HubSpot private-app access token
    pattern: '\bpat-[a-z]{2}\d?-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:hubspot-token]'
  - id: saas.airtable
    name: Airtable personal access token
    pattern: '\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:airtable-token]'
  - id: saas.dropbox
    name: Dropbox short-lived access token
    pattern: '\bsl\.[A-Za-z0-9_-]{70,}'
    severity: block
    locked: true
    replacement: '[REDACTED:dropbox-token]'
  - id: saas.dynatrace
    name: Dynatrace API token
    pattern: '\bdt0c01\.[A-Z0-9]{24}\.[a-f0-9]{64}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:dynatrace-token]'
  - id: saas.meta-graph
    name: Meta / Facebook Graph API access token
    pattern: '\bEAA[A-Za-z0-9]{90,}'
    severity: block
    locked: true
    replacement: '[REDACTED:meta-token]'
  - id: saas.replicate
    name: Replicate API token
    pattern: '\br8_[A-Za-z0-9]{37,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:replicate-token]'
  - id: saas.groq
    name: Groq API key
    pattern: '\bgsk_[A-Za-z0-9]{40,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:groq-key]'
  - id: saas.mailgun
    name: Mailgun private API key
    pattern: '\bkey-[0-9a-z]{32}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:mailgun-key]'
  - id: saas.slack
    name: Slack tokens and webhooks
    pattern: '\b(xox[abcdeoprs]|xapp)-[A-Za-z0-9-]{10,}\b|https://hooks\.slack\.com/(services|triggers|workflows)/[A-Za-z0-9/]+'
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
