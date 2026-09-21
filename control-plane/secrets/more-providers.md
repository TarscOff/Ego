---
schema: ego.secrets/1
family: more-providers
title: Additional distinctive-prefix provider tokens
detectors:
  - id: saas.databricks
    name: Databricks personal access token
    pattern: '\bdapi[a-f0-9]{32}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:databricks-token]'
  - id: saas.shopify
    name: Shopify access token
    pattern: '\bshp(at|ss|ca|pa)_[a-fA-F0-9]{32}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:shopify-token]'
  - id: infra.terraform-cloud
    name: Terraform Cloud / HCP API token
    pattern: '\b[a-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=-]{60,70}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:terraform-cloud-token]'
  - id: saas.newrelic
    name: New Relic user API key
    pattern: '\bNRAK-[A-Z0-9]{27}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:newrelic-key]'
  - id: saas.grafana-sa
    name: Grafana service-account token
    pattern: '\bglsa_[A-Za-z0-9]{32}_[a-f0-9]{8}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:grafana-token]'
  - id: saas.grafana-cloud
    name: Grafana Cloud access policy token
    pattern: '\bglc_[A-Za-z0-9+/=]{32,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:grafana-cloud-token]'
  - id: saas.square
    name: Square OAuth access token
    pattern: '\bsq0(atp|csp)-[A-Za-z0-9_-]{22,43}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:square-token]'
  - id: oauth.google-client-secret
    name: Google OAuth client secret
    pattern: '\bGOCSPX-[A-Za-z0-9_-]{28}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:google-oauth-secret]'
  - id: saas.stripe-webhook
    name: Stripe webhook signing secret
    pattern: '\bwhsec_[A-Za-z0-9]{32,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:stripe-webhook-secret]'
  - id: forge.github.fine-grained-pat
    name: GitHub fine-grained personal access token
    pattern: '\bgithub_pat_[A-Za-z0-9_]{60,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:github-pat]'
  - id: forge.github.app-token
    name: GitHub App / OAuth access token
    pattern: '\b(gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:github-token]'
  - id: saas.linear
    name: Linear API key
    pattern: '\blin_api_[A-Za-z0-9]{40,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:linear-key]'
  - id: saas.notion
    name: Notion integration token
    pattern: '\bntn_[A-Za-z0-9]{40,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:notion-token]'
  - id: saas.figma
    name: Figma personal access token
    pattern: '\bfigd_[A-Za-z0-9_-]{40,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:figma-token]'
  - id: saas.doppler
    name: Doppler service / personal token
    pattern: '\bdp\.(pt|st|sa|scim|audit)\.[A-Za-z0-9]{40,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:doppler-token]'
  - id: infra.planetscale
    name: PlanetScale password or service token
    pattern: '\bpscale_(pw|tkn)_[A-Za-z0-9_.=-]{32,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:planetscale-token]'
  - id: saas.sentry-auth
    name: Sentry auth token
    pattern: '\bsntry[su]_[A-Za-z0-9_.=-]{40,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:sentry-token]'

---
