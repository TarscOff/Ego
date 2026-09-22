---
schema: ego.secrets/1
family: git-forge
title: Git and forge tokens
detectors:
  - id: forge.github.pat
    name: GitHub personal access token
    pattern: '\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:github-token]'
  - id: forge.github.fine-grained
    name: GitHub fine-grained token
    pattern: '\bgithub_pat_[A-Za-z0-9_]{20,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:github-token]'
  - id: forge.gitlab.token
    name: GitLab tokens (personal, project, deploy, runner, pipeline)
    pattern: '\bglpat-[A-Za-z0-9_-]{16,}\b|\bgl(dt|rt|pt|ft|ptt|cbt|agent|oas|imt|soat|ffct)-[A-Za-z0-9_-]{16,}\b|\bGR1348941[A-Za-z0-9_-]{20,}\b'
    severity: block
    locked: true
    replacement: '[REDACTED:gitlab-token]'
  - id: forge.azure-devops.pat
    name: Azure DevOps personal access token (context keyed)
    pattern: '((?:azure[_-]?devops|ado|vsts)[_-]?(?:pat|token)\s*[:=]\s*["'']?)([A-Za-z0-9]{40,})'
    group: 2
    severity: block
    locked: true
    replacement: '[REDACTED:ado-token]'
  - id: forge.bitbucket.token
    name: Bitbucket app password or access token (context keyed)
    pattern: '((?:bitbucket|bb)[_-]?(?:token|app[_-]?password)\s*[:=]\s*["'']?)([A-Za-z0-9._~+/=-]{16,})'
    group: 2
    severity: block
    locked: true
    replacement: '[REDACTED:bitbucket-token]'
---
# Git and forge tokens
