---
schema: ego.matchers/1
id: matchers
title: Operation to capability matchers
notes: >
  Matchers are evaluated in order; the first match wins. Bash commands are split into segments on `&&`, `||`, `;` and
  `|`; leading `VAR=value` assignments, `sudo`, `env`, `nice`, `time`, `xargs` prefixes are stripped before matching;
  every segment must be allowed for the command to be allowed and the most restrictive verdict wins. `command` patterns
  are regular expressions applied to the normalized segment; `path` patterns are glob-like prefixes applied to the
  resolved path relative to the workspace root or to the home directory (prefix `~/`); `url` patterns match hostnames.
matchers:
  # --- hook and gate self-protection (absolute) ---
  - capability: harness.gate.bypass
    tool: Bash
    command: '(^|\s)(harness|ego)\s+hook\b'
  - capability: harness.gate.bypass
    tool: Bash
    command: '(^|\s)(harness|ego)\s+decision\s+answer\b'
  - capability: harness.launcher.invoke-nested
    tool: Bash
    command: '^(claude|codex)(\s|$)'
  - capability: harness.launcher.invoke-nested
    tool: Bash
    command: '^(script|expect|unbuffer)\b'
  - capability: harness.gate.bypass
    tool: Write
    path: '.harness/runtime/decisions/**'
  - capability: harness.gate.bypass
    tool: Edit
    path: '.harness/runtime/decisions/**'
  # --- git remote (absolute) ---
  - capability: git.remote.push.force
    tool: Bash
    command: '^git\s+push\b.*(\s--force(-with-lease)?\b|\s-f\b|\s\+)'
  - capability: git.remote.tag.delete
    tool: Bash
    command: '^git\s+push\b.*(--delete|\s:refs/tags/|\s:[A-Za-z0-9._/-]*tag)'
  - capability: git.remote.branch.delete
    tool: Bash
    command: '^git\s+push\b.*(--delete\b|\s:[A-Za-z0-9._/-]+)'
  - capability: git.remote.tag.push
    tool: Bash
    command: '^git\s+push\b.*(--tags\b|\srefs/tags/)'
  - capability: git.remote.push
    tool: Bash
    command: '^git\s+push\b'
  - capability: git.hooks.bypass
    tool: Bash
    command: '^git\s+(commit|push|merge)\b.*(\s--no-verify\b|\s-n\b)'
  - capability: git.hooks.bypass
    tool: Bash
    command: '^git\s+(-c\s+core\.hooksPath|config\b.*core\.hooksPath)'
  - capability: git.hooks.bypass
    tool: Bash
    command: '^git\s+(commit-tree|update-ref)\b'
  # --- forge CLIs (absolute PR mutation, narrow writes, issues) ---
  - capability: forge.pr.merge
    tool: Bash
    command: '^(gh\s+pr\s+merge|glab\s+mr\s+merge|az\s+repos\s+pr\s+update\b.*--status\s+completed)\b'
  - capability: forge.pr.create
    tool: Bash
    command: '^(gh\s+pr\s+create|glab\s+mr\s+create|az\s+repos\s+pr\s+create)\b'
  - capability: forge.pr.close
    tool: Bash
    command: '^(gh\s+pr\s+close|glab\s+mr\s+close)\b'
  - capability: forge.pr.approve
    tool: Bash
    command: '^(gh\s+pr\s+review\b.*--approve|glab\s+mr\s+approve)\b'
  - capability: forge.pr.modify
    tool: Bash
    command: '^(gh\s+pr\s+(edit|ready|reopen|lock|unlock)|glab\s+mr\s+(update|reopen))\b'
  - capability: forge.release.publish
    tool: Bash
    command: '^(gh\s+release\s+(create|upload|edit)|glab\s+release\s+(create|upload))\b'
  - capability: forge.issue.close
    tool: Bash
    command: '^(gh\s+issue\s+close|glab\s+issue\s+close)\b'
  - capability: forge.issue.create
    tool: Bash
    command: '^(gh\s+issue\s+create|glab\s+issue\s+create)\b'
  - capability: forge.issue.edit
    tool: Bash
    command: '^(gh\s+issue\s+(edit|transfer|pin|lock)|glab\s+issue\s+update)\b'
  - capability: forge.issue.comment
    tool: Bash
    command: '^(gh\s+issue\s+comment|glab\s+issue\s+note)\b'
  - capability: forge.review.comment
    tool: Bash
    command: '^(gh\s+pr\s+(comment|review)|glab\s+mr\s+note)\b'
  - capability: forge.pr.read
    tool: Bash
    command: '^(gh\s+pr\s+(view|list|diff|checks|status)|glab\s+mr\s+(view|list|diff))\b'
  - capability: forge.issue.read
    tool: Bash
    command: '^(gh\s+issue\s+(view|list|status)|glab\s+issue\s+(view|list))\b'
  - capability: forge.repo.read
    tool: Bash
    command: '^(gh\s+(repo\s+view|api\s+-X\s+GET|api\s+(?!-X))|glab\s+(repo\s+view|api))\b'
  # --- production (absolute; contexts named production/prod) ---
  - capability: production.k8s.mutate
    tool: Bash
    command: '^kubectl\b.*(--context[= ]\S*(prod|production)\S*|-n\s+\S*(prod|production)\S*|--namespace[= ]\S*(prod|production)\S*).*\b(apply|delete|patch|edit|scale|rollout|create|replace|drain|cordon|taint)\b'
  - capability: production.helm.mutate
    tool: Bash
    command: '^helm\s+(install|upgrade|uninstall|rollback|delete)\b.*(--kube-context[= ]\S*(prod|production)\S*|-n\s+\S*(prod|production)\S*|--namespace[= ]\S*(prod|production)\S*)'
  - capability: production.cloud.mutate
    tool: Bash
    command: '^(terraform\s+(apply|destroy)|pulumi\s+(up|destroy)|aws\s+\S+\s+(create|delete|update|put|terminate|modify)|gcloud\s+\S+.*\b(create|delete|update)\b|az\s+\S+.*\b(create|delete|update)\b)'
  - capability: production.deploy
    tool: Bash
    command: '^(argocd\s+app\s+(sync|delete|set|rollback)|flux\s+(reconcile|suspend|resume)|kubectl\s+argo\s+rollouts)\b'
  - capability: production.dns.mutate
    tool: Bash
    command: '^(aws\s+route53\s+change-resource-record-sets|gcloud\s+dns\s+record-sets\s+(create|update|delete)|az\s+network\s+dns\b.*\b(create|delete|update)\b)'
  - capability: production.iam.mutate
    tool: Bash
    command: '^(aws\s+iam\s+(create|delete|attach|detach|put|update)|gcloud\s+iam\b.*\b(create|delete|add|remove)\b|az\s+role\s+assignment\s+(create|delete))'
  - capability: production.kms.mutate
    tool: Bash
    command: '^(aws\s+kms\s+(create|schedule-key-deletion|disable|enable|put|update)|gcloud\s+kms\b.*\b(create|destroy|update)\b|az\s+keyvault\b.*\b(create|delete|set|update)\b)'
  - capability: production.secrets.mutate
    tool: Bash
    command: '^(vault\s+(kv\s+(put|delete|destroy)|write|delete)|aws\s+secretsmanager\s+(create|put|update|delete)|gcloud\s+secrets\s+(create|versions\s+add|delete))\b'
  # --- destructive roots (absolute) ---
  - capability: fs.destructive-root
    tool: Bash
    command: '^rm\s+(-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*|-r\s+-f|-f\s+-r)\s+(/|~|\$HOME|\.|\*|/\*)(\s|$)'
  # --- credential stores (absolute writes, denied reads) ---
  - capability: fs.credential-store.write
    tool: Write
    path: '~/.ssh/**'
  - capability: fs.credential-store.write
    tool: Write
    path: '~/.aws/**'
  - capability: fs.credential-store.write
    tool: Write
    path: '~/.config/gcloud/**'
  - capability: fs.credential-store.write
    tool: Write
    path: '~/.kube/**'
  - capability: fs.credential-store.write
    tool: Write
    path: '~/.netrc'
  - capability: fs.credential-store.write
    tool: Write
    path: '~/.npmrc'
  - capability: fs.credential-store.write
    tool: Write
    path: '~/.pypirc'
  - capability: fs.credential-store.read
    tool: Read
    path: '~/.ssh/**'
  - capability: fs.credential-store.read
    tool: Read
    path: '~/.aws/**'
  - capability: fs.credential-store.read
    tool: Read
    path: '~/.config/gcloud/**'
  - capability: fs.credential-store.read
    tool: Read
    path: '~/.kube/**'
  - capability: fs.credential-store.read
    tool: Read
    path: '~/.netrc'
  - capability: fs.credential-store.read
    tool: Read
    path: '~/.npmrc'
  - capability: fs.credential-store.read
    tool: Read
    path: '~/.pypirc'
  - capability: fs.credential-store.read
    tool: Bash
    command: '^(cat|less|more|head|tail|grep|sed|awk|cp|scp|base64|xxd|od)\b.*(~|\$HOME|/Users/[^/]+|/home/[^/]+)/\.(ssh|aws|kube|netrc|npmrc|pypirc|config/gcloud)\b'
  # --- hook and control-plane protection ---
  - capability: fs.hook-config.write
    tool: Write
    path: '.claude/settings.json'
  - capability: fs.hook-config.write
    tool: Write
    path: '.claude/settings.local.json'
  - capability: fs.hook-config.write
    tool: Write
    path: '.codex/**'
  - capability: fs.hook-config.write
    tool: Write
    path: '.harness/hooks/**'
  - capability: fs.hook-config.write
    tool: Write
    path: '~/.claude/settings.json'
  - capability: fs.hook-config.write
    tool: Bash
    command: '^(chmod|rm|mv|cp|truncate|tee|sed\s+-i)\b.*(\.git/hooks|\.harness/hooks|\.claude/settings|\.codex/)'
  - capability: fs.generated.write
    tool: Write
    path: '.harness/generated/**'
  - capability: fs.generated.write
    tool: Write
    path: 'policies/generated/**'
  - capability: fs.env-file.write
    tool: Write
    path: '**/.env'
  - capability: fs.env-file.write
    tool: Write
    path: '**/.env.*'
  - capability: fs.env-file.read
    tool: Read
    path: '**/.env'
  - capability: fs.env-file.read
    tool: Read
    path: '**/.env.*'
  # --- git local classes ---
  - capability: git.local.status
    tool: Bash
    command: '^git\s+(status|diff|log|blame|show|branch(\s+-[avr]+)?|reflog|remote\s+-v|remote\s+show|ls-files|rev-parse|describe|shortlog|worktree\s+list|stash\s+list)\b'
  - capability: git.remote.inspect
    tool: Bash
    command: '^git\s+(ls-remote|remote(\s+(-v|show|get-url))?)\b'
  - capability: git.remote.fetch
    tool: Bash
    command: '^git\s+fetch\b'
  - capability: git.remote.clone
    tool: Bash
    command: '^git\s+clone\b'
  - capability: git.remote.pull
    tool: Bash
    command: '^git\s+pull\b'
  - capability: git.local.amend
    tool: Bash
    command: '^git\s+commit\b.*--amend\b'
  - capability: git.local.commit
    tool: Bash
    command: '^git\s+commit\b'
  - capability: git.local.stage
    tool: Bash
    command: '^git\s+(add|rm\s+--cached|restore\s+--staged)\b'
  - capability: git.local.rebase
    tool: Bash
    command: '^git\s+rebase\b'
  - capability: git.local.reset
    tool: Bash
    command: '^git\s+reset\b'
  - capability: git.local.restore
    tool: Bash
    command: '^git\s+(restore|checkout\s+(--\s+)?\S+\.\S+)\b'
  - capability: git.local.clean
    tool: Bash
    command: '^git\s+clean\b'
  - capability: git.local.branch.delete
    tool: Bash
    command: '^git\s+branch\s+(-[dD]|--delete)\b'
  - capability: git.local.branch.create
    tool: Bash
    command: '^git\s+(branch\s+[^-]|checkout\s+-b|switch\s+-c)'
  - capability: git.local.checkout
    tool: Bash
    command: '^git\s+(checkout|switch)\b'
  - capability: git.local.stash
    tool: Bash
    command: '^git\s+stash\b'
  - capability: git.local.tag
    tool: Bash
    command: '^git\s+tag\b'
  - capability: git.local.merge
    tool: Bash
    command: '^git\s+merge\b'
  - capability: git.local.cherry-pick
    tool: Bash
    command: '^git\s+(cherry-pick|revert)\b'
  - capability: git.worktree.remove
    tool: Bash
    command: '^git\s+worktree\s+(remove|prune)\b'
  # --- local runtime ---
  - capability: db.local.drop
    tool: Bash
    command: '^(dropdb|psql\b.*\bDROP\s+DATABASE|mysql\b.*\bDROP\s+DATABASE)'
  - capability: db.local.migrate
    tool: Bash
    command: '^(npx\s+)?(typeorm|prisma\s+migrate|alembic|flyway|liquibase|knex\s+migrate|sequelize\s+db:migrate|dbmate)\b'
  - capability: db.local.query
    tool: Bash
    command: '^(psql|mysql|sqlite3|redis-cli|mongosh)\b'
  - capability: db.local.start
    tool: Bash
    command: '^(pg_ctl|postgres|mysqld|redis-server|mongod)\b'
  - capability: container.prune
    tool: Bash
    command: '^(docker|podman)\s+(system\s+prune|image\s+prune|volume\s+prune|container\s+prune)\b'
  - capability: container.build
    tool: Bash
    command: '^(docker|podman)\s+(build|buildx)\b'
  - capability: container.inspect
    tool: Bash
    command: '^(docker|podman)\s+(ps|images|inspect|logs|top|stats|version|info|image\s+ls)\b'
  - capability: container.run
    tool: Bash
    command: '^(docker|podman)(-compose)?\b'
  - capability: k8s.local.delete
    tool: Bash
    command: '^(kind\s+delete|k3d\s+cluster\s+delete|minikube\s+delete|kubectl\s+delete\s+(ns|namespace))\b'
  - capability: k8s.local.apply
    tool: Bash
    command: '^(kubectl|helm|kind|k3d|minikube|kustomize)\b'
  # --- command classes ---
  - capability: command.privileged
    tool: Bash
    command: '^(sudo|doas|su)\b'
  - capability: command.network-tool
    tool: Bash
    command: '^(curl|wget|scp|sftp|rsync\b.*:|ssh|nc|ncat|telnet)\b'
  - capability: command.destructive
    tool: Bash
    command: '^rm\s+-[a-zA-Z]*r'
  - capability: command.test
    tool: Bash
    command: '^(npm\s+(test|run\s+test\S*)|npx\s+(vitest|jest|mocha|playwright)|pnpm\s+test|yarn\s+test|pytest|go\s+test|cargo\s+test|node\s+--test)\b'
  - capability: command.build
    tool: Bash
    command: '^(npm\s+run\s+(build|typecheck|lint|format|check)|npx\s+(tsc|esbuild|eslint|prettier|vite|next|ng)|pnpm\s+(build|lint)|yarn\s+(build|lint)|go\s+(build|vet)|cargo\s+(build|check|clippy)|make\b)'
  - capability: command.read-only
    tool: Bash
    command: '^(ls|cat|head|tail|less|more|wc|grep|rg|egrep|fgrep|find|fd|tree|pwd|echo|printf|which|type|env|printenv|date|whoami|id|uname|df|du|stat|file|diff|sort|uniq|cut|awk(?!.*-i)|sed(?!\s+-i)|jq|yq|xargs\s+(ls|cat|grep|rg|wc)|node\s+(-v|--version|-e\s+["'']console)|npm\s+(ls|view|--version|-v|outdated|why|explain)|python3?\s+(--version|-V|-c\s+["'']print)|tsc\s+--version|git\s+--version|history)\b'
  - capability: command.local-mutation
    tool: Bash
    command: '^(npm\s+(install|i|ci|uninstall|update|run\s+(format:fix|lint:fix|generate|codegen))|npx\s+(prettier|eslint)\b.*(--write|--fix)|pnpm\s+(install|add|remove)|yarn\s+(add|remove|install)|pip\s+install|poetry\s+(install|add)|go\s+(mod|get)|cargo\s+(add|update)|mkdir|touch|cp|mv|ln|chmod\s+[0-7+]|tar|zip|unzip|node\b|python3?\b|tsx\b|ts-node\b)'
  # --- network classes (WebFetch / MCP url tools) ---
  - capability: network.localhost
    tool: WebFetch
    url: '^(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(:\d+)?$'
  - capability: network.public-read
    tool: WebFetch
    url: '.*'
---
# Operation to capability matchers

The machine part of this file is the frontmatter. Matchers translate what a host reports (a shell command, a file
path, a URL, an MCP tool name) into a capability identifier that the compiled authority table can decide. The order is
the priority: absolute-deny matchers come first so a compound command cannot hide a push behind a harmless prefix.

Consumers may add matchers in `.harness/overlay/matchers.md`; they may only map to existing capabilities that are
ASK or DENY in the effective table (narrowing), never introduce an ALLOW mapping for a command the core classifies
as unknown or stricter.

MCP tools (`mcp__<server>__<tool>`) are not listed here: they resolve through the consumer's `.harness/mcp-trust.md`
to `mcp.local.*` or `mcp.remote.*` capabilities, and to `mcp.unknown` when the server or tool is not listed.
