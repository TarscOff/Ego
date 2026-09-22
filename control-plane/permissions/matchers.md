---
schema: ego.matchers/1
id: matchers
title: Operation to capability matchers
notes: >
  Matchers are evaluated in order; the first match wins. Bash commands are split into segments on `&&`, `||`, `;` and
  `|`; leading `VAR=value` assignments, `sudo`, `env`, `nice`, `time`, `xargs` prefixes and the global option flags of
  `git`, `gh` and `glab` (`git -C dir`, `git -c k=v`, `--git-dir`, `gh -R owner/repo`, …) are stripped before matching;
  a `-c core.hooksPath=…` option surfaces as a `git config core.hooksPath` segment; output redirections (`>`, `>>`) are
  classified as writes to their target path;
  every segment must be allowed for the command to be allowed and the most restrictive verdict wins. `command` patterns
  are regular expressions applied to the normalized segment; `path` patterns are glob-like prefixes applied to the
  resolved path relative to the workspace root or to the home directory (prefix `~/`); `url` patterns match hostnames.
matchers:
  # --- hook and gate self-protection (absolute) ---
  - capability: ego.gate.bypass
    tool: Bash
    command: '(^|\s|/)(harness|ego|harness\.js|ego\.js|ego-hook\.sh|git-hook\.sh)(\s+hook\b|\s+(claude-code|codex-cli)\s+(SessionStart|UserPromptSubmit|PreToolUse|PostToolUse|SubagentStart|SubagentStop|Stop|SessionEnd)\b)'
  - capability: ego.gate.bypass
    tool: Bash
    command: '(^|\s)(npx|bunx|pnpx)\s+(harness|ego|@tarscoff/ego)\s+hook\b'
  - capability: ego.gate.bypass
    tool: Bash
    command: '(^|\s)hook\s+(claude-code|codex-cli)\s+(SessionStart|UserPromptSubmit|PreToolUse|PostToolUse|SubagentStart|SubagentStop|Stop|SessionEnd)\b'
  - capability: ego.gate.bypass
    tool: Bash
    command: '(^|\s)(decision\s+answer|budget\s+extend|modes\s+set|sources\s+(add|remove))(\s|$)'
  - capability: command.env-inject
    tool: Bash
    command: '^env-inject\s+(LD_PRELOAD|LD_LIBRARY_PATH|DYLD_|BASH_ENV|ENV$|PROMPT_COMMAND|NODE_OPTIONS|PYTHONSTARTUP|PYTHONPATH|PERL5OPT|RUBYOPT|GIT_|EGO_|CLAUDE_|CODEX_|SSH_ASKPASS|SUDO_ASKPASS|IFS|SHELL$)'
  - capability: command.env-override
    tool: Bash
    command: '^env-inject\s+'
  - capability: git.alias.inline
    tool: Bash
    command: '^git\s+(alias-override|alias-shell|alias-opaque)\b'
  - capability: ego.runtime.tamper
    tool: Bash
    command: '(^|\s)(\b(cp|mv|tee|ln|install|dd|rsync|sed\s+-i|perl\s+-p?i|truncate|rm|chmod|chown|touch|python3?|node)\b|>>?)[^|;&]*\.harness/(runtime|generated|hooks)(/|\b)'
  - capability: ego.runtime.tamper
    tool: Bash
    command: '(^|\s)(\b(cp|mv|tee|ln|install|dd|rsync|sed\s+-i|perl\s+-p?i|truncate|rm|chmod|chown|touch)\b|>>?)[^|;&]*\.harness/harness\.md'
  - capability: ego.launcher.invoke-nested
    tool: Bash
    command: '^(claude|codex)(\s|$)'
  - capability: ego.launcher.invoke-nested
    tool: Bash
    command: '^(script|expect|unbuffer)\b'
  - capability: ego.gate.bypass
    tool: Write
    path: '.harness/runtime/decisions/**'
  - capability: ego.gate.bypass
    tool: Edit
    path: '.harness/runtime/decisions/**'
  - capability: ego.runtime.tamper
    tool: Write
    path: '.harness/runtime/**'
  - capability: ego.runtime.tamper
    tool: Write
    path: '.harness/generated/**'
  - capability: ego.runtime.tamper
    tool: Write
    path: '.harness/hooks/**'
  - capability: ego.runtime.tamper
    tool: Write
    path: '.harness/harness.md'
  - capability: ego.trust.tamper
    tool: Write
    path: '~/.ego/trust/**'
  - capability: ego.trust.tamper
    tool: Bash
    command: '(^|\s)(rm|mv|cp|tee|sed\s+-i|truncate|chmod)\b.*\.ego/(trust|index|releases|runtimes)/'
  # --- git remote (organization-locked) ---
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
    command: '^git\s+commit\b.*\s--no-verify\b'
  - capability: git.hooks.bypass
    tool: Bash
    command: '^git\s+(push|merge|pull|rebase|cherry-pick|revert|am)\b.*\s--no-verify\b'
  - capability: git.hooks.bypass
    tool: Bash
    # `-c core.hooksPath=…` is a bypass wherever it sits, including AFTER the verb (`git clone -c core.hooksPath=…`,
    # round 13). Reading the value back (`--get`) is not a change.
    command: '^git\b(?![^|;&]*\s--get\b)[^|;&]*core\.hooksPath'
  - capability: git.hooks.bypass
    tool: Bash
    command: '^git\s+(commit-tree|update-ref)\b'
  # --- forge CLIs (organization-locked PR and issue mutation, narrow writes) ---
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
  - capability: forge.api.mutate
    tool: Bash
    command: '^(gh|glab)\s+api\s+graphql\b(?=[\s\S]*\bmutation\b)'
  - capability: forge.api.mutate
    tool: Bash
    # graphql body loaded from a file/stdin (field=@path): cannot inspect it, so a mutation cannot be ruled out -> fail closed
    command: '^(gh|glab)\s+api\s+graphql\b(?=[\s\S]*(=@|\s--input\b|\s-(\s|$)|=\s*[$`]))'
  - capability: forge.api.mutate
    tool: Bash
    command: '^(gh|glab)\s+api\b(?!\s+graphql\b)(?=.*(\s(-X|--method|--request)(\s+|=)?(POST|PUT|PATCH|DELETE)\b|\s(-f|-F|--field|--raw-field|--input|--form)(\s|=|\S*=)))'
  - capability: forge.api.mutate
    tool: Bash
    # the method arrives from a variable or a substitution: it cannot be shown to be a read, so it fails closed
    command: '^(gh|glab)\s+api\b(?=.*\s(-X|--method|--request)(\s+|=)?[$`])'
  - capability: forge.repo.read
    tool: Bash
    command: '^(gh\s+(repo\s+view|api)|glab\s+(repo\s+view|api))\b'
  # --- production (absolute; contexts named production/prod) ---
  - capability: production.k8s.mutate
    tool: Bash
    command: '^(kubectl|oc)\b(?=.*(--context[= ]\S*(prod|production)\S*|(^|\s)-n\s*\S*(prod|production)\S*|--namespace[= ]\S*(prod|production)\S*|--kubeconfig[= ]\S*(prod|production)\S*|--server[= ]\S*(prod|production)\S*))(?=.*\s(apply|delete|patch|edit|scale|rollout|create|replace|drain|cordon|uncordon|taint|exec|cp|annotate|label|set|expose|run|autoscale|attach|port-forward|debug|certificate|proxy)\b)'
  - capability: production.helm.mutate
    tool: Bash
    command: '^helm\b(?=.*\s(install|upgrade|uninstall|rollback|delete|test)\b)(?=.*(--kube-context[= ]\S*(prod|production)\S*|(^|\s)-n\s*\S*(prod|production)\S*|--namespace[= ]\S*(prod|production)\S*|--kubeconfig[= ]\S*(prod|production)\S*))'
  - capability: production.cloud.mutate
    tool: Bash
    command: '^((terraform|tofu)\s+(?:-\S+\s+)*(apply|destroy)|pulumi\s+(?:-\S+\s+)*(up|destroy)|aws\s+(?:--\S+(?:\s+[^-]\S*)?\s+)*\S+\s+(create|delete|update|put|terminate|modify|remove|run-instances|start-instances|stop-instances|reboot-instances|rm|mv|cp|sync|rb|mb|invoke|publish|associate|disassociate|attach|detach|authorize|revoke|batch-delete-image|delete-object|put-object|copy-object|delete-objects)|gcloud\s+(?!config\b|auth\b)\S+.*\b(create|delete|update|deploy|remove|rm)\b|az\s+\S+.*\b(create|delete|update|deploy|remove|purge)\b)'
  - capability: production.deploy
    tool: Bash
    command: '^(argocd\s+app\s+(sync|delete|set|rollback)|flux\s+(reconcile|suspend|resume)|kubectl\s+argo\s+rollouts)\b'
  - capability: production.dns.mutate
    tool: Bash
    command: '^(aws\s+(?:--\S+(?:\s+[^-]\S*)?\s+)*route53\s+change-resource-record-sets|gcloud\s+dns\s+record-sets\s+(create|update|delete)|az\s+network\s+dns\b.*\b(create|delete|update)\b)'
  - capability: production.iam.mutate
    tool: Bash
    command: '^(aws\s+(?:--\S+(?:\s+[^-]\S*)?\s+)*iam\s+(create|delete|attach|detach|put|update)|gcloud\s+iam\b.*\b(create|delete|add|remove)\b|az\s+role\s+assignment\s+(create|delete))'
  - capability: production.kms.mutate
    tool: Bash
    command: '^(aws\s+(?:--\S+(?:\s+[^-]\S*)?\s+)*kms\s+(create|schedule-key-deletion|disable|enable|put|update)|gcloud\s+kms\b.*\b(create|destroy|update)\b|az\s+keyvault\b.*\b(create|delete|set|update)\b)'
  - capability: production.secrets.mutate
    tool: Bash
    command: '^(vault\s+(kv\s+(put|delete|destroy)|write|delete)|aws\s+secretsmanager\s+(create|put|update|delete)|gcloud\s+secrets\s+(create|versions\s+add|delete))\b'
  # a database client aimed at a production host or connection string is a production mutation, not a local query.
  # (The general local-vs-remote target resolution lives in the evaluator; this catches the explicitly named case.)
  - capability: production.database.mutate
    tool: Bash
    command: '^(psql|mysql|mariadb|mongosh|mongo|redis-cli|clickhouse-client|cqlsh)\b(?=[^|;&]*(-h\s*\S*(prod|production)\S*|--host[= ]\S*(prod|production)\S*|://[^\s/]*(prod|production)[^\s/]*))'
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
  - capability: fs.credential-store.write
    tool: Write
    path: '~/.config/gh/**'
  - capability: fs.credential-store.write
    tool: Write
    path: '~/.azure/**'
  - capability: fs.credential-store.write
    tool: Write
    path: '~/.docker/config.json'
  - capability: fs.credential-store.write
    tool: Write
    path: '~/.gnupg/**'
  - capability: fs.credential-store.write
    tool: Write
    path: '~/.git-credentials'
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
    tool: Read
    path: '~/.config/gh/**'
  - capability: fs.credential-store.read
    tool: Read
    path: '~/.azure/**'
  - capability: fs.credential-store.read
    tool: Read
    path: '~/.docker/config.json'
  - capability: fs.credential-store.read
    tool: Read
    path: '~/.gnupg/**'
  - capability: fs.credential-store.read
    tool: Read
    path: '~/.git-credentials'
  - capability: fs.credential-store.write
    tool: Bash
    command: '(^|\s)(\b(tee|cp|mv|install|ln|dd|rsync|sed\s+-i|perl\s+-p?i|truncate|chmod|chown|rm|ssh-keygen|ssh-add|ssh-copy-id|gpg\s+--import|gcloud\s+auth|az\s+login|kubectl\s+config|npm\s+(login|adduser|config\s+set|set))\b|>>?)[^|;&]*(~|\$HOME|\$\{HOME\}|/Users/[^/\s]+|/home/[^/\s]+|/root)/\.(ssh|aws|kube|netrc|npmrc|pypirc|config/gcloud|config/gh|azure|docker/config\.json|gnupg|git-credentials)\b'
  - capability: fs.credential-store.write
    tool: Bash
    command: '^(aws\s+configure\b|gcloud\s+auth\s+(login|activate-service-account)|az\s+login|gh\s+auth\s+login|glab\s+auth\s+login|npm\s+(login|adduser)|docker\s+login|vault\s+login)'
  - capability: fs.credential-store.read
    tool: Bash
    command: '(~|\$HOME|\$\{HOME\}|/Users/[^/\s]+|/home/[^/\s]+|/root)/\.(ssh|aws|kube|netrc|npmrc|pypirc|config/gcloud|config/gh|azure|docker/config\.json|gnupg|git-credentials)\b'
  - capability: fs.credential-store.read
    tool: Bash
    command: '(^|\s|=)\.(ssh|aws|kube|gnupg)/'
  # --- hook and control-plane protection ---
  - capability: ego.control-plane.edit
    tool: Write
    path: 'policies/organization/**'
  - capability: ego.control-plane.edit
    tool: Write
    path: 'control-plane/**'
  - capability: ego.control-plane.edit
    tool: Write
    path: 'policies/baselines/**'
  - capability: ego.control-plane.edit
    tool: Write
    path: 'policies/frameworks/**'
  - capability: ego.control-plane.edit
    tool: Write
    path: 'policies/schemas/**'
  - capability: ego.control-plane.edit
    tool: Write
    path: 'policies/templates/**'
  - capability: ego.mcp-trust.edit
    tool: Write
    path: '.harness/mcp-trust.md'
  - capability: fs.hook-config.write
    tool: Write
    path: '**/.claude/settings.json'
  - capability: fs.hook-config.write
    tool: Write
    path: '**/.claude/settings.local.json'
  - capability: fs.hook-config.write
    tool: Write
    path: '**/.codex/**'
  - capability: fs.hook-config.write
    tool: Write
    path: '~/.claude/settings.json'
  - capability: fs.hook-config.write
    tool: Write
    path: '**/.git/hooks/**'
  - capability: fs.hook-config.write
    tool: Write
    path: '**/.husky/**'
  - capability: fs.hook-config.write
    tool: Write
    path: '**/.claude/settings.local.json'
  - capability: fs.git-internals.write
    tool: Write
    path: '**/.git/**'
  - capability: fs.git-internals.write
    tool: Write
    path: '**/.git'
  - capability: fs.hook-config.write
    tool: Bash
    command: '(^|\s)(\b(chmod|chown|rm|mv|cp|ln|install|truncate|tee|touch|sed\s+-i|perl\s+-p?i)\b|>>?)[^|;&]*(\.git/hooks|\.husky/|\.harness/hooks|\.claude/settings|\.codex/|core\.hooksPath)'
  - capability: fs.git-internals.write
    tool: Bash
    command: '(^|\s)(\b(chmod|chown|rm|mv|cp|ln|install|truncate|tee|touch|sed\s+-i|perl\s+-p?i)\b|>>?)[^|;&]*(^|\s|/)\.git/'
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
  # Mutating branch, recovery and remote-configuration spellings are matched BEFORE the broad `status` matcher below:
  # it accepts a bare `branch`, `reflog` and `remote`, so every `git branch -f`, `git reflog expire` and
  # `git remote set-url` used to read as a listing and reach ALLOW (round 13).
  - capability: git.alias.inline
    tool: Bash
    command: '^git\b[^|;&]*\s(--upload-pack|--receive-pack|--exec)(=|\s)'
  # `-u` is the short form of --upload-pack for the transport verbs (it means something else for push/stash)
  - capability: git.alias.inline
    tool: Bash
    command: '^git\s+(clone|fetch|ls-remote|pull)\b[^|;&]*\s-u(\s+|)\S'
  # merge-index runs the program named as its first operand
  - capability: git.alias.inline
    tool: Bash
    command: '^git\s+merge-index\b'
  # `git <read verb> --output=PATH` writes PATH with no other governance on it
  - capability: fs.repo.write
    tool: Bash
    command: '^git\b[^|;&]*\s(--output|-o)(=|\s)\S'
  # a clone template directory is copied into .git, hooks included: it installs hooks that then run
  - capability: git.hooks.bypass
    tool: Bash
    command: '^git\s+(clone|init)\b[^|;&]*\s--template(=|\s)'
  # a forcing refspec (leading +) overwrites a local branch, destroying unpushed commits
  - capability: git.local.reset
    tool: Bash
    command: '^git\s+(fetch|pull)\b[^|;&]*(\s\+\S+:\S|\s(-f|--force)\b[^|;&]*\s\S+:\S)'
  - capability: git.local.branch.delete
    tool: Bash
    command: '^git\s+branch\b[^|;&]*\s(-[a-zA-Z]*[dD][a-zA-Z]*|--delete)(\s|$)'
  - capability: git.local.reset
    tool: Bash
    command: '^git\s+branch\b[^|;&]*\s(-[a-zA-Z]*f[a-zA-Z]*|--force)(\s|$)'
  - capability: git.local.reset
    tool: Bash
    command: '^git\s+(checkout|switch|branch)\b[^|;&]*\sforce-ref-reset(\s|$)'
  - capability: git.local.recovery.destroy
    tool: Bash
    command: '^git\s+(reflog\s+(expire|delete)|gc\b[^|;&]*--prune|stash\s+(clear|drop))\b'
  - capability: git.local.branch.delete
    tool: Bash
    command: '^git\s+tag\b[^|;&]*\s(-[a-zA-Z]*[df][a-zA-Z]*|--delete|--force)(\s|$)'
  - capability: git.remote.configure
    tool: Bash
    command: '^git\s+remote\s+(add|remove|rm|rename|set-url|set-branches|set-head|prune)\b'
  - capability: git.local.restore
    tool: Bash
    command: '^git\s+(checkout|switch)\b[^|;&]*\s(-[a-zA-Z]*f[a-zA-Z]*|--force|--discard-changes)(\s|$)'
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
    command: '^git\s+(restore|checkout\s+(--\s+)?\S+\.\S+|checkout\b[^|;&]*\s--\s+\S+)\b'
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
  # A container is only a boundary when it is actually a boundary. These options remove the isolation the runtime
  # would otherwise give, so the command inside is running on the host (challenge finding 4).
  - capability: command.privileged
    tool: Bash
    command: '^(docker|podman)\b[^|;&]*\s(--privileged|--pid[= ]host|--net(work)?[= ]host|--userns[= ]host|--ipc[= ]host|--cap-add[= ]?(ALL|SYS_ADMIN))'
  # `docker|podman exec` enters an ALREADY-RUNNING container whose isolation EGO never established, and runs an
  # unclassified command there. `run` is judged by its own flags and bind mounts above and below, so it is not
  # gated wholesale: that would make ordinary local development ask on every invocation. The unverified isolation
  # of the container runtime itself is a containment requirement (#26), not a per-invocation prompt.
  - capability: command.script-opaque
    tool: Bash
    command: '^(docker|podman)(\s+compose)?\s+exec\b'
  - capability: container.prune
    tool: Bash
    command: '^(docker|podman)\s+(system\s+prune|image\s+prune|volume\s+prune|container\s+prune)\b'
  - capability: container.build
    tool: Bash
    command: '^(docker|podman)\s+(build|buildx)\b'
  - capability: container.inspect
    tool: Bash
    command: '^(docker|podman)\s+(ps|images|inspect|logs|top|stats|version|info|image\s+ls)\b'
  # a bind mount hands the container the host path: mounting home, the filesystem root or a credential directory
  # reads it just as surely as `cat` would (round 14)
  - capability: fs.credential-store.read
    tool: Bash
    command: '^(docker|podman)\s+\S+\b[^|;&]*\s(-v|--volume|--mount)(=|\s)\S*((~|\$HOME|\$\{HOME\})(/[^:\s]*)?:|/:|[^:\s]*\.(ssh|aws|kube|gnupg|docker|npmrc|pypirc)[^:\s]*:)'
  - capability: container.registry.push
    tool: Bash
    command: '^(docker|podman)\s+(push\b|buildx\s+build\b[^|;&]*--push)'
  - capability: container.run
    tool: Bash
    command: '^(docker|podman)(-compose)?\b'
  - capability: k8s.local.delete
    tool: Bash
    command: '^(kind\s+delete|k3d\s+cluster\s+delete|minikube\s+delete|kubectl\b[^|;&]*\sdelete\s+(ns|namespace))\b'
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
  # inline interpreters are opaque, so a body that NAMES a protected store fails closed to the same deny the literal verb receives.
  # Round 13: this block sits BEFORE command.read-only. Its `console.log(…)` / `print(…)` carve-out used to win
  # first-match and turn a credential read or a hook write into a silent ALLOW.
  - capability: fs.credential-store.write
    tool: Bash
    command: '(^|\s)(node|nodejs|deno|bun|tsx|ts-node|python|python2|python3|ruby|perl|php|Rscript|osascript)\b[^;|&]*?\s(-e|-c|-r|-E|-p|--eval|--exec|--command)\b[\s\S]*(\.ssh/|\.aws/credentials|\.aws/config|\.gnupg|\.netrc|\.npmrc|\.pypirc|\.kube/|\.git-credentials|\.docker/config|id_rsa|id_ed25519|id_ecdsa|id_dsa)'
  - capability: ego.trust.tamper
    tool: Bash
    command: '(^|\s)(node|nodejs|deno|bun|tsx|ts-node|python|python2|python3|ruby|perl|php|Rscript|osascript)\b[^;|&]*?\s(-e|-c|-r|-E|-p|--eval|--exec|--command)\b[\s\S]*\.ego/(trust|runtimes|releases|index)\b'
  - capability: fs.hook-config.write
    tool: Bash
    command: '(^|\s)(node|nodejs|deno|bun|tsx|ts-node|python|python2|python3|ruby|perl|php|Rscript|osascript)\b[^;|&]*?\s(-e|-c|-r|-E|-p|--eval|--exec|--command)\b[\s\S]*(\.git/hooks|\.husky/|\.githooks/|\.harness/hooks|core\.hooksPath|\.claude/settings|\.codex/)'
  - capability: ego.runtime.tamper
    tool: Bash
    command: '(^|\s)(node|nodejs|deno|bun|tsx|ts-node|python|python2|python3|ruby|perl|php|Rscript|osascript)\b[^;|&]*?\s(-e|-c|-r|-E|-p|--eval|--exec|--command)\b[\s\S]*\.harness/(generated|runtime)\b'
  - capability: fs.git-internals.write
    tool: Bash
    command: '(^|\s)(node|nodejs|deno|bun|tsx|ts-node|python|python2|python3|ruby|perl|php|Rscript|osascript)\b[^;|&]*?\s(-e|-c|-r|-E|-p|--eval|--exec|--command)\b[\s\S]*\.git/(refs|objects|config|HEAD|packed-refs|info|logs)'
  # An inline body that spawns a process, escapes to a shell or touches the filesystem is never read-only, whatever
  # it is wrapped in. Round 13: `node -e 'console.log(execSync("git push origin main"))'` reached ALLOW.
  - capability: command.interpreter-inline
    tool: Bash
    command: '(^|\s)(node|nodejs|deno|bun|tsx|ts-node|python|python2|python3|ruby|perl|php|Rscript|osascript)\b[^;|&]*?\s(-e|-c|-r|-E|-p|--eval|--exec|--command)\b[\s\S]*(child_process|execSync|execFileSync|spawnSync|execFile|spawn\s*\(|os\.system|os\.popen|subprocess|popen|IO\.popen|shell_exec|proc_open|passthru|system\s*\(|require\s*\(|import\s|__import__|fs\.|writeFile|appendFile|unlink|rmSync|rmdir|readFile|open\s*\(|eval\s*\(|Function\s*\(|process\.|Deno\.|Bun\.)'
  # awk and sed are read-only only while their program neither escapes to a shell nor writes a file
  - capability: command.interpreter-inline
    tool: Bash
    # a pipe on EITHER side of a quoted string inside an awk program is a shell command (`"cmd" | getline`,
    # `print | "cmd"`); sed's `e` command and the s///e flag execute their result; `w` writes a file
    command: '^(awk|gawk|mawk|nawk|sed)\b[\s\S]*(system\s*\(|\|\s*["'']|["'']\s*\|&?|\|\s*&?\s*getline|ENVIRON|close\s*\(|print[fl]?[^|>]*>|\bw\s+/|--in-place|(^|[;{''"\s])[0-9$,~+]*\s*e[\s;}]|s(.)(?:(?!\3).)*\3(?:(?!\3).)*\3[a-z]*e)'
  # sed's `e` FLAG on a substitution executes the result, with ANY delimiter (`s|x|id|e`, `s#x#id#e`).
  # A dedicated matcher keeps the backreference unambiguous.
  - capability: command.interpreter-inline
    tool: Bash
    command: '^(?:sed|gsed)\b[\s\S]*\ss(.)(?:(?!\1)[\s\S])*\1(?:(?!\1)[\s\S])*\1[a-z]*e'
  # a program supplied by FILE is opaque: it is judged like any other script, not as a read-only one-liner
  - capability: command.interpreter-script
    tool: Bash
    command: '^(awk|gawk|mawk|nawk|sed)\b[^|;&]*\s(-f|--file|--source)(=|\s)'
  # read-only search tools that can hand a file to an arbitrary program
  - capability: command.interpreter-script
    tool: Bash
    command: '^(rg|ripgrep|grep|ag)\b[^|;&]*\s(--pre|--hostname-bin|--pre-glob)(=|\s)'
  - capability: command.read-only
    tool: Bash
    command: '^(?:(?:ls|cat|head|tail|less|more|wc|grep|rg|egrep|fgrep|tree|pwd|echo|printf|which|type|env|printenv|date|whoami|id|uname|df|du|stat|file|diff|uniq|cut|jq|yq|history)\b|find\b|fd\b|sort\b|awk(?!.*-i)\b|sed(?!\s+(?:-i|--in-place))\b|xargs\s+(?:ls|cat|grep|rg|wc)\b|node\s+(?:-v|--version)\b|node\s+-e\s+["'']?console\.log\((?:"[^"()]*"|''[^''()]*''|[0-9.]*)\)["'']?\s*$|npm\s+(?:ls|view|--version|-v|outdated|why|explain)\b|python3?\s+(?:--version|-V)\b|python3?\s+-c\s+["'']?print\((?:"[^"()]*"|''[^''()]*''|[0-9.]*)\)["'']?\s*$|tsc\s+--version\b|git\s+--version\b)'
  # interposed interpreter options (`python3 -u -c`, `node --no-warnings -e`) must not escape the ^-anchored match
  - capability: command.interpreter-inline
    tool: Bash
    command: '^(?:(?:node|nodejs|deno|bun|tsx|ts-node)\s+(?:-[-\w=.]+\s+)*(?:-e|--eval|-p|--print|-r|--require|-[A-Za-z]*[er])|(?:python3?|ruby|perl|php|Rscript)\s+(?:-[-\w=.]+\s+)*(?:-c|-e|-r|-E|-[A-Za-z]*[cerE]))'
  - capability: command.interpreter-script
    tool: Bash
    command: '^(node|python3?|tsx|ts-node|bun|deno\s+run|ruby|perl|php)\s+(?!-)[^\s]+\.(js|mjs|cjs|ts|mts|py|rb|pl|php)\b'
  - capability: command.local-mutation
    tool: Bash
    command: '^(npm\s+(install|i|ci|uninstall|update|run\s+(format:fix|lint:fix|generate|codegen))|npx\s+(prettier|eslint)\b.*(--write|--fix)|pnpm\s+(install|add|remove)|yarn\s+(add|remove|install)|pip\s+install|poetry\s+(install|add)|go\s+(mod|get)|cargo\s+(add|update)|(mkdir|touch|cp|mv|ln|tar|zip|unzip)\b|chmod\s+[0-7+])'
  # Any remaining interpreter invocation runs a program the kernel has not read. It is opaque, not a local
  # mutation: `node dist/index`, `node .`, `python3 -m pkg`, `deno task x` (challenge finding 3).
  - capability: command.interpreter-script
    tool: Bash
    command: '^(node|nodejs|deno|bun|tsx|ts-node|python|python2|python3|ruby|perl|php|Rscript|osascript)\b'
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
the priority: locked-deny matchers (absolute and organization-locked) come first so a compound command cannot hide a push behind a harmless prefix.

Consumers may add matchers in `.harness/overlay/matchers.md`; they may only map to existing capabilities that are
ASK or DENY in the effective table (narrowing), never introduce an ALLOW mapping for a command the core classifies
as unknown or stricter.

MCP tools (`mcp__<server>__<tool>`) are not listed here. **Today every one of them resolves to `mcp.unknown`**:
`ego init` writes `.harness/mcp-trust.md` into the consumer repository, but nothing parses it yet, so no
`mcp.local.*` or `mcp.remote.*` capability is ever reached. The resolution is phase-2 work (issue #10), and the
failure is in the safe direction — an unresolved MCP tool is treated as unknown, never as trusted. This paragraph
previously described the resolver as if it existed (challenge finding 10).
