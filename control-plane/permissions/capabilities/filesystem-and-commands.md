---
schema: ego.capabilities/1
id: filesystem-and-commands
family: local
title: Local filesystem and commands
---
# Local filesystem and commands

Ordinary engineering inside the checkout is allowed. Credential stores and unrelated directories are protected.
Command classes are recognised by the matchers in `../matchers.md`; an unrecognised command is `command.unknown`.

## Allowed

- [x] `fs.repo.read` — read files inside registered repositories of the workspace.
- [x] `fs.repo.search` — search files inside registered repositories.
- [x] `fs.repo.write` — create or edit files inside registered repositories, outside protected and generated paths.
- [x] `fs.repo.delete` — delete files inside registered repositories.
- [x] `fs.repo.rename` — rename or move files inside registered repositories.
- [x] `fs.repo.mkdir` — create directories inside registered repositories.
- [x] `fs.runtime.write` — write runtime temporary state under `.harness/runtime/` through the kernel.
- [x] `command.read-only` — read-only commands (listing, printing, searching, status, version queries).
- [x] `command.build` — build and compile commands declared by the overlay or recognised by the matchers.
- [x] `command.test` — test commands declared by the overlay or recognised by the matchers.
- [x] `command.local-mutation` — ordinary local mutations (package installs in the checkout, formatters, generators).

## Requires human approval

- [x] `fs.outside-workspace.read` — read files outside registered repositories and outside the EGO home.
- [x] `fs.env-file.read` — read `.env` and similar local secret files.
- [x] `fs.local-config.write` — change local tool configuration outside the checkout (shell profiles, global git config).
- [x] `command.unknown` — a command the matchers cannot classify; the host's own permission prompt decides.
- [x] `command.destructive` — destructive but non-root deletions and history rewrites inside the checkout.
- [x] `command.privileged` — commands requiring elevated privileges.
- [x] `command.network-tool` — commands that themselves perform network transfers (curl, wget, scp, rsync to remote).

## Denied

- [x] `fs.generated.write` — hand-editing generated artifacts (`.harness/generated/`, `policies/generated/`, generated adapter configs); regenerate through the approved generators instead.
- [x] `fs.outside-workspace.write` — write files outside registered repositories and the EGO home.
- [x] `fs.env-file.write` — write `.env` and similar local secret files.
- [x] `fs.credential-store.read` — read SSH keys, cloud credential files, kubeconfig credentials, password stores, netrc, npmrc, pypirc.
- [x] `fs.hook-config.write` — edit host hook or permission configuration (`.claude/settings*.json`, `.codex/**`, `.git/hooks/**`, `.harness/hooks/**`) outside HARNESS_MAINTENANCE in the EGO repository.
