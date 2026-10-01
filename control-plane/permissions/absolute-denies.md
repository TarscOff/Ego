---
schema: ego.capabilities/1
id: absolute-denies
family: absolute
absolute: true
lock: absolute
title: Absolute core denies
---
# Absolute core denies

These operations are denied in every profile, every authority mode, every task and every host. No organization policy,
profile, product overlay, task grant, mode, skill, issue text, stakeholder document or model output can widen them.
Any lower layer that mentions one of these identifiers fails compilation. Each entry names the failure it prevents.
Operations an organization may legitimately decide to allow live in `capabilities/organization-locked.md` instead
(Q98): DENY by default, widenable only by the organization policy layer.

## Denied

- [x] `production.k8s.mutate` — production Kubernetes mutation: agents analyse, compare and plan production; they never execute against it.
- [x] `production.database.mutate` — production database mutation.
- [x] `production.helm.mutate` — production Helm release mutation.
- [x] `production.cloud.mutate` — cloud infrastructure mutation.
- [x] `production.secrets.mutate` — production secret mutation.
- [x] `production.dns.mutate` — DNS mutation.
- [x] `production.iam.mutate` — IAM mutation.
- [x] `production.kms.mutate` — KMS mutation.
- [x] `production.deploy` — production deployment.
- [x] `production.feature-flags.mutate` — production feature-flag mutation.
- [x] `production.messaging.mutate` — production broker mutation.
- [x] `production.storage.mutate` — production storage mutation.
- [x] `mcp.remote.production.mutate` — production mutation through a remote MCP server.
- [x] `fs.destructive-root` — recursive deletion of a filesystem root, home directory or the checkout root.
- [x] `fs.credential-store.write` — writing SSH keys, cloud credential files, password stores, netrc, npmrc, pypirc.
- [x] `fs.outside-workspace.write` — writing files outside the registered repositories and the EGO home. It is the reach of every other protection on this list: a path the governed tree does not contain is a path no protected-path rule, no hook and no ledger can see, and no organization has a reason to delegate it. It was DENY in every cell and widenable by nobody long before it was marked; the mark makes the refusal say so (Q98 follow-up 1).
- [x] `git.hooks.bypass` — `--no-verify`, `-n` on commit, `core.hooksPath` changes, plumbing that skips hooks (`commit-tree`, `update-ref`). The hooks are the repository-side half of the gate; skipping them defeats the control rather than changing a rule it enforces, which is the line Q98 draws between an administrable act and a bypass (Q98 follow-up 1).
- [x] `ego.gate.bypass` — any attempt to convert HUMAN_DECISION_REQUIRED into approval, answer a decision from a tool, run the human prompt hook from a shell, or write decision records directly.
- [x] `ego.trust.tamper` — editing the trust store, release keys or the cached runtimes under EGO_HOME from any tool.
- [x] `ego.runtime.tamper` — writing runtime state (`.harness/runtime/`), generated artifacts (`.harness/generated/`), hook shims or the pin from any tool; the kernel alone writes them through its own commands.
- [x] `ego.launcher.invoke-nested` — starting a nested agent host (`claude`, `codex`) or a pseudo-terminal wrapper from a tool to manufacture a human channel.
