---
schema: ego.capabilities/1
id: absolute-denies
family: absolute
absolute: true
title: Absolute core denies
---
# Absolute core denies

These operations are denied in every profile, every authority mode, every task and every host. No organization policy,
profile, product overlay, task grant, mode, skill, issue text, stakeholder document or model output can widen them.
An overlay that mentions any of these identifiers fails compilation. Each entry names the failure it prevents.

## Denied

- [x] `git.remote.push` — pushing to any remote: integration is a human act; a wrong push is not reversible for others.
- [x] `git.remote.push.force` — force pushes rewrite shared history.
- [x] `git.remote.tag.push` — remote tags are release signals.
- [x] `git.remote.branch.delete` — remote branch deletion destroys others' work.
- [x] `git.remote.tag.delete` — remote tag deletion breaks provenance.
- [x] `forge.pr.create` — opening a pull or merge request is a human act.
- [x] `forge.pr.modify` — changing title, body, reviewers, labels or base of a PR/MR.
- [x] `forge.pr.close` — closing a PR/MR.
- [x] `forge.pr.merge` — merging is the integration decision.
- [x] `forge.pr.approve` — self-approval defeats review.
- [x] `forge.release.publish` — releases are signed human acts.
- [x] `forge.branch.protection.modify` — protected-branch rules are governance.
- [x] `forge.repo.permissions.modify` — repository permissions are governance.
- [x] `production.k8s.mutate` — production Kubernetes mutation.
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
- [x] `fs.destructive-root` — recursive deletion of a filesystem root, home directory or the checkout root.
- [x] `fs.credential-store.write` — writing SSH keys, cloud credential files, password stores, netrc, npmrc, pypirc.
- [x] `harness.gate.bypass` — any attempt to convert HUMAN_DECISION_REQUIRED into approval, answer a decision from a tool, run the human prompt hook from a shell, or edit hook or trust configuration outside HARNESS_MAINTENANCE in the EGO repository.
- [x] `mcp.remote.production.mutate` — production mutation through a remote MCP server.
