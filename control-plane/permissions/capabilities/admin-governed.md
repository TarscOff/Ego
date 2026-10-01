---
schema: ego.capabilities/1
id: admin-governed
family: admin-governed
lock: admin-governed
title: ADMIN_GOVERNED capabilities
---
# ADMIN_GOVERNED capabilities

Denied at the core layer and widenable only by the organization policy layer (`policies/organization/permissions.md`,
read from the governed checkout; a human accepts any widening with `ego init`). A product overlay, a task grant, an
authority mode, a skill, an issue, a stakeholder document or a model can never widen them. Day one behaviour is
identical to a HARD_LOCK (an absolute deny); the difference is that an accountable organization can decide otherwise,
in a versioned, explainable, testable file. Moving an identifier between this file and `../absolute-denies.md` is a
MAJOR release (Q84, Q98).

This tier was formerly named `organization-locked` (the old name) until the Q98 naming migration (issue #16 section 12). The loader still reads
the old spelling of `family:` and `lock:` as an alias and reports the file in one deprecation line; new files use the
canonical values `family: admin-governed` and `lock: admin-governed`.

**Every capability in this tier is administrable, and there is no release phasing.** An organization decides, in a
versioned file, whether each one is disabled or available. Nothing here is ever moved to a non-widenable lock: a human
decision by the product owner (2026-09-22) settled that external-effect capabilities stay administrable rather than
being hard-locked for a "v1", which supersedes the HARD_LOCK list in issue #16 §5.

**The ceiling is `ASK`.** These are external effects: they leave the project-owned local workspace and change shared
state. An organization may enable one, and then a human approves each occurrence; enabling it does not convert it into
an unattended `ALLOW`. A layer that asks for `ALLOW` is compiled to `ASK`, and the capability's provenance records that
it was clamped, so the decision stays visible instead of silently ignored. No host mode — `open`, `free`, full-PC,
skip-permissions — suppresses that gate. This is the bounded human approval of decision Q98 (`TASK_APPROVAL`): it is
what makes the capability administrable rather than unattended, not a temporary restriction.

## Denied

- [x] `git.remote.push` — pushing to any remote: integration is a human act unless the organization delegates it.
- [x] `git.remote.push.force` — force pushes rewrite shared history.
- [x] `git.remote.tag.push` — remote tags are release signals.
- [x] `git.remote.branch.delete` — remote branch deletion destroys others' work.
- [x] `git.remote.tag.delete` — remote tag deletion breaks provenance.
- [x] `forge.pr.create` — opening a pull or merge request.
- [x] `forge.pr.modify` — changing title, body, reviewers, labels or base of a PR/MR.
- [x] `forge.pr.close` — closing a PR/MR.
- [x] `forge.pr.merge` — merging is the integration decision.
- [x] `forge.pr.approve` — self-approval defeats review unless the organization explicitly defines otherwise.
- [x] `forge.release.publish` — releases are signed human acts.
- [x] `forge.release.delete` — deleting a release or one of its assets (`gh release delete`, `delete-asset`, `DELETE …/releases/…`): the inverse of a signed human act, and it breaks provenance for everyone who already pulled it.
- [x] `forge.repo.delete` — deleting a repository or project on the forge (`gh repo delete`, `glab repo delete`, `DELETE repos/OWNER/REPO`): irreversible and shared.
- [x] `forge.branch.protection.modify` — protected-branch rules are governance: branch protection, rulesets, protected tags, required approvals (`gh api` and `glab api` writes to `…/branches/*/protection`, `…/rulesets`, `…/protected_branches`, `az repos policy`). CHANGING a rule is administrable; defeating one (`enforce_admins=false`, a bypass actor, `gh pr merge --admin`) is `forge.protection.bypass`, an absolute deny.
- [x] `forge.repo.permissions.modify` — repository permissions and settings are governance: collaborators, teams, deploy keys, invitations, visibility, archiving, renaming (`gh repo edit|rename|archive`, `gh repo deploy-key`, `gh api` writes to `…/collaborators`, `…/keys`, `…/teams`, a repository PATCH).
- [x] `forge.issue.create` — create issues or work items.
- [x] `forge.issue.edit` — edit issue title, body, labels or milestone.
- [x] `forge.issue.transition` — change issue state or workflow column (`gh issue reopen`, `gh project item-edit|item-add|item-archive|item-delete`).
- [x] `forge.issue.close` — close issues.
- [x] `forge.issue.delete` — delete an issue or work item (`gh issue delete`): unlike closing, it cannot be undone.
- [x] `forge.api.mutate` — any mutating call through the forge API escape hatch (`gh api -X POST|PUT|PATCH|DELETE`, field flags, GraphQL mutations, or the same request sent with `curl`, `wget` or an HTTP client to a forge API host) that no more specific identifier names. A request whose path names an act this file lists (a merge, a repository delete, a protection or permission change) is judged as that act: the organization locks the act, not the spelling.
