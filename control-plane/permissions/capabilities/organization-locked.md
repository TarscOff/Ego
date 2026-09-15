---
schema: ego.capabilities/1
id: organization-locked
family: organization-locked
lock: organization
title: Organization-locked denies
---
# Organization-locked denies

Denied at the core layer and widenable only by the organization policy layer (`policies/organization/permissions.md`
in the organization's governance repository). A product overlay, a task grant, an authority mode, a skill, an issue,
a stakeholder document or a model can never widen them. Day one behaviour is identical to an absolute deny; the
difference is that an accountable organization can decide otherwise, in a versioned, explainable, testable file.
Moving an identifier between this file and `../absolute-denies.md` is a MAJOR release (Q84, Q98).

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
- [x] `forge.branch.protection.modify` — protected-branch rules are governance.
- [x] `forge.repo.permissions.modify` — repository permissions are governance.
- [x] `forge.issue.create` — create issues or work items.
- [x] `forge.issue.edit` — edit issue title, body, labels or milestone.
- [x] `forge.issue.transition` — change issue state or workflow column.
- [x] `forge.issue.close` — close issues.
- [x] `forge.api.mutate` — any mutating call through the forge API escape hatch (`gh api -X POST|PUT|PATCH|DELETE`, field flags, GraphQL mutations); the specific operation cannot be told apart from a PR merge or an issue edit.
