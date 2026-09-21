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

**The v1 ceiling is `ASK`.** These are external effects: they leave the project-owned local workspace and change
shared state. An organization may enable one, and then a human approves each occurrence; an organization may not turn
one into an unattended `ALLOW`. A layer that asks for `ALLOW` is compiled to `ASK`, and the capability's provenance
records that it was clamped, so the decision stays visible instead of silently ignored. No host mode — `open`, `free`,
full-PC, skip-permissions — suppresses that gate. This is decision Q98; the canonical wording for this tier is
`ADMIN_GOVERNED`, and `organization-locked` is the compatibility name still used by the schema.

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
