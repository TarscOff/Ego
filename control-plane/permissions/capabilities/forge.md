---
schema: ego.capabilities/1
id: forge
family: forge
title: Forge read, narrow write, issues and work items
---
# Forge read, narrow write, issues and work items

The forge abstraction covers GitHub, GitLab, Azure DevOps, Bitbucket and future providers through one contract.
Reading is broadly allowed; writing is narrow and separate from repository mutation. Pull-request creation,
modification, closing, merging, self-approval and release publication are organization-locked denies (Q98): DENY
unless the organization policy layer says otherwise. So is every act that changes the rules or the permissions of a
repository, and every deletion of what cannot be recreated (a repository, a release, an issue). Defeating a
protection instead of changing it (`gh pr merge --admin`, enforcement switched off for administrators, a bypass
actor) is `forge.protection.bypass`, an absolute deny that no layer can widen.

An act is judged by what it does, not by the tool that spells it: `gh pr merge` and `gh api -X PUT …/merge` are the
same act under the same identifier. A write that no more specific identifier names is `forge.api.mutate`.

## Allowed

- [x] `forge.repo.read` — repository metadata, branches, tags, commits, release metadata.
- [x] `forge.pr.read` — pull or merge requests, reviews, comments, threads.
- [x] `forge.checks.read` — checks, pipelines, build results.
- [x] `forge.issue.read` — issues and work items, comments, links, dependencies.

## Requires human approval

- [x] `forge.review.comment` — reply to a code-review comment.
- [x] `forge.review.thread.reply` — reply in a review thread.
- [x] `forge.review.thread.resolve` — resolve a review thread after the issue is genuinely addressed.
- [x] `forge.issue.comment` — comment on an issue or work item (used for criteria proposals and completion notes).
- [x] `forge.issue.assign` — assign an issue to the current developer (forge-visible ownership).

## Denied

Issue creation, editing, transition and closing are organization-locked denies (see `organization-locked.md`): DENY
here, widenable only by organization policy.
