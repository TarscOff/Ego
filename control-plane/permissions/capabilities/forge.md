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
unless the organization policy layer says otherwise.

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
