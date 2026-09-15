---
schema: ego.capabilities/1
id: git
family: git
title: Git local and remote
---
# Git local and remote

Local history is the agent's working material. Remote mutation is never the agent's decision; the organization-locked
denies in `organization-locked.md` cover push, force push, remote tags and remote branch deletion (DENY unless the
organization policy layer says otherwise, Q98).

## Allowed

- [x] `git.local.status` — status, diff, log, blame, show, branch listing, reflog.
- [x] `git.local.branch.create` — create local branches.
- [x] `git.local.checkout` — switch branches or check out files when no foreign live session holds dirty work in the checkout.
- [x] `git.local.stash` — stash and unstash when no foreign live session holds dirty work in the checkout.
- [x] `git.local.stage` — stage changes.
- [x] `git.local.commit` — create local commits (overlay may set ASK; LEADQ-style products ask before committing).
- [x] `git.local.tag` — create local tags.
- [x] `git.remote.inspect` — list remotes and remote refs.
- [x] `git.remote.fetch` — fetch.
- [x] `git.remote.clone` — clone.
- [x] `git.remote.pull` — pull when the local branch is clean and fast-forwardable; otherwise treated as a merge.
- [x] `git.local.merge` — merge locally.
- [x] `git.local.cherry-pick` — cherry-pick locally.

## Requires human approval

- [x] `git.local.amend` — amend the last local commit.
- [x] `git.local.rebase` — rebase local history.
- [x] `git.local.reset` — reset local history or the index.
- [x] `git.local.restore` — discard working-tree changes.
- [x] `git.local.clean` — remove untracked files.
- [x] `git.local.branch.delete` — delete local branches.
- [x] `git.worktree.remove` — remove worktrees.

## Denied

- [x] `git.hooks.bypass` — `--no-verify`, `-n` on commit, `core.hooksPath` changes, plumbing that skips hooks.
- [x] `git.alias.inline` — an inline alias (`git -c alias.x=…`, `--config-env=alias.x=…`) redefines what a git verb runs; the aliased verb is judged as what it expands to, and a shell or opaque alias is refused.
