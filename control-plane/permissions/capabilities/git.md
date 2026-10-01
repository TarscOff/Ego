---
schema: ego.capabilities/1
id: git
family: git
title: Git local and remote
---
# Git local and remote

Local history is the agent's working material. Remote mutation is never the agent's decision; the ADMIN_GOVERNED
capabilities in `admin-governed.md` cover push, force push, remote tags and remote branch deletion (DENY unless the
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

- [x] `git.local.merge.network` — apply whatever the last fetch brought (`FETCH_HEAD`, `ORIG_HEAD`). The fetch
  itself is ordinary and names any URL it likes; the merge is where that content reaches the working tree, and it
  rewrites tracked files — governed ones included — that no human has seen.

- [x] `git.local.amend` — amend the last local commit.
- [x] `git.local.rebase` — rebase local history.
- [x] `git.local.reset` — reset local history or the index.
- [x] `git.local.restore` — discard working-tree changes.
- [x] `git.local.clean` — remove untracked files.
- [x] `git.local.branch.delete` — delete local branches.
- [x] `git.worktree.remove` — remove worktrees.
- [x] `git.local.recovery.destroy` — destroy the local recovery net: `reflog expire`/`reflog delete`, `gc --prune`, `stash clear`/`stash drop`. These do not change the working tree, so they read as harmless, but they are what makes an unwanted reset or force-move unrecoverable.
- [x] `git.remote.configure` — add, rename, remove or re-point a remote (`remote add`, `set-url`, `set-branches`, `set-head`). Reconfiguring where the repository pushes and fetches is not remote inspection.
- [x] `git.identity.override` — attribute a commit to a name or address the agent was not given: `git -c
  user.name=… -c user.email=…`, `git commit --author=…`, or a signing key. The environment spelling
  (`GIT_AUTHOR_NAME=…`) was already in front of a person and its two command-line spellings were not; a commit
  credited to a named human who did not write it is a statement about who is responsible for it.

## Denied

`git.hooks.bypass` (`--no-verify`, `-n` on commit, `core.hooksPath` changes, plumbing that skips hooks) is an
absolute deny and lives in `../absolute-denies.md`.

- [x] `git.alias.inline` — an inline alias (`git -c alias.x=…`, `--config-env=alias.x=…`) redefines what a git verb runs; the aliased verb is judged as what it expands to, and a shell or opaque alias is refused. The transport options that name a program to run (`--upload-pack`, `--receive-pack`, `--exec`) are refused the same way: they hand git an arbitrary command line.
