# Changelog

All notable changes to EGO are recorded here. The format follows Keep a Changelog; versions follow the SemVer
discipline of decision Q84 (authority changes are never patch releases).

## [Unreleased]

### Added
- Repository skeleton, toolchain, frozen architecture baseline (`docs/architecture/pre-build-package.md`).

### Changed (authority — MAJOR under Q84)
- **A session grant lifts only a capability whose effect stays on this machine** (Q98 section 4 / issue #16 sections
  4 and 8: "never permit an unattended external-write ALLOW", and a human phrase is a bounded task approval, never a
  durable authority grant). Until now `you can comment on the issue` made every later `gh issue comment` — any issue,
  any `-R` repository — ALLOW for the whole session, `reply to the comment` did the same for `gh pr comment` and
  `gh pr review --comment`, and `you can curl it` turned a `curl -X PUT …/pulls/3/merge` or `curl -X DELETE
  https://api.github.com/repos/o/r` from ASK to ALLOW. Each compiled capability now carries `effect: local|external`,
  derived from its identifier by a positive grammar (`*.local.*` and the namespaces `fs`, `command`, `ego`, `git`,
  `container` are local unless the scope segment is `remote`, `nonlocal`, `registry`, `target`, …; everything else,
  including a namespace nobody has classified, is external). `applyGrants` — the one decision point — refuses to lift an
  external capability, the hook says so instead of recording "ALLOW for this session", and the clamp is recorded in the
  capability's provenance beside the organization's ASK-ceiling clamp. The four forge phrases of `grants.md`
  (`forge.issue.assign`, `forge.issue.comment`, `forge.review.comment`, `forge.review.thread.resolve`) are still
  recognised and reported but lift nothing; every grant for local work (`git.local.*`, `db.local.drop`,
  `k8s.local.delete`, `container.prune`, `ego.*`, `command.privileged`) works as before. An external capability that
  becomes local in a later release is reported by the authority diff as `grants-widened` (MAJOR).
- **`command.network-tool` means a fetch; a send is `network.external-write` (new, ASK, DENY in HIGH_ASSURANCE like the
  tool it was split from).** `curl`, `wget`, `wget2`, `http`, `https`, `xh` and `xhs` are read by the request — the
  method it really sends (`-d` makes a POST, `-T` a PUT, `-G` turns data back into a query, httpie reads standard input
  unless told not to), the host it names, whether that is a declared local target. A fetch, or a write to a declared
  local host (`localhost`, `127.0.0.1`, `[::1]`, `*.localhost`, `host.docker.internal`, …) is unchanged, and the grant
  for it still works. A write to a forge API host is the forge act it spells (`forge.pr.merge`, `forge.repo.delete`,
  `forge.protection.bypass`, `forge.api.mutate`, …) — the request is turned into its `gh api` form and read by the same
  patterns — and is DENY by default instead of an ASK a grant could lift. A write to any other host, a destination that
  cannot be resolved (`$URL`, `-X $M`, `-K file`, a proxy or a resolver override), `scp`, `sftp`, `rsync` to a remote,
  `ssh`, `nc`, `ncat`, `telnet`, a `/dev/tcp` redirection, a remote `tar -f host:path`, a tool pointed at an endpoint in
  no lockfile (`--registry`, `https_proxy=`) is `network.external-write`. Two matchers that never matched were
  repaired on the way: `rsync` to a remote absolute path (`host:/srv/`) and `tar -f user@host:path`. `http`, `https`,
  `xh`, `xhs` and `wget2` joined the bounded commands, and `http-server`, which is not `http`, is not matched.
- **Lock-tier move: `git.hooks.bypass` and `fs.outside-workspace.write` are now absolute denies** (Q98 follow-up 1).
  Both were DENY in all 12 profile × mode cells and no organization layer could widen them (a layer listing either
  failed to compile with a generic "attempts to widen"), but neither was marked, so the refusal read as an ordinary
  deny and the table did not say what the product decision says. They moved from `capabilities/git.md` and
  `capabilities/filesystem-and-commands.md` to `absolute-denies.md`. Effective verdicts are unchanged. What changes:
  a layer that merely *mentions* either id (a narrowing overlay, a profile `narrow` entry, a mode override, a grant,
  an organization policy) now fails with "may not reference absolute deny" instead of being accepted when it
  restated DENY. The authority diff reports `lock-changed none → absolute` for both, which `classifyAuthorityChanges`
  grades MAJOR (moving an identifier between lock tiers, Q84). That is acceptable here because the package is
  `0.1.0` and unreleased: there is no previous release tag for the release pipeline's authority diff to compare
  against, and no consumer overlay in this repository names either id.
- `git push --no-verify` is now classified `git.hooks.bypass` (absolute) instead of `git.remote.push`. The flag skips
  the pre-push hook, which is EGO's own repository-side gate for that verb; classified as the push it decorates, it
  became an ASK as soon as an organization enabled pushing, while the same flag on `git commit` was an absolute deny.
  A matcher placed ahead of the push rules re-partitions `push` (MAJOR, Q84); `merge`, `pull`, `rebase`,
  `cherry-pick`, `revert` and `am` were already `git.hooks.bypass`.
- **New absolute deny `forge.protection.bypass`** (Q98 follow-up 2, test 15c; #1 comment 2 puts "bypass of
  branch/repository protection" in the non-widenable core and no identifier expressed it). Matchers: `gh pr merge
  --admin`, `az repos pr update --bypass-policy`, `DELETE …/branches/*/protection/enforce_admins`, and any write to a
  protection or ruleset whose body (inline fields, a readable `--input`/`-F key=@file` document, a heredoc or a
  piped literal) sets `enforce_admins` to false/null, adds `bypass_actors` or `bypass_pull_request_allowances`, or
  puts `enforcement` to `disabled`/`evaluate`. A protection write whose body was named and could not be read (a file
  over the size limit, a path outside the workspace, a missing file, a variable, a pipe that is not a literal) is
  judged as the bypass it could not rule out: that a protection is not being defeated is a claim to be earned by
  reading the body, and padding a file must not hide `enforce_admins: false`. An ordinary rule change therefore needs
  its body inside the workspace. Adding an absolute id is a MAJOR change (Q84). `git push --force` is not this: it
  stays `git.remote.push.force`.
- **Matchers for three administrable ids that no pattern reached** (`forge.branch.protection.modify`,
  `forge.repo.permissions.modify`, `forge.issue.transition`): an organization enabling them used to change nothing,
  because every such call stayed `forge.api.mutate` or fell to `command.unknown`. They now sit ahead of the generic
  escape hatch. Three destructive acts that fell to ASK `command.unknown` get identifiers, DENY by default and
  administrable at the ASK ceiling like the rest of the tier: `forge.repo.delete`, `forge.release.delete`,
  `forge.issue.delete`. `gh api -X PUT …/pulls/N/merge` is now `forge.pr.merge` (the organization locks the act, not
  the spelling), and `gh api -X DELETE repos/OWNER/REPO` is `forge.repo.delete`. Matcher re-partitioning and new
  identifiers are MAJOR/MINOR under Q84; default verdicts are unchanged (all DENY), except that the commands that
  were ASK `command.unknown` (`gh repo delete`, `gh release delete`, `gh issue reopen`, `gh repo edit`, …) are DENY.
- A hit is now marked absolute by the capability it names, in one place (`evaluate`), not by each of the code paths
  that construct hits; a path-classified write outside the workspace is labelled "absolute core deny" in the reason.
- **A shell word is judged by what it resolves to — one resolver for the shell layer** (closure audit 2026-10-01, wave 2).
  `echo x > d/../settings.json` with `d -> .claude/sub` was ALLOW while `cd d && echo x > ../settings.json` — the same
  file — was DENY: about forty sites turned a word into a path with `resolve(cwd, word)`, which applies `..` to the text,
  and the kernel follows `d` first. `authority/paths.ts` now answers "what may this word denote" once — the lexical and
  the physical reading, as written and trimmed, in every directory the shell may be in, after `~`, `~+`, `~-`, `~user`,
  `$HOME`, `${HOME}`, `$PWD`, `$OLDPWD` — and every site judges all of them and keeps the worst. A redirection, a writer's
  operand, an archive extraction, a `find -exec` payload, a git pathspec, an option's value and the file a script reader
  opens all go through it. Visible changes: a write through `link/..` is judged by the link's target (DENY where it names a
  protected path); a path through `/proc/self/cwd`, `/proc/self/root` or an open descriptor above 2 (`/dev/fd/3`) asks;
  `curl -o /dev/null URL` is an ASK like `curl URL` (it was an absolute DENY: an option's value was not read as a discard
  device the way a redirection was), `wget -O` and `curl -D`/`-c` destinations are judged, and `echo x > /dev/disk0` is
  DENY (a redirection dropped every path under `/dev`; now only the discard devices are dropped, `/dev/shm` is scratch).
  A `HOME`, `PWD` or `OLDPWD` the command line assigns from something unreadable makes later uses of the name ask. A
  decision shares one view of the filesystem (the ordinary-development corpus runs in about two thirds of its former time).
