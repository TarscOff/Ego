# Changelog

All notable changes to EGO are recorded here. The format follows Keep a Changelog; versions follow the SemVer
discipline of decision Q84 (authority changes are never patch releases).

## [Unreleased]

### Added
- Repository skeleton, toolchain, frozen architecture baseline (`docs/architecture/pre-build-package.md`).

### Changed (authority — MAJOR under Q84)
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
  puts `enforcement` to `disabled`/`evaluate`. Adding an absolute id is a MAJOR change (Q84). `git push --force` is
  not this: it stays `git.remote.push.force`.
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
