# Changelog

All notable changes to EGO are recorded here. The format follows Keep a Changelog; versions follow the SemVer
discipline of decision Q84 (authority changes are never patch releases).

## [Unreleased]

### Added
- Repository skeleton, toolchain, frozen architecture baseline (`docs/architecture/pre-build-package.md`).
- **Failure reason codes** (issue #16 section 10). Every non-ALLOW evaluation result carries a typed `code`, a
  structured `rule` (the rule source, and whether configuration can change the outcome), and a reason string that
  leads with the code and says both: `HARD_LOCKED` (an absolute deny; nothing can change it), `ADMIN_DENIED` (an
  ADMIN_GOVERNED capability the organization has not enabled, or a DENY the selected profile or authority mode chose;
  the organization layer, the profile or the mode can change it), `HUMAN_APPROVAL_REQUIRED` (an ASK: one human
  approval, TASK_APPROVAL), `SCOPE_DENIED` (a protected path, a target that is named but not a declared local one, an
  operation the core table denies and no policy enables), `TARGET_UNCLASSIFIED` (what used to be text inside the
  reason; now the code), `POLICY_INVALID` (a policy that does not load or compile, or a pin that fails its stamp: the
  command or hook fails closed with the code, the file and what can fix it) and `POLICY_STALE` (a cache from another
  runtime or naming, an edited layer file, a widening awaiting a human, a pin not yet at the required trust: in
  `ego check`, `ego doctor`, at SessionStart and in the pre-promotion refusal). `NETWORK_UNAVAILABLE`,
  `SERVICE_UNAVAILABLE`, `RUNTIME_CAPABILITY_UNAVAILABLE` and `DOWNSTREAM_AUTH_DENIED` are members of the enum with
  their producers documented as arriving with the phase that owns the module (forge, MCP and tracker adapters in phase
  2, host conformance in phase 6); nothing produces them yet and nothing pretends to. The mapping from a decision to
  its code is one function (`explainOutcome`), the hook decision carries the code (`HookDecision.code`), and both
  host dialects render the reason through one reader (`decisionReason`) so the code reaches the human on claude-code
  and on codex-cli. `Evaluation.reason` stays prose; `code` and `rule` are new fields, so existing consumers are
  unaffected, though the reason text now begins with the code and ends with two sentences.
- **`ego capabilities`, `ego explain capability` and `ego doctor` print the Q98 vocabulary** (issue #16 section 12):
  per capability the effect class (`LOCAL_WORKSPACE` or `EXTERNAL_EFFECT`), the lock tier (`HARD_LOCK`,
  `ADMIN_GOVERNED` or none), the verdict in force, the ceiling (the widest verdict any configuration path can reach:
  ASK for an ADMIN_GOVERNED external write), the layer that decided (`core`, `admin-governed`, `organization (…)`,
  `profile P`, `mode M`) and, for a capability whose verdict depends on where the command points, the
  target-classification rule. Every field is derived from the compiled table; the target rule is read from the same
  table the resolver uses to choose the capability, so the rule shown is the rule applied. `ego doctor` lists the
  ADMIN_GOVERNED and the target-dependent capabilities one by one and summarises the rest; `ego doctor --capabilities`
  lists all of them.
- **`ego authority diff <old> <new>`** prints the classified changes between two compiled tables
  (`diffAuthorityTables` and `classifyAuthorityChanges`, written for the release pipeline and referenced by no
  command until now), the semver class under Q84, and marks every WIDENING with the profile × mode cells it applies in.
  An operand is `core`, `current`, `proposed` (the layer files as they are in the working tree, before a human accepts
  them: the review `ego init` asks for), or the path of a policy cache or table file, including one written by an
  earlier release. `--fail-on-widening` exits 1 when anything widens. It only reads.
- **The local-development target registry has project and organization layers, and `ego init` proposes and adopts
  targets** (Q98 sections 1, 7 and 8). `control-plane/workspace/local-targets.md` said a project or an organization may
  add targets it owns while the compiler read exactly one file. `.harness/local-targets.md` and
  `policies/organization/local-targets.md` may now add kube contexts, database hosts, container contexts and production
  markers; a layer never removes a marker and never declares a production-marked name local (ignored, with a diagnostic
  in `ego doctor`). Declaring a target local is a widening: it never applies from the working tree, and takes effect
  when a human runs `ego init` and accepts it. Each declaration is local for one family of tools only. The compiled
  table and its hash carry the merged targets, and `diffAuthorityTables` reports `local-target-added` (MAJOR).
  `ego init` detects local-development surfaces from repository files only and prints proposals;
  `--local-target <kube|db|container>:<name>` (repeatable, a human act refused from an agent shell) adopts them,
  `--no-local-targets` declines, and the AUTHORITY DIFF is printed after any change. A new capability
  `ego.local-targets.edit` (ASK) guards `.harness/local-targets.md`.
- **An ASK on an operation that leaves this machine presents what is being approved** (Q98 section 8): action, target
  service or repository or resource, branch / cluster / database / tool, a bounded secret-masked summary, why it asks,
  and how reversible it is (`authority/approval.ts`). Durable tasks do not exist before phase 2, so the task line says so.

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
- **Naming migration: `organization-locked` is `ADMIN_GOVERNED` (issue #16 section 12, #2 section 12). MAJOR under Q84
  for the schema, no verdict moves.** The canonical terms are `LOCAL_WORKSPACE`, `EXTERNAL_EFFECT`, `HARD_LOCK`,
  `ADMIN_GOVERNED` and `TASK_APPROVAL`; the code, the messages, the doctor, `ego capabilities`, `ego explain`, the
  SessionStart text, the generated root instructions, the provenance and the documents now use them. What was renamed:
  the file `control-plane/permissions/capabilities/organization-locked.md` is `admin-governed.md` (`family:
  admin-governed`, `lock: admin-governed`); `CapabilityLock` `'organization'` is `'admin-governed'`;
  `ControlPlane.organizationLocked` and `CompiledAuthorityTable.organizationLocked` are `adminGoverned`; the provenance
  layer strings read `admin-governed` and `organization (widened admin-governed deny…)`; the compile errors for a mode
  or a grant that names the tier say `ADMIN_GOVERNED capability`. **What did not change:** every effective verdict in
  every profile × mode cell, the tier membership, the ASK ceiling and the lock-tier semantics. `ego authority diff`
  between the previous release's table and this one is empty; that was checked against the previous compiler's own
  output, not only against a hand-made fixture. **The authority-table hash does change**, because the field name and
  the provenance strings are part of the hashed body. Consumer action: none is required. No pin records the table hash
  (the pin holds version, integrity, sources, schemas, node and profile), so no pin is invalidated. The policy cache
  (`.harness/generated/policy.json`) is gitignored, per machine and keyed on the runtime identity, so the upgrade
  regenerates it on the next hook anyway; until then `ego check` and `ego doctor` report `POLICY_STALE` with a message
  that says why, and a cache written under the old naming is read in the new shape rather than discarded, so a layer
  widening a human already accepted is not turned into a pending one. If you maintain a control-plane fork or an
  `organization-locked.md` of your own, rename it and its `family:` and `lock:` values when convenient: the old
  spelling is a read alias, translated once and reported as one deprecation line per file (in the policy cache's
  `notices`, in `ego doctor`, and on stderr from the commands that load the control plane). The alias widens nothing:
  a tier declared outside the core layer is still refused, and an unknown `lock:` value still fails closed. Code that
  reads `table.organizationLocked` or compares `lock === 'organization'` must follow the rename (TypeScript reports
  both); a CI job that keeps a stored table to diff against needs nothing, because the diff reads old tables.
- Provenance `file` names and the target-resolution reason no longer lose their first character when the control-plane
  root is given with a trailing slash (`ermissions/…`).
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
  A `HOME`, `PWD` or `OLDPWD` the command line assigns from something unreadable makes later uses of the name ask, and a leading `~` is the HOME the line assigned (`export HOME=/etc; echo x > ~/passwd`). A
  decision shares one view of the filesystem (the ordinary-development corpus runs in about two thirds of its former time).
- **Five readers answer five dimensions the findings kept reopening** (closure audit 2026-10-01, wave 3: database
  statements, wildcard reach, redirections, wrapper nests, the directory stack).
  *One reader of the statements a database client runs.* `clickhouse-client --host prod-ch --query 'show tables' -q 'drop
  table t'` was a production DROP TABLE at ALLOW: the production exception for reads kept its own scan of the line for
  statements (`-c`, `-e`, a list of long names), which did not know clickhouse's short `-q`. The client's own grammar now
  answers, for every option spelling together (long name and its abbreviations, short letter, value glued to either,
  repeated, clustered), and `cqlsh` and `influx` have one beside psql, mysql, sqlite3, mongo, redis and clickhouse. A plain
  read given by `-q` against a production host is ALLOW like every plain read (it was an absolute DENY). A statement that
  drops a DATABASE, SCHEMA or KEYSPACE is `db.local.drop` (ASK) however its option carries it (`mysql -e'DROP DATABASE
  app'` had no word boundary for the matcher; the matcher stays as the text net for a here-string). A variable a flag NAMES
  is followed to its value (`dbmate --env PROD_URL`: DENY at a production URL, ASK when the value is not on the line, DENY
  when the name carries a production marker); `knex|sequelize|atlas --env production` is judged by the environment name;
  `flyway -url="$X"` and `liquibase --url=$X` ask (the connection string is built at run time).
  *Wildcards are judged by the names they match.* `cat .e*`, `.??*`, `.e?v`, `Grep` with `glob: "*"` and the like read or
  printed `.env` at ALLOW; the directory is read (bounded: a reached bound asks) and every match is classified. A bare
  wildcard is judged once `dotglob`/`GLOB_DOTS`/GLOBIGNORE or a zsh `(D)` qualifier is on the line. A Glob/Grep brace
  expansion refused for its budget asks on the tool surface as it does in a Bash word. `Glob "*"` and `Grep` with a
  catch-all glob in a directory that holds a hidden credential file now ask; in one that does not they are unchanged.
  *One reader of redirections.* An operator glued to a word ends it (`find . -delete>/dev/null`, `git checkout
  -f>/dev/null` were ALLOW where the spaced forms ask; `ls>/dev/null` was an unknown command; `bash<<<'git push'` is the
  script it spells), the matchers that describe the act also read it without its redirections (`git checkout . >/dev/null`
  was ALLOW; `terraform apply -auto-approve > --help` took its target for a help flag), a `/dev/tcp` name is read after
  quote removal (`/dev/"tcp"/h/80`), and zsh's `>!`, `>>!`, `&>!`, `>&!` are judged in both readings (`echo x >! /etc/hosts`
  was ALLOW). `sh run.sh </dev/null` runs run.sh.
  *A nest deeper than a walk goes is unproved.* Nine `env`s before `-C ~/.ssh` ended the directory walk silently
  (now read to 64, and beyond that the directory is unproved); the carrier, http-client and git-config-include walks say
  so too. *The directory stack is edited by the option*: `pushd -n DIR` and `popd -n` leave the directory, `+N`/`-N` and
  unknown options make it unknown, `dirs -c` empties the stack (pinned against bash and zsh).
