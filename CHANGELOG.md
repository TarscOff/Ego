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
- **Ordinary development, second half of the closure audit** (independent reviews of wave 5: `U-10` .. `U-19`, `PA-12`, `PA-13`,
  `AUTH-13`). The reviewer who measured 52,825 commands found that the waves had left 62% of typed ordinary commands asking and 45 of
  6,197 refused outright, and that a refusal is the verdict nobody can approve. Each finding is a cause with ONE reader now:
  - **The forms that only look are one table** (`authority/local-reads.ts`). `go list|env|doc`, `go mod graph|why|verify`, `cargo
    tree|metadata|locate-project|pkgid`, `gem list|env|which|…`, `bundle config`, `dotnet --version|--info`, `git symbolic-ref` (one
    operand), `git submodule status`, `git config` reads, `git notes list|show`, `gh run|workflow|release|repo list`, `gh auth status`,
    `helm repo list|update`, `helm plugin list`, `helm dependency list`, `pip check|cache|inspect`, `npm root|prefix|pkg get|audit|search`
    and EGO's own `ego status|doctor|check|help|version|capabilities|explain capability|authority diff|modes|context explain|sources` are
    read by a positive grammar (the option words the row knows, the operands it takes, nothing else) and are ordinary; an option the row
    does not list, a second operand, a word a shell fills in and a path to the program are not the row. It is asked only when no matcher
    decided, and the same table says the form is not an unmodelled closure. `mvn`, `./gradlew`, `bundle show|list` and `dotnet list`
    stay out: each runs something the repository wrote (shown with the real bundler: a `system` call in the Gemfile runs on `bundle show`).
    `helm repo add`, `dependency update|build` and `pull` still fetch or record something the kernel has not read, and ask.
  - **A hooks directory is not a program** (`U-10`). `core.hooksPath` is the directory the hook resolver reads, not a command line: every
    husky repository asked "no matcher: .husky/_" for `git status`. `init.templateDir` is a directory for `git init`/`git clone` only, and a
    proxy whose value is a URL is not a program.
  - **Which variables choose what runs is one list** (`authority/env-vars.ts`, `U-11`). The names, the list copied into `matchers.md` and
    three patterns that matched `NAME=` anywhere in a segment (and refused `subprocess.run(cmd, shell=True)`, a python heredoc that
    mentioned `IFS=`, and a script line `ENV=${1:-dev}`) are replaced by the evaluator's own: the marker's word says refused or asked
    about. A location variable (`PYTHONPATH`, `CLASSPATH`, `JAVA_HOME`, `GOPATH`, `CARGO_HOME`, …) is judged by where it points: a place
    in the checkout asks, a toolchain outside the checkout and a store at the tool's own default location are ordinary, and a scratch
    directory, a word a shell fills in and a credential store keep the refusal. A bare `IFS=` or `ENV=` sets a variable of that shell and is
    not an injection. `--experimental-vm-modules` (what jest asks for) is not a loader. A binding in a string a carrier hands to a shell
    (`watch 'export BASH_ENV=/tmp/x'`) is reported by the normalizer.
  - **A directory selector is a `cd`** (`U-12`): `npm --prefix backend run build`, `npm -C`, `pnpm -C|--dir`, `yarn --cwd`, `bun --cwd` name a
    directory inside a registered root and are resolved like `cd backend &&`; a workspace or filter selector still asks.
  - **A removal leaves the name what it was** (`U-14`): `rm -rf dist && npm run build`, where the build removes it again, is ordinary; a name
    that was created or replaced earlier in the line is still not the name it says.
  - **An option letter is not its other case** (`U-16`): the pager rule of `git grep -O` and the strategy rule of `git merge -s` say so
    with `(?-i:…)`; `git grep -o`, `git archive -o`, `git format-patch -o` and `git merge -S` are ordinary, `git archive` and `git
    format-patch` are local mutations whose destination the option table judges.
  - **A template is not a secret** (`U-17`): `.env.example`, `.env.sample`, `.env.template` and `.env.dist` are read and edited like any
    file; `fs.env-file.write` is an ASK in STANDARD (the first-run copy of the template) and stays a DENY in STRICT, HIGH_ASSURANCE and
    PRODUCTION_ADVISORY.
  - **Every file curl writes** (`U-18`): a complete option table of curl (derived from `curl --help all`) and the `%output{FILE}` of a `-w`
    format, inline or taken from a file, are read by the one parser; `--libcurl`, `--alt-svc`, `--ssl-sessions` and the format are writes.
  - **A wildcard is judged by what could govern it** (`PA-12`): the names a rule can reach are asked individually, the directory a set
    lives in once; `wc -l logs/*.txt` over eight thousand files costs what it costs over a hundred. The bound stays for a set too large to list.
  - **A link is judged where it is used** (`PA-13`): `ln -s . self`, `ln -s .. parent` and `ln -s /usr/local/bin/node node` record a name and
    write nothing at the target; a name the same line makes is read through its link, a link into or to a governed tree is the route it
    always was. The write branch and the link branch now ask the same question of "a root or above it" (`atOrAboveRoot`).
  - **The gates the corpus accounts for say why** (`U-13`): `GATE_REASONS` ties each reason to the capability the evaluator reports, and a
    test compares them; the four claims that were false are corrected.
- **A cluster command is read once** (closure of root cause RC-K8S, independent reviews 7-11: `sa10-33` CRITICAL and
  `r11-68 69 70 71 72 73 74 75 76 77 169 170 186 187 191 206`). `kubectl`, `oc`, `helm` and minikube's own `kubectl`
  were judged by four readers that each knew a slice of the command line — a verb table, a dry-run scanner, the regexes
  of `matchers.md` and a target resolver over text whose quoting was already gone. `kubectl --context production set
  env deploy/x 'A=b --list'` was a production mutation at ALLOW because the resolver read the last blank-separated
  words as the read-only flag. `authority/k8s.ts` (`k8sEffect`) now answers, over the words as the tool receives them,
  which cluster is reached (`--context`, `--cluster`, `--user`, `--server`/`-s`, `--kubeconfig`/`oc --config` and the
  CONTENT of a kubeconfig the workspace holds, judged by its SERVER, `KUBECONFIG`, `KUBERNETES_MASTER`,
  `KUBERNETES_SERVICE_HOST`, `HELM_KUBECONTEXT`, `HELM_KUBEAPISERVER`, `HELM_NAMESPACE`, `minikube kubectl --`), what is
  read (a Secret by resource type, by a `-f`/`-k` source, by a stream, by a word a shell fills in; `helm status -o
  json|yaml`; `kubectl config view --raw|--flatten`; a file named as `KEY=PATH`), what changes (a flag VALUE is data,
  never the flag; the last `--list` and the last dry-run flag decide) and what runs (a plugin, a credential plugin in
  a kubeconfig, a post-renderer). One option table (`k8s.ts`) now feeds the verb scan, the dry-run reader, the
  help-probe reader and `flagFilledInAfter`. Verdicts that change for ordinary commands: a verb the tool does not have
  (`kubectl foo`, `kubectl argo rollouts get`, `helm secrets view`, `helm unittest`) and an option in front of the verb
  that the tool does not have are plugin invocations and ASK, also against a local cluster; `kubectl config view
  --flatten` and a `kubectl config set-*` behind a global option are denied like their plain spellings; a Secret read
  from a non-local cluster through a source the kernel cannot read is denied; a workspace kubeconfig whose context
  points at a server that is not a declared local one is no longer local, and one that is (a kind or k3d cluster's)
  now makes `kubectl --kubeconfig ./kube.conf apply -f x.yaml` local without a `--context`; a kubeconfig the same
  command line writes, or whose credential plugin runs a program, asks.
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
- **The container tools are read by one reader** (closure audit 2026-10-01, wave 3, root cause RC-CTR). docker, podman,
  nerdctl, compose, buildx, builder and bake were read in six places — the help-probe test, the global-option
  stripper, the engine resolver, the image detector, the bake reader and the Dockerfile reader — each with its own idea
  of where the verb sits, and a fix at one spelling left its siblings open. `authority/containers.ts` is now the only
  one: the options of each program with their arity, the management groups with their own options, a table of the verbs
  the product decided about, the engine options accepted past the verb, and one reading of what a build reads and
  produces. Visible changes: (1) a verb that is not in the table — `docker debug`, `docker pass`, `docker scout`, a
  plugin, a word built at run time — or an option of unknown arity where the verb belongs asks
  (`command.unmodelled-closure`) where the catch-all ALLOW answered before; (2) `--host`, `-H`, `--context` and `--builder`
  are engine options wherever docker accepts them — before the verb, after it, glued, `=`-joined — and stop at the
  words a container program is given (`docker run IMG tool --context x` names no engine, and was a DENY for `--builder`);
  a quoted verb is the verb; `buildx create`/`builder create` against any endpoint binds that engine; (3) `docker buildx
  bake`, `docker bake`, `docker builder bake` and `docker compose build|up --build|run --build` read the bake files
  (HCL and JSON) and compose files the tool reads by default or by `-f`, the Dockerfile each target names, an inline
  Dockerfile and `--set` overrides, and judge the RUN lines like any Dockerfile — `docker compose build` with a read,
  ordinary Dockerfile is no longer an ASK of its own; a file written earlier in the same command, a variable, a matrix, an
  anchor, an include or a remote definition asks; (4) outputs, caches and secrets are the pushes, writes and reads they
  are for a flag, `--set SELECTOR.KEY=` and a file alike: `-otype=registry` and `--set '*.output=type=registry'` ask, and
  `--set default.output=/etc` is a write to `/etc`; (5) `docker logout` and `podman|nerdctl login|logout` are credential
  writes like `docker login`; `docker compose run -e AWS_…` is a credential exposure like `docker run -e`; `compose
  down --volumes=true`, `podman pod rm|prune`, `podman machine rm|reset`, `nerdctl namespace rm` and `colima delete` are
  destruction like `docker rm`. A command after `--` in a plugin verb (`docker pass run -- psql -h prod-db …`) is
  analysed as the command it is, also behind `sudo`, `env` or `sh -c`. Ordinary container development (`docker ps`,
  `run`, `build`, `compose up`, `logs`; `docker exec` still asks) is unchanged, and so is the accepted behaviour that a
  plain `docker compose up` does not read the compose file.
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
- **What makefile text `make` will run, and whether any of it was written or can be rewritten before or while it runs, is
  one question with one reader** (closure audit 2026-10-01, wave 2, root cause "make"). The freshness ledger answered
  "is this makefile stale" at the first read of an invocation and nowhere else; eight reviewed findings were the other
  places. Visible changes, each from ALLOW to ASK or DENY and none for an ordinary command:
  - `make 2>&1`, `make > log` and `make 2>&1 | tail` read the redirection's words as goals, found no rule for them and ran
    the default goal under that proof (a default goal that pushes was ALLOW; it is now the DENY it always was for `make`).
  - The shell expands an unquoted word with `*`, `?` or `[` before make starts, and make is handed the result: `make -f
    ev*.mk` opens what matches, `make -C su* all` enters `sub`, `make dep*` builds the `deploy` a directory of that name
    selects (a phony target runs). The command line was read with the pattern as if it were the name. One reader
    (`shellGlobWords`) expands the whole word, as the shell does: `'ev*.mk'`, `--file=ev*.mk` and `-fev*.mk` stay literal
    (checked against GNU make 3.81). A glob character produced by a brace expansion is no longer quoted back in
    (`make -f ev*.m{k..k}`). A `-f` or `-I` word nobody can resolve asks instead of being dropped; `-I DIR` /
    `--include-dir` are part of where an `include` is looked for.
  - A makefile that a rule of the makefile can build is remade by make - the rule's recipe runs for every goal, `-n`
    included - so what was read is a pre-image: a pattern rule (`%.mk: %.in`), a suffix rule, a wildcard or computed
    target and `.DEFAULT` count, not only a rule with the file's own name. An implicit rule counts when its source is
    there or can be made, so an old-style `%: %.sh` or `.c:` rule leaves a Makefile alone.
  - A recipe's second pass asks: `cp evil.mk Makefile` then `make run`, a sub-makefile replaced and read again under a stamp
    file, the same through an npm script or a shell script (the cycle guard compares the write ledger at entry and at
    re-entry), and `CMD="..." make run` inside a recipe is a different invocation (the key carries the environment).
  - A shell function is read again at its call when a file or the directory moved since its definition (`f() { make -C
    sub all; }; cp evil.mk sub/Makefile; f`, `...; cd sub; f`).
  - The ledger records a writer in the directory it runs in (`env -C`, `env --chdir`, `git -C`), a deletion or a move
    away (`rm GNUmakefile && make` makes the next makefile in make's order the one that runs), and a sed script or a file
    name with an `=` in it no longer hides the write (`sed -i 's/^CMD=true/CMD=sh/' Makefile`).
  - The recipes of `make -j`, the stages of a pipeline, a background job and what follows it, and the later passes of a
    loop are each read against the writes of the others.
  - A command the makefile runs while it is read that is not a pure read (`X := $(shell cp gen.in gen.mk)` above `-include
    gen.mk`, a script, `$(file >gen.mk,...)`) may write the makefile read after it: the invocation asks. A version
    lookup, `date` and `uname` keep their ALLOW.

  A growing recursion stops at the analysis depth and asks, as before. `$(MAKE)` in a recipe is still a variable this
  resolver does not read, so a recipe line that spells it asks.
- **A wrapper is peeled by its own options, and a tool's options are read by the parser the tool has — one table each**
  (closure audit 2026-10-01, wave 3; independent review 11). `timeout -s KILL 5 sed -n '1w .claude/settings.json' f`,
  `env --unset A sed …`, `find -exec sed …`, `yarn exec git -C control-plane checkout …`, `watch 'git commit -nm x'` and
  `env -S'git commit -m x' -n` hid the carried command from every reader of the line as written, because five readers kept
  five copies of the wrapper loop and each knew the options its author had met. `authority/carriers.ts` is the one table of
  carriers (their own options with values, clusters, glued forms and abbreviations; the command STRINGS they carry; the
  operands they take) and `peelCarriers` the one reader, iterated to a fixed point: the normalizer, the head finder, the
  awk scanner, the environment-input scan and the directory finder all use it. A STRICT carrier meeting an own option it
  does not list, or a chain nested past twelve, makes the segment ask (`command.script-opaque`) instead of guessing where
  the command begins. A `find -exec` / `fd -x` clause, a `watch` or `sem` argument and the words `env` appends to a `-S`
  string are carried bodies, like `sh -c`. In the same way `authority/options.ts` (a GNU / Go / compiler option grammar) and
  `authority/tools.ts` (one table per modelled tool, each option's value marked as a file written, a directory written into,
  a file read, a program, code, a configuration or a Python module) replace the per-reader regexes for tar, sort, sed, the
  shells, go, the C compilers, eslint, prettier, pylint, python and the git subcommands that write: `tar --extr -C
  .git/hooks`, `tar --use=./x`, `sort --o=…`, `go build -o=.git/hooks/pre-commit`, `gcc -MF.git/hooks/x`, `git checkout-index
  --prefix=.git/hooks/`, `git archive --out=…`, `git format-patch -o …` and `bash -n +n -c BODY` are judged by what the tool
  would do. `authority/sed.ts` reads a sed script as a script, so a file glued to `w`, `W` or the `w` flag of `s` is a write
  (and `r FILE` is a read). Visible changes for ordinary work: `time -p CMD`, `/usr/bin/time -v CMD` and `tar -xOf a.tgz
  FILE` (extraction to standard output) are ALLOW where they asked; `echo 'rm -rf /' | bash -n` is a syntax check, not an
  execution; an option that NAMES a program or module a bounded runner loads (`clang --ld-path=./x`, `gcc -fuse-ld=./x`,
  `eslint -f ./fmt.js`, `prettier --config ./evil.json`, `pylint --init-hook "…"`, `python3 -m venv` with a `venv.py` beside
  it) asks; `bun test` is bun's own runner, not the package script of the same name, and asks like `go test`.
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
- **A database client's command line is read by the client's own table - for the target, the statements, the files and the
  pipe** (wave-5 review of the closure audit, RV-DB-1, RV-DB-2, RV-DB-3). `authority/db-options.ts` holds one table per
  client (psql, mysql and its administration and dump tools, mongosh, redis-cli, clickhouse-client, cqlsh, influx, the
  PostgreSQL tools) and one parser; the statement reader, the target resolver, the output-file reader, the `-l` and
  `redis-cli INFO` exceptions and the standard-input condition all ask its answer.
  *The target.* `psql --ho=prod-db.acme.com -c 'update users set active=false'` was ALLOW and `--host=` an absolute deny
  (getopt takes any unambiguous prefix; the host scan matched the word `--host`); `mysql --hos=`, `clickhouse-client --ho=`
  and the dump tools were the same. Every host option is now read in every spelling the client accepts (an abbreviation,
  a glued value, a cluster, a list, `host:port` for mongosh, repeated: the strongest decides). A connection string where a
  database name goes (`psql -d "$DATABASE_URL"`, `pg_dump --dbname=`, `redis-cli -u "$URL"`: the server is the string's, whatever
  `-h` says) and a profile named in an abbreviation (`mysql --login-p=`) are UNCLASSIFIED, where they were the local socket.
  *What is a host.* `mongosh -u john.doe`, `mysql -u app.user -e 'drop table x'`, `psql -U app my.app` and `redis-cli -a
  pass.word` were absolute denials: a dotted word was a host wherever the old scan did not know it for an option's value. The
  table says which words are values and what an operand is - a database NAME in psql, mysql and the dump tools (so `psql
  prod-db.acme.com` is a database on the local socket), a host in cqlsh, an address in mongosh and clickhouse-client - and
  `psql -Uhenry` is a user, not `-U` and a host `enry`.
  *The psql script.* `printf 'select 1 as a$$$\n\\o |touch f\n' | psql` ran the program at ALLOW: the scanner took the second `$` for a
  dollar quote. The scanner (`authority/sql-lex.ts`) now follows psql's own lexer, checked against the real psql 15, 16 and 17 and
  fuzzed against it: a `$` continues a name, a number that runs into a letter is one token, `\;` and `\:` leave the line going on
  as SQL (they used to swallow it: `select 1 \; \o |cmd`), a backquote is no quote, a tag may hold non-ASCII letters; the two
  forms older and newer clients lex differently are refused. `:name` interpolates a variable and psql lexes its text, so the
  values `-v` and `\set` give are read in place and any other reference (`\gset`, `\getenv`, nothing on the line) asks.
  *The pipe.* Standard input is a script where the client was given no statement of its own, which is the table's answer, not a
  prefix test of the words: `echo 'system id' | mysql -c` (a flag), `echo '.shell id' | sqlite3 -cmd .tables db` (not a statement)
  ran the program at ALLOW; `psql -qc 'x'` and `--comm` are statements and replace it. Visible: `pg_dump --fil=out.sql` and
  `mysqldump --res=out.sql` write the file their path says, like `-f`.
- **A look is not an act - one reader of the role of a word** (closure audit 2026-10-01, register cause F: 50 over-gated
  findings, 13 of them HIGH, and the critical review-11 #142). `grep -rn "hook claude-code PreToolUse" docs/` - reading the
  documentation that describes the gate - was an absolute deny, as were `git commit -m "docs: explain --no-verify"`,
  `git grep core.hooksPath docs`, `grep -rn claude src/`, `git log --grep=...`, `echo "ego hook"` and `jq . <
  .harness/runtime/state.json`: the text matchers, the path readers and the scan for governed programs in argument position
  read a segment as a bag of words and could not tell the word searched for from the word run. `authority/operands.ts` now
  answers it once, from a grammar of the tools that take data (grep and its twins, ripgrep, `git grep`, the pickaxe and
  message options of git, `echo`/`printf`), and the normalizer takes those words out before any matcher reads the text. An
  option nobody listed leaves the line unread, a redirection is never data (the tokenizer reports whether an operator was
  written bare, quoted or escaped), and a head that is a path is not trusted. The write matchers name what is WRITTEN: an input
  redirection and the first operand of a copy are reads, so `tee /tmp/o < .harness/runtime/state.json` and `cp
  .claude/settings.json /tmp/s.json` are ALLOW and the doing forms stay absolute denies. Reading the EGO trust store
  (`cat ~/.ego/trust/keys.json`, `du -sh ~/.ego`, `cp -r ~/.ego/trust /tmp/copy`) is a read, as the Read tool already judged
  it; writing, moving, linking or copying INTO it is still `ego.trust.tamper`. A probe performs nothing, decided once: a
  help flag after the verb (`git push --help origin main`, `gh pr merge -h`), `help` as a verb, a redirection glued to a flag
  (`--dry-run>/dev/null`), a dry-run cluster (`-vn`), the dry run of `git add|rm|mv|clean` and `commit --dry-run` (read as
  `git status`, which still runs the filters the repository configures), the print options of git (`git --exec-path`), the
  manual of curl and wget and `ssh -V`/`-Q`, and a syntax check behind `flock`. A read keeps the verdict of a read:
  `kubectl get` and `helm status` in PRODUCTION_ADVISORY, `gh api -X GET ... -f q=x`, `aws configure get region`,
  `psql -c 'EXPLAIN (FORMAT JSON) ...'` and `clickhouse-client -q 'SHOW TABLES'` against a production host, `psql -l>/dev/null`,
  `java -version`, `git config --file X --get`, `git stash list --all`, `git diff --textconv`, `GIT_PAGER=cat git log`,
  `git -c alias.st=status st`, `ls ~/*` (which now asks as a read outside the workspace and no longer refuses), and
  `find . -name '*.tmp' -exec rm {} \;` (an ASK where it was an absolute deny; a search that names or selects a governed
  tree is still refused). The remaining fixes of the group are `sort --o FILE` (an unauthorized ALLOW: any unambiguous
  prefix of `--output`), a here-document delimiter that is a regular-expression metacharacter (the evaluator threw), and
  `trap '...'`/`<<<` unquoting their body a second time. One narrowing came with the reads: `kubectl config view --raw`
  and `--flatten` print the kubeconfig unredacted and are now a credential read wherever the verb sits (`kubectl --context
  production config view --raw` slipped under an anchor on `config`, and would have become ALLOW in the production advisory once
  a cluster read stopped taking the advisory's verdict). Not changed, on purpose: `helm get values|manifest|all` of a production
  release and `docker logs|inspect` on a non-local engine stay refused (they print secrets).
  *Merged with the readers of the carrier, option, path and cluster groups, one reader for each question both sides had
  answered.* What `sort` writes is the sort table's answer (`tools.ts`, every unambiguous prefix of `--output`), not a second
  scan; whether `git config --file F` reads or writes F is `gitConfigAsks` (`tools.ts`), asked by the table's file role and by the
  scan of output flags alike; whether a wildcard may match a name that begins with a dot is `shellGlobOptions().dotfiles`, asked by
  the glob expansion and by the judgement of a glob that cannot be expanded; where the command behind `sudo`, `env`, `xargs` or a
  `find -exec` clause starts and ends is `carriers.ts` (`peelCarriers`, `payloadSpans`) for the data-word reader, the
  normalizer's payload reader, the raw-text scanners and the make producer (a `find -exec make -f x.mk \;` is `make -f x.mk`,
  not make with a goal called `;`); where a word ends at a redirection operator glued to it is `separateGluedRedirections`;
  and a cluster read keeps the read verdict AFTER the cluster reader has added what the command does besides reading (the
  kubeconfig printed, a program run), except a read that goes to an API server named on the line or in the environment
  (`--server https://evil.test`, `KUBERNETES_MASTER=`) or with a kubeconfig the kernel cannot read: that sends the
  credentials where nobody vouched for, and keeps the advisory's refusal (`K8sEffect.unvouched`; in the ordinary mode it is
  ALLOW as it was, a recorded residual). `-o` of kubectl, oc, helm and minikube is the output format, not a file
  (`kubectl get pods -o yaml` was a repository write in the advisory). A word the data reader proves to be data
  (`git log -S "=>" --oneline`) is no longer taken for env's `-S` command string, and a word that is no verb of kubectl, oc or
  helm is a plugin the tool starts with everything after it, never a manual (`kubectl foo --help bar`).
- **A decision ends inside the hook's budget on any input** (closure audit 2026-10-01, wave 3, "time"). A sed script of seven hundred
  spaces followed by `git push origin main` is an absolute deny, and the scan that read the script backtracked for 66 to 105
  seconds before saying so; the host gives a hook thirty, and a hook that has not answered has not refused. The sed scanners
  (`w FILE`, `e CMD`, the `s///w` flag), eight matcher patterns (the awk/sed `e` command, the copy verbs of the runtime, hook and
  trust-store rules, the no-op builtins, the registry push, the credential mount) and four scans in the splitter and the path walk
  were quadratic or worse and are linear. A work budget (`authority/work-bound.ts`) ends what is left: text read, processes spawned
  and paths judged are paid for in units, the same units on every machine, and past the limit (10 million; the largest decision in the
  corpus spends about a nineteenth of it) the decision ends with an ASK whose reason is "too large to classify within the bound" - what
  was found before it is kept, so a DENY stays a DENY. One command larger than 32 KiB is not scanned but asks on its own, so the
  commands around it are still read, and a command nested deeper than the stack is an ASK instead of an exception. Visible change:
  a command (not a heredoc body) of more than 32 KiB, or one call that runs several dozen git commands or more, asks.
- **One reader of a git command line** (closure audit 2026-10-01, wave 3, "git"). `authority/git-invocation.ts` reads a git line by the
  canonical names of its options (taken from `git <verb> -h`: `switch --force-create` is `-C`, a long option is any unambiguous prefix, a
  cluster is each letter, a global option that takes a value no longer displaces the verb), judges configuration keys by one table of the
  keys git documents (`man.<tool>.path`, `browser.<tool>.path`, `sendemail.*`, `gpg.*.program` name programs; `author.*`, `committer.*`
  and `--config-env` are identity), reads the pathspecs of a checkout or restore from the parsed line (`git checkout HEAD -- .` is
  `git checkout .`), and treats a transport verb's repository operand as a read of the local path it denotes (`file://` URLs included).
  Visible changes: `git clone --config user.name=…` and `git -c author.name=… commit` ask (git.identity.override); `git stash push
  --include-untr` asks as `-u` does; a hyphenated git command no rule names (`git commit-graph write`, `git fetch-pack`, `git
  status-x`) asks instead of being read as the verb it begins with (the patterns of matchers.md are told it is another word; the
  readers that are keyed by the verb git has - the hooks it fires, the files it writes, `git checkout-index` among them - still see
  it), and `git remote-ext` is the `ext::` act; the repository's own configuration is what git reports as local (`--show-scope`),
  through as many includes as git follows (an include chain deeper than git's own limit makes git refuse, which is an ASK).
- **One recorder of what a shell line binds** (closure audit 2026-10-01, wave 3, "environment"). `authority/bindings.ts` answers which
  names a command binds - an assignment, `export` and its kin, `printf -v`, `read`, `mapfile`, `getopts`, a loop's variable, `let`, the
  `${NAME:=default}` expansion - and a quoted assignment word handed to `env` or `export` binds as the bare one does. `printf -v PATH …; ls`
  and `read EDITOR …; git commit` are gated as `PATH=… ls` is. The word `version` is a subcommand only after the tools that have one
  (`go`, `cargo`, `docker`, `kubectl`, `helm`, `terraform`, `gcloud`, `az`, `git lfs`, `poetry`, `uv`): `node version`, `make version` and
  `yarn version` are no longer read-only. A flag that selects the program npm runs scripts in asks whether or not the script is in the
  manifest, npm's scoped registry flag (`--@scope:registry`) is an endpoint like `--registry`, and awk's file options are read as getopt
  reads them (`gawk -Eevil.awk`, `-nievil.awk`).
- **One reader of where a command runs while the shell evaluates text; function bodies run at their call; a word the shell builds can undo a
  dry run; every exception is a coded verdict** (closure audit 2026-10-02, wave 6, shell structure: SH-1 … SH-6, RB-1, RB-4, RB-5).
  `echo $[$(git push origin main)]` ran the push at ALLOW: the splitter read the old arithmetic form `$[ … ]` up to its first `]` and
  swallowed it as inert text, while `$(( … ))` beside it had been given its commands. The same text ran in every place a builtin or the
  shell evaluates a word - `declare 'a[$(CMD)]=1'` (and `typeset`, `local`, `let`, `read`, `unset`, `printf -v`, `[[ … -eq … ]]`, `test -v`), a
  quoted subscript in an assignment or a `${a[…]}`, `(( … ))`, `for (( … ))`, zsh's `${(e)…}`, `mapfile -C CMD`, a variable the line filled
  with code and then evaluated (`x='a[$(CMD)]'; echo $((x))`, `eval "$x"`) - because a quote was read as protection from evaluation. One
  lexer (`shell-lexer.ts`) now finds where an expression ends and which spans are commands, one table (`evaluated-words.ts`, derived from
  the builtins of bash 3.2, bash 5.2 and zsh 5.9) says which words a builtin evaluates, and the splitter hands the commands over as
  segments of a subshell; the script reader's heredoc delimiter scan uses the same extent. A function body is read in the table of
  functions at its call: `git() { unset -f git; git "$@"; }; git push origin main` runs the real push (a name that anything in the unit
  removes is not proved bound inside a body; a body that names its parameters is read again with the call's words). A word the shell builds
  after the last dry-run flag - a command's output, a default, every argument - may be the flag that undoes it, so the dry run is not
  proved, for kubectl, oc, helm, git push / rm / mv, rsync, patch and the cloud CLIs; a plain variable in a name slot is still a name.
  A verb or an option's value of `git`, `kubectl`, `docker`, `psql` … is not a file name under the match directory of `find -execdir`.
  `evaluate()` never throws: any exception ends in an ASK with a typed code that keeps what was found before it, a glob component too long
  to compile is a gap, and the hook refuses a payload that is not an object, that names another event than the one registered
  (`"hook_event_name":"Stop"` on a PreToolUse hook answered `{}` with exit 0 and evaluated nothing), that nests past the stack or whose
  session id no file name holds, with `TARGET_UNCLASSIFIED` and exit 2. Visible change: a declaration, `read`, `unset`, `let` or
  `[[ -eq ]]` whose operand holds a command substitution in a subscript is read as the command; `find -execdir git status` and the like no
  longer ask; `xargs` is unchanged (it appends words from standard input, which can be options).
- **A project's overlay narrows, and is read as its author meant it** (closure audit 2026-10-01, wave 3, "overlay"). An overlay `command`
  rule is added beside the core's answer and the strictest wins (it was appended after every core rule under first-match-wins, so a rule
  for `make deploy` or `*.pem` never ran); a `path` or `url` rule is combined with the core's the same way. A `path` is read as a
  `.gitignore` line is: a name matches at any depth, `dir/**` and `dir/` are the directory and everything below it, `{a,b}` and `[Pp]`
  work, `~/` is the home directory and a leading `/` the filesystem; the Write and Edit tools are one rule; a bare file name that exists
  where a command runs is a path operand (`cat service-account.json`, `cd secrets && cat db.txt`); and a recursive read of a tree that
  holds a protected path (`grep -r x .` over `secrets/**`) reads it. A rule whose tool never asks about its field (`tool: Bash` with a
  `path`) is refused when the overlay is compiled. Removing an overlay rule from the working tree is a widening, held pending until a
  human accepts it. Visible change: an overlay that loaded with a rule that never ran now fails to compile and says which.
- **The time bound reaches the readers the other wave-3 branches added** (closure audit 2026-10-01, wave 3: the "git, environment, overlay,
  time" branch ported onto the carrier, option, database, container, cluster, make and proportionality readers). Measured on the merged
  tree, a decision that is not under the bound could still take seconds: thirty kilobytes of `{a,b}{a,b}…` took 27 seconds to be refused
  (every call of the brace expander reads the whole word, nine levels of recursion deep), `rm many/f?.txt` repeated fifteen hundred times
  over a directory of twenty thousand entries took 13 seconds (each word listed the directory again), the stages of a pipeline of ten
  thousand commands were listed in pairs, and a command that moves into a directory that is not there ten thousand times asked the disk
  each time. They are paid for in the same units now: the brace expander per call, a directory listing per entry (and read once per
  decision by the wildcard expander), the pairs of racing stages before they are listed, and the `stat` of a directory once per decision.
  A pattern of the segment rules that read a here-document or here-string (`<<<?|<\(`, in the runtime, harness, hook-config, credential and
  trust-store rules) parsed a run of `<` in as many ways as there are ways to write it as twos and threes - a hundred of them hung the
  hook - and has one parse now (`<<+(?!<)`), the same language. Visible changes: none for an ordinary command (the largest decision in
  the ordinary corpus spends 4% of the bound, the largest attack spelling 8%); `find -exec env EDITOR=x git commit \;` and `fd -x env
  VAR=x …` carry the assignment like `env EDITOR=x git commit` does (it was ALLOW); `git checkout-index` and `git format-patch` are read
  as the writes they are again, and a hyphenated git command is renamed for the patterns only, never for the readers keyed by the verb.
- **A body reaches the same readers as the command line it holds** (closure audit 2026-10-02, integration of the four waves; found by the
  corpus crossing every class with every producer). Two routes through a producer's body did not meet the readers a plain command line does.
  (1) The cycle guard identified a producer's pass by what it resolves to, and for a git hook that is the hooks directory and the verb: `env
  'EDITOR=/tmp/x' git commit` inside the pre-commit hook of `git commit` was "the same execution" as the commit that fired the hook, was
  cut off as a repeat and never asked about the environment it hands the command - ASK on the command line, ALLOW in the hook and in a
  lint-staged task. The environment a pass runs in is now part of which pass it is, for every producer (make's key always carried it): a
  second pass in another environment is read, a second pass in the same one is still a repeat. Visible change: a hook that runs the commit
  or checkout that fired it again with an assignment (a program-selecting name asks, as on the command line; any other name is a further
  pass that the analysis may not finish and then asks) asks; a hook that does not re-enter is as it was. (2) A make override carries a
  command, and the guard against `make -E` / `--eval` scanned the normalised words, in which `V="gawk -Eevil.awk d.txt"` holds a word
  spelled like make's option: the command line was called "supplied on stdin", the makefile unreadable, and the program file the override
  names was never read (`grep -E` in an override asked too). make's command line has one reader, which reads the words make is handed.
- **One reader of "is this name production", and the cluster, container and option readers that disagreed with it** (closure audit 2026-10-02,
  wave 5: independent findings AUTH-1, K8-01 to K8-06, CT-01 to CT-08, OT-01). The seven reviewers of what the five waves changed found the
  repository's old cause again: one dimension, several readers, a fix at one spelling.
  (1) *Production names.* A marker is a WORD of a name (`hasProductionMarker`, `control-plane/local-targets.ts`): the name is cut at every
  non-alphanumeric character, between a letter and a digit and where the case changes, so `prd1`, `prod01`, `live2`, `eksProd` and `aks-prd1-weu` are
  production - under an accepted wildcard (`aks-*`) they were ALLOW - and `products`, `product-catalog`, `reproduce` and `liveness` are not. Four
  matchers in `matchers.md` read the letters `prod` anywhere in a context, namespace or kubeconfig (`kubectl --context minikube -n products rollout
  restart` was an ABSOLUTE deny) and the word `secrets` anywhere on a production line (a pod called `secrets-api`, `auth can-i get secrets`): they are
  gone, the target model answers (k8s.ts), a production Helm release lands on `production.helm.mutate` and the compiler lists the landing capabilities
  as pre-denied, so the authority diff reports no protection removed. A namespace, a user or a kubeconfig path is still read by the same word
  reader; only the type position of `get`/`describe` holds a resource type. `preprod` joins the kernel's `production_markers`.
  (2) *Container engines.* The variables that select an engine are one table (`CONTAINER_ENGINE_ENV`, containers.ts) read by the resolver and
  derived into the normalizer's list: `CONTAINER_CONNECTION`, `CONTAINERD_ADDRESS` and the variables that point at the file that holds the choice
  (`CONTAINERS_CONF`, `PODMAN_CONNECTIONS_CONF`, `BUILDX_CONFIG`, `NERDCTL_TOML`, `DOCKER_CERT_PATH`, `CONTAINER_SSHKEY`, ...) were read by neither.
  A socket (`unix://`, `npipe://`, `fd://`, a path) is local unless its name says production. `--pull` of `run`/`create` takes a value.
  `save`, `history` and `top` print what `inspect` and `logs` print and are no longer reads of another engine. `docker logout` is an ASK, not an
  absolute refusal; `docker init`, `scout quickview|cves|...`, `model ls|status|...` and `desktop status|version|logs` are modelled reads and the rest
  of those plugins still ask. `docker cp`, `podman cp`, `compose cp` and `kubectl cp` out of a container are writes to their destination, judged as
  `cp` is. The bind-mount matcher is gone (its `/:` matched every source with a trailing slash); the path judge reads the real source.
  (3) *Dockerfiles.* What a RUN line does to a PATH is the image's, wherever in the body it is found (a redirection, an output flag, an operand, a
  script the line runs): `RUN CGO_ENABLED=0 go build -o /app/server .` and `RUN echo x > /etc/apt/sources.list.d/x.list` no longer deny; `rm`,
  dependency installs (`npm ci`, `pip install`, `apt-get install`, `apk add`) and the programs the new `image_setup` vocabulary list names
  (`apt-get update`, `useradd`, `chown`) are the image's own work. Commands that reach beyond the image - a push, a fetch piped into a shell, an
  upload, a cloud call, an unknown program - are classified as before. `CGO_ENABLED=0|1` is a switch, not a program.
  (4) *Clusters.* A repeated `--kubeconfig` is a string option: each file is read as the world it could be and the strictest decides (`KUBECONFIG`
  stays a merged list); `--kuberc` is read - a default for `context`, `cluster`, `user`, `server`, `namespace` or an option nobody listed asks;
  the names in the place of a resource (`deploy/$APP`, `pod/$P`, the pod side of `cp`) are data, not directories built at run time; helm 4's
  `--color`, `--colour` and `--content-cache` are options; a JSON kubeconfig is read; `kubernetes.docker.internal` and the IPv6, mapped, upper-case
  and trailing-dot spellings of the loopback are local (`[::1]evil` is no URL); `kubectl kuberc`, `oc`, `podman-compose`, `lima` and `buildah` are
  known to the vocabulary.
  (5) *Program options.* An option names a program for the TOOL that has it (`program-operands.ts`): `-B` is gcc's directory of sub-programs and
  grep's lines of context, `-ldflags` is a flag list read by what the flags are (`-s -w -X` are ordinary, `-extld` is a program), `-e sh` is a pattern
  to grep, and a compiler with a version in its name is the compiler. `grep -B 3`, `make -B` and `go build -ldflags "-s -w"` no longer ask.
  Tests: `packages/kernel/test/closure-clusters2.test.ts`, with differentials against the real kubectl, docker and helm that skip when the tool is absent.
- **One reader of the path a word denotes, and the operands that are not words** (closure audit 2026-10-02, wave 6, "paths": findings PA-01
  to PA-17 of the seven independent reviewers). `pathCandidates` was asked about the words of a command and not about what it does not model,
  and the reviewers' filesystem oracle (a sandbox of canaries and links, every command run for real) found each of those. (1) The operand of
  `xargs`, of a read loop and of `$(...)` is another command's output: `echo ~/.ssh/id_rsa | xargs cat` printed a key at ALLOW once the words
  `echo` prints were masked as data. A producer whose output is known (`echo`, `printf`, a here-string, `cat` of a file the line may read)
  hands its words to the consumer, which is judged as the command it is with them in place; one that lists paths (`find`, `ls`, `git ls-files`)
  adds nothing; any other feeding a command that opens its operands as files asks (`dataflow.ts`, `flow.ts`). (2) The normalizer joins word
  VALUES back into text that the path readers tokenize again, so `touch 'a"b/pre-commit'` was read as `ab/pre-commit` while the shell opened
  a link called `a"b` into `.git/hooks`: the path readers get the words the shell passed (`words.ts`), a name as typed (`$PWD`, `~+`, `{a,b}`
  quoted) is one more reading of a word, a dashed word is a name after `--` or when it exists, and a quoted `&` or `$` begins a name. (3)
  A wildcard is the names it matches: a bare one is an operand when it matches (`cat *.pem` over an overlay's `*.pem`), one in a protected
  directory component of a destination is that destination (`touch .har?ess/generated/x` was an ASK where the spelled-out path is an absolute
  refusal), and `rm *.log` is an ordinary write (it asked); one that matches nothing is the name it spells, and asks where the line makes names
  or the pattern could be a protected one. (4) A directory is its contents for the rules that describe contents (`cp -R ~/./.aws out`, `grep -r .
  $HOME//.ssh`, `ls lssh` over a link), and the credential directories are compared the way the volume compares names (`Grep ~/.SSH`). (5) A
  protected directory that is itself a link is the place it leads to (`.claude -> shared/claude`, a dotfile manager's `~/.ssh`), a `.git`
  that is a file has its hooks and configuration where it says (`aliases.ts`), and a copy that keeps a link to a governed tree makes one
  (`cp -a lgen nl && echo x > nl/x`; `links.ts`). (6) The standard input under another name is the file the line opened for input.
  (7) `--serialize-diagnostics`, `-Wl,-Map=`, `mktemp` and the other options that create files are in the option tables. (8) The codex
  adapter: only the host's own shell (a bare name or a system path) is its wrapper, the `shell`, `login`, `env` and directory fields of a
  call are folded into the line, a JSON text that is also a script is judged as both, and a shell call carrying a field nobody read - an
  escalation request among them - asks (`host-fields.ts`). Visible changes: `rm *.log`, `chmod +x scripts/*.sh` and `mv *.log logs/` no longer
  ask; a substitution whose output is known (`touch "$(echo .harness/runtime/pin.json)"`) is the refusal the path it prints is; `xargs`
  and `$(...)` fed by a command that is neither listed nor readable ask where they were ALLOW; a seeded filesystem oracle is a permanent test.
  The oracle's further seeds closed five more spellings at the same readers: a `cd` word is read as typed as well (`cd '~+'/..` is the directory
  called `~+`), a name with a blank and an angle bracket in one word is one name, `..` after a wildcard component goes up from where the matched
  name leads, a destination a tool's table finds is read when its variables are known (`cc --serialize-diagnostics $HOME/x`), and `mktemp -u`
  creates nothing in the directory `-p` names either.
  Joined with the other wave-6 readers, and read again with the ordinary-development differential (7,471 commands, judged on main, on this
  branch alone and on the join): the route a link opens into a governed tree has ONE reader for `ln -s` and for a copy that keeps links (a
  copy keeps no exemption for a link to the checkout itself); a database client's statement is data, not a name with blanks; the value of a
  location variable (`GOPATH=$HOME/go`) is read as expanded, not as the directory called `$HOME`; and four spellings that the branch alone
  made ask or refuse where main did not are repaired - a `$` the shell does not expand, inside a string with a blank and a slash (`git commit
  -m 'fix $HOME in a/b'`), is a character and no longer a name built at run time; the script of `sed` is a program, so a piece of it that
  looks like a path (`/^$/d`, `.*//`, `/start/,/end/p`) is neither an operand nor a destination (`sed -i 's/ .*//' f` was an absolute refusal
  and `sed -n '/a/,/b/p' f` asked); a wildcard that is only a piece of a string (`perl -pi -e 's/".*"/x/'`) asks, as it did before wildcard
  destinations were enumerated; a parenthesis is a glob group only with its partner in the same segment (`python -c 'print("a/*")'` is a
  program text); and an unenumerable segment (`@(a|b)`) bounds a wildcard only where there is a directory to match it in.
- **The authority path is robust, and three properties are enforced by tests that read the code** (closure audit 2026-10-02, wave 5,
  independent reviews "authority" and "robust": AUTH-2..12, AUTH-14, RB-2, RB-3, RB-6, RB-7; `closure-authority2.test.ts`). The policy cache is
  derived state: a file that cannot be read (empty, truncated, a conflict marker, a directory) is absent and regenerated, and a cache written
  by an earlier build is read by `ego doctor`, `ego check` and `ego authority diff` with the same tolerance (AUTH-2, AUTH-10). "Is this table
  wider" has ONE description (`authority/table-diff.ts`, `AUTHORITY_TABLE_FIELDS`: every field of a compiled table is named in it, as authority,
  derived or provenance, and a field the description does not name does not compile); the release gate, the pending-widening gate, `ego authority
  diff` and the AUTHORITY DIFF `ego init` prints are one function over it, and the gate is its widening subset (AUTH-3). It now sees what the
  hand-written predicates missed: a reordered matcher, a widened vocabulary, a relaxed profile requirement, a changed default mode. The table
  hash no longer carries a path of the machine (AUTH-11). **A widening is accepted on the machine of the person who read it**: what a person
  accepts is the layer files and the widening lines they were shown, re-verified when the acceptance is written (AUTH-4), and the cache is
  sealed with an HMAC whose key lives in `EGO_HOME` (`policy-seal.key`, mode 0600, made by `ego init`), so a cache that a teammate's commit or
  a copied directory brings in - internally perfect, recording an acceptance nobody gave on this machine - is read as absent (AUTH-5).
  **Upgrade note: the first `ego init` on each machine after this release re-accepts the widenings in the layer files**, because the caches
  written before it are not sealed; until then they are pending and the narrow policy applies. A tool call that runs `ego init` or `ego sync`
  asks (new capability `ego.policy.accept`), as `ego upgrade` and `ego skills install` do (their grant rows lifted nothing real: the matchers
  were missing or unanchored), `sudo -i`/`-s`/`-e`/`su`/`doas -s` ask, and `dropdb` is a bounded client like `psql` (AUTH-7). A refusal names the
  rule that set the verdict, not a mode that has no override for the cell (`cellOrigins`; AUTH-8), and a mode may only narrow an ADMIN_GOVERNED
  capability: BENCHMARK and PRODUCTION_ADVISORY keep refusing push, PR creation and API writes once an organization enables them (AUTH-9;
  `ego authority diff` now reads `STANDARD 2/4`). An approval whose endpoint holds a malformed percent escape is presented as text, not thrown
  (AUTH-12). Every capability has a producer or is listed as RESERVED with the reason, in a test (AUTH-14).
  Robustness: the decision is made outside the session lock and the locked section keeps it when the grants and the mode are unchanged (RB-2:
  forty parallel tool calls of one session, every counter exact); the duration budget counts activity, with an idle gap capped at thirty
  minutes, the retry key is the whole step, and a failure is read from every field a host puts one in (RB-3); a Codex payload nests its argv,
  environment and working directory under `action`, and is the same command however it is nested (RB-6); and the work units a decision spends
  depend on the command and the declared configuration only - not on HOME, the temporary directory, the checkout depth or whether the process
  has decided the command before (RB-7).
  **Channel integrity** (AUTH-6, general property II): text from a layer file, a repository file, a command line or a tool input reaches a
  person or a model only as quoted data - `shownText` (`util/shown-text.ts`): one line, `\` and `"` escaped, every control, bidirectional and
  invisible character written as an escape, bounded at 120 characters with a count. The sources are declared `@untrusted` in the code; the
  hook adapters and the CLI put every string through `terminalSafe`; a bounded-command entry that is not a command name is not taken, and
  says so; and a structural test fails when code under `packages/*/src` builds a message from one of those sources without the function.
  **Bounded work** (general property I): `test/support/pathological.ts` has one seeded generator per reader family (50 of them; five name the
  readers of the operand flow and of the link-keeping copy, merged after the harness was written), and the test
  asserts at growing sizes that a decision is a verdict, never a throw, paid for in proportion to its input, and an ASK that says "too large to
  classify within the bound" when the bound is reached. It found two readers that paid nothing: the copies a nested `$(…)` makes (three
  kilobytes took two and a half seconds at the bound) and every read of a workspace file (a command naming two thousand different 60 KB
  scripts read 120 MB for nothing); both are charged, and so is the repository config. Visible changes: none for an ordinary command (the
  verdicts of the ordinary corpus are unchanged, and its largest decision is still a small part of the bound).
  **Ported onto the readers of waves 5 and 6** (the three places where the two lines of work answered one question twice are one reader each):
  a Codex shell call is read by ONE function, flat or nested under `action`, with the fields of both - `shell` and `login`, the four spellings of
  the working directory (the same fact under two names is one directory), `env` and `user` - and the environment is exported BEFORE the
  directory change, so the whole line is judged in the directory it runs in; the vocabulary of the table is described list by list, typed over
  every list (the image-setup list that the container closure added is read by the diff, the init diff and the pending-widening gate, and an
  unaccepted addition to it is dropped by the clamp); and what a decision spends no longer depends on the machine in three more places that
  the operand-flow and the contents probe added: the directory a producer's words name (HOME and the working directory are one character
  while the producer is read, and HOME is written as `~` in the line the consumer is judged as), the contents probe of a directory the
  machine keeps for itself (HOME or the temporary directory, there or not), and the canonical form of a path that has already been walked.
  One more decode of a percent escape (the location a tool's own variable names) is the one that cannot throw.
