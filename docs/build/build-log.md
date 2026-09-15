# Build log

One entry per phase (baseline section M, item 20). Every entry records the four check lines exactly as they stand:
`DETERMINISTIC CHECKS`, `IN-SESSION REVIEW`, `INDEPENDENT-AGENT REVIEW`, `CONFORMANCE`. An in-session review never
substitutes for an independent-agent review; a deferred check is never marked passed.

## Phase 0 — repository skeleton, toolchain, frozen baseline (commit b9434b3, 2026-09-11)

- DETERMINISTIC CHECKS: PASSED (typecheck, lint, prettier config)
- IN-SESSION REVIEW: PASSED
- INDEPENDENT-AGENT REVIEW: DEFERRED_BUDGET (subagent budget exhausted at the time; re-run folded into the phase 1 review below)
- CONFORMANCE: NOT RUN (nothing to conform yet)

## Phase 1 — kernel core (2026-09-14 → 2026-09-15)

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
  double verification, conformance and build-log audit): the first two launches were cut off by the session limit
  and then by exhausted usage credits (1 of 55 agents completed: the Codex dialect fix verified, with two missing
  pinning tests and a host-matrix note, both added). Relaunched on 2026-09-15; results recorded here when it completes.
- **Incident during round 2** (found 2026-09-15 when the checkpoint commit failed): EGO git hooks had been written
  into this repository's own `.git/hooks` at 02:17, pointing at a shim that does not exist here, so every commit
  failed. No pre-existing hook was displaced. Cause: `installGitHooks` accepted a directory that was not a git
  toplevel, and git resolved the hooks path upward to the enclosing repository. The stray hooks were moved to the
  session scratchpad, and `installGitHooks` now refuses any directory that is not the top level of its own
  repository (pinned by `packages/kernel/test/githooks.test.ts`).

### Check lines

- DETERMINISTIC CHECKS: PASSED — `npm run typecheck`, `npm run lint` (packages and tests), `node --test` (112 tests),
  `npm run build` (dist/ego.js, development identity `-dev.<sha>.dirty` while the tree is dirty). Hook latency: the
  in-process kernel path is pinned under 60 ms by `hooks.test.ts` (K26); process wall-clock including Node start-up
  is measured by the conformance audit and reported as a number, not claimed against the kernel budget.
- IN-SESSION REVIEW: PASSED — smoke-tested init → hooks → status → check → doctor → delegation on temporary
  repositories, and every round-1/round-2 finding reproduced before being fixed.
- INDEPENDENT-AGENT REVIEW: IN PROGRESS — rounds 1 and 2 recorded above; round 3 (verification of the round-2
  residual fixes plus a fresh pass) pending. This line becomes PASSED only when a round ends with no confirmed HIGH
  or MEDIUM finding, and FAILED otherwise; it is never set from an in-session review.
- CONFORMANCE: NOT RUN — the host conformance suite (real Claude Code and Codex CLI hook semantics, permission
  modes, managed tier, prompt-hook caller marker) is a phase 6 deliverable; `claude-code` capabilities marked
  SUPPORTED in the host matrix rest on the pre-build verification recorded in the baseline (section C), `codex-cli`
  capabilities are UNVERIFIED and the Codex dialect fails closed on everything but ALLOW.
