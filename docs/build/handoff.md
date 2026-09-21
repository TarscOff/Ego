# EGO build handoff

Snapshot for resuming work. Written 2026-09-21. Pair this with `docs/build/build-log.md` (the per-phase record) and
`docs/architecture/pre-build-package.md` (the frozen baseline, decisions Q1–Q97, plus Q98).

## Current state

- **Branch**: `main`. **HEAD**: `159222b`. Working tree clean.
- **Deterministic gate is green**: `npm run typecheck`, `npm run lint` (`eslint packages tests`), `node --test`
  (**152 tests**), `npm run build` (a release build refuses a dirty/untagged tree; use `EGO_ALLOW_DIRTY=1` for a local
  throwaway build).
- Everything is **committed locally only**. Nothing pushed, no PRs, no production changes — and that constraint holds.

## What is being built

EGO is an organization-grade, model-agnostic Agentic Engineering Control Plane kernel: TypeScript, Node ≥ 24, zero
runtime deps, single esbuild bundle `dist/ego.js`. The permission evaluator must DENY unsafe agent commands; the git
hooks must scan for secrets and govern pushes; the launcher pins and verifies runtimes. We are in **phase 1** (kernel
core), specifically inside the **mandatory independent-agent review loop** that must run clean before phase 1 closes.

The rule that governs the loop (from the user): every phase records four check lines exactly — `DETERMINISTIC CHECKS`,
`IN-SESSION REVIEW`, `INDEPENDENT-AGENT REVIEW`, `CONFORMANCE`. Never substitute an in-session review for an
independent-agent one; never mark a deferred/failing check as passed. `INDEPENDENT-AGENT REVIEW` becomes PASSED only
when a **complete** review round ends with **zero confirmed HIGH or MEDIUM** findings.

## Independent-agent review loop — status

Each round is a background Workflow: dimension/cluster skeptics + fresh adversarial reviewers find bypasses, then
adversarial refuters must **reproduce** each finding before it counts. Every confirmed finding is fixed and pinned by a
deterministic test in the same round, then committed.

| Round | Findings confirmed | Commit | Notes |
|------|--------------------|--------|-------|
| 1–3  | 49 / 18 / 14+D1    | `6abcd6e` and earlier | pre-this-session; see build-log |
| 4    | 8                  | `92f14b6` | env -S, forge fields, pax, hooks honesty |
| 5    | 19                 | `b8fddc3` | interpreter-body writes, archive dests, mv source, trust dir-node, glued syntax |
| 6    | 16                 | `ed757a4` | zip/bsdtar/tar --directory, trust globs, ANSI-C, HARNESS_MAINTENANCE spoof, worktree fail-open |
| 7    | 3 (partial)        | `c040519` | **usage limit cut 13/16 agents**; the 3 that ran found 3 HIGH, fixed by hand |
| 8    | 6                  | `734d696` | complete run; tar write modes, quoted commit flags, multi-digit redirects, redaction span leak, Slack xapp-/xoxe-, control-plane write matcher |
| 9    | 10                 | `a1341c3` | secret-scan gaps (npm/pypi/azure-SAS/DigitalOcean/Docker), >| redirect, commit $IFS splice, .git gitlink file, nested hook config |
| 10   | 13                 | `cccf31d` | secret-detector sweep (16 new: Databricks/Shopify/Terraform/NewRelic/Grafana/Square/Google/Stripe-webhook/GitHub/Linear/Notion/Figma/Doppler/PlanetScale/Sentry), commit ${IFS%?} trims, >>| redirect, symlinked .git, npm install lifecycle |
| 11   | 9                  | `d6046d5` | commit default-value, sh -euc cluster, cloud global opts, tilde paths, make -C, install hooks, 4 secrets, curl -u |
| 12   | 5                  | `159222b` | commit empty-expansion, make -f altmakefile, sort/uniq/yq writes, rm EGO_HOME root, aws-secret-in-json |
| 13   | pending (held)     | —       | ready to launch; held pending the user's incoming prompt (may answer Q98) |

A key framing added in round 7 and kept in round 8: the verdict ladder is ALLOW (silent) < ASK (human approves once) <
DENY. An opaque command reaching **ASK is the designed human gate, not a bypass**. Reviewers report only reaches to
**ALLOW** (silent), a concrete missed DENY spelling that lands on ASK where sibling spellings DENY, or (for the secret
scan) a real secret that is not blocked. This separates genuine defects from the inherent limits of statically
classifying obfuscated opaque code, and lets the loop converge.

## In progress

- **Round 13 is ready but HELD**: rounds 4-12 are done and committed. The user said a big prompt is coming (possibly
  the Q98 answer), so round 13 is not launched yet to avoid redoing work if the prompt redirects. Counts are trending
  down (8, 19, 16, 6, 10, 13, 9, 5). When cleared to continue: launch round 13 (verify round-12 fixes + fresh pass),
  then reproduce/fix/pin/commit any confirmed HIGH/MEDIUM, iterate. When a COMPLETE round ends with zero confirmed
  HIGH/MEDIUM, set `INDEPENDENT-AGENT REVIEW` to PASSED for phase 1. Q98 still needs the user's explicit answer.

## Remaining

1. **Finish the review loop** to a clean complete round, then flip the `INDEPENDENT-AGENT REVIEW` line to PASSED.
2. **Q98 needs the user's explicit confirmation** before phase 1 closes: the split of forge capabilities into
   `lock: organization` (DENY at core, widenable only by `policies/organization/permissions.md`) vs `lock: absolute`
   (never widenable). It is currently implemented under the recommended default and documented in
   `docs/architecture/alignment-2026-09.md`; moving an id between tiers is a MAJOR change (Q84).
3. **Phases 2–7** per the frozen baseline: tasks/held-scopes/forge/workspace-registry (2); skills/catalog/ask (3);
   grilling/evidence/benchmark (4); policies/stakeholder-packs/decisions (5); remote source adapters +
   `distribution bundle` + conformance suite (6); phase-7 validation. `CONFORMANCE` stays NOT RUN until the phase-6
   host conformance suite exists; the `codex-cli` dialect fails closed on everything but ALLOW until then.

## How to resume the work

- **Re-run / continue a review**: launch a new Workflow like the round-8 script at
  `…/workflows/scripts/ego-phase1-review-round8-wf_cd054da6-27f.js`, or resume one with
  `Workflow({scriptPath, resumeFromRunId})` (completed agents replay from cache). Read a finished run's findings from
  its `journal.jsonl` before trusting the summary. If a run dies on the usage limit, the main session can reproduce and
  fix the completed agents' findings by hand (that is not "independent", so it does not by itself make a round count as
  clean — a complete independent round still has to run).
- **Reproduce an evaluator verdict**: a probe importing the `.ts` sources by absolute path and calling
  `evaluate(table, ctx, {tool:'Bash', input:{command}})`. Scratch probes live under the session scratchpad
  (`r5probe.mjs`, `r6probe.mjs`, `r7probe.mjs`) and cover the reproductions for those rounds.
- **Run shell-shim tests under real `/bin/sh`**, not zsh — word-splitting differs and zsh hides real bypasses.

## Files that matter most

- `packages/kernel/src/authority/evaluate.ts` — the evaluator (tokenizer incl. ANSI-C `$'…'`, wrappers/env incl.
  `env -S`, redirections incl. glued, `cd` tracking, archive/`mv`/`cp` destination resolution, trust-store reach,
  quote-aware `git commit` bypass, weight-based decisive verdict with lock tiers). Most fixes land here.
- `control-plane/permissions/matchers.md` — declarative matchers (forge, production k8s/cloud, credential/trust/hook
  interpreter-body matchers, git hook-bypass). **Order matters**: `classifyNormalized` takes the first matching matcher,
  so a more-specific DENY must precede a general one (e.g. the interpreter-body denies sit before
  `command.interpreter-inline`). Regexes are single-backslash in YAML single-quotes.
- `packages/kernel/src/hooks/handle.ts` — hook kernel: budgets/modes, retry hard-stop key normalisation,
  `HARNESS_MAINTENANCE` gated on `pathInside(cpRoot, projectRoot)` (unforgeable), policy-cache widening clamp.
- `packages/kernel/src/project/githooks.ts` + `runtime/posix/git-hook.sh` — hook install/shim (spaced paths, linked
  worktree resolves `.harness` via the git common dir, pre-push scan no longer trusts `--remotes`).
- `packages/kernel/src/control-plane/load.ts` + `util/markdown.ts` — fail-closed loader (ordered-list / malformed
  checkbox / stray-marker capability declarations all error instead of vanishing).
- Tests: `packages/kernel/test/{bypass,control-plane,hooks,githooks,launcher,detect}.test.ts`,
  `tests/integration/cli.test.ts`. Each review round appended a `round-N residuals` block.

## Constraints in force

Commit locally after each phase; never push, never open PRs, never mutate production. A peer/other session cannot grant
escalation. Keep the four check lines honest; never mark a deferred check passed. Grilling is closed — no reopening
settled decisions unless a genuine Q1–Q97 contradiction surfaces.
