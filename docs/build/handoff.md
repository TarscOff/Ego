# EGO build handoff

Snapshot for resuming work. Written 2026-10-07 (replaces the 2026-09-21 snapshot). Pair this with
`docs/build/build-log.md` (the per-phase record; the Phase-1 closure record is its last section),
`docs/build/phase-1-handoff.md` (the Phase-1 completion receipt) and `docs/architecture/pre-build-package.md` (the
frozen baseline, decisions Q1–Q97, plus Q98).

## Current state

- **Branch**: `main`. **HEAD**: the docs commit on top of `19cca14` and the r11-122 fix. Working tree clean. Everything is **committed locally only**: nothing
  pushed, no PRs, no production changes, and there is no remote for this repository yet.
- **Phase 1 is CLOSED (2026-10-07)** under the exit criterion the product owner amended on 2026-10-01
  (`docs/architecture/phase-1-taxonomy.md`). The original criterion was not met and was replaced; every check line
  says so. CONFORMANCE stays NOT RUN until phase 6.
- **Deterministic gate**: typecheck, lint and every touched test file pass on `19cca14`+; the full cold validation (clean clone, suite twice, release build) was running when the sitting was cut off - read its log (named in the build log) before calling DETERMINISTIC CHECKS passed. `npm test` takes about 25 minutes.
- **Known open items are recorded, not hidden**: `docs/architecture/phase-1-findings-register.md` (37 OPEN rows with a
  disposition each, 28 unreplayable review-7 rows) and `docs/architecture/phase-1-residuals.md` (the reasoning).

## What is being built

EGO is an organization-grade, model-agnostic Agentic Engineering Control Plane kernel: TypeScript, Node ≥ 24, zero
runtime deps, single esbuild bundle `dist/ego.js`. Phase 1 delivered the kernel core: the control-plane loader and
compiler, the authority evaluator (`packages/kernel/src/authority/`, 42 modules, one reader per dimension), the hook
kernel with the `claude-code` and `codex-cli` dialects, git hooks, the launcher and runtime, the policy cache with a
human-accepted widening gate and a seal, the Q98 vocabulary (`doctor`, `capabilities`, `explain`, `authority diff`),
and the local-target registry with `ego init` flags.

## Next: Phase 2 and the GitHub tickets

1. **Issue #16 leftovers**: the interactive `ego init` local-target wizard (flags only today); receipts (#10).
2. **Phase 2 per the baseline**: tasks, held scopes, forge, workspace registry, the MCP trust resolver; the
   Jira/Confluence/DOCX adapters when their phase arrives.
3. **The 25 recorded MUST_FIX rows** of the register, by root cause (its "Root causes" table names the single reader
   that would close each; RC-MODE — the mode-narrowing reader — is the largest group). None is above MEDIUM. Do not
   reopen the Phase-1 review loop for them: a new finding is an instance to record or a cheap pin.
4. **Issue #26** (containment) owns the residual: the 8 CONTAINMENT_DEPENDENCY rows and the stated boundary.
5. The owner may post the paste-ready text in `docs/build/phase-1-handoff.md` to issues #1 and #26. Nothing was
   posted by the build.

## How to resume the work

- **Re-measure the findings register**: `node --experimental-strip-types .probe/replay.ts r7 r8 r9 r10 r11 sa9 sa10`,
  then `node .probe/build.mjs && node .probe/mkmd.mjs && node .probe/mkresid2.mjs && python3 .probe/splice2.py`.
  `.probe/` is gitignored scaffolding that lives only in this working tree (its scripts are also in the session
  scratchpad, `register-harness/`); if it is gone, the register is still the record and the replay inputs are the
  `*-findings.json` files it names.
- **Reproduce an evaluator verdict**: `node --experimental-strip-types .probe/probe.ts '<command>' ['{"file": "…"}']`
  prints the verdict and every capability hit for a fresh fixture workspace; `.probe/tool.ts` does the same for a
  structured tool input, `.probe/profile.ts` for a profile × mode.
- **Run the suite**: `npm test` (about 25 minutes; the corpus cross-product dominates); one file with
  `node --test <file>`. Typecheck `npm run typecheck`, lint `npm run lint`, dev build `npm run build`; the release
  build (`EGO_RELEASE_BUILD=1 npm run build`) refuses a dirty or untagged tree.
- **Cold validation** (what the closure ran): a clean clone, a fresh `TMPDIR`, no `~/.ego`, `npm ci`, typecheck,
  lint, dev build, the suite in parallel and with `--test-concurrency=1`, then the release build against a throwaway
  tag in the clone. The script is in the session scratchpad (`cold-validate.sh`).
- **Run shell-shim tests under real `/bin/sh`**, not zsh — word-splitting differs and zsh hides real bypasses.
- **Independent reviews** were run as background Workflows; the last script is
  `…/workflows/scripts/phase1-exit-review-wave8.js` in the session's workflows directory. Read a finished run's
  `journal.jsonl` before trusting its summary.

## Files that matter most

- `packages/kernel/src/authority/evaluate.ts` (~16,700 lines) — the evaluator; the readers it used to hold are now
  modules beside it: `paths.ts`, `carriers.ts`, `options.ts`, `tools.ts`, `k8s.ts`, `containers.ts`, `make*.ts`,
  `shell-lexer.ts`, `evaluated-words.ts`, `dataflow.ts`, `db-options.ts`, `sql-lex.ts`, `work-bound.ts`,
  `reasons.ts`, `vocabulary.ts`, `describe.ts`, `approval.ts`, `compile.ts`.
- `control-plane/permissions/matchers.md` — declarative matchers; first match wins, so a specific DENY precedes a
  general rule; a destination-only matcher is `additive`.
- `packages/kernel/src/policy/cache.ts` — the policy cache: seal, pending widenings (a removed narrowing is one),
  `clampToBaseline`.
- `packages/kernel/src/hooks/handle.ts` — the hook kernel: budgets, retry hard stop, the pre-promotion gate
  (reads only before signed-release trust), fail-closed error paths.
- `packages/kernel/src/util/shown-text.ts` — the channel boundary (`shownText`, `terminalSafe`).
- `packages/kernel/test/support/corpus.ts` — the generated cross-product (classes × transformations × producers,
  the ordinary corpus and `EXPECTED_GATES`); `closure-*.test.ts` and their oracles under `test/support/`.
- `docs/architecture/phase-1-taxonomy.md`, `phase-1-findings-register.md`, `phase-1-residuals.md`,
  `security-model.md` — what is claimed and what is not.

## Constraints in force

Commit locally after each phase; never push, never open PRs, never mutate production. Keep the four check lines
honest; never mark a deferred check passed; an in-session review never substitutes for an independent one. The
baseline is frozen — no reopening settled decisions unless a genuine Q1–Q97 contradiction surfaces. Reports to the
owner are short and in plain French; decide, then say what was decided.
