# Phase 1 — handoff (2026-09-30)

> This is the homogeneous completion receipt (baseline section G) for the Phase-1 stabilization sitting that followed exit
> review 10. **Phase 1 is NOT closed.** The reasons, and the decision that only the product owner can take, are at the top.

## Status

| | |
|---|---|
| **PHASE 1** | **OPEN.** Not closed, and not closable by the current exit criterion — see "The decision". |
| DETERMINISTIC CHECKS | PASSED for HEAD: typecheck, lint, 274/274 tests (two of the four earlier full runs found regressions that were then fixed). Not re-run: a cold validation from a clean tree with `rm -rf ~/.ego` and a release build. |
| IN-SESSION REVIEW | PASSED (probes against bash, zsh and GNU make 3.81 for the claims that depend on them). |
| INDEPENDENT-AGENT REVIEW | **FAILED** — exit review 11: 258 confirmed findings, 209 unauthorized ALLOW (16 CRITICAL), zero new classes. About thirty fixed; ~225 OPEN by cause. |
| CONFORMANCE | NOT RUN — a phase 6 deliverable; unchanged. |

## The decision (OPEN — not taken by me)

Twelve reviews in a row have added **no architectural class** (the taxonomy of eleven is closed, and each class is enforced as a
general property over a generated cross-product, 40,452 combinations, which has itself found defects no reviewer reported).
The **instance** count has not converged: 187 → 136 → 190 → 121 → **258**. Each round closes exactly the set it was shown, and
the next fresh review — new lenses, new budget — finds a set of the same size or larger.

The cause is structural, not a matter of effort: the kernel **allows by default and denies by pattern**, so every spelling nobody
listed (of a shell, and of ~200 CLIs) is an unauthorized ALLOW. The exit criterion "a fresh review finds no unauthorized ALLOW"
is a claim about an unbounded set. Options, all recorded in `docs/architecture/phase-1-residuals.md`:

1. **Amend the criterion** to the one `docs/architecture/phase-1-taxonomy.md` already states — class closure, a generated
   cross-product that holds, every KNOWN finding closed or recorded — and close Phase 1 with the residual stated as a
   **containment dependency** (issue #26: the classifier is defense in depth; the boundary is an OS sandbox). Cheapest, and the
   only one the data supports as reachable.
2. **Invert the default on the highest-risk surfaces**: ALLOW only a short positive list of command shapes with strict grammars
   (a SQL read is now a grammar, not a blocklist), ASK for everything else. The unauthorized-ALLOW set becomes bounded by
   construction; the price is proportionality (ordinary commands outside the list ask until added).
3. **Keep the loop.** ~40M subagent tokens per fresh review, ~1 hour wall-clock for it, several hours of fixing; expect ~200 more.

A second, smaller OPEN decision: is a plain `SELECT` against a production database a read (ASK) or a mutation-capable statement
(absolute DENY)? Today it is DENY; the reviewers expect ASK. Not decided.

## Outcome

Since exit review 10 (HEAD `339c76b` → `f993e8a`, 18 local commits): the 179 findings of review 10, the 11 more that freezing them
into the corpus found, the 121 that a self-attack on those fixes found, and ~30 of the 258 of review 11 are closed. Two of my
own claims were wrong and are corrected in the documents that stated them (GNU make's target-specific variable; `help` as a
trailing word for git).

## What changed (by cause, not by spelling)

- **One reader per dimension.** Two or three pieces of code had decided each of: is this a help probe (`helpProbeHead`, with option
  arity per CLI, redirections and `--` respected); where does `$( )` end (`scanSubstitutionBody`: comments, `${…}`, ANSI-C, nested
  quotes, `case` subjects); what does make's command line mean (`parseMakeCommandLine`); which directory does a command run in
  (`runDirectory`: `env -u X -C`, `--chd=`, `-iC`, `-S`, `git --no-pager -C`, through `flock`); is this SQL statement a read
  (`isReadStatement`, a strict grammar). A matcher that duplicated the database exceptions was deleted.
- **A working directory is a set** (`cwdTimeline`): conditional `cd`, `||`/`&&`, branches, loops, functions, `source`, `pushd`/`popd`,
  subshell scopes, the last stage of a pipeline. Checked for soundness against real bash and zsh over 71 scripts
  (`cwd-timeline.test.ts`), not asserted.
- **The freshness ledger**: a path is stale when it or an ancestor was written, case-folded, through any link, after a glob, in a
  loop's next pass, by `sort -o`, `uniq IN OUT`, `find -exec`, `sed w`.
- **Redirections are not operands** (`cp x governed 2>&1` had `2>&1` as its destination — found by the cross-product), and a
  quoted `>` is not a redirection.
- **Environment**: variable names are families; values are parsed as URLs (userinfo included); every assignment of an `export`
  list is carried; literals a line assigned are substituted; a writer with a run-time operand asks.
- **Tool paths**: the hooks directory a repository configures (itself, in another case, symlink targets, an included config);
  wildcard search globs read as the tool reads them; a web search is public egress whatever it filters to; an overlay matcher a
  mode can release to ALLOW is refused.
- **Tests**: 240 → 274. New: `exit-review-10`, `selfattack-10`, `exit-review-11`, `cwd-timeline` (differential). Corpus: 67 → 101
  root classes, 23,924 → 40,452 combinations. Each new exact-verdict test fails against the tree before its fixes.

## What to observe

```bash
git log --oneline 339c76b..HEAD          # the 18 commits
npm run typecheck && npm run lint && npm test   # 274 tests; 11–20 minutes (the corpus dominates)
node --experimental-strip-types .probe/probe.ts 'git push origin help'   # .probe/ is gitignored scaffolding
```

Records: `docs/build/build-log.md` (exit reviews 10 and 11, the self-attack, the corrections),
`docs/architecture/phase-1-residuals.md` (by cause; the OPEN list; the decision), `docs/architecture/phase-1-taxonomy.md`.

## Affected surfaces

`packages/kernel/src/authority/evaluate.ts` (~11,000 lines; nearly all of it), `…/compile.ts` (overlay check),
`control-plane/permissions/matchers.md`, `control-plane/profiles/strict.md`, `control-plane/modes/production-advisory.md`,
`control-plane/workspace/bounded-commands.md`, the corpus and five test files.

## Explicitly not performed

No push, no pull request, no production mutation. No cold validation (clean tree, `rm -rf ~/.ego`, release build) for HEAD. No
exit review 12. CONFORMANCE not run. The OPEN list of review 11 (~225) is not fixed.

## Remaining work

The decision above. If option 1: amend the criterion in the baseline's issue #1 and the taxonomy, run the cold validation, close
the gates. If option 2: choose the surfaces (database clients, cloud CLIs, `git`), write the positive grammars, put the default
to ASK behind them. If option 3: the OPEN list by cause in the residuals document is the work list.

## Known limitations and risks

- ~225 review-11 findings are OPEN; the kernel should not be presented as a security boundary. Its verdicts are best-effort
  gating with an absolute-deny floor for a listed set.
- The suite takes 11–20 minutes (was ~9); the corpus cross-product is most of it. Machine load roughly doubled it once.
- `find . -name '*.tmp' -exec rm {} \;` is an absolute DENY (over-gating, pre-existing, OPEN).
- A `cd` under a branch, loop or function, `cd a b`, and a `popd` with nothing pushed make the directory UNKNOWN: an ASK for what
  follows. Honest, and noisier than before.
- `.probe/` (the reproduction scaffold) is gitignored and lives only in this working tree; the workflow scripts live in the
  session's scratchpad, not in the repository.
- My process cost: a test waiter looped for five hours on a file that never changed (killed), and two of my fixes were built on
  experiments that could not distinguish the hypotheses (both corrected). The log says so.

## Local commits

- `f993e8a` docs(phase-1): record exit review 11 — 258 findings, zero new classes — and the decision the series now owes the product owner
- `631f416` fix(kernel): exit review 11, the part fixed in the same sitting — my own regressions, the CRITICAL findings and the cheap structural one…
- `2390161` docs(phase-1): correct three details of the self-attack entry (script count, what the first differential run found, a sentence that descri…
- `0908b54` docs(phase-1): record the self-attack on exit review 10's fixes, and correct the make claim in the review-10 entry
- `cd9fe65` fix(kernel): the self-attack on exit review 10's fixes — one reader per dimension, a working directory that is a set, and a premise of m…
- `1556bd2` docs(phase-1): record exit review 10 and the eleven defects freezing it found
- `7fe322b` fix(kernel): freezing exit review 10 into the corpus found eleven more — a cd spelled as a quote, a case arm in a substitution, a semico…
- `f95544a` fix(kernel): looking is not doing — proportionality for help, dry-run and read statements; a link is a second name
- `45d1c4c` fix(kernel): a subprocess that could not answer, a directive that loads native code, and modes that stopped short
- `271eacb` fix(kernel): a configuration file that names a program, and an identity stated on the command line
- `8929d4d` fix(kernel): tables that disagreed, a bound that stayed silent, and six readers that stopped short
- `322368c` fix(kernel): the quoting the resolver could not see, and an endpoint named by the environment
- `4091ffa` fix(kernel): a copy lands under a name, a merge dropped five fields, and a response file is a command line
- `b3a23c3` fix(kernel): enumerations that were wrong by omission, and two copies of one list that disagreed
- `02d897a` fix(kernel): every spelling a client accepts, and every flag that names a file
- `edd774a` fix(kernel): a directory change in a subshell, or in a branch that may not run, binds nothing outside it
- `190f34e` fix(kernel): a brace result is the word the shell will see, and a probe flag in a value position is a value
- `5cafecc` fix(kernel): a separator EGO invented, a metacharacter one reader never learned, and two tildes
