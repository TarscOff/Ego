# EGO security model

Decision "option B", taken by the product owner on 2026-09-22 after round 15 of the independent adversarial review.
This document states what each mechanism does, and — just as importantly — what it does not do. Nothing here may be
softened into a claim EGO cannot keep.

## Why this document exists

Phase 1 was originally gated on a single promise: that the command classifier could be hardened until an independent
adversarial review found nothing. Three rounds measured that promise with an identical instrument:

| Round | Confirmed findings |
|------:|-------------------:|
| 13 | 61 |
| 14 | 76 |
| 15 | 67 |

Between rounds 14 and 15 every one of the 76 findings was fixed and pinned by a test. An identical pass then found 67
more, and a large share of them were neighbouring spellings of those very fixes — several were defects the fixes
themselves introduced. The conclusion is not that the classifier is bad. It is that **exhaustively enumerating the
ways a shell can express an effect is not a security boundary**, because the enumeration has no end.

## The six mechanisms

Each does one job. None replaces another.

| Mechanism | What it actually does | What it does NOT do |
|---|---|---|
| **Git** | Records code changes and makes them reviewable | Does not constrain what a process may reach |
| **Worktrees** | Isolate Git working state between tasks | **Not containment.** A worktree shares the filesystem, the network, the credentials and the process table |
| **Authority** | Decides whether a recognised effect is permitted, and by whom | Cannot decide about an effect it was never shown |
| **Classifier** | Recognises known semantic effects in commands, paths, redirections, archives, interpreters and targets | Cannot enumerate every spelling of every effect; is not a boundary |
| **Containment** | Restricts what a process can physically reach: filesystem, network, credentials, tool surface | Does not understand intent, and **does not exist in every profile** |
| **Independent review** | Finds weaknesses in all of the above, continuously | Never proves their absence |

## The rule that holds the model together

The classifier will always have a frontier. What matters is what happens at that frontier, and the rule is:

```text
KNOWN + AUTHORIZED           -> execute according to policy
UNKNOWN / OPAQUE + CONTAINED -> execute only inside the permitted containment boundary
UNKNOWN / OPAQUE + NO ADEQUATE SANDBOX -> ASK or DENY according to policy and risk
                                       -> NEVER a silent ALLOW
KNOWN CLASS + AN OPERAND NAMING A PROGRAM, SCRIPT OR DESTINATION
THAT THE CLASS DOES NOT BOUND          -> treat as UNKNOWN / OPAQUE
```

The fourth line was added after the first challenge of this contract. Without it the rule *endorsed*
`tar -I /tmp/pwn`: the class is known (`command.local-mutation`), the class is authorized (`ALLOW`), and an arbitrary
program runs. A class only counts as known when it bounds what its operands can do.

**A sandbox is a containment boundary. A parser is not.** EGO therefore never converts "the classifier did not
recognise this" into "this is fine". It converts it into a question for a human, unless a real boundary is present to
make the question unnecessary.

This is enforced in the evaluator, and the distinction is **structural, not textual**: `resolveScriptCommand`
returns a required `resolution` outcome, never a prose reason a consumer has to interpret. The next section states
that ladder. The short version is that only a **proven** absence — the manifest was fully read and genuinely has no
such script, so `npm test` without a test script fails on its own — lets a declared class keep its verdict. Anything
that WILL execute and could not be read reaches the human gate **at every depth**, including through an enclosing
declared class. That narrows September alignment item 5.

Nothing falls through to `ALLOW` *by silence* any more. A tool the evaluator does not model, a modelled tool with a
missing or unexpected operand, an interpreter invocation that matched nothing else, an `exec` into an unknown
container, a database client handed a program file or an in-band shell escape, and a `WebSearch` with no url are
all resolved to a governed capability rather than to silence.

The precision matters, because the stronger reading — *nothing reaches ALLOW that should not* — is a claim no
classifier can keep and this document must not make. What EGO claims is narrower and testable: **an unmodelled
thing is never mistaken for a permitted one.** Things that reach ALLOW because a decision put them there are
listed, with their residual risk, in [`phase-1-residuals.md`](phase-1-residuals.md). On claude-code an `allow` is rendered as `permissionDecision: "allow"`,
which *suppresses the host's own prompt* — so returning `ALLOW` for something unmodelled was strictly worse than
saying nothing.

### The structured tool surface, and what it costs

"Structured path" in the Phase-1 exit criterion means every call that is **not a Bash string** — `Write`, `Edit`,
`MultiEdit`, `NotebookEdit`, `apply_patch`, `Read`, `Grep`, `Glob`, `LS`, `WebFetch`, `WebSearch`, an `mcp__` tool, a tool
nobody modelled — *and the two host adapters that turn a raw payload into one*. The input shape is part of the surface,
not only the tool name. Pinned in [`closure-tools.test.ts`](../../packages/kernel/test/closure-tools.test.ts), at the
evaluator and through the real hook path of both hosts:

- **One operand per tool.** `TOOL_OPERANDS` in the evaluator says which key a tool is judged by (`file_path`, or
  `notebook_path` for the notebook tool; `url` only for `WebFetch`, so a `WebSearch` is always `network.public-read`).
  An operand that is present and not a string, or a second operand-shaped key beside it (`path` on a `Write`, `cmd` on a
  `Bash`), is read as the kind of operand it names and the call asks — it is not known which key the host honours.
- **A path is judged by what it resolves to.** A link is followed even when its target does not exist yet (the nearest
  existing ancestor of the destination is judged), `..` after a link names the parent of the link target, and a path with
  leading or trailing whitespace or a NUL is classified under every reading and always asks, never judged as if it had been
  trimmed. The shell shares the same resolver.
- **`apply_patch` headers are read the way the host's parser reads them:** every line is trimmed, a trimmed line that is a
  header is a write target wherever it sits, and a trimmed `*** ` line that is none of the known headers makes the whole
  patch unparseable (DENY).
- **Codex sends an argv, not a string.** The codex-cli dialect turns `["ls","-la"]` into the shell-quoted line that
  executes, the host's own `["bash","-lc",<script>]` wrapper into the script, and a `workdir` into its `cd`; any other
  shape is left as it arrived and asked about (refused on codex-cli, where `ASK` is refused until conformance).
- **MCP.** Every `mcp__` tool is `mcp.unknown` (DENY). `.harness/mcp-trust.md` is written by `ego init` and read by
  nothing, so listing a server there has no effect; the resolver is phase-2 work (issue #10), and the `mcp.local.*` /
  `mcp.remote.*` classes are not reachable until it lands.

**The cost of "nothing falls through to ALLOW".** A tool the evaluator does not model asks. On claude-code that is a
prompt for every host tool EGO has not read — `Task`, `Skill`, `KillShell`, a tool shipped next month — and on codex-cli
it is a refusal. The noise pushes people to switch the hook off, which is worse than any one tool, so the host tools
that cannot act on anything are listed **by name, with the reason beside the name** (`INERT_HOST_TOOLS` in the
evaluator): `TodoWrite` (the agent's own checklist) and `BashOutput` (reads the output of a shell whose start was
already judged). The list is spelled exactly — `todowrite` or `TodoWrite ` is an unmodelled tool — and it stays this
small. `ExitPlanMode` and `AskUserQuestion` are deliberately **not** on it: they do nothing to the machine, but their
whole function is the host's prompt to the human, and a hook `allow` suppresses that prompt, so asking costs nothing
and allowing would answer for the human.

## Positive security claims must be earned

The fifth challenge found the failure that four rounds of enumeration had been circling: **a parser failing to find
something is not proof that it does not exist.** The producer had one bit — `missing` or `unread` — and `missing`
was the only state that kept a declared ALLOW. "Not parsed" and "not present" are the same observation to a regex,
so every gap between EGO's grammar and the real tool was routed into the one state that fails **open**. An ordinary
`build test:` rule, a prerequisite, a `.DEFAULT_GOAL`, an `include` — all common make — hid a `git push` behind
`command.build` ALLOW.

Resolution is now a structured outcome, and only the values marked below carry a positive claim:

| Outcome | Meaning | Keeps a declared ALLOW |
|---|---|:--:|
| `RESOLVED_COMPLETE` | everything that will execute was located and read | yes |
| `ABSENT_VERIFIED` | **proven** that nothing will execute | yes |
| `PARTIAL` | some of what will execute was resolved; the rest was not | no |
| `UNSUPPORTED` | the source uses constructs this resolver does not model | no |
| `UNREADABLE` | the source exists but could not be read | no |
| `DYNAMIC` | the target, path or command is built at runtime | no |
| `STALE` | resolved, but the source is rewritten before the effect runs | no |
| `CONTEXT_UNVERIFIED` | the context the conclusion depends on was not proven | no |
| `AMBIENT_UNRESOLVED` | an implicit producer attached to repository state was not resolved | no |
| `NOT_A_PRODUCER` | **proven**: this head introduces no closure beyond what its arguments name | yes |
| `UNKNOWN_PRODUCER` | the head discovers and runs content EGO was never shown | no |

The consumer is a single total rule over that enum, and `resolutionEffect()` names the **proven** values rather than
enumerating the unproven ones — so an outcome added later falls to the opaque side by construction rather than by
someone remembering. `PARTIAL` is what makes this more than a rename: a body may now be *incomplete*. The resolved
lines are still analysed **and** the unresolved remainder is reported, instead of one unparsable recipe line
discarding the whole target, or a partly-parsed makefile passing for a complete one.

EGO does **not** reimplement GNU make, the shell, npm or git. It models a subset and records every construct it does
not model; the unmodelled part fails safe.

## The verified execution environment

`{cwd, cwdVerified}` was one dimension, and it was the only one EGO made earn its keep. Everything else that decides
**which bytes run** was assumed: the configuration that selects the body, the binding that turns a name into a
program, the freshness of the sources a conclusion rests on, the events an operation raises. Each of those silently
re-points the analysis at a different reality while the verdict still reads RESOLVED. The environment is therefore
multi-dimensional, and the invariant is:

> A positive ALLOW may exist only when the relevant execution closure is **context-verified**,
> **configuration-complete enough**, **binding-resolved where required**, **fresh**, and **fully passed through the
> canonical analyzer**.

"Relevant" is doing deliberate work: a claim must prove the dimensions it actually depends on, not all of them —
proving all of them would gate ordinary development, and proving only the directory was the hole.

| Dimension | What it decides | How it fails safe |
|---|---|---|
| **cwd / workspace** | what a relative path means | dynamic `cd`, unresolvable `-C`, logical/physical disagreement, a directory outside every registered root |
| **configuration** | *which* body the tool selects | `core.hooksPath`, makefile precedence, an unreadable `include`, a workspace selector |
| **binding** | which *program* a name runs | a makefile or command line assigning `SHELL`, `.SHELLFLAGS` or `PATH` |
| **freshness** | whether the bytes read are the bytes that run | the write ledger, shared across every depth |
| **ambient events** | what runs that the command never names | git hooks by event, install lifecycle scripts |
| **sources** | what a conclusion rests on | fingerprints, so a conclusion can be re-checked |

**Typed dispatch.** `ProducerResult | null` gave every producer a second, untyped return channel that silently
meant `ABSENT_VERIFIED` — the strongest claim in the ladder, made by omission. `null` is gone. `kind: 'none'` means
*no registered producer claims this head*, which is a fact about the producer table, not a conclusion about
execution, and it is reached by a lookup rather than by a producer giving up.

**Scoped opacity.** An unknown now names which part of the closure it is about — `binding:Makefile`,
`config:gen.mk`, `body:deploy`, `ambient:install` — so a reader sees what EGO could not see, and a local unknown
stops poisoning unrelated safe work: an unresolved `deploy` target leaves `build` and `test` at ALLOW.

**Transitive freshness.** The write ledger belongs to the *command*, not to one producer, and is mutated in place
across every depth. `./configure && make build` no longer reuses the Makefile that `configure` rewrote one level
down.

**Self-modifying producers.** A makefile that is itself a target of that makefile is remade and re-run by make, so
what EGO read is the pre-image of what executes. That is reported as a freshness gap rather than asserted complete.

**Ambient events.** Hooks are resolved in two steps — the semantic events an operation raises, then the hooks those
events listen to. `reference-transaction` fires on *any* ref update and `post-index-change` on *any* index change,
which a verb-to-hook table cannot express: a verb added later only declares what it does, a hook only what it
listens to.

## Complete provenance

Decision of 2026-09-23, closing the last four classes as one problem rather than four patches:

> A positive execution claim requires complete provenance of **process inputs**, **dispatch ownership**,
> **trust delegation** and **repository/tree state**.

**Process inputs.** `normalizeSegment` strips leading `VAR=value` assignments before the producer boundary, so a
producer could satisfy "configuration-complete" *vacuously* about a tool the same command line had just re-pointed:
`MAKEFILES=extra.mk make build` was ALLOW while make executed `extra.mk`. The environment now carries the
assignments that materially change execution semantics — `MAKEFILES`, `MAKEFLAGS`, `SHELL`, `npm_config_*`, `PATH`,
`GIT_*` and their neighbours — and the relevance is per producer kind. EGO does not model the environment; it
captures the inputs required to justify the claim being made, and `FOO=bar make build` is untouched.

**Dispatch ownership.** A producer table that does not claim a head was reporting `ABSENT_VERIFIED` — the strongest
claim in the ladder — so every program that *discovers its own executable content* carried a positive ALLOW over a
closure nobody had looked for. The silence of a lookup is now split three ways by an authored, administrable
vocabulary (`control-plane/workspace/bounded-commands.md`):

| | meaning | claim |
|---|---|---|
| `NOT_A_PRODUCER` | the head is **bounded**: its closure is exactly what its arguments name | positive |
| `ABSENT_VERIFIED` | a producer claimed the head and proved nothing executes | positive |
| `UNKNOWN_PRODUCER` | the head discovers and runs content EGO was never shown | opaque |

A discovering tool has two shapes, and conflating them cost ordinary work for nothing. One runs repository code it
locates by **pattern** — test files, a task graph — which EGO cannot bound without emulating the tool. The other
runs whatever its **configuration** names, and is bounded while that configuration is data: `eslint .` is ALLOW in a
repository whose config is JSON and a human gate in one whose config is `eslint.config.js`, because in the second
case eslint imports and runs that file. This is the same configuration-closure rule EGO applies to git, make and
lint-staged, applied to a tool.

The cost is stated plainly: **test commands now ask.** `npm test`, `pytest`, `go test`, `cargo test` and
`node --test` execute repository code EGO was never shown, so they cannot hold a positive claim. Measured across a
TypeScript monorepo, a Go service, a poetry project, a Rust crate and a husky repository — 79 ordinary commands, 8
gated, every one of them a test command. An organization that accepts the risk for a given tool moves it to
`bounded` in its overlay, and that decision is recorded rather than assumed.

**Trust delegation.** Trust is transitive. EGO's hook shim is recognised byte for byte, which *elides its body* —
and that transfers its closure obligation to whatever it delegates to. The shim `exec`s
`.harness/hooks/git-hook.sh`, a file inside the mutable workspace it governs. The entrypoint is trusted only while
the whole chain is resolved, fingerprinted against what `ego init` installed, fresh, and inside the boundary. A
missing, modified or possibly-rewritten delegate is an unanalysed body, not a trusted one.

**Tree state.** A checkout, reset, stash pop, merge, rebase, cherry-pick, restore, clean or worktree switch replaces
a repository-determined, **unenumerable** set of tracked files — which the per-path write ledger cannot express. The
environment carries tree freshness, and a conclusion drawn from repository content after such an operation is a
pre-image. `git checkout main && make build` is a human gate; `make build && git checkout main` is not, because
order is respected; `git status && make build` is not, because status changes nothing.

## The global invariant

A positive ALLOW requires the relevant execution closure to be **dispatch-known**, **context-verified**,
**environment-complete enough**, **configuration-complete enough**, **binding-resolved where required**,
**trust-chain-complete**, **tree-state-fresh**, and **passed through the canonical analyzer**. Any required
dimension unresolved means UNKNOWN/OPAQUE — named by scope, so the gap is legible and a local unknown does not
poison unrelated safe work.

## Execution closure

Security analysis cannot consider only the executable text present in the command. The **execution closure** of an
operation is the set of bodies EGO must account for before it may make a positive claim about it:

- a make target's **prerequisites**, transitively, plus `include`d fragments, every `-f` file, `.DEFAULT_GOAL`,
  both branches of a conditional (EGO cannot evaluate the condition, so it analyses the union), `.ONESHELL`
  recipes as one shell, and cumulative `-C`;
- an **install**'s dependency-tree lifecycle scripts, which EGO cannot read — `npm install` is therefore
  `command.ambient-unresolved` (ASK) and `npm install --ignore-scripts` is ALLOW. This is a deliberate behaviour
  change: an install genuinely executes third-party code, and it is the one gate that composes with the next one;
- a **git verb's hooks**. Installed hooks have no producer to name them: `npm install` lets a dependency install a
  hook and the next `git commit` runs it, two individually-ALLOW decisions composing into unanalysed execution.
  Each verb now carries the hooks it fires. EGO's own governance shim is re-rendered and compared **byte for byte**,
  so it is recognised by provenance rather than by a producer deciding something is safe — a repository governed by
  EGO keeps `git commit` at ALLOW, and any other hook body goes through the canonical analyzer.

The closure is proportional: `make build`, `npm run build` and `git commit` in an ordinary repository are all
still ALLOW. `npm test` is NOT — it gates, by the decision stated two paragraphs above, because a test runner
executes repository code EGO was never shown. An earlier revision of this sentence listed it among the untouched
commands, contradicting the same document and the code.

## Freshness

A body that was resolved correctly can be rewritten before it runs. `analyzeSegments` therefore carries a **write
ledger** that grows as it walks: redirection targets and the destination operands of the write commands. A producer
resolving a source that is already in the ledger returns `STALE` rather than the contents it read, so
`cp evil.mk Makefile && make build` can no longer be judged from the Makefile that was replaced.

This covers mutation by an earlier unit of the same decision. It does **not** cover another process racing EGO
between the verdict and the execution; that is a containment concern (#26), stated again under limitations.

## Context verification is earned

`cwdVerified` used to default to `true` merely because a cwd string existed, so every relative conclusion inherited
a claim nobody had checked. The invocation directory now counts as proven only when it **exists** and lies inside a
registered repository root. And because `cd` is *logical* by default but *physical* under `-P`, a `..` segment after
a symlinked component resolves to two different directories: where the two disagree, the base is not proven and
everything below it is downgraded.

## The producer contract: true by construction, not by vigilance

Four independent challenges exposed the same meta-defect in the repairs themselves, not in the rules: a rule would be
implemented at the place being inspected and quietly miss its siblings. The opacity filter covered one producer of
four. The canonical pipeline was true for three of four. Each fix was correct where it was written and absent
everywhere else, so the next round found the same class through a different door.

The answer is not more vigilance. It is to make the property structural.

A **producer** is anything that turns one invocation into other executable content: `make`, an npm/yarn/pnpm/bun
script, a lifecycle hook, a shell script, and anything added later. The contract is stated once, in the type:

| A producer MAY | A producer MAY NOT |
|---|---|
| Resolve which body will execute | Decide a segment is safe |
| Resolve the body's execution context | Remove builtins, redirections, substitutions or any executable line |
| Provide provenance (which file, which directory) | Absorb UNKNOWN into a friendlier enclosing class |
| Report that it could not resolve (UNKNOWN) | Emit a verdict, or weaken the analysis of a nested body |

Two halves of that are enforced by the shape of the code rather than by a test: `resolveScriptCommand` returns
`{kind, key, provenance?, body, bodyRes?, reason, unresolved?}` — **there is no field a verdict could travel in** — and
its single caller hands the body straight to `analyzeSegments`. The prefix-keyword stripping that producers used to do
(`then`, `do`, `if`, `@`, `-`) now lives in the analyzer's own normalization, so a producer has nothing left to filter
with. `packages/kernel/test/producer-contract.test.ts` pins the rest: fifteen bodies are analysed at top level and
again behind six producers, including two nested combinations, and every verdict must match.

The consequence to keep in mind when adding a producer: you get to say *what runs* and *where*, never *whether it is
allowed*. If a new producer needs to classify something itself, that is the signal that the canonical analyzer is
missing a case — fix it there, where every producer benefits at once.

## What each profile may honestly claim

Containment is a property of the host and the profile, never of the classifier. Issue #26 owns the implementation.

**Today, no profile provides OS-level containment.** The table below therefore has two separate columns: what the
profile is *designed* to provide once issue #26 lands, and what is *actually in force right now*. They must never be
conflated, and the second column is the one any claim about EGO's security has to rest on.

| Profile | Designed isolation (#26, not built) | Actually in force today | What EGO may claim today |
|---|---|---|---|
| **STANDARD** | Current checkout; policies, hooks, claims, validation | **Policies and hooks only.** Held scopes/claims are phase 2 and the validation matrix is phase 3-4, so neither is in force. No process, filesystem or network restriction. | Normal local work stays fluid, and known-safe `LOCAL_WORKSPACE` operations are `ALLOW`. EGO must **not** pretend arbitrary opaque execution is physically contained. Ambiguous actions able to escape the governed workspace `ASK` or `DENY`. |
| **STRICT** | A dedicated branch and worktree per task | **Nothing beyond STANDARD.** The branch/worktree execution strategy is not implemented. | Exactly what STANDARD claims, and nothing more. Even once built, **worktree isolation is not filesystem, network or process containment.** |
| **HIGH_ASSURANCE** | Worktree plus a sandbox or managed boundary: restricted filesystem, credentials, network, external targets and tool surface | **The narrowed capability set only.** Managed-settings tamper protection is a HOST feature EGO records in its capability matrix; EGO neither installs nor verifies it, so it is not something EGO provides. **No sandbox, no filesystem, credential, network or tool-surface restriction.** | Exactly what STANDARD claims. It may **not** yet rely on containment for anything. |

The third column is why the fail-safe rule currently resolves to `ASK` in *every* profile: there is no boundary to
defer to anywhere. When issue #26 lands, only the profile whose containment is both required and verified may move
unknown execution from `ASK` to a contained `ALLOW`.

When the host provides hooks only, EGO claims hooks only. `control-plane/containment/controls.md` declares each
control together with its per-host support, and `ego doctor` reports what a given host satisfies. Note a real gap:
`packages/kernel/src/hosts/matrix.ts` carries its own capability keys and **is not** the source doctor consults for
containment, so the two tables can drift apart with nothing to catch it. Reconciling them is part of issue #26.

## What the regression corpus is for

Roughly 200 reproduced bypasses are pinned as deterministic tests across
`packages/kernel/test/{bypass,effects,redact,control-plane,hooks,githooks}.test.ts`. Their purpose changed with this
decision. They are no longer evidence that the classifier is complete — they are evidence that **known** bypass
classes stay closed. A finding from a future review becomes one of three things:

1. a **regression fixture**, when it exposes a concrete known bypass;
2. a **classifier improvement**, when one semantic fix closes a real family;
3. a **containment requirement**, when interpreting it exhaustively would amount to reimplementing the shell or the
   tool. These are recorded against issue #26 rather than answered with another regex.

### Organized by root semantic class, not by the order the defects arrived

A corpus of literal spellings proves that a list of past bugs stays fixed. It cannot say whether a NEW spelling of
an old effect is covered — which is exactly how `echo "$(git push origin main)"` reached ALLOW inside a class that
had been closed for weeks, and how `( chmod 777 /etc/passwd )` did the same.

`packages/kernel/test/support/corpus.ts` is therefore written the other way round: twenty ROOT SEMANTIC CLASSES,
each with the canonical spellings of the effect and an authority **floor**; a set of TRANSFORMATIONS that carry an
effect without changing it; a set of PRODUCERS that put it behind a file EGO must resolve. The variants are the
cross-product — generated, not enumerated. A transformation added there is tested against every class at once, and
a class added there is tested against every transformation at once.

The invariant the cross-product asserts is **semantic authority monotonicity**: wrapping, quoting, embedding,
transporting, configuring or indirectly invoking an effect never reduces its verdict
(`monotonicity.test.ts`, `corpus.test.ts`). The frozen class list those classes map to is
[`phase-1-taxonomy.md`](phase-1-taxonomy.md).

The same file carries the other half of the contract: the ordinary-development corpus, which pins the **exact** set
of commands that gate across seven ecosystems together with the reason each one is gated. A new gate on ordinary
work has to be added there deliberately, rather than appearing as a slowly rising percentage.

## The fifth state: KNOWN-BUT-WRONG

A second independent challenge found that the first three states were not exhaustive. A resolver can be
**confidently wrong**: `make -C tools gen` had its recipe classified against the PARENT's working directory, so EGO
read a decoy `./gen.sh` at the repository root while make ran `tools/gen.sh`. Holding the executed file fixed and
changing only the never-executed decoy moved the verdict — proof that the verdict was computed from the wrong file.
There was no opacity signal at all.

The contract therefore carries a state before all the others:

```text
KNOWN + VERIFIED EXECUTION CONTEXT   -> evaluate normally through authority/policy
KNOWN + UNVERIFIED OR INCOMPLETE CONTEXT -> treat as UNKNOWN / OPAQUE
```

A `ResolutionContext` (`packages/kernel/src/authority/evaluate.ts`) carries the directory a conclusion is relative
to and whether that directory was **proven**. It is threaded through effect resolution: a `make -C` recipe resolves
in the `-C` directory, an npm script in its manifest's directory, a shell script in the caller's. The recursion's
cycle guard keys on the directory too, so a same-named target elsewhere is a different effect rather than a skipped
one. Where the context cannot be proven — a dynamic `cd`, an unmodelled workspace selector (`-w`, `--prefix`,
`--filter`), a makefile whose target is only visible through an `include` or a pattern rule — the conclusion is
downgraded to opaque instead of being asserted.

**Analysis truncation is also opaque.** Reaching the recursion depth limit returns an opacity hit; it never falls
back to the enclosing declared class, which previously let a chain of indirection launder anything.

## Residual reconciliation

Every remaining HIGH/MEDIUM finding is classified in
[`phase-1-residuals.md`](phase-1-residuals.md) as exactly one of MUST_FIX, ACCEPTED_PRODUCT_BEHAVIOR,
UNKNOWN_PRODUCER/FAIL-SAFE or CONTAINMENT_DEPENDENCY. **Only a MUST_FIX counts as an unresolved Phase-1 defect.**
Counting a recorded decision, a working fail-safe and a named requirement on issue #26 as defects is what made
earlier rounds look like they were not converging while the contract was in fact holding.

That document also states, for `docker compose up`, exactly what EGO still enforces around an accepted ALLOW —
`exec` and the isolation-removing flags gate, a bind mount's source is classified as a real path — what the
residual risk is in plain words, and the four guarantees issue #26 owes. EGO's honest claim about it today is
written there as such: **permitted and uncontained.**

## Known limitations, stated plainly

- The classifier does not understand arbitrary shell, and no amount of hardening will make it do so.
- Containment is not implemented yet. Until issue #26 lands, **no profile provides OS-level containment**, which is
  precisely why unknown execution asks a human in every profile today.
- Secret detection is a catalogue. It blocks the provider formats it knows; new providers are ordinary maintenance.
- Host conformance is unverified until the phase-6 suite exists; the `codex-cli` dialect fails closed on everything
  but `ALLOW` until then.
- A human who approves an `ASK` is trusted. EGO bounds what is asked, not who answers.
- A `cd` into a directory that does not exist is assumed to have succeeded. With `&&` that assumption is safe —
  the cd fails, so nothing after it runs. With `;` the rest of the line runs in the ORIGINAL directory and EGO
  attributes it to the wrong one. Telling the two apart needs the separator, which segment splitting discards.
  Requiring the target to exist was implemented and then reverted: it made `mkdir -p x && cd x` and every
  `cd src && …` in a checkout EGO has not materialised ask a human, which is a usability break, not a boundary.
- The execution context EGO models is the working directory and the manifest/recipe it resolves against. PATH
  resolution, shell aliases and functions, `direnv`, `.npmrc` and most environment-dependent resolution are **not**
  modelled. Where they would change which artifact executes, EGO has no signal at all — that is the residual shape
  of the KNOWN-BUT-WRONG class, and it is why containment (#26) remains a separate and necessary boundary.
