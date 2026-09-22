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

This is enforced in the evaluator, and the distinction is **structural, not textual**. `resolveScriptCommand`
returns `unresolved: 'missing' | 'unread'`, decided by whether the file EXISTS — not by whether we happened to read
it, and never by matching a prose reason string. `missing` means nothing can execute (`npm test` with no test
script fails on its own) and a declared class keeps its verdict. `unread` means something WILL execute that could
not be read — unreadable, too large, malformed, wrongly encoded, reached through another working directory,
dynamically constructed or unsupported — and the human gate applies **at every depth**, including through an
enclosing declared class. That narrows September alignment item 5.

Nothing falls through to `ALLOW` any more. A tool the evaluator does not model, a modelled tool with a missing or
unexpected operand, an interpreter invocation that matched nothing else, an `exec` into an unknown container, a
database client handed a program file or an in-band shell escape, and a `WebSearch` with no url are all resolved to
a governed capability rather than to silence. On claude-code an `allow` is rendered as `permissionDecision: "allow"`,
which *suppresses the host's own prompt* — so returning `ALLOW` for something unmodelled was strictly worse than
saying nothing.

## Positive security claims must be earned

The fifth challenge found the failure that four rounds of enumeration had been circling: **a parser failing to find
something is not proof that it does not exist.** The producer had one bit — `missing` or `unread` — and `missing`
was the only state that kept a declared ALLOW. "Not parsed" and "not present" are the same observation to a regex,
so every gap between EGO's grammar and the real tool was routed into the one state that fails **open**. An ordinary
`build test:` rule, a prerequisite, a `.DEFAULT_GOAL`, an `include` — all common make — hid a `git push` behind
`command.build` ALLOW.

Resolution is now a structured outcome, and **exactly two of its values carry a positive claim**:

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

The consumer is a single total rule over that enum, and `resolutionEffect()` names the **proven** values rather than
enumerating the unproven ones — so an outcome added later falls to the opaque side by construction rather than by
someone remembering. `PARTIAL` is what makes this more than a rename: a body may now be *incomplete*. The resolved
lines are still analysed **and** the unresolved remainder is reported, instead of one unparsable recipe line
discarding the whole target, or a partly-parsed makefile passing for a complete one.

EGO does **not** reimplement GNU make, the shell, npm or git. It models a subset and records every construct it does
not model; the unmodelled part fails safe.

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

The closure is proportional: `make build`, `npm run build`, `npm test` and `git commit` in an ordinary repository
are all still ALLOW.

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
