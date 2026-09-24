# The frozen architectural taxonomy

> Status: **FROZEN** for Phase 1 (2026-09-24). A new finding is classified against this list. It is an *instance*
> of a class unless it cannot be expressed as one — and only a class that cannot be expressed here reopens the
> architecture.

## Why a taxonomy rather than a count

Twelve adversarial challenge rounds and three exit reviews produced a few hundred findings. Counting them says
almost nothing: rounds 9 through 12 produced 25, 28, 29 and 26 *instances* and **zero** new architectural classes,
while the single most severe defect of the whole phase — `echo "$(git push origin main)"` reaching ALLOW — was an
instance of a class that had been known and closed for weeks.

So the exit criterion is not "no findings". It is:

1. the class list below is **closed** — a fresh review produces no class that is not on it;
2. every class is enforced as a **general property**, asserted over a generated cross-product rather than over the
   spellings that happened to be reported (`packages/kernel/test/support/corpus.ts`);
3. a fresh high-risk review finds **no instance that crosses an authority floor**.

Criterion 3 is what the command-substitution defect proved criterion 1 alone cannot give: a known class can still
contain an implementation gap that turns a denied effect into ALLOW.

## The classes

### 1. Segment structure

Shell text does not reveal which commands it runs until its structure is consumed. Operators (`&&`, `||`, `;`, `|`,
`&`), command substitution (`$( )`, backticks) in every quoting state, process substitution (`<( )`, `>( )`),
subshells `( )`, brace groups `{ }`, line continuations, embedded newlines and heredoc bodies each decide whether a
command is seen at all.

*Enforced in* `splitShellSegments`. *Asserted by* the transformation cross-product.
*Instances that crossed a floor:* double-quoted command substitution (exit review 3); the subshell `( )`
(corpus by semantic class, 2026-09-24); and, in exit review 4, a `#` comment carrying an apostrophe (which
swallowed every following line), `$((cmd) )` read as arithmetic when a shell reads it as a command substitution,
`((cmd))`, a `case` branch's pattern list, a function definition's header, `2>&1` and `>&FILE` split on the `&`,
a `<<` anywhere on a script line opening a phantom heredoc that hid the rest of the file, and a backslash
continuation inside a script body.

### 2. Wrapper transparency

A command reached through a runner is still that command: `env`, a leading assignment, `command`, `nohup`,
`timeout`, `nice`, `stdbuf`, `xargs`, `sh|bash|zsh -c`, `su|runuser|flock --command`, `env -S`, `exec -a NAME`,
`npx`/`bunx`, `pnpm exec`. A wrapper that takes its OWN operands (`npx --package`, `flock FILE`) is not transparent
and must not be stripped as though it were.

*Enforced in* `normalizeSegment`. *Asserted by* the transformation cross-product.
*Instances that crossed a floor:* `exec -c -a NAME prog` (exec's own options before the alias), `/bin/sh -c '…'`
(an interpreter named by its absolute path, read as a script path), a `-c` anywhere in `bash script.sh -c x`
hijacking the interpreter, and `trap 'CMD' EXIT` and `sh <<< 'CMD'` as unmodelled carriers (exit review 4).

### 3. Producer resolution

The effect is not in the command line: it is in a file EGO must locate, read and resolve — a makefile (recipes,
prerequisites, includes, `-C`, `-f`, `.ONESHELL`), a package manifest's scripts (including pre/post), a shell
script, a git hook, a lint-staged configuration — and these nest.

*Enforced in* `resolveScriptCommand` and the producer contract (`producer-contract.test.ts`).
*Asserted by* the producer cross-product.
*Instances that crossed a floor:* a script body's line was classified as its first command only, so a quoted
substitution or a `;` inside a `.sh` was invisible (corpus by semantic class, 2026-09-24).

### 4. Resolution outcome — positive claims must be earned

A parser failing to find something is not proof that it does not exist. Exactly three of the eleven
`ResolutionOutcome` values carry a positive claim (`RESOLVED_COMPLETE`, `ABSENT_VERIFIED`, `NOT_A_PRODUCER`);
everything else is opacity *by construction*, because `resolutionEffect` names the proven values rather than
enumerating the unproven ones — so a value added later is opaque until someone decides otherwise.

*Enforced in* `resolutionEffect`. *Asserted by* `resolution.test.ts`.

### 5. The verified execution environment

A conclusion is relative to an environment, and the environment has more than one dimension: working directory and
whether it was *proven*, configuration closure, binding (program lookup) resolution, environment inputs, the write
ledger (transitive freshness), and repository/tree state. A dimension that is declared and never consulted is the
"accepted but unconsumed" defect; every dimension here gates.

*Enforced in* `ExecutionEnvironment` and `environmentGaps`. *Asserted by* `environment.test.ts`.

### 6. Target classification

Which system an effect reaches is a property EGO must resolve, not assume: LOCAL / PRODUCTION / EXTERNAL /
UNCLASSIFIED, for Kubernetes contexts, container runtimes (`--context`, `-H`, `DOCKER_HOST`, `docker context use`),
databases (flag, URI and positional forms), and cloud CLIs. A bare positional that the tool itself resolves locally
— `psql prod`, `mongosh prod` — is local, and treating it as remote would be a false gate, not a safeguard.

*Enforced in* `classifyTargetName`, `resolveK8sTarget`, `resolveContainerTarget`, `control-plane/workspace/local-targets.md`.
*Asserted by* the `production`, `db`, `container` and `k8s` corpus classes.
*Instances that crossed a floor:* docker's global options displacing the subcommand, so `docker --tls exec`
reached ALLOW; `image` treated as a read verb although it is a management GROUP whose members mutate; and the
engine's local test being a SUBSTRING match, so `tcp://[fd00:acme:prod::1]:2375` was the local daemon
(exit review 4).

### 7. Complete provenance of a positive claim

A positive execution claim requires complete provenance of: **process inputs** (environment, argv, stdin carriers),
**dispatch ownership** (which program the head actually names), **trust delegation** (EGO's own hook chain, byte
for byte), and **repository/tree state** (a file conclusion drawn before a write that invalidates it).

*Enforced in* `segmentEnvInputs`, `gitLocalProgramValues`, `trustChainComplete`, the write ledger.
*Asserted by* `provenance.test.ts`.

### 8. Ambient execution closure

Some producers are attached to repository state rather than named on the command line: git hooks fire on `commit`,
`checkout`, `push`; an install runs the whole dependency tree's lifecycle scripts, which EGO cannot read, and
`--ignore-scripts` is the only spelling that provably runs none.

*Enforced in* the ambient producer path (`AMBIENT_UNRESOLVED`). *Asserted by* `effects.test.ts` and the git-hook
producers in the corpus.

### 9. Path classification

Where a path points decides the verdict: literal-prefix canonicalisation of globs, `/`-anchored or `..`-carrying
patterns, write destinations (`>`, `-o`, `--output`, `tee`, `dd of=`, in-place `sed`), archive extraction and
recursive copy as *unenumerable* writes, credential stores and agent-configuration files.

*Enforced in* the path matchers and `writtenPathOperands` / `writesUnenumerably`.
*Asserted by* the `fs` and `ego` corpus classes.

### 10. Policy layering and administration

Every lock is administrable and every widening is a human act: organization layers are refused from the working
tree, reported pending by `doctor`, and accepted only by a human `ego init`. `ASK` is the designed human gate, not
a degraded `ALLOW`, and a layer asking for `ALLOW` on an organization-locked capability is clamped to `ASK` with
the clamp recorded in provenance.

*Enforced in* the control-plane compiler and `ego init`. *Asserted by* `control-plane.test.ts` and
`trust-and-hosts.test.ts`.

### 11. Proportionality

The dual of every class above. A control plane that gates ordinary development is not safe — it is switched off,
and then nothing is governed. Proportionality regressions are defects of the same seriousness as bypasses, and
several were introduced by fixes to the classes above (`docker run … sh -c`, `git blame -C`, Git LFS repositories,
`SHELL := /bin/bash`, `g++`, `docker --context default`).

*Asserted by* the ordinary-development corpus, which pins the **exact** set of gated commands and the reason each
one is gated, rather than a percentage.

## What is deliberately NOT a class

- **A spelling, a flag or a wrapper name.** These are instances of classes 1, 2 and 6. They are fixed where they
  are found and covered by adding a line to the cross-product — they do not reopen the architecture.
- **An unmodelled producer asking.** `mvn`, `gradle`, `bazel`, `rake`, `bundle exec`, `composer` and the test
  runners execute repository-defined tasks EGO does not model, so they ask — in every invocation form, including
  their version probes. That is the contract working, recorded in
  [`phase-1-residuals.md`](phase-1-residuals.md) as UNKNOWN_PRODUCER / FAIL-SAFE.
- **A containment requirement.** A finding whose only honest answer is OS-level isolation belongs to issue #26,
  not to another regex.

## What is claimed, and what is not

Claimed: for every (class, spelling, transformation, producer) in `support/corpus.ts`, the verdict does not fall
below the class's authority floor; and ordinary development in seven ecosystems is gated only where
`EXPECTED_GATES` says so and for the reason written there.

Not claimed: exhaustive coverage of the shell language. The grammar is larger than any list, `eval` and a
`$`-headed command are irreducibly dynamic and are reported as such, and a transformation nobody has written down
is not tested by having written down the others. What the structure buys is that the next transformation costs one
line and is then tested against every class at once.
