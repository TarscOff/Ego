# Phase-1 residual reconciliation

Decision of 2026-09-23. Eight independent challenges produced findings faster than they could be argued about, and
the backlog had stopped distinguishing three different things: a hole, a decision, and a boundary EGO has not built.
Every remaining HIGH/MEDIUM finding is classified here as **exactly one** of four kinds, and a finding in the last
three is no longer counted as an unresolved security defect.

| Kind | Meaning | Counted as an unresolved defect? |
|---|---|:--:|
| **MUST_FIX** | a real unauthorized effect can still reach ALLOW | yes |
| **ACCEPTED_PRODUCT_BEHAVIOR** | intentionally permitted by an explicit prior product decision | no — but the boundary and the residual risk are stated |
| **UNKNOWN_PRODUCER / FAIL-SAFE** | EGO does not model the closure, so ASK/DENY applies | no — this is the contract working |
| **CONTAINMENT_DEPENDENCY** | the semantic action is permitted; its blast radius belongs to issue #26 | no — but #26 owes a named guarantee |

Nothing here may claim containment that is not implemented. **No profile provides OS-level containment today**, so
every CONTAINMENT_DEPENDENCY below is an accepted risk *now* and a requirement *later*, not a protection in force.

## MUST_FIX — closed in this pass

| Finding | Was | Now |
|---|---|---|
| `.npmrc` / `.yarnrc.yml` `script-shell` re-points the interpreter of every package script | ALLOW | PARTIAL → ASK. The identical setting as a command-line flag was already modelled; the FILE was not. Only a file that actually sets an execution key gates — a `.npmrc` with a registry is untouched. |
| `pip install`, `poetry install`, `bundle install`, `gem install`, `composer install`, `uv sync`, … reached ALLOW while `npm install` asked | ALLOW | AMBIENT_UNRESOLVED → ASK. Acquiring and running third-party code is the same execution surface in every ecosystem; gating one and not the others was an inconsistency, not a decision. |

## ACCEPTED_PRODUCT_BEHAVIOR

### `docker compose up`, `docker compose up -d`, `docker run`, `docker compose run`

**Status: intentional ALLOW. Not a Phase-1 unresolved finding.**

This was gated in an earlier round and the gate was **reversed by explicit product decision**: only `exec` into a
running container and the flags that remove isolation (`--privileged`, `--pid=host`, `--network=host`,
`--userns=host`, `-v /:/host`) gate. Running a container is the ordinary way to work on a containerised project,
and treating it as opaque execution made the control plane unusable for that whole class of repository.

**The accepted ALLOW is for the LOCAL DEFAULT DAEMON ONLY.** The decision reversed a gate on running a container
*here*; it said nothing about a remote engine, and the first version of this document stated the boundary entirely
in terms of a local daemon without saying so. The container runtime is now enrolled in the same Q98 target model
as Kubernetes and databases: an explicit `-H`/`--host`/`-c`/`--context`/`--url`, and `docker context use`, are
classified, and a production engine is an absolute deny exactly as `kubectl --context production apply` already
was. `docker plugin install` acquires and runs third-party code on the HOST, outside any container, and is an
install like any other.

**The exact boundary EGO enforces today**

- The *semantic* action — start the services a compose file describes **on the local default daemon** — is ALLOW.
- What that container may reach is **not** analysed. A compose file can name a repository `Dockerfile` whose `RUN`
  steps execute arbitrary code, mount host paths, publish ports and read the environment. EGO does not read the
  compose file, does not read the Dockerfile, and does not claim to.
- What is still enforced around it: `docker exec` and the isolation-removing flags gate; a bind mount's **source**
  is classified as a real path, so `-v ~/.ssh:/x` is judged as a read of the credential store; writes to protected
  paths performed by the shell around the command are classified normally.

**Residual risk, stated plainly.** A context selected AMBIENTLY — `docker context use` having been run in an
earlier, separately governed session, or `DOCKER_HOST` exported in the shell profile — is not knowable to the
kernel at the moment of the verdict; `docker context use` is itself classified now, so the escalation must happen
outside a governed session. An agent that can write a `Dockerfile` or a `docker-compose.yml` and then run
`docker compose up` obtains arbitrary code execution with no human gate. That is accepted because the alternative —
gating every container run — was tried and rejected, and because the write itself is governed: the compose file and
the Dockerfile are repository files, and a change to them is visible in the diff a human reviews.

**What issue #26 must guarantee around it.** This is the one residual whose mitigation is entirely containment:

1. a profile that requires containment must run container commands under a boundary that restricts host bind
   mounts to the checkout and the runtime root;
2. the daemon socket must not be reachable from a governed session in that profile — a reachable
   `/var/run/docker.sock` is equivalent to root on the host and defeats every other control;
3. network egress from the container must fall under the same egress control as the session;
4. `ego doctor` must report which of the three are in force, and must say UNVERIFIED where it cannot check — it may
   not report a container boundary it has not verified.

Until #26 lands, EGO's honest claim is: **`docker compose up` is permitted and uncontained.**

### `git clone <url> /tmp/…`, writes under the scratch tree

`/tmp` and the system scratch tree are classified `fs.scratch.write` (ALLOW) by a prior decision. Cloning an
arbitrary repository into the scratch tree is therefore permitted; cloning into `~/.ssh` is DENY, as it should be.
Residual risk: content of unknown provenance lands on disk. It does not execute by being cloned, and executing it
afterwards is classified on its own.

### Writing the overlay policy layers

`.harness/permissions.md` and `.harness/overlay/matchers.md` are writable at ALLOW; the organization layer
`policies/organization/permissions.md` and the compiled cache `.harness/generated/policy.json` are DENY.

That asymmetry is correct and was verified end to end through the real hook path, not assumed: the overlay layers
may only **narrow**. An overlay that tries to widen makes the control plane fail validation —

```text
overlay layer attempts to widen "git.remote.push" from DENY to ALLOW; lower layers may only narrow
overlay matcher may not map "^git\s+push" to ALLOW capability "command.read-only"; overlay matchers only narrow
```

— and the hook then fails closed rather than deciding. So an agent may tighten its own leash and may not loosen it.
Residual risk: an agent can make the control plane invalid, which stops the session. That is a denial of its own
service, not an escalation.

### `helm repo add`

Writes local helm configuration. Permitted as a local-workspace operation. Residual risk: a later `helm install`
from that repository pulls charts of unknown provenance — which is classified when it happens, not here.

## UNKNOWN_PRODUCER / FAIL-SAFE — the contract working as designed

These are **not defects**. EGO does not model their execution closure, so the human gate applies. Each is one line in `policies/organization/bounded-commands.md` away from being declared bounded by an
organization that accepts the risk — a real layer, loaded by the kernel, and a WIDENING like any other: it is
refused from the working tree, reported by `ego doctor` as pending, and applied only when a human runs `ego init`
from their own terminal. An agent shell cannot accept it. An earlier version of this document promised that escape
hatch before it existed; the vocabulary lives in the installed package's control plane, which a consumer cannot
edit, so the promise had nothing behind it.

| Command | Why EGO does not model it | Verdict |
|---|---|---|
| `mvn`, `gradle`, `bazel`, `sbt`, `dotnet build` | execute repository-defined plugins, goals and targets — producers whose grammar EGO would have to reimplement | ASK |
| `rake`, `bundle exec`, `gulp`, `grunt`, `turbo`, `nx`, `lerna` | run repository-defined tasks, or re-enter another package's scripts through a head EGO does not model | ASK |
| `pytest`, `vitest`, `jest`, `node --test`, `go test`, `cargo test` | execute repository code located by **pattern**; bounding it means emulating the runner | ASK |
| `git lfs pull` | runs the LFS filter and replaces tracked content; the filter is a configured program | ASK |
| `npm run x -w pkg`, `pnpm --filter`, `npm --prefix` | select a manifest through a workspace graph EGO does not model | ASK |
| a makefile larger than the read ceiling, an unreadable `include`, a `$(VAR)`-headed recipe | the source could not be read, or is built at runtime | ASK |
| `mvn -v`, `gradle --version` | **every invocation form of an unmodelled producer asks, including its version probe.** The opacity is a property of the HEAD — EGO cannot say what `mvn` executes — and the control plane's vocabulary names heads, not invocation forms. Carving out a flag would be a per-spelling exception to a by-construction rule, which is the defect this phase removed. Where the same head is NOT a producer (`yarn`, `pnpm`, `bun`, `deno`, `pip list`), the version probe is ALLOW | ASK |

**Proportionality cost, measured rather than asserted — including where it is worst.**

| Measured on | Ordinary commands | Gated | What gates |
|---|---:|---:|---|
| TypeScript monorepo, Go, Python/poetry, Rust, husky | 79 | 8 (10%) | `npm test`, `make test`, `pytest`, `go test`, `cargo test` — every one a test command |
| C/C++ with CMake and a real Makefile | — | see note | `cmake`/`ninja` drive a build and gate; `--version` and `-t targets` do not |
| Java/Maven, Ruby, PHP, LFS repository | 66 | 12, of which 9 non-test | `mvn`/`gradle`/`rake` (task runners), `bundle`/`composer`/`gem` (installs), `composer dump-autoload`, `git lfs pull` |
| **This repository (EGO itself)** | 44 | **7 (16%)** | see below |
| **Seven ecosystems, pinned as a test** (git, shell, node, python, go, rust, jvm) | 73 | **13 (18%)** | 8 test runners, 1 install (`pip install`), 4 unmodelled task runner (`mvn`, `gradle`) |

The last row is the one that is now ENFORCED rather than measured once: `packages/kernel/test/corpus.test.ts`
asserts the EXACT set of gated commands and fails if a command gates without an entry in `EXPECTED_GATES` naming
the reason, or if one listed there quietly becomes ALLOW. A rising gate rate can no longer arrive unnoticed.

The third row is the honest one, and an earlier version of this document left it out. On EGO's own checkout the
gates are `npm test` and `node --test …` (test runners), `npm run lint` and `eslint packages` (this repository has
an executable `eslint.config.js`, so eslint imports and runs it), `npm run build` and `if npm run build; …` (the
build script is `node scripts/build.mjs`, an interpreter running a program file — a gate that predates all of this
work), and `git rebase` (its own capability, also pre-existing).

These rows are the ecosystems that were measured, not every ecosystem. A repository whose loop is mostly test,
lint and install commands gates more than one whose loop is mostly build, status and diff — the rate is a
property of the LOOP, not of EGO, and quoting a single number for it would be the overstatement this document
exists to avoid. What is invariant across all of them is WHICH KINDS of command gate: test runners, project task
runners, dependency installs, and tools whose configuration is executable.

So the measured rate is **10% on the five-ecosystem sample and 16% here**, and the difference is entirely EGO's own
executable lint configuration and its `node`-driven build. Quoting only the lower number would have been true of
the sample and misleading about the tool.

## Closed after exit review 4 (2026-09-24)

All eight findings the review left open are resolved. Each is recorded with what the fix actually was, because
several turned out to be deeper than the symptom that was filed, and three of the fixes were themselves reviewed
and found defective before they landed.

| Finding | What it really was | Class |
|---|---|---|
| `echo 'rm -rf /' \| bash` | **A PIPELINE IS AN EXECUTION EDGE.** The separator was discarded by segment splitting, so the two stages looked unrelated. The splitter now returns `ShellStage[]` carrying the edge, and the analyzer reads the upstream's LITERAL output as the downstream interpreter's script — or, when it is not readable (`curl … \| sh`), reports opacity. Both ends are read in canonical form, so `env bash`, `timeout 5 sh`, `sudo bash`, `bash -euo pipefail` and `bash 2>&1` are the same edge | 1 |
| `redis-cli --cluster call HOST:PORT` | the node is a later positional the bare-operand scan never reached. The node list is CONTIGUOUS, so the scan breaks at the first operand that is not a node — scanning to the end read a key shaped `prod:1` as a production host and produced an unapprovable false deny | 6 |
| a database host in a client config file | an EXPLICIT `--defaults-file`, `--login-path`, `--defaults-extra-file` or `cqlshrc` is UNCLASSIFIED, like `service=`. The IMPLICIT default option file is deliberately not a signal: no evidence is on the command line, and gating a bare `psql` would gate the ordinary inner loop | 6 |
| `pnpm dlx`, `yarn dlx` | `dlx` means download-and-execute: the runner is no longer transparent, the acquisition is surfaced, and the inner command is still analysed. `npm exec` and `bun x` were found to be ALIASES of `npx`/`bunx` that took a different code path, so the acquisition guard never saw them; they are now rewritten to the one-word spelling | 2 |
| `$(VAR)` in a make recipe | the resolver handed the shell make's PRE-IMAGE. It over-gated (`echo $(VERSION)` read as a substitution) and, far worse, UNDER-gated: a variable's value is spliced in before the shell parses, so `EVIL := ; git push origin main` with `echo $(EVIL)` really did run the push and was ALLOW. `$(shell …)` runs at PARSE time — for any target and for `make -n` — and was invisible everywhere outside a recipe line. There is now a make expansion model: variables, `$$`, automatic variables, the text functions, and `$(shell …)` handed over as the execution it is. An UNDEFINED variable is opaque, because make imports the environment and accepts `make VAR=…` | 3 |
| a heredoc body at the top level | a body is one of THREE things and the shell decides which: a SCRIPT when its reader takes its program from stdin (`bash <<EOF`), an EXPANSION SITE when the delimiter is unquoted (and there is no quoting inside a body at all), or inert DATA. All three are modelled. The producer path had to be fixed with it: `scriptSegments` removed the body but left the opener's `<<DELIM`, which re-opened a heredoc whose delimiter could never arrive and hid every remaining line of the script | 1 |
| `aws --endpoint-url http://localhost:4566` | the cloud CLIs were never enrolled in the target model at all — `classifyTargetName` was dead code for `aws`, `gcloud` and `az`. The family is enrolled, and this is the kernel's ONE de-escalation: for k8s, databases and containers the default asserts LOCAL and the resolver raises it, while for a cloud CLI the default IS the real provider, so LOCAL must replace the hit. Three guards carry that weight: the default is PRODUCTION, the host is compared WHOLE, and only `aws`/`gcloud`/`az` may take the branch | 6 |
| `/opt/x/kubectl get pods` | **ACCEPTED**, unchanged: a path inside the workspace is read, and outside it the system tool is trusted by name. Gating every absolute path would gate `/usr/bin/git status` | — |

## Closed after exit review 6 (2026-09-24)

Ten floor crossings — every one a DENY arriving as ASK, none an unauthorized ALLOW — closed as seven root causes
plus three the generated cross-product found while proving the fixes. They are listed by CAUSE because that is how
they were fixed; the spellings are in `packages/kernel/test/support/corpus.ts`, where each is now a transform or a
class case tested against every other class.

| Cause | The general statement | Class |
|---|---|---|
| `bash -o pipefail -c CMD` | an option's VALUE is not an operand, so the scan for the inline script must step over it | 2 |
| `echo hi;# it's fine` | a `#` comment starts at a WORD boundary, which an unquoted operator makes as surely as a space | 1 |
| `. <(echo CMD)` | `source` and `.` RUN the file they are handed: the gate listed only the interpreters | 1 |
| `echo CMD \| bash <&0` | `<&N` DUPLICATES the descriptor the pipe installed; only a redirection from a FILE replaces it | 1 |
| `DOCKER_HOST=… docker exec box sh` | target sensitivity belongs to the TOOL, not to the capability that won the first match — `docker exec` is script-opaque, and that capability was not enrolled | 6 |
| `sudo bash -c 'CMD'` | a privilege wrapper's tail is a command, and `tokens.join(' ')` is not the inverse of `tokenize`: it erases the quoting that says where a word ends | 2 |
| `echo -e 'a\x20b' \| sh` | `\xHH` and `\0NNN` are text; they are decoded and masked to a byte the way the shell masks them | 1 |
| `if VAR=… docker exec …` | the normalizer stripped the environment prefix ONCE, *before* the shell keywords, so the assignment stayed at the head and no `^`-anchored matcher could match at all | 1 |
| `trap 'DOCKER_HOST=… docker exec …'` | the container engine was enrolled in the target RESOLVER but not in the target-environment RE-ATTACHMENT | 6 |
| the re-attached assignment itself | the resolver read it from `envInputs` only and never as a token: accepted, and unconsumed, one layer down | 6 |

Two of the generated variants were corrected rather than the kernel, and that is recorded because the distinction
matters: `nohup VAR=x cmd` is not a command any shell runs — the shell recognises an assignment only at the start
of a simple command, so `nohup` is handed `VAR=x` as its program name — and `chmod\040777` is `\0407`, a BEL, not
a space, because `\0ddd` takes up to three octal digits. Gating a command the shell would refuse to run is not a
safety property, and asserting a literal the shell would not produce is not evidence.

## Closed after exit review 7 (2026-09-24)

Every finding the review produced is resolved. The six that outlived the first pass are recorded by CAUSE, because
three of them were one cause and that one is now pinned by a property rather than by three lines.

| Cause | The general statement |
|---|---|
| `oc`, `mysqladmin`, `clickhouse client` | **TWO LISTS OF THE SAME THING DRIFTED.** The resolver keeps tool heads in code; the control plane keeps head alternations in `matchers.md`. These three were in the resolver and in neither matcher, so no capability matched, `retargetLocalCapability` had nothing to re-target, and the command fell through to `command.unknown`. Pinned by *PROPERTY: every tool the target model knows reaches the target model* — which immediately found a seventh instance of itself, `nerdctl` |
| `AWS_ENDPOINT_URL_S3=…localhost aws iam delete-user` | **A SERVICE-SCOPED ENDPOINT IS EVIDENCE ABOUT THAT SERVICE.** It points the S3 client at an emulator and says nothing about IAM. The unscoped `AWS_ENDPOINT_URL` still covers every service, which is what LocalStack really does |
| `PUBSUB_EMULATOR_HOST=… gcloud compute instances delete` | the same statement for the Google emulator variables, against a product that has no emulator at all |
| `{ echo 'git push origin main'; echo ls; } \| sh` | **A GROUP WRITES THE CONCATENATION OF WHAT ITS COMMANDS WRITE,** so the upstream of a pipe fed by one is the whole group. Only the last stage was being read, so the first line of the script was invisible |
| `flock /tmp/build.lock -c 'npm test'` | the CARRIER had no matcher, so the standard idiom for serializing a build reached `command.unknown` while its body was analysed correctly |

### The second pass: the findings whose effect lives in a FILE

Thirteen more were never verified in the first pass, because their effect is in a workspace file rather than on the
command line. All reproduced; all closed. Eight were make shapes the parser could not see (`X != CMD` running while
make parses, a rule line indented with SPACES, `.PHONY-thing` matching `.PHONY`, a WILDCARD include, an included
makefile the same makefile REMAKES, a target-specific rebind on a `::` rule, a PATH entry judged before `/usr/..`
was resolved away, and an IMPLICIT `%.o: %.c` rule that is now RESOLVED rather than merely reported blind). One was
a whole producer: **a Dockerfile is a producer**, and `docker build .` executes every `RUN` line as root with the
whole context copied in, while EGO resolved Makefiles, manifest scripts and shell scripts and treated this one as
opaque. Two were git's content filters: a clean filter runs on `git status` and `git diff` as well, and the read
verbs were excluded for a reason — Git LFS — that the exemption now NAMES; and the test for an included config file
is WHO PULLS IT IN, not where it sits.

### Closed as well, from the full sweep of all 157 findings

Every self-contained finding was re-run against its expected floor. That sweep closed nine more by cause: an image
that IS a CLI carries that CLI's command line (`docker run … amazon/aws-cli iam delete-user`), awk forks a shell
whose command is a string expression that is often a LITERAL, a rendered production release is a credential read
(`helm get manifest|values|all`), the variables that name a program (`SWIFT_EXEC`, `JAVA_TOOL_OPTIONS`, `LD_AUDIT`),
`--cap-add=CAP_SYS_ADMIN` with the prefix docker also accepts, a marker the normalizer appended being hidden by an
operator inside a REF NAME, `git checkout .` discarding the whole working tree, and — twice more — `join(' ')`
used where `requote` was needed, because the quoting is what says where a word ends.

### The last three, and what became of them

Two of the three were closed by RESOLVING them rather than by declaring a verdict, which is the difference
between an answer and an opinion.

- **`git revert <commit>` is judged by what the commit it names actually touched.** Neither blanket answer was
  right: DENY made an everyday act an absolute deny in any governed repository, because the path route reaches
  `.harness`; ALLOW let `git revert <the commit that hardened the control plane>` undo a matcher unattended. Git
  knows which files the commit touched, so the write is judged as the write it is, and a commit-ish the kernel
  cannot resolve stays fail-safe. Pinned by *PROPERTY: a revert is judged by what the commit it names actually
  touched*.
- **A recursive delete of a DERIVED directory destroys nothing that cannot be regenerated.** `rm -rf
  node_modules` is the most routine recovery command in JavaScript development, and `dist`, `target`,
  `__pycache__`, `vendor`, `Pods` and their siblings are build output by convention in their ecosystems. The list
  is AUTHORED in `control-plane/permissions/matchers.md` so an organization can shorten it; every other recursive
  deletion keeps `command.destructive`, and a path that leaves the workspace or reaches a protected tree is still
  judged on the path and still denied.

One stays, as a decision:

| Command | Verdict | Why it is not raised |
|---|---|---|
| `podman login -u bot -p hunter2 …` | ASK | The review's expectation was DENY. A password on a command line is a leak a human should SEE, and the remedy (`--password-stdin`) exists — but docker itself only WARNS about the inline form, and a DENY would refuse a legitimate registry login that no human could then approve. `command.credential-exposure` puts it in front of a person, which is what the gate is for. |

That one is not an unauthorized ALLOW; it is the designed human gate. The next fresh review is the criterion, not
this list.

## Closed after exit review 8 (2026-09-28)

Every unauthorized ALLOW the review produced is resolved. What remains below the reviewer's floor at HEAD 161c610
is 19 rows where EGO ASKS and the reviewer wanted DENY — the designed human gate — and 26 proportionality rows
where EGO asks about something the reviewer would allow. Neither is an unauthorized ALLOW.

The review's own lesson, recorded by CAUSE rather than by instance:

| Cause | The general statement |
|---|---|
| **The shell deletes a backslash-newline before it parses anything.** | `do\<newline>cker` is `docker`. The line-continuation is removed by the lexer, ahead of every other rule, so any parser that tokenises first reads a head that will never exist. Removed before tokenization now, verified against bash, zsh and dash. |
| **A filename is what the FILESYSTEM says it is.** | macOS folds `ſ` to `s` and `K` (U+212A) to `k`, so `.harnesſ/runtime/pin.json` IS the governance tree. Paths are compared on `p.normalize('NFC').toUpperCase().toLowerCase()`. |
| **Looking at something is not doing it.** | `git config core.hooksPath` reads; `make -n` prints; `sed -n '1p'` prints; `psql -h /tmp` is a unix socket DIRECTORY; `influx -host localhost` is a Go-style LONG option; `aws s3 cp s3://… .` downloads; `cp README.md ..` writes into a directory that only "contains" `.harness` because it contains the checkout. Ten absolute DENYs over INSPECTIONS — and an absolute deny is the one verdict a human cannot approve, so this shape of false positive removes the gate instead of raising it. |
| **A readable command is not opacity.** | `command.script-opaque` ASKS, correctly, for text nobody can read. sed's `e`, git's `-O<pager>`, a Dockerfile in a heredoc and `--pathspec-from-file` all carried their command as plain text and still arrived there. Each now feeds the canonical analyzer; the streams that genuinely cannot be read stay opacity. |
| **A tool the matchers name and the analyzer does not is a hole with a sign on it.** | nerdctl was in the privileged-mount matcher and absent from the bind-mount resolver, so the identical docker line was DENY and nerdctl ASK. Pinned by `PROPERTY: every tool the target model knows reaches the target model`. |
| **The flag is what makes the tool a writer.** | Judged as writers unconditionally, `sed` and `perl` refused every READ of a governed file; judged never, `ruby -i -pe` and `gawk -i inplace` rewrote one. One question, asked once, in `editsInPlace`. |
| **A carrier anchored at token 0 sees no wrapper.** | `sudo git …`, `FOO=bar sed …` and a single-command `bash -c "…"` body all hid the same three carriers, because the normalizer returns strings and the quoting that makes a program ONE WORD is gone by then. Found by the in-repo cross-product, twice, after I had added the carriers. |

Three fixes in this review were themselves found defective before they landed, and two of those were found by
attacking my own last two commits: `git rm` classified ALLOW without judging its pathspecs; an "in-place edit is
an ordinary write" rule that swallowed `perl -i -e '<code>'`; `sed -f script.sed OPERAND`, where the operand is
an INPUT and not the script; and `/` excluded from the ancestor test because `/` + `/` is `//`.

## Closed after exit review 9 (2026-09-29)

Every unauthorized ALLOW of exit review 9 is resolved, and so is every defect of the self-attack on its own
fixes. Four findings stand REFUTED by settled decisions, each pinned by a test that failed when the change was
attempted: renaming a LOCAL branch (`git branch -m`), merging a NAMED branch, `helm get values` against
production being a credential dump (exit review 7), and `rsync` into `.git/hooks` keeping its
`fs.git-internals.write` classification rather than the narrower hook one.

Recorded by CAUSE. The instances are in the build log; these are the statements.

| Cause | The general statement |
|---|---|
| **The shell expands braces before it expands anything else, and unconditionally.** | Unlike pathname expansion it does not care whether the file exists, so `.harnes{s..s}/runtime/decisions/d1.json` IS one word naming EGO's own decision records, and `--no-verif{y..y}` IS the hook-bypass flag. Every literal reader below the lexer was reading a word that will never exist. Asserted by a DIFFERENTIAL test against `/bin/zsh`, not by inspection. |
| **A carrier's quoting stands where the body should be.** | Every reader that works on the SEGMENT AS WRITTEN — the redirection scan, `git -C`, the commit argv, brace expansion — sees `sh -c "…"` instead of what it carries, because an inner shell runs its own expansion pass. Re-entering EVERY body is NOT the fix: a duplicate hit changes the decisive capability and defeats the LOCAL de-escalation. The condition names the readers that need it. |
| **Looking at something is not doing it — and an absolute DENY over looking removes the gate.** | 24 findings: a dry run, a help probe, a question mode, a syntax check, a read verb, a word inside an option VALUE, a copy whose first operand is the SOURCE. A human cannot approve a DENY, so this shape of false positive is worse than a noisy one. |
| **Every exception that lets an operator LOOK is a spelling that can hide the ACT.** | The mirror of the line above, and the whole content of the self-attack. `--dry-run=none` executes and persists; `EXPLAIN ANALYSE` executes what it wraps; `help` is a verb and `--version` a flag, not any word; `ln -s SRC DIR` puts the link INSIDE the directory; `make -q` still parses, and a parse-time `$(shell …)` runs. An exception must be a claim about the WHOLE act, tested on the text as written. |
| **An opacity must never REPLACE a stronger verdict.** | A producer marked STALE returned a null body, discarding contents it had already read — so an absolute deny became approvable the moment any earlier segment could not be classified. What was read is handed over; the staleness is a gap. And staleness is consulted BEFORE absence, because absence is a positive claim too. |
| **A reached cap is not an absence** — met three more times. | The brace-expansion budget, the conditional branch-value budget, and the default-goal candidate cap were all silent. Each now reports, and the resolution becomes PARTIAL. |
| **A rule under a broad ALLOW is a rule that never runs.** | Matching is first-match-wins per segment. Three rules added in this review had to be MOVED above the matchers that shadowed them, and three of five were still ALLOW after the first placement — which is how that was discovered. |

Three mistakes in the fixing itself, kept because the pattern is the point: a `!== null` comparison on a function
returning a BOOLEAN; a `for` without braces that put the condition outside the loop; and a psql metacommand
spelled as a PREFIX with an optional backslash, so `db.dropDatabase()` matched as `\d`. All three were caught by
a test within minutes of being written, two of them by the generated cross-product.

## Closed after exit review 10 (2026-09-30)

179 findings (100 unauthorized ALLOW, 79 over-gated DENY) and the eleven more that freezing them into the corpus
found. Every one is closed, refuted, or recorded below. Recorded by CAUSE; the instances are in the build log and
in `packages/kernel/test/exit-review-10.test.ts`.

| Cause | The general statement |
|---|---|
| **The directory a line runs in is what the earlier segments LEFT, not what they SAY.** | A directory change binds the rest of the line only where the shell applied it in THIS shell, unconditionally: not in a pipeline stage, a background job, a substitution, a subshell, a function body, a branch or a `case` arm, and not when it was `cd -` or `popd`. Doubt is CARRIED to what follows and no positive claim may rest on it. A directory change is recognised by what the shell resolves the word to (`directoryChange()`): `'cd'`, `c\d`, `c""d`, `builtin cd` and `command cd` are the builtin, and a test for the text `cd` saw none of them. |
| **A parser and a shell read different words.** | The shell removes quoting, expands braces and globs and cuts a rule line at a semicolon BEFORE the word reaches any reader. Every reader must be handed the word the shell will see, or report that it was not. Pinned against `/bin/zsh` and GNU make 3.81, not against a description. |
| **A reader must be reachable from every carrier — two copies of one list.** | The condition that decides whether a carried body is re-read named `git -C` and `env -C` but not `--chdir`, and demanded whitespace before the word where a quote can stand. `sh -c 'flock l -c "env --chdir=…"'` never re-entered. |
| **The tool looks where it looks, not where the workspace ends.** | `npm run build` walks up past the registered root; `docker build -f F <url>` runs the REMOTE Dockerfile; a make target-specific variable's value includes its `;` and what follows; `[core] hooksPath` moves the hooks. A producer must read what the tool reads, from where the tool looks, and report what it cannot. |
| **A write is a write behind a wrapper.** | The freshness ledger read the head of the raw segment, so `env cp evil.mk sub` recorded nothing. It reads the normalized head, as every other reader does; an extraction behind a wrapper is unenumerable too. A symlink is a second name for its target FROM THE NEXT SEGMENT ON — the `ln` that creates it is not a write through it, which is the proportionality half of the same statement. |
| **Looking is not doing — an absolute DENY over looking removes the gate.** | 77 findings, thirty from one cause (`--help`). The exception is a claim about the WHOLE line: last word, not an option value, no `--`, a verb that carries no argv elsewhere, unquoted. Its mirror is pinned: a NAME or a VALUE that spells `help` is not the flag. |
| **A reached bound, or a subprocess that could not answer, is not an absence.** | A git configuration too large to list, an awk program past the read bound, a brace nesting past the expander: each is ASK, with the reason, and never the same as "nothing there". |
| **An enumeration is wrong by omission.** | Tools that name their write destination by a flag (`--tsBuildInfoFile`, `--metafile`, `prettier --write`), names a credential file is given (a wildcard tail is asked of them), hook directories, engine environment variables. Where a list must exist it is derived from the matchers or asked of a sample, and the sample is the thing under test. |
| **"Only narrows" has to hold in every mode.** | An overlay matcher was checked against the BASE table; a mode can release the capability to ALLOW. The compile step now refuses any overlay mapping to a capability some mode overrides to ALLOW. |

### Recorded, not closed

- **OPEN PRODUCT DECISION — `SELECT` against a production database.** `psql -h prod-db.acme.com -U ro -c 'SELECT
  1'` is an absolute DENY. A SELECT can call `pg_terminate_backend()`, `setval()`, `lo_import()` or take a
  `FOR UPDATE` lock, and EGO does not parse SQL, so the exception for read statements is a short allowlist
  (`\d…`, `SHOW`, `EXPLAIN` without `ANALYZE`, `-l`). The exit reviewer expects ASK for a plain SELECT. Making it
  ASK is a one-line change with a real cost — a mutating function call becomes approvable instead of refused. It
  is recorded as OPEN, not as ACCEPTED_PRODUCT_BEHAVIOR.
- **DENY → ASK by design.** A brace nesting past 8 (the expander reports it), an awk program file past the read
  bound, and a `cd` inside a branch, loop or function followed by a relative write. The kernel cannot say which
  word, program or directory it is looking at, so it asks. Each is asserted as `ASK`, not left unpinned.

## Closed after the self-attack on the fixes of exit review 10 (2026-09-30)

121 confirmed (110 unauthorized ALLOW, 11 over-gated DENY), from ten lenses; every one closed, refuted or recorded. By CAUSE:

| Cause | The general statement |
|---|---|
| **One reader per dimension — two copies of one list drift.** | Whether a line is a help probe, where a `$( )` ends, how make's command line reads, which directory a command runs in, and which statements of a database client are reads were each decided by two or three pieces of code. They now have one each (`helpProbeHead`, `scanSubstitutionBody`, `parseMakeCommandLine`, `runDirectory`, `isReadStatement`), and the duplicated matcher was deleted rather than corrected. |
| **A working directory is a SET.** | `cwdTimeline`: a conditional change leaves both possibilities; `&&` holds for the rest of its chain and leaves the earlier directory possible afterwards; `||` runs on failure; a branch, a loop, a function and a case arm are unioned; a subshell is a scope; `cd` is recognised by what the shell resolves the word to. Verified for soundness against bash and zsh, not asserted. |
| **A strict grammar beats a blocklist.** | A read of a production database is `\d…`, `SHOW …`, `DESCRIBE t [col]`, `EXPLAIN …` without ANALYZE, `-l`, `-V` — and nothing that merely lacks a write verb (`created_at` contains `create`; `\g` ends a statement in mysql without a semicolon; `--exe` is `--execute`). |
| **A path is stale when it or an ancestor was written.** | Case-folded; through a symlink to a directory; after a glob, a rename, a directory made in the same command, a loop's next iteration, a hard link, `sort -o`, `uniq IN OUT`, `find -exec`, `sed w`. |
| **Names are families, values are parsed.** | `*_PROXY`, `*_REGISTRY`, `*_INDEX_URL`, `*_ENDPOINT*`; the host of a URL with userinfo (`localhost:80@evil.example`); `NODE_OPTIONS` judged by an allowlist of inert options; every assignment of an `export` list; an assignment behind `then`/`do`/`else`; `GIT_TRACE*` as the write it is. |
| **A redirection is not an operand, and a quoted `>` is not a redirection.** | `cp x f 2>&1` has the destination `f`; `git commit -m "why > f is refused"` writes nothing. `mysql < file` is judged as the read it is. |
| **A search tool reads a glob the way the search tool does.** | Braces with a slash inside, backslash escapes, a doubled suffix (`.env.*.local`); a web search is public egress whatever it filters its results to. |
| **A premise of mine was wrong, and the fix built on it with it.** | See the build log: GNU make's target-specific variable takes the whole tail as its value. |

### Recorded, not closed

- `kustomize build .` where `kustomization.yaml` lists a REMOTE resource fetches it (LOW). The kernel asks only when a URL is on the command line.
- `cd a b` (zsh's substitution form) and a `popd` with nothing pushed in the same command make the directory UNKNOWN, which is the honest answer and an ASK for what follows it.
- An `env -C`/`git -C` in play disables the alternative-directory judgement for that segment (the directory it names is judged on its own).
- `CGO_ENABLED=0 go build` asks: `CGO_*` is in the execution-input list a producer gate reads. Unchanged from before this pass.

## OPEN after exit review 11 (2026-09-30) - and the decision this document owes the product owner

258 findings (209 unauthorized ALLOW, 49 over-gated DENY), zero new classes. About 30 were fixed in the same sitting
(listed in the build log). **The remaining ~225 are OPEN**, and they are recorded by cause rather than by instance because
the instances are not the point:

| Cause (lens counts in brackets) | What is open |
|---|---|
| **A table is wrong by omission** (runners 13, policy-layer 13, containers 13, k8s-cloud 13, db 8) | tools that run a program named by their OWN option or config: `clang --ld-path`, `gcc -fuse-ld`, `prettier --config`, `eslint -f ./x.js`, `pylint --init-hook`, `npm --script-shell`, `yarn-path`, `bun test`, `python -m black`; `docker buildx bake` (≈10 spellings: the bake file names Dockerfiles and targets), `docker pass`, `docker debug --host`, `buildx create --driver remote`; `kubectl --cluster`, `config view --flatten`, `get -f s.yaml` of a Secret, `--kubeconfig` with a kind context; `dbmate --env`. (The database-client rows - `sqlite3 … writefile()/edit()`, `psql -o '\|cmd'`, `mysql -e'…'` - are CLOSED, see below.) |
| **A path is judged by its spelling, not by the file** (fs-paths 14, hostapi 7, absolutes 12, errors 4) | a symlink whose NAME contains a glob character; `git checkout-index --prefix=.git/hooks/`; `tar --extr`/`--use=`; `cat .e*` and other wildcard shell operands that reach credential stores. (A leading space in a tool `file_path` and a write through a symlink to a path that does not exist yet were in this row; both are closed - see "Structured tool surface" below. So are `..` after a link at every shell site, a quoted path with padding, and `echo x > /dev/disk0`, a raw device that a redirection used to drop with the null device - see security-model.md, "A shell word is judged by what it resolves to".) |
| **A reached bound is still not an absence, on surfaces that were not wired** (limits 8, expansion-new 14) | `env env env …` nested past the depth cap, a `cd` chain past the path cap, `flock -c "flock -c …"` nested past four, a brace budget over 64 in `Glob`/`Grep` (the overflow report was wired only into the Bash loop). |
| **Carried commands and producers** (carriers 14, producers-deep 14, claims 14) | `find … -exec` payloads of several kinds; `timeout -s KILL`, `env --unset A` before `sed 'w …'`; `yarn exec git -C …`; `watch 'git commit -nm x'`; a Dockerfile written in the same command before `docker buildx bake`; `lint-staged` config written or chosen by a variable; a `make -f ev*.mk` glob; `DF=x; docker build -f "$DF"` (a variable assigned earlier names the file). |
| **Variables a line assigned** (claims, carriers, crossproduct) | partly closed (literals substituted; a run-time writer operand asks). Still open: `O=--context; docker $O production rm -f app`, `R=secret; kubectl get $R`, a variable holding a SUBCOMMAND or an OPTION. |
| **Proportionality** (proportionality 14, exceptions 4, profiles 13) | 49 over-gated DENY, most of them a dry run or a listing with a redirection or an extra flag: `git push --help >/dev/null`, `git push -vn`, `git grep core.hooksPath`, `git config --file … --get`, `gh api -X GET`, `cat ~/.ego/trust/keys.json` (a READ of the trust store), `grep -rn '~/.ssh' docs`, `find . -name '*.tmp' -exec rm {} \;` (pre-existing). |
| **Environment and bounded-command tables** (markers 8, bounded 1, policy-layer) | `printf -v PATH …`, `read PATH`, `HELM_PLUGINS=`, `git -c man.man.path=… log --help`, `bash -n +n`, `node version`. |
| **Overlay and profile edges** (overlay 6, profiles 13, taxonomy 10) | an overlay-protected path after the overlay's matcher is deleted from the tree; `service-account.json`/`secrets/*` patterns; STRICT not narrowing `git pull --no-ff`. |

### CLOSED after the audit of 2026-10-01: the database-client family (class: a known client and an operand it does not bound)

A database client handed something that makes it run a program, write a file outside its database or load native code kept
the plain-client verdict `db.local.query` (ALLOW). Two of the findings were CRITICAL and are closed: review-11 #102 and #130
(`sqlite3 :memory: "select writefile('.git/hooks/pre-commit', …)"` put an executable git hook on disk), and #131
(`mongosh --eval` with an alias of `require`). The earlier fixes had each closed one spelling (`.shell`, `\!`, `COPY … TO
PROGRAM`); the family is now read by ONE grammar per client (`dbClientEscape` in `evaluate.ts`) - what is positively known to
be harmless is ordinary and everything else is opaque:

- **sqlite3**: a statement is ordinary only when it starts with ordinary DML/DDL and every call is on the pure list (so
  `writefile`, `readfile`, `fsdir`, `edit`, `zipfile`, `load_extension`, `ATTACH`, `VACUUM INTO` and `CREATE VIRTUAL TABLE` ask);
  a dot-command only by its WHOLE name from a short read-only list (sqlite3 accepts any unambiguous prefix, so `.sh` is
  `.shell`); the database file operand is judged as a write.
- **psql**: options from psql's own list; `-o`/`--output`/`-L` and the meta-commands `\o \g \gx \w \s \copy \lo_export` hand a path
  to the path rules and a pipe to the opaque class; an editor, an include, `\setenv`, `\gexec` and a backquote in any argument
  are opaque; server-side `COPY`, `pg_read_file`, `lo_export`, `DO`, `LOAD`, `CREATE FUNCTION/EXTENSION`, `ALTER SYSTEM` ask.
- **mysql/mariadb**: options from the client's own list (abbreviations resolve only when unambiguous); `pager`, `system`,
  `source`, `edit`, `delimiter`, `connect` and their backslash forms are opaque; `tee` is a write; `INTO OUTFILE`, `LOAD DATA`,
  `load_file()`, `SET GLOBAL` ask. `mysqlsh` runs scripts and is not read.
- **mongosh/mongo**: an inline script is ordinary only as one recognised statement (`show`, `use`, or `db.<collection>.<method>`
  with literal arguments and cursor modifiers) - never a callback, an unknown identifier, `$where`, `$function`,
  `$accumulator`, `$out` or `$merge`. The blocklist matcher in `matchers.md` is removed.
- **redis-cli/valkey-cli**: `MODULE`, `CONFIG SET`, `REPLICAOF`, `DEBUG`, `SHUTDOWN`, scripting, `MIGRATE`, `ACL`/`CLUSTER`
  changes ask; `--rdb` is a write.
- **clickhouse-client**: a table function or clause that reaches a file, a URL, a bucket, another server or a program asks, even
  against a local server; `--pager`, `--history_file`, `--config-file`, `--queries-file` ask.
- **Environment**: `PSQLRC`, `PSQL_PAGER`, `PSQL_EDITOR`, `PSQL_HISTORY`, `PGSYSCONFDIR`, `LIBMYSQL_PLUGIN_DIR`, the history
  variables and `OPENSSL_CONF` join the enumeration in `ENV_INJECT_RE`.
- A statement the shell fills in at run time (`-c "$STATEMENT"`) is not read and asks, for every client.
- An option the reader does not know asks (it cannot be called inert) but is not KNOWN to leave the database, so on a
  production host it is a question and not a refusal; an option known to run something (`mysql --pager`) or a
  program-valued output is refused there.

Against a production host the same escape is no longer the plain-SELECT read: it is refused (DENY). Pinned by
`packages/kernel/test/closure-db.test.ts` and by the corpus classes in `test/support/corpus.ts` (`db` family). Not covered, and
still ASK for another reason: `cqlsh`, `influx`, `pg_dumpall`/`pg_restore`/`pgbench`, `mysqladmin` and `clickhouse
local` are unmodelled producers (`command.unmodelled-closure`); `flyway`/`liquibase` apply a migration FILE and are the
`db.local.migrate` class. (`pg_dump` and `mysqldump` are the plain-client class; since the second wave below they ask only
for what they do, not because the file they write is called `dump.sql`.)

### CLOSED in the second wave of the audit of 2026-10-01: the producer and profile leftovers of the first wave

Pinned by `packages/kernel/test/closure-producers.test.ts`.

- **make names are make's, not the shell's** (closure audit F20). A rule's targets, its prerequisites, an `include` and a
  `.DEFAULT_GOAL` were each split on whitespace by a regular expression that also cut the head at the first colon, `=` or `#`:
  `a\ b:` registered the targets `a\` and `b`, `a\:b:` and `a\#b:` were not rules, and `make 'a b'` found no rule, so the goal came out
  absent and its recipe ran at ALLOW. One reader (`readMakeNames`) now answers "what are the names here" for all four, checked
  against GNU make 3.81: a run of backslashes in front of a blank, colon or hash halves and an odd one out escapes it, a backslash in
  front of anything else stays; a command-line goal is one name whatever it holds. A wildcard in a target or a prerequisite (`dep*:`)
  names whatever files exist, so it is a rule the text does not name (blind, like a pattern rule). Not modelled: make's tilde
  expansion of a goal.
- **`npm_config_<name>` is the key `<name>`** (npm lowercases the variable and turns the underscores after the first character into
  hyphens, the prefix in any case). The variable family was an enumeration of the dangerous names and `node-options` was not on it:
  `npm_config_node_options='--require ./evil.js' npm run build` was ALLOW. The variable is now read by the keys npm accepts, the other
  way round: a short list of keys that execute nothing and redirect nothing (presentation, notices, install policy, network
  limits) stays ordinary, an empty value is ignored as npm ignores it, and every other key asks. The keys that name a program or a
  module (`onload-script`, `init-module`, `node-gyp`, `editor`, `git`, `browser`, `viewer`, `scripts-prepend-node-path` beside
  `script-shell`, `shell` and `node-options`) are one table read by the flag, the `.npmrc` and the variable spellings; a flag is also the
  key it abbreviates, because npm takes any unambiguous prefix (`--node-opt` is `--node-options`, verified on npm 11). The flag and
  `.npmrc` readers remain a list of the keys that run something, because most `--words` before a script name are options of the
  command and not configuration keys.
- **`lint-staged` reads the configurations below the working directory.** Since 13 it uses the configuration nearest to each staged
  file, found with `git ls-files` (tracked, and untracked-not-ignored), so a `.lintstagedrc` under `packages/a` runs on the files staged
  there even when it is started at the root. The classifier does not start git for this (a repository can name a program in its own
  configuration, `core.fsmonitor`): the tracked paths are read from the index file (layouts 2, 3 and 4, a worktree's `.git` file followed;
  a sparse or split index is a problem, not a short list) and the untracked ones from a walk that skips only what the ignore files
  provably exclude and the nested repositories git lists as one entry. Bounds: 20000 config-named tracked files, 20000 untracked entries
  the walk looks at (tracked entries are free), 128 MiB of index and 2M listed entries; a reached bound, an unreadable index or a
  directory that cannot be listed is an ask that says so, never "nothing there". A configuration, an ignore file or a directory the
  command writes below the working directory earlier in the same command makes the answer STALE. `--shell <path>` is an unresolved gap.
  `pnpm lint-staged` and `yarn lint-staged` (the binary, when no script has that name) are resolved as `lint-staged`; they used to keep
  the class of an unbounded matcher prefix and never read the configuration.
- **A stricter profile is never looser than a weaker one.** `narrow` is not inherited, so `git merge --no-ff topic` was ASK under
  STRICT and ALLOW under HIGH_ASSURANCE. The compiler now refuses a control plane in which STANDARD <= STRICT <= HIGH_ASSURANCE fails for
  any capability in any mode (`PROFILE_ORDER`); on the shipped plane it found exactly `git.local.merge` and `git.local.cherry-pick`, which
  `high-assurance.md` now lists.
- **A dry run that a word of the shell could undo is not a dry run.** `kubectl --context production apply -f x.yaml --dry-run=client
  $FLAG` was ALLOW although `$FLAG` may be `--dry-run=none`. Against a target that is not a declared local one the line is judged as the
  act when a word the shell fills in stands where a flag can stand: after a verb that takes no names (`apply`, `replace`, `create -f`,
  `delete -f`), after the operands `helm upgrade|install|rollback|test|push` take, or as the name of an option. The value of an option that
  takes one, a word that starts with a literal non-dash character and a name slot are not flags. **Residual, recorded:** a verb that names any
  number of objects (`delete TYPE NAME...`, `label`, `helm uninstall`) cannot tell a name from a flag by position, so `kubectl --context
  production delete --dry-run=client pod x $MORE` is read as names - which is what keeps `pod $NAME`, the ordinary preview of a delete, out
  of the refusals.
- **Database proportionality.** The net that asks when a client "runs an unread program" matched a file NAME by extension anywhere on
  the line, so `pg_dump app > dump.sql` and `sqlite3 app.db .dump > dump.sql` asked because their output file ends in `.sql`. The
  extension is now a statement about what a client READS: a redirection target and the value of an output option are subtracted
  one-for-one and judged as writes by the path rules (so `pg_dump app -f .git/hooks/pre-commit` is a write to a hook, not a pass, and
  `mysqldump app -r .git/hooks/pre-commit`, which was ALLOW, is no longer). A client's option is spelled as it is (`-Fc` is a format, not
  `-f`). A statement is data for the path scan: a word of it that names no directory is not a path, so the SQL operator `~` was no longer the
  home directory. And `~`, `~*`, `!~`, `!~*` are accepted by the plain-SELECT grammar, with the backslashes of a single-quoted literal (not an
  escape string, not in front of a quote) read as data, so `select ... where code ~ '^\d+$'` against a production host is the read it is
  and not an absolute refusal.
- **Recorded, not closed.** A bare `c` in a statement followed by three words is read as psql's `\c` reconnect (`... where c = 1 and d = 2` on a
  statement that is not a read): the host it names is a word of the SQL. `kubectl ... apply --help $FLAG` is not recognised as a probe. `oc` is
  not a bounded command. The nested-configuration walk does not read `core.excludesFile`; a directory it cannot prove ignored it walks.
  The matcher `pnpm\s+(build|lint)` / `yarn\s+(build|lint)` in `matchers.md` has no word boundary, so `pnpm lint-anything` keeps the build
  class whenever no script has that name (only `lint-staged` is resolved; the others fall back to a binary EGO does not model).

### The decision (OPEN - not taken here)

Twelve reviews establish two things. **The architecture is closed**: eleven classes, none added since review 1 of this series,
and each is enforced as a general property over a generated cross-product (40,000+ combinations) that has found defects no
reviewer reported. **The instance set is not**: 187 → 136 → 190 → 121 → 258, each round closing exactly what it was shown.

The kernel's failure mode is an **unauthorized ALLOW for an input nobody listed**, because it allows by default and denies
by pattern. Three honest options, none of which this phase can choose:

1. **Amend the exit criterion to the one the taxonomy already states** - class closure, a generated cross-product that
   holds, and every KNOWN finding closed or recorded - and close Phase 1 with the residual stated as a containment
   dependency (issue #26: the classifier is defense in depth, the boundary is the OS sandbox). Cheapest; true to the data.
2. **Invert the default for the highest-risk surfaces**: ALLOW only for a short positive list of command shapes with
   strict grammars (the way a SQL read is now a grammar, not a blocklist), ASK for everything else. Unknown becomes a
   question instead of a yes, and the unauthorized-ALLOW set becomes bounded by construction. The cost is proportionality:
   ordinary commands outside the list ask until they are added, and the list is itself a product surface.
3. **Keep the loop.** One cycle costs about 40M subagent tokens for the review alone, an hour of wall-clock for it, and several hours of
   fixing; the evidence is that it will produce another ~200 findings. It is the option the current criterion implies, and it is reported here as one that has not converged
   in five cycles.

## A validation gate that lives in a temporary directory is not a gate

The 200,334-command attack corpora that earlier rounds reported were ad-hoc text files in a session temporary
directory. That directory has since been cleaned, so the figure cannot be reproduced at any later commit, and the
gate it represented no longer exists. Recorded because the lesson generalises: evidence that cannot be re-run is
not evidence.

The permanent replacement is `packages/kernel/test/support/corpus.ts`, which is IN THE REPOSITORY and GENERATED
rather than accumulated — 67 root semantic classes × 97 transformations × 60 producers, asserting **23,924**
combinations, and growing by one line per new transformation.

The proportionality probe that lived beside those corpora is gone too, and it is not missed: `corpus.test.ts`
enforces the same property in the repository, over 103 ordinary commands across seven ecosystems, and every one
that gates is named with its reason in `EXPECTED_GATES`. A gate that only exists while a shell session is open is
the same non-gate twice.

## The parallel-test failure, and a diagnosis this document got wrong

It was recorded here as "several test processes materialising the same content-derived source identity at once, on
a cold start". **That is not the mechanism, and it needs no concurrency at all** — it needs ONE long-lived process
and ONE write to the distributed tree:

- `selfIdentity()` computes the runtime identity ONCE per process and caches it. `node --test` runs each test FILE
  in one process, so `cli.test.ts` caches it at its first `ego init` and keeps it for all nineteen tests.
- The identity is a hash over the 56 files `package.json#files` distributes — `control-plane/**`, `docs/**`,
  `dist/**`, `bin/`, `runtime/posix/`. `packages/**` and `tests/**` are NOT in it, so editing `evaluate.ts` never
  moved it, and editing `docs/build/build-log.md` — which AGENTS.md REQUIRES every phase — always did.
- `initProject` wrote the PIN and then called `materializeRuntime`, which re-reads the live tree and throws when
  the second reading differs. The throw was unguarded, so every later `ego init` in that process left the project
  PINNED AND UNGOVERNED: no policy cache, no generated artifacts, no hook shim. The failures are a SUFFIX of the
  file, which is exactly the "8 of 19" shape.

That explains every control — serial passes, the file alone passes, the second run passes — without appealing to
CPU starvation, and it was reproduced in a SINGLE process with one write. Two further defects in the same function
came with it, and all are closed:

- **HASH-THEN-COPY.** `materializeRuntime` verified the live tree and copied it afterwards, so a write landing
  between the two produced a cache directory named by one identity whose bytes hash to another — with no error at
  all — which `verifyRuntimeDirectory` later called TAMPERED. EGO corrupting its own cache and then blaming
  tampering. It now hashes the COPY, so the name is a fact about the bytes.
- **TOCTOU ON PLACEMENT.** `existsSync(target)` followed by an unguarded `renameSync` made the loser of a race
  throw ENOTEMPTY. Losing that race is SUCCESS: the winner's bytes hash to the same value by construction.
- **A FAILED CACHE POPULATION MUST NOT LEAVE A PROJECT UNGOVERNED.** The runtime cache is a launcher optimisation;
  the policy cache, the artifacts and the hooks are the governance.
- `selfVersion()` shelled out to git on each of its twelve call sites and was not memoized, so one process could
  have produced two versions if a git call ever failed. Nothing was observed going wrong; an identity must not
  depend on a subprocess succeeding the same way twice.

MEASURED AFTER THE FIX: the same deliberate provocation — editing `docs/build/build-log.md` AND
`control-plane/permissions/matchers.md` while the parallel suite runs — goes from 8 failures to 1, and that one is
a trust assertion reading an identity that genuinely moved, not a half-initialised project. With the tree settled,
the first parallel run passes. Editing the distributed tree WHILE the suite runs is still not a supported
condition: the identity really does change, and EGO is right to say so. What changed is that saying so no longer
leaves a project pinned and enforcing nothing.

REMAINING, recorded rather than fixed: `detectProject` lists a repository's SIBLINGS with
`readdirSync(dirname(gitRoot))`. Every fixture is created in the system temp directory, so each `ego init` stats
every temp entry on the machine and the cost grows with everything any run ever left behind. The corpus now keeps
its own hundreds of fixtures under one parent, which removes the largest contributor; the O(n) scan itself is a
performance defect, not a verdict defect, and is left for Phase 2.

Three of these fixes were themselves found defective by review before they landed, and the record is kept because
the pattern is the point: a first cut at the pipeline edge tested the RAW segment, so every wrapped interpreter
escaped it; a first cut at the redis node scan ran to the end of the line and denied an ordinary key; a first cut
at the heredoc modelled only the inert case and poisoned the producer path. None of them was a new architectural
class, and each was caught by asking what the SHELL does rather than what the parser does.

## CONTAINMENT_DEPENDENCY

The semantic action is intentionally permitted. What it may reach is issue #26's problem, and **#26 is not built**.

| Action | Permitted because | What #26 must guarantee |
|---|---|---|
| `cargo build` | compiling code already acquired is ordinary work. **Residual risk, stated:** a cold cache makes cargo acquire too, and every dependency's `build.rs` runs at compile time | build steps execute under the profile's filesystem and network boundary |
| `docker compose up` | see above | the four guarantees listed above |
| `go build`, `tsc`, `javac`, the C/C++ toolchain, **with their default flags** | compile source to objects and execute nothing else. The flags that make them run a program — `-B`, `-wrapper`, `-fplugin=`, `-specs=`, `-toolexec`, `-processor` — are classified as unbounded program operands and gate; the row was written before they were, and was false until then | writes confined to the checkout and the runtime root |
| an approved ASK | a human approved a specific action, not an unbounded session | the approval's blast radius is bounded by the profile, not by the classifier |

`cargo run` is NOT in that row: it builds and then EXECUTES the result, so it gates as an unmodelled closure like
any other runner. An earlier revision of this table listed it as permitted, which the code never did.

**The seam between an install and a build**, stated once: *acquiring* third-party code and running it is a human
gate; *compiling* code already acquired is a containment dependency. The seam is imperfect — a cold cargo cache
acquires — and it is drawn here deliberately rather than left implicit, because drawing it somewhere is the only
alternative to gating every build in every ecosystem.

## Structured tool surface: closed 2026-10-01, and what stays recorded

Audit of 2026-10-01 re-ran the structured-tool findings (apply_patch headers, WebSearch, MCP trust, unknown tools, operand
shapes, the Codex adapter) and criterion check C3. Closed and pinned in `packages/kernel/test/closure-tools.test.ts`, at the
evaluator and through the real hook path of both hosts: an indented or padded `apply_patch` header (any Unicode
whitespace, CRLF, after an Add / Delete / Update) is a header; an unrecognised `*** ` header refuses the patch; a write
through a symlink whose target does not exist yet is judged by the target (the resolver is shared with the shell); `..`
after a link; a path with leading or trailing whitespace or a NUL; `WebSearch` with a `url` key; an optional operand
that is present and not a string; a second operand-shaped key beside a tool's own; the Codex argv / JSON `arguments`
shapes; the MCP trust wording in the host matrix, the `ego init` template and the capability page.

| Item | Class | Severity | Disposition | Why it stays recorded |
|---|---|---|---|---|
| A shell redirection or writer operand with `..` AFTER a symlink (`echo x > d/../settings.json`, `d -> .claude/sub`) | a path is judged by its spelling | MEDIUM | **CLOSED 2026-10-01 (closure wave 2, paths)** | The shell layer joined the working directory and a word with `resolve()` at about forty places, which applies `..` to the text. One resolver (`authority/paths.ts`, `pathCandidates`) now answers "what may this word denote" for every site - the lexical and the physical reading, as written and trimmed, in every directory the shell may be in - and each site judges all of them and keeps the worst. Pinned by `closure-paths.test.ts` (a redirection, writer and option operands, an extraction, a `find -exec` payload, a `cd` set, a shell standing in a link, the file a reader opens, a link whose name holds a space, and the resolver checked against open(2)) and by corpus classes in families `fs` and `command`. Recorded limits are in security-model.md, "A shell word is judged by what it resolves to". |
| `docker build -f "my docs/Dockerfile" .` (a space in the path) is ALLOW | the normalizer drops the quoting a producer needs | MEDIUM | **MUST_FIX (open)** | Found while closing the shell path layer (closure wave 2, paths) and NOT caused by it: `make -C "my docs"`, `awk -f` and the shell-script producers either read the right file or ask, but the Dockerfile producer takes `-f` and the build context from the normalised words, reads a file called `my`, finds none and reports an absence it never verified. A Dockerfile whose `RUN` line is a locked command is then not seen. The fix is the producer reading the segment as written (or the normalizer keeping a word with whitespace whole), which changes what every matcher sees; deferred rather than guessed at. |
| The Codex `apply_patch` parser differential | a path is judged by its spelling | HIGH if Codex trims as upstream suggests | **UNVERIFIED until conformance (K4)** | EGO's reader is now a superset of what the upstream parser (`codex-rs/apply-patch`, read from a summary, not executed here) accepts as a header; whether the installed Codex agrees line for line is confirmed only by a conformance run on a machine with Codex installed. Over-reading can only add write targets, never hide one. |
| Whether a host forwards undeclared or mistyped operand keys to `PreToolUse` | operand shape | LOW | **FAIL-SAFE** | A spec-valid host rejects them first. If it does not, they now ask (`command.unknown`) and any path or command they name is classified. |
| Hook `allow` for `TodoWrite` / `BashOutput` | proportionality | LOW | **ACCEPTED_PRODUCT_BEHAVIOR** | Listed by name in `INERT_HOST_TOOLS`; every other unmodelled tool still asks. `ExitPlanMode` and `AskUserQuestion` ask on purpose (a hook `allow` would suppress the prompt that is their function). |
| Codex `bash -lc <script>` is judged as the script | claims | LOW | **ACCEPTED_PRODUCT_BEHAVIOR** | The exact three-element wrapper is the host's own spelling of "run this script"; login-shell start-up files are the host's baseline, not model input. Any other wrapper shape keeps its words and asks. |
| `mcp.local.*` / `mcp.remote.*` unreachable | unmodelled producer | MEDIUM | **UNKNOWN_PRODUCER/FAIL-SAFE** | Every `mcp__` tool is `mcp.unknown` (DENY); the resolver is phase-2 work (issue #10). |

## What this changes about the exit criterion

A finding is an **unresolved Phase-1 defect** only when it is MUST_FIX. A finding classified into one of the other
three is a *recorded decision*, a *working fail-safe*, or a *named requirement on #26* — and counting those as
defects is what made the previous rounds look like they were not converging when the contract was in fact holding.
