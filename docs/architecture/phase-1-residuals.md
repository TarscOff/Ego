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

### Three that stay as they are, deliberately

| Command | Verdict | Why it is not raised |
|---|---|---|
| `podman login -u bot -p hunter2 …` | ASK | A password on a command line is a leak a human should SEE; refusing it outright would block a legitimate registry login that no human could then approve. `command.credential-exposure` exists for exactly this. |
| `git revert <commit>` | ASK | DENY was tried and is disproportionate: the path route makes it an absolute core deny in any repository containing `.harness`, i.e. every governed repository. Reverting a commit is deliberate enough to ask and ordinary enough not to refuse. |
| `rm -rf node_modules` | ASK | `command.destructive` asks for every recursive deletion, `rm -rf build` included. That is the standing policy, and the ordinary-development corpus accounts for it. |

None of the three is an unauthorized ALLOW; each is the designed human gate. The next fresh review is the gate,
not this list.

## A validation gate that lives in a temporary directory is not a gate

The 200,334-command attack corpora that earlier rounds reported were ad-hoc text files in a session temporary
directory. That directory has since been cleaned, so the figure cannot be reproduced at any later commit, and the
gate it represented no longer exists. Recorded because the lesson generalises: evidence that cannot be re-run is
not evidence.

The permanent replacement is `packages/kernel/test/support/corpus.ts`, which is IN THE REPOSITORY and GENERATED
rather than accumulated — 34 root semantic classes × 87 transformations × 35 producers, asserting 11,645
combinations, and growing by one line per new transformation.

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

## What this changes about the exit criterion

A finding is an **unresolved Phase-1 defect** only when it is MUST_FIX. A finding classified into one of the other
three is a *recorded decision*, a *working fail-safe*, or a *named requirement on #26* — and counting those as
defects is what made the previous rounds look like they were not converging when the contract was in fact holding.
