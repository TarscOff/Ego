# Phase-1 residual reconciliation

Decision of 2026-09-23, restated on 2026-10-01. Eight independent challenges produced findings faster than they could be argued about, and
the backlog had stopped distinguishing three different things: a hole, a decision, and a boundary EGO has not built.
Every finding is either CLOSED or carries **exactly one** of four dispositions, and only a MUST_FIX counts as an unresolved Phase-1 defect.
The per-finding record is [`phase-1-findings-register.md`](phase-1-findings-register.md); this document keeps the reasoning behind the dispositions.
Until 2026-10-01 this paragraph read "every remaining HIGH/MEDIUM finding is classified here", which was not true of the ~225 open review-11
findings, recorded by cause only; the register is what makes it true.

| Kind | Meaning | Counted as an unresolved defect? |
|---|---|:--:|
| **MUST_FIX** | a real unauthorized effect can still reach ALLOW | yes |
| **ACCEPTED_PRODUCT_BEHAVIOR** | intentionally permitted by an explicit prior product decision | no — but the boundary and the residual risk are stated |
| **UNKNOWN_PRODUCER / FAIL-SAFE** (`FAIL_SAFE` in the register) | EGO does not model the closure, or errs towards refusal (an over-gated DENY), so ASK/DENY applies | no — this is the contract working; an over-gated DENY is a class-11 debt, not a security defect |
| **CONTAINMENT_DEPENDENCY** | the semantic action is permitted; its blast radius belongs to issue #26 | no — but #26 owes a named guarantee, and a CRITICAL row is never recorded this way |

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

**Proportionality cost, re-measured on 2026-10-01 (`0111e63`: 123 commands, 14 gated, 11.4%) and on the closure tree (2026-10-07).** The
ordinary-development corpus of `packages/kernel/test/support/corpus.ts` (`ORDINARY`) holds **412 commands in 25 groups** (git, shell, node,
python, go, rust, jvm, container, database, kubernetes, make, pipelines, structure, inspection, and the groups each closure wave added for the
surface it touched), plus 30 commands run against real Makefiles (`ORDINARY_MAKEFILES`). **17 of the 412 gate (4.1%)**, and each is named
with its reason in `EXPECTED_GATES`:

| Gated | Commands | Why |
|---|---|---|
| 8 test runners | `npx vitest run`, `npx jest`, `pytest`, `pytest -q tests/`, `go test ./...`, `cargo test`, `mvn test`, `./gradlew test` | they execute repository code located by pattern |
| 1 install | `pip install -r requirements.txt` | acquiring and running third-party code |
| 4 JVM builds and probes | `mvn -v`, `mvn -q compile`, `gradle --version`, `./gradlew build` | unmodelled producers ask in every invocation form, version probes included |
| 1 network read | `aws s3 cp s3://my-fixtures/data.json ./data.json` | a download from a cloud store |
| 3 inline programs | `python3 - <<'PY' …`, `node - <<'EOF' …`, `python3 -c '…'` | an interpreter runs a program the kernel has not read |

`corpus.test.ts` asserts the EXACT set and the exact size of the corpus (412), and fails if a command gates without an entry in
`EXPECTED_GATES`, if one listed there quietly becomes ALLOW, or if the corpus changes size without the count being changed deliberately, so a
rising gate rate cannot arrive unnoticed. Git, shell, container, database, kubernetes, pipeline and structural commands (395 of the 412) never gate.

The earlier version of this section quoted four ad-hoc samples (10% on a five-ecosystem sample, 16% on EGO's own checkout, 18% on seven
ecosystems, and a C/C++ note). Their scripts no longer exist, so none of them can be re-run; they are retired, for the reason given in "A validation gate
that lives in a temporary directory is not a gate". What is invariant, and is what the corpus pins, is WHICH KINDS of command gate: test runners,
project task runners, dependency installs, and tools whose configuration is executable. The rate is a property of the LOOP, not of EGO: a repository
whose loop is mostly test, lint and install commands gates more than one whose loop is mostly build, status and diff.

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

Every finding the review produced was resolved at the time. Re-measured on `0111e63` and again on the closure tree of 2026-10-07 (register): 82 of the 110 recorded findings are CLOSED and 28 cannot be replayed, because the review-7 data kept the command and not the Makefile, manifest or hook it ran against. The six that outlived the first pass are recorded by CAUSE, because
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

All 131 unauthorized ALLOWs of the review are CLOSED on the closure tree (replayed 2026-10-07; first on `0111e63`, 2026-10-01; register), 5 of them now ASK where the reviewer wanted DENY, which is the designed human gate. This paragraph used to read "Every unauthorized ALLOW the review produced is resolved", measured at HEAD 161c610; it was not true of `c54d8b2`, where the 2026-10-01 audit reported the fourth spelling of the function-binding finding (`git() { echo hi; } | cat`, newline, `git push origin main`, CRITICAL, r8-39) ALLOW again. It is DENY on `0111e63`. The DENY-arriving-as-ASK rows were 19 at 161c610 and are 6 here (the rest are DENY now); the 26 proportionality rows counted at 161c610 are not in the review-8 data file and are not re-measured.

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

Of the 86 findings of exit review 9, 84 are CLOSED on the closure tree and 2 are settled decisions recorded below (`git branch -m`, `helm get values` on production). Of the 50 findings of the self-attack on its fixes, 48 are CLOSED and 2 are OPEN and recorded: sa9-40 (MEDIUM, FAIL_SAFE: `cp .claude/hooks/pre-commit.sh /tmp/backup.sh`); sa9-42 (MEDIUM, MUST_FIX: `Write to <repo>/.claude/skills/evil/run.sh`). The sentence that stood here before 2026-10-01, "every unauthorized ALLOW of exit review 9 is resolved, and so is every defect of the self-attack", was true of the first and not of the second. Four findings stand REFUTED by settled decisions, each pinned by a test that failed when the change was
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
found. On the closure tree: all 100 unauthorized ALLOWs are CLOSED; of the 79 over-gated DENYs 79 are CLOSED and none is OPEN (the four FAIL_SAFE rows of 2026-10-01 - reads of the cluster tools refused in PRODUCTION_ADVISORY, a heredoc delimiter that made the evaluator throw, `ssh -Q cipher` under HIGH_ASSURANCE - are CLOSED). The sentence that stood here before 2026-10-01, "Every one is closed, refuted, or recorded below", did not record the four FAIL_SAFE rows that measurement found. Recorded by CAUSE; the instances are in the build log and
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

- **DECIDED 2026-09-30 (commit `c54d8b2`) — `SELECT` against a production database is a read.** `psql -h prod-db.acme.com -U ro -c 'SELECT 1'`
  is ALLOW by a strict positive grammar (`isPlainSelect`). INTO, FOR UPDATE, LOCK IN SHARE MODE, PROCEDURE, WITH, a comment of any kind, a
  user-variable assignment, a dollar-quoted body, a qualified or quoted call, any function not on the pure list and a statement over 4,000
  characters stay the act they are (DENY). This bullet used to record the question as OPEN and expected ASK; the owner decided it the other way, and
  it is pinned by `select-read.test.ts`. A SELECT can still reach a function nobody listed - that residual is the pure-function list, which is
  a short allowlist, not a blocklist.
- **DENY → ASK by design.** A brace nesting past 8 (the expander reports it), an awk program file past the read
  bound, and a `cd` inside a branch, loop or function followed by a relative write. The kernel cannot say which
  word, program or directory it is looking at, so it asks. Each is asserted as `ASK`, not left unpinned.

## Closed after the self-attack on the fixes of exit review 10 (2026-09-30)

121 confirmed (110 unauthorized ALLOW, 11 over-gated DENY), from ten lenses. Re-measured on the closure tree (2026-10-07): 119 CLOSED, 2 OPEN and recorded (sa10-63, LOW, MUST_FIX: `cp evil.mk hard.mk && make all`; sa10-107, LOW, CONTAINMENT_DEPENDENCY: `kustomize build .`). On `0111e63` (2026-10-01) 14 were OPEN, two of them CRITICAL (sa10-33, sa10-34, through listed neighbours); both are CLOSED and pinned. By CAUSE:

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

## OPEN after exit review 11 (re-measured 2026-10-01, and again on the closure tree on 2026-10-07)

Exit review 11 reported 258 findings (209 unauthorized ALLOW, 49 over-gated DENY) and no new class. The first version of this section recorded
about 225 of them as OPEN "by cause only", with no severity and no disposition per finding. That was an estimate, and it is replaced by a measurement:
[`phase-1-findings-register.md`](phase-1-findings-register.md) replays every per-finding record of exit reviews 7-11 and of the two self-attacks (935 rows)
on the Phase-1 closure tree (closure audit waves 1-6 merged; the first measurement, on `0111e63` after wave 1, is in the register's history) and records,
for each row, the reviewer's severity, the taxonomy class, the cause group, the status on this tree and, for an OPEN row, one disposition with its reason.
Every number below is computed from that table by script.

**Exit review 11 on this tree.** 258 rows: 227 CLOSED, 31 OPEN (30 unauthorized ALLOW, 1 over-gated DENY), 0 not replayable.

| Severity | UA rows | UA CLOSED | UA OPEN | of those MUST_FIX | CONTAINMENT_DEPENDENCY | OG rows | OG OPEN |
|---|--:|--:|--:|--:|--:|--:|--:|
| CRITICAL | 16 | 16 | 0 | 0 | 0 | 1 | 0 |
| HIGH | 119 | 119 | 0 | 0 | 0 | 15 | 0 |
| MEDIUM | 66 | 40 | 26 | 19 | 7 | 23 | 0 |
| LOW | 8 | 4 | 4 | 4 | 0 | 10 | 1 |

Closure wave 1 moved review 11 from "about 225 OPEN" to 191 OPEN (measured 2026-10-01); waves 2-6 moved it to 31. Every CRITICAL and every HIGH spelling the review reported is CLOSED; what stays OPEN is 0 CRITICAL, 0 HIGH, 26 MEDIUM, 5 LOW, each recorded with its disposition below and, one by one, in the register.

**All reviews, by cause group.** 37 rows are OPEN across the seven datasets (exit reviews 7-11, self-attacks 9 and 10); severity is the reviewers', disposition is this register's. The spellings are the rows' own, as the register shows them.

| Cause | OPEN | C | H | M | L | MUST_FIX | CONTAINMENT_DEPENDENCY | FAIL_SAFE | ACCEPTED_PRODUCT_BEHAVIOR | What is open |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|---|
| **A** A table is wrong by omission | 11 | 0 | 0 | 9 | 2 | 5 | 5 | 0 | 1 | `git branch -m main evil`, `helm template x https://evil.example/chart.tgz`, `git stash push -ua`, `gh api https://evil.test/x`, `git pull --rebase`, `git fetch origin main:main --force`, … (11 rows) |
| **B** A path is judged by its spelling, not by the file | 9 | 0 | 0 | 7 | 2 | 8 | 1 | 0 | 0 | `clang -MD -MF .git/hooks/pre-commit -c a.c`, `ar x x.a`, `node --experimental-strip-types .probe/tool.ts Grep '{"pattern":"KEY","pa…`, `node --experimental-strip-types .probe/tool.ts Read '{"file_path":"{DIR}/…`, `file -C -m control-plane/magic`, `cd /Users/tarik/Desktop/EGO && node --experimental-strip-types .probe/pro…`, … (9 rows) |
| **C** A reached bound is still not an absence | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | - |
| **D** Carried commands and producers | 5 | 0 | 0 | 4 | 1 | 3 | 2 | 0 | 0 | `make`, `prettier --check .`, `eslint .`, `cp -ft . d/Makefile && make build`, `cp evil.mk hard.mk && make all` |
| **E** Variables a line assigned | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | - |
| **F** Proportionality | 3 | 0 | 0 | 1 | 2 | 0 | 0 | 2 | 1 | `helm --kube-context production get values billing`, `docker -H tcp://prod.acme.com:2375 logs x`, `cp .claude/hooks/pre-commit.sh /tmp/backup.sh` |
| **G** Environment and bounded-command tables | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | - |
| **H** Overlay and profile edges | 9 | 0 | 0 | 8 | 1 | 9 | 0 | 0 | 0 | `git branch feature`, `git pull --no-ff origin main`, `git branch x (profile STANDARD, mode PRODUCTION_ADVISORY: 'node --experim…`, `git branch feature-x`, `black .`, `git pull --no-ff origin main`, … (9 rows) |
| **S** Shell structure and lexing | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | - |

**The dispositions.**

- **MUST_FIX (25).** 0 CRITICAL, 0 HIGH, 20 MEDIUM, 5 LOW. The effect reaches a floor (production, the control plane, a hook, a credential store, `--no-verify`, a push) or the gap is in a *modelled* tool's own documented option; "in doubt" is MUST_FIX. They fall into 9 root causes (RC-MK, RC-K8S, RC-WRT, RC-OPT, RC-MODE, RC-PTH, RC-NET, RC-GIT, RC-DB), each a second reader of a question that has a first one; the register names the single reader that would close each and reproduces every row. By this document's definition they are unresolved defects; the amended criterion lets the phase close with them RECORDED (none is CRITICAL), and they are carried into Phase 2 as the first work on the readers they name.
- **CONTAINMENT_DEPENDENCY (8).** `prettier --check .`, `eslint .`, `rustc --codegen linker=./ld.sh x.rs`, `javac --processor-path ./proc X.java`, `cargo fmt (config: .cargo/config.toml with [alias] fmt = "run --bin evil …`, `rubocop -r ./evil.rb`, `prettier --check . with package.json {"prettier":"./evil.js"}⏎prettier --…`, `kustomize build .`: a runner, compiler or tool told to load a program, or a producer that fetches a remote resource. Running the tool is ordinary work and its option set is open-ended, so the classifier cannot be complete; the named spellings should still be added to the table, but only the OS sandbox of issue #26 bounds the class. 0 CRITICAL, 0 HIGH, 7 MEDIUM, 1 LOW.
- **FAIL_SAFE (2).** `docker -H tcp://prod.acme.com:2375 logs x`, `cp .claude/hooks/pre-commit.sh /tmp/backup.sh`: an over-gated DENY (or an evaluator crash the hook turns into a block). Wrong in the safe direction, not a security defect, but a class-11 debt: an absolute DENY over looking removes the human gate instead of raising it (see "Looking at something is not doing it" above).
- **ACCEPTED_PRODUCT_BEHAVIOR (2).** r9-24, r9-40: renaming a local branch (`git branch -m`) and `helm get values` against production, both REFUTED by decisions recorded in the sections above.

### CRITICAL rows that remain

For every one of the 184 replayable CRITICAL unauthorized-ALLOW rows the reported spelling no longer reaches ALLOW: 184 are CLOSED outright (5 of them now ASK where the reviewer wanted DENY). **No CRITICAL row is OPEN on this tree** - the three that were OPEN on `0111e63` through a listed neighbour (r11-142, sa10-33, sa10-34) are CLOSED and pinned - and 7 cannot be replayed. Condition 4 of the amended criterion ("no CRITICAL finding is unresolved") holds for every row the data can replay; the unreplayable rows are recorded, not closed:

- r7-4, r7-5, r7-7, r7-8, r7-9, r7-32, r7-33 (review 7, unauthorized ALLOW): the review-7 data kept the command and not the fixture it needed (a Makefile, a manifest, a hook). The same families are CLOSED in review 8 with their fixtures (`make deploy` r8-8..12, `npm run build prodk` r8-16..18, nested `make` r8-95..96); nothing proves these seven, so they are not called closed.

### What the earlier text of this section got wrong

- "About 225 of the 258 are OPEN" - measured on `0111e63`: 191 OPEN, 67 CLOSED; on the closure tree: 31 OPEN, 227 CLOSED.
- The table listed the database-client rows and the structured-tool rows as "CLOSED, see below"; both are CLOSED on this tree (re-replayed) and stay recorded in the two sections below.
- It named no severity and no disposition for any row; the register does.
- (2026-10-07) The measurement of 2026-10-01 recorded r11-119 (an overlay narrowing removed from the working tree taking effect at once) OPEN by a script that imported an earlier worktree, not the tree under measurement. On the closure tree the removal of an overlay narrowing is a pending widening (`tableWidenings` and `clampToBaseline` in `policy/cache.ts`, closure audit wave 6) and the row is CLOSED. r11-255 (a formatter, a build or a test runner passing the pre-promotion gate as a read) was CLOSED by a fix of 2026-10-07, not by the waves.


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

### The decision (taken by the product owner on 2026-10-01)

Twelve reviews establish two things. **The architecture is closed**: eleven classes, none added since review 1 of this series,
and each is enforced as a general property over a generated cross-product that has found defects no reviewer reported. **The instance set is not**:
187 → 136 → 190 → 121 → 258, each round closing exactly what it was shown.

The kernel's failure mode is an **unauthorized ALLOW for an input nobody listed**, because it allows by default and denies by pattern. Three options were put to the
owner on 2026-09-30:

1. **CHOSEN (2026-10-01): amend the exit criterion** to the one the taxonomy already states - class closure, a generated cross-product that holds, and every KNOWN
   finding closed or recorded - and close Phase 1 with the residual stated as a containment dependency (issue #26: the classifier is defence in depth, the
   boundary is the OS sandbox). Cheapest; true to the data.
2. *Not chosen.* Invert the default for the highest-risk surfaces: ALLOW only for a short positive list of command shapes with strict grammars (the way a SQL read is
   now a grammar, not a blocklist), ASK for everything else. It would bound the unauthorized-ALLOW set by construction at the cost of proportionality, and the list is itself a
   product surface. It stays available; nothing here forecloses it.
3. *Not chosen.* Keep the loop. One cycle costs about 40M subagent tokens for the review alone, an hour of wall-clock for it and several hours of fixing, and the
   evidence is that it produces another ~200 findings; it has not converged in five cycles.

**A second decision, taken the day before and implemented in `c54d8b2`: a plain `SELECT` against a production database is a read.** `psql -h prod-db.acme.com -U ro -c
'SELECT 1'` is ALLOW by a strict positive grammar (`isPlainSelect`); the earlier text of this document recorded it as an OPEN product decision and expected ASK. INTO, FOR
UPDATE, LOCK IN SHARE MODE, PROCEDURE, WITH, a comment of any kind, a user-variable assignment, a dollar-quoted body, a qualified or quoted call, any function not on the
pure list and a statement over 4,000 characters stay the act they are (DENY); re-checked on `0111e63` and on the closure tree (`select-read.test.ts`).

**The amended exit criterion** replaces "a fresh independent review finds no unauthorized ALLOW", which was not met (twelve reviews ran) and is replaced, not satisfied.
Phase 1 closes only when ALL of the following hold:

1. The class list is closed: twelve consecutive independent reviews produced no new class ([`phase-1-taxonomy.md`](phase-1-taxonomy.md), eleven classes).
2. Every class is enforced as a general property by the generated cross-product (`packages/kernel/test/support/corpus.ts`), and that suite passes.
3. Every KNOWN finding is either closed and pinned by a deterministic test, or recorded with class, severity and disposition ([`phase-1-findings-register.md`](phase-1-findings-register.md)).
4. No CRITICAL finding is unresolved.
5. The residual - an unauthorized ALLOW for an input nobody listed - is stated as a containment dependency owned by issue #26: the classifier is defence in depth, the OS sandbox is the boundary.

**Status on the closure tree (2026-10-07; first measured on `0111e63` on 2026-10-01).**

- (1) holds: the exit review of 2026-10-07 (six of seven reviewers returned; 52 findings) produced no new class, as the twelve reviews before it did not; its findings are instances of classes 1, 2, 6, 9, 10 and 11 and of the two invariants (one of which it showed false for one path, now repaired).
- (2) holds: the generated cross-product and the whole suite pass on a clean clone of the closure tree (typecheck, lint and every touched test file on the closure tree; the full cold run - both suite passes and the release build - was in progress when the sitting was cut off and is recorded in the build log as IN PROGRESS, never as passed unread).
- (3) is met for the 935 rows the data kept: 870 are CLOSED (424 with the reported spelling literally in a test file; the other 446 are pinned by a differently spelled test of the same class or by the generated cross-product, which the register cannot tell apart), 37 are OPEN and recorded with class, severity and one disposition, and 28 review-7 rows could not be replayed and are recorded as such. The 83 findings of contract-challenge rounds 10-12 kept a severity and no command; they are recorded, not closed.
- (4) holds for every replayable row: no CRITICAL row is OPEN; 7 CRITICAL review-7 rows are not replayable (their families are CLOSED with fixtures in review 8) and are recorded, not closed.
- (5) is stated here, in the register and in the taxonomy. It is not recorded on issue #26 or issue #1: writing to those issues is the owner's act, and the paste-ready text is in `docs/build/phase-1-handoff.md`.

**Phase 1 is CLOSED on 2026-10-07 under the amended criterion**: conditions (1)-(5) hold as stated above, the residual is recorded
and owned by issue #26, and the build log carries the four check lines in force and the record of the exit review. What a reader must
not take from this: that the classifier is a boundary. It is not, and the first lines of `security-model.md` say so.



## Exit review 13 (2026-10-07): the closure review, what it found, what was fixed and what is recorded

*Re-measured on the final tree after these fixes: 869 CLOSED, 38 OPEN, 28 not replayable. One row re-opened: r11-122 (MEDIUM, FAIL_SAFE) - a recursive CONTENT read of EGO_HOME (`grep -r sha ~/.ego`) is a credential read since AX-3, while `du -sh ~/.ego` and `find ~/.ego -name '*.json'` keep their ALLOW.*

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

The findings, one row each (status: FIXED with the test that pins it, PARTIAL, CLOSED (ASK) where the human gate applies, or RECORDED with
the disposition this document uses; the class is the reviewer's, in their words):

| id | sev | kind | class | status / disposition | what |
|---|---|---|---|---|---|
| AX-1 | C | UNAUTHORIZED_ALLOW | 10 Policy layering (instance; root in 9 Path classification: | FIXED · closure-authority2 B. AX-1 (the fallback joins the worst-of; a ~/ rule matches only under HOME) | Library, temp workspace W (no real home touched): write '.harness/overlay/matchers.md' = |
| AX-2 | H | UNAUTHORIZED_ALLOW | 10 Policy layering and administration | FIXED · q98-vocabulary B7c (the question names the widenings it accepts) | Real repo, human 'ego init --offline'; the agent writes policies/organization/permissions.md (push -> 'Require |
| AX-3 | H | UNAUTHORIZED_ALLOW | 9 Path classification (credential store) | FIXED · bypass (the seal key is a credential store) | 'node .probe/probe.ts' equivalents with egoHome set: Bash 'cat ~/.ego/policy-seal.key' -> ALLOW command.read-o |
| AX-4 | H | UNAUTHORIZED_ALLOW | 6 Target classification (sibling of wave-5 AUTH-1: prd1/eksP | FIXED · q98-local-targets, closure-clusters2 AUTH-1 (a marker glued to a word) | Project layer .harness/local-targets.md with k8s_local_contexts: ['app*'] (accepted: 3 literal characters) com |
| AX-5 | M | UNAUTHORIZED_ALLOW | 10 Policy layering | RECORDED · MUST_FIX | Session record .harness/runtime/sessions/<id>.json with grants ['ego.policy.accept','command.unknown','command |
| AX-6 | L | OTHER | 10 Policy layering | RECORDED · RECORDED | seal-attack.ts case 7: a cache sealed by this key, written by runtime C with acceptedLayerSources = current la |
| AX-7 | L | CRASH_OR_HANG | none needed (robustness of a read-only command) | RECORDED · MUST_FIX | 'ego authority diff <file> core' where <file> is {...core, organizationLocked: null} (adminGoverned removed) - |
| AX-8 | L | OVER_GATED | 11 Proportionality | RECORDED · FAIL_SAFE | 'node ~/.ego/runtimes/<id>/dist/ego.js init' -> DENY ego.trust.tamper HARD_LOCKED (absolute, no human can appr |
| AX-9 | L | OTHER | 10 Policy layering | RECORDED · RECORDED | hook-failclosed.ts: a hook run with EGO_HOME=<repo>/.harness/h creates the directory and policy-seal.key insid |
| AX-10 | L | UNAUTHORIZED_ALLOW | 9 Path classification | RECORDED · MUST_FIX | 'echo x > .envrc' -> ALLOW fs.repo.write; direnv would export EGO_HOME/PATH into the human's shell for later ' |
| AX-11 | L | OTHER | none needed (host payload robustness) | RECORDED · RECORDED | PreToolUse payload with cwd: 42 -> exit 0 allow for 'ls' (evaluated with a numeric cwd). |
| RVDBX-1 | M | UNAUTHORIZED_ALLOW | 6 Target classification | RECORDED · MUST_FIX | node --experimental-strip-types .probe/rv-db-exit/ev.ts with 'flyway migrate', 'dbmate up', 'liquibase update' |
| RVDBX-2 | M | OVER_GATED | 11 Proportionality / 3 Producer resolution | RECORDED · FAIL_SAFE | ev.ts with mysql --init-command="set names utf8" -e "select 1" (also --init-command="SET sql_mode=''", "set au |
| RVDBX-3 | M | OVER_GATED | 6 Target classification / 11 Proportionality | RECORDED · FAIL_SAFE | ev.ts with 'redis-cli -h redis get foo', 'redis-cli -h redis hgetall h', 'redis-cli -h redis mget a b c', 'mon |
| RVDBX-4 | M | OVER_GATED | 6 Target classification | RECORDED · FAIL_SAFE | ev.ts with 'psql -h db -c "update t set a=1"', 'psql -h postgres -c "insert into t values(1)"', 'mysql -h mysq |
| RVDBX-5 | M | UNAUTHORIZED_ALLOW | 6 Target classification | RECORDED · MUST_FIX | ev.ts with "psql -v d=database -c 'drop :d app'" (and with a trailing -c 'select 1') |
| RVDBX-6 | L | OVER_GATED | 11 Proportionality | RECORDED · FAIL_SAFE | ev.ts with 'psql -c "select 1 /* comment */"' |
| RVDBX-7 | L | OVER_GATED | 6 Target classification | RECORDED · FAIL_SAFE | ev.ts with 'clickhouse client -q "select 1"' vs 'clickhouse-client -q "select 1"' |
| RVDBX-8 | L | OVER_GATED | 6 Target classification | RECORDED · FAIL_SAFE | ev.ts with "mysql -e 'DROP /* c */ DATABASE app'" |
| RVDBX-9 | L | OTHER | 11 Proportionality (soundness, no floor crossed) | RECORDED · RECORDED | prod.ts psql/mysql with 'select 1 \n drop database app' (newline, no semicolon) |
| RVP6-1 | C | UNAUTHORIZED_ALLOW | 9 Path classification (link creation / recursive copy as une | FIXED · closure-paths RVP6-1 (cp -s / cp -l / ln make a second name) | FILE source, no pre-existing link, plain '/./':  node --experimental-strip-types .probe/probe.ts 'cp -s .harne |
| RVP6-2 | H | UNAUTHORIZED_ALLOW | 1 Segment structure (here-string body) + PA-01 operand flow; | FIXED · closure-paths RVP6-2 (a here-string is what xargs reads) | node --experimental-strip-types .probe/probe.ts 'xargs cat <<< ~//.ssh/id_rsa'  (with a real ~/.ssh/id_rsa) -> |
| RVP6-3 | H | UNAUTHORIZED_ALLOW | 9 Path classification (literal-prefix canonicalisation of a  | FIXED · closure-paths RVP6-3 (a glob root matched down to HOME) | In a sandbox whose home directory basename matches the glob: 'grep -r . $HOME/../ho*', 'grep -rn x ~/../ho*',  |
| RVP6-4 | M | UNAUTHORIZED_ALLOW | 9 Path classification / 6 target classification (option-valu | RECORDED · MUST_FIX | With a cloned-repo hostile link ('a b' -> .git/hooks, '{a,b}' -> .claude, home/proj -> ../repo): 'tar -xf arc. |
| RVP6-5 | M | UNAUTHORIZED_ALLOW | 9/11 (PA-09 residual family: an absolute floor reachable at  | CLOSED (ASK) · the human gate applies | 'for f in lgen/*; do echo x > $f; done' (lgen -> .harness/generated) -> ASK, real write to .harness/generated  |
| RVP6-6 | L | OTHER | 1/9 (bound, cross-cutting invariant I) | RECORDED · RECORDED | words.ts restoreQuoting MAX_HOSTILE_WORDS=64 and dataflow.ts MAX_WORDS=64 silently drop the surplus; a segment |
| SH-EXIT-1 | H | OTHER | 2 (Wrapper transparency); boundary with class 1 (segment str | FIXED · closure-shell SH-EXIT-1..3 (redirections moved behind the command) | node --experimental-strip-types .probe/probe.ts '>/dev/null nohup kubectl --context production delete pod x'   |
| SH-EXIT-2 | M | OTHER | 2 (Wrapper transparency) / 1 (segment structure) | FIXED · closure-shell (coproc is a prefix) | node --experimental-strip-types .probe/probe.ts 'coproc kubectl --context production delete pod x'  → ASK (zsh |
| SH-EXIT-3 | M | OTHER | 1 (segment structure) — zsh `=word` (EQUALS) expansion names | FIXED · closure-shell (=cmd is cmd) | node --experimental-strip-types .probe/probe.ts '=rm -rf control-plane'  → ASK (oracle: under zsh '=rm' expand |
| SH-EXIT-4 | L | OTHER | 2 (Wrapper transparency) — a forwarder function defined insi | RECORDED · RECORDED | node --experimental-strip-types .probe/probe.ts 'true && g(){ git "$@"; }; g push origin main'  → ASK (top-lev |
| CX-01 | C | UNAUTHORIZED_ALLOW | 6 (target classification: a Secret read on a production clus | FIXED · closure-containers CX-01 (the words after -- are the type) | node --experimental-strip-types .probe/probe.ts "kubectl --context production get -- secrets"   Also ALLOW: 'k |
| CX-02 | C | UNAUTHORIZED_ALLOW | 6 (target classification: a production database/API target c | FIXED · closure-containers CX-02 (the argv after the image is analysed inside the container; a program nothing classifies stays the container run it was) | node --experimental-strip-types .probe/probe.ts "docker run --rm postgres:16 psql postgresql://admin:pw@prod-d |
| CX-03 | H | UNAUTHORIZED_ALLOW | 9 (path classification: a write destination of a build optio | FIXED · closure-containers CX-03 (--iidfile, --metadata-file, --cidfile are host writes) | node --experimental-strip-types .probe/probe.ts "docker build --iidfile .git/hooks/pre-commit ." '{"Dockerfile |
| CX-04 | H | OVER_GATED | 9 (path classification) and 11 (proportionality): an absolut | PARTIAL · closure-containers CX-04 (no longer an absolute refusal; the path scan still reads the container path as this machine's and asks - open with CX-07) | node --experimental-strip-types .probe/probe.ts "docker run --rm -v /data alpine sh"   Also DENY ABS: 'docker  |
| CX-05 | H | OVER_GATED | 9 (path classification) and 11 (proportionality): a read-onl | FIXED · closure-containers CX-05 (a :ro / readonly mount is a read) | node --experimental-strip-types .probe/probe.ts "docker run --rm -v /etc/localtime:/etc/localtime:ro alpine da |
| CX-06 | H | OVER_GATED | 9 (path classification: host path rules applied to the image | RECORDED · a product decision: U-04 (2026-10-02) judges a ~ or a relative name in a RUN line as the place it would be on this machine, and the corpus pins it; the review asks for the image's reading. Over-gating (FAIL_SAFE) until the owner decides | node --experimental-strip-types .probe/probe.ts "docker build -t x ." '{"Dockerfile":"FROM alpine\nRUN mkdir - |
| CX-07 | M | OVER_GATED | 11 / 9 | RECORDED · FAIL_SAFE | probe.ts "docker run --rm -v ./:/app -w /app node:22 npm test" -> ASK fs.outside-workspace.read 'path argument |
| CX-08 | M | OVER_GATED | 7 (freshness ledger) applied to image paths / 11 | RECORDED · FAIL_SAFE | probe.ts "docker build -t app ." '{"Dockerfile":"FROM debian\nRUN apt-get update && apt-get install -y curl && |
| CX-09 | M | UNAUTHORIZED_ALLOW | 3 (producer resolution: the bake file set is chosen by an en | RECORDED · MUST_FIX | probe.ts "BUILDX_BAKE_FILE=other.hcl docker buildx bake" '{"other.hcl":"target \"a\" {}\n","docker-bake.hcl":" |
| CX-10 | M | UNAUTHORIZED_ALLOW | 3 (producer resolution: an override file in the default set  | RECORDED · MUST_FIX | probe.ts "docker buildx bake" '{"docker-bake.hcl":"group \"default\" { targets = [\"a\"] }\ntarget \"a\" { doc |
| CX-11 | M | OVER_GATED | 3 / 11 | RECORDED · FAIL_SAFE | probe.ts "docker compose build b" '{"compose.yaml":"services:\n  a:\n    build: .\n  b:\n    build: ./sub\n"," |
| CX-12 | M | UNAUTHORIZED_ALLOW | 6 (target classification: the cluster's proxy-url re-routes  | RECORDED · MUST_FIX | probe.ts "kubectl --kubeconfig kc.yaml delete pod x" with kc.yaml: clusters[0].cluster = {server: https://127. |
| CX-13 | M | OVER_GATED | 6 / 11 | RECORDED · FAIL_SAFE | probe.ts "kubectl --kubeconfig ~/.kube/config --context kind-dev delete pod x" -> DENY k8s.nonlocal.mutate 'ku |
| CX-14 | L | OVER_GATED | 11 | RECORDED · FAIL_SAFE | probe.ts "KUBECONFIG=./kc.yaml kubectl get pods" (kc.yaml local, in the workspace) -> ASK command.env-override |
| CX-15 | M | OVER_GATED | 11 (vocabulary; outside this area, reported because it gates | RECORDED · FAIL_SAFE | probe.ts "kubectl --context kind-dev get secret db -o jsonpath='{.data.password}' ¦ base64 -d" -> ASK command. |
| CX-16 | L | UNAUTHORIZED_ALLOW | 6/7 (a plugin is a program) | RECORDED · MUST_FIX | probe.ts "helm --kube-context production diff upgrade app ./chart" -> ALLOW command.read-only; every other unk |
| CX-17 | L | UNAUTHORIZED_ALLOW | 6 | RECORDED · MUST_FIX | probe.ts "kubectl --kubeconfig kc.yaml delete pod x" with context kind-dev -> {cluster: c (127.0.0.1), user: p |
| CX-18 | L | OVER_GATED | 11 | RECORDED · FAIL_SAFE | 'docker build --network host .' -> ASK command.privileged; 'docker context create local --docker host=unix:/// |
| CX-19 | L | UNAUTHORIZED_ALLOW | 2 (wrapper transparency inside a carried argv) | RECORDED · MUST_FIX | probe.ts "docker run --rm alpine sh -c 'python3 -c \"import os;os.system(\\\"git push origin main\\\")\"'" ->  |
| CX-20 | M | TEST_GAP | 11 / 3 | RECORDED · TEST_GAP | No test asserts the ALLOW direction of 'docker run' with '-w DIR', a ':ro' mount, '$(pwd)', or an anonymous '- |
| RB-EXIT-1 | C | CRASH_OR_HANG | Class 11 (proportionality) is the nearest, but this is reall | FIXED · closure-shell RB-EXIT-1 (every re-read of the pending text is paid for: the bound is reached as a question) | node --experimental-strip-types .probe/probe.ts "$(node -e 'process.stdout.write("echo "+"(".repeat(700000)+"; |
| RB-EXIT-2 | H | UNAUTHORIZED_ALLOW | Class 1 (segment structure) + the monotonicity property ('de | FIXED · closure-shell RB-EXIT-2 (a pipe inside a group reads the stage before it) | Plain:  echo 'git commit --no-verify -m x' ¦ bash  => DENY git.hooks.bypass (HARD_LOCK). Grouped alone:  ( ech |

## A validation gate that lives in a temporary directory is not a gate

The 200,334-command attack corpora that earlier rounds reported were ad-hoc text files in a session temporary
directory. That directory has since been cleaned, so the figure cannot be reproduced at any later commit, and the
gate it represented no longer exists. Recorded because the lesson generalises: evidence that cannot be re-run is
not evidence.

The permanent replacement is `packages/kernel/test/support/corpus.ts`, which is IN THE REPOSITORY and GENERATED
rather than accumulated — on the closure tree (2026-10-07) **232 root semantic classes in the 11 taxonomy families (1,374 canonical cases) ×
115 transformations × 77 producers**, plus 412 ordinary commands and 30 Makefile-driven ones (on `0111e63`, 2026-10-01, it was 119 classes,
537 spellings, 98 transformations, 68 producers and 123 ordinary commands, asserting 56,377 combinations by a counting script that is not in
the repository; the suite asserts the floor of every generated combination and the exact ordinary count, not one total, so no total is quoted
here), and growing by one line per new transformation.

The proportionality probe that lived beside those corpora is gone too, and it is not missed: `corpus.test.ts`
enforces the same property in the repository, over 123 ordinary commands in 11 groups, and every one
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
| a runner, compiler or linter told to load a program: `eslint -f ./x.js`, `prettier --config`, `pylint --init-hook`, `rustc -C linker=`, `javac --processor-path`, `clang --ld-path`, `rubocop -r`, `bun test`, `python3 -m <module>`, a cargo alias (15 register rows, root cause RC-RUN) | running the tool is ordinary work and its option and configuration set is open-ended, so no table is complete; the named spellings are added anyway | the program a tool is told to load runs under the profile's filesystem, credential and network boundary |
| `kustomize build .` where `kustomization.yaml` lists a REMOTE resource (LOW, recorded since exit review 10) | the kernel asks only when a URL is on the command line | build steps that fetch run under the profile's network boundary |

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

Under the criterion amended on 2026-10-01 (see "The decision") a finding is an **unresolved Phase-1 defect** only when it is a MUST_FIX row of
[`phase-1-findings-register.md`](phase-1-findings-register.md). A row classified into one of the other three is a *recorded decision*, a *working
fail-safe* or a *named requirement on #26*, and counting those as defects is what made the previous rounds look as though they were not converging when the
contract was in fact holding. The converse is what the previous version of this paragraph allowed: a MUST_FIX recorded under a kind that is not counted. A
CRITICAL row is never recorded away; it stays MUST_FIX until it is CLOSED and pinned.
