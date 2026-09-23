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

**Proportionality cost, measured rather than asserted — including where it is worst.**

| Measured on | Ordinary commands | Gated | What gates |
|---|---:|---:|---|
| TypeScript monorepo, Go, Python/poetry, Rust, husky | 79 | 8 (10%) | test commands only |
| Java/Maven, Ruby, PHP, LFS repository | 66 | 12 (9 non-test) | installs and project task runners |
| **This repository (EGO itself)** | 44 | **7 (16%)** | see below |

The third row is the honest one, and an earlier version of this document left it out. On EGO's own checkout the
gates are `npm test` and `node --test …` (test runners), `npm run lint` and `eslint packages` (this repository has
an executable `eslint.config.js`, so eslint imports and runs it), `npm run build` and `if npm run build; …` (the
build script is `node scripts/build.mjs`, an interpreter running a program file — a gate that predates all of this
work), and `git rebase` (its own capability, also pre-existing).

So the rate is **10% on a typical consumer repository and 16% here**, and the difference is entirely EGO's own
executable lint configuration and its `node`-driven build. Quoting only the lower number would have been true of
the sample and misleading about the tool.

## CONTAINMENT_DEPENDENCY

The semantic action is intentionally permitted. What it may reach is issue #26's problem, and **#26 is not built**.

| Action | Permitted because | What #26 must guarantee |
|---|---|---|
| `cargo build`, `cargo run` | compiling code already acquired is ordinary work. **Residual risk, stated:** a cold cache makes cargo acquire too, and every dependency's `build.rs` runs at compile time | build steps execute under the profile's filesystem and network boundary |
| `docker compose up` | see above | the four guarantees listed above |
| `go build`, `tsc`, `javac`, the C/C++ toolchain, **with their default flags** | compile source to objects and execute nothing else. The flags that make them run a program — `-B`, `-wrapper`, `-fplugin=`, `-specs=`, `-toolexec`, `-processor` — are classified as unbounded program operands and gate; the row was written before they were, and was false until then | writes confined to the checkout and the runtime root |
| an approved ASK | a human approved a specific action, not an unbounded session | the approval's blast radius is bounded by the profile, not by the classifier |

**The seam between an install and a build**, stated once: *acquiring* third-party code and running it is a human
gate; *compiling* code already acquired is a containment dependency. The seam is imperfect — a cold cargo cache
acquires — and it is drawn here deliberately rather than left implicit, because drawing it somewhere is the only
alternative to gating every build in every ecosystem.

## What this changes about the exit criterion

A finding is an **unresolved Phase-1 defect** only when it is MUST_FIX. A finding classified into one of the other
three is a *recorded decision*, a *working fail-safe*, or a *named requirement on #26* — and counting those as
defects is what made the previous rounds look like they were not converging when the contract was in fact holding.
