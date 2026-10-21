---
schema: ego.containment/1
id: containment
title: Controls declared per profile and host
controls:
  - id: protected-paths
    kind: enforcement
    description: 'Credential stores, hook and permission configuration, generated artifacts and the trust store are refused BEFORE the call runs: to file tools, and to a shell command that names one of them in a spelling the classifier recognises. That is classification in the hook, not a boundary. A program the classifier cannot read reaches the human gate rather than a refusal, and nothing observes the file system after a shell command: PostToolUse records a ledger line (the tool, a one-line summary, whether it failed) and inspects no path. Drift in the files EGO generated (hook shims, slash commands, the Codex hook file, AGENTS.md) is found on demand by `ego check` and `ego doctor`, which compare them with the generation manifest. .claude/settings.json is co-owned with the user, so doctor reports only that it still names the EGO hook shim.'
    required_in: [STANDARD, STRICT, HIGH_ASSURANCE]
    recommended_in: []
    hosts:
      claude-code: SUPPORTED
      codex-cli: UNVERIFIED
  - id: secret-redaction-boundary
    kind: enforcement
    description: 'PARTIAL. EGO redacts what IT writes — the runtime ledger, receipts and its own evidence — and originals are never logged. It does NOT route a host tool''s output through a redactor: nothing in the kernel rewrites tool output before the model sees it, so a secret a tool prints reaches the transcript. Routing tool output through the redactor needs the host to hand EGO that output, which is phase-6 conformance work.'
    required_in: [STANDARD, STRICT, HIGH_ASSURANCE]
    recommended_in: []
    hosts:
      claude-code: PARTIAL
      codex-cli: PARTIAL
  - id: held-scope-isolation
    kind: isolation
    description: 'NOT IMPLEMENTED (held scopes are phase 2). Designed: two live sessions never mutate the same held scope, and a foreign live session in the checkout downgrades or refuses uncertain shell mutation per profile. Nothing enforces this today and no foreign live session is detected.'
    required_in: [STRICT, HIGH_ASSURANCE]
    recommended_in: [STANDARD]
    hosts:
      claude-code: UNAVAILABLE
      codex-cli: UNVERIFIED
  - id: worktree-isolation
    kind: isolation
    description: 'ISOLATION OF GIT STATE, NOT CONTAINMENT, and never to be reported as containment: a worktree separates Git working state between concurrent sessions and nothing else. It shares the filesystem, the network, the credentials and the process table. NOT IMPLEMENTED: EGO neither creates nor requires a worktree, and nothing refuses a second live session in a checkout (held scopes are phase 2). Listed so that doctor can say so under its own heading, isolation, rather than under containment; the physical boundary is issue #26.'
    required_in: [HIGH_ASSURANCE]
    recommended_in: [STRICT]
    hosts:
      claude-code: UNAVAILABLE
      codex-cli: UNVERIFIED
  - id: managed-settings-lock
    kind: host-feature
    description: 'HOST FEATURE, NOT VERIFIED BY EGO. When the host enforces a managed settings tier, a session cannot edit its own guards. EGO neither installs, reads nor checks that tier: it records the control as UNVERIFIED here and in the capability matrix, and must not report it SATISFIED on a host''s word. Verification is phase-6 conformance work.'
    required_in: [HIGH_ASSURANCE]
    recommended_in: [STRICT]
    hosts:
      claude-code: UNVERIFIED
      codex-cli: UNVERIFIED
  - id: sandboxed-command-execution
    kind: containment
    description: 'DESIGNED, NOT IMPLEMENTED (issue #26): shell commands would run in a host sandbox with a write scope limited to the checkout and the runtime root. EGO neither establishes, requires nor detects such a boundary today, whatever the host offers, and no profile requires it. `ego doctor` lists it under the profiles that recommend it as not in force; that line never fails the run.'
    required_in: []
    recommended_in: [STRICT, HIGH_ASSURANCE]
    hosts:
      claude-code: UNAVAILABLE
      codex-cli: UNVERIFIED
  - id: network-egress-control
    kind: containment
    description: 'PARTIAL, AND NOT CONTAINMENT TODAY: no OS-level restriction on egress exists (issue #26); only the classifier acts. HIGH_ASSURANCE narrows `command.network-tool` and `network.public-read` to DENY (STANDARD and STRICT leave both at ASK). It therefore refuses a shell command whose head is a network client the classifier recognises (curl, wget, scp, sftp, rsync with a remote operand, ssh, nc, ncat, telnet, `pnpm dlx`, `yarn dlx`, a /dev/tcp redirect, a registry or host override on a package tool), WebFetch of any URL that is not localhost, and WebSearch. It does NOT restrict git remote operations (`git fetch`, `clone`, `pull`, `ls-remote`), forge reads (`gh`, `glab`), package-registry reads (`npm view`), container runs (`docker pull`, `docker run`, `docker compose up`), or any program the classifier does not recognise as a network client, which asks as unknown execution when nothing else classifies it.'
    required_in: [HIGH_ASSURANCE]
    recommended_in: [STRICT]
    hosts:
      claude-code: PARTIAL
      codex-cli: UNVERIFIED
  - id: subagent-inheritance
    kind: enforcement
    description: 'A subagent''s calls arrive in the parent session. They are evaluated with that session''s profile, mode and grants and counted against its budgets; the agent identifier is recorded as a trace and never changes a verdict, so a subagent has no way to widen any of them. Inheriting the task arrives with durable tasks (phase 2).'
    required_in: [STANDARD, STRICT, HIGH_ASSURANCE]
    recommended_in: []
    hosts:
      claude-code: SUPPORTED
      codex-cli: UNVERIFIED
---
# Controls

Policy says what is allowed. Authority says who decided. Containment is what would stop an action technically when
policy and authority are argued with. The three are never conflated (alignment item 3): a DENY verdict is a policy
statement, a hook exit is an authority enforcement, a sandbox is a containment control.

A worktree is none of the three. It isolates Git working state between sessions and shares the filesystem, the
network, the credentials and the process table, so it is isolation of Git state and is never reported as
containment. The file lists controls of different kinds side by side, and each declares its `kind`: `containment`
restricts what a process can physically reach; `isolation` separates Git or session state and shares everything else;
`enforcement` is a decision the kernel takes in-band about what it sees; `host-feature` is something the host
provides and EGO only records. `ego doctor` reports each control under its kind. **No control of kind `containment`
is in force today**: the classifier is defense in depth, not a boundary (`docs/architecture/security-model.md`), and
the boundary is issue #26.

Each control lists the profiles that require it, the profiles that recommend it, and its status on every host.
Nothing but `ego doctor` reads this file, and it enforces nothing. For the pinned profile, `doctor` reports every
control the profile requires or recommends, for the host in use or for both hosts when none can be determined. The
status in `hosts` is a declaration EGO authored, never a measurement of the running host: SUPPORTED is reported as
SATISFIED (declared, not verified), UNVERIFIED as UNVERIFIED, PARTIAL and UNAVAILABLE as NOT SATISFIED with the gap
named. A NOT SATISFIED line fails the run only for a control the profile REQUIRES and only when the host is known;
UNVERIFIED lines and recommended controls are printed and never fail it. With no host determined every status is
printed UNVERIFIED. A profile states what it needs and `doctor` states what is in force; where the two differ, the
line says so. HIGH_ASSURANCE is designed to rely on technical isolation rather than on prompt instructions; none is
in force today, and what separates it from STRICT now is its narrowed capability set and tighter budgets.

Host support is recorded in two places, for two purposes. This file is the design: which controls exist, which
profile needs each and what each would do, with the status `doctor` prints. `packages/kernel/src/hosts/matrix.ts`
is the record of host capabilities by key, with the conformance check that will verify each. For every id both carry,
`packages/kernel/test/closure-docs.test.ts` fails when the two statuses differ. A control with no key in the matrix
is recorded here only.
