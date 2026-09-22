# September 2026 implementation alignment

A hardening and compatibility review against the frozen baseline (Q1–Q97). Each item was inspected against the
current implementation and classified; only PARTIAL, MISSING, CONFLICTING and OBSOLETE items change anything. Every
change is the smallest coherent one, keeps canonical ownership in the kernel, and carries deterministic tests.

| # | Item | Classification | Disposition |
|---|---|---|---|
| 1 | Kernel versus host runtime | EQUIVALENT | Baseline section A and C already: adapters translate events and capabilities, contain no governance. Rule restated in `docs/architecture/adr/` on BUILD phase 6 with the adapter conformance suite. |
| 2 | Host capability matrix per host | EQUIVALENT | Q32, Q90: matrix keyed by host identifier with SUPPORTED / PARTIAL / UNAVAILABLE / UNVERIFIED; UNAVAILABLE preferred to fake parity. Implemented in `packages/kernel/src/hosts/` (phase 1) and reported by `doctor`. |
| 3 | Policy ≠ authority ≠ containment | PARTIAL | Containment existed implicitly (worktree isolation, protected paths, HIGH_ASSURANCE isolation). Added an explicit containment control catalogue (`control-plane/containment/controls.md`) with per-profile requirements and host matrix status; enforcement of worktree isolation lands in phase 2 with held scopes. |
| 4 | Configurable policies versus absolute denies | CONFLICTING | The baseline made push, PR mutation, release, issue mutation and production mutation absolute (Docker, Kubernetes, database, network and MCP writes were already ordinary ALLOW/ASK/DENY capabilities). The review asks that organization-configurable behaviour not be hard-coded as absolute. Resolved by a capability lock tier: `absolute` (never widenable) versus `organization` (DENY by default, widenable only by the organization policy layer, never by overlay, grant, mode or model). Default split proposed as Q98 (see below); the mechanism supports either answer by moving identifiers between files. |
| 5 | Effect-based authorization | PARTIAL | The evaluator already expanded `bash -c`, `xargs`, `sudo`, `$(...)` and backticks. Added: `npm|pnpm|yarn run <script>` resolves the script from `package.json` and classifies its body; `./x.sh`, `bash x.sh`, `source x.sh` classify the script's lines when the file is inside the workspace and statically readable; interpreter invocations (`python x.py`, `node x.js`, …) and opaque scripts classify as `command.interpreter-script` / `command.script-opaque` (ASK); `make <target>` classifies the recipe. Most restrictive verdict wins. Tests in `packages/kernel/test/effects.test.ts`. |
| 6 | Untrusted content and provenance | PARTIAL | Q61, Q68 and the decision-gate design already treat forge, pack and issue text as data. Added the explicit trust-class enum, provenance record and data-framing helper (`packages/kernel/src/context/trust.ts`, tested); the forge and context pipelines that will call it land in phases 2–3. Today no untrusted text reaches a model through the kernel: hooks inject only kernel-generated lines. |
| 7 | Agent identity and delegation trace | EQUIVALENT | Q48 clarification: agent identifiers are ephemeral trace identity, never authority. The ledger records operator → task → session → host → parent agent → child agent → tool (phase 2). |
| 8 | Execution budgets | MISSING | Only the context budget existed. Added `budgets` to every profile (duration, iterations, tool calls, retries, delegation depth, concurrent subagents, network operations, token and cost where observable, `on_exceed`), compiled into the authority table and enforced by the hooks' session counters (phase 1 hooks, phase 2 task state). Exceeding a budget BLOCKS or ESCALATES; never infinite retries. |
| 9 | Durable task ≠ model session | EQUIVALENT (one field added) | Q20, Q36–Q50. Added `activeCorrections` (redacted) to the session record now, re-injected at SessionStart so corrections survive compaction and resume within a host session; the durable task contract (phase 2) carries them across sessions, hosts and models. |
| 10 | Progressive disclosure | EQUIVALENT | Q28, section I: root budgets, scoped rules, `context explain` with a reason per item. |
| 11 | MCP 2026-07-28 | MISSING | A versioned MCP compatibility matrix is added in phase 2 with the MCP trust module (`docs/integrations/mcp-compatibility.md`); the kernel never builds on deprecated primitives; MCP Task and EGO Task are distinct state machines by construction (different modules, no shared state). Verification of the 2026-07-28 revision against the primary specification is a phase-2 task. |
| 12 | MCP trust model | PARTIAL | Classes discover / read / narrow-write / mutate existed; added `privileged-destructive` as a fifth class (`mcp.local.privileged`, `mcp.remote.privileged`, DENY by default, asserted in `control-plane.test.ts`). Unknown endpoints already fail safe; per-tool resolution through `.harness/mcp-trust.md` lands in phase 2. |
| 13 | Real evidence | EQUIVALENT | Q12, Q35, section G: fingerprint-bound validations and verdicts; STALE ≠ PASS; claims are never evidence. |
| 14 | Review independence | EQUIVALENT (one guard added) | Q12: builder ≠ reviewer, fresh context. Added in phase 4: the reviewer agent definition is read-only and a reviewer write is a conformance failure. |
| 15 | Benchmark → eval intelligence | PARTIAL | Q13, Q31 covered reproducibility; phase 4 stores append-only, attempt-aware records with taskId, runId, attemptId, host, modelId when the host reports it, snapshot, policy and kernel fingerprints, risk, surface, outcome. |
| 16 | Multiple trials | PARTIAL | Phase 4 benchmark runner supports N trials per task with variance; single-run conclusions are labelled as such in reports. |
| 17 | Multi-dimensional evaluation | PARTIAL | Phase 4 stores the listed dimensions; a composite score exists only as a transparent secondary view. |
| 18 | Issue and ticket generation | EQUIVALENT | Q54: proposed criteria carry provenance and need human approval; issue creation remains a governed forge capability (DENY by default). |
| 19 | Issue freshness | EQUIVALENT | Q55, Q62. |
| 20 | DONE ≠ issue closed | EQUIVALENT (Q98 note) | Q59 unchanged: local DONE never closes an issue. `forge.issue.close` moves from absolute to organization-locked, so an organization may delegate closing; the default stays DENY. |
| 21 | Supply-chain trust | EQUIVALENT | Q77–Q97. External skills carry identity, pin, checksum, source, provenance, license, compatibility (Q11). |
| 22 | Harness self-maintenance | EQUIVALENT (rule made explicit) | Q9 EGO_MAINTENANCE keeps protections active; the conformance suite adds the invariant "a weakened guard is never validated by an execution under itself" as a checked property in phase 7. |
| 23 | Harness garbage collection | MISSING | `harness gc --proposals` (phase 3): deterministic detection of dead capability IDs, unused policies, duplicated rules, stale skills, adapters for unsupported hosts, permanently ignored warnings, expired fallbacks; produces a reviewable proposal, never removes automatically. |
| 24 | Stable contracts, replaceable implementations | EQUIVALENT | The kernel's exported types are the contracts; host details live in adapters. |

## Q98 — Capability lock tiers (opened by item 4)

Item 4 conflicts with the baseline's absolute-deny list. The mechanism now distinguishes two locks:

- `absolute`: never widenable by any layer, in any profile, mode or host. Proposed content: destructive filesystem
  roots, credential-store writes, hook and trust configuration tampering outside EGO_MAINTENANCE, gate bypass,
  nested-host invocation from tools, and every production mutation category (the product promise is "never mutate
  production"; the organization gets analysis, comparison and planning, not execution).
- `organization`: DENY at the core layer, widenable only by the organization policy layer (`policies/organization/
  permissions.md`), never by a product overlay, grant, mode, skill or model. Content: `git.remote.push`,
  `git.remote.push.force`, `git.remote.tag.push`, `git.remote.branch.delete`, `git.remote.tag.delete`, `forge.pr.create`,
  `forge.pr.modify`, `forge.pr.close`, `forge.pr.merge`, `forge.pr.approve`, `forge.release.publish`,
  `forge.branch.protection.modify`, `forge.repo.permissions.modify` and the issue mutations
  `forge.issue.create|edit|transition|close`. `mcp.remote.production.mutate` stays absolute with every production
  mutation. Baseline sentences affected: section H (git remote, forge deny, issues), Q4 (deterministic enforcement is
  unchanged: organization-locked denies are enforced by the same hooks and matchers), Q59 (DONE ≠ closed unchanged),
  Q84 (a lock move is MAJOR); the amendment log in `pre-build-package.md` records them.

The recommended answer keeps the day-one behaviour identical (everything above is DENY until an organization writes
a policy) while making the widening path explicit, versioned and testable. Moving an identifier between the two files
is a MAJOR release under Q84.

### Q98 resolution — human decision, 2026-09-22

The product owner settled the open tier question: **every lock in this tier is administrable, and there is no release
phasing.** There is no "v1 hard lock" that is later relaxed; `forge.pr.create`, `forge.pr.merge`,
`git.remote.push.force`, `git.remote.branch.delete`, `git.remote.tag.delete` and `forge.branch.protection.modify`
therefore stay `lock: organization` and are **not** moved to `absolute-denies.md`. This supersedes the HARD_LOCK list
in issue #16 §5.

What administrable means, precisely:

- an organization decides, in a versioned and reviewable file, whether each capability is disabled or available;
- enabling an **external effect** makes it available behind a bounded human approval (`ASK`), not unattended. A layer
  asking for `ALLOW` compiles to `ASK` and the provenance records the clamp. That gate is what makes the capability
  administrable rather than silent — it is not a temporary restriction;
- no host mode (`open`, `free`, full-PC, skip-permissions) suppresses it.

The `absolute` tier keeps only EGO's self-protection and the never-mutate-production promise: gate bypass, trust-store
and runtime tampering, credential-store writes, destructive filesystem roots, nested-host invocation, and the
production mutation categories. Issue #16 §3 asks for exactly that list to remain non-widenable. If that boundary is
also meant to become administrable, it is a separate human decision and must be recorded here before it is built.
