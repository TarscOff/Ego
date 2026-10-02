---
schema: ego.capabilities/1
id: ego
family: ego
title: Harness self-governance and distribution
---
# Harness self-governance and distribution

Capabilities EGO exercises on itself. Editing the control plane, hook configuration or trust files is normal work only
in the EGO repository under EGO_MAINTENANCE; everywhere else generated artifacts are regenerated, never edited.
Human decision gates have no capability that opens them: answering a decision is a human act through the prompt hook.

## Allowed

- [x] `ego.runtime.write` — the kernel writes `.harness/runtime/` (sessions, tasks, claims, ledger, evidence).
- [x] `ego.generated.regenerate` — regenerate generated artifacts through `init`, `sync`, `upgrade`, `rollback`, `check`.
- [x] `ego.overlay.edit` — edit the product overlay under `.harness/overlay/` and `.harness/permissions.md` (narrowing only).
- [x] `ego.sync.network` — obtain runtimes, release metadata and skills through the classified `sync` and `skills` network capabilities.
- [x] `ego.evidence.export` — export evidence bundles to local filesystem destinations.

## Requires human approval

- [x] `ego.budget.extend` — extend an execution budget of the current task beyond the profile value; only a human grant moves it to ALLOW, once, for the current task.
- [x] `ego.pin.change` — `upgrade` and `rollback` change the project pin.
- [x] `ego.skills.install` — install or update external skills from configured sources.
- [x] `ego.policy.accept` — `ego init` and `ego sync` (which runs init) from a tool call. Run on a person's terminal they ACCEPT the widenings that arrived in the layer files since the last accepted run (an organization policy, a local-target declaration, a vocabulary addition); run where an agent shell is recognised they accept nothing. It asks so that the person who approves it knows what it is.
- [x] `ego.mcp-trust.edit` — edit `.harness/mcp-trust.md`.
- [x] `ego.local-targets.edit` — edit `.harness/local-targets.md`, the project's declaration of which clusters, databases and container contexts are local development targets. Declaring one is a widening: nothing in the file applies until a human runs `ego init` and accepts it, so the write asks first.

## Denied

- [x] `ego.control-plane.edit` — edit `control-plane/`, `policies/` baselines or trust files outside EGO_MAINTENANCE in the EGO repository.
- [x] `ego.hooks.edit` — edit generated hook configuration outside EGO_MAINTENANCE in the EGO repository.
- [x] `ego.decision.answer` — record a human decision from any tool, shell, file or subagent.
