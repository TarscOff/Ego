---
schema: ego.profile/1
id: HIGH_ASSURANCE
title: High assurance
context_budget_tokens: 2000
organization_ceiling_tokens: 4000
# enforced by the profile's identity (any profile but STANDARD), not by anything reading this setting
requires_signed_release_trust: true
# declared, not enforced: read only by `ego doctor`, which reports it NOT SATISFIED; EGO does not install or verify a managed tier
requires_managed_tier: true
# declared, not enforced: read only by `ego doctor`, which reports it NOT SATISFIED; `ego verify --range` is phase 6
requires_remote_verify_backstop: true
# declared, not enforced: read by no code; the Stop hook never blocks DONE and the Grilling review is phase 4
grilling_review_unavailable: BLOCK_DONE
# declared, not enforced: read by no code; the Stop hook never blocks DONE and the forge snapshot is phase 2
forge_unreachable_at_done: BLOCK_DONE
# declared, not enforced: read by no code; no worktree is created and no second session is refused (held scopes are phase 2)
shell_uncertain_mutation_with_foreign_live_session: REQUIRE_ISOLATION
# declared, not enforced: read by no code; the human decision gate is phase 5
owner_weakening_plain_policy: DECISION
# declared, not enforced: read by no code; the human decision gate is phase 5
model_flagged_conflict_on_control: DECISION_WITH_KEEP
budgets:
  max_duration_minutes: 180
  max_iterations: 40
  max_tool_calls: 1000
  max_retries_per_step: 2
  max_delegation_depth: 1
  max_concurrent_subagents: 2
  max_network_operations: 50
  max_tokens: null
  max_cost_usd: null
  on_exceed: BLOCK
narrow:
  - capability: git.local.commit
    verdict: ASK
  # NARROW IS NOT INHERITED FROM STRICT, so everything STRICT narrows is listed here again: a merge and a cherry-pick
  # create a commit exactly as `git commit` does, and were ALLOW in the strongest profile while STRICT asked. The
  # compiler refuses a profile that is looser than a weaker one for any capability in any mode.
  - capability: git.local.merge
    verdict: ASK
  - capability: git.local.cherry-pick
    verdict: ASK
  - capability: command.local-mutation
    verdict: ASK
  - capability: command.network-tool
    verdict: DENY
  # a request that SENDS is a network tool's work too: splitting the fetch from the send must not open a door that
  # `command.network-tool` had closed
  - capability: network.external-write
    verdict: DENY
  - capability: network.public-read
    verdict: DENY
---
# HIGH_ASSURANCE

The strongest assurance EGO is designed to give. The design asks for more than the code yet provides, so this page has
two halves, as STRICT's does: what is enforced today, and what is declared and not enforced. Assurance is meant to
come from enforcement and evidence, not from more prompt text, which is why the context budget is the same as
STRICT's. Today what separates this profile from STRICT is its own `narrow` list and its tighter budgets. The list is not
inherited from STRICT's, so it repeats everything STRICT narrows; the compiler refuses a control plane in which this
profile is looser than STRICT (or STRICT looser than STANDARD) for any capability in any mode, so a list that falls
behind fails the build instead of opening a door in the strongest profile.

**Enforced today.** The same signed-release-trust requirement as STRICT (`requires_signed_release_trust`, enforced by
the profile's identity and not by reading the setting) and BLOCK budgets. `narrow` makes `command.network-tool`,
`network.external-write` and `network.public-read` DENY and makes local commits, merges, cherry-picks and local
mutation commands ask. The network clients the classifier
recognises (curl, wget, scp, ssh and their kin), WebFetch of any URL that is not localhost and WebSearch are refused.
That is a rule about the commands EGO recognises, not an egress restriction: git remote operations, forge reads,
package-registry reads and container runs are not covered, and no OS-level restriction exists
(`network-egress-control` in `containment/controls.md` says exactly what is covered).

**Declared, not enforced today** (design; issue #26 and later phases). No sandbox, worktree or managed boundary
exists in any profile, and a worktree would isolate Git state only:

- tamper protection through the host's managed tier (Claude Code managed settings with `allowManagedHooksOnly` and
  `allowManagedPermissionRulesOnly`; Codex `requirements.toml`) is `requires_managed_tier: true`. EGO neither installs,
  reads nor verifies a managed tier; the setting is read only by `doctor`, which reports it NOT SATISFIED.
- `requires_remote_verify_backstop: true` asks for a remote `ego verify --range` backstop on a protected branch. The
  command is phase 6; the setting is read only by `doctor`, which reports it NOT SATISFIED.
- `shell_uncertain_mutation_with_foreign_live_session: REQUIRE_ISOLATION` asks for worktree isolation for concurrent
  sessions, with a second live session refused in a bound checkout. Nothing creates a worktree or refuses a second
  session (held scopes are phase 2).
- the same declared settings as STRICT: `grilling_review_unavailable`, `forge_unreachable_at_done`,
  `owner_weakening_plain_policy` and `model_flagged_conflict_on_control`.

`doctor` reports each control and requirement of this profile as SATISFIED (a status EGO declared, not one it
verified), UNVERIFIED or NOT SATISFIED. It never reports a guarantee satisfied on a host's word, and it names the
profile settings that nothing reads.

Execution budgets (`budgets`) bound one task: wall-clock duration, agent iterations, tool calls, retries of one step,
delegation depth, concurrent subagents and network operations. Token and cost limits apply only where the host reports
them (`null` = not observable). Exceeding a budget stops the task with `on_exceed`: BLOCK refuses further governed tool
calls until a human extends the budget (`ego.budget.extend`, ASK); ESCALATE raises a decision and continues only
with an answer. Repeated failure of one step never loops: once a step has used its retries, BLOCK profiles refuse the next identical attempt and ESCALATE profiles require a human decision for it.
