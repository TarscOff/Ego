---
schema: ego.profile/1
id: STRICT
title: Strict assurance (enterprise default)
context_budget_tokens: 2000
organization_ceiling_tokens: 4000
# enforced by the profile's identity (any profile but STANDARD), not by anything reading this setting
requires_signed_release_trust: true
requires_managed_tier: false
requires_remote_verify_backstop: false
# declared, not enforced: read by no code; the Stop hook never blocks DONE and the Grilling review is phase 4
grilling_review_unavailable: BLOCK_DONE
# declared, not enforced: read by no code; the Stop hook never blocks DONE and the forge snapshot is phase 2
forge_unreachable_at_done: BLOCK_DONE
# declared, not enforced: read by no code; no foreign live session is detected until held scopes exist (phase 2)
shell_uncertain_mutation_with_foreign_live_session: DENY
# declared, not enforced: read by no code; the human decision gate is phase 5
owner_weakening_plain_policy: DECISION
# declared, not enforced: read by no code; the human decision gate is phase 5
model_flagged_conflict_on_control: DECISION_WITH_KEEP
budgets:
  max_duration_minutes: 240
  max_iterations: 60
  max_tool_calls: 1500
  max_retries_per_step: 3
  max_delegation_depth: 2
  max_concurrent_subagents: 3
  max_network_operations: 200
  max_tokens: null
  max_cost_usd: null
  on_exceed: BLOCK
narrow:
  - capability: git.local.commit
    verdict: ASK
  # A COMMIT IS A REAL-WORLD EFFECT THAT THREE CAPABILITIES CAN PRODUCE, and the narrowing was written against one
  # of them: `git merge --no-ff` and `git cherry-pick` create a commit and write the merged files into the working
  # tree, and were ALLOW while `git commit` was ASK (exit review 10).
  - capability: git.local.merge
    verdict: ASK
  - capability: git.local.cherry-pick
    verdict: ASK
  - capability: command.local-mutation
    verdict: ASK
---
# STRICT

The enterprise default. This page has two halves: what the profile enforces today, and what it declares and no code
enforces yet. `ego doctor` reports the second half.

**Enforced today.** Every HARD_LOCK and ADMIN_GOVERNED capability is enforced deterministically by the blocking
PreToolUse hook (and, for commits and pushes, by the repo-side git hooks, which `--no-verify` bypasses). Governed
mutation begins only once the pinned runtime identity has signed-release trust: until `ego sync` promotes it, only
reads and the pre-promotion commands run. That requirement (`requires_signed_release_trust`) is enforced by the
profile's identity, which is any profile other than STANDARD, and not by anything reading the setting. STRICT narrows
local commits, merges, cherry-picks and local mutation commands to ASK so the human sees every commit and every
installer run once per grant.

**Declared, not enforced today.** These are parsed, validated and compiled, and no code reads them:

- `grilling_review_unavailable: BLOCK_DONE` and `forge_unreachable_at_done: BLOCK_DONE` mean DONE should be blocked
  while the forge snapshot is unverified or the model-assisted Grilling review is unavailable. The Stop hook never
  blocks, the forge snapshot is phase 2 and the Grilling review is phase 4.
- `shell_uncertain_mutation_with_foreign_live_session: DENY` means an uncertain shell mutation should be denied when a
  foreign live session shares the checkout or a path is frozen. No foreign live session is detected until held scopes
  exist (phase 2), so nothing is denied for this reason.
- `owner_weakening_plain_policy: DECISION` and `model_flagged_conflict_on_control: DECISION_WITH_KEEP` are
  decision-gate behaviours (phase 5).
- A human decision accepted only through a conformance-verified presentation and input channel is a requirement of
  this profile that nothing meets yet: `doctor` reports CHANNEL_UNVERIFIED, and grants recorded through the prompt
  hook are disclosed in the receipt (phase 6).

Execution budgets (`budgets`) bound one task: wall-clock duration, agent iterations, tool calls, retries of one step,
delegation depth, concurrent subagents and network operations. Token and cost limits apply only where the host reports
them (`null` = not observable). Exceeding a budget stops the task with `on_exceed`: BLOCK refuses further governed tool
calls until a human extends the budget (`ego.budget.extend`, ASK); ESCALATE raises a decision and continues only
with an answer. Repeated failure of one step never loops: once a step has used its retries, BLOCK profiles refuse the next identical attempt and ESCALATE profiles require a human decision for it.
