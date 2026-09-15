---
schema: ego.profile/1
id: STRICT
title: Strict assurance (enterprise default)
context_budget_tokens: 2000
organization_ceiling_tokens: 4000
requires_signed_release_trust: true
requires_managed_tier: false
requires_remote_verify_backstop: false
grilling_review_unavailable: BLOCK_DONE
forge_unreachable_at_done: BLOCK_DONE
shell_uncertain_mutation_with_foreign_live_session: DENY
owner_weakening_plain_policy: DECISION
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
  - capability: command.local-mutation
    verdict: ASK
---
# STRICT

The enterprise default. Every absolute deny must be enforced deterministically by a blocking hook or the repo-side
layer; governed mutation begins only once the pinned runtime identity has signed-release trust; a human decision is
accepted only through a conformance-verified presentation and input channel; DONE is blocked while the forge snapshot
is unverified or the model-assisted Grilling review is unavailable; uncertain shell mutations are denied when a
foreign live session shares the checkout or policy paths are frozen.

STRICT narrows local commits and local mutation commands to ASK so the human sees every commit and every installer
run once per grant.

Execution budgets (`budgets`) bound one task: wall-clock duration, agent iterations, tool calls, retries of one step,
delegation depth, concurrent subagents and network operations. Token and cost limits apply only where the host reports
them (`null` = not observable). Exceeding a budget stops the task with `on_exceed`: BLOCK refuses further governed tool
calls until a human extends the budget (`harness.budget.extend`, ASK); ESCALATE raises a decision and continues only
with an answer. Repeated failure of one step never loops: the retry limit is a hard stop.
