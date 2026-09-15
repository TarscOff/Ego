---
schema: ego.profile/1
id: STANDARD
title: Standard assurance
context_budget_tokens: 2500
organization_ceiling_tokens: 4000
requires_signed_release_trust: false
requires_managed_tier: false
requires_remote_verify_backstop: false
grilling_review_unavailable: CONTINUE_WITH_DISCLOSURE
forge_unreachable_at_done: CONTINUE_WITH_DISCLOSURE
shell_uncertain_mutation_with_foreign_live_session: DETECT_AFTER
owner_weakening_plain_policy: AUTO_WITH_INFORM
model_flagged_conflict_on_control: INFORM
budgets:
  max_duration_minutes: 480
  max_iterations: 100
  max_tool_calls: 3000
  max_retries_per_step: 3
  max_delegation_depth: 3
  max_concurrent_subagents: 5
  max_network_operations: 500
  max_tokens: null
  max_cost_usd: null
  on_exceed: ESCALATE
narrow: []
---
# STANDARD

A reasonable engineering baseline. Deterministic enforcement of absolute and organization-locked denies is still required; what STANDARD
relaxes is ceremony, not authority. Where a guarantee cannot be met, STANDARD continues with explicit disclosure in
`doctor`, `status` and the receipt: unsigned runtime trust, relayed presentation, an unavailable model-assisted review,
a stale forge snapshot.

`narrow` lists capability identifiers this profile moves toward DENY relative to the core table; STANDARD narrows
nothing.

Execution budgets (`budgets`) bound one task: wall-clock duration, agent iterations, tool calls, retries of one step,
delegation depth, concurrent subagents and network operations. Token and cost limits apply only where the host reports
them (`null` = not observable). Exceeding a budget stops the task with `on_exceed`: BLOCK refuses further governed tool
calls until a human extends the budget (`harness.budget.extend`, ASK); ESCALATE raises a decision and continues only
with an answer. Repeated failure of one step never loops: once a step has used its retries, BLOCK profiles refuse the next identical attempt and ESCALATE profiles require a human decision for it.
