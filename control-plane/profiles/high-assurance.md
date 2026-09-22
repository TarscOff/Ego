---
schema: ego.profile/1
id: HIGH_ASSURANCE
title: High assurance
context_budget_tokens: 2000
organization_ceiling_tokens: 4000
requires_signed_release_trust: true
requires_managed_tier: true
requires_remote_verify_backstop: true
grilling_review_unavailable: BLOCK_DONE
forge_unreachable_at_done: BLOCK_DONE
shell_uncertain_mutation_with_foreign_live_session: REQUIRE_ISOLATION
owner_weakening_plain_policy: DECISION
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
  - capability: command.local-mutation
    verdict: ASK
  - capability: command.network-tool
    verdict: DENY
  - capability: network.public-read
    verdict: DENY
---
# HIGH_ASSURANCE

Everything STRICT requires, plus tamper protection through the host's managed tier (Claude Code managed settings with
`allowManagedHooksOnly` and `allowManagedPermissionRulesOnly`; Codex `requirements.toml`), a remote `harness verify
--range` backstop on a protected branch, worktree isolation for concurrent sessions (a second live session is refused in
a bound checkout), and no public network use by tools. Assurance comes from enforcement and evidence, not from more
prompt text: the context budget is the same as STRICT.

`doctor` reports every requirement of this profile as SATISFIED or NOT SATISFIED; the profile never claims a
guarantee its host cannot verify.

Execution budgets (`budgets`) bound one task: wall-clock duration, agent iterations, tool calls, retries of one step,
delegation depth, concurrent subagents and network operations. Token and cost limits apply only where the host reports
them (`null` = not observable). Exceeding a budget stops the task with `on_exceed`: BLOCK refuses further governed tool
calls until a human extends the budget (`ego.budget.extend`, ASK); ESCALATE raises a decision and continues only
with an answer. Repeated failure of one step never loops: once a step has used its retries, BLOCK profiles refuse the next identical attempt and ESCALATE profiles require a human decision for it.
