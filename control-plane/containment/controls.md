---
schema: ego.containment/1
id: containment
title: Containment controls
controls:
  - id: protected-paths
    description: Credential stores, hook and permission configuration, generated artifacts and the trust store are refused to file tools and detected after shell writes.
    required_in: [STANDARD, STRICT, HIGH_ASSURANCE]
    recommended_in: []
    hosts:
      claude-code: SUPPORTED
      codex-cli: UNVERIFIED
  - id: secret-redaction-boundary
    description: Tool output, evidence and receipts pass the structured and regex redactors before leaving the kernel; originals are never logged. The redactor is host-independent; the hook path that feeds it is verified per host.
    required_in: [STANDARD, STRICT, HIGH_ASSURANCE]
    recommended_in: []
    hosts:
      claude-code: SUPPORTED
      codex-cli: UNVERIFIED
  - id: held-scope-isolation
    description: Two live sessions never mutate the same held scope; a foreign live session in the checkout downgrades or refuses uncertain shell mutation per profile.
    required_in: [STRICT, HIGH_ASSURANCE]
    recommended_in: [STANDARD]
    hosts:
      claude-code: PARTIAL
      codex-cli: UNVERIFIED
  - id: worktree-isolation
    description: Concurrent sessions work in separate git worktrees bound to the same logical workspace; a second live session in a bound checkout is refused.
    required_in: [HIGH_ASSURANCE]
    recommended_in: [STRICT]
    hosts:
      claude-code: PARTIAL
      codex-cli: UNVERIFIED
  - id: managed-settings-lock
    description: Host settings and hooks come from the managed tier only, so a session cannot edit its own guards.
    required_in: [HIGH_ASSURANCE]
    recommended_in: [STRICT]
    hosts:
      claude-code: SUPPORTED
      codex-cli: UNVERIFIED
  - id: sandboxed-command-execution
    description: Shell commands run in a host sandbox with a write scope limited to the checkout and the runtime root.
    required_in: []
    recommended_in: [STRICT, HIGH_ASSURANCE]
    hosts:
      claude-code: PARTIAL
      codex-cli: UNVERIFIED
  - id: network-egress-control
    description: Tool network egress is restricted to classified endpoints; HIGH_ASSURANCE denies public network use by tools.
    required_in: [HIGH_ASSURANCE]
    recommended_in: [STRICT]
    hosts:
      claude-code: PARTIAL
      codex-cli: UNVERIFIED
  - id: subagent-inheritance
    description: Subagents inherit the parent session's task, profile, mode, grants and budgets and can never widen them.
    required_in: [STANDARD, STRICT, HIGH_ASSURANCE]
    recommended_in: []
    hosts:
      claude-code: SUPPORTED
      codex-cli: UNVERIFIED
---
# Containment controls

Policy says what is allowed. Authority says who decided. Containment is what stops an action technically when policy
and authority would otherwise be argued with. The three are never conflated (alignment item 3): a DENY verdict is a
policy statement, a hook exit is an authority enforcement, a sandbox or a worktree is a containment control.

Each control lists the profiles that require it, the profiles that recommend it, and its status on every host.
`doctor` reports a required control whose host status is not SUPPORTED as NOT SATISFIED; the profile never claims a
guarantee its host cannot verify. HIGH_ASSURANCE prefers technical isolation over prompt instructions.
