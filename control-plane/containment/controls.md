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
    description: 'PARTIAL. EGO redacts what IT writes — the runtime ledger, receipts and its own evidence — and originals are never logged. It does NOT route a host tool''s output through a redactor: nothing in the kernel rewrites tool output before the model sees it, so a secret a tool prints reaches the transcript. Routing tool output through the redactor needs the host to hand EGO that output, which is phase-6 conformance work.'
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
    description: 'NOT CONTAINMENT, and never to be reported as such: a worktree separates Git working state between concurrent sessions and nothing else. It shares the filesystem, the network, the credentials and the process table. Listed here as a coordination control so doctor can report it honestly; the physical boundary is issue #26. Not implemented today — held scopes are phase 2.'
    required_in: [HIGH_ASSURANCE]
    recommended_in: [STRICT]
    hosts:
      claude-code: PARTIAL
      codex-cli: UNVERIFIED
  - id: managed-settings-lock
    description: 'HOST FEATURE, NOT VERIFIED BY EGO. When the host enforces a managed settings tier, a session cannot edit its own guards. EGO neither installs nor checks that tier: it records what the host claims in the capability matrix and must not report the control SATISFIED on that basis alone. Verification is phase-6 conformance work.'
    required_in: [HIGH_ASSURANCE]
    recommended_in: [STRICT]
    hosts:
      claude-code: SUPPORTED
      codex-cli: UNVERIFIED
  - id: sandboxed-command-execution
    description: 'DESIGNED, NOT IMPLEMENTED (issue #26): shell commands would run in a host sandbox with a write scope limited to the checkout and the runtime root. EGO neither establishes nor verifies this boundary today, and no profile requires it.'
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
