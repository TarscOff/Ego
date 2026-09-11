---
schema: ego.coordination/1
id: coordination
title: Multi-session coordination constants
heartbeat_ttl_seconds: 900
heartbeat_ttl_without_pid_seconds: 3600
handoff_grace_seconds: 1800
lock_timeout_ms: 3000
lock_stale_break_ms: 30000
gc_ended_sessions_days: 7
gc_unheld_claims_days: 30
---
# Multi-session coordination constants

Authored defaults for the held-scopes model (decisions Q36–Q50). A holder is live while its heartbeat is younger than
`heartbeat_ttl_seconds`, or, when no pid is known (Codex), `heartbeat_ttl_without_pid_seconds`. An alive-but-silent
holder blocks until an explicit `--force`. The lock around check-and-write is held for milliseconds, times out after
`lock_timeout_ms` (fail closed with a retry hint) and is broken after `lock_stale_break_ms` or when its pid is dead.
Environment overrides (`EGO_COORDINATION_*`) exist for tests only.
