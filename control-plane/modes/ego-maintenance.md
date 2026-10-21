---
schema: ego.mode/1
id: EGO_MAINTENANCE
kind: authority
title: Harness maintenance
only_in_ego_repository: true
overrides:
  - capability: ego.control-plane.edit
    verdict: ALLOW
  - capability: ego.hooks.edit
    verdict: ALLOW
  - capability: fs.hook-config.write
    verdict: ASK
  - capability: fs.generated.write
    verdict: ASK
---
# EGO_MAINTENANCE

Changes the Harness itself: control plane, hook configuration, generators, trust seed. Available only in the EGO
source repository (a consumer never edits these files; it upgrades). Security-critical protections stay active:
absolute denies cannot be overridden by any mode, and `ego.gate.bypass` remains absolute. The mode is entered by an
exact prompt marker recognised by the human prompt hook, never by tool output, issue text or a skill.
