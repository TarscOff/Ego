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
narrow: []
---
# STANDARD

A reasonable engineering baseline. Deterministic enforcement of absolute denies is still required; what STANDARD
relaxes is ceremony, not authority. Where a guarantee cannot be met, STANDARD continues with explicit disclosure in
`doctor`, `status` and the receipt: unsigned runtime trust, relayed presentation, an unavailable model-assisted review,
a stale forge snapshot.

`narrow` lists capability identifiers this profile moves toward DENY relative to the core table; STANDARD narrows
nothing.
