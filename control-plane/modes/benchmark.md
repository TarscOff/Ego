---
schema: ego.mode/1
id: BENCHMARK
kind: authority
title: Benchmark
overrides:
  - capability: forge.review.comment
    verdict: DENY
  - capability: forge.review.thread.reply
    verdict: DENY
  - capability: forge.review.thread.resolve
    verdict: DENY
  - capability: forge.issue.comment
    verdict: DENY
  - capability: forge.issue.assign
    verdict: DENY
  - capability: ego.skills.install
    verdict: DENY
  - capability: ego.pin.change
    verdict: DENY
  # ...AND EVERY ADMINISTRABLE WRITE. These are the capabilities an organization can enable (ADMIN_GOVERNED: DENY until it does, never past ASK
  # once it has). A mode may narrow one and may never widen one, and until it was allowed to say so an organization that enabled `gh pr create`
  # or `git push` made them ASK inside a benchmark run - the leak this mode exists to prevent. DENY here is a no-op without an organization
  # policy and the whole point with one. (The test of this file derives the list from the ADMIN_GOVERNED capabilities: a new forge or remote
  # write that is not listed fails it.)
  - capability: forge.pr.create
    verdict: DENY
  - capability: forge.pr.modify
    verdict: DENY
  - capability: forge.pr.close
    verdict: DENY
  - capability: forge.pr.merge
    verdict: DENY
  - capability: forge.pr.approve
    verdict: DENY
  - capability: forge.release.publish
    verdict: DENY
  - capability: forge.release.delete
    verdict: DENY
  - capability: forge.repo.delete
    verdict: DENY
  - capability: forge.branch.protection.modify
    verdict: DENY
  - capability: forge.repo.permissions.modify
    verdict: DENY
  - capability: forge.issue.create
    verdict: DENY
  - capability: forge.issue.edit
    verdict: DENY
  - capability: forge.issue.transition
    verdict: DENY
  - capability: forge.issue.close
    verdict: DENY
  - capability: forge.issue.delete
    verdict: DENY
  - capability: forge.api.mutate
    verdict: DENY
  - capability: git.remote.push
    verdict: DENY
  - capability: git.remote.push.force
    verdict: DENY
  - capability: git.remote.tag.push
    verdict: DENY
  - capability: git.remote.branch.delete
    verdict: DENY
  - capability: git.remote.tag.delete
    verdict: DENY
---
# BENCHMARK

Runs a controlled task against a frozen repository snapshot for model comparison. Every forge write and every Harness
self-change is denied so a benchmark run can never leak into a real tracker or change the runtime under test. Human
decision gates behave exactly as in NORMAL_DELIVERY: a benchmark task that reaches one stops.
