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
  - capability: harness.skills.install
    verdict: DENY
  - capability: harness.pin.change
    verdict: DENY
---
# BENCHMARK

Runs a controlled task against a frozen repository snapshot for model comparison. Every forge write and every Harness
self-change is denied so a benchmark run can never leak into a real tracker or change the runtime under test. Human
decision gates behave exactly as in NORMAL_DELIVERY: a benchmark task that reaches one stops.
