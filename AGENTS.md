# EGO

EGO is an organization-grade, model-agnostic Agentic Engineering Control Plane kernel. This repository is the
kernel's source; consumer repositories install the released package and keep only a thin `.harness/` overlay.

The frozen architecture baseline is `docs/architecture/pre-build-package.md` (decisions Q1–Q97). Do not reopen a
settled decision; if implementation uncovers a genuine contradiction that Q1–Q97 cannot resolve, stop and say so.

## Working in this repository

- TypeScript, Node ≥ 24, zero runtime npm dependencies in the kernel; dev dependencies only.
- Tests use `node:test`; run `npm test`. Typecheck with `npm run typecheck`. Lint with `npm run lint`.
- Authored truth lives in `control-plane/`, `policies/`, `skills/`, `templates/`, `docs/`. Generated files carry a
  provenance header and are never edited by hand. Runtime state under `.harness/runtime/` is gitignored.
- Every phase of the build is recorded in `docs/build/build-log.md` with the four check lines:
  DETERMINISTIC CHECKS, IN-SESSION REVIEW, INDEPENDENT-AGENT REVIEW, CONFORMANCE. Never mark a deferred check as passed.
- Commit locally after each phase. Never push, never open pull requests, never mutate production.

## Reporting

Receipts follow the homogeneous completion receipt (section G of the baseline): status, outcome, what changed, what to
observe, affected surfaces, validation evidence, documentation, local commits, explicitly not performed, remaining
work, known limitations, risks.
