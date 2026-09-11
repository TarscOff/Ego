# Control plane

This directory is the authored, human-readable source of EGO's behaviour. Markdown is the authoring front-end; the
policy compiler turns it into a canonical machine representation (`policies/generated/` in this repository,
`.harness/generated/policy.json` in consumers). Generated files are never edited by hand. A malformed file here fails
compilation closed: nothing is silently weakened.

## Layout

| Directory | What it holds | Schema |
|---|---|---|
| `permissions/absolute-denies.md` | Denies no lower layer may reference or widen | `ego.capabilities/1` with `absolute: true` |
| `permissions/capabilities/*.md` | Narrow capability families with ALLOW / ASK / DENY sections | `ego.capabilities/1` |
| `permissions/matchers.md` | Deterministic operation → capability matchers (tool, command, path, URL) | `ego.matchers/1` |
| `permissions/grants.md` | Exact verb table for human grants (ASK → ALLOW, current task only) | `ego.grants/1` |
| `permissions/release-keys.md` | Trusted release signing keys (absolute-core file) | `ego.release-keys/1` |
| `profiles/*.md` | STANDARD, STRICT, HIGH_ASSURANCE: budgets, requirements, narrowing | `ego.profile/1` |
| `modes/*.md` | Authority modes (change what may happen) | `ego.mode/1` |
| `intents/*.md` | Task intents (change routing, never authority) | `ego.intent/1` |
| `secrets/*.md` | Secret detectors and redaction rules | `ego.secrets/1` |
| `surfaces/`, `risk/` | Surface catalogue and risk tiers | `ego.surfaces/1`, `ego.risk/1` |
| `workspace/coordination.md` | Coordination constants (TTLs, lock timeouts) | `ego.coordination/1` |
| `lexicon/`, `skills/`, `validations/`, `reviewers/`, `documentation/`, `decisions/` | Routing hints, skill defaults and sources, validation and reviewer catalogues, documentation surfaces, decision-gate configuration | see each file |

## Verdict semantics

Every capability has one of three verdicts per profile and authority mode: `ALLOW` (no prompt), `ASK` (human approval
through the host's permission prompt), `DENY`. Sections `## Allowed`, `## Requires human approval`, `## Denied` carry
checkbox items; a checked item is active at that layer, an unchecked item is documented but inactive. The same
identifier in two sections of one file is a compile error. Omission means inherit from the layer above.

Precedence: ABSOLUTE CORE DENY > ORGANIZATION POLICY > HARNESS PROFILE > PRODUCT OVERLAY > TASK GRANT (ASK → ALLOW
only, current task) > MODEL DECISION. A lower layer may narrow (move toward DENY) and never widen. An overlay that
references an absolute deny, or tries to widen anything, fails compilation.

## How to add things

- **A capability**: add a checked item under the right section of the family file in `permissions/capabilities/`, with
  a stable dotted identifier and a one-line description; add a matcher in `permissions/matchers.md` when the operation
  can be recognised deterministically. Run `harness policy compile` and `harness check`.
- **A permission change for a product**: in the consumer, edit `.harness/permissions.md` using the same sections; it
  may only narrow.
- **A secret detector or redaction rule**: add an entry to the relevant family in `secrets/` with `severity` (`block` or
  `warn`); core detectors carry `locked: true` and their severity may be raised, never lowered, by overlays.
- **A validation, reviewer, technology, skill, external skill provider, user intent, lexicon example, policy domain,
  compliance framework, forge provider, model adapter**: see `docs/extending-the-harness/`.
- **A mode**: add `modes/<id>.md` with `kind: authority` and its overrides; never widen an absolute deny.
- **An intent**: add `intents/<id>.md`; intents route work and change no authority.

`harness catalog` regenerates `HARNESS_CATALOG.md` from these files.
