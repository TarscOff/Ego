# Control plane

This directory is the authored, human-readable source of EGO's behaviour. Markdown is the authoring front-end; the
policy compiler turns it into a canonical machine representation (`policies/generated/` in this repository,
`.harness/generated/policy.json` in consumers). Generated files are never edited by hand. A malformed file here fails
compilation closed: nothing is silently weakened.

## Layout

| Directory | What it holds | Schema |
|---|---|---|
| `permissions/absolute-denies.md` | Denies no lower layer may reference or widen | `ego.capabilities/1` with `lock: absolute` |
| `permissions/capabilities/organization-locked.md` | Denies widenable only by the organization policy layer (Q98) | `ego.capabilities/1` with `lock: organization` |
| `containment/controls.md` | Containment controls (isolation, sandboxing) per profile and host, distinct from policy and authority | `ego.containment/1` |
| `permissions/capabilities/*.md` | Narrow capability families with ALLOW / ASK / DENY sections | `ego.capabilities/1` |
| `permissions/matchers.md` | Deterministic operation → capability matchers (tool, command, path, URL) | `ego.matchers/1` |
| `permissions/grants.md` | Exact verb table for human grants (ASK → ALLOW, current task only) | `ego.grants/1` |
| `permissions/release-keys.md` | Trusted release signing keys (absolute-core file) | `ego.release-keys/1` |
| `profiles/*.md` | STANDARD, STRICT, HIGH_ASSURANCE: context and execution budgets, requirements, narrowing | `ego.profile/1` |
| `modes/*.md` | Authority modes (change what may happen) | `ego.mode/1` |
| `intents/*.md` | Task intents (change routing, never authority) | `ego.intent/1` |
| `secrets/*.md` | Secret detectors and redaction rules | `ego.secrets/1` |
| `workspace/coordination.md` | Coordination constants (TTLs, lock timeouts) | `ego.coordination/1` |
| `surfaces/`, `risk/` (phase 2), `lexicon/`, `skills/`, `validations/`, `reviewers/`, `documentation/` (phase 3–4), `decisions/` (phase 5) | Surface catalogue and risk tiers, routing hints, skill defaults and sources, validation and reviewer catalogues, documentation surfaces, decision-gate configuration; authored in later phases (the directories appear with their first file) | see each file when authored |

## Verdict semantics

Every capability has one of three verdicts per profile and authority mode: `ALLOW` (no prompt), `ASK` (human approval
through the host's permission prompt), `DENY`. Sections `## Allowed`, `## Requires human approval`, `## Denied` carry
checkbox items; a checked item is active at that layer, an unchecked item is documented but inactive. The same
identifier in two sections of one file is a compile error. Omission means inherit from the layer above.

Precedence: ABSOLUTE CORE DENY > ORGANIZATION POLICY > HARNESS PROFILE > PRODUCT OVERLAY > TASK GRANT (ASK → ALLOW
only, current task) > MODEL DECISION. A lower layer may narrow (move toward DENY) and never widen. An overlay that
references an absolute deny, or tries to widen anything, fails compilation. The single exception is the
organization-locked tier: identifiers in `capabilities/organization-locked.md` are DENY at the core and the
organization policy layer alone may widen them; overlays, grants, modes, skills and models never can.

Commands are classified by their effect, not their spelling: `npm run <script>` is classified by the script body in
`package.json`, `./x.sh` and `bash x.sh` by the lines of the script when it is inside the workspace and static,
`make <target>` by the recipe; the most restrictive verdict found anywhere in the effect wins. A script the kernel
cannot see (missing, outside the workspace, dynamic commands, an interpreter program) is `command.script-opaque` or
`command.interpreter-script` (ASK) unless the matchers already declared the outer command's class.

## How to add things

- **A capability**: add a checked item under the right section of the family file in `permissions/capabilities/`, with
  a stable dotted identifier and a one-line description; add a matcher in `permissions/matchers.md` when the operation
  can be recognised deterministically. A checked item under any other heading is a compile error, never silently
  ignored. Run `npm test` here (the loader tests compile the control plane) and `ego check` in a consumer;
  `ego policy compile` arrives with phase 5.
- **A permission change for a product**: in the consumer, edit `.harness/permissions.md` using the same sections; it
  may only narrow.
- **A secret detector or redaction rule**: add an entry to the relevant family in `secrets/` with `severity` (`block` or
  `warn`); core detectors carry `locked: true` and their severity may be raised, never lowered, by overlays.
- **A validation, reviewer, technology, skill, external skill provider, user intent, lexicon example, policy domain,
  compliance framework, forge provider, model adapter**: `docs/extending-ego/` is authored with phase 3.
- **A mode**: add `modes/<id>.md` with `kind: authority` and its overrides; never widen an absolute deny.
- **An intent**: add `intents/<id>.md`; intents route work and change no authority.

`ego catalog` (phase 3) regenerates `HARNESS_CATALOG.md` from these files.
