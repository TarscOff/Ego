# EGO security model

Decision "option B", taken by the product owner on 2026-09-22 after round 15 of the independent adversarial review.
This document states what each mechanism does, and — just as importantly — what it does not do. Nothing here may be
softened into a claim EGO cannot keep.

## Why this document exists

Phase 1 was originally gated on a single promise: that the command classifier could be hardened until an independent
adversarial review found nothing. Three rounds measured that promise with an identical instrument:

| Round | Confirmed findings |
|------:|-------------------:|
| 13 | 61 |
| 14 | 76 |
| 15 | 67 |

Between rounds 14 and 15 every one of the 76 findings was fixed and pinned by a test. An identical pass then found 67
more, and a large share of them were neighbouring spellings of those very fixes — several were defects the fixes
themselves introduced. The conclusion is not that the classifier is bad. It is that **exhaustively enumerating the
ways a shell can express an effect is not a security boundary**, because the enumeration has no end.

## The six mechanisms

Each does one job. None replaces another.

| Mechanism | What it actually does | What it does NOT do |
|---|---|---|
| **Git** | Records code changes and makes them reviewable | Does not constrain what a process may reach |
| **Worktrees** | Isolate Git working state between tasks | **Not containment.** A worktree shares the filesystem, the network, the credentials and the process table |
| **Authority** | Decides whether a recognised effect is permitted, and by whom | Cannot decide about an effect it was never shown |
| **Classifier** | Recognises known semantic effects in commands, paths, redirections, archives, interpreters and targets | Cannot enumerate every spelling of every effect; is not a boundary |
| **Containment** | Restricts what a process can physically reach: filesystem, network, credentials, tool surface | Does not understand intent, and **does not exist in every profile** |
| **Independent review** | Finds weaknesses in all of the above, continuously | Never proves their absence |

## The rule that holds the model together

The classifier will always have a frontier. What matters is what happens at that frontier, and the rule is:

```text
KNOWN + AUTHORIZED           -> execute according to policy
UNKNOWN / OPAQUE + CONTAINED -> execute only inside the permitted containment boundary
UNKNOWN / OPAQUE + NO ADEQUATE SANDBOX -> ASK or DENY according to policy and risk
                                       -> NEVER a silent ALLOW
```

**A sandbox is a containment boundary. A parser is not.** EGO therefore never converts "the classifier did not
recognise this" into "this is fine". It converts it into a question for a human, unless a real boundary is present to
make the question unnecessary.

This is enforced in the evaluator: a command whose effect could not be resolved reaches
`command.script-opaque` / `command.unknown`, which are `ASK`. A *declared* class (a build, a test) keeps its verdict
when its effect could not be resolved because the target **does not exist** — `npm test` with no test script fails
harmlessly — and loses it when something **will run that could not be read**: an unreadable script, a non-script
executable, a recipe built from a variable. That narrows September alignment item 5, which previously let a declared
class absorb any unresolvable effect.

## What each profile may honestly claim

Containment is a property of the host and the profile, never of the classifier. Issue #26 owns the implementation.

**Today, no profile provides OS-level containment.** The table below therefore has two separate columns: what the
profile is *designed* to provide once issue #26 lands, and what is *actually in force right now*. They must never be
conflated, and the second column is the one any claim about EGO's security has to rest on.

| Profile | Designed isolation (#26, not built) | Actually in force today | What EGO may claim today |
|---|---|---|---|
| **STANDARD** | Current checkout; policies, hooks, claims, validation | Policies, hooks, claims, validation. No process, filesystem or network restriction. | Normal local work stays fluid, and known-safe `LOCAL_WORKSPACE` operations are `ALLOW`. EGO must **not** pretend arbitrary opaque execution is physically contained. Ambiguous actions able to escape the governed workspace `ASK` or `DENY`. |
| **STRICT** | A dedicated branch and worktree per task | **Nothing beyond STANDARD.** The branch/worktree execution strategy is not implemented. | Exactly what STANDARD claims, and nothing more. Even once built, **worktree isolation is not filesystem, network or process containment.** |
| **HIGH_ASSURANCE** | Worktree plus a sandbox or managed boundary: restricted filesystem, credentials, network, external targets and tool surface | Managed-settings tamper protection and the narrowed capability set only. **No sandbox, no filesystem, credential, network or tool-surface restriction.** | Exactly what STANDARD claims. It may **not** yet rely on containment for anything. |

The third column is why the fail-safe rule currently resolves to `ASK` in *every* profile: there is no boundary to
defer to anywhere. When issue #26 lands, only the profile whose containment is both required and verified may move
unknown execution from `ASK` to a contained `ALLOW`.

When the host provides hooks only, EGO claims hooks only. `control-plane/containment/controls.md` declares each
control together with its per-host support, and `ego doctor` reports what a given host satisfies. Note a real gap:
`packages/kernel/src/hosts/matrix.ts` carries its own capability keys and **is not** the source doctor consults for
containment, so the two tables can drift apart with nothing to catch it. Reconciling them is part of issue #26.

## What the regression corpus is for

Roughly 200 reproduced bypasses are pinned as deterministic tests across
`packages/kernel/test/{bypass,effects,redact,control-plane,hooks,githooks}.test.ts`. Their purpose changed with this
decision. They are no longer evidence that the classifier is complete — they are evidence that **known** bypass
classes stay closed. A finding from a future review becomes one of three things:

1. a **regression fixture**, when it exposes a concrete known bypass;
2. a **classifier improvement**, when one semantic fix closes a real family;
3. a **containment requirement**, when interpreting it exhaustively would amount to reimplementing the shell or the
   tool. These are recorded against issue #26 rather than answered with another regex.

## Known limitations, stated plainly

- The classifier does not understand arbitrary shell, and no amount of hardening will make it do so.
- Containment is not implemented yet. Until issue #26 lands, **no profile provides OS-level containment**, which is
  precisely why unknown execution asks a human in every profile today.
- Secret detection is a catalogue. It blocks the provider formats it knows; new providers are ordinary maintenance.
- Host conformance is unverified until the phase-6 suite exists; the `codex-cli` dialect fails closed on everything
  but `ALLOW` until then.
- A human who approves an `ASK` is trusted. EGO bounds what is asked, not who answers.
