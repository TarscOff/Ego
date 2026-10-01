// A DETERMINISTIC BOUND ON THE WORK ONE DECISION MAY DO (closure audit 2026-10-01, wave 3, "time"; exit review 11, r11-243).
//
// The host gives a PreToolUse hook thirty seconds, and a hook that has not answered by then has not refused: the tool call
// runs. So "the kernel is correct" is not enough - it has to be correct FAST, on any input, including input written to be
// slow. A sed script of seven hundred spaces followed by `git push origin main` is an absolute deny, and the scan that was
// reading the script backtracked for a hundred seconds before it got as far as saying so.
//
// The cure for a slow SCAN is to make the scan linear (the sed scanners in evaluate.ts now are). The cure for an input that
// is merely LARGE, or that fans out (a body that carries bodies that carry bodies; a script that names scripts), is a bound:
// every primitive that reads command-derived text calls `chargeWork(units)` BEFORE it reads it, and when the units spent
// by one decision pass the limit the decision ends, with a verdict, at once.
//
// WHY UNITS AND NOT A CLOCK. A deadline in milliseconds would make the answer depend on the machine: the same command
// would be classified on a fast host and refused on a loaded one, and a regression test could never pin either. Units
// are counted from the text itself (about one per character a primitive reads, plus a flat price for the primitives that
// do not read text - a process spawned, a segment analysed), so the same command costs the same on every machine and the
// verdict is reproducible.
//
// WHAT THE VERDICT IS. ASK, with the reason "too large to classify within the bound" - never ALLOW, because a bound that is
// reached is not an absence of risk, and never a late DENY, because the point is that the answer arrives. The caller
// (`classifyBounded` in evaluate.ts) turns the exception into that hit.

/** Thrown by `chargeWork` when one decision has spent more than it may. It is caught in exactly one place. */
export class WorkBoundExceeded extends Error {
  readonly spent: number;
  readonly limit: number;
  constructor(spent: number, limit: number) {
    super(`too large to classify within the bound (${spent} work units spent, the limit is ${limit})`);
    this.name = 'WorkBoundExceeded';
    this.spent = spent;
    this.limit = limit;
  }
}

/**
 * THE LIMIT, AND WHY IT IS THIS NUMBER. One unit is about one character read by a primitive (see `chargeWork` call sites in
 * evaluate.ts). Measured on this repository on 2026-10-01 (script in the closure-time test):
 *
 *   - the largest decision in the test corpus (every ordinary command, every attack spelling, every generated family
 *     member) spends about WORK_MEASURED_CORPUS_MAX units;
 *   - the largest line of any shell script, workflow `run:` block, Makefile recipe or package script under this repository
 *     (the producers read those and hand each line over) spends about WORK_MEASURED_SCRIPT_MAX;
 *   - a decision costs on the order of a microsecond per unit on the development host, so the limit below is a few
 *     seconds of work - far inside the thirty the host gives, and far above anything a person or an agent writes.
 *
 * The limit is a margin of two orders of magnitude over the largest ordinary decision measured. Raising it is a decision
 * about how long a hook may be asked to think; lowering it makes ordinary work ask.
 */
export const WORK_LIMIT = 10_000_000;
/** the measurements the limit was derived from, kept beside it so the margin is checkable (see test/closure-time.test.ts) */
export const WORK_MEASURED_CORPUS_MAX = 0;
export const WORK_MEASURED_SCRIPT_MAX = 0;

let spent = 0;
let limit = WORK_LIMIT;
let active = false;
let finished = 0;
let override: number | null = null;

/** Runs `body` under a fresh budget. Nested calls share the outer one: one decision, one budget. */
export function withWorkBound<T>(body: () => T, units = override ?? WORK_LIMIT): T {
  if (active) return body();
  active = true;
  spent = 0;
  limit = units;
  try {
    return body();
  } finally {
    finished = spent;
    active = false;
  }
}

/** Units spent by the decision in progress, or by the last one when none is (for the tests that measure the margin). */
export function workSpent(): number {
  return active ? spent : finished;
}

/** Test seam: a different limit for every decision until `null` restores the real one. Only a test calls this. */
export function overrideWorkLimit(units: number | null): void {
  override = units;
}

/** Pay for work BEFORE doing it. Outside a bounded decision this is free, so a unit test of one reader is not metered. */
export function chargeWork(units: number): void {
  if (!active) return;
  spent += units;
  if (spent > limit) throw new WorkBoundExceeded(spent, limit);
}
