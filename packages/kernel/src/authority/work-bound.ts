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
 * THE LIMIT, AND WHY IT IS THIS NUMBER. One unit is about one character read by a primitive; the primitives that read no text pay a flat
 * price (a stage 3,000, a path judged 2,500, a write 1,500, a process spawned 100,000 - the constants sit beside their call sites in
 * evaluate.ts and paths.ts). Measured on this repository on 2026-10-01, the numbers the test of this module checks the margin of:
 *
 *   - the largest decision in the command family of the test corpus - 16,358 decisions: every ordinary command, every attack spelling
 *     and every generated variant of it - spends 535,517 units; a git command costs about 180,000 of them, because it spawns processes;
 *     a command that is not git costs a few tens of thousands;
 *   - the longest command in that corpus is 190 characters, the longest line of any script, workflow step, Makefile recipe or package
 *     script under this repository is 122, and the longest script in it (runtime/posix/git-hook.sh, 1,472 characters) spends 213,004;
 *   - a decision spends between 0.04 and 0.2 microseconds a unit on the development host, so the limit is one to two seconds of work
 *     on the shapes that are slowest per unit - a hundred kilobytes of `ln -s a b;`, answered at the limit in about a second - and a
 *     small fraction of the thirty the host gives. A machine several times slower, and a host that is busy, still answer in time.
 *
 * The limit is nineteen times the largest decision measured, and about fifty git commands in one call. Raising it is a decision about
 * how long a hook may be asked to think; lowering it makes ordinary work ask.
 *
 * RE-MEASURED AFTER THE OTHER WAVE-3 READERS WERE MERGED (2026-10-02: the carrier table, the option parser, the database, container, cluster
 * and make readers, the wildcard sets, the role of a word). They cost more per command than the readers the numbers above were taken
 * against, and the limit was NOT raised: of the 253 ordinary commands of the corpus the largest spends 414,780 units (`watch 'git status;
 * ls'`: two git processes), of its 1,020 attack spellings 842,265, and of every generated variant of them - 108,232 decisions - 1,286,948
 * (`docker exec box -- docker buildx bake --set …`); the 99.9th percentile is 847,078 and none reaches the bound. The limit is 7.8 times the
 * largest of them all, 24 times the largest ordinary command. What the merge added that was NOT priced - a pairing of racing stages, a
 * brace expansion, a directory listing, a `stat` of a directory - was found by timing shapes just under the 32 KiB a stage may have
 * (closure-git-env.test.ts) and is priced beside its call site now. A wildcard that matches two thousand paths is judged two thousand
 * times and spends about half of the limit (it asks anyway: the expansion is bounded at two thousand).
 */
export const WORK_LIMIT = 10_000_000;

let spent = 0;
let limit = WORK_LIMIT;
let active = false;
let finished = 0;
let override: number | null = null;
let decisions = 0;

/** Runs `body` under a fresh budget. Nested calls share the outer one: one decision, one budget. */
export function withWorkBound<T>(body: () => T, units = override ?? WORK_LIMIT): T {
  if (active) return body();
  active = true;
  decisions += 1;
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

/* ------------------------------------------------------------------------------------------------------------- *
 * A MEMO SAVES TIME, NOT THE BOUND (closure audit 2026-10-02, RB-7)
 * ------------------------------------------------------------------------------------------------------------- */

/**
 * A value remembered across decisions - the toplevel of a directory, the hooks directories of a context - because computing it costs a
 * process or a read. The header of this module says the units a decision spends are the command's: "the same command costs the same on
 * every machine". A memo that skipped the charge made them the process's: a warm process spent 100,000 units less than a cold one on
 * the same command (the spawn it did not make), and a command within that margin of the limit was answered by one and refused by the
 * other. So the FIRST use of an entry in each decision pays what computing it cost, exactly once; the uses after it in the same
 * decision are free, as they always were.
 */
export class DecisionMemo<K extends object | string, V> {
  private readonly entries: { get(k: K): MemoEntry<V> | undefined; set(k: K, e: MemoEntry<V>): unknown };
  /** `weak`: the keys are objects, and the memo must not keep them alive */
  constructor(weak = false) {
    this.entries = (weak ? new WeakMap<WeakKey, MemoEntry<V>>() : new Map<K, MemoEntry<V>>()) as unknown as DecisionMemo<K, V>['entries'];
  }
  get(key: K, compute: () => V): V {
    const hit = this.entries.get(key);
    if (hit) {
      if (hit.paidIn !== decisions) {
        hit.paidIn = decisions;
        chargeWork(hit.cost);
      }
      return hit.value;
    }
    const before = workSpent();
    const value = compute();
    this.entries.set(key, { value, cost: Math.max(0, workSpent() - before), paidIn: decisions });
    return value;
  }
}

interface MemoEntry<V> {
  value: V;
  /** what computing it cost, in work units */
  cost: number;
  /** the decision that last paid for it */
  paidIn: number;
}
