// Runtime root `.harness/runtime/` per logical workspace (section E): stamp, sessions, ledger. Never canonical, never
// pushed. Record classes have one writer class each: session records owner-written, ledger append-only.
import { join } from 'node:path';
import { appendFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import {
  ensureDir,
  isDir,
  isFile,
  readJsonIfExists,
  writeJsonAtomic,
  readTextIfExists,
  writeExclusive,
} from '../util/fs.ts';
import { gitMainWorktree } from '../util/git.ts';
import { COMPATIBILITY } from '../launcher/self.ts';

export interface RuntimeStamp {
  schema: 'ego.runtime-stamp/1';
  runtimeSha256: string;
  version: string;
  runtimeStateSchema: number;
  createdAt: string;
}

export interface RuntimeRoot {
  /** absolute path of `.harness/runtime/` */
  dir: string;
  /** main worktree of the workspace root the runtime root belongs to */
  workspaceRoot: string;
  stamp: RuntimeStamp;
  created: boolean;
}

export class StampIncompatibleError extends Error {
  constructor(stamp: RuntimeStamp) {
    super(
      `runtime-root stamp incompatible: the workspace runtime state uses schema ${stamp.runtimeStateSchema} (written by ${stamp.version}), which this runtime cannot read (readable: ${COMPATIBILITY.readableRuntimeStateSchemas.join(', ')}). Run \`harness upgrade --workspace\` from a runtime that reads it, or \`harness rollback\` to the stamped runtime.`,
    );
    this.name = 'StampIncompatibleError';
  }
}

export function runtimeRootDir(projectRoot: string): string {
  const main = gitMainWorktree(projectRoot) ?? projectRoot;
  return join(main, '.harness', 'runtime');
}

/** Opens (creating if needed) the runtime root and validates the stamp against this runtime's compatibility. */
export function openRuntimeRoot(
  projectRoot: string,
  self: { runtimeSha256: string; version: string },
  now: string,
): RuntimeRoot {
  const workspaceRoot = gitMainWorktree(projectRoot) ?? projectRoot;
  const dir = join(workspaceRoot, '.harness', 'runtime');
  for (const sub of ['sessions', 'tasks', 'claims', 'ledger', 'evidence', 'decisions', 'tmp'])
    ensureDir(join(dir, sub));
  const stampPath = join(dir, 'stamp.json');
  let stamp = readJsonIfExists<RuntimeStamp>(stampPath);
  let created = false;
  if (!stamp) {
    const fresh: RuntimeStamp = {
      schema: 'ego.runtime-stamp/1',
      runtimeSha256: self.runtimeSha256,
      version: self.version,
      runtimeStateSchema: COMPATIBILITY.runtimeStateSchema,
      createdAt: now,
    };
    if (writeExclusive(stampPath, JSON.stringify(fresh, null, 2) + '\n')) {
      stamp = fresh;
      created = true;
    } else stamp = readJsonIfExists<RuntimeStamp>(stampPath)!;
  }
  if (!(COMPATIBILITY.readableRuntimeStateSchemas as readonly number[]).includes(stamp.runtimeStateSchema))
    throw new StampIncompatibleError(stamp);
  return { dir, workspaceRoot, stamp, created };
}

/** Rewrites the stamp: only `upgrade` and `sync` may call this (section E). */
export function rewriteStamp(
  root: RuntimeRoot,
  self: { runtimeSha256: string; version: string },
  now: string,
): RuntimeStamp {
  const stamp: RuntimeStamp = {
    schema: 'ego.runtime-stamp/1',
    runtimeSha256: self.runtimeSha256,
    version: self.version,
    runtimeStateSchema: COMPATIBILITY.runtimeStateSchema,
    createdAt: now,
  };
  writeJsonAtomic(join(root.dir, 'stamp.json'), stamp);
  return stamp;
}

// ---------------------------------------------------------------------------------------------------------------
// Ledger: append-only JSON lines, one file per day, redacted by the caller before append.
// ---------------------------------------------------------------------------------------------------------------

export interface LedgerEntry {
  at: string;
  kind: string;
  sessionId?: string;
  agentId?: string;
  taskId?: string;
  data?: Record<string, unknown>;
}

export function appendLedger(root: RuntimeRoot, entry: LedgerEntry): void {
  const file = join(root.dir, 'ledger', `${entry.at.slice(0, 10)}.jsonl`);
  ensureDir(join(root.dir, 'ledger'));
  appendFileSync(file, JSON.stringify(entry) + '\n');
}

export function readLedger(
  root: RuntimeRoot,
  opts: { sessionId?: string; kinds?: string[]; limit?: number } = {},
): LedgerEntry[] {
  const dir = join(root.dir, 'ledger');
  if (!isDir(dir)) return [];
  const out: LedgerEntry[] = [];
  for (const f of readdirSync(dir)
    .filter((f) => f.endsWith('.jsonl'))
    .sort()) {
    const text = readTextIfExists(join(dir, f)) ?? '';
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      try {
        const e = JSON.parse(line) as LedgerEntry;
        if (opts.sessionId && e.sessionId !== opts.sessionId) continue;
        if (opts.kinds && !opts.kinds.includes(e.kind)) continue;
        out.push(e);
      } catch {
        /* a torn line at the tail is ignored; append-only files are never rewritten */
      }
    }
  }
  return opts.limit ? out.slice(-opts.limit) : out;
}

// ---------------------------------------------------------------------------------------------------------------
// Sessions: owner-written records (one per host session), used for liveness, mode, grants and budget counters.
// ---------------------------------------------------------------------------------------------------------------

export interface SessionCounters {
  iterations: number;
  toolCalls: number;
  networkOperations: number;
  concurrentSubagents: number;
  delegationDepth: number;
  maxRetriesForOneStep: number;
  failuresByStep: Record<string, number>;
}

export interface SessionRecord {
  schema: 'ego.session/1';
  sessionId: string;
  host: string;
  cwd: string;
  pid?: number;
  startedAt: string;
  heartbeatAt: string;
  endedAt?: string;
  mode: string;
  profile: string;
  taskId?: string;
  grants: string[];
  counters: SessionCounters;
  budgetExtensions: Record<string, number>;
  budgetState?: {
    action: 'BLOCK' | 'ESCALATE';
    breaches: Array<{ dimension: string; limit: number; observed: number }>;
    since: string;
  };
  agents: Array<{
    agentId: string;
    parentAgentId?: string;
    agentType?: string;
    startedAt: string;
    endedAt?: string;
  }>;
  /** user corrections that must survive compaction (alignment item 9); bounded */
  activeCorrections: string[];
}

export function sessionPath(root: RuntimeRoot, sessionId: string): string {
  return join(root.dir, 'sessions', `${sessionId.replace(/[^A-Za-z0-9._-]/g, '_')}.json`);
}

export function readSession(root: RuntimeRoot, sessionId: string): SessionRecord | null {
  return readJsonIfExists<SessionRecord>(sessionPath(root, sessionId));
}

export function writeSession(root: RuntimeRoot, s: SessionRecord): void {
  writeJsonAtomic(sessionPath(root, s.sessionId), s);
}

export function newSession(init: {
  sessionId: string;
  host: string;
  cwd: string;
  pid?: number;
  mode: string;
  profile: string;
  now: string;
}): SessionRecord {
  const s: SessionRecord = {
    schema: 'ego.session/1',
    sessionId: init.sessionId,
    host: init.host,
    cwd: init.cwd,
    startedAt: init.now,
    heartbeatAt: init.now,
    mode: init.mode,
    profile: init.profile,
    grants: [],
    counters: {
      iterations: 0,
      toolCalls: 0,
      networkOperations: 0,
      concurrentSubagents: 0,
      delegationDepth: 0,
      maxRetriesForOneStep: 0,
      failuresByStep: {},
    },
    budgetExtensions: {},
    agents: [],
    activeCorrections: [],
  };
  if (init.pid !== undefined) s.pid = init.pid;
  return s;
}

/**
 * Mutual exclusion for one session record: an `O_EXCL` lock file with a stale break (section E lock constants). Two
 * concurrent hook invocations (parent and subagent) otherwise lose counters and budget breaches in a read-modify-write.
 */
export function withSessionLock<T>(
  root: RuntimeRoot,
  sessionId: string,
  fn: () => T,
  opts: { timeoutMs?: number; staleMs?: number } = {},
): T {
  const lock = `${sessionPath(root, sessionId)}.lock`;
  const timeout = opts.timeoutMs ?? 3000;
  const stale = opts.staleMs ?? 30000;
  const deadline = Date.now() + timeout;
  for (;;) {
    if (writeExclusive(lock, `${process.pid} ${new Date().toISOString()}\n`)) break;
    try {
      const age = Date.now() - statSync(lock).mtimeMs;
      const holder = Number((readTextIfExists(lock) ?? '').split(' ')[0]);
      // a lock whose holder is dead (killed hook) is broken at once; a live holder is waited for up to the stale limit
      if (age > stale || (Number.isFinite(holder) && holder > 0 && !processAlive(holder))) {
        rmSync(lock, { force: true });
        continue;
      }
    } catch {
      continue;
    }
    if (Date.now() > deadline)
      throw new Error(`session ${sessionId} is locked by another hook invocation (waited ${timeout} ms)`);
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
  }
  try {
    return fn();
  } finally {
    rmSync(lock, { force: true });
  }
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'EPERM';
  }
}

export function listSessions(root: RuntimeRoot): SessionRecord[] {
  const dir = join(root.dir, 'sessions');
  if (!isDir(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => readJsonIfExists<SessionRecord>(join(dir, f)))
    .filter((s): s is SessionRecord => s !== null);
}

export function isRuntimeRootPresent(projectRoot: string): boolean {
  return isFile(join(runtimeRootDir(projectRoot), 'stamp.json'));
}
