import {
  mkdirSync,
  readFileSync,
  writeFileSync,
  renameSync,
  existsSync,
  statSync,
  readdirSync,
  openSync,
  closeSync,
  fsyncSync,
  rmSync,
} from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { randomBytes } from 'node:crypto';

export function readText(path: string): string {
  return readFileSync(path, 'utf8');
}

export function readTextIfExists(path: string): string | null {
  try {
    return readFileSync(path, 'utf8');
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw e;
  }
}

export function readJson<T = unknown>(path: string): T {
  return JSON.parse(readFileSync(path, 'utf8')) as T;
}

export function readJsonIfExists<T = unknown>(path: string): T | null {
  const t = readTextIfExists(path);
  return t === null ? null : (JSON.parse(t) as T);
}

/**
 * JSON from a file that is DERIVED STATE - a policy cache, a generated manifest: something `ego init` writes and any run can
 * write again. Such a file that cannot be read is ABSENT, never fatal: a zero-byte file left by a sync tool or a crash, a
 * truncated write, a hand edit, a conflict marker, a directory where the file should be. The reader that threw on these made
 * every hook event, `ego doctor` and `ego init` - the remedy the error itself names - exit 2 until a person deleted a
 * protected generated file by hand (closure audit 2026-10-02, AUTH-2). Do NOT use it for state that cannot be regenerated (a
 * session record, the runtime stamp, the trust store): for those a file that does not parse is a refusal, not an absence.
 */
export function readJsonIfReadable<T = unknown>(path: string): T | null {
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as T;
  } catch {
    return null;
  }
}

/** Atomic write: temp file in the same directory, fsync, rename. */
export function writeAtomic(path: string, data: string | Uint8Array): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp-${process.pid}-${randomBytes(4).toString('hex')}`;
  const fd = openSync(tmp, 'w');
  try {
    writeFileSync(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
}

export function writeJsonAtomic(path: string, value: unknown): void {
  writeAtomic(path, JSON.stringify(value, null, 2) + '\n');
}

/** Create-only write (O_EXCL). Returns false when the file already exists. */
export function writeExclusive(path: string, data: string): boolean {
  mkdirSync(dirname(path), { recursive: true });
  try {
    const fd = openSync(path, 'wx');
    try {
      writeFileSync(fd, data);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    return true;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'EEXIST') return false;
    throw e;
  }
}

export function ensureDir(path: string): void {
  mkdirSync(path, { recursive: true });
}

export function exists(path: string): boolean {
  return existsSync(path);
}

export function isDir(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

export function isFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

export function removeRecursive(path: string): void {
  rmSync(path, { recursive: true, force: true });
}

export interface WalkOptions {
  /** directory names to skip anywhere in the tree */
  skipDirs?: string[];
  /** list symbolic links as entries (never followed); used to detect links planted in immutable directories */
  includeSymlinks?: boolean;
  /** maximum depth (root = 0); undefined = unlimited */
  maxDepth?: number;
}

/** Deterministic recursive file listing (sorted, POSIX-relative paths). */
export function walkFiles(root: string, opts: WalkOptions = {}): string[] {
  const skip = new Set(opts.skipDirs ?? ['node_modules', '.git']);
  const out: string[] = [];
  const visit = (dir: string, depth: number) => {
    if (opts.maxDepth !== undefined && depth > opts.maxDepth) return;
    const entries = readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
      a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
    );
    for (const ent of entries) {
      const full = join(dir, ent.name);
      if (ent.isDirectory()) {
        if (skip.has(ent.name)) continue;
        visit(full, depth + 1);
      } else if (ent.isFile() || (opts.includeSymlinks && ent.isSymbolicLink())) {
        out.push(relative(root, full).split(sep).join('/'));
      }
    }
  };
  visit(root, 0);
  return out.sort();
}

export function toPosix(p: string): string {
  return p.split(sep).join('/');
}

export function absolute(p: string, base = process.cwd()): string {
  return resolve(base, p);
}
