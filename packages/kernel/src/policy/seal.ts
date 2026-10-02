// THE POLICY CACHE IS SEALED WITH A SECRET THE WORKING TREE CANNOT WRITE (closure audit 2026-10-02, AUTH-5).
//
// `.harness/generated/policy.json` records the table every hook enforces AND which layer widenings a human accepted (`acceptedLayerSources`). Its
// integrity field was an unkeyed sha256 of its own body: anyone who can write the file can compute it. The agent cannot write the file (an absolute
// deny, `ego.runtime.tamper`) and the pre-commit hook refuses to commit it, but a TEAMMATE's commit can carry it (`git add -f`, or a machine without
// the hook): a cache whose table already holds the widening, whose `layerSources` equal what the layer files hash to and whose accepted record
// says a human accepted it was read by the next hook of every clone as exactly that - a human acceptance nobody gave. `ego check` reported it
// fresh, because the forged record equals what `ego init` would have written.
//
// The seal is an HMAC-SHA256 over the whole record (minus the seal), keyed by a secret that lives in EGO_HOME: outside every working tree, the home
// of the trust store the path rules already make an absolute deny (`ego.trust.tamper`), written by `ego init` on a person's machine and never
// distributed. A cache whose seal does not verify is not the one this machine wrote, and is treated as ABSENT: recompiled, with every widening
// in the layer files pending a human, whatever it said it had accepted.
//
// Three states of the argument every reader takes: a key (verify), `null` (a seal is required and this machine has no key: nothing can be
// verified, so nothing is read), and `undefined` (no authentication: the unit tests of the compiler, which have no home). Production callers pass
// the first two - `sealFor(env)` - and a test (closure-authority2.test.ts) reads the callers for a call that does not.
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { closeSync, fsyncSync, mkdirSync, openSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { egoHome } from '../launcher/home.ts';
import { isDir, readTextIfExists } from '../util/fs.ts';
import { canonicalJson } from '../util/hash.ts';

export interface SealKey {
  readonly hex: string;
}

const KEY_FILE = 'policy-seal.key';

/** a file with nobody else's permissions from its first byte: the secret is never readable by another user, not even for the instant between create and chmod */
function writeSecret(path: string, data: string, replace: boolean): boolean {
  mkdirSync(dirname(path), { recursive: true });
  const target = replace ? `${path}.tmp-${process.pid}-${randomBytes(4).toString('hex')}` : path;
  let fd: number;
  try {
    fd = openSync(target, 'wx', 0o600);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'EEXIST') return false;
    throw e;
  }
  try {
    writeFileSync(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  if (replace) renameSync(target, path);
  return true;
}

/**
 * The key in `home`, or null when there is none and `create` is false (or it cannot be made). Never throws: a home that cannot be read is no key.
 * `repair` (only the command a person runs - `ego init`) replaces a key file that is not a key: a truncated copy, an empty file a sync tool made.
 * It would otherwise be a permanent absence, and every hook of the machine would compile the policy afresh and write nothing. The caches sealed
 * under the old key cannot be verified anyway; every widening in them comes back pending.
 */
export function sealKeyIn(home: { root: string }, opts: { create: boolean; repair?: boolean }): SealKey | null {
  const path = join(home.root, KEY_FILE);
  const read = (): SealKey | null => {
    try {
      const text = (readTextIfExists(path) ?? '').trim();
      return /^[0-9a-f]{64}$/.test(text) ? { hex: text } : null;
    } catch {
      return null;
    }
  };
  const had = read();
  if (had || !opts.create) return had;
  try {
    const present = readTextIfExists(path) !== null;
    if (present && !opts.repair) return null;
    writeSecret(path, `${randomBytes(32).toString('hex')}\n`, present);
  } catch {
    return null;
  }
  // (two creators race on the exclusive write; whichever lost reads the winner's key)
  return read();
}

/**
 * The key a hook, a command or a git hook uses on this machine: the one in EGO_HOME, created when the home directory exists (it does once
 * `ego init` has run anywhere on this machine) and never created in a home that does not - a hook must not make a directory in a place nobody
 * set up.
 */
export function sealFor(env: NodeJS.ProcessEnv = process.env): SealKey | null {
  const home = egoHome(env);
  return sealKeyIn(home, { create: isDir(home.root) });
}

/** The seal of a record: the HMAC of its canonical form, without the seal itself. */
export function sealOf(record: Record<string, unknown>, key: SealKey): string {
  const { seal: _own, ...body } = record;
  return createHmac('sha256', Buffer.from(key.hex, 'hex')).update(canonicalJson(body)).digest('hex');
}

export function sealVerifies(record: Record<string, unknown>, key: SealKey): boolean {
  const given = record['seal'];
  if (typeof given !== 'string' || !/^[0-9a-f]{64}$/.test(given)) return false;
  return timingSafeEqual(Buffer.from(given, 'hex'), Buffer.from(sealOf(record, key), 'hex'));
}
