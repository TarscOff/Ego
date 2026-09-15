// EGO_HOME layout (decision Q79): runtimes/ immutable bytes, releases/ append-only metadata, trust/ store,
// index/ mutable mappings, mirror/ skills and docs, pins/ bounded local pin history.
import { homedir } from 'node:os';
import { join } from 'node:path';
import { cpSync, renameSync, existsSync, readdirSync, readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { ensureDir, readJsonIfExists, writeJsonAtomic, isDir, writeAtomic, isFile } from '../util/fs.ts';
import { computeInternalManifest, identityFromManifest, listRuntimeFiles } from './identity.ts';

export interface EgoHome {
  root: string;
  runtimes: string;
  releases: string;
  trust: string;
  index: string;
  mirror: string;
  pins: string;
}

export function egoHome(env: NodeJS.ProcessEnv = process.env): EgoHome {
  const root = env['EGO_HOME'] && env['EGO_HOME'].trim() !== '' ? env['EGO_HOME'] : join(homedir(), '.ego');
  return {
    root,
    runtimes: join(root, 'runtimes'),
    releases: join(root, 'releases'),
    trust: join(root, 'trust'),
    index: join(root, 'index'),
    mirror: join(root, 'mirror'),
    pins: join(root, 'pins'),
  };
}

export function ensureHome(home: EgoHome): void {
  for (const d of [home.root, home.runtimes, home.releases, home.trust, home.index, home.mirror, home.pins])
    ensureDir(d);
}

// ---------------------------------------------------------------------------------------------------------------
// Index: one file per <name>@<version>, one current identity per version string, acquisition records, displaced list.
// ---------------------------------------------------------------------------------------------------------------

export type TrustLevel =
  | 'registry (unsigned)'
  | 'local-tarball (unsigned)'
  | 'bundle (unsigned)'
  | 'signed-release'
  | 'bundle (signed-release)';
export type IdentityState = 'SUPERSEDED' | 'TAMPERED' | 'REVOKED';

export const TRUST_RANK: Record<TrustLevel, number> = {
  'registry (unsigned)': 0,
  'local-tarball (unsigned)': 0,
  'bundle (unsigned)': 0,
  'signed-release': 1,
  'bundle (signed-release)': 1,
};

export interface AcquisitionRecord {
  source: string;
  trust: TrustLevel;
  verifiedByKeyId?: string;
  cachedAt: string;
}

export interface IndexEntry {
  schema: 'ego.index/1';
  name: string;
  version: string;
  identity: string;
  records: AcquisitionRecord[];
  displaced: Array<{ identity: string; state: IdentityState; at: string; reason?: string }>;
  /** state of the current identity when not healthy */
  state?: IdentityState;
}

export function indexPath(home: EgoHome, name: string, version: string): string {
  return join(home.index, `${name.replace(/\//g, '__')}@${version}.json`);
}

export function readIndex(home: EgoHome, name: string, version: string): IndexEntry | null {
  return readJsonIfExists<IndexEntry>(indexPath(home, name, version));
}

export function listIndexEntries(home: EgoHome): IndexEntry[] {
  if (!isDir(home.index)) return [];
  return readdirSync(home.index)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => readJsonIfExists<IndexEntry>(join(home.index, f)))
    .filter((e): e is IndexEntry => e !== null);
}

export class IdentityConflictError extends Error {
  readonly existing: string;
  readonly incoming: string;
  constructor(version: string, existing: string, incoming: string, hard: boolean) {
    super(
      `IDENTITY_CONFLICT: version ${version} is already mapped to runtime identity ${existing.slice(0, 12)}…; refusing a different identity ${incoming.slice(0, 12)}…${hard ? ' (both signature-backed: resolve out of band, see bootstrap doctor)' : ' (unsigned mapping keeps the first identity)'}`,
    );
    this.name = 'IdentityConflictError';
    this.existing = existing;
    this.incoming = incoming;
  }
}

/**
 * Adds an acquisition record for (name, version, identity). Enforces one current identity per version string across
 * all names (Q79): signed replaces unsigned (displaced → SUPERSEDED), unsigned vs unsigned is refused first-wins,
 * signed vs signed is a hard conflict.
 */
export function indexAdd(
  home: EgoHome,
  name: string,
  version: string,
  identity: string,
  record: AcquisitionRecord,
  now: string,
): IndexEntry {
  ensureHome(home);
  const incomingSigned = TRUST_RANK[record.trust] > 0;
  // cross-name check on the same version string
  for (const other of listIndexEntries(home)) {
    if (other.version === version && other.identity !== identity) {
      const existingSigned = other.records.some((r) => TRUST_RANK[r.trust] > 0);
      if (existingSigned && incomingSigned)
        throw new IdentityConflictError(version, other.identity, identity, true);
      if (!incomingSigned) throw new IdentityConflictError(version, other.identity, identity, false);
      // incoming is signed, existing is unsigned: displace it
      other.displaced.push({
        identity: other.identity,
        state: 'SUPERSEDED',
        at: now,
        reason: `superseded by signed identity ${identity.slice(0, 12)}`,
      });
      other.identity = identity;
      other.records = [];
      writeJsonAtomic(indexPath(home, other.name, other.version), other);
    }
  }
  const path = indexPath(home, name, version);
  let entry = readJsonIfExists<IndexEntry>(path);
  if (!entry) {
    entry = { schema: 'ego.index/1', name, version, identity, records: [], displaced: [] };
  } else if (entry.identity !== identity) {
    const existingSigned = entry.records.some((r) => TRUST_RANK[r.trust] > 0);
    if (existingSigned && incomingSigned)
      throw new IdentityConflictError(version, entry.identity, identity, true);
    if (!incomingSigned) throw new IdentityConflictError(version, entry.identity, identity, false);
    entry.displaced.push({
      identity: entry.identity,
      state: 'SUPERSEDED',
      at: now,
      reason: `superseded by signed identity ${identity.slice(0, 12)}`,
    });
    entry.identity = identity;
    entry.records = [];
    delete entry.state;
  }
  const dup = entry.records.find(
    (r) =>
      r.source === record.source && r.trust === record.trust && r.verifiedByKeyId === record.verifiedByKeyId,
  );
  if (!dup) entry.records.push(record);
  writeJsonAtomic(path, entry);
  return entry;
}

export function setIdentityState(
  home: EgoHome,
  name: string,
  version: string,
  state: IdentityState | undefined,
): void {
  const path = indexPath(home, name, version);
  const entry = readJsonIfExists<IndexEntry>(path);
  if (!entry) return;
  if (state) entry.state = state;
  else delete entry.state;
  writeJsonAtomic(path, entry);
}

/** Effective trust: highest non-revoked record (Q96). Records verified by a revoked key are excluded. */
export function effectiveTrust(entry: IndexEntry, revokedKeyIds: Set<string>): TrustLevel | null {
  let best: TrustLevel | null = null;
  for (const r of entry.records) {
    if (r.verifiedByKeyId && revokedKeyIds.has(r.verifiedByKeyId)) continue;
    if (best === null || TRUST_RANK[r.trust] > TRUST_RANK[best]) best = r.trust;
  }
  return best;
}

export function isSignedTrust(level: TrustLevel | null): boolean {
  return level !== null && TRUST_RANK[level] > 0;
}

// ---------------------------------------------------------------------------------------------------------------
// Runtime cache: immutable directories written once by temp-dir-and-rename.
// ---------------------------------------------------------------------------------------------------------------

export function runtimeDir(home: EgoHome, identity: string): string {
  return join(home.runtimes, identity);
}

export function isRuntimeCached(home: EgoHome, identity: string): boolean {
  return isDir(runtimeDir(home, identity)) && isFile(join(runtimeDir(home, identity), 'dist', 'ego.js'));
}

/** Copies a verified package root into the cache. Idempotent: an existing directory is never touched. */
export function materializeRuntime(
  home: EgoHome,
  sourceRoot: string,
  expectedIdentity: string,
): { created: boolean; dir: string } {
  ensureHome(home);
  const target = runtimeDir(home, expectedIdentity);
  if (existsSync(target)) return { created: false, dir: target };
  const manifest = computeInternalManifest(sourceRoot);
  const actual = identityFromManifest(manifest);
  if (actual !== expectedIdentity)
    throw new Error(
      `refusing to materialize: computed identity ${actual.slice(0, 12)}… does not match expected ${expectedIdentity.slice(0, 12)}…`,
    );
  const tmp = `${target}.tmp-${process.pid}-${randomBytes(4).toString('hex')}`;
  ensureDir(tmp);
  for (const rel of listRuntimeFiles(sourceRoot)) {
    cpSync(join(sourceRoot, rel), join(tmp, rel), { recursive: false, force: true, dereference: true });
  }
  writeAtomic(join(tmp, 'manifest.internal.json'), JSON.stringify(manifest, null, 2) + '\n');
  renameSync(tmp, target);
  return { created: true, dir: target };
}

/** Moves a tampered directory aside so it can be re-materialized (the only permitted replacement, Q79). */
export function quarantineRuntime(home: EgoHome, identity: string, now: string): string | null {
  const target = runtimeDir(home, identity);
  if (!existsSync(target)) return null;
  const aside = `${target}.tampered-${now.replace(/[^0-9]/g, '').slice(0, 14)}`;
  renameSync(target, aside);
  return aside;
}

// ---------------------------------------------------------------------------------------------------------------
// Release metadata store: append-only, never overwritten.
// ---------------------------------------------------------------------------------------------------------------

export function releaseDir(home: EgoHome, identity: string): string {
  return join(home.releases, identity);
}

export class ReleaseMetadataMismatch extends Error {
  constructor(file: string) {
    super(
      `release metadata mismatch: ${file} already exists with different bytes (releases/ is append-only)`,
    );
    this.name = 'ReleaseMetadataMismatch';
  }
}

export function appendReleaseFile(
  home: EgoHome,
  identity: string,
  fileName: string,
  content: Buffer | string,
): 'written' | 'identical' {
  const dir = releaseDir(home, identity);
  ensureDir(dir);
  const path = join(dir, fileName);
  const buf = Buffer.isBuffer(content) ? content : Buffer.from(content);
  if (isFile(path)) {
    // binary-safe comparison: signature files are raw bytes
    if (readFileSync(path).equals(buf)) return 'identical';
    throw new ReleaseMetadataMismatch(fileName);
  }
  writeAtomic(path, buf);
  return 'written';
}

export function releaseFiles(home: EgoHome, identity: string): string[] {
  const dir = releaseDir(home, identity);
  return isDir(dir) ? readdirSync(dir).sort() : [];
}
