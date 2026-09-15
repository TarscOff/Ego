// Launcher-set operations (section J): `sync` from cache and `file:` sources, trust promotion, `distribution
// import|verify`, `bootstrap doctor [--reverify]`. Network source adapters (npm, HTTPS, GitHub Release) land in
// phase 6; until then remote sources are reported as skipped by name, never silently.
import { join, resolve, basename } from 'node:path';
import { readFileSync, readdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import type { Pin } from './pin.ts';
import {
  type EgoHome,
  ensureHome,
  readIndex,
  indexAdd,
  effectiveTrust,
  isSignedTrust,
  isRuntimeCached,
  materializeRuntime,
  appendReleaseFile,
  releaseDir,
  releaseFiles,
  listIndexEntries,
  setIdentityState,
  runtimeDir,
  quarantineRuntime,
  type TrustLevel,
} from './home.ts';
import { loadTrustStore, seedAndMergeRevocations, revokedKeyIds, verifySignatures } from './trust.ts';
import {
  parseSha256Sums,
  listSignatureFiles,
  readExternalManifest,
  extractNpmTarball,
  tarballSha256,
  type ExternalManifest,
} from './artifacts.ts';
import { computeRuntimeIdentity, verifyRuntimeDirectory, isDevelopmentVersion } from './identity.ts';
import { loadControlPlane } from '../control-plane/load.ts';
import { isDir, isFile, readJsonIfExists } from '../util/fs.ts';
import { selfVersion } from './self.ts';
import { sha256Hex } from '../util/hash.ts';

export interface SourceRef {
  kind: 'npm' | 'github-release' | 'https' | 'file';
  raw: string;
  target: string;
}

export function parseSource(raw: string): SourceRef {
  const m = /^(npm|github-release|https|file):(.+)$/.exec(raw);
  if (!m)
    throw new Error(
      `invalid source "${raw}" (expected npm:<pkg>, github-release:<owner/repo>, https:<url>, file:<path>)`,
    );
  return { kind: m[1] as SourceRef['kind'], raw, target: m[2]! };
}

/** Seeds the trust store from the executing package's release-keys.md under bootstrap trust (every launcher start). */
export function seedTrust(
  home: EgoHome,
  controlPlaneRoot: string,
  now: string,
): { added: string[]; revoked: string[] } {
  const cp = loadControlPlane(controlPlaneRoot);
  const r = seedAndMergeRevocations(home, cp.releaseKeys.keys, selfVersion(), now);
  return { added: r.added, revoked: r.revoked };
}

export interface ReleaseMetadataSet {
  dir: string;
  manifest: ExternalManifest;
  /** sha256 of the manifest.json bytes as read, compared with the signed SHA256SUMS entry */
  manifestSha256: string;
  sums: Buffer;
  sumsEntries: ReturnType<typeof parseSha256Sums>;
  signatures: ReturnType<typeof listSignatureFiles>;
}

/** Reads a release metadata directory (manifest.json, SHA256SUMS, SHA256SUMS.<keyid>.sig). */
export function readReleaseMetadata(dir: string): ReleaseMetadataSet | null {
  const manifestPath = join(dir, 'manifest.json');
  const sumsPath = join(dir, 'SHA256SUMS');
  if (!isFile(manifestPath) || !isFile(sumsPath)) return null;
  const sums = readFileSync(sumsPath);
  const manifestBytes = readFileSync(manifestPath);
  return {
    dir,
    manifest: readExternalManifest(manifestPath),
    manifestSha256: sha256Hex(manifestBytes),
    sums,
    sumsEntries: parseSha256Sums(sums.toString('utf8')),
    signatures: listSignatureFiles(dir),
  };
}

export interface VerificationResult {
  trusted: boolean;
  verifiedByKeyId?: string;
  reasons: string[];
}

/** Verifies release metadata against the trust store and, when given, a tarball's transport hash. */
/**
 * Verification = at least one `SHA256SUMS.<keyid>.sig` verifies under a trusted, non-revoked key (section J); other
 * signature files (older keys, revoked keys, unknown keys after a rotation) are reported, never fatal. The signed
 * `SHA256SUMS` must list `manifest.json` with the hash of the manifest bytes actually read, so a forged manifest can
 * never borrow a genuine signature set to promote an attacker-chosen runtime identity.
 */
export function verifyReleaseMetadata(
  home: EgoHome,
  meta: ReleaseMetadataSet,
  tarballPath?: string,
): VerificationResult {
  const reasons: string[] = [];
  const notes: string[] = [];
  const store = loadTrustStore(home);
  if (meta.signatures.length === 0) reasons.push('no SHA256SUMS.<keyid>.sig signature file');
  const sig = verifySignatures(
    store,
    meta.sums,
    meta.signatures.map((s) => ({ keyId: s.keyId, signature: s.signature })),
  );
  for (const c of sig.checks) {
    if (!c.ok)
      notes.push(
        `signature by key ${c.keyId}: ${store.keys.some((k) => k.id === c.keyId) ? 'INVALID' : 'unknown key'}`,
      );
    else if (c.revoked) notes.push(`signature by key ${c.keyId}: valid but the key is REVOKED`);
  }
  if (!sig.trusted)
    reasons.push(
      `no signature verifies under a trusted, non-revoked key (${notes.join('; ') || 'no checks'})`,
    );
  const manifestEntry = meta.sumsEntries.find((e) => e.file === 'manifest.json');
  if (!manifestEntry)
    reasons.push('SHA256SUMS does not list manifest.json: the manifest is not bound to the signature');
  else if (manifestEntry.sha256 !== meta.manifestSha256)
    reasons.push('manifest.json bytes differ from the signed SHA256SUMS entry');
  const listed = meta.sumsEntries.find((e) => e.file === meta.manifest.tarballFile);
  if (!listed) reasons.push(`SHA256SUMS does not list ${meta.manifest.tarballFile}`);
  else if (listed.sha256 !== meta.manifest.tarballSha256)
    reasons.push('manifest tarballSha256 differs from SHA256SUMS');
  if (tarballPath) {
    const actual = tarballSha256(tarballPath);
    if (actual !== meta.manifest.tarballSha256)
      reasons.push(
        `tarball hash ${actual.slice(0, 12)} differs from the signed ${meta.manifest.tarballSha256.slice(0, 12)}`,
      );
  }
  const out: VerificationResult = {
    trusted: sig.trusted && reasons.length === 0,
    reasons: [...reasons, ...notes.map((n) => `note: ${n}`)],
  };
  if (sig.verifiedByKeyId) out.verifiedByKeyId = sig.verifiedByKeyId;
  return out;
}

export function appendReleaseMetadata(home: EgoHome, identity: string, meta: ReleaseMetadataSet): string[] {
  const written: string[] = [];
  for (const f of ['manifest.json', 'SHA256SUMS', ...meta.signatures.map((s) => s.file)]) {
    if (appendReleaseFile(home, identity, f, readFileSync(join(meta.dir, f))) === 'written') written.push(f);
  }
  return written;
}

export interface PromotionResult {
  promoted: boolean;
  trust: TrustLevel | null;
  message: string;
  skipped: string[];
}

/**
 * Trust promotion (section J): obtain signed release metadata for the pinned identity from any release-metadata
 * source, verify a signature, check runtime_sha256 equals the pin and the cached bytes, append, raise index trust.
 */
export function promoteTrustFromSources(
  home: EgoHome,
  pin: Pin,
  controlPlaneRoot: string,
  now: string,
  opts: { offline: boolean; env: NodeJS.ProcessEnv },
): PromotionResult {
  ensureHome(home);
  seedTrust(home, controlPlaneRoot, now);
  const entry = readIndex(home, pin.name, pin.version);
  const store = loadTrustStore(home);
  const current = entry ? effectiveTrust(entry, revokedKeyIds(store)) : null;
  if (isDevelopmentVersion(pin.version))
    return {
      promoted: false,
      trust: current,
      message: 'DEV_IDENTITY_NOT_PROMOTABLE: development identities carry no signed release metadata',
      skipped: [],
    };
  if (isSignedTrust(current))
    return { promoted: false, trust: current, message: `trust already ${current}`, skipped: [] };
  const skipped: string[] = [];
  const candidates: string[] = [];
  for (const raw of pin.sources) {
    let src: SourceRef;
    try {
      src = parseSource(raw);
    } catch (e) {
      skipped.push(`${raw}: ${(e as Error).message}`);
      continue;
    }
    if (src.kind === 'file') candidates.push(resolve(src.target));
    else skipped.push(`${raw}: ${opts.offline ? 'offline' : 'remote source adapters land in phase 6'}`);
  }
  // a release metadata set already appended under releases/<identity>/ counts as a local source
  if (releaseFiles(home, pin.integrity).includes('manifest.json'))
    candidates.unshift(releaseDir(home, pin.integrity));
  for (const dir of candidates) {
    const metaDir = findMetadataDir(dir, pin.version);
    if (!metaDir) {
      skipped.push(`${dir}: no release metadata for ${pin.version}`);
      continue;
    }
    const meta = readReleaseMetadata(metaDir);
    if (!meta) continue;
    if (meta.manifest.runtimeSha256 !== pin.integrity) {
      skipped.push(
        `${metaDir}: manifest runtime identity ${meta.manifest.runtimeSha256.slice(0, 12)} is not the pinned ${pin.integrity.slice(0, 12)}`,
      );
      continue;
    }
    const v = verifyReleaseMetadata(home, meta);
    if (!v.trusted) {
      skipped.push(`${metaDir}: ${v.reasons.join('; ')}`);
      continue;
    }
    if (isRuntimeCached(home, pin.integrity)) {
      const check = verifyRuntimeDirectory(runtimeDir(home, pin.integrity), pin.integrity);
      if (!check.ok) {
        setIdentityState(home, pin.name, pin.version, 'TAMPERED');
        return {
          promoted: false,
          trust: current,
          message: `TAMPERED: cached runtime ${pin.integrity.slice(0, 12)} recomputes to ${check.actual.slice(0, 12)}; run \`harness distribution import\` to re-materialize`,
          skipped,
        };
      }
    }
    appendReleaseMetadata(home, pin.integrity, meta);
    const rec = {
      source: metaDir === releaseDir(home, pin.integrity) ? 'releases-store' : `file:${metaDir}`,
      trust: 'signed-release' as TrustLevel,
      verifiedByKeyId: v.verifiedByKeyId!,
      cachedAt: now,
    };
    indexAdd(home, pin.name, pin.version, pin.integrity, rec, now);
    // a legitimately re-established trust (re-signed metadata under a current key, verified bytes) clears REVOKED
    if (entry?.state === 'REVOKED' || (entry?.state === 'TAMPERED' && isRuntimeCached(home, pin.integrity)))
      setIdentityState(home, pin.name, pin.version, undefined);
    return {
      promoted: true,
      trust: 'signed-release',
      message: `trust: ${current ?? 'none'} -> signed-release (key ${v.verifiedByKeyId})`,
      skipped,
    };
  }
  return {
    promoted: false,
    trust: current,
    message: `trust unchanged (${current ?? 'not indexed'}); ${skipped.length ? 'sources tried: ' + skipped.join(' | ') : 'no release-metadata source available'}`,
    skipped,
  };
}

function findMetadataDir(dir: string, version: string): string | null {
  if (!isDir(dir)) return null;
  if (isFile(join(dir, 'manifest.json'))) return dir;
  for (const cand of [join(dir, version), join(dir, `v${version}`), join(dir, `ego-${version}`)])
    if (isFile(join(cand, 'manifest.json'))) return cand;
  return null;
}

export interface SyncResult {
  ok: boolean;
  messages: string[];
  cached: boolean;
  trust: TrustLevel | null;
}

/** `sync`: ensure a hash-verified cache entry for the pinned identity from the equal launcher or `file:` sources; promote trust. */
export function syncProject(
  home: EgoHome,
  pin: Pin,
  launcher: { root: string; runtimeSha256: string; version: string },
  controlPlaneRoot: string,
  now: string,
  opts: { offline: boolean; env: NodeJS.ProcessEnv },
): SyncResult {
  ensureHome(home);
  const messages: string[] = [];
  if (!isRuntimeCached(home, pin.integrity)) {
    if (launcher.runtimeSha256 === pin.integrity && isFile(join(launcher.root, 'dist', 'ego.js'))) {
      materializeRuntime(home, launcher.root, pin.integrity);
      indexAdd(
        home,
        pin.name,
        pin.version,
        pin.integrity,
        {
          source: 'launcher',
          trust: isDevelopmentVersion(pin.version) ? 'local-tarball (unsigned)' : 'registry (unsigned)',
          cachedAt: now,
        },
        now,
      );
      messages.push(`materialized the launcher runtime ${pin.integrity.slice(0, 12)} into the cache`);
    } else {
      const got = acquireFromFileSources(home, pin, now, messages);
      if (!got) {
        messages.push(
          `EGO ${pin.version} (runtime ${pin.integrity.slice(0, 12)}) is pinned but not installed and no local source provides it${opts.offline ? ' (offline: cache and file: sources only)' : ' (remote source adapters land in phase 6)'}. Run \`harness distribution import <bundle-or-tarball>\` or add a file: source with \`harness sources add\`.`,
        );
        return { ok: false, messages, cached: false, trust: null };
      }
    }
  } else {
    const check = verifyRuntimeDirectory(runtimeDir(home, pin.integrity), pin.integrity);
    if (!check.ok) {
      setIdentityState(home, pin.name, pin.version, 'TAMPERED');
      messages.push(
        `TAMPERED: cached runtime ${pin.integrity.slice(0, 12)} recomputes to ${check.actual.slice(0, 12)}${check.unlisted.length ? ` (unlisted files: ${check.unlisted.join(', ')})` : ''}; move it aside with \`harness distribution import --re-materialize\``,
      );
      return { ok: false, messages, cached: true, trust: null };
    }
    messages.push(`runtime ${pin.integrity.slice(0, 12)} verified in the cache`);
  }
  const promo = promoteTrustFromSources(home, pin, controlPlaneRoot, now, opts);
  messages.push(promo.message);
  const entry = readIndex(home, pin.name, pin.version);
  const trust = entry ? effectiveTrust(entry, revokedKeyIds(loadTrustStore(home))) : null;
  return { ok: true, messages, cached: true, trust };
}

function acquireFromFileSources(home: EgoHome, pin: Pin, now: string, messages: string[]): boolean {
  for (const raw of pin.sources) {
    let src: SourceRef;
    try {
      src = parseSource(raw);
    } catch {
      continue;
    }
    if (src.kind !== 'file') continue;
    const dir = resolve(src.target);
    const tarball = findTarball(dir, pin.version);
    if (!tarball) continue;
    const r = importTarball(home, tarball, now, { expectedIdentity: pin.integrity, name: pin.name });
    messages.push(...r.messages);
    if (r.ok) return true;
  }
  return false;
}

function findTarball(dir: string, version: string): string | null {
  if (isFile(dir) && dir.endsWith('.tgz')) return dir;
  if (!isDir(dir)) return null;
  const names = readdirSync(dir);
  const exact = names.find((n) => n === `ego-${version}.tgz` || n === `tarscoff-ego-${version}.tgz`);
  if (exact) return join(dir, exact);
  const sub = [join(dir, version), join(dir, `v${version}`)].find((d) => isDir(d));
  return sub ? findTarball(sub, version) : null;
}

export interface ImportResult {
  ok: boolean;
  identity?: string;
  version?: string;
  trust?: TrustLevel;
  messages: string[];
}

/**
 * `distribution import <tarball|bundle-dir>`: verify the release signature when metadata is present, extract to a
 * temporary directory, recompute the runtime hash, materialize, append metadata, index with the right trust level.
 */
export function importTarball(
  home: EgoHome,
  path: string,
  now: string,
  opts: { expectedIdentity?: string; name?: string; reMaterialize?: boolean; requireSigned?: boolean } = {},
): ImportResult {
  ensureHome(home);
  const messages: string[] = [];
  const abs = resolve(path);
  if (!isFile(abs)) return { ok: false, messages: [`not a file: ${abs}`] };
  const tmp = mkdtempSync(join(tmpdir(), 'ego-import-'));
  try {
    extractNpmTarball(readFileSync(abs), tmp);
    const id = computeRuntimeIdentity(tmp);
    if (opts.expectedIdentity && id.runtimeSha256 !== opts.expectedIdentity) {
      return {
        ok: false,
        messages: [
          `runtime identity mismatch: ${basename(abs)} computes to ${id.runtimeSha256.slice(0, 12)}, expected ${opts.expectedIdentity.slice(0, 12)}`,
        ],
      };
    }
    const metaDir =
      findMetadataDir(join(abs, '..'), id.version) ??
      (isFile(join(abs, '..', 'manifest.json')) ? join(abs, '..') : null);
    let trust: TrustLevel = 'local-tarball (unsigned)';
    let verifiedBy: string | undefined;
    if (metaDir) {
      const meta = readReleaseMetadata(metaDir);
      if (meta) {
        if (meta.manifest.runtimeSha256 !== id.runtimeSha256)
          messages.push(
            `release metadata in ${metaDir} describes runtime ${meta.manifest.runtimeSha256.slice(0, 12)}, not ${id.runtimeSha256.slice(0, 12)}; ignored`,
          );
        else {
          const v = verifyReleaseMetadata(home, meta, abs);
          if (v.trusted) {
            trust = 'signed-release';
            verifiedBy = v.verifiedByKeyId;
            appendReleaseMetadata(home, id.runtimeSha256, meta);
            messages.push(`release signature verified (key ${verifiedBy})`);
          } else messages.push(`release metadata present but not trusted: ${v.reasons.join('; ')}`);
        }
      }
    }
    if (opts.requireSigned && trust !== 'signed-release')
      return { ok: false, messages: [...messages, 'refused: this profile requires a signed release'] };
    if (isDevelopmentVersion(id.version) && trust === 'signed-release')
      return {
        ok: false,
        messages: [...messages, 'refused: a development identity cannot carry signed-release trust'],
      };
    if (opts.reMaterialize && isRuntimeCached(home, id.runtimeSha256)) {
      const aside = quarantineRuntime(home, id.runtimeSha256, now);
      messages.push(`moved the existing cache directory aside: ${aside}`);
      setIdentityState(home, opts.name ?? id.name, id.version, undefined);
    }
    const m = materializeRuntime(home, tmp, id.runtimeSha256);
    messages.push(
      m.created
        ? `materialized ${id.runtimeSha256.slice(0, 12)} (${id.version})`
        : `runtime ${id.runtimeSha256.slice(0, 12)} already cached (immutable)`,
    );
    const rec: Parameters<typeof indexAdd>[4] = { source: `file:${abs}`, trust, cachedAt: now };
    if (verifiedBy) rec.verifiedByKeyId = verifiedBy;
    const entry = indexAdd(home, opts.name ?? id.name, id.version, id.runtimeSha256, rec, now);
    if (
      entry.state &&
      verifyRuntimeDirectory(runtimeDir(home, id.runtimeSha256), id.runtimeSha256).ok &&
      (entry.state !== 'REVOKED' || trust === 'signed-release')
    ) {
      setIdentityState(home, entry.name, entry.version, undefined);
      messages.push(
        `cleared state ${entry.state}: bytes verified${trust === 'signed-release' ? ' and signature re-established' : ''}`,
      );
    }
    return { ok: true, identity: id.runtimeSha256, version: id.version, trust, messages };
  } catch (e) {
    return { ok: false, messages: [...messages, (e as Error).message] };
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

/** `distribution verify <tarball>`: signature, transport hash and runtime identity, without touching the cache. */
export function verifyDistribution(home: EgoHome, path: string): { ok: boolean; lines: string[] } {
  const abs = resolve(path);
  const lines: string[] = [];
  if (!isFile(abs)) return { ok: false, lines: [`not a file: ${abs}`] };
  const tmp = mkdtempSync(join(tmpdir(), 'ego-verify-'));
  try {
    extractNpmTarball(readFileSync(abs), tmp);
    const id = computeRuntimeIdentity(tmp);
    lines.push(
      `tarball: ${basename(abs)}`,
      `tarball_sha256: ${tarballSha256(abs)}`,
      `runtime identity: ${id.runtimeSha256} (${id.name} ${id.version})`,
    );
    const metaDir =
      findMetadataDir(join(abs, '..'), id.version) ??
      (isFile(join(abs, '..', 'manifest.json')) ? join(abs, '..') : null);
    const meta = metaDir ? readReleaseMetadata(metaDir) : null;
    if (!meta) {
      lines.push(
        'release metadata: none found next to the tarball (manifest.json, SHA256SUMS, SHA256SUMS.<keyid>.sig)',
        'verdict: UNSIGNED (hash-only; STANDARD may use it, STRICT+ refuse)',
      );
      return { ok: false, lines };
    }
    const v = verifyReleaseMetadata(home, meta, abs);
    lines.push(
      `manifest runtime identity: ${meta.manifest.runtimeSha256}${meta.manifest.runtimeSha256 === id.runtimeSha256 ? ' (matches)' : ' (MISMATCH)'}`,
    );
    for (const r of v.reasons) lines.push(`problem: ${r}`);
    lines.push(
      v.trusted && meta.manifest.runtimeSha256 === id.runtimeSha256
        ? `verdict: VERIFIED (key ${v.verifiedByKeyId})`
        : 'verdict: NOT VERIFIED',
    );
    return { ok: v.trusted && meta.manifest.runtimeSha256 === id.runtimeSha256, lines };
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

export interface BootstrapDoctorReport {
  ok: boolean;
  lines: string[];
}

/** `bootstrap doctor [--reverify]`: home layout, trust store, index consistency; reverify recomputes every cached runtime. */
export function bootstrapDoctor(
  home: EgoHome,
  controlPlaneRoot: string,
  now: string,
  opts: { reverify: boolean; launcher?: { name: string; version: string; identity: string } },
): BootstrapDoctorReport {
  ensureHome(home);
  const lines: string[] = [];
  let ok = true;
  const seeded = seedTrust(home, controlPlaneRoot, now);
  const store = loadTrustStore(home);
  lines.push(
    `EGO_HOME: ${home.root}`,
    `trust store: ${store.keys.length} key(s)${store.keys.length === 0 ? ' (no release keys published yet: every runtime stays unsigned)' : ''}${seeded.added.length ? `, seeded ${seeded.added.join(', ')}` : ''}${seeded.revoked.length ? `, revoked ${seeded.revoked.join(', ')}` : ''}`,
  );
  for (const k of store.keys)
    lines.push(`  key ${k.id}: ${k.status} (${k.origin}, fingerprint ${k.fingerprint.slice(0, 16)}…)`);
  lines.push(
    'independent channel: the release key fingerprint and revocation notices are published outside GitHub (DNS TXT / HTTPS page); README copies are convenience only (M16)',
  );
  const revoked = revokedKeyIds(store);
  const entries = listIndexEntries(home);
  lines.push(`index: ${entries.length} entr${entries.length === 1 ? 'y' : 'ies'}`);
  const byVersion = new Map<string, string>();
  for (const e of entries) {
    const trust = effectiveTrust(e, revoked);
    const cached = isRuntimeCached(home, e.identity);
    let state = e.state ?? (cached ? 'ok' : 'not cached');
    if (opts.reverify && cached) {
      const check = verifyRuntimeDirectory(runtimeDir(home, e.identity), e.identity);
      if (!check.ok) {
        setIdentityState(home, e.name, e.version, 'TAMPERED');
        state = 'TAMPERED';
        ok = false;
      }
      const signedRecords = e.records.filter((r) => r.verifiedByKeyId);
      if (signedRecords.length && signedRecords.every((r) => revoked.has(r.verifiedByKeyId!))) {
        setIdentityState(home, e.name, e.version, 'REVOKED');
        state = 'REVOKED';
        ok = false;
      }
      if (state === 'ok') {
        const rf = releaseFiles(home, e.identity);
        if (rf.includes('manifest.json')) {
          const meta = readReleaseMetadata(releaseDir(home, e.identity));
          if (meta && !verifyReleaseMetadata(home, meta).trusted)
            lines.push(
              `  ${e.name}@${e.version}: release metadata no longer verifies under the current trust store`,
            );
        }
      }
    }
    const prev = byVersion.get(e.version);
    if (prev && prev !== e.identity) {
      lines.push(
        `  IDENTITY_CONFLICT: version ${e.version} maps to ${prev.slice(0, 12)} and ${e.identity.slice(0, 12)}`,
      );
      ok = false;
    }
    byVersion.set(e.version, e.identity);
    lines.push(
      `  ${e.name}@${e.version}: identity ${e.identity.slice(0, 12)}… trust ${trust ?? 'none'} state ${state}${e.displaced.length ? ` displaced ${e.displaced.map((d) => `${d.identity.slice(0, 12)}(${d.state})`).join(', ')}` : ''}`,
    );
  }
  if (opts.launcher) {
    const clash = entries.find(
      (e) => e.version === opts.launcher!.version && e.identity !== opts.launcher!.identity,
    );
    if (clash) {
      lines.push(
        `  IDENTITY_CONFLICT: the launcher itself (${opts.launcher.name}@${opts.launcher.version}, identity ${opts.launcher.identity.slice(0, 12)}…) collides with ${clash.name}@${clash.version} → ${clash.identity.slice(0, 12)}…; one version string maps to one identity (Q79). Rebuild from a clean tree or remove the stale index entry after checking its records.`,
      );
      ok = false;
    }
  }
  const cachedDirs = isDir(home.runtimes)
    ? readdirSync(home.runtimes).filter((d) => /^[0-9a-f]{64}$/.test(d))
    : [];
  const unindexed = cachedDirs.filter((d) => !entries.some((e) => e.identity === d));
  if (unindexed.length)
    lines.push(
      `cache: ${unindexed.length} runtime(s) cached without an index entry: ${unindexed.map((d) => d.slice(0, 12)).join(', ')}`,
    );
  lines.push(`bootstrap doctor: ${ok ? 'OK' : 'PROBLEMS'}${opts.reverify ? ' (reverified)' : ''}`);
  return { ok, lines };
}

export function indexSummary(
  home: EgoHome,
  name: string,
  version: string,
): { entry: ReturnType<typeof readIndex>; trust: TrustLevel | null } {
  const entry = readIndex(home, name, version);
  const trust = entry ? effectiveTrust(entry, revokedKeyIds(loadTrustStore(home))) : null;
  return { entry, trust };
}

export { readJsonIfExists };
