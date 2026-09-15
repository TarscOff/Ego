import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync, rmSync, symlinkSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, sign as cryptoSign, createHash } from 'node:crypto';
import {
  computeRuntimeIdentity,
  hashPackageJsonWithoutName,
  verifyRuntimeDirectory,
  isDevelopmentVersion,
  nodeSatisfies as nodeSatisfiesImport,
} from '../src/launcher/identity.ts';
import {
  egoHome,
  ensureHome,
  indexAdd,
  IdentityConflictError,
  readIndex,
  effectiveTrust,
  materializeRuntime,
  appendReleaseFile,
  ReleaseMetadataMismatch,
  isRuntimeCached,
  runtimeDir,
  setIdentityState as setIdentityStateImport,
  readIndex as readIndexImport,
} from '../src/launcher/home.ts';
import {
  saveTrustStore,
  loadTrustStore,
  seedAndMergeRevocations,
  verifySignatures,
  fingerprintOfPublicKey,
  revokedKeyIds,
} from '../src/launcher/trust.ts';
import {
  parseSha256Sums,
  formatSha256Sums,
  readTarGz,
  extractNpmTarball,
  tarballSha256,
} from '../src/launcher/artifacts.ts';
import { writePin, readPin, PinError } from '../src/launcher/pin.ts';
import {
  importTarball,
  promoteTrustFromSources,
  verifyDistribution,
  bootstrapDoctor,
  syncProject,
} from '../src/launcher/sync.ts';

const CP = new URL('../../../control-plane/', import.meta.url).pathname;
const NOW = '2026-09-14T10:00:00.000Z';

function tmp(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

function fakePackage(
  dir: string,
  version: string,
  name = '@tarscoff/ego',
  extra: Record<string, string> = {},
): string {
  const root = join(dir, 'package');
  mkdirSync(join(root, 'dist'), { recursive: true });
  mkdirSync(join(root, 'control-plane'), { recursive: true });
  writeFileSync(
    join(root, 'package.json'),
    JSON.stringify({ name, version, files: ['dist/', 'control-plane/', 'bin/'] }, null, 2),
  );
  writeFileSync(join(root, 'dist', 'ego.js'), `export async function main(){return 0}\n// ${version}\n`);
  writeFileSync(join(root, 'control-plane', 'README.md'), '# cp\n');
  for (const [rel, body] of Object.entries(extra)) {
    mkdirSync(join(root, rel, '..'), { recursive: true });
    writeFileSync(join(root, rel), body);
  }
  return root;
}

function tarball(dir: string, out: string): string {
  // COPYFILE_DISABLE keeps macOS bsdtar from adding AppleDouble `._*` entries, which a real npm tarball never has
  const r = spawnSync('tar', ['-czf', out, '-C', dir, 'package'], {
    encoding: 'utf8',
    env: { ...process.env, COPYFILE_DISABLE: '1' },
  });
  assert.equal(r.status, 0, r.stderr);
  return out;
}

function keypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string };
  const raw = Buffer.from(jwk.x, 'base64url');
  return {
    privateKey,
    publicKeyBase64: raw.toString('base64'),
    fingerprint: createHash('sha256').update(raw).digest('hex'),
  };
}

function signedMetadata(
  dir: string,
  tgz: string,
  runtimeSha256: string,
  version: string,
  keyId: string,
  privateKey: ReturnType<typeof keypair>['privateKey'],
): void {
  const tarballSha = tarballSha256(tgz);
  const manifest = {
    schema: 'ego.release-manifest/1',
    name: '@tarscoff/ego',
    version,
    commit: 'abc',
    nodeFloor: '>=24',
    runtimeSha256,
    tarballSha256: tarballSha,
    tarballFile: `ego-${version}.tgz`,
    keyIds: [keyId],
    schemas: {},
    execContract: 'ego.exec/1',
    authorityChanges: [],
    trustedKeyChanges: [],
  };
  const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 2));
  writeFileSync(join(dir, 'manifest.json'), manifestBytes);
  const sums = formatSha256Sums([
    { sha256: tarballSha, file: `ego-${version}.tgz` },
    { sha256: createHash('sha256').update(manifestBytes).digest('hex'), file: 'manifest.json' },
  ]);
  writeFileSync(join(dir, 'SHA256SUMS'), sums);
  writeFileSync(join(dir, `SHA256SUMS.${keyId}.sig`), cryptoSign(null, Buffer.from(sums), privateKey));
}

test('runtime identity excludes only the package name and includes the version', () => {
  const a = fakePackage(tmp('ego-id-a-'), '1.0.0', '@tarscoff/ego');
  const b = fakePackage(tmp('ego-id-b-'), '1.0.0', '@other/ego-rescoped');
  const c = fakePackage(tmp('ego-id-c-'), '1.0.1', '@tarscoff/ego');
  assert.equal(computeRuntimeIdentity(a).runtimeSha256, computeRuntimeIdentity(b).runtimeSha256);
  assert.notEqual(computeRuntimeIdentity(a).runtimeSha256, computeRuntimeIdentity(c).runtimeSha256);
  assert.equal(
    hashPackageJsonWithoutName('{"name":"x","version":"1"}'),
    hashPackageJsonWithoutName('{"version":"1","name":"y"}'),
  );
  assert.ok(isDevelopmentVersion('1.2.0-dev.a1b2c3d'));
  assert.ok(!isDevelopmentVersion('1.2.0'));
});

test('index: one identity per version; signed displaces unsigned; unsigned vs unsigned refused; signed vs signed hard conflict', () => {
  const home = egoHome({ EGO_HOME: tmp('ego-home-') });
  ensureHome(home);
  indexAdd(
    home,
    '@tarscoff/ego',
    '1.0.0',
    'a'.repeat(64),
    { source: 'registry', trust: 'registry (unsigned)', cachedAt: NOW },
    NOW,
  );
  assert.throws(
    () =>
      indexAdd(
        home,
        '@tarscoff/ego',
        '1.0.0',
        'b'.repeat(64),
        { source: 'file', trust: 'local-tarball (unsigned)', cachedAt: NOW },
        NOW,
      ),
    IdentityConflictError,
  );
  const e = indexAdd(
    home,
    '@tarscoff/ego',
    '1.0.0',
    'b'.repeat(64),
    { source: 'file', trust: 'signed-release', verifiedByKeyId: 'k1', cachedAt: NOW },
    NOW,
  );
  assert.equal(e.identity, 'b'.repeat(64));
  assert.equal(e.displaced[0]?.state, 'SUPERSEDED');
  assert.throws(
    () =>
      indexAdd(
        home,
        '@tarscoff/ego',
        '1.0.0',
        'c'.repeat(64),
        { source: 'file', trust: 'signed-release', verifiedByKeyId: 'k1', cachedAt: NOW },
        NOW,
      ),
    /both signature-backed/,
  );
  // cross-name check on the same version string
  assert.throws(
    () =>
      indexAdd(
        home,
        '@other/ego',
        '1.0.0',
        'd'.repeat(64),
        { source: 'registry', trust: 'registry (unsigned)', cachedAt: NOW },
        NOW,
      ),
    IdentityConflictError,
  );
  const entry = readIndex(home, '@tarscoff/ego', '1.0.0')!;
  assert.equal(effectiveTrust(entry, new Set()), 'signed-release');
  assert.equal(effectiveTrust(entry, new Set(['k1'])), null);
});

test('cache is immutable and tamper is detected; release metadata is append-only', () => {
  const home = egoHome({ EGO_HOME: tmp('ego-home-') });
  const pkg = fakePackage(tmp('ego-pkg-'), '1.0.0');
  const id = computeRuntimeIdentity(pkg).runtimeSha256;
  const m1 = materializeRuntime(home, pkg, id);
  const m2 = materializeRuntime(home, pkg, id);
  assert.ok(m1.created && !m2.created && isRuntimeCached(home, id));
  assert.throws(() => materializeRuntime(home, pkg, 'f'.repeat(64)), /refusing to materialize/);
  assert.ok(verifyRuntimeDirectory(runtimeDir(home, id), id).ok);
  writeFileSync(join(runtimeDir(home, id), 'dist', 'ego.js'), 'tampered');
  const v = verifyRuntimeDirectory(runtimeDir(home, id), id);
  assert.ok(!v.ok && v.actual !== id);
  assert.equal(appendReleaseFile(home, id, 'SHA256SUMS', 'x'), 'written');
  assert.equal(appendReleaseFile(home, id, 'SHA256SUMS', 'x'), 'identical');
  assert.throws(() => appendReleaseFile(home, id, 'SHA256SUMS', 'y'), ReleaseMetadataMismatch);
});

test('pin: generated, provenance-stamped, hand edits detected', () => {
  const root = tmp('ego-pin-');
  writePin(root, {
    name: '@tarscoff/ego',
    version: '1.0.0',
    integrity: 'a'.repeat(64),
    sources: ['npm:@tarscoff/ego'],
    schemas: { pin: 'ego.pin/1' },
    node: '>=24',
    profile: 'STRICT',
    taskSource: 'issue-preferred',
  });
  const p = readPin(root);
  assert.equal(p.profile, 'STRICT');
  const path = join(root, '.harness', 'harness.md');
  writeFileSync(path, readFileSync(path, 'utf8').replace('profile: STRICT', 'profile: STANDARD'));
  assert.throws(() => readPin(root), PinError);
});

test('artifacts: SHA256SUMS parsing, tar reading, traversal refused', () => {
  assert.deepEqual(parseSha256Sums('# c\n' + 'a'.repeat(64) + '  ego-1.0.0.tgz\n'), [
    { sha256: 'a'.repeat(64), file: 'ego-1.0.0.tgz' },
  ]);
  assert.throws(() => parseSha256Sums('nonsense'), /malformed/);
  const dir = tmp('ego-tar-');
  fakePackage(dir, '1.0.0');
  const tgz = tarball(dir, join(dir, 'ego-1.0.0.tgz'));
  const entries = readTarGz(readFileSync(tgz));
  assert.ok(entries.some((e) => e.name === 'package/package.json'));
  const out = tmp('ego-tar-out-');
  const written = extractNpmTarball(readFileSync(tgz), out);
  assert.ok(written.includes('dist/ego.js'));
});

test('trust store: bootstrap seed only when empty, revocations merged, signatures verified per key', () => {
  const home = egoHome({ EGO_HOME: tmp('ego-home-') });
  const k1 = keypair();
  const k2 = keypair();
  const seed = [
    {
      id: 'k1',
      algorithm: 'ed25519' as const,
      publicKey: k1.publicKeyBase64,
      fingerprint: k1.fingerprint,
      status: 'active' as const,
    },
  ];
  const s1 = seedAndMergeRevocations(home, seed, '1.0.0', NOW);
  assert.deepEqual(s1.added, ['k1']);
  const s2 = seedAndMergeRevocations(
    home,
    [
      ...seed,
      {
        id: 'k2',
        algorithm: 'ed25519' as const,
        publicKey: k2.publicKeyBase64,
        fingerprint: k2.fingerprint,
        status: 'active' as const,
      },
    ],
    '1.0.1',
    NOW,
  );
  assert.deepEqual(s2.added, [], 'a later seed never adds keys (only cross-signed releases do)');
  assert.throws(
    () =>
      seedAndMergeRevocations(
        egoHome({ EGO_HOME: tmp('ego-home-') }),
        [{ ...seed[0]!, fingerprint: 'deadbeef' }],
        '1',
        NOW,
      ),
    /fingerprint does not match/,
  );
  const sums = Buffer.from('a'.repeat(64) + '  ego-1.0.0.tgz\n');
  const good = cryptoSign(null, sums, k1.privateKey);
  const store = loadTrustStore(home);
  assert.ok(verifySignatures(store, sums, [{ keyId: 'k1', signature: good }]).trusted);
  assert.ok(!verifySignatures(store, sums, [{ keyId: 'k1', signature: Buffer.alloc(64) }]).trusted);
  assert.ok(
    !verifySignatures(store, sums, [{ keyId: 'k2', signature: cryptoSign(null, sums, k2.privateKey) }])
      .trusted,
    'unknown key',
  );
  const s3 = seedAndMergeRevocations(home, [{ ...seed[0]!, status: 'revoked' }], '1.0.2', NOW);
  assert.deepEqual(s3.revoked, ['k1']);
  assert.ok(
    !verifySignatures(loadTrustStore(home), sums, [{ keyId: 'k1', signature: good }]).trusted,
    'revoked key verifies nothing',
  );
  assert.equal(fingerprintOfPublicKey(k1.publicKeyBase64), k1.fingerprint);
  assert.deepEqual([...revokedKeyIds(loadTrustStore(home))], ['k1']);
});

test('distribution import and verify: unsigned vs signed, hash mismatch, tamper re-materialization, STRICT refusal', () => {
  const home = egoHome({ EGO_HOME: tmp('ego-home-') });
  ensureHome(home);
  const k1 = keypair();
  saveTrustStore(home, {
    schema: 'ego.trust-store/1',
    keys: [
      {
        id: 'k1',
        algorithm: 'ed25519',
        publicKey: k1.publicKeyBase64,
        fingerprint: k1.fingerprint,
        status: 'active',
        origin: 'bootstrap-seed',
        addedAt: NOW,
      },
    ],
  });
  const src = tmp('ego-rel-');
  const pkg = fakePackage(src, '1.0.0');
  const id = computeRuntimeIdentity(pkg).runtimeSha256;
  const unsignedDir = tmp('ego-unsigned-');
  const tgzU = tarball(src, join(unsignedDir, 'ego-1.0.0.tgz'));
  const u = importTarball(home, tgzU, NOW);
  assert.ok(u.ok && u.trust === 'local-tarball (unsigned)' && u.identity === id, u.messages.join('\n'));
  assert.ok(!verifyDistribution(home, tgzU).ok);
  const refused = importTarball(home, tgzU, NOW, { requireSigned: true });
  assert.ok(!refused.ok && /requires a signed release/.test(refused.messages.join('\n')));
  // signed
  const signedDir = tmp('ego-signed-');
  const tgz = tarball(src, join(signedDir, 'ego-1.0.0.tgz'));
  signedMetadata(signedDir, tgz, id, '1.0.0', 'k1', k1.privateKey);
  const v = verifyDistribution(home, tgz);
  assert.ok(v.ok, v.lines.join('\n'));
  assert.match(v.lines.join('\n'), /VERIFIED \(key k1\)/);
  const s = importTarball(home, tgz, NOW);
  assert.ok(s.ok && s.trust === 'signed-release', s.messages.join('\n'));
  assert.equal(effectiveTrust(readIndex(home, '@tarscoff/ego', '1.0.0')!, new Set()), 'signed-release');
  // tampered signed metadata: manifest hash mismatch
  const badDir = tmp('ego-bad-');
  const tgzB = tarball(src, join(badDir, 'ego-1.0.0.tgz'));
  signedMetadata(badDir, tgzB, 'e'.repeat(64), '1.0.0', 'k1', k1.privateKey);
  assert.ok(!verifyDistribution(home, tgzB).ok);
  // tamper the cache, reverify marks TAMPERED, re-materialize repairs
  writeFileSync(join(runtimeDir(home, id), 'dist', 'ego.js'), 'tampered');
  const bd = bootstrapDoctor(home, CP, NOW, { reverify: true });
  assert.ok(!bd.ok && /TAMPERED/.test(bd.lines.join('\n')));
  assert.equal(readIndex(home, '@tarscoff/ego', '1.0.0')?.state, 'TAMPERED');
  const re = importTarball(home, tgz, NOW, { reMaterialize: true });
  assert.ok(re.ok, re.messages.join('\n'));
  assert.ok(verifyRuntimeDirectory(runtimeDir(home, id), id).ok);
  assert.equal(readIndex(home, '@tarscoff/ego', '1.0.0')?.state, undefined);
  // a development identity can never carry signed trust
  const devSrc = tmp('ego-dev-');
  const devPkg = fakePackage(devSrc, '1.1.0-dev.abcdef1');
  const devDir = tmp('ego-devrel-');
  const devTgz = tarball(devSrc, join(devDir, 'ego-1.1.0-dev.abcdef1.tgz'));
  signedMetadata(
    devDir,
    devTgz,
    computeRuntimeIdentity(devPkg).runtimeSha256,
    '1.1.0-dev.abcdef1',
    'k1',
    k1.privateKey,
  );
  const dev = importTarball(home, devTgz, NOW);
  assert.ok(!dev.ok && /development identity/.test(dev.messages.join('\n')));
});

test('sync from a file: source materializes and promotes trust; offline names skipped sources', () => {
  const home = egoHome({ EGO_HOME: tmp('ego-home-') });
  ensureHome(home);
  const k1 = keypair();
  saveTrustStore(home, {
    schema: 'ego.trust-store/1',
    keys: [
      {
        id: 'k1',
        algorithm: 'ed25519',
        publicKey: k1.publicKeyBase64,
        fingerprint: k1.fingerprint,
        status: 'active',
        origin: 'bootstrap-seed',
        addedAt: NOW,
      },
    ],
  });
  const src = tmp('ego-rel-');
  const pkg = fakePackage(src, '2.0.0');
  const id = computeRuntimeIdentity(pkg).runtimeSha256;
  const relDir = tmp('ego-releases-');
  mkdirSync(join(relDir, '2.0.0'));
  const tgz = tarball(src, join(relDir, '2.0.0', 'ego-2.0.0.tgz'));
  signedMetadata(join(relDir, '2.0.0'), tgz, id, '2.0.0', 'k1', k1.privateKey);
  const pin = {
    name: '@tarscoff/ego',
    version: '2.0.0',
    integrity: id,
    sources: ['npm:@tarscoff/ego', `file:${relDir}`],
    schemas: {},
    node: '>=24',
    profile: 'STRICT',
    stamp: '',
  };
  const launcher = {
    root: fakePackage(tmp('ego-launcher-'), '1.0.0'),
    runtimeSha256: 'x'.repeat(64),
    version: '1.0.0',
  };
  const r = syncProject(home, pin, launcher, CP, NOW, { offline: true, env: {} });
  assert.ok(r.ok, r.messages.join('\n'));
  assert.equal(r.trust, 'signed-release');
  assert.ok(isRuntimeCached(home, id));
  const again = promoteTrustFromSources(home, pin, CP, NOW, { offline: true, env: {} });
  assert.match(again.message, /already signed-release/);
  // a pin nobody can provide offline
  const missing = syncProject(
    home,
    { ...pin, integrity: 'b'.repeat(64), version: '2.0.1' },
    launcher,
    CP,
    NOW,
    { offline: true, env: {} },
  );
  assert.ok(!missing.ok && /pinned but not installed/.test(missing.messages.join('\n')));
  rmSync(relDir, { recursive: true, force: true });
});

test('verification: at least one trusted non-revoked signature suffices; the manifest is bound to the signed sums', () => {
  const home = egoHome({ EGO_HOME: tmp('ego-home-') });
  ensureHome(home);
  const k1 = keypair();
  const k2 = keypair();
  saveTrustStore(home, {
    schema: 'ego.trust-store/1',
    keys: [
      {
        id: 'k1',
        algorithm: 'ed25519',
        publicKey: k1.publicKeyBase64,
        fingerprint: k1.fingerprint,
        status: 'active',
        origin: 'bootstrap-seed',
        addedAt: NOW,
      },
    ],
  });
  const src = tmp('ego-rel-');
  const pkg = fakePackage(src, '3.0.0');
  const id = computeRuntimeIdentity(pkg).runtimeSha256;
  const dir = tmp('ego-signed-');
  const tgz = tarball(src, join(dir, 'ego-3.0.0.tgz'));
  signedMetadata(dir, tgz, id, '3.0.0', 'k1', k1.privateKey);
  // an extra signature by an unknown key (rotation in progress) and a garbage signature file must not break verification
  writeFileSync(
    join(dir, 'SHA256SUMS.k2.sig'),
    cryptoSign(null, readFileSync(join(dir, 'SHA256SUMS')), k2.privateKey),
  );
  writeFileSync(join(dir, 'SHA256SUMS.k9.sig'), Buffer.alloc(64));
  const v = verifyDistribution(home, tgz);
  assert.ok(v.ok, v.lines.join('\n'));
  assert.match(v.lines.join('\n'), /note: signature by key k2: unknown key/);
  // a forged manifest that reuses the genuine signature set is refused: SHA256SUMS binds manifest.json
  const forged = tmp('ego-forged-');
  const tgzF = tarball(src, join(forged, 'ego-3.0.0.tgz'));
  signedMetadata(forged, tgzF, id, '3.0.0', 'k1', k1.privateKey);
  const m = JSON.parse(readFileSync(join(forged, 'manifest.json'), 'utf8')) as { runtimeSha256: string };
  m.runtimeSha256 = 'e'.repeat(64);
  writeFileSync(join(forged, 'manifest.json'), JSON.stringify(m, null, 2));
  const vf = verifyDistribution(home, tgzF);
  assert.ok(!vf.ok);
  assert.match(vf.lines.join('\n'), /manifest.json bytes differ from the signed SHA256SUMS entry/);
  // a sums file without a manifest entry never binds
  const unbound = tmp('ego-unbound-');
  const tgzU = tarball(src, join(unbound, 'ego-3.0.0.tgz'));
  signedMetadata(unbound, tgzU, id, '3.0.0', 'k1', k1.privateKey);
  const sums = formatSha256Sums([{ sha256: tarballSha256(tgzU), file: 'ego-3.0.0.tgz' }]);
  writeFileSync(join(unbound, 'SHA256SUMS'), sums);
  writeFileSync(join(unbound, 'SHA256SUMS.k1.sig'), cryptoSign(null, Buffer.from(sums), k1.privateKey));
  assert.match(verifyDistribution(home, tgzU).lines.join('\n'), /does not list manifest.json/);
  // REVOKED is cleared when promotion re-establishes trust under a current key
  const s = importTarball(home, tgz, NOW);
  assert.ok(s.ok && s.trust === 'signed-release');
  const { setIdentityState, readIndex: ri } = await_home();
  setIdentityState(home, '@tarscoff/ego', '3.0.0', 'REVOKED');
  const pin = {
    name: '@tarscoff/ego',
    version: '3.0.0',
    integrity: id,
    sources: [`file:${dir}`],
    schemas: {},
    node: '>=24',
    profile: 'STRICT',
    stamp: '',
  };
  // drop the signed record so promotion runs again
  const entry = ri(home, '@tarscoff/ego', '3.0.0')!;
  entry.records = entry.records.filter((r) => r.trust !== 'signed-release');
  writeFileSync(join(home.index, '@tarscoff__ego@3.0.0.json'), JSON.stringify(entry));
  const promo = promoteTrustFromSources(home, pin, CP, NOW, { offline: true, env: {} });
  assert.ok(promo.promoted, promo.message);
  assert.equal(ri(home, '@tarscoff/ego', '3.0.0')?.state, undefined);
});

test('identity covers every file under a distributed directory; node floor parsing', () => {
  const dir = tmp('ego-depth-');
  const pkg = fakePackage(dir, '1.0.0');
  const before = computeRuntimeIdentity(pkg).runtimeSha256;
  mkdirSync(join(pkg, 'dist', 'tests'), { recursive: true });
  writeFileSync(join(pkg, 'dist', 'tests', 'planted.js'), 'evil');
  assert.notEqual(
    computeRuntimeIdentity(pkg).runtimeSha256,
    before,
    'a file planted under dist/tests changes the identity',
  );
  mkdirSync(join(pkg, 'dist', 'node_modules'), { recursive: true });
  writeFileSync(join(pkg, 'dist', 'node_modules', 'x.js'), 'ignored: npm never packs node_modules');
  const withNm = computeRuntimeIdentity(pkg).runtimeSha256;
  rmSync(join(pkg, 'dist', 'node_modules'), { recursive: true });
  assert.equal(computeRuntimeIdentity(pkg).runtimeSha256, withNm);
  const { nodeSatisfies } = await_identity();
  assert.ok(nodeSatisfies('24.19.0', '>=24'));
  assert.ok(!nodeSatisfies('22.11.0', '>=24'));
  assert.ok(nodeSatisfies('24.0.0', '>=24.0.0'));
  assert.ok(nodeSatisfies('26.1.0', '>=24 || ^22'));
  assert.ok(!nodeSatisfies('23.9.0', '^24'));
});

function await_home() {
  return { setIdentityState: setIdentityStateImport, readIndex: readIndexImport };
}
function await_identity() {
  return { nodeSatisfies: nodeSatisfiesImport };
}

test('a symlink planted in the immutable cache fails verification; bootstrap doctor names the launcher own identity conflict', () => {
  const home = egoHome({ EGO_HOME: tmp('ego-home-') });
  const pkg = fakePackage(tmp('ego-pkg-'), '4.0.0');
  const id = computeRuntimeIdentity(pkg).runtimeSha256;
  materializeRuntime(home, pkg, id);
  assert.ok(verifyRuntimeDirectory(runtimeDir(home, id), id).ok);
  symlinkSync('/etc', join(runtimeDir(home, id), 'dist', 'planted'));
  const v = verifyRuntimeDirectory(runtimeDir(home, id), id);
  assert.ok(!v.ok);
  assert.ok(v.unlisted.includes('dist/planted'));
  // bootstrap doctor with the launcher identity colliding with another name's entry for the same version
  const home2 = egoHome({ EGO_HOME: tmp('ego-home-') });
  ensureHome(home2);
  indexAdd(
    home2,
    '@other/ego',
    '5.0.0',
    'b'.repeat(64),
    { source: 'x', trust: 'registry (unsigned)', cachedAt: NOW },
    NOW,
  );
  const r = bootstrapDoctor(home2, CP, NOW, {
    reverify: false,
    launcher: { name: '@tarscoff/ego', version: '5.0.0', identity: 'a'.repeat(64) },
  });
  assert.ok(!r.ok);
  assert.match(r.lines.join('\n'), /IDENTITY_CONFLICT: the launcher itself/);
});
