import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadControlPlane, loadOverlayCapabilities, normalizePhrase } from '../src/control-plane/load.ts';
import { ControlPlaneValidationError } from '../src/control-plane/types.ts';
import { compileAuthority, diffAuthorityTables, classifyAuthorityChanges } from '../src/authority/compile.ts';

const ROOT = new URL('../../../control-plane/', import.meta.url).pathname;

test('loads the authored control plane without problems', () => {
  const cp = loadControlPlane(ROOT);
  assert.ok(cp.absoluteDenies.capabilities.some((c) => c.id === 'git.remote.push'));
  assert.ok(cp.capabilityDocs.length >= 5);
  assert.ok(cp.matchers.length > 50);
  assert.equal(cp.profiles.map((p) => p.id).sort().join(','), 'HIGH_ASSURANCE,STANDARD,STRICT');
  assert.equal(cp.modes.find((m) => m.isDefault)?.id, 'NORMAL_DELIVERY');
  assert.equal(cp.intents.length, 6);
  assert.ok(cp.secrets.flatMap((s) => s.detectors).length >= 30);
  assert.equal(cp.coordination.heartbeatTtlSeconds, 900);
});

test('compiles a deterministic authority table with correct precedence', () => {
  const cp = loadControlPlane(ROOT);
  const t1 = compileAuthority(cp);
  const t2 = compileAuthority(cp);
  assert.equal(t1.tableHash, t2.tableHash);
  assert.equal(t1.effective['git.remote.push'], 'DENY');
  assert.equal(t1.effective['git.local.commit'], 'ALLOW');
  assert.equal(t1.profiles['STRICT']!.modes['NORMAL_DELIVERY']!['git.local.commit'], 'ASK');
  assert.equal(t1.profiles['STANDARD']!.modes['NORMAL_DELIVERY']!['git.local.commit'], 'ALLOW');
  assert.equal(t1.profiles['STANDARD']!.modes['PRODUCTION_ADVISORY']!['fs.repo.write'], 'DENY');
  assert.equal(t1.profiles['STANDARD']!.modes['HARNESS_MAINTENANCE']!['harness.control-plane.edit'], 'ALLOW');
  assert.equal(t1.profiles['HIGH_ASSURANCE']!.modes['HARNESS_MAINTENANCE']!['git.remote.push'], 'DENY');
  assert.ok(t1.preDeniedCommandClasses.includes('git.remote.push'));
  assert.ok(t1.protectedPaths.some((p) => p.path === '~/.ssh/**'));
  assert.equal(t1.sanitizerLockedMinimums['oauth.jwt'], 'block');
});

function writeOverlay(dir: string, body: string): string {
  const f = join(dir, 'permissions.md');
  writeFileSync(f, body);
  return f;
}

test('overlay may narrow but never widen or reference absolute denies', () => {
  const cp = loadControlPlane(ROOT);
  const dir = mkdtempSync(join(tmpdir(), 'ego-overlay-'));
  const narrow = loadOverlayCapabilities(
    writeOverlay(dir, '---\nschema: ego.capabilities/1\nid: overlay\nfamily: overlay\n---\n# Overlay\n\n## Requires human approval\n\n- [x] `git.local.commit` — ask\n'),
    'overlay',
  );
  const t = compileAuthority(cp, { overlay: narrow });
  assert.equal(t.effective['git.local.commit'], 'ASK');
  assert.equal(t.provenance['git.local.commit']!.at(-1)!.layer, 'overlay');

  const widen = loadOverlayCapabilities(
    writeOverlay(dir, '---\nschema: ego.capabilities/1\nid: overlay\nfamily: overlay\n---\n# Overlay\n\n## Allowed\n\n- [x] `git.local.rebase` — allow\n'),
    'overlay',
  );
  assert.throws(() => compileAuthority(cp, { overlay: widen }), ControlPlaneValidationError);

  const absolute = loadOverlayCapabilities(
    writeOverlay(dir, '---\nschema: ego.capabilities/1\nid: overlay\nfamily: overlay\n---\n# Overlay\n\n## Denied\n\n- [x] `git.remote.push` — restated\n'),
    'overlay',
  );
  assert.throws(() => compileAuthority(cp, { overlay: absolute }), /absolute deny/);
});

test('a malformed control plane fails closed with every problem listed', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ego-cp-'));
  cpSync(ROOT, dir, { recursive: true });
  mkdirSync(join(dir, 'permissions', 'capabilities'), { recursive: true });
  writeFileSync(
    join(dir, 'permissions', 'capabilities', 'broken.md'),
    '---\nschema: ego.capabilities/1\nid: broken\nfamily: broken\n---\n# Broken\n\n## Allowed\n\n- [x] `git.local.commit` — duplicate id\n\n## Denied\n\n- [x] `x.same` — a\n\n## Allowed\n\n- [x] `x.same` — twice\n',
  );
  assert.throws(
    () => loadControlPlane(dir),
    (e: unknown) => e instanceof ControlPlaneValidationError && e.problems.some((p) => p.includes('already declared')) && e.problems.some((p) => p.includes('more than one section')),
  );
});

test('authority diff classifies SemVer impact', () => {
  const cp = loadControlPlane(ROOT);
  const base = compileAuthority(cp);
  const dir = mkdtempSync(join(tmpdir(), 'ego-diff-'));
  cpSync(ROOT, dir, { recursive: true });
  writeFileSync(
    join(dir, 'permissions', 'capabilities', 'extra.md'),
    '---\nschema: ego.capabilities/1\nid: extra\nfamily: extra\n---\n# Extra\n\n## Denied\n\n- [x] `extra.new-thing` — new capability introduced as DENY\n',
  );
  const next = compileAuthority(loadControlPlane(dir));
  const changes = diffAuthorityTables(base, next);
  assert.deepEqual(changes, [{ capability: 'extra.new-thing', kind: 'added', to: 'DENY' }]);
  assert.equal(classifyAuthorityChanges(changes, next), 'minor');
  const changed = diffAuthorityTables(next, base);
  assert.equal(classifyAuthorityChanges(changed, base), 'major');
});

test('phrase normalization folds accents and punctuation', () => {
  assert.equal(normalizePhrase("Tu peux commiter, ça !"), 'tu peux commiter ca');
});
