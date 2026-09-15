import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, cpSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadControlPlane, loadOverlayCapabilities, normalizePhrase } from '../src/control-plane/load.ts';
import { ControlPlaneValidationError } from '../src/control-plane/types.ts';
import { compileAuthority, diffAuthorityTables, classifyAuthorityChanges } from '../src/authority/compile.ts';
import { loadOverlayMatchers } from '../src/policy/cache.ts';

const ROOT = new URL('../../../control-plane/', import.meta.url).pathname;

test('loads the authored control plane without problems', () => {
  const cp = loadControlPlane(ROOT);
  assert.ok(cp.absoluteDenies.capabilities.some((c) => c.id === 'production.deploy'));
  assert.ok(!cp.absoluteDenies.capabilities.some((c) => c.id === 'git.remote.push'));
  assert.ok(cp.organizationLocked?.capabilities.some((c) => c.id === 'git.remote.push'));
  assert.equal(cp.organizationLocked?.lock, 'organization');
  assert.ok(cp.containment.length >= 6);
  assert.equal(cp.profiles.find((p) => p.id === 'STRICT')?.budgets.onExceed, 'BLOCK');
  assert.equal(cp.profiles.find((p) => p.id === 'STANDARD')?.budgets.maxDelegationDepth, 3);
  assert.ok(cp.capabilityDocs.length >= 5);
  assert.ok(cp.matchers.length > 50);
  assert.equal(
    cp.profiles
      .map((p) => p.id)
      .sort()
      .join(','),
    'HIGH_ASSURANCE,STANDARD,STRICT',
  );
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
  assert.ok(t1.preDeniedCommandClasses.includes('production.k8s.mutate'));
  assert.ok(t1.organizationLocked.includes('forge.pr.merge'));
  assert.equal(t1.capabilities['git.remote.push']!.lock, 'organization');
  assert.equal(t1.capabilities['production.deploy']!.lock, 'absolute');
  assert.equal(t1.profiles['STRICT']!.budgets.maxToolCalls, 1500);
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
    writeOverlay(
      dir,
      '---\nschema: ego.capabilities/1\nid: overlay\nfamily: overlay\n---\n# Overlay\n\n## Requires human approval\n\n- [x] `git.local.commit` — ask\n',
    ),
    'overlay',
  );
  const t = compileAuthority(cp, { overlay: narrow });
  assert.equal(t.effective['git.local.commit'], 'ASK');
  assert.equal(t.provenance['git.local.commit']!.at(-1)!.layer, 'overlay');

  const widen = loadOverlayCapabilities(
    writeOverlay(
      dir,
      '---\nschema: ego.capabilities/1\nid: overlay\nfamily: overlay\n---\n# Overlay\n\n## Allowed\n\n- [x] `git.local.rebase` — allow\n',
    ),
    'overlay',
  );
  assert.throws(() => compileAuthority(cp, { overlay: widen }), ControlPlaneValidationError);

  const absolute = loadOverlayCapabilities(
    writeOverlay(
      dir,
      '---\nschema: ego.capabilities/1\nid: overlay\nfamily: overlay\n---\n# Overlay\n\n## Denied\n\n- [x] `production.deploy` — restated\n',
    ),
    'overlay',
  );
  assert.throws(() => compileAuthority(cp, { overlay: absolute }), /absolute deny/);
});

test('organization-locked denies: only the organization layer may widen them (Q98)', () => {
  const cp = loadControlPlane(ROOT);
  const dir = mkdtempSync(join(tmpdir(), 'ego-org-'));
  const orgWiden = loadOverlayCapabilities(
    writeOverlay(
      dir,
      '---\nschema: ego.capabilities/1\nid: org\nfamily: organization\n---\n# Org\n\n## Requires human approval\n\n- [x] `git.remote.push` — the organization delegates pushes to feature branches under review\n',
    ),
    'organization',
  );
  const t = compileAuthority(cp, { organization: orgWiden });
  assert.equal(t.effective['git.remote.push'], 'ASK');
  assert.match(t.provenance['git.remote.push']!.at(-1)!.layer, /organization/);
  // the product overlay can narrow it back, never widen it
  const overlayNarrow = loadOverlayCapabilities(
    writeOverlay(
      dir,
      '---\nschema: ego.capabilities/1\nid: overlay\nfamily: overlay\n---\n# Overlay\n\n## Denied\n\n- [x] `git.remote.push` — this product never pushes\n',
    ),
    'overlay',
  );
  assert.equal(
    compileAuthority(cp, { organization: orgWiden, overlay: overlayNarrow }).effective['git.remote.push'],
    'DENY',
  );
  const overlayWiden = loadOverlayCapabilities(
    writeOverlay(
      dir,
      '---\nschema: ego.capabilities/1\nid: overlay\nfamily: overlay\n---\n# Overlay\n\n## Allowed\n\n- [x] `git.remote.push` — nope\n',
    ),
    'overlay',
  );
  assert.throws(() => compileAuthority(cp, { overlay: overlayWiden }), /widen/);
  assert.throws(() => compileAuthority(cp, { organization: orgWiden, overlay: overlayWiden }), /widen/);
  // the organization layer still cannot touch absolute denies or widen ordinary DENY beyond what it declares
  const orgAbsolute = loadOverlayCapabilities(
    writeOverlay(
      dir,
      '---\nschema: ego.capabilities/1\nid: org\nfamily: organization\n---\n# Org\n\n## Allowed\n\n- [x] `production.deploy` — never\n',
    ),
    'organization',
  );
  assert.throws(() => compileAuthority(cp, { organization: orgAbsolute }), /absolute deny/);
  const orgOrdinaryWiden = loadOverlayCapabilities(
    writeOverlay(
      dir,
      '---\nschema: ego.capabilities/1\nid: org\nfamily: organization\n---\n# Org\n\n## Allowed\n\n- [x] `fs.env-file.write` — nope\n',
    ),
    'organization',
  );
  assert.throws(() => compileAuthority(cp, { organization: orgOrdinaryWiden }), /widen/);
  // an overlay may never declare a lock
  assert.throws(
    () =>
      loadOverlayCapabilities(
        writeOverlay(
          dir,
          '---\nschema: ego.capabilities/1\nid: o\nfamily: o\nlock: organization\n---\n# O\n\n## Denied\n\n- [x] `git.local.rebase` — x\n',
        ),
        'overlay',
      ),
    ControlPlaneValidationError,
  );
  // moving an identifier between lock tiers is a MAJOR authority change
  const t0 = compileAuthority(cp);
  const t1 = structuredClone(t0);
  t1.capabilities['git.remote.push']!.lock = 'absolute';
  const changes = diffAuthorityTables(t0, t1);
  assert.ok(changes.some((c) => c.kind === 'lock-changed' && c.capability === 'git.remote.push'));
  assert.equal(classifyAuthorityChanges(changes, t1), 'major');
});

test('modes and grants can never reference organization-locked denies', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ego-cp-lock-'));
  cpSync(ROOT, dir, { recursive: true });
  writeFileSync(
    join(dir, 'modes', 'evil.md'),
    '---\nschema: ego.mode/1\nid: EVIL\nkind: authority\noverrides:\n  - capability: git.remote.push\n    verdict: ALLOW\n---\n# EVIL\n',
  );
  assert.throws(() => loadControlPlane(dir), /organization-locked deny "git.remote.push"/);
});

test('a profile without budgets fails to load', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ego-cp-budget-'));
  cpSync(ROOT, dir, { recursive: true });
  const f = join(dir, 'profiles', 'strict.md');
  writeFileSync(f, readFileSync(f, 'utf8').replace(/budgets:[\s\S]*?on_exceed: BLOCK\n/, ''));
  assert.throws(() => loadControlPlane(dir), /budgets block is required/);
  writeFileSync(
    f,
    readFileSync(f, 'utf8').replace(
      'narrow:',
      'budgets:\n  max_duration_minutes: 0\n  on_exceed: MAYBE\nnarrow:',
    ),
  );
  assert.throws(() => loadControlPlane(dir), /max_duration_minutes must be a positive integer/);
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
    (e: unknown) =>
      e instanceof ControlPlaneValidationError &&
      e.problems.some((p) => p.includes('already declared')) &&
      e.problems.some((p) => p.includes('more than one section')),
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
  assert.equal(normalizePhrase('Tu peux commiter, ça !'), 'tu peux commiter ca');
});

test('fail closed: checked items under an unrecognised heading, non-list overrides, missing detectors, bad overlay matchers', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ego-cp-fc-'));
  cpSync(ROOT, dir, { recursive: true });
  writeFileSync(
    join(dir, 'permissions', 'capabilities', 'typo.md'),
    '---\nschema: ego.capabilities/1\nid: typo\nfamily: typo\n---\n# Typo\n\n## Deny list\n\n- [x] `x.hidden` — would vanish\n',
  );
  assert.throws(() => loadControlPlane(dir), /capability "x.hidden" sits under heading "Deny list"/);
  rmSync(join(dir, 'permissions', 'capabilities', 'typo.md'));
  writeFileSync(
    join(dir, 'modes', 'production-advisory.md'),
    readFileSync(join(dir, 'modes', 'production-advisory.md'), 'utf8').replace(
      /overrides:[\s\S]*?---\n#/,
      'overrides: nope\n---\n#',
    ),
  );
  assert.throws(() => loadControlPlane(dir), /overrides must be a list/);
  cpSync(join(ROOT, 'modes', 'production-advisory.md'), join(dir, 'modes', 'production-advisory.md'));
  writeFileSync(
    join(dir, 'secrets', 'application.md'),
    '---\nschema: ego.secrets/1\nfamily: application\n---\n# a\n',
  );
  assert.throws(() => loadControlPlane(dir), /detectors must be a list/);
  cpSync(join(ROOT, 'secrets', 'application.md'), join(dir, 'secrets', 'application.md'));
  loadControlPlane(dir);
  const overlayDir = mkdtempSync(join(tmpdir(), 'ego-om-'));
  const f = join(overlayDir, 'matchers.md');
  writeFileSync(
    f,
    '---\nschema: ego.matchers/1\nmatchers:\n  - capability: command.unknown\n    tool: Shell\n    command: x\n---\n# m\n',
  );
  assert.throws(() => loadOverlayMatchers(f), /invalid tool "Shell"/);
  writeFileSync(f, '---\nschema: ego.matchers/1\nmatchers: nope\n---\n# m\n');
  assert.throws(() => loadOverlayMatchers(f), /must be a list/);
  writeFileSync(
    f,
    '---\nschema: ego.matchers/1\nmatchers:\n  - capability: command.unknown\n    tool: Bash\n---\n# m\n',
  );
  assert.throws(() => loadOverlayMatchers(f), /no command, path or url/);
});

test('authority diff covers every profile/mode cell, matcher removals and budgets; provenance never carries absolute paths', () => {
  const cp = loadControlPlane(ROOT);
  const t0 = compileAuthority(cp);
  // a change visible only in one cell (HIGH_ASSURANCE / BENCHMARK) is still a MAJOR change
  const t1 = structuredClone(t0);
  t1.profiles['HIGH_ASSURANCE']!.modes['BENCHMARK']!['fs.repo.write'] = 'DENY';
  const c1 = diffAuthorityTables(t0, t1);
  assert.ok(
    c1.some(
      (c) =>
        c.kind === 'changed' && c.cell === 'HIGH_ASSURANCE/BENCHMARK' && c.capability === 'fs.repo.write',
    ),
  );
  assert.equal(classifyAuthorityChanges(c1, t1), 'major');
  // removing a matcher (an operation loses its classification) is MAJOR
  const t2 = structuredClone(t0);
  t2.matchers = t2.matchers.filter((m) => m.capability !== 'git.remote.push.force');
  const c2 = diffAuthorityTables(t0, t2);
  assert.ok(c2.some((c) => c.kind === 'matcher-removed'));
  assert.equal(classifyAuthorityChanges(c2, t2), 'major');
  // a new matcher that maps to an ALLOW capability is MAJOR, to a DENY one MINOR
  const t3 = structuredClone(t0);
  t3.matchers.push({
    capability: 'command.read-only',
    tool: 'Bash',
    command: '^mytool\\b',
    layer: 'overlay',
  });
  assert.equal(classifyAuthorityChanges(diffAuthorityTables(t0, t3), t3), 'major');
  const t4 = structuredClone(t0);
  t4.matchers.push({
    capability: 'command.destructive',
    tool: 'Bash',
    command: '^mytool\\b',
    layer: 'overlay',
  });
  assert.equal(classifyAuthorityChanges(diffAuthorityTables(t0, t4), t4), 'minor');
  // a budget change is reported and MINOR
  const t5 = structuredClone(t0);
  t5.profiles['STRICT']!.budgets.maxToolCalls = 9999;
  const c5 = diffAuthorityTables(t0, t5);
  assert.ok(c5.some((c) => c.kind === 'budget-changed' && /STRICT\.maxToolCalls/.test(c.detail ?? '')));
  assert.equal(classifyAuthorityChanges(c5, t5), 'minor');
  // identical tables: no changes
  assert.equal(classifyAuthorityChanges(diffAuthorityTables(t0, structuredClone(t0)), t0), 'none');
  // provenance of layer files is relative when a project root is given, so the table hash is location-independent
  const dir = mkdtempSync(join(tmpdir(), 'ego-prov-'));
  const f = join(dir, '.harness', 'permissions.md');
  mkdirSync(join(dir, '.harness'), { recursive: true });
  writeFileSync(
    f,
    '---\nschema: ego.capabilities/1\nid: overlay\nfamily: overlay\n---\n# o\n\n## Denied\n\n- [x] `git.local.rebase` — no\n',
  );
  const withRoot = compileAuthority(cp, { overlay: loadOverlayCapabilities(f, 'overlay'), projectRoot: dir });
  assert.equal(withRoot.provenance['git.local.rebase']!.at(-1)!.file, '.harness/permissions.md');
  const dir2 = mkdtempSync(join(tmpdir(), 'ego-prov2-'));
  mkdirSync(join(dir2, '.harness'), { recursive: true });
  writeFileSync(join(dir2, '.harness', 'permissions.md'), readFileSync(f, 'utf8'));
  const withRoot2 = compileAuthority(cp, {
    overlay: loadOverlayCapabilities(join(dir2, '.harness', 'permissions.md'), 'overlay'),
    projectRoot: dir2,
  });
  assert.equal(withRoot.tableHash, withRoot2.tableHash);
});

test('locked files: preamble items, unchecked items and a null overrides key fail closed; privileged MCP is DENY', () => {
  const cp = loadControlPlane(ROOT);
  const t = compileAuthority(cp);
  assert.equal(t.effective['mcp.local.privileged'], 'DENY');
  assert.equal(t.effective['mcp.remote.privileged'], 'DENY');
  const dir = mkdtempSync(join(tmpdir(), 'ego-cp-locked-'));
  cpSync(ROOT, dir, { recursive: true });
  const abs = join(dir, 'permissions', 'absolute-denies.md');
  const original = readFileSync(abs, 'utf8');
  writeFileSync(
    abs,
    original.replace('- [x] `production.storage.mutate`', '- [ ] `production.storage.mutate`'),
  );
  assert.throws(() => loadControlPlane(dir), /is unchecked in a locked file/);
  writeFileSync(
    abs,
    original
      .replace(
        '# Absolute core denies',
        '- [x] `production.storage.mutate` — moved\n\n# Absolute core denies',
      )
      .replace('- [x] `production.storage.mutate` — production storage mutation.\n', ''),
  );
  assert.throws(() => loadControlPlane(dir), /appears before the first heading/);
  writeFileSync(abs, original);
  const mode = join(dir, 'modes', 'production-advisory.md');
  writeFileSync(mode, readFileSync(mode, 'utf8').replace(/overrides:[\s\S]*?---\n#/, 'overrides:\n---\n#'));
  assert.throws(() => loadControlPlane(dir), /overrides must be a list/);
});

test('authority diff: an inserted matcher that shadows existing ones is MAJOR; weakening a locked detector is MAJOR', () => {
  const cp = loadControlPlane(ROOT);
  const t0 = compileAuthority(cp);
  const t1 = structuredClone(t0);
  // a new DENY class inserted first re-partitions command.read-only
  t1.matchers.unshift({
    capability: 'command.destructive',
    tool: 'Bash',
    command: '^ls\\b',
    layer: 'overlay',
  });
  const c1 = diffAuthorityTables(t0, t1);
  assert.ok(c1.some((c) => c.kind === 'matcher-repartitioned'));
  assert.equal(classifyAuthorityChanges(c1, t1), 'major');
  const t2 = structuredClone(t0);
  delete t2.sanitizerLockedMinimums['oauth.jwt'];
  assert.equal(classifyAuthorityChanges(diffAuthorityTables(t0, t2), t2), 'major');
  const t3 = structuredClone(t0);
  t3.sanitizerLockedMinimums['oauth.jwt'] = 'warn';
  assert.ok(diffAuthorityTables(t0, t3).some((c) => c.kind === 'sanitizer-weakened'));
});

test('fail closed: checkbox-less capability bullets, starred preamble items and a null narrow key', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ego-cp-r3-'));
  cpSync(ROOT, dir, { recursive: true });
  const abs = join(dir, 'permissions', 'absolute-denies.md');
  const original = readFileSync(abs, 'utf8');
  writeFileSync(abs, original.replace('- [x] `production.storage.mutate`', '- `production.storage.mutate`'));
  assert.throws(() => loadControlPlane(dir), /"production.storage.mutate" under "Denied" has no checkbox/);
  writeFileSync(
    abs,
    original
      .replace('- [x] `production.storage.mutate` — production storage mutation.\n', '')
      .replace(
        '# Absolute core denies',
        '* [x] `production.storage.mutate` — moved\n\n# Absolute core denies',
      ),
  );
  assert.throws(() => loadControlPlane(dir), /appears before the first heading/);
  writeFileSync(abs, original);
  const strict = join(dir, 'profiles', 'strict.md');
  writeFileSync(strict, readFileSync(strict, 'utf8').replace(/narrow:\n( {2}- [\s\S]*?)(?=---)/, 'narrow:\n'));
  assert.throws(() => loadControlPlane(dir), /narrow must be a list/);
});

test('authority diff: grant phrases, protections and a wider new mode cell are MAJOR', () => {
  const t0 = compileAuthority(loadControlPlane(ROOT));
  const g = structuredClone(t0);
  g.grants[0]!.phrases.push('just do it');
  assert.equal(classifyAuthorityChanges(diffAuthorityTables(t0, g), g), 'major');
  const n = structuredClone(t0);
  n.grantNegations = n.grantNegations.slice(1);
  assert.equal(classifyAuthorityChanges(diffAuthorityTables(t0, n), n), 'major');
  const pp = structuredClone(t0);
  pp.protectedPaths = pp.protectedPaths.slice(1);
  assert.ok(diffAuthorityTables(t0, pp).some((c) => c.kind === 'protection-removed'));
  assert.equal(classifyAuthorityChanges(diffAuthorityTables(t0, pp), pp), 'major');
  const pd = structuredClone(t0);
  pd.preDeniedCommandClasses = pd.preDeniedCommandClasses.slice(1);
  assert.equal(classifyAuthorityChanges(diffAuthorityTables(t0, pd), pd), 'major');
  const m = structuredClone(t0);
  m.profiles['STRICT']!.modes['LOOSE'] = {
    ...m.profiles['STRICT']!.modes[m.defaultMode]!,
    'fs.env-file.write': 'ALLOW',
  };
  const cm = diffAuthorityTables(t0, m);
  assert.ok(
    cm.some((c) => c.kind === 'changed' && c.capability === 'fs.env-file.write' && c.cell === 'STRICT/LOOSE'),
  );
  assert.equal(classifyAuthorityChanges(cm, m), 'major');
});
