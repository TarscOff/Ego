// PHASE-1 CLOSURE, AUTHORITY TIERS (independent audit of 2026-10-01, Q98 items). Three families of defect, each
// pinned at the level of the CLASS rather than the spelling the audit happened to use:
//
//   1. a session grant lifted an EXTERNAL effect from ASK to ALLOW (issue #16 section 4: "never permit an unattended
//      external-write ALLOW, in any host mode"; section 8: a human phrase is a bounded task approval, never a durable
//      authority grant);
//   2. two identifiers that are non-widenable in effect were not MARKED so (Q98 follow-up 1);
//   3. "bypass of branch/repository protection" had no capability at all, and three declared admin-governed
//      identifiers had no matcher, so enabling them changed nothing (Q98 follow-up 2, test 15c).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadControlPlane, loadOverlayCapabilities } from '../src/control-plane/load.ts';
import {
  compileAuthority,
  diffAuthorityTables,
  classifyAuthorityChanges,
} from '../src/authority/compile.ts';
import { evaluate, type EvaluationContext } from '../src/authority/evaluate.ts';
import { table, workspace } from './support/corpus.ts';

const ROOT = new URL('../../../control-plane/', import.meta.url).pathname;
const PROFILES = Object.keys(table.profiles).sort();
const MODES = Object.keys(table.profiles[PROFILES[0]!]!.modes).sort();

const dir = workspace();
function run(
  command: string,
  over: Partial<EvaluationContext> = {},
  t: typeof table = table,
): ReturnType<typeof evaluate> {
  return evaluate(
    t,
    { profile: 'STANDARD', mode: 'NORMAL_DELIVERY', repoRoots: [dir], cwd: dir, ...over },
    { tool: 'Bash', input: { command } },
  );
}
const overlayDoc = (
  kind: 'organization' | 'overlay',
  section: string,
  ...ids: string[]
): ReturnType<typeof loadOverlayCapabilities> => {
  const d = mkdtempSync(join(tmpdir(), 'ego-closure-'));
  const f = join(d, 'permissions.md');
  writeFileSync(
    f,
    `---\nschema: ego.capabilities/1\nid: ${kind}\nfamily: ${kind}\n---\n# L\n\n## ${section}\n\n${ids
      .map((id) => `- [x] \`${id}\` — layer text\n`)
      .join('')}`,
  );
  return loadOverlayCapabilities(f, kind);
};
/** every administrable external capability, enabled at ASK by an organization: the most permissive legal table */
const ADMIN_GOVERNED = table.organizationLocked;
const enabledTable = compileAuthority(loadControlPlane(ROOT), {
  organization: overlayDoc('organization', 'Requires human approval', ...ADMIN_GOVERNED),
});
/** a private copy of the authored control plane to edit */
function editedControlPlane(edit: (file: (rel: string) => string, write: (rel: string, body: string) => void) => void): string {
  const d = mkdtempSync(join(tmpdir(), 'ego-closure-cp-'));
  cpSync(ROOT, d, { recursive: true });
  edit(
    (rel) => readFileSync(join(d, rel), 'utf8'),
    (rel, body) => writeFileSync(join(d, rel), body),
  );
  return d;
}

/* ------------------------------------------------------------------------------------------------------------- *
 * 2. TIER MARKING (Q98 follow-up 1)
 * ------------------------------------------------------------------------------------------------------------- */

const NON_WIDENABLE_BY_EFFECT = ['git.hooks.bypass', 'fs.outside-workspace.write'] as const;

test('tier marking: git.hooks.bypass and fs.outside-workspace.write are ABSOLUTE and DENY in all 12 profile x mode cells', () => {
  assert.equal(PROFILES.length * MODES.length, 12);
  for (const id of NON_WIDENABLE_BY_EFFECT) {
    assert.ok(table.absoluteDenies.includes(id), `${id} must be in table.absoluteDenies`);
    assert.equal(table.capabilities[id]!.lock, 'absolute', id);
    assert.equal(table.capabilities[id]!.absolute, true, id);
    assert.ok(!table.organizationLocked.includes(id), `${id} is not an administrable lock`);
    for (const p of PROFILES)
      for (const m of MODES) assert.equal(table.profiles[p]!.modes[m]![id], 'DENY', `${id} in ${p}/${m}`);
  }
});

test('tier marking: no layer can reference either identifier — the refusal is the absolute one, not a generic "widen"', () => {
  const cp = loadControlPlane(ROOT);
  for (const id of NON_WIDENABLE_BY_EFFECT) {
    // an organization asking to enable it, and a product overlay restating it
    assert.throws(
      () => compileAuthority(cp, { organization: overlayDoc('organization', 'Requires human approval', id) }),
      /may not reference absolute deny/,
      `organization -> ${id}`,
    );
    assert.throws(
      () => compileAuthority(cp, { overlay: overlayDoc('overlay', 'Denied', id) }),
      /may not reference absolute deny/,
      `overlay -> ${id}`,
    );
    // a mode override and a grant entry fail at load
    const withMode = editedControlPlane((_f, write) =>
      write(
        'modes/evil.md',
        `---\nschema: ego.mode/1\nid: EVIL\nkind: authority\noverrides:\n  - capability: ${id}\n    verdict: ALLOW\n---\n# EVIL\n`,
      ),
    );
    assert.throws(() => loadControlPlane(withMode), new RegExp(`mode may not override absolute deny "${id}"`));
    const withGrant = editedControlPlane((f, write) =>
      write(
        'permissions/grants.md',
        f('permissions/grants.md').replace(
          '  - capability: git.local.commit\n',
          `  - capability: ${id}\n    phrases: ["do it anyway"]\n  - capability: git.local.commit\n`,
        ),
      ),
    );
    assert.throws(() => loadControlPlane(withGrant), new RegExp(`grant may not reference absolute deny "${id}"`));
    // a profile narrowing is also a reference
    const withProfile = editedControlPlane((f, write) =>
      write(
        'profiles/strict.md',
        f('profiles/strict.md').replace('narrow:\n', `narrow:\n  - capability: ${id}\n    verdict: DENY\n`),
      ),
    );
    assert.throws(
      () => compileAuthority(loadControlPlane(withProfile)),
      new RegExp(`profile may not reference absolute deny "${id}"`),
    );
  }
});

test('tier marking: moving an identifier between lock tiers is a MAJOR authority change (Q84), and the diff says so', () => {
  const before = structuredClone(table);
  for (const id of NON_WIDENABLE_BY_EFFECT) {
    before.capabilities[id]!.lock = 'none';
    before.capabilities[id]!.absolute = false;
    before.absoluteDenies = before.absoluteDenies.filter((x) => x !== id);
  }
  const changes = diffAuthorityTables(before, table);
  for (const id of NON_WIDENABLE_BY_EFFECT)
    assert.ok(changes.some((c) => c.kind === 'lock-changed' && c.capability === id && c.toLock === 'absolute'), id);
  assert.equal(classifyAuthorityChanges(changes, table), 'major');
});

test('tier marking: the effective verdict did not move — every spelling that was DENY is still DENY, now labelled absolute', () => {
  for (const [cmd, cap] of [
    ['git commit --no-verify -m x', 'git.hooks.bypass'],
    ['git commit -n -m x', 'git.hooks.bypass'],
    ['git -c core.hooksPath=/dev/null commit -m x', 'git.hooks.bypass'],
    ['git push --no-verify origin feature/x', 'git.hooks.bypass'],
    ['echo x > /etc/hosts', 'fs.outside-workspace.write'],
    ['cp payload /etc/cron.d/x', 'fs.outside-workspace.write'],
  ] as const) {
    for (const profile of PROFILES) {
      const r = run(cmd, { profile });
      assert.equal(r.verdict, 'DENY', `${cmd} in ${profile}`);
      assert.equal(r.decisive?.capability === cap || r.hits.some((h) => h.capability === cap), true, `${cmd}: ${cap}`);
      assert.match(r.reason, /absolute core deny/, cmd);
    }
  }
});

test('tier marking: an organization that ENABLES pushing still cannot make a hook bypass an ASK, whichever verb carries the flag', () => {
  for (const id of ADMIN_GOVERNED) assert.equal(enabledTable.effective[id], 'ASK', `${id} is enabled in this table`);
  for (const verb of [
    'commit',
    'merge main',
    'rebase main',
    'cherry-pick abc',
    'am p.mbox',
    'revert abc',
    'pull origin main',
    'push origin feature/x',
  ]) {
    for (const cmd of [`git ${verb} --no-verify`, `git -C . ${verb} --no-verify`, `git ${verb} --no-verif`]) {
      const r = run(cmd, {}, enabledTable);
      assert.equal(r.verdict, 'DENY', cmd);
      assert.equal(r.decisive?.capability, 'git.hooks.bypass', cmd);
    }
  }
  // ...and the same push without the flag is the ordinary, human-approved integration act
  assert.equal(run('git push origin feature/x', {}, enabledTable).verdict, 'ASK');
});
