// Q98 VOCABULARY AND REASON CODES (issue #16 sections 10 and 12; #2 section 12). Three families, each pinned at the
// level of the CLASS rather than at the spelling that happened to be wrong:
//
//   A. NAMING. The tier a human sees as ADMIN_GOVERNED was still spelled `organization-locked` in the schema, the
//      compiled table, the provenance, the messages and the capability file. One migration, with a read alias, so
//      nothing a consumer wrote under the old name silently changes meaning or strands a cache.
//   B. REASON CODES. A refusal named a capability and, sometimes, a tier in prose. It now carries a typed code
//      (HARD_LOCKED, ADMIN_DENIED, HUMAN_APPROVAL_REQUIRED, SCOPE_DENIED, TARGET_UNCLASSIFIED, POLICY_INVALID,
//      POLICY_STALE; four more defined for the phases that own their producers), the rule source, and whether
//      configuration can change the outcome. ONE function maps a decision to its code.
//   C. TERMINOLOGY AND DIFFS. `ego doctor`, `ego capabilities` and `ego explain capability` print the effect class,
//      lock tier, effective verdict, ceiling, source layer and the target rule — all derived from the compiled table,
//      none hand-listed — and `ego authority diff` makes a reconfiguration reviewable with every widening marked.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { spawnSync } from 'node:child_process';
import { evaluate, type EvaluationContext, type Evaluation } from '../src/authority/evaluate.ts';
import {
  compileAuthority,
  diffAuthorityTables,
  classifyAuthorityChanges,
  type CompiledAuthorityTable,
} from '../src/authority/compile.ts';
import { loadControlPlane, loadOverlayCapabilities } from '../src/control-plane/load.ts';
import {
  ensurePolicyCache,
  readPolicyCache,
  policyCacheFreshness,
  POLICY_CACHE_RELATIVE,
} from '../src/policy/cache.ts';
import { sealFor } from '../src/policy/seal.ts';
import { handleHook, type HookRuntime } from '../src/hooks/handle.ts';
import type { HookDecision, HookEvent } from '../src/hooks/events.ts';
import { writePin, readPin } from '../src/launcher/pin.ts';
import { selfIdentity, selfVersion } from '../src/launcher/self.ts';
import { sha256Canonical } from '../src/util/hash.ts';
import { runCheck } from '../src/project/check.ts';
import { runGitHook } from '../src/project/githooks.ts';
import { runDoctor, formatDoctor } from '../src/project/doctor.ts';
import { renderClaudeCodeOutput } from '../../adapter-claude-code/src/dialect.ts';
import { renderCodexOutput } from '../../adapter-codex-cli/src/dialect.ts';
import { runCommand, type ProjectContext } from '../../cli/src/commands.ts';
import { main } from '../../cli/src/main.ts';
import { table, workspace, SEMANTIC_CLASSES } from './support/corpus.ts';

const CP = new URL('../../../control-plane/', import.meta.url).pathname;
const REPO = new URL('../../../', import.meta.url).pathname;
const SELF = () => ({ runtimeSha256: selfIdentity().runtimeSha256, version: selfVersion() });

const reasons = () => import('../src/authority/reasons.ts');
const describeMod = () => import('../src/authority/describe.ts');
const legacyMod = () => import('../src/control-plane/legacy-names.ts');

/* ------------------------------------------------------------------------------------------------------------- *
 * fixtures
 * ------------------------------------------------------------------------------------------------------------- */

function gitEnv(): NodeJS.ProcessEnv {
  const e: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) if (!/^GIT_/.test(k)) e[k] = v;
  return e;
}

type ProfileName = 'STANDARD' | 'STRICT' | 'HIGH_ASSURANCE';

/** every project fixture lives under one parent: `detectProject` lists a repository's SIBLINGS, and the system temp
 *  directory holds thousands (support/corpus.ts explains the same cost) */
const FIXTURES = mkdtempSync(join(tmpdir(), 'ego-q98v-root-'));

/** a consumer project pinned to this runtime, the way hooks.test.ts builds one */
function project(profile: ProfileName = 'STANDARD'): {
  root: string;
  rt: HookRuntime;
  env: NodeJS.ProcessEnv;
  ctx: ProjectContext;
} {
  const root = mkdtempSync(join(FIXTURES, 'proj-'));
  spawnSync('git', ['init', '-q'], { env: gitEnv(), cwd: root });
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'demo', scripts: {} }));
  const self = selfIdentity();
  writePin(root, {
    name: self.name,
    version: selfVersion(),
    integrity: self.runtimeSha256,
    sources: [],
    schemas: {},
    node: '>=24',
    profile,
    taskSource: 'ad-hoc',
  });
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    EGO_HOME: mkdtempSync(join(tmpdir(), 'ego-q98v-home-')),
    CLAUDE_PROJECT_DIR: root,
  };
  let t = 0;
  const pin = readPin(root);
  const rt: HookRuntime = {
    projectRoot: root,
    pin,
    now: () => new Date(Date.UTC(2026, 9, 1, 10, 0, t++ % 59)).toISOString(),
    controlPlaneRoot: CP,
    env,
  };
  return { root, rt, env, ctx: { root, pin, prePromotion: false } };
}

const hookEv = (root: string, event: HookEvent['event'], extra: Partial<HookEvent> = {}): HookEvent => ({
  host: 'claude-code',
  event,
  sessionId: 's1',
  cwd: root,
  raw: {},
  ...extra,
});
const pre = (root: string, command: string): HookEvent =>
  hookEv(root, 'PreToolUse', { tool: { name: 'Bash', input: { command } } });

/** an organization layer file: `section` is the verdict section the ids are listed under */
function orgPolicy(
  root: string,
  section: 'Allowed' | 'Requires human approval' | 'Denied',
  ...ids: string[]
): void {
  const f = join(root, 'policies', 'organization', 'permissions.md');
  mkdirSync(join(root, 'policies', 'organization'), { recursive: true });
  writeFileSync(
    f,
    `---\nschema: ego.capabilities/1\nid: organization\nfamily: organization\n---\n# Organization\n\n## ${section}\n\n${ids.map((id) => `- [x] \`${id}\` — enabled by the organization\n`).join('')}`,
  );
}

interface CliResult {
  code: number;
  out: string;
  err: string;
}
async function cli(p: ReturnType<typeof project>, argv: string[]): Promise<CliResult> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await runCommand(
    argv,
    {
      cwd: p.root,
      env: p.env,
      stdin: '',
      out: (s) => out.push(s),
      err: (s) => err.push(s),
      now: () => '2026-10-01T10:00:00.000Z',
    },
    p.ctx,
  );
  return { code, out: out.join('\n'), err: err.join('\n') };
}

/** every file under `dir` (relative paths), skipping state that is not source */
function walk(dir: string, keep: (rel: string) => boolean): string[] {
  const out: string[] = [];
  const visit = (d: string): void => {
    for (const name of readdirSync(d)) {
      if (['node_modules', '.git', '.probe', 'dist', '.harness'].includes(name)) continue;
      const abs = join(d, name);
      if (statSync(abs).isDirectory()) visit(abs);
      else if (keep(relative(dir, abs))) out.push(relative(dir, abs));
    }
  };
  visit(dir);
  return out.sort();
}

/* ------------------------------------------------------------------------------------------------------------- *
 * A. NAMING: ADMIN_GOVERNED is spelled one way, and the old spelling is a read alias
 * ------------------------------------------------------------------------------------------------------------- */

/** The old name in every spelling it ever had in a file. */
const LEGACY_NAME = /organization[-_ ]?locked/i;

test('A1 the old tier name survives only in the module that reads it, and in lines that say it is the old name', () => {
  const offenders: string[] = [];
  // SOURCE: only the alias module may spell it, and says so
  for (const rel of walk(join(REPO, 'packages'), (r) => /\/src\/.*\.ts$/.test('/' + r)))
    if (rel !== join('kernel', 'src', 'control-plane', 'legacy-names.ts'))
      readFileSync(join(REPO, 'packages', rel), 'utf8')
        .split('\n')
        .forEach(
          (l, i) =>
            LEGACY_NAME.test(l) && offenders.push(`packages/${rel}:${i + 1}: ${l.trim().slice(0, 100)}`),
        );
  // THE AUTHORED CONTROL PLANE and the documents a reader meets first: a mention must label itself as the old name
  const documents = [
    ...walk(join(REPO, 'control-plane'), () => true).map((r) => join('control-plane', r)),
    join('docs', 'architecture', 'security-model.md'),
    join('docs', 'architecture', 'alignment-2026-09.md'),
    join('docs', 'build', 'handoff.md'),
  ];
  for (const rel of documents)
    readFileSync(join(REPO, rel), 'utf8')
      .split('\n')
      .forEach(
        (l, i) =>
          LEGACY_NAME.test(l) &&
          !/formerly|previously|legacy|old name|previous name|compatibility alias|deprecated/i.test(l) &&
          offenders.push(`${rel}:${i + 1}: ${l.trim().slice(0, 100)}`),
      );
  assert.deepEqual(
    offenders,
    [],
    'the canonical name is ADMIN_GOVERNED (admin-governed in a file); say "formerly organization-locked" when the old name is the point',
  );
});

test('A2 the compiled table, the capability file and the provenance use the canonical name', () => {
  const t = table as unknown as Record<string, unknown> & CompiledAuthorityTable;
  assert.ok(Array.isArray((t as { adminGoverned?: string[] }).adminGoverned), 'table.adminGoverned');
  assert.equal('organizationLocked' in t, false, 'the old field is gone from the table');
  const admin = (t as unknown as { adminGoverned: string[] }).adminGoverned;
  assert.ok(admin.length >= 20 && admin.includes('forge.pr.merge') && admin.includes('git.remote.push'));
  for (const id of admin) {
    const c = table.capabilities[id]!;
    assert.equal(c.lock, 'admin-governed', `${id} lock`);
    assert.equal(c.family, 'admin-governed', `${id} family`);
    assert.equal(table.provenance[id]![0]!.layer, 'admin-governed', `${id} provenance`);
    assert.ok(!table.absoluteDenies.includes(id), `${id} is not a HARD_LOCK`);
  }
  assert.equal(
    Object.values(table.capabilities).filter((c) => c.lock === 'admin-governed').length,
    admin.length,
    'every capability with the tier is listed, and nothing else is',
  );
  assert.ok(existsSync(join(CP, 'permissions', 'capabilities', 'admin-governed.md')));
  assert.ok(!existsSync(join(CP, 'permissions', 'capabilities', 'organization-locked.md')));
  const head = readFileSync(join(CP, 'permissions', 'capabilities', 'admin-governed.md'), 'utf8').split(
    '---',
  )[1]!;
  assert.match(head, /^family: admin-governed$/m);
  assert.match(head, /^lock: admin-governed$/m);
  // a widening says which tier it widened, in the canonical words
  const f = join(mkdtempSync(join(tmpdir(), 'ego-q98v-org-')), 'permissions.md');
  writeFileSync(
    f,
    '---\nschema: ego.capabilities/1\nid: o\nfamily: organization\n---\n# O\n\n## Allowed\n\n- [x] `forge.pr.create` — a\n\n## Requires human approval\n\n- [x] `forge.pr.merge` — b\n',
  );
  const widened = compileAuthority(loadControlPlane(CP), {
    organization: loadOverlayCapabilities(f, 'organization'),
  });
  assert.match(
    widened.provenance['forge.pr.create']!.at(-1)!.layer,
    /widened admin-governed deny, clamped to the ASK ceiling/,
  );
  assert.match(widened.provenance['forge.pr.merge']!.at(-1)!.layer, /widened admin-governed deny\)/);
});

/** A copy of the control plane as the previous release authored it: the file under its old name, with the old family and
 *  lock values. `edit` may change more. */
function legacyControlPlane(): string {
  const d = mkdtempSync(join(tmpdir(), 'ego-q98v-legacy-cp-'));
  cpSync(CP, d, { recursive: true });
  const dir = join(d, 'permissions', 'capabilities');
  const text = readFileSync(join(dir, 'admin-governed.md'), 'utf8')
    .replace('id: admin-governed', 'id: organization-locked')
    .replace('family: admin-governed', 'family: organization-locked')
    .replace('lock: admin-governed', 'lock: organization');
  writeFileSync(join(dir, 'organization-locked.md'), text);
  renameSync(join(dir, 'admin-governed.md'), join(d, 'admin-governed.md.bak'));
  return d;
}

test('A3 a control plane authored under the old name still loads, means the same thing, and says so once', () => {
  const legacy = legacyControlPlane();
  const cp = loadControlPlane(legacy) as unknown as { notices?: string[] };
  assert.ok(Array.isArray(cp.notices), 'the loader reports what it translated');
  assert.equal(cp.notices!.length, 1, 'one line for the file, not one per capability');
  assert.match(cp.notices![0]!, /organization-locked/);
  assert.match(cp.notices![0]!, /admin-governed/);
  assert.match(cp.notices![0]!, /organization-locked\.md/, 'it names the file to change');
  const old = compileAuthority(loadControlPlane(legacy));
  assert.deepEqual(old.adminGoverned, (table as unknown as { adminGoverned: string[] }).adminGoverned);
  assert.deepEqual(old.effective, table.effective, 'no verdict moved');
  assert.deepEqual(
    old.capabilities,
    table.capabilities,
    'the tier, the family and the effect class are the canonical ones',
  );
  assert.deepEqual(old.profiles, table.profiles);
  assert.equal(diffAuthorityTables(table, old).length, 0);
  // the canonical files raise no note
  assert.deepEqual((loadControlPlane(CP) as unknown as { notices?: string[] }).notices, []);
  // neighbours of the same class: a fork that carries both spellings of the file has two files for one tier; a file
  // that mixes the spellings (old lock value, canonical family) is read the same way, with a note naming only `lock:`
  const both = legacyControlPlane();
  cpSync(join(both, 'admin-governed.md.bak'), join(both, 'permissions', 'capabilities', 'admin-governed.md'));
  assert.throws(() => loadControlPlane(both), /only one admin-governed file is allowed/);
  const mixed = legacyControlPlane();
  const legacyFile = join(mixed, 'permissions', 'capabilities', 'organization-locked.md');
  writeFileSync(
    legacyFile,
    readFileSync(legacyFile, 'utf8').replace('family: organization-locked', 'family: admin-governed'),
  );
  const mixedCp = loadControlPlane(mixed) as unknown as { notices: string[] };
  assert.equal(mixedCp.notices.length, 1);
  assert.match(mixedCp.notices[0]!, /`lock:`/);
  assert.doesNotMatch(mixedCp.notices[0]!, /`family:`/);
  // an alias is not a licence: only the core layer may declare a tier, and an unknown value still fails closed
  const d = mkdtempSync(join(tmpdir(), 'ego-q98v-lock-'));
  const bad = join(d, 'permissions.md');
  writeFileSync(
    bad,
    '---\nschema: ego.capabilities/1\nid: o\nfamily: organization-locked\nlock: organization\n---\n# O\n\n## Denied\n\n- [x] `forge.pr.create` — a\n',
  );
  assert.throws(() => loadOverlayCapabilities(bad, 'organization'), /only the core layer may declare a lock/);
  writeFileSync(
    bad,
    '---\nschema: ego.capabilities/1\nid: o\nfamily: o\nlock: banana\n---\n# O\n\n## Denied\n\n- [x] `forge.pr.create` — a\n',
  );
  assert.throws(
    () => loadOverlayCapabilities(bad, 'organization'),
    /lock must be absolute, admin-governed or none/,
  );
  // an organization policy file that copied the old family header keeps meaning exactly what it meant
  writeFileSync(
    bad,
    '---\nschema: ego.capabilities/1\nid: o\nfamily: organization-locked\n---\n# O\n\n## Requires human approval\n\n- [x] `forge.pr.create` — a\n',
  );
  const doc = loadOverlayCapabilities(bad, 'organization');
  assert.equal(
    compileAuthority(loadControlPlane(CP), { organization: doc }).effective['forge.pr.create'],
    'ASK',
  );
});

/** What the PREVIOUS release (commit 0111e63) wrote into a policy cache for an organization that enabled
 *  forge.pr.create at ASK and git.remote.push at ALLOW (clamped). Real output of that compiler, trimmed to the parts
 *  that carry the old names — an oracle that does not share an author with the code that reads it. */
const LEGACY_ORACLE = {
  schema: 'ego.authority-table/1',
  sourceHashes: {
    'permissions/absolute-denies.md': 'dd742b9b1cb31400d62f0be1ef2948fb225a2e9e3cbad7a1857fd64db201b73f',
    'permissions/capabilities/organization-locked.md':
      'ebde42138db67cf7224c18fcf89feab0621881371cdbe98c4c6faa11e71ce156',
  },
  capabilities: {
    'forge.pr.create': {
      family: 'organization-locked',
      description: 'opening a pull or merge request.',
      absolute: false,
      lock: 'organization',
      core: 'DENY',
      effect: 'external',
    },
    'git.remote.push': {
      family: 'organization-locked',
      description: 'pushing to any remote.',
      absolute: false,
      lock: 'organization',
      core: 'DENY',
      effect: 'external',
    },
    'forge.issue.comment': {
      family: 'forge',
      description: 'comment on an issue.',
      absolute: false,
      lock: 'none',
      core: 'ASK',
      effect: 'external',
    },
    'production.deploy': {
      family: 'absolute',
      description: 'production deployment.',
      absolute: true,
      lock: 'absolute',
      core: 'DENY',
      effect: 'external',
    },
  },
  absoluteDenies: ['production.deploy'],
  organizationLocked: ['forge.pr.create', 'git.remote.push'],
  effective: {
    'forge.pr.create': 'ASK',
    'git.remote.push': 'ASK',
    'forge.issue.comment': 'ASK',
    'production.deploy': 'DENY',
  },
  provenance: {
    'forge.pr.create': [
      {
        layer: 'organization-locked',
        file: 'permissions/capabilities/organization-locked.md',
        verdict: 'DENY',
      },
      {
        layer: 'organization (widened organization-locked deny)',
        file: 'policies/organization/permissions.md',
        verdict: 'ASK',
      },
    ],
    'git.remote.push': [
      {
        layer: 'organization-locked',
        file: 'permissions/capabilities/organization-locked.md',
        verdict: 'DENY',
      },
      {
        layer: 'organization (widened organization-locked deny, clamped to the ASK ceiling)',
        file: 'policies/organization/permissions.md',
        verdict: 'ASK',
      },
    ],
    'forge.issue.comment': [
      { layer: 'core', file: 'permissions/capabilities/forge.md', verdict: 'ASK' },
      {
        layer: 'grant (external effect: a session grant cannot lift it above the ASK ceiling)',
        file: 'permissions/grants.md',
        verdict: 'ASK',
      },
    ],
    'production.deploy': [{ layer: 'absolute', file: 'permissions/absolute-denies.md', verdict: 'DENY' }],
  },
};

test('A4 a table written under the old name is upgraded field by field, and only the names change', async () => {
  const { upgradeLegacyTable, isLegacyTable } = await legacyMod();
  assert.equal(isLegacyTable(LEGACY_ORACLE), true);
  const up = upgradeLegacyTable(
    structuredClone(LEGACY_ORACLE) as never,
  ) as unknown as typeof LEGACY_ORACLE & {
    adminGoverned: string[];
    tableHash: string;
  };
  assert.equal(isLegacyTable(up), false);
  assert.deepEqual(up.adminGoverned, ['forge.pr.create', 'git.remote.push']);
  assert.equal('organizationLocked' in up, false);
  assert.equal(up.capabilities['forge.pr.create']!.lock, 'admin-governed');
  assert.equal(up.capabilities['forge.pr.create']!.family, 'admin-governed');
  assert.equal(up.capabilities['production.deploy']!.lock, 'absolute', 'a HARD_LOCK keeps its value');
  assert.equal(up.capabilities['forge.issue.comment']!.lock, 'none');
  assert.deepEqual(up.effective, LEGACY_ORACLE.effective, 'no verdict is touched');
  assert.equal(up.provenance['forge.pr.create']![0]!.layer, 'admin-governed');
  assert.equal(up.provenance['forge.pr.create']![1]!.layer, 'organization (widened admin-governed deny)');
  assert.equal(
    up.provenance['git.remote.push']![1]!.layer,
    'organization (widened admin-governed deny, clamped to the ASK ceiling)',
  );
  assert.equal(up.provenance['forge.pr.create']![0]!.file, 'permissions/capabilities/admin-governed.md');
  assert.deepEqual(Object.keys(up.sourceHashes).sort(), [
    'permissions/absolute-denies.md',
    'permissions/capabilities/admin-governed.md',
  ]);
  assert.equal(
    JSON.stringify(up).match(LEGACY_NAME),
    null,
    'nothing of the old name is left in the upgraded table',
  );
  // the upgraded table is internally consistent: its hash is the canonical hash of its body
  const { tableHash, ...body } = up;
  assert.equal(tableHash, sha256Canonical(body));
  // upgrading is idempotent on a current table
  assert.deepEqual(upgradeLegacyTable(structuredClone(table) as never), table);
});

/** the previous release's rendering of a current table: the same content under the old names. Only the names the old
 *  compiler wrote — the field, the `lock` and `family` values, the provenance layers and files, the source-hash keys —
 *  and never authored prose (a description that mentions the file stays as its author wrote it). */
function toLegacy(t: CompiledAuthorityTable): Record<string, unknown> {
  const {
    tableHash: _h,
    adminGoverned,
    ...rest
  } = structuredClone(t) as unknown as Record<string, unknown> & {
    tableHash: string;
    adminGoverned: string[];
    capabilities: Record<string, { lock: string; family: string }>;
    provenance: Record<string, Array<{ layer: string; file: string }>>;
    sourceHashes: Record<string, string>;
  };
  for (const c of Object.values(rest.capabilities)) {
    if (c.lock === 'admin-governed') c.lock = 'organization';
    if (c.family === 'admin-governed') c.family = 'organization-locked';
  }
  for (const trace of Object.values(rest.provenance))
    for (const step of trace) {
      step.layer = step.layer.replaceAll('admin-governed', 'organization-locked');
      step.file = step.file.replace(/admin-governed\.md$/, 'organization-locked.md');
    }
  rest.sourceHashes = Object.fromEntries(
    Object.entries(rest.sourceHashes).map(([k, v]) => [
      k.replace(/admin-governed\.md$/, 'organization-locked.md'),
      v,
    ]),
  );
  const body = { ...rest, organizationLocked: adminGoverned } as Record<string, unknown>;
  return { ...body, tableHash: sha256Canonical(body) };
}

test('A5 the authority diff between an old-name table and the current one shows no change at all', async () => {
  const { upgradeLegacyTable } = await legacyMod();
  const legacy = toLegacy(table);
  assert.ok('organizationLocked' in legacy);
  const up = upgradeLegacyTable(legacy as never);
  assert.deepEqual(diffAuthorityTables(up, table), [], 'no widening, no narrowing, no re-partition');
  assert.equal(classifyAuthorityChanges(diffAuthorityTables(up, table), table), 'none');
  assert.deepEqual(up, table, 'it is the table itself, hash included');
});

test('A6 a cache written under the old name is POLICY_STALE with a clear message, never corrupt, and regenerates without losing an accepted widening', async () => {
  const p = project();
  orgPolicy(p.root, 'Requires human approval', 'forge.pr.create');
  const accepted = ensurePolicyCache(CP, p.root, SELF(), { acceptWidening: true }).cache;
  assert.equal(accepted.table.effective['forge.pr.create'], 'ASK');
  assert.equal(accepted.pendingWidening, undefined);
  // the previous release left this on disk: another runtime identity, the old names, a hash over the old body
  const path = join(p.root, POLICY_CACHE_RELATIVE);
  writeFileSync(
    path,
    JSON.stringify({
      ...accepted,
      runtimeSha256: 'e'.repeat(64),
      runtimeVersion: '0.0.9',
      table: toLegacy(accepted.table),
    }),
  );
  const read = readPolicyCache(p.root) as unknown as {
    table: { adminGoverned?: string[] };
    legacyNaming?: boolean;
  } | null;
  assert.ok(read, 'a legacy cache is readable, not discarded as corrupt');
  assert.ok(read.table.adminGoverned!.includes('forge.pr.create'), 'it reads in the current shape');
  assert.equal(read.legacyNaming, true);
  const fresh = policyCacheFreshness(CP, p.root, SELF()) as {
    fresh: boolean;
    reasons: string[];
    code?: string;
  };
  assert.equal(fresh.fresh, false);
  assert.equal(fresh.code, 'POLICY_STALE');
  const { formatFreshness } = await import('../src/policy/cache.ts');
  const message = formatFreshness(fresh as never);
  assert.match(message, /^POLICY_STALE: /);
  assert.match(message, /previous (organization-locked )?naming/);
  assert.match(message, /ego init/, 'it names the consumer action');
  // the same message is what the human reads in `ego check` and `ego doctor`
  const check = runCheck(p.root).items.find((i) => i.name === 'policy cache')!;
  assert.equal(check.ok, false);
  assert.match(check.detail, /^POLICY_STALE: /);
  const doctor = formatDoctor(
    runDoctor({ cwd: p.root, env: p.env, now: () => '2026-10-01T10:00:00.000Z', offline: true }),
  );
  assert.match(doctor, /compiled policy cache: POLICY_STALE: /);
  // a hook regenerates it. The widening the human accepted before the upgrade is still accepted: nothing stranded
  const regenerated = ensurePolicyCache(CP, p.root, SELF()).cache as unknown as PolicyCacheShape;
  assert.equal(
    regenerated.pendingWidening,
    undefined,
    'an accepted widening is not turned into a pending one',
  );
  assert.equal(regenerated.table.effective['forge.pr.create'], 'ASK');
  assert.equal(regenerated.legacyNaming, undefined);
  const onDisk = JSON.parse(readFileSync(path, 'utf8')) as { table: Record<string, unknown> };
  assert.ok('adminGoverned' in onDisk.table && !('organizationLocked' in onDisk.table));
  assert.equal(policyCacheFreshness(CP, p.root, SELF()).fresh, true);
  // the same runtime identity does not excuse an old-name cache (a development tree keeps its identity across edits)
  writeFileSync(path, JSON.stringify({ ...accepted, table: toLegacy(accepted.table) }));
  const same = ensurePolicyCache(CP, p.root, SELF());
  assert.equal(same.regenerated, true);
  assert.ok('adminGoverned' in same.cache.table);
});
test('A7 a cache written under the old name is never the baseline a widening is measured against', () => {
  const p = project();
  orgPolicy(p.root, 'Requires human approval', 'forge.pr.create');
  const accepted = ensurePolicyCache(CP, p.root, SELF(), { acceptWidening: true }).cache;
  assert.equal(accepted.table.effective['forge.pr.create'], 'ASK');
  // a cache in the old shape that records the WIDE table under the CURRENT runtime identity and no accepted layer
  // sources: believed as a baseline, it would make the organization file's widening look like no widening at all
  writeFileSync(
    join(p.root, POLICY_CACHE_RELATIVE),
    JSON.stringify({ ...accepted, acceptedLayerSources: {}, table: toLegacy(accepted.table) }),
  );
  const again = ensurePolicyCache(CP, p.root, SELF()).cache as unknown as PolicyCacheShape;
  assert.ok(again.pendingWidening, 'the widening is still waiting for a human');
  assert.equal(again.table.effective['forge.pr.create'], 'DENY', 'and is not applied');
  assert.equal(handleHook(pre(p.root, 'gh pr create --fill'), p.rt).action, 'deny');
});
interface PolicyCacheShape {
  pendingWidening?: unknown;
  legacyNaming?: boolean;
  table: CompiledAuthorityTable;
}

/* ------------------------------------------------------------------------------------------------------------- *
 * B. REASON CODES
 * ------------------------------------------------------------------------------------------------------------- */

const ALL_CODES = [
  'HARD_LOCKED',
  'ADMIN_DENIED',
  'HUMAN_APPROVAL_REQUIRED',
  'SCOPE_DENIED',
  'TARGET_UNCLASSIFIED',
  'NETWORK_UNAVAILABLE',
  'SERVICE_UNAVAILABLE',
  'RUNTIME_CAPABILITY_UNAVAILABLE',
  'DOWNSTREAM_AUTH_DENIED',
  'POLICY_INVALID',
  'POLICY_STALE',
];
const DEFERRED = [
  'NETWORK_UNAVAILABLE',
  'SERVICE_UNAVAILABLE',
  'RUNTIME_CAPABILITY_UNAVAILABLE',
  'DOWNSTREAM_AUTH_DENIED',
];

test('B1 the reason-code enum has the eleven members of issue #16 section 10, and the four without a producer say so', async () => {
  const { REASON_CODES, REASON_CODE_INFO } = await reasons();
  assert.deepEqual([...REASON_CODES].sort(), [...ALL_CODES].sort());
  for (const code of REASON_CODES) {
    const info = REASON_CODE_INFO[code];
    assert.ok(info.meaning.length > 20 && info.configurable.length > 10, code);
    assert.ok(['live', 'deferred'].includes(info.producer.status), code);
    assert.ok(info.producer.where.length > 10, `${code} documents its producer`);
  }
  assert.deepEqual(
    REASON_CODES.filter((c) => REASON_CODE_INFO[c].producer.status === 'deferred').sort(),
    [...DEFERRED].sort(),
  );
  for (const c of DEFERRED)
    assert.match(
      REASON_CODE_INFO[c as keyof typeof REASON_CODE_INFO].producer.where,
      /phase \d/i,
      `${c} names the phase that owns it`,
    );
  // NOT FAKED: no source file other than the enum itself produces a deferred code
  const producers: string[] = [];
  for (const rel of walk(join(REPO, 'packages'), (r) => /\/src\/.*\.ts$/.test('/' + r)))
    if (rel !== join('kernel', 'src', 'authority', 'reasons.ts'))
      for (const c of DEFERRED)
        if (readFileSync(join(REPO, 'packages', rel), 'utf8').includes(c))
          producers.push(`${rel} mentions ${c}`);
  assert.deepEqual(producers, [], 'a deferred code has no producer until the module that owns it exists');
});

type Call = { tool: string; input: Record<string, unknown> };
const bash = (command: string): Call => ({ tool: 'Bash', input: { command } });
const HOME = process.env['HOME'] ?? '';
const WS = workspace();
const write = (p: string): Call => ({
  tool: 'Write',
  input: { file_path: p.replace('$WS', WS).replace('~', HOME) },
});
const read = (p: string): Call => ({
  tool: 'Read',
  input: { file_path: p.replace('$WS', WS).replace('~', HOME) },
});

interface Case {
  /** what is being asked, in words */
  what: string;
  call: Call;
  profile?: ProfileName;
  mode?: string;
  verdict: 'DENY' | 'ASK';
  capability: string;
  code: string;
  tier: 'HARD_LOCK' | 'ADMIN_GOVERNED' | 'none';
  /** whether configuration can change the outcome */
  changeable: boolean;
}

const CASES: Case[] = [
  // ---- HARD_LOCKED: an absolute deny, wherever the call arrives from. Nothing can change it.
  {
    what: 'production Kubernetes mutation',
    call: bash('kubectl --context prod-eu apply -f x.yaml'),
    verdict: 'DENY',
    capability: 'production.k8s.mutate',
    code: 'HARD_LOCKED',
    tier: 'HARD_LOCK',
    changeable: false,
  },
  {
    what: 'production database mutation',
    call: bash("psql -h prod-db.acme.com -c 'delete from t'"),
    verdict: 'DENY',
    capability: 'production.database.mutate',
    code: 'HARD_LOCKED',
    tier: 'HARD_LOCK',
    changeable: false,
  },
  {
    what: 'cloud mutation at the provider default',
    call: bash('terraform apply -auto-approve'),
    verdict: 'DENY',
    capability: 'production.cloud.mutate',
    code: 'HARD_LOCKED',
    tier: 'HARD_LOCK',
    changeable: false,
  },
  {
    what: 'a hook bypass flag',
    call: bash('git push --no-verify origin main'),
    verdict: 'DENY',
    capability: 'git.hooks.bypass',
    code: 'HARD_LOCKED',
    tier: 'HARD_LOCK',
    changeable: false,
  },
  {
    what: 'defeating a branch protection',
    call: bash('gh pr merge 3 --admin'),
    verdict: 'DENY',
    capability: 'forge.protection.bypass',
    code: 'HARD_LOCKED',
    tier: 'HARD_LOCK',
    changeable: false,
  },
  {
    what: 'a write outside the governed workspace',
    call: write('/etc/ego-probe.conf'),
    verdict: 'DENY',
    capability: 'fs.outside-workspace.write',
    code: 'HARD_LOCKED',
    tier: 'HARD_LOCK',
    changeable: false,
  },
  {
    what: 'deleting a filesystem root',
    call: bash('rm -rf /'),
    verdict: 'DENY',
    capability: 'fs.destructive-root',
    code: 'HARD_LOCKED',
    tier: 'HARD_LOCK',
    changeable: false,
  },
  {
    what: 'writing a credential store',
    call: write('~/.ssh/authorized_keys'),
    verdict: 'DENY',
    capability: 'fs.credential-store.write',
    code: 'HARD_LOCKED',
    tier: 'HARD_LOCK',
    changeable: false,
  },
  {
    what: 'tampering with generated authority',
    call: write('$WS/.harness/generated/policy.json'),
    verdict: 'DENY',
    capability: 'ego.runtime.tamper',
    code: 'HARD_LOCKED',
    tier: 'HARD_LOCK',
    changeable: false,
  },
  // ---- ADMIN_DENIED: an ADMIN_GOVERNED capability the organization has not enabled; the organization layer can
  {
    what: 'a push',
    call: bash('git push origin main'),
    verdict: 'DENY',
    capability: 'git.remote.push',
    code: 'ADMIN_DENIED',
    tier: 'ADMIN_GOVERNED',
    changeable: true,
  },
  {
    what: 'a force push',
    call: bash('git push --force origin feature'),
    verdict: 'DENY',
    capability: 'git.remote.push.force',
    code: 'ADMIN_DENIED',
    tier: 'ADMIN_GOVERNED',
    changeable: true,
  },
  {
    what: 'opening a pull request',
    call: bash('gh pr create --title x'),
    verdict: 'DENY',
    capability: 'forge.pr.create',
    code: 'ADMIN_DENIED',
    tier: 'ADMIN_GOVERNED',
    changeable: true,
  },
  {
    what: 'a merge spelled as a raw API request',
    call: bash('curl -X PUT https://api.github.com/repos/o/r/pulls/3/merge'),
    verdict: 'DENY',
    capability: 'forge.pr.merge',
    code: 'ADMIN_DENIED',
    tier: 'ADMIN_GOVERNED',
    changeable: true,
  },
  {
    what: 'creating an issue',
    call: bash('gh issue create --title x'),
    verdict: 'DENY',
    capability: 'forge.issue.create',
    code: 'ADMIN_DENIED',
    tier: 'ADMIN_GOVERNED',
    changeable: true,
  },
  {
    what: 'deleting a repository',
    call: bash('gh repo delete o/r --yes'),
    verdict: 'DENY',
    capability: 'forge.repo.delete',
    code: 'ADMIN_DENIED',
    tier: 'ADMIN_GOVERNED',
    changeable: true,
  },
  // ... and a DENY that the SELECTED PROFILE or MODE chose is policy configuration too
  {
    what: 'a network tool under HIGH_ASSURANCE (the profile narrows it)',
    call: bash('curl https://example.com'),
    profile: 'HIGH_ASSURANCE',
    verdict: 'DENY',
    capability: 'command.network-tool',
    code: 'ADMIN_DENIED',
    tier: 'none',
    changeable: true,
  },
  {
    what: 'an issue comment under the BENCHMARK mode (the mode narrows it)',
    call: bash('gh issue comment 3 -b hi'),
    mode: 'BENCHMARK',
    verdict: 'DENY',
    capability: 'forge.issue.comment',
    code: 'ADMIN_DENIED',
    tier: 'none',
    changeable: true,
  },
  // ---- HUMAN_APPROVAL_REQUIRED: an ASK. A human approves THIS operation
  {
    what: 'a download',
    call: bash('curl https://example.com'),
    verdict: 'ASK',
    capability: 'command.network-tool',
    code: 'HUMAN_APPROVAL_REQUIRED',
    tier: 'none',
    changeable: true,
  },
  {
    what: 'an issue comment',
    call: bash('gh issue comment 3 -b hi'),
    verdict: 'ASK',
    capability: 'forge.issue.comment',
    code: 'HUMAN_APPROVAL_REQUIRED',
    tier: 'none',
    changeable: false /* external: the ceiling is ASK */,
  },
  {
    what: 'a hard reset',
    call: bash('git reset --hard HEAD~1'),
    verdict: 'ASK',
    capability: 'git.local.reset',
    code: 'HUMAN_APPROVAL_REQUIRED',
    tier: 'none',
    changeable: true,
  },
  {
    what: 'privilege escalation',
    call: bash('sudo ls'),
    verdict: 'ASK',
    capability: 'command.privileged',
    code: 'HUMAN_APPROVAL_REQUIRED',
    tier: 'none',
    changeable: true,
  },
  {
    what: 'a read outside the workspace',
    call: read('/etc/hosts'),
    verdict: 'ASK',
    capability: 'fs.outside-workspace.read',
    code: 'HUMAN_APPROVAL_REQUIRED',
    tier: 'none',
    changeable: false,
  },
  {
    what: 'a send to a host nobody classified',
    call: bash('curl -X POST https://api.prod.example.com/x -d a=b'),
    verdict: 'ASK',
    capability: 'network.external-write',
    code: 'HUMAN_APPROVAL_REQUIRED',
    tier: 'none',
    changeable: false,
  },
  {
    what: 'a tool the evaluator does not model',
    call: { tool: 'Frobnicate', input: {} },
    verdict: 'ASK',
    capability: 'command.unknown',
    code: 'HUMAN_APPROVAL_REQUIRED',
    tier: 'none',
    changeable: false,
  },
  // ---- SCOPE_DENIED: outside the governed boundary or a protected path, with no policy that enables it
  {
    what: 'writing the host hook configuration',
    call: write('$WS/.claude/settings.json'),
    verdict: 'DENY',
    capability: 'fs.hook-config.write',
    code: 'SCOPE_DENIED',
    tier: 'none',
    changeable: true /* the EGO_MAINTENANCE mode releases it */,
  },
  {
    what: 'writing a secret-bearing environment file',
    call: write('$WS/.env'),
    verdict: 'DENY',
    capability: 'fs.env-file.write',
    code: 'SCOPE_DENIED',
    tier: 'none',
    changeable: false,
  },
  {
    what: 'reading a credential store',
    call: read('~/.aws/credentials'),
    verdict: 'DENY',
    capability: 'fs.credential-store.read',
    code: 'SCOPE_DENIED',
    tier: 'none',
    changeable: false,
  },
  {
    what: 'editing the control plane',
    call: write('$WS/control-plane/permissions/matchers.md'),
    verdict: 'DENY',
    capability: 'ego.control-plane.edit',
    code: 'SCOPE_DENIED',
    tier: 'none',
    changeable: true /* the EGO_MAINTENANCE mode releases it */,
  },
  {
    what: 'a cluster that is named but not a declared local target',
    call: bash('kubectl --context my-new-cluster apply -f x.yaml'),
    verdict: 'DENY',
    capability: 'k8s.nonlocal.mutate',
    code: 'SCOPE_DENIED',
    tier: 'none',
    changeable: false,
  },
  {
    what: 'environment injection into a governed command',
    call: bash('LD_PRELOAD=/tmp/x.so ls'),
    verdict: 'DENY',
    capability: 'command.env-inject',
    code: 'SCOPE_DENIED',
    tier: 'none',
    changeable: false,
  },
  {
    what: 'a web fetch under HIGH_ASSURANCE',
    call: { tool: 'WebFetch', input: { url: 'https://example.com' } },
    profile: 'HIGH_ASSURANCE',
    verdict: 'DENY',
    capability: 'network.public-read',
    code: 'ADMIN_DENIED',
    tier: 'none',
    changeable: true,
  },
  // ---- TARGET_UNCLASSIFIED: where the effect lands could not be resolved
  {
    what: 'a Kubernetes apply with the ambient context',
    call: bash('kubectl apply -f k8s/'),
    verdict: 'ASK',
    capability: 'k8s.target.unclassified',
    code: 'TARGET_UNCLASSIFIED',
    tier: 'none',
    changeable: false,
  },
  {
    what: 'a database statement against an environment variable',
    call: bash("psql $DATABASE_URL -c 'delete from t'"),
    verdict: 'ASK',
    capability: 'db.target.unclassified',
    code: 'TARGET_UNCLASSIFIED',
    tier: 'none',
    changeable: false,
  },
  {
    what: 'a container engine chosen by a variable',
    call: bash('docker -H $H run x'),
    verdict: 'ASK',
    capability: 'container.target.unclassified',
    code: 'TARGET_UNCLASSIFIED',
    tier: 'none',
    changeable: false,
  },
  {
    what: 'an MCP tool whose server nothing resolves',
    call: { tool: 'mcp__github__create_issue', input: {} },
    verdict: 'DENY',
    capability: 'mcp.unknown',
    code: 'TARGET_UNCLASSIFIED',
    tier: 'none',
    changeable: false,
  },
];

function evalCase(c: Case): Evaluation {
  const ctx: EvaluationContext = {
    profile: c.profile ?? 'STANDARD',
    mode: c.mode ?? 'NORMAL_DELIVERY',
    repoRoots: [WS],
    cwd: WS,
  };
  return evaluate(table, ctx, c.call);
}

test('B2 every capability class reached through the evaluator yields the right code, rule source and configurability', () => {
  const byCode = new Map<string, number>();
  for (const c of CASES) {
    const r = evalCase(c) as Evaluation & {
      code?: string;
      rule?: { source: string; changeable: boolean; changeBy: string };
    };
    const label = `${c.what} [${c.code}]`;
    assert.equal(r.verdict, c.verdict, `${label}: verdict`);
    assert.equal(
      r.decisive?.capability ?? (r.hits.length === 0 ? 'command.unknown' : undefined),
      c.capability,
      `${label}: capability`,
    );
    assert.equal(r.code, c.code, `${label}: code (${r.reason})`);
    assert.ok(r.reason.startsWith(`${c.code}: `), `${label}: the reason leads with the code (${r.reason})`);
    assert.match(r.reason, /Rule source: \S/, `${label}: rule source`);
    assert.match(
      r.reason,
      c.changeable ? /Configuration can change it: \S/ : /Configuration cannot change it: \S/,
      `${label}: configurability (${r.reason})`,
    );
    assert.ok(r.rule && r.rule.source.length > 3 && r.rule.changeBy.length > 3, `${label}: structured rule`);
    assert.equal(r.rule!.changeable, c.changeable, `${label}: structured configurability`);
    // the tier is named in the canonical words, never in the old ones
    if (c.tier === 'HARD_LOCK') assert.match(r.reason, /HARD_LOCK/, label);
    if (c.tier === 'ADMIN_GOVERNED') assert.match(r.reason, /ADMIN_GOVERNED/, label);
    assert.doesNotMatch(r.reason, LEGACY_NAME, label);
    byCode.set(c.code, (byCode.get(c.code) ?? 0) + 1);
  }
  // each live code is exercised through more than one capability class
  for (const code of [
    'HARD_LOCKED',
    'ADMIN_DENIED',
    'HUMAN_APPROVAL_REQUIRED',
    'SCOPE_DENIED',
    'TARGET_UNCLASSIFIED',
  ])
    assert.ok((byCode.get(code) ?? 0) >= 3, `${code} is covered by at least three capability classes`);
});

test('B3 an ALLOW carries no code; a refusal that is not a capability (apply_patch) still does', () => {
  const ctx: EvaluationContext = { profile: 'STANDARD', mode: 'NORMAL_DELIVERY', repoRoots: [WS], cwd: WS };
  const ok = evaluate(table, ctx, bash('echo hi')) as Evaluation & { code?: string };
  assert.equal(ok.verdict, 'ALLOW');
  assert.equal(ok.code, undefined);
  const patch = evaluate(table, ctx, {
    tool: 'apply_patch',
    input: { command: 'not a patch' },
  }) as Evaluation & { code?: string };
  assert.equal(patch.verdict, 'DENY');
  assert.equal(patch.code, 'SCOPE_DENIED');
  assert.match(patch.reason, /Rule source: /);
  assert.match(patch.reason, /Configuration (can|cannot) change it: /);
});

test('B4 a mapped code is a function of the tier, never of the spelling: every neighbour of a case keeps its code', () => {
  // five neighbouring spellings per tier, each a different path into the same capability class
  const neighbours: Array<[string, string]> = [
    ['HARD_LOCKED', 'kubectl --namespace prod --context kind-dev delete -f x.yaml'],
    ['HARD_LOCKED', 'CTX=prod; kubectl --context $CTX apply -f x.yaml'],
    ['HARD_LOCKED', 'bash -c "git push --no-verify origin main"'],
    ['HARD_LOCKED', 'echo $(git push --no-verify)'],
    ['HARD_LOCKED', 'git commit --no-verify -m x'],
    ['ADMIN_DENIED', 'bash -c "git push origin main"'],
    ['ADMIN_DENIED', 'git -C . push origin HEAD:main'],
    ['ADMIN_DENIED', 'FOO=1 git push origin main'],
    ['ADMIN_DENIED', 'gh -R o/r pr create --fill'],
    ['ADMIN_DENIED', 'gh api -X DELETE repos/o/r'],
    ['TARGET_UNCLASSIFIED', 'kubectl delete -f k8s/'],
    ['TARGET_UNCLASSIFIED', 'helm upgrade app ./chart'],
    ['TARGET_UNCLASSIFIED', 'mysql -h $DB -e "drop table t"'],
    ['TARGET_UNCLASSIFIED', 'kubectl --context="$(cat ctx)" apply -f x'],
    ['TARGET_UNCLASSIFIED', 'kubectl config use-context kind-dev && kubectl apply -f x.yaml'],
  ];
  const ctx: EvaluationContext = { profile: 'STANDARD', mode: 'NORMAL_DELIVERY', repoRoots: [WS], cwd: WS };
  for (const [code, cmd] of neighbours) {
    const r = evaluate(table, ctx, bash(cmd)) as Evaluation & { code?: string };
    assert.notEqual(r.verdict, 'ALLOW', cmd);
    assert.equal(r.code, code, `${cmd} → ${r.reason}`);
  }
});

test('B5 no refusal in the regression corpus lacks a code, a rule source or a configurability statement', () => {
  const ctx: EvaluationContext = { profile: 'STANDARD', mode: 'NORMAL_DELIVERY', repoRoots: [WS], cwd: WS };
  let refusals = 0;
  const bad: string[] = [];
  for (const cls of SEMANTIC_CLASSES) {
    const dir = cls.files ? workspace({ ...cls.files }) : WS;
    // every third spelling of every class: the evaluator costs ~50ms a case, and the mapping is a function of the
    // decision, so breadth across classes matters more than depth within one
    for (const cmd of cls.cases.filter((_, i) => i % 3 === 0)) {
      const r = evaluate(table, { ...ctx, repoRoots: [dir], cwd: dir }, bash(cmd)) as Evaluation & {
        code?: string;
        rule?: unknown;
      };
      if (r.verdict === 'ALLOW') {
        if (r.code !== undefined) bad.push(`ALLOW with a code: ${cmd}`);
        continue;
      }
      refusals++;
      if (!r.code || !ALL_CODES.includes(r.code)) bad.push(`no code: ${cmd}`);
      else if (!r.reason.startsWith(`${r.code}: `)) bad.push(`code not leading: ${cmd}`);
      if (!/Rule source: \S/.test(r.reason)) bad.push(`no rule source: ${cmd}`);
      if (!/Configuration (can|cannot) change it: \S/.test(r.reason)) bad.push(`no configurability: ${cmd}`);
      if (!r.rule) bad.push(`no structured rule: ${cmd}`);
    }
  }
  assert.ok(refusals > 100, `the sweep saw ${refusals} refusals`);
  assert.deepEqual(bad.slice(0, 10), []);
});

test('B6 the hook output carries the code, in both host dialects', () => {
  const p = project();
  const deny = handleHook(pre(p.root, 'git push --no-verify origin main'), p.rt) as HookDecision & {
    code?: string;
  };
  assert.equal(deny.action, 'deny');
  assert.equal(deny.code, 'HARD_LOCKED');
  assert.match(deny.reason ?? '', /HARD_LOCKED/);
  assert.match(deny.userMessage ?? '', /HARD_LOCKED/, 'the message the human sees names the code too');
  const cc = JSON.parse(renderClaudeCodeOutput(deny).stdout) as {
    systemMessage?: string;
    hookSpecificOutput: { permissionDecisionReason: string };
  };
  assert.match(cc.hookSpecificOutput.permissionDecisionReason, /HARD_LOCKED/);
  assert.match(cc.hookSpecificOutput.permissionDecisionReason, /Rule source: /);
  assert.match(cc.hookSpecificOutput.permissionDecisionReason, /Configuration cannot change it/);
  const cx = JSON.parse(renderCodexOutput(deny).stdout) as { reason: string };
  assert.match(cx.reason, /HARD_LOCKED/);
  assert.match(cx.reason, /Configuration cannot change it/);
  for (const [cmd, code] of [
    ['git push origin main', 'ADMIN_DENIED'],
    ['gh issue comment 3 -b hi', 'HUMAN_APPROVAL_REQUIRED'],
    ['kubectl apply -f k8s/', 'TARGET_UNCLASSIFIED'],
  ] as const) {
    const d = handleHook(pre(p.root, cmd), p.rt) as HookDecision & { code?: string };
    assert.equal(d.code, code, cmd);
    assert.match(
      JSON.parse(renderClaudeCodeOutput(d).stdout).hookSpecificOutput.permissionDecisionReason,
      new RegExp(code),
      cmd,
    );
    assert.match(JSON.parse(renderCodexOutput(d).stdout).reason, new RegExp(code), `codex ${cmd}`);
  }
  const protectedPath = handleHook(
    hookEv(p.root, 'PreToolUse', {
      tool: { name: 'Write', input: { file_path: join(p.root, '.claude', 'settings.json') } },
    }),
    p.rt,
  ) as HookDecision & { code?: string };
  assert.equal(protectedPath.code, 'SCOPE_DENIED');
  assert.equal(handleHook(pre(p.root, 'echo hi'), p.rt).action, 'allow');
  assert.equal((handleHook(pre(p.root, 'echo hi'), p.rt) as { code?: string }).code, undefined);
  // the dialect is the second reader: a decision that carries a code but whose text forgot it is still rendered with it
  const bare: HookDecision & { code: string } = {
    event: 'PreToolUse',
    action: 'deny',
    reason: 'plain text',
    code: 'POLICY_INVALID',
    exitCode: 2,
  };
  assert.match(
    JSON.parse(renderClaudeCodeOutput(bare).stdout).hookSpecificOutput.permissionDecisionReason,
    /^POLICY_INVALID: plain text/,
  );
  assert.match(JSON.parse(renderCodexOutput(bare).stdout).reason, /^POLICY_INVALID: plain text/);
  // and one that already carries it is not decorated twice
  const once = JSON.parse(renderClaudeCodeOutput(deny).stdout).hookSpecificOutput
    .permissionDecisionReason as string;
  assert.equal((once.match(/HARD_LOCKED/g) ?? []).length, 1);
});

test('B7 other refusals the hook takes are coded too: budgets, the retry stop, the missing tool name, pre-promotion', () => {
  const p = project();
  const none = handleHook(hookEv(p.root, 'PreToolUse'), p.rt) as HookDecision & { code?: string };
  assert.equal(none.action, 'deny');
  assert.equal(none.code, 'TARGET_UNCLASSIFIED');
  assert.match(none.reason ?? '', /TARGET_UNCLASSIFIED/);
  const promoted = project('STRICT');
  const prePromo = handleHook(pre(promoted.root, 'git commit -m x'), {
    ...promoted.rt,
    prePromotion: true,
  }) as HookDecision & { code?: string };
  assert.equal(prePromo.action, 'deny');
  assert.equal(prePromo.code, 'POLICY_STALE');
  assert.match(prePromo.reason ?? '', /POLICY_STALE/);
  assert.match(prePromo.reason ?? '', /ego sync/);
});

test('B7b the pre-push hook refuses an agent shell with the same code, rule source and configurability', () => {
  const p = project();
  // (the cache is the one THIS machine wrote: sealed with the key in the project's EGO_HOME, which the git hook is given as well - AUTH-5)
  const seal = sealFor(p.env);
  const agent = { CLAUDECODE: '1', EGO_HOME: p.env['EGO_HOME']! };
  ensurePolicyCache(CP, p.root, SELF(), { seal });
  const refused = runGitHook('pre-push', p.root, agent, '');
  assert.equal(refused.ok, false);
  const text = refused.messages.join('\n');
  assert.match(text, /ADMIN_DENIED: pushes from agent sessions are governed by EGO/);
  assert.match(text, /a human pushes from their own terminal/, 'the remedy it always named');
  assert.match(text, /Rule source: ADMIN_GOVERNED, /);
  assert.match(text, /Configuration can change it: the organization policy layer/);
  // and it agrees with the PreToolUse refusal for the same capability, because both come from one mapping
  const hook = handleHook(pre(p.root, 'git push origin main'), p.rt) as HookDecision & { code?: string };
  assert.equal(hook.code, 'ADMIN_DENIED');
  // an organization that enables the push at ASK lets the shell reach the PreToolUse gate
  orgPolicy(p.root, 'Requires human approval', 'git.remote.push');
  ensurePolicyCache(CP, p.root, SELF(), { acceptWidening: true, seal });
  assert.equal(runGitHook('pre-push', p.root, agent, '').ok, true);
});

test('B8 POLICY_INVALID: a policy that fails to compile refuses with the code, the file and what can fix it', async () => {
  const p = project();
  orgPolicy(p.root, 'Requires human approval', 'no.such.capability');
  assert.throws(() => handleHook(pre(p.root, 'ls'), p.rt), /unknown capability/);
  const out: string[] = [];
  const err: string[] = [];
  const code = await main(['hook', 'claude-code', 'PreToolUse'], {
    cwd: p.root,
    env: p.env,
    stdin: JSON.stringify({
      hook_event_name: 'PreToolUse',
      session_id: 's9',
      cwd: p.root,
      tool_name: 'Bash',
      tool_input: { command: 'ls' },
    }),
    out: (s) => out.push(s),
    err: (s) => err.push(s),
    now: () => '2026-10-01T10:00:00.000Z',
  });
  assert.equal(code, 2, 'a policy that cannot be read fails closed');
  const text = err.join('\n');
  assert.match(text, /POLICY_INVALID/);
  assert.match(text, /policies\/organization\/permissions\.md/, 'it names the file');
  assert.match(text, /no\.such\.capability/);
  assert.match(text, /Rule source: /);
  assert.match(text, /Configuration can change it: /);
  // a syntactically broken control-plane edit through the CLI (not a hook) gets the same treatment
  const cap = await main(['capabilities'], {
    cwd: p.root,
    env: p.env,
    stdin: '',
    out: () => undefined,
    err: (s) => err.push(s),
    now: () => '2026-10-01T10:00:00.000Z',
  });
  assert.equal(cap, 2);
  assert.match(err.join('\n'), /POLICY_INVALID/);
});

test('B9 POLICY_STALE: a pending widening is named at SessionStart, in doctor and in check', async () => {
  const p = project();
  orgPolicy(p.root, 'Requires human approval', 'forge.pr.create');
  const start = handleHook(hookEv(p.root, 'SessionStart', { source: 'startup' }), p.rt);
  assert.match(start.context ?? '', /POLICY_STALE/);
  assert.match(start.context ?? '', /ego init/);
  assert.match(start.context ?? '', /forge\.pr\.create/);
  // not applied: the push is still refused, the pull request still refused
  assert.equal(handleHook(pre(p.root, 'gh pr create --fill'), p.rt).action, 'deny');
  const doctor = formatDoctor(
    runDoctor({ cwd: p.root, env: p.env, now: () => '2026-10-01T10:00:00.000Z', offline: true }),
  );
  assert.match(doctor, /pending widening: POLICY_STALE: /);
  const check = runCheck(p.root).items.find((i) => i.name === 'policy cache')!;
  assert.match(check.detail, /^POLICY_STALE: /);
  // an edited layer file and a cache from another runtime are stale in the same words
  const q = project();
  ensurePolicyCache(CP, q.root, SELF());
  const path = join(q.root, POLICY_CACHE_RELATIVE);
  const cache = JSON.parse(readFileSync(path, 'utf8')) as { runtimeSha256: string };
  writeFileSync(path, JSON.stringify({ ...cache, runtimeSha256: 'd'.repeat(64) }));
  const { formatFreshness } = await import('../src/policy/cache.ts');
  const stale = formatFreshness(policyCacheFreshness(CP, q.root, SELF()));
  assert.match(stale, /^POLICY_STALE: .*compiled by runtime/);
  assert.match(stale, /Rule source: /);
  assert.match(stale, /Configuration can change it: /);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * C. TERMINOLOGY: doctor, capabilities and explain say the same five things, derived from the table
 * ------------------------------------------------------------------------------------------------------------- */

test('C1 the per-capability view is derived from the table: effect class, tier, verdict, ceiling, source, target rule', async () => {
  const { describeCapabilities, describeCapability } = await describeMod();
  const views = describeCapabilities(table, 'STANDARD', 'NORMAL_DELIVERY');
  assert.equal(views.length, Object.keys(table.capabilities).length, 'every capability, none hand-picked');
  for (const v of views) {
    const c = table.capabilities[v.id]!;
    assert.equal(
      v.effectClass,
      c.effect === 'local' ? 'LOCAL_WORKSPACE' : 'EXTERNAL_EFFECT',
      `${v.id} effect class`,
    );
    assert.equal(
      v.lockTier,
      c.lock === 'absolute' ? 'HARD_LOCK' : c.lock === 'admin-governed' ? 'ADMIN_GOVERNED' : 'none',
      `${v.id} tier`,
    );
    assert.equal(v.verdict, table.profiles['STANDARD']!.modes['NORMAL_DELIVERY']![v.id], `${v.id} verdict`);
    assert.ok(['ALLOW', 'ASK', 'DENY'].includes(v.ceiling), `${v.id} ceiling`);
    // the ceiling is never narrower than what is in force
    const rank = { ALLOW: 0, ASK: 1, DENY: 2 } as const;
    assert.ok(
      rank[v.ceiling] <= rank[v.verdict],
      `${v.id}: ceiling ${v.ceiling} is at least as permissive as the verdict ${v.verdict}`,
    );
    assert.ok(v.source.length > 3, `${v.id} source`);
  }
  // the ceiling follows the tier
  for (const id of (table as unknown as { adminGoverned: string[] }).adminGoverned) {
    const v = describeCapability(table, 'STANDARD', 'NORMAL_DELIVERY', id)!;
    assert.equal(v.ceiling, 'ASK', `${id}: an administrable external effect has a standing ceiling of ASK`);
    assert.equal(v.effectClass, 'EXTERNAL_EFFECT');
    assert.equal(v.verdict, 'DENY', 'and DENY until an organization enables it');
  }
  for (const id of table.absoluteDenies)
    assert.equal(describeCapability(table, 'STANDARD', 'NORMAL_DELIVERY', id)!.ceiling, 'DENY', id);
  // an organization that enables a capability changes the source, not the ceiling
  const f = join(mkdtempSync(join(tmpdir(), 'ego-q98v-ceil-')), 'p.md');
  writeFileSync(
    f,
    '---\nschema: ego.capabilities/1\nid: o\nfamily: o\n---\n# O\n\n## Requires human approval\n\n- [x] `forge.pr.create` — a\n',
  );
  const enabled = compileAuthority(loadControlPlane(CP), {
    organization: loadOverlayCapabilities(f, 'organization'),
  });
  const e = describeCapability(enabled, 'STANDARD', 'NORMAL_DELIVERY', 'forge.pr.create')!;
  assert.equal(e.verdict, 'ASK');
  assert.equal(e.ceiling, 'ASK');
  assert.match(e.source, /organization/);
  // a narrowing says whose it is
  const net = describeCapability(table, 'HIGH_ASSURANCE', 'NORMAL_DELIVERY', 'command.network-tool')!;
  assert.equal(net.verdict, 'DENY');
  assert.match(net.source, /profile HIGH_ASSURANCE/);
  assert.match(
    describeCapability(table, 'STANDARD', 'BENCHMARK', 'forge.issue.comment')!.source,
    /mode BENCHMARK/,
  );
});

test('C2 a capability that depends on a target prints the classification rule, derived from the resolver table', async () => {
  const { describeCapabilities } = await describeMod();
  const { targetDependentCapabilities } = await import('../src/authority/evaluate.ts');
  const views = describeCapabilities(table, 'STANDARD', 'NORMAL_DELIVERY');
  const withRule = views.filter((v) => v.targetRule !== undefined).map((v) => v.id);
  assert.ok(withRule.length >= 15, `${withRule.length} target-dependent capabilities`);
  assert.deepEqual(
    [...withRule].sort(),
    [...targetDependentCapabilities(table)].sort(),
    'the view and the resolver read one table',
  );
  for (const id of [
    'k8s.local.apply',
    'k8s.local.delete',
    'db.local.query',
    'db.local.migrate',
    'container.run',
    'production.cloud.mutate',
    'k8s.nonlocal.mutate',
    'db.target.unclassified',
  ])
    assert.ok(withRule.includes(id), id);
  assert.ok(!withRule.includes('fs.repo.read') && !withRule.includes('forge.pr.create'));
  const k8s = views.find((v) => v.id === 'k8s.local.apply')!.targetRule!;
  assert.match(k8s, /k8s_local_contexts/, 'it names the list that declares a local target');
  assert.match(k8s, /local-targets\.md/);
  assert.match(k8s, /production\.k8s\.mutate/);
  assert.match(k8s, /k8s\.nonlocal\.mutate/);
  assert.match(k8s, /k8s\.target\.unclassified/);
  assert.match(views.find((v) => v.id === 'db.local.query')!.targetRule!, /db_local_hosts/);
  assert.match(views.find((v) => v.id === 'db.target.unclassified')!.targetRule!, /UNCLASSIFIED/);
});

test('C3 `ego capabilities`, `ego explain capability` and `ego doctor` print the vocabulary', async () => {
  const p = project('STANDARD');
  const caps = await cli(p, ['capabilities']);
  assert.equal(caps.code, 0, caps.err);
  const row = (id: string): string =>
    caps.out
      .split('\n')
      .find(
        (l) => new RegExp(`\\b${id.replaceAll('.', '\\.')}\\b`).test(l) && /^(ALLOW|ASK |DENY)/.test(l),
      ) ?? '';
  assert.match(row('forge.pr.create'), /^DENY/);
  assert.match(row('forge.pr.create'), /EXTERNAL_EFFECT/);
  assert.match(row('forge.pr.create'), /ADMIN_GOVERNED/);
  assert.match(row('forge.pr.create'), /ceiling ASK/);
  assert.match(row('forge.pr.create'), /admin-governed/, 'the source layer');
  assert.match(row('fs.repo.read'), /LOCAL_WORKSPACE/);
  assert.match(row('fs.repo.read'), /ceiling ALLOW/);
  assert.match(row('production.deploy'), /HARD_LOCK/);
  assert.match(row('production.deploy'), /ceiling DENY/);
  assert.match(caps.out, /target: .*k8s_local_contexts/, 'a target-dependent capability prints its rule');
  assert.doesNotMatch(caps.out, LEGACY_NAME);
  assert.doesNotMatch(caps.out, /\[(absolute|admin-governed)\]/, 'the internal keys are not the label');

  const ex = await cli(p, ['explain', 'capability', 'forge.pr.create']);
  assert.equal(ex.code, 0, ex.err);
  assert.match(ex.out, /effect class EXTERNAL_EFFECT/);
  assert.match(ex.out, /lock tier ADMIN_GOVERNED/);
  assert.match(ex.out, /effective DENY/);
  assert.match(ex.out, /ceiling ASK/);
  assert.match(ex.out, /source admin-governed/);
  assert.match(ex.out, /ADMIN_GOVERNED capability: only the organization policy layer/);
  assert.match(ex.out, /TASK_APPROVAL/, 'the bounded approval is named');
  assert.doesNotMatch(ex.out, LEGACY_NAME);
  const hard = await cli(p, ['explain', 'capability', 'production.deploy']);
  assert.match(hard.out, /lock tier HARD_LOCK/);
  assert.match(hard.out, /HARD_LOCK capability \(an absolute core deny\): no organization policy/);
  const tgt = await cli(p, ['explain', 'capability', 'k8s.local.apply']);
  assert.match(tgt.out, /effect class LOCAL_WORKSPACE/);
  assert.match(tgt.out, /target rule: .*k8s_local_contexts/);

  // doctor prints the governed surface; --capabilities prints every capability
  const lines = runDoctor({
    cwd: p.root,
    env: p.env,
    now: () => '2026-10-01T10:00:00.000Z',
    offline: true,
  }).lines;
  const auth = lines.filter((l) => l.section === 'authority');
  assert.ok(auth.length >= 20, `${auth.length} authority lines`);
  const prCreate = auth.find((l) => l.item === 'forge.pr.create')!;
  assert.ok(prCreate, 'an ADMIN_GOVERNED capability has its own line');
  assert.match(prCreate.detail, /EXTERNAL_EFFECT/);
  assert.match(prCreate.detail, /ADMIN_GOVERNED/);
  assert.match(prCreate.detail, /ceiling ASK/);
  const k8sGroup = auth.find((l) => l.item === 'target-dependent (k8s)')!;
  assert.ok(k8sGroup, 'the target-dependent capabilities are grouped by the kind of target');
  assert.match(k8sGroup.detail, /k8s\.local\.apply/);
  assert.match(k8sGroup.detail, /k8s_local_contexts/);
  assert.ok(!auth.some((l) => l.item === 'fs.repo.read'), 'the default does not list every capability');
  const summary = auth.find((l) => l.item === 'capability matrix')!;
  assert.match(summary.detail, /HARD_LOCK/);
  assert.match(summary.detail, /ADMIN_GOVERNED/);
  assert.match(summary.detail, /LOCAL_WORKSPACE/);
  assert.match(summary.detail, /EXTERNAL_EFFECT/);
  assert.doesNotMatch(formatDoctor({ ok: true, lines, projectRoot: p.root }), LEGACY_NAME);
  const all = await cli(p, ['doctor', '--capabilities']);
  assert.ok(
    all.out.split('\n').filter((l) => /\b(LOCAL_WORKSPACE|EXTERNAL_EFFECT)\b/.test(l)).length >=
      Object.keys(table.capabilities).length,
  );
});

test('C4 the SessionStart text and the generated root instructions use the canonical tiers', () => {
  const p = project();
  const start = handleHook(hookEv(p.root, 'SessionStart', { source: 'startup' }), p.rt);
  const text = start.context ?? '';
  assert.match(text, /HARD_LOCK/);
  assert.match(text, /ADMIN_GOVERNED/);
  assert.doesNotMatch(text, LEGACY_NAME);
  assert.doesNotMatch(text, /absolute denies/);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * D. `ego authority diff`: a reconfiguration is reviewable, and a widening can never be silent
 * ------------------------------------------------------------------------------------------------------------- */

test('D1 `ego authority diff` prints the classified changes and marks every widening', async () => {
  const p = project();
  const seal = sealFor(p.env);
  ensurePolicyCache(CP, p.root, SELF(), { seal });
  orgPolicy(p.root, 'Requires human approval', 'forge.pr.create');
  // before a human accepts it the working-tree file is only a PROPOSAL: current is unchanged, proposed is wider
  const preview = await cli(p, ['authority', 'diff', 'current', 'proposed']);
  assert.equal(preview.code, 0, preview.err);
  assert.match(preview.out, /MAJOR/);
  assert.match(preview.out, /WIDENING/);
  assert.match(preview.out, /forge\.pr\.create/);
  assert.match(preview.out, /DENY -> ASK/);
  // (two of the four modes - BENCHMARK and PRODUCTION_ADVISORY - deny every administrable write even once an organization enables it: AUTH-9)
  assert.match(preview.out, /STANDARD 2\/4/, 'it says in which profile and in how many of its modes');
  assert.match(preview.out, /1 widening/);
  const failing = await cli(p, ['authority', 'diff', 'current', 'proposed', '--fail-on-widening']);
  assert.equal(failing.code, 1, 'a CI step can refuse an unreviewed widening');
  // a human accepts it; core -> current now shows the same change, and the reverse is a narrowing with no WIDENING mark
  ensurePolicyCache(CP, p.root, SELF(), { acceptWidening: true, seal });
  const applied = await cli(p, ['authority', 'diff', 'core', 'current']);
  assert.match(applied.out, /WIDENING.*forge\.pr\.create/);
  const reverse = await cli(p, ['authority', 'diff', 'current', 'core']);
  assert.equal(reverse.code, 0);
  assert.doesNotMatch(reverse.out, /WIDENING/);
  assert.match(reverse.out, /forge\.pr\.create/);
  assert.match(reverse.out, /ASK -> DENY/);
  const same = await cli(p, ['authority', 'diff', 'current', 'current']);
  assert.match(same.out, /no authority changes/);
  assert.equal(same.code, 0);
});

test('D2 the operands may be files, including tables written by an earlier release', async () => {
  const p = project();
  const dir = mkdtempSync(join(tmpdir(), 'ego-q98v-diff-'));
  const old = join(dir, 'old-policy.json');
  const cache = ensurePolicyCache(CP, p.root, SELF()).cache;
  // a whole policy cache as the previous release wrote it, and a bare table
  writeFileSync(old, JSON.stringify({ ...cache, table: toLegacy(cache.table) }));
  const bare = join(dir, 'table.json');
  writeFileSync(bare, JSON.stringify(cache.table));
  const same = await cli(p, ['authority', 'diff', old, bare]);
  assert.equal(same.code, 0, same.err);
  assert.match(same.out, /no authority changes/, 'the rename alone is not an authority change');
  const against = await cli(p, ['authority', 'diff', old, 'current']);
  assert.match(against.out, /no authority changes/);
  // a table that loses a protection is a widening in the old table's own words
  const weaker = structuredClone(cache.table);
  weaker.profiles['STANDARD']!.modes['NORMAL_DELIVERY']!['git.remote.push'] = 'ASK';
  const weakFile = join(dir, 'weaker.json');
  writeFileSync(weakFile, JSON.stringify(weaker));
  const w = await cli(p, ['authority', 'diff', bare, weakFile]);
  assert.match(w.out, /WIDENING.*git\.remote\.push.*DENY -> ASK/);
});

test('D3 `ego authority diff` fails with a usage line, never with a guess', async () => {
  const p = project();
  const none = await cli(p, ['authority']);
  assert.equal(none.code, 2);
  assert.match(none.err, /usage: ego authority diff <old> <new>/);
  const one = await cli(p, ['authority', 'diff', 'core']);
  assert.equal(one.code, 2);
  assert.match(one.err, /usage: ego authority diff <old> <new>/);
  const missing = await cli(p, ['authority', 'diff', 'core', join(tmpdir(), 'ego-q98v-no-such-file.json')]);
  assert.equal(missing.code, 2);
  assert.match(missing.err, /cannot read/);
  const dir = mkdtempSync(join(tmpdir(), 'ego-q98v-junk-'));
  writeFileSync(join(dir, 'junk.json'), '{"not":"a table"}');
  const junk = await cli(p, ['authority', 'diff', 'core', join(dir, 'junk.json')]);
  assert.equal(junk.code, 2);
  assert.match(junk.err, /not an authority table/);
  const help = await cli(p, ['help']);
  assert.match(help.out, /authority/, 'help lists the command');
});
