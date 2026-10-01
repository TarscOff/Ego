// Q98 LOCAL-DEVELOPMENT TARGET REGISTRY (issue #16 sections 1, 7 and 8; closure audit 2026-10-01, Q98-§7,
// Q98-§7-local-target-registry, Q98-§8, Q98-§11 tests 4/5/6/7/21).
//
// `control-plane/workspace/local-targets.md` said "a project or an organization may add targets it owns" while the
// compiler read exactly one file, so a team's own development cluster or database could never be declared local and
// every operation against it was a refusal. The registry now has three layers (the kernel's authored default, the
// organization's `policies/organization/local-targets.md`, the project's `.harness/local-targets.md`) and these
// tests pin the rules that make a layer safe:
//
//   1. A layer ADDS. It never removes a production marker and it never declares a production-marked name local.
//   2. Declaring a target LOCAL is a WIDENING: it turns a refusal into an allowed operation. So it travels the road
//      every other widening travels - written out of band, never applied from the working tree by a hook, accepted
//      by a human running `ego init`.
//   3. Each declaration answers ONE question for ONE family of tools. A database host a team calls local is not
//      thereby a Docker engine, a cloud endpoint or a network destination.
//   4. What cannot be resolved stays TARGET_UNCLASSIFIED. Nothing here guesses.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { main } from '../../cli/src/main.ts';
import { initProject } from '../src/project/init.ts';
import { addToFrontmatterList } from '../src/project/local-surfaces.ts';
import { evaluate } from '../src/authority/evaluate.ts';
import { diffAuthorityTables, classifyAuthorityChanges } from '../src/authority/compile.ts';
import { ensurePolicyCache, readPolicyCache, type PolicyCache } from '../src/policy/cache.ts';
import { ctx, workspace } from './support/corpus.ts';

const CP = new URL('../../../control-plane/', import.meta.url).pathname;
const SELF = { runtimeSha256: 'q98-local-targets-test', version: '0.0.0-test' };

// EVERY FIXTURE LIVES UNDER ONE PARENT, not directly in the system temp directory: `detectProject` lists the SIBLINGS of
// a repository, so a fixture created straight in $TMPDIR makes each `ego init` stat every temp entry on the machine
// (see the note in support/corpus.ts). It took a hundred seconds a test before this.
const PARENT = mkdtempSync(join(tmpdir(), 'ego-q98-root-'));

type Lists = Partial<
  Record<
    'k8s_local_contexts' | 'db_local_hosts' | 'container_local_contexts' | 'production_markers',
    string[]
  >
>;

/** A local-targets layer file, in the markdown-list format the kernel's own file uses. */
const layerFile = (lists: Lists): string =>
  '---\nschema: ego.local-targets/1\n' +
  Object.entries(lists)
    .map(([k, v]) => (v.length ? `${k}:\n${v.map((x) => `  - '${x}'`).join('\n')}\n` : `${k}: []\n`))
    .join('') +
  '---\n# Local targets\n';

const PROJECT_FILE = '.harness/local-targets.md';
const ORG_FILE = 'policies/organization/local-targets.md';

/** What a hook sees: the cache for the working tree as it is now. A widening is clamped, never applied. */
const asHook = (dir: string): PolicyCache => ensurePolicyCache(CP, dir, SELF).cache;
/** What `ego init` from a human terminal does: the same compile with acceptance. */
const asHuman = (dir: string): PolicyCache =>
  ensurePolicyCache(CP, dir, SELF, { acceptWidening: true }).cache;

const judge = (cache: PolicyCache, dir: string, command: string) =>
  evaluate(cache.table, ctx(dir), { tool: 'Bash', input: { command } });
const cap = (cache: PolicyCache, dir: string, command: string): string =>
  judge(cache, dir, command).decisive?.capability ?? '(none)';
const verdictOf = (cache: PolicyCache, dir: string, command: string): string =>
  judge(cache, dir, command).verdict;

/* ------------------------------------------------------------------------------------------------------------- *
 * 1. A DECLARED TARGET IS LOCAL ONLY AFTER A HUMAN ACCEPTS THE FILE (Q98 tests 4 and 5)
 * ------------------------------------------------------------------------------------------------------------- */

test('a project-declared kube context is local only AFTER a human init accepts the file (Q98 test 4)', () => {
  const dir = workspace({ [PROJECT_FILE]: layerFile({ k8s_local_contexts: ['team-dev'] }) });
  const apply = 'kubectl --context team-dev apply -f k8s/dev.yaml';

  // a hook compiling the working tree sees a WIDENING and applies none of it: the context is a named remote cluster
  const pending = asHook(dir);
  assert.equal(cap(pending, dir, apply), 'k8s.nonlocal.mutate');
  assert.equal(verdictOf(pending, dir, apply), 'DENY');
  assert.ok(pending.pendingWidening, 'the declaration is recorded as pending, not dropped');
  assert.match(pending.pendingWidening!.widenings.join('\n'), /team-dev/);
  assert.deepEqual(pending.table.localTargets.declared, [], 'the clamped table carries no declaration');

  // asking again changes nothing: the working tree never takes effect on its own, however often a hook reads it
  assert.equal(cap(asHook(dir), dir, apply), 'k8s.nonlocal.mutate');

  // the human runs `ego init`
  const accepted = asHuman(dir);
  assert.equal(cap(accepted, dir, apply), 'k8s.local.apply');
  assert.equal(verdictOf(accepted, dir, apply), 'ALLOW');
  assert.equal(accepted.pendingWidening, undefined);

  // and from then on a hook reads the accepted table
  const later = asHook(dir);
  assert.equal(cap(later, dir, apply), 'k8s.local.apply');
  assert.deepEqual(
    later.table.localTargets.declared.map((d) => `${d.kind}:${d.name}:${d.layer}:${d.file}`),
    [`kube:team-dev:project:${PROJECT_FILE}`],
  );
});

test('a project-declared database host is local only after acceptance, and then a migration needs no ASK (Q98 test 5)', () => {
  const dir = workspace({ [PROJECT_FILE]: layerFile({ db_local_hosts: ['devdb.corp.internal'] }) });
  const migrate = 'psql -h devdb.corp.internal -d app -c "drop table if exists scratch"';
  assert.equal(cap(asHook(dir), dir, migrate), 'db.nonlocal.mutate');
  const accepted = asHuman(dir);
  // exactly what the same statement against localhost earns: a development database is the agent's working material
  assert.equal(
    cap(accepted, dir, migrate),
    cap(accepted, dir, 'psql -h localhost -d app -c "drop table if exists scratch"'),
  );
  assert.equal(cap(accepted, dir, migrate), 'db.local.query');
  assert.equal(verdictOf(accepted, dir, migrate), 'ALLOW');
  // the URL spelling and the environment spelling are the same question and get the same answer
  for (const cmd of [
    'psql postgres://app:pw@devdb.corp.internal:5432/app -c "delete from scratch"',
    'PGHOST=devdb.corp.internal psql -c "delete from scratch"',
    'mysql --host=devdb.corp.internal -e "delete from scratch"',
    'DATABASE_URL=postgres://devdb.corp.internal/app psql "$DATABASE_URL" -c "delete from scratch"',
  ]) {
    assert.equal(cap(accepted, dir, cmd), 'db.local.query', cmd);
  }
  // a different host, and a host that merely CONTAINS the declared one, are still somebody else's database
  for (const cmd of [
    'psql -h other.corp.internal -c "delete from t"',
    'psql -h devdb.corp.internal.evil.test -c "delete from t"',
    'psql -h xdevdb.corp.internal -c "delete from t"',
  ]) {
    assert.equal(cap(accepted, dir, cmd), 'db.nonlocal.mutate', cmd);
  }
});

test('the organization layer travels the same road, and its file is a protected path for an agent', () => {
  const dir = workspace({ [ORG_FILE]: layerFile({ k8s_local_contexts: ['acme-sandbox-*'] }) });
  const apply = 'kubectl --context acme-sandbox-eu apply -f a.yaml';
  assert.equal(cap(asHook(dir), dir, apply), 'k8s.nonlocal.mutate');
  const accepted = asHuman(dir);
  assert.equal(cap(accepted, dir, apply), 'k8s.local.apply');
  assert.equal(accepted.table.localTargets.declared[0]?.layer, 'organization');
  assert.equal(accepted.table.localTargets.declared[0]?.file, ORG_FILE);

  // an agent cannot write either layer file without a human seeing it: the organization file is DENY like the rest of
  // `policies/organization/**`, the project file asks
  const writeTo = (path: string) =>
    evaluate(accepted.table, ctx(dir), { tool: 'Write', input: { file_path: join(dir, path) } });
  assert.equal(writeTo(ORG_FILE).verdict, 'DENY');
  assert.equal(writeTo(PROJECT_FILE).verdict, 'ASK');
  assert.equal(writeTo(PROJECT_FILE).decisive?.capability, 'ego.local-targets.edit');
  // ...in every spelling a shell has for writing
  for (const cmd of [
    `echo "  - 'x'" >> ${PROJECT_FILE}`,
    `sed -i s/team/other/ ${PROJECT_FILE}`,
    `tee ${PROJECT_FILE} < /dev/null`,
    `cp /dev/null ${PROJECT_FILE}`,
    `mv new.md ${PROJECT_FILE}`,
  ]) {
    const r = judge(accepted, dir, cmd);
    assert.equal(r.verdict, 'ASK', cmd);
    assert.ok(
      r.hits.some((h) => h.capability === 'ego.local-targets.edit'),
      `${cmd}: ${r.hits.map((h) => h.capability).join(', ')}`,
    );
  }
});

test('both layers contribute, the provenance names the layer, and one declaration is one entry', () => {
  const dir = workspace({
    [ORG_FILE]: layerFile({ k8s_local_contexts: ['shared-dev'], db_local_hosts: ['pg.dev.acme.test'] }),
    [PROJECT_FILE]: layerFile({
      k8s_local_contexts: ['shared-dev', 'my-kind'],
      container_local_contexts: ['team-docker'],
    }),
  });
  const t = asHuman(dir).table.localTargets;
  assert.deepEqual(
    t.declared.map((d) => `${d.kind}:${d.name}:${d.layer}`),
    [
      'container:team-docker:project',
      'db:pg.dev.acme.test:organization',
      'kube:my-kind:project',
      'kube:shared-dev:organization',
    ],
    'sorted, and a name both layers declare is attributed to the organization once',
  );
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 2. PRODUCTION WINS (Q98 test 7)
 * ------------------------------------------------------------------------------------------------------------- */

test('a layer naming a production-marked target as local is ignored with a diagnostic, even after acceptance (Q98 test 7)', () => {
  const dir = workspace({
    [PROJECT_FILE]: layerFile({
      k8s_local_contexts: ['acme-prod-eks', 'kind-production', 'team-dev'],
      db_local_hosts: ['prod-db.acme.internal', 'live.db.acme.internal', 'devdb.acme.internal'],
      container_local_contexts: ['prd-docker'],
    }),
  });
  const accepted = asHuman(dir);
  const t = accepted.table.localTargets;
  assert.deepEqual(
    t.declared.map((d) => `${d.kind}:${d.name}`),
    ['db:devdb.acme.internal', 'kube:team-dev'],
    'only the non-production declarations were adopted',
  );
  assert.deepEqual(t.ignored.map((i) => `${i.kind}:${i.name}`).sort(), [
    'container:prd-docker',
    'db:live.db.acme.internal',
    'db:prod-db.acme.internal',
    'kube:acme-prod-eks',
    'kube:kind-production',
  ]);
  for (const i of t.ignored) {
    assert.match(i.reason, /production/i, i.name);
    assert.equal(i.layer, 'project');
    assert.equal(i.file, PROJECT_FILE);
  }
  // production stays production: the absolute denies still apply to every one of them
  assert.equal(
    cap(accepted, dir, 'kubectl --context acme-prod-eks apply -f a.yaml'),
    'production.k8s.mutate',
  );
  assert.equal(cap(accepted, dir, 'kubectl --context kind-production delete ns x'), 'production.k8s.mutate');
  assert.equal(
    cap(accepted, dir, 'psql -h prod-db.acme.internal -c "delete from users"'),
    'production.database.mutate',
  );
  assert.equal(
    cap(accepted, dir, 'psql -h live.db.acme.internal -c "drop table t"'),
    'production.database.mutate',
  );
  assert.equal(cap(accepted, dir, 'docker --context prd-docker run alpine true'), 'production.deploy');
  assert.equal(verdictOf(accepted, dir, 'kubectl --context acme-prod-eks apply -f a.yaml'), 'DENY');
  // ...while the entry that is not production-marked in the same file works
  assert.equal(cap(accepted, dir, 'kubectl --context team-dev apply -f a.yaml'), 'k8s.local.apply');
});

test('a layer cannot remove a production marker, and the markers it adds only narrow (applied at once)', () => {
  const dir = workspace({ [PROJECT_FILE]: layerFile({ production_markers: ['uat'] }) });
  // narrowing is not a widening: no human is needed, a hook applies it
  const cache = asHook(dir);
  assert.equal(cache.pendingWidening, undefined);
  assert.deepEqual(cache.table.localTargets.productionMarkers, ['live', 'prd', 'prod', 'production', 'uat']);
  assert.equal(cap(cache, dir, 'kubectl --context kind-uat apply -f a.yaml'), 'production.k8s.mutate');
  assert.equal(cap(cache, dir, 'kubectl --context kind-dev apply -f a.yaml'), 'k8s.local.apply');
  // an empty list, or a file that lists nothing, removes nothing - the kernel's markers are not the layer's to take away
  for (const body of [layerFile({ production_markers: [] }), layerFile({ k8s_local_contexts: ['x-dev'] })]) {
    const d = workspace({ [PROJECT_FILE]: body });
    const c = asHuman(d);
    for (const m of ['prod', 'production', 'prd', 'live'])
      assert.ok(c.table.localTargets.productionMarkers.includes(m), m);
    assert.equal(cap(c, d, 'kubectl --context kind-prod apply -f a.yaml'), 'production.k8s.mutate');
  }
});

test('a production marker a layer added and later removed is a widening: it needs a human, like a local target', () => {
  const dir = workspace({ [PROJECT_FILE]: layerFile({ production_markers: ['uat'] }) });
  const first = asHuman(dir);
  assert.equal(cap(first, dir, 'kubectl --context uat-cluster apply -f a.yaml'), 'production.k8s.mutate');
  writeFileSync(join(dir, PROJECT_FILE), layerFile({ production_markers: [] }));
  const hook = asHook(dir);
  assert.ok(hook.pendingWidening, 'removing a marker is recorded as pending');
  assert.match(hook.pendingWidening!.widenings.join('\n'), /uat/);
  assert.equal(
    cap(hook, dir, 'kubectl --context uat-cluster apply -f a.yaml'),
    'production.k8s.mutate',
    'still production',
  );
  assert.equal(
    cap(asHuman(dir), dir, 'kubectl --context uat-cluster apply -f a.yaml'),
    'k8s.nonlocal.mutate',
  );
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 3. EACH DECLARATION ANSWERS ONE QUESTION FOR ONE FAMILY OF TOOLS
 * ------------------------------------------------------------------------------------------------------------- */

test('a declaration is local for its own tool family and for nothing else', () => {
  const dir = workspace({
    [PROJECT_FILE]: layerFile({
      k8s_local_contexts: ['team-kube'],
      db_local_hosts: ['devdb.corp.internal'],
      container_local_contexts: ['team-docker'],
    }),
  });
  const c = asHuman(dir);
  // each one is local where it was declared...
  assert.equal(cap(c, dir, 'kubectl --context team-kube apply -f a.yaml'), 'k8s.local.apply');
  assert.equal(cap(c, dir, 'psql -h devdb.corp.internal -c "delete from t"'), 'db.local.query');
  assert.equal(verdictOf(c, dir, 'docker --context team-docker run alpine true'), 'ALLOW');
  // ...and a kube context is not a Docker context, a Docker context is not a kube context
  assert.equal(cap(c, dir, 'docker --context team-kube run alpine true'), 'container.nonlocal.run');
  assert.equal(cap(c, dir, 'kubectl --context team-docker apply -f a.yaml'), 'k8s.nonlocal.mutate');
  assert.equal(cap(c, dir, 'kubectl --context devdb.corp.internal apply -f a.yaml'), 'k8s.nonlocal.mutate');
  // a database host that a team calls local is not the local machine: it is no Docker engine, no cloud endpoint and
  // no network destination, so none of the three de-escalations the machine-local hosts earn reaches it
  assert.equal(
    cap(c, dir, 'docker -H tcp://devdb.corp.internal:2375 run alpine true'),
    'container.nonlocal.run',
  );
  assert.equal(
    cap(c, dir, 'aws --endpoint-url http://devdb.corp.internal iam delete-user --user-name x'),
    'production.cloud.mutate',
  );
  assert.equal(cap(c, dir, 'curl -X POST http://devdb.corp.internal/x -d y'), 'network.external-write');
  assert.equal(
    cap(c, dir, 'kubectl --server https://devdb.corp.internal:6443 apply -f a.yaml'),
    'k8s.nonlocal.mutate',
  );
  // the kernel's own machine-local hosts keep every one of those meanings
  assert.equal(cap(c, dir, 'docker -H tcp://localhost:2375 run alpine true'), 'container.run');
});

test('a production marker in a container or database name reaches the absolute deny however it was declared', () => {
  // the container resolver reads the machine-local hosts BEFORE it looks for a marker, so a layer must never be able
  // to put a marked name on that list: the registry refuses it where the list is built, not where it is read
  const dir = workspace({
    [PROJECT_FILE]: layerFile({
      db_local_hosts: ['prod-engine.acme.internal'],
      container_local_contexts: ['team-prod'],
    }),
  });
  const c = asHuman(dir);
  assert.equal(
    cap(c, dir, 'docker -H tcp://prod-engine.acme.internal:2375 run alpine true'),
    'production.deploy',
  );
  assert.equal(cap(c, dir, 'docker --context team-prod run alpine true'), 'production.deploy');
  assert.deepEqual(c.table.localTargets.declared, []);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 4. NOTHING IS GUESSED (Q98 test 6)
 * ------------------------------------------------------------------------------------------------------------- */

test('an unresolvable target stays TARGET_UNCLASSIFIED however many targets are declared (Q98 test 6)', () => {
  const dir = workspace({
    [PROJECT_FILE]: layerFile({ k8s_local_contexts: ['team-dev'], db_local_hosts: ['devdb.corp.internal'] }),
  });
  const c = asHuman(dir);
  for (const [cmd, capability] of [
    ['kubectl apply -f k8s/dev.yaml', 'k8s.target.unclassified'],
    ['kubectl --context "$CTX" delete ns x', 'k8s.target.unclassified'],
    ['kubectl --context $(cat .ctx) apply -f a.yaml', 'k8s.target.unclassified'],
    ['helm uninstall billing', 'k8s.target.unclassified'],
    ['psql $DATABASE_URL -c "delete from users"', 'db.target.unclassified'],
    ['psql -h "$DB_HOST" -c "delete from users"', 'db.target.unclassified'],
  ] as const) {
    const r = judge(c, dir, cmd);
    assert.equal(r.verdict, 'ASK', cmd);
    assert.equal(r.decisive?.capability, capability, cmd);
    assert.match(r.reason, /TARGET_UNCLASSIFIED/, cmd);
  }
  // a kubeconfig the workspace does not own says nothing about where the declared name points, so it is not local
  assert.equal(
    cap(c, dir, 'kubectl --kubeconfig /tmp/other.yaml --context team-dev apply -f a.yaml'),
    'k8s.nonlocal.mutate',
  );
});

test('a pattern broad enough to declare everything local is refused, and so is a name a shell could expand', () => {
  const dir = workspace({
    [PROJECT_FILE]: layerFile({
      k8s_local_contexts: ['*', 'k*', '??', '*-*', 'ok-dev', '$CTX', 'a b', 'x;y', '`id`'],
      db_local_hosts: ['*', '10.*', '*.com', 'db.dev.acme.test', '[::1]'],
    }),
  });
  const t = asHuman(dir).table.localTargets;
  assert.deepEqual(
    t.declared.map((d) => `${d.kind}:${d.name}`),
    ['db:db.dev.acme.test', 'kube:ok-dev'],
  );
  assert.equal(t.ignored.length, 12);
  for (const i of t.ignored)
    assert.match(i.reason, /too broad|not a valid|opaque|metacharacter|already/i, `${i.name}: ${i.reason}`);
  // and nothing became local by accident
  const c = asHuman(dir);
  assert.equal(cap(c, dir, 'kubectl --context some-shared-cluster apply -f a.yaml'), 'k8s.nonlocal.mutate');
  assert.equal(cap(c, dir, 'psql -h anything.example.com -c "drop table t"'), 'db.nonlocal.mutate');
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 5. THE TABLE, ITS HASH AND ITS DIFF
 * ------------------------------------------------------------------------------------------------------------- */

test('the compiled table and its hash carry the merged targets; the order a file lists them in changes nothing', () => {
  const a = workspace({ [PROJECT_FILE]: layerFile({ k8s_local_contexts: ['one-dev', 'two-dev'] }) });
  const b = workspace({ [PROJECT_FILE]: layerFile({ k8s_local_contexts: ['two-dev', 'one-dev'] }) });
  const none = workspace({});
  const ta = asHuman(a).table;
  const tb = asHuman(b).table;
  const tn = asHuman(none).table;
  assert.equal(ta.tableHash, tb.tableHash, 'canonical: file order is not part of the table');
  assert.notEqual(
    ta.tableHash,
    tn.tableHash,
    'a declaration changes the hash a pin and a cache are compared by',
  );
  assert.deepEqual(
    ta.localTargets.declared.map((d) => d.name),
    ['one-dev', 'two-dev'],
  );
  // the hash does not depend on where the checkout is
  assert.ok(!JSON.stringify(ta.localTargets).includes(a));
});

test('removing a declaration narrows at once; the authority diff names a local target as a widening', () => {
  const dir = workspace({ [PROJECT_FILE]: layerFile({ k8s_local_contexts: ['team-dev'] }) });
  const before = asHuman(dir).table;
  const baseline = asHuman(workspace({})).table;
  const changes = diffAuthorityTables(baseline, before);
  const added = changes.filter((c) => c.kind === 'local-target-added');
  assert.equal(added.length, 1);
  assert.match(added[0]!.detail ?? '', /kube context "team-dev".*project.*local-targets\.md/);
  assert.equal(
    classifyAuthorityChanges(changes, before),
    'major',
    'declaring a local target is never a patch',
  );
  // the other direction narrows
  const narrowed = diffAuthorityTables(before, baseline);
  assert.ok(narrowed.some((c) => c.kind === 'local-target-removed'));

  writeFileSync(join(dir, PROJECT_FILE), layerFile({ k8s_local_contexts: [] }));
  const hook = asHook(dir);
  assert.equal(hook.pendingWidening, undefined, 'a narrowing needs no human');
  assert.equal(cap(hook, dir, 'kubectl --context team-dev apply -f a.yaml'), 'k8s.nonlocal.mutate');
});

test('a layer file that is malformed fails closed; one that is absent is simply absent', () => {
  const bad = workspace({
    [PROJECT_FILE]: '---\nschema: ego.local-targets/1\nk8s_local_contexts: nope\n---\n',
  });
  assert.throws(() => asHuman(bad), /k8s_local_contexts/);
  const wrongSchema = workspace({ [PROJECT_FILE]: '---\nschema: ego.permissions/9\n---\n' });
  assert.throws(() => asHuman(wrongSchema), /schema must be ego\.local-targets\/1/);
  const typo = workspace({
    [PROJECT_FILE]: '---\nschema: ego.local-targets/1\nk8s_contexts:\n  - team-dev\n---\n',
  });
  assert.throws(
    () => asHuman(typo),
    /unknown key "k8s_contexts"/,
    'a misspelt key must not be a silent no-op',
  );
  const none = workspace({});
  assert.deepEqual(asHuman(none).table.localTargets.declared, []);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 6. AN UNRELATED REPOSITORY OR PATH IS NOT SILENTLY LOCAL (Q98 test 21)
 * ------------------------------------------------------------------------------------------------------------- */

test('another repository is not this repository: its declarations, its files and its paths are not local (Q98 test 21)', () => {
  const mine = workspace({});
  const theirs = workspace({ [PROJECT_FILE]: layerFile({ k8s_local_contexts: ['their-dev'] }) });
  asHuman(theirs);
  const c = asHuman(mine);
  assert.deepEqual(c.table.localTargets.declared, [], 'a sibling repository declares nothing for this one');
  assert.equal(cap(c, mine, 'kubectl --context their-dev apply -f a.yaml'), 'k8s.nonlocal.mutate');

  // a layer file that is a link to somebody else's file is not read: only a file the repository itself owns counts
  const outside = mkdtempSync(join(PARENT, 'other-'));
  writeFileSync(join(outside, 'local-targets.md'), layerFile({ k8s_local_contexts: ['linked-dev'] }));
  const linked = workspace({});
  mkdirSync(join(linked, '.harness'), { recursive: true });
  symlinkSync(join(outside, 'local-targets.md'), join(linked, PROJECT_FILE));
  const lc = asHuman(linked);
  assert.deepEqual(lc.table.localTargets.declared, []);
  assert.equal(lc.table.localTargets.ignored.length, 1);
  assert.match(
    lc.table.localTargets.ignored[0]!.reason,
    /outside the repository|symbolic link|not a regular file/,
  );
  assert.equal(cap(lc, linked, 'kubectl --context linked-dev apply -f a.yaml'), 'k8s.nonlocal.mutate');

  // the checkout's own kubeconfig is the workspace's; a path outside it is not
  const kinds = [
    'kubectl --kubeconfig /srv/other-repo/kube.conf --context kind-dev apply -f a.yaml',
    'kubectl --kubeconfig ../other-repo/kube.conf --context their-dev apply -f a.yaml',
  ];
  for (const cmd of kinds) assert.notEqual(verdictOf(c, mine, cmd), 'ALLOW', cmd);

  // paths: a repository that is not one of the registered roots is outside the workspace
  const other = '/opt/ego-unrelated-repo';
  const write = (tool: 'Write' | 'Edit', file: string) =>
    evaluate(c.table, ctx(mine), { tool, input: { file_path: file } });
  assert.equal(write('Write', `${other}/src/a.ts`).decisive?.capability, 'fs.outside-workspace.write');
  assert.equal(write('Edit', `${other}/src/a.ts`).verdict, 'DENY');
  assert.equal(
    evaluate(c.table, ctx(mine), { tool: 'Read', input: { file_path: `${other}/src/a.ts` } }).verdict,
    'ASK',
  );
  for (const cmd of [
    `echo x > ${other}/src/a.ts`,
    `touch ${other}/src/a.ts`,
    `cp README.md ${other}/src/`,
    `rm -rf ${other}/src`,
    `git -C ${other} push origin main`,
  ]) {
    assert.equal(verdictOf(c, mine, cmd), 'DENY', cmd);
  }
  for (const cmd of [
    `git -C ${other} commit -m x`,
    `cd ${other} && git commit -m x`,
    `cd ${other} && npm run build`,
  ]) {
    assert.notEqual(verdictOf(c, mine, cmd), 'ALLOW', cmd);
  }
  assert.ok(existsSync(mine));
  assert.ok(readFileSync(join(mine, 'package.json'), 'utf8').length > 0);
});

// keep the compiler honest about the cache the tests above read back
test('the cache round-trips the declared targets', () => {
  const dir = workspace({ [PROJECT_FILE]: layerFile({ k8s_local_contexts: ['team-dev'] }) });
  const written = asHuman(dir);
  const read = readPolicyCache(dir);
  assert.deepEqual(read?.table.localTargets, written.table.localTargets);
  assert.equal(read?.table.tableHash, written.table.tableHash);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 7. `ego init`: DETECT, PROPOSE, ADOPT (issue #16 section 7)
 * ------------------------------------------------------------------------------------------------------------- */

const gitEnv = (): NodeJS.ProcessEnv => {
  const e: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) if (!/^GIT_/.test(k)) e[k] = v;
  return e;
};

/** a human terminal: nothing marks it as an agent shell */
const humanEnv = (home: string, extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv => ({
  PATH: process.env['PATH'],
  HOME: home,
  EGO_HOME: join(home, '.ego'),
  LANG: 'C',
  ...extra,
});

function repo(files: Record<string, string> = {}): string {
  const dir = mkdtempSync(join(PARENT, 'repo-'));
  spawnSync('git', ['init', '-q'], { env: gitEnv(), cwd: dir });
  spawnSync('git', ['config', 'user.email', 't@example.com'], { env: gitEnv(), cwd: dir });
  spawnSync('git', ['config', 'user.name', 't'], { env: gitEnv(), cwd: dir });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'demo', version: '1.0.0' }));
  for (const [name, content] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, name)), { recursive: true });
    writeFileSync(join(dir, name), content);
  }
  spawnSync('git', ['add', '-A'], { env: gitEnv(), cwd: dir });
  spawnSync('git', ['commit', '-qm', 'init'], { env: gitEnv(), cwd: dir });
  return dir;
}

async function ego(
  argv: string[],
  cwd: string,
  env: NodeJS.ProcessEnv,
  stdin = '',
): Promise<{ code: number; out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await main(argv, {
    cwd,
    env,
    stdin,
    out: (s) => out.push(s),
    err: (s) => err.push(s),
    now: () => '2026-10-01T10:00:00.000Z',
  });
  return { code, out: out.join('\n'), err: err.join('\n') };
}

/** the verdict of a command through the real hook entry point, so the cache a hook reads is the one tested */
async function hookVerdict(dir: string, env: NodeJS.ProcessEnv, command: string): Promise<string> {
  const r = await ego(
    ['hook', 'claude-code', 'PreToolUse'],
    dir,
    env,
    JSON.stringify({
      session_id: 'q98',
      cwd: dir,
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command },
    }),
  );
  return JSON.parse(r.out).hookSpecificOutput.permissionDecision as string;
}

const COMPOSE = `services:
  db:
    image: postgres:16
    ports:
      - "127.0.0.1:5432:5432"
  cache:
    image: redis:7
    ports: ["6379:6379"]
  web:
    build: .
    ports:
      - "3000:3000"
`;
const SURFACE_FILES: Record<string, string> = {
  'docker-compose.yml': COMPOSE,
  '.env.example':
    'DATABASE_URL=postgres://app:s3cretpw-do-not-print@db:5432/app\nREDIS_URL=redis://cache:6379\nANALYTICS_DB_HOST=analytics.acme.com\nSTRIPE_KEY=sk_test_x\n',
  'kind-config.yaml': 'kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nname: dev\n',
  'skaffold.yaml':
    'apiVersion: skaffold/v4beta6\nkind: Config\ndeploy:\n  kubeContext: team-dev\nprofiles:\n  - name: release\n    deploy:\n      kubeContext: acme-prod-eks\n',
  Tiltfile: "allow_k8s_contexts('tilt-dev')\n",
  '.devcontainer/devcontainer.json':
    '{\n  // the app container joins the compose network\n  "dockerComposeFile": "../docker-compose.yml",\n  "service": "web",\n  "runServices": ["db", "cache"] /* data stores */\n}\n',
};

test('init DETECTS local-development surfaces from repository files and PROPOSES them; it adopts nothing', async () => {
  const dir = repo(SURFACE_FILES);
  const home = mkdtempSync(join(PARENT, 'home-'));
  const r = await ego(['init'], dir, humanEnv(home));
  assert.equal(r.code, 0, r.out + r.err);
  // what each file revealed
  assert.match(
    r.out,
    /detected: docker-compose\.yml: services db \(postgres:16, localhost:5432\), cache \(redis:7, localhost:6379\)/,
  );
  assert.match(
    r.out,
    /detected: \.env\.example: DATABASE_URL host db, REDIS_URL host cache, ANALYTICS_DB_HOST host analytics\.acme\.com/,
  );
  assert.match(r.out, /detected: kind-config\.yaml: kind cluster dev \(context kind-dev\)/);
  assert.match(r.out, /detected: skaffold\.yaml: kubeContext team-dev, acme-prod-eks/);
  assert.match(r.out, /detected: Tiltfile: allow_k8s_contexts tilt-dev/);
  assert.match(
    r.out,
    /detected: \.devcontainer\/devcontainer\.json: compose-based devcontainer, service web, runs db, cache/,
  );
  // what is already local is said to need nothing; what is not is proposed with the exact command that adopts it
  assert.match(r.out, /already LOCAL_DEV, nothing to adopt: .*db:localhost/);
  assert.match(r.out, /already LOCAL_DEV, nothing to adopt: .*kube:kind-dev/);
  for (const [kind, name] of [
    ['kube', 'team-dev'],
    ['kube', 'tilt-dev'],
    ['db', 'db'],
    ['db', 'cache'],
  ]) {
    assert.match(
      r.out,
      new RegExp(
        `proposed LOCAL_DEV: ${kind}:${name} \\(.*\\) - adopt with: ego init --local-target ${kind}:${name}`,
      ),
    );
  }
  // production is listed as refused, never proposed
  assert.match(r.out, /not proposed: kube:acme-prod-eks \(names production/);
  assert.doesNotMatch(r.out, /proposed LOCAL_DEV: kube:acme-prod-eks/);
  // a host that is somebody's DNS is evidence of nothing local, and a secret in a template is never echoed
  assert.doesNotMatch(r.out, /proposed LOCAL_DEV: db:analytics/);
  assert.doesNotMatch(r.out, /s3cretpw/);
  // a proposal changes nothing
  assert.ok(!existsSync(join(dir, '.harness', 'local-targets.md')));
  assert.equal(await hookVerdict(dir, humanEnv(home), 'kubectl --context team-dev apply -f a.yaml'), 'deny');
  assert.equal(await hookVerdict(dir, humanEnv(home), 'psql -h db -c "delete from t"'), 'deny');
  // and the same printout is not a decision: `--no-local-targets` declines it
  const declined = await ego(['init', '--no-local-targets'], dir, humanEnv(home));
  assert.equal(declined.code, 0, declined.out + declined.err);
  assert.doesNotMatch(declined.out, /proposed LOCAL_DEV|local development surfaces/);
});

test('init --local-target adopts into .harness/local-targets.md, prints the AUTHORITY DIFF, and a hook then allows it', async () => {
  const dir = repo(SURFACE_FILES);
  const home = mkdtempSync(join(PARENT, 'home-'));
  const env = humanEnv(home);
  await ego(['init'], dir, env);
  const r = await ego(['init', '--local-target', 'kube:team-dev', '--local-target=db:db'], dir, env);
  assert.equal(r.code, 0, r.out + r.err);
  assert.match(
    r.out,
    /adopted LOCAL_DEV target\(s\) into \.harness\/local-targets\.md: kube:team-dev, db:db/,
  );
  // the diff names what widened, in the words a person reads
  assert.match(r.out, /AUTHORITY DIFF against the previously accepted table \(major\):/);
  assert.match(
    r.out,
    /WIDENS local-target-added \(kube context "team-dev" declared LOCAL_DEV by the project \(\.harness\/local-targets\.md\)\)/,
  );
  assert.match(r.out, /WIDENS local-target-added \(database host "db" declared LOCAL_DEV by the project/);
  const file = readFileSync(join(dir, '.harness', 'local-targets.md'), 'utf8');
  assert.match(file, /k8s_local_contexts:\n {2}- 'team-dev'\n/);
  assert.match(file, /db_local_hosts:\n {2}- 'db'\n/);
  // the proposal is no longer a proposal
  assert.doesNotMatch(r.out, /proposed LOCAL_DEV: (kube:team-dev|db:db) /);
  // the hook now reads the accepted table
  assert.equal(await hookVerdict(dir, env, 'kubectl --context team-dev apply -f a.yaml'), 'allow');
  assert.equal(await hookVerdict(dir, env, 'psql -h db -c "drop table if exists scratch"'), 'allow');
  assert.equal(await hookVerdict(dir, env, 'kubectl --context some-shared-cluster apply -f a.yaml'), 'deny');
  assert.equal(await hookVerdict(dir, env, 'kubectl --context acme-prod-eks apply -f a.yaml'), 'deny');
  // the same init again changes nothing and prints no diff
  const again = await ego(['init'], dir, env);
  assert.doesNotMatch(again.out, /AUTHORITY DIFF/);
  assert.equal((await ego(['check'], dir, env)).code, 0);
  // and a third target is appended without disturbing the first two or the file's comments
  writeFileSync(
    join(dir, '.harness', 'local-targets.md'),
    file.replace('k8s_local_contexts:\n', '# the team dev cluster\nk8s_local_contexts:\n'),
  );
  const third = await ego(
    ['init', '--local-target', 'kube:other-dev', '--local-target', 'container:team-docker'],
    dir,
    env,
  );
  assert.equal(third.code, 0, third.out + third.err);
  const text = readFileSync(join(dir, '.harness', 'local-targets.md'), 'utf8');
  assert.match(text, /# the team dev cluster\nk8s_local_contexts:\n {2}- 'team-dev'\n {2}- 'other-dev'\n/);
  assert.match(text, /container_local_contexts:\n {2}- 'team-docker'\n/);
  assert.equal(await hookVerdict(dir, env, 'docker --context team-docker run --rm alpine true'), 'allow');
});

test('init refuses --local-target from an agent shell, for a production name, for a bad spelling, and writes nothing', async () => {
  const dir = repo(SURFACE_FILES);
  const home = mkdtempSync(join(PARENT, 'home-'));
  const env = humanEnv(home);
  await ego(['init'], dir, env);
  const before = readFileSync(join(dir, '.harness', 'generated', 'policy.json'), 'utf8');
  const target = join(dir, '.harness', 'local-targets.md');

  // an agent shell, in each spelling the hosts mark one with
  for (const marker of [
    { CLAUDECODE: '1' },
    { CLAUDE_CODE: '1' },
    { CLAUDE_PID: '123' },
    { CODEX_SANDBOX: 'seatbelt' },
    { CODEX_CLI: '1' },
  ]) {
    const r = await ego(['init', '--local-target', 'kube:team-dev'], dir, humanEnv(home, marker));
    assert.equal(r.code, 2, JSON.stringify(marker));
    assert.match(
      r.err,
      /adopting a local development target is a human act from your own terminal, never from an agent shell/,
    );
    assert.ok(!existsSync(target), 'nothing was written');
  }

  // production, whichever way it is spelled, and nothing is written even for the valid one given beside it
  for (const spec of [
    'kube:acme-prod-eks',
    'kube:PRODUCTION',
    'db:prod-db.acme.internal',
    'container:prd-docker',
    'kube:live',
  ]) {
    const r = await ego(['init', '--local-target', 'kube:team-dev', '--local-target', spec], dir, env);
    assert.equal(r.code, 2, spec);
    assert.match(r.err, /refused: .* cannot be adopted as a .* - names production/, spec);
    assert.ok(!existsSync(target), `${spec}: the valid target beside it was not written either`);
  }

  // spellings that are not a target at all
  for (const spec of [
    'team-dev',
    'k8s:team-dev',
    'kube:',
    ':x',
    'kube:$CTX',
    'kube:*',
    'db:*.com',
    'kube:a b',
  ]) {
    const r = await ego(['init', '--local-target', spec], dir, env);
    assert.equal(r.code, 2, spec);
    assert.match(r.err, /--local-target takes <kind>:<name>|cannot be adopted/, spec);
  }
  assert.equal(
    (await ego(['init', '--local-target'], dir, env)).code,
    2,
    'a flag with no value is an error, not a silent decline',
  );
  const both = await ego(['init', '--local-target', 'kube:team-dev', '--no-local-targets'], dir, env);
  assert.equal(both.code, 2);
  assert.match(both.err, /contradict/);

  assert.ok(!existsSync(target));
  assert.equal(
    readFileSync(join(dir, '.harness', 'generated', 'policy.json'), 'utf8'),
    before,
    'the table did not move',
  );
});

test('a name that is already local needs no entry: nothing is written and init says why', async () => {
  const dir = repo({});
  const env = humanEnv(mkdtempSync(join(PARENT, 'home-')));
  await ego(['init'], dir, env);
  const r = await ego(
    ['init', '--local-target', 'kube:kind-dev', '--local-target', 'db:localhost'],
    dir,
    env,
  );
  assert.equal(r.code, 0, r.out + r.err);
  assert.match(r.out, /not written: kube:kind-dev \(already local by default\)/);
  assert.match(r.out, /not written: db:localhost \(already local by default\)/);
  assert.ok(!existsSync(join(dir, '.harness', 'local-targets.md')));
});

test('a layer file edited out of band is pending until a human init, and the human sees the diff they accept', async () => {
  const dir = repo({});
  const home = mkdtempSync(join(PARENT, 'home-'));
  const env = humanEnv(home);
  await ego(['init'], dir, env);
  // the file arrives (an agent write the human allowed, a teammate's commit)
  mkdirSync(join(dir, '.harness'), { recursive: true });
  writeFileSync(join(dir, '.harness', 'local-targets.md'), layerFile({ k8s_local_contexts: ['team-dev'] }));
  assert.equal(
    await hookVerdict(dir, env, 'kubectl --context team-dev apply -f a.yaml'),
    'deny',
    'not applied from the working tree',
  );
  assert.match((await ego(['doctor'], dir, env)).out, /pending widening/);
  assert.equal((await ego(['check'], dir, env)).code, 1);
  // an agent shell cannot accept it
  const agent = await ego(['init'], dir, humanEnv(home, { CLAUDECODE: '1' }));
  assert.match(agent.out, /policy widening NOT applied/);
  assert.equal(await hookVerdict(dir, env, 'kubectl --context team-dev apply -f a.yaml'), 'deny');
  // the human's init accepts it AND says what it accepted
  const human = await ego(['init'], dir, env);
  assert.doesNotMatch(human.out, /policy widening NOT applied/);
  assert.match(human.out, /AUTHORITY DIFF against the previously accepted table \(major\):/);
  assert.match(human.out, /WIDENS local-target-added \(kube context "team-dev"/);
  assert.equal(await hookVerdict(dir, env, 'kubectl --context team-dev apply -f a.yaml'), 'allow');
  // doctor reports the registry, and what it refused
  writeFileSync(
    join(dir, '.harness', 'local-targets.md'),
    layerFile({ k8s_local_contexts: ['team-dev', 'acme-prod-eks'] }),
  );
  const refused = await ego(['init'], dir, env);
  assert.match(
    refused.out,
    /ignored by the local-target registry: kube:acme-prod-eks from the project \(\.harness\/local-targets\.md\) - names production/,
  );
  const doctor = await ego(['doctor'], dir, env);
  assert.match(doctor.out, /local targets: .*1 declared.*team-dev/);
  assert.match(doctor.out, /local targets ignored: .*acme-prod-eks/);
});

test('a human terminal is asked about waiting widenings and a no leaves them pending; nothing needs an answer when there is no terminal', () => {
  const dir = repo({});
  const home = mkdtempSync(join(PARENT, 'home-'));
  const env = humanEnv(home);
  initProject({ cwd: dir, env, offline: true });
  mkdirSync(join(dir, '.harness'), { recursive: true });
  writeFileSync(
    join(dir, '.harness', 'local-targets.md'),
    layerFile({ db_local_hosts: ['devdb.corp.internal'] }),
  );

  // a person says no: the widening stays pending and is shown to them
  const asked: string[][] = [];
  const no = initProject({
    cwd: dir,
    env,
    offline: true,
    confirmWidening: (w) => (asked.push(w), false),
  });
  assert.equal(asked.length, 1);
  assert.match(asked[0]!.join('\n'), /database host "devdb\.corp\.internal"/);
  assert.match(no.notes.join('\n'), /policy widening NOT applied/);
  assert.equal(readPolicyCache(dir)?.table.localTargets.declared.length, 0);
  // ...and declining while asking to adopt another target is refused rather than half done
  assert.throws(
    () =>
      initProject({
        cwd: dir,
        env,
        offline: true,
        localTargets: ['kube:x-dev'],
        confirmWidening: () => false,
      }),
    /declined: widenings are waiting/,
  );
  // a person says yes
  const yes = initProject({ cwd: dir, env, offline: true, confirmWidening: () => true });
  assert.equal(yes.localTargets.authorityDiff?.widenings.length, 1);
  assert.equal(readPolicyCache(dir)?.table.localTargets.declared.length, 1);
  // with nothing waiting nobody is asked
  let calls = 0;
  initProject({ cwd: dir, env, offline: true, confirmWidening: () => (calls++, true) });
  assert.equal(calls, 0);
});

test('detection reads only files inside the repository: not a linked file, not ~/.kube/config, not the environment', async () => {
  const home = mkdtempSync(join(PARENT, 'home-'));
  mkdirSync(join(home, '.kube'), { recursive: true });
  writeFileSync(
    join(home, '.kube', 'config'),
    'apiVersion: v1\ncontexts:\n- name: home-kube-dev\n  context: {cluster: c, user: u}\ncurrent-context: home-kube-dev\n',
  );
  const outside = mkdtempSync(join(PARENT, 'outside-'));
  writeFileSync(join(outside, 'skaffold.yaml'), 'deploy:\n  kubeContext: linked-dev\n');
  const dir = repo({});
  symlinkSync(join(outside, 'skaffold.yaml'), join(dir, 'skaffold.yaml'));
  const r = await ego(
    ['init'],
    dir,
    humanEnv(home, { KUBECONFIG: join(home, '.kube', 'config'), DATABASE_URL: 'postgres://x@envdb/app' }),
  );
  assert.equal(r.code, 0, r.out + r.err);
  assert.doesNotMatch(r.out, /linked-dev|home-kube-dev|envdb/);
  assert.doesNotMatch(r.out, /local development surfaces/);
});

test('what a repository file says is printed as one token of a bounded grammar: no prose, quote, command or control character', async () => {
  const dir = repo({
    'skaffold.yaml':
      'deploy:\n  kubeContext: x-dev\n  kubeContext: "ok\x1b[31m-dev"\n  kubeContext: team dev with spaces\n  kubeContext: $(curl evil)\n',
    Tiltfile: "allow_k8s_contexts(['ok-dev', 'run `curl evil`', \"$(id)\", 'say \\'hi\\' now'])\n",
    'docker-compose.yml':
      'services:\n  "weird service\x1b[2J":\n    image: "postgres\x07 and then some prose"\n',
    '.env.example': 'DATABASE_URL=postgres://u:p@host with spaces/app\nDB_HOST=bad\x1b[0mhost\n',
  });
  const home = mkdtempSync(join(PARENT, 'home-'));
  const r = await ego(['init'], dir, humanEnv(home));
  assert.equal(r.code, 0, r.out + r.err);
  const printed = r.out
    .split('\n')
    .slice(r.out.split('\n').findIndex((l) => l.startsWith('local development surfaces')))
    .filter((l) => /^ {2}(detected|already|proposed|not proposed)/.test(l));
  assert.ok(printed.length > 0);
  for (const line of printed) {
    assert.match(line, /^[ -~]*$/, `printable ASCII only: ${JSON.stringify(line)}`);
    assert.doesNotMatch(line, /[`$'"\\]/, `no quote, backtick, $ or backslash: ${line}`);
  }
  assert.doesNotMatch(r.out, /curl evil|\$\(id\)|with spaces|prose|team dev/);
  assert.match(r.out, /proposed LOCAL_DEV: kube:ok-dev /);
  assert.match(r.out, /proposed LOCAL_DEV: kube:x-dev /);
  // nothing that is not a single token became a proposal
  assert.doesNotMatch(r.out, /proposed LOCAL_DEV: kube:(run|say|team|ok\?)/);
});

test('adding to a layer file keeps its comments and every other entry, in each shape the list can have', () => {
  const add = (src: string, key: string, name: string) => addToFrontmatterList(src, key, name);
  assert.equal(
    add('---\nschema: x\nk8s_local_contexts: []\n---\nbody\n', 'k8s_local_contexts', 'a-dev'),
    "---\nschema: x\nk8s_local_contexts:\n  - 'a-dev'\n---\nbody\n",
  );
  assert.equal(
    add(
      "---\nk8s_local_contexts:\n  # mine\n  - 'one'\n  - two # why\n\nother: 1\n---\n",
      'k8s_local_contexts',
      'three',
    ),
    "---\nk8s_local_contexts:\n  # mine\n  - 'one'\n  - two # why\n  - 'three'\n\nother: 1\n---\n",
  );
  assert.equal(
    add("---\nk8s_local_contexts: [one, 'two']\n---\n", 'k8s_local_contexts', 'x-dev'),
    "---\nk8s_local_contexts:\n  - one\n  - 'two'\n  - 'x-dev'\n---\n",
  );
  assert.equal(
    add('---\nschema: x\n---\n', 'db_local_hosts', 'h.test'),
    "---\nschema: x\ndb_local_hosts:\n  - 'h.test'\n---\n",
  );
  assert.throws(() => add('no frontmatter', 'db_local_hosts', 'x'), /no frontmatter/);
  assert.throws(() => add('---\ndb_local_hosts: nope\n---\n', 'db_local_hosts', 'x'), /not a list/);
});
