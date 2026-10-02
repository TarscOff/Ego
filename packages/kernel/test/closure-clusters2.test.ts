// CLOSURE OF THE CLUSTER, CONTAINER AND PRODUCTION-NAME READERS, WAVE 5 (seven independent reviewers read what the five
// closure waves changed: AUTH-1, K8-01 to K8-06, CT-01 to CT-08, OT-01).
//
// THE CAUSE IN EVERY CASE IS THE ONE THE REPOSITORY KEEPS PAYING FOR: A DIMENSION HAS MORE THAN ONE READER, AND A FIX AT ONE
// SPELLING LEAVES ITS SIBLINGS OPEN.
//
//   - "is this name production" was answered by a token function that wanted a non-alphanumeric boundary after the marker
//     (so `prd1`, `prod1`, `live2`, `prod01` were not production), by two matcher regexes in matchers.md that looked for the
//     letters `prod` anywhere in a context, namespace or kubeconfig (so a namespace called `products` on a kind cluster was an
//     ABSOLUTE deny), and by the database and container resolvers. It is answered once now (control-plane/local-targets.ts,
//     `hasProductionMarker`), and asked of the fields that name a target and of nothing else.
//   - "which engine does this container command talk to" was a list of variables in the resolver, another in the normalizer,
//     and a third nowhere, so `CONTAINER_CONNECTION=production podman run` and the variables that point at a configuration
//     file were no engine at all. The table is containers.ts's, and both readers derive from it.
//   - "what does this verb print" was a flag that said `save`, `history` and `top` were harmless against a production engine
//     while `inspect` and `logs` were not.
//   - "is this path the image's or the host's" was answered by one judge of seven.
//
// Every test below is a property of the ONE reader with the reviewers' spelling and its neighbours. Where the reviewer's
// oracle was a real tool, a bounded seeded differential against it follows, and skips cleanly when the tool is absent.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { evaluate } from '../src/authority/evaluate.ts';
import { ensurePolicyCache, type PolicyCache } from '../src/policy/cache.ts';
import * as LT from '../src/control-plane/local-targets.ts';
import { workspace, verdict, table, ctx } from './support/corpus.ts';

const CP = new URL('../../../control-plane/', import.meta.url).pathname;
const SELF = { runtimeSha256: 'closure-clusters2-test', version: '0.0.0-test' };
// (fixtures are made under one parent, as corpus.ts does: `detectProject` lists the siblings of a repository)
void mkdtempSync(join(tmpdir(), 'ego-clusters2-root-'));

type Expect = 'DENY' | 'ASK' | 'ALLOW' | 'GATED';
type Case = readonly [cmd: string, expect: Expect, files?: Record<string, string>];

const cap = (cmd: string, dir: string): string =>
  evaluate(table, ctx(dir), { tool: 'Bash', input: { command: cmd } }).decisive?.capability ?? '-';

/** Every case is run and every miss is reported at once: the first failure must not hide the rest. */
function run(cases: readonly Case[], common: Record<string, string> = {}): void {
  const misses: string[] = [];
  for (const [cmd, expect, files] of cases) {
    const dir = workspace({ ...common, ...(files ?? {}) });
    const got = verdict(cmd, dir);
    const ok = expect === 'GATED' ? got !== 'ALLOW' : got === expect;
    if (!ok) misses.push(`${expect} expected, ${got} (${cap(cmd, dir)}): ${cmd.replace(/\n/g, '\\n')}`);
  }
  assert.deepEqual(misses, []);
}

/** A project that declares wildcards local, accepted by a human (`ego init`): the registry as it is after a team adopted `aks-*`. */
const LAYER = (lists: Record<string, string[]>): string =>
  '---\nschema: ego.local-targets/1\n' +
  Object.entries(lists)
    .map(([k, v]) => `${k}:\n${v.map((x) => `  - '${x}'`).join('\n')}\n`)
    .join('') +
  '---\n# Local targets\n';
function accepted(lists: Record<string, string[]>): { cache: PolicyCache; dir: string } {
  const dir = workspace({ '.harness/local-targets.md': LAYER(lists) });
  return { cache: ensurePolicyCache(CP, dir, SELF, { acceptWidening: true }).cache, dir };
}
const judge = (a: { cache: PolicyCache; dir: string }, command: string) =>
  evaluate(a.cache.table, ctx(a.dir), { tool: 'Bash', input: { command } });

const MARKERS = table.localTargets.productionMarkers;

/* ------------------------------------------------------------------------------------------------------------- *
 * 1. "IS THIS NAME PRODUCTION" HAS ONE READER (AUTH-1, K8-01)
 * ------------------------------------------------------------------------------------------------------------- */

test('a name is production when a marker is a WORD of it: numbered environments, either order, any separator (AUTH-1)', () => {
  const production = [
    // the reviewer's: a number after the marker made it "not a token"
    'aks-prd1-weu', 'aks-live1-weu', 'team-prd2', 'team-live1', 'db.prod1.eu.acme.test', 'dev-prod1', 'prod01', 'live2', 'prd1', 'prod1',
    // the shapes a name comes in
    'prod', 'production', 'prd', 'live', 'prd-1', 'prod-eu', 'eu-prod', 'eu_prod', 'eu.prod.corp', 'aks-production-weu', 'kind-production',
    'acme-prod-eks', 'prod_eu_1', '1prod', 'eu1prod2', 'PROD-EU', 'Prod', 'LIVE',
    // CamelCase is word boundaries too
    'eksProd', 'ProdEU', 'clusterProd1', 'PRODCluster', 'aksPrdWeu',
    // pre-production is shared and production-like
    'pre-prod', 'preprod', 'preprod1', 'pre-production',
  ];
  const notProduction = [
    // words that merely CONTAIN the letters
    'products', 'product-service', 'product-catalog', 'productivity', 'produce', 'prodigy', 'reproduce', 'reproduction', 'liveness',
    'delivery', 'alive', 'olive', 'oliver', 'lively', 'prodsys', 'kind-reproduce', 'kind-product-catalog', 'k3d-products',
    // local names
    'minikube', 'kind-dev', 'docker-desktop', 'localhost', 'aks-dev-weu', 'team-eu', 'dev-1', 'staging', 'stg1', 'ProductCatalog', 'eksProducts',
  ];
  const bad: string[] = [];
  for (const n of production) if (!LT.hasProductionMarker(n, MARKERS)) bad.push(`${n} should be production`);
  for (const n of notProduction) if (LT.hasProductionMarker(n, MARKERS)) bad.push(`${n} should not be production`);
  assert.deepEqual(bad, []);
  // a marker a layer adds is read the same way, and several words in a row are several words in a row
  assert.ok(LT.hasProductionMarker('team-uat2-eu', [...MARKERS, 'uat']));
  assert.ok(LT.hasProductionMarker('x-sandbox-eu-1', [...MARKERS, 'sandbox-eu']));
  assert.ok(!LT.hasProductionMarker('x-sandbox-us', [...MARKERS, 'sandbox-eu']));
  assert.deepEqual(LT.nameWords('eksProd2-WEU'), ['eks', 'prod', '2', 'weu']);
});

test('the numbered production name reaches the absolute denies in every family, whichever wildcard was accepted (AUTH-1)', () => {
  const a = accepted({
    k8s_local_contexts: ['aks-*', 'team-*'],
    db_local_hosts: ['*.eu.acme.test'],
    container_local_contexts: ['dev-*'],
  });
  const misses: string[] = [];
  const want = (cmd: string, capability: string): void => {
    const e = judge(a, cmd);
    if (e.decisive?.capability !== capability || e.verdict !== 'DENY') misses.push(`${capability} expected, ${e.verdict} ${e.decisive?.capability}: ${cmd}`);
  };
  for (const n of ['aks-prd1-weu', 'aks-live1-weu', 'team-prd2', 'team-live1', 'aks-prod01-weu', 'aks-prod1-weu']) {
    want(`kubectl --context ${n} apply -f x.yaml`, 'production.k8s.mutate');
    want(`kubectl --context ${n} delete deploy x`, 'production.k8s.mutate');
    want(`helm upgrade --kube-context ${n} app ./chart`, 'production.helm.mutate');
    want(`kubectl --context aks-dev-weu --cluster ${n} apply -f x.yaml`, 'production.k8s.mutate');
  }
  // the namespace of a production release on a development cluster is production too
  for (const ns of ['prd2', 'prod2', 'live1', 'prod-eu1']) want(`kubectl --context aks-dev-weu -n ${ns} apply -f x.yaml`, 'production.k8s.mutate');
  for (const h of ['db.prod1.eu.acme.test', 'db.prd1.eu.acme.test', 'db1.live2.eu.acme.test'])
    want(`psql -h ${h} -c "drop table t"`, 'production.database.mutate');
  for (const c of ['dev-prod1', 'dev-prd1', 'dev-live2']) {
    want(`docker --context ${c} run hello`, 'production.deploy');
    want(`DOCKER_CONTEXT=${c} docker run hello`, 'production.deploy');
  }
  assert.deepEqual(misses, []);
  // ...and the development names in the same registry are untouched
  assert.equal(judge(a, 'kubectl --context aks-dev-weu apply -f x.yaml').verdict, 'ALLOW');
  assert.equal(judge(a, 'psql -h db.dev.eu.acme.test -c "drop table t"').verdict, 'ALLOW');
  assert.equal(judge(a, 'docker --context dev-eu run hello').verdict, 'ALLOW');
});

test('every resolver agrees with the one reader, over generated names (the three readers could not disagree)', () => {
  const words = ['dev', 'prod', 'prd', 'live', 'production', 'products', 'product-catalog', 'reproduce', 'liveness', 'delivery', 'preprod', 'uat'];
  const joins = ['-', '.', '_'];
  const tails = ['', '1', '01', '-eu', '2-weu', '-1'];
  let seed = 20261002;
  const next = (n: number): number => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return seed % n;
  };
  const a = accepted({ k8s_local_contexts: ['aks-*'], db_local_hosts: ['*.eu.acme.test'], container_local_contexts: ['aks-*'] });
  const misses: string[] = [];
  for (let i = 0; i < 90; i++) {
    const w = words[next(words.length)]!;
    const name = `aks${joins[next(3)]}${w}${tails[next(tails.length)]}`;
    const isProd = LT.hasProductionMarker(name, a.cache.table.localTargets.productionMarkers);
    const check = (cmd: string, capability: string): void => {
      const e = judge(a, cmd);
      const got = e.decisive?.capability === capability && e.verdict === 'DENY';
      if (got !== isProd) misses.push(`${name} is ${isProd ? '' : 'not '}production but ${cmd} -> ${e.verdict} ${e.decisive?.capability}`);
    };
    check(`kubectl --context ${name} delete deploy x`, 'production.k8s.mutate');
    check(`helm --kube-context ${name} uninstall x`, 'production.helm.mutate');
    check(`docker --context ${name} run hello`, 'production.deploy');
    check(`psql -h ${name.replace(/[_]/g, '-')}.eu.acme.test -c "drop table t"`, 'production.database.mutate');
  }
  assert.deepEqual(misses, []);
});

test('a namespace, a release or a resource that merely CONTAINS the letters is not production (K8-01)', () => {
  run([
    // the reviewer's: the namespace `products` on a local cluster was an ABSOLUTE deny
    ['kubectl --context minikube -n products rollout restart deploy/api', 'ALLOW'],
    ['kubectl --context kind-dev -n product-service delete pod x', 'ALLOW'],
    ['kubectl --context kind-product-catalog delete pod x', 'ALLOW'],
    ['kubectl --context kind-reproduce delete pod x', 'ALLOW'],
    ['helm --kube-context kind-dev upgrade app ./chart -n products', 'ALLOW'],
    // the neighbours: every flag the old regexes read, and the other verbs
    ['kubectl --context kind-dev --namespace=products apply -f x.yaml', 'ALLOW', { 'x.yaml': 'kind: ConfigMap\nmetadata:\n  name: x\n' }],
    ['kubectl --context kind-dev -n productivity scale deploy/api --replicas=2', 'ALLOW'],
    ['kubectl --context kind-dev -n liveness delete pod x', 'ALLOW'],
    ['kubectl --context kind-dev -n delivery delete pod x', 'ALLOW'],
    ['kubectl --context docker-desktop -nproducts delete pod x', 'ALLOW'],
    ['kubectl -n products --context kind-dev patch deploy/api -p {}', 'ALLOW'],
    ['helm --kube-context minikube upgrade --install products ./chart', 'ALLOW'],
    ['helm --kube-context kind-dev uninstall product-service -n products', 'ALLOW'],
    ['kubectl --context kind-dev delete deploy/production-api', 'ALLOW'],
    // production stays production: the word, either order, a number after it
    ['kubectl --context kind-dev -n production delete pod x', 'DENY'],
    ['kubectl --context kind-dev -n prod-eu delete pod x', 'DENY'],
    ['kubectl --context kind-dev -n prod1 delete pod x', 'DENY'],
    ['helm --kube-context kind-dev upgrade app ./chart -n production', 'DENY'],
    ['kubectl --context kind-prod delete pod x', 'DENY'],
  ]);
  const dir = workspace();
  // and the capability is the target model's, with one reader: the production verdicts name production.* ids
  assert.equal(cap('kubectl --context kind-dev -n prod1 delete pod x', dir), 'production.k8s.mutate');
  assert.equal(cap('helm --kube-context kind-dev upgrade app ./chart -n prod1', dir), 'production.helm.mutate');
});

test('reading a Secret on production is gated by the TYPE of what is read, not by a word anywhere on the line (K8-03)', () => {
  const PROD = 'kubectl --context production';
  run([
    // the reviewer's: reads of a pod or a deployment whose NAME contains the word, and an authorization check
    [`${PROD} describe pod secrets-api-7d9`, 'ALLOW'],
    [`${PROD} get deploy secrets-manager`, 'ALLOW'],
    [`${PROD} get pods -l app=secrets`, 'ALLOW'],
    [`${PROD} get pods secret-store -n production`, 'ALLOW'],
    [`${PROD} auth can-i get secrets`, 'ALLOW'],
    // the neighbours: a NAME that is exactly the word is a name, an exact type is not
    [`${PROD} get pod secrets`, 'ALLOW'],
    [`${PROD} describe deploy secret`, 'ALLOW'],
    [`${PROD} get pods --field-selector metadata.name=secrets`, 'ALLOW'],
    [`${PROD} logs deploy/secrets-manager`, 'ALLOW'],
    [`${PROD} auth can-i list secrets --as=system:serviceaccount:x:y`, 'ALLOW'],
    // a resource TYPE of Secret stays a credential read, in every spelling the type has
    [`${PROD} get secrets`, 'DENY'],
    [`${PROD} get secret db -o yaml`, 'DENY'],
    [`${PROD} get secret/db`, 'DENY'],
    [`${PROD} get pods,secrets`, 'DENY'],
    [`${PROD} get all,secret`, 'DENY'],
    [`${PROD} describe secrets.v1`, 'DENY'],
    [`${PROD} get --show-labels secrets`, 'DENY'],
    [`${PROD} get pod/x secret/db`, 'DENY'],
    [`${PROD} get -f secret.yaml`, 'DENY', { 'secret.yaml': 'apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\n' }],
  ]);
});
