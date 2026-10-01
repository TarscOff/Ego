// CLOSURE OF THE CLUSTER-COMMAND FAMILY (independent reviews 7-11, root cause RC-K8S: sa10-33 and r11-68, 69, 70, 71, 72,
// 73, 74, 75, 76, 169, 170, 186, 187, 191, 206).
//
// THE CAUSE. A cluster command's effect was decided by four readers that each answered one slice of the same question
// and disagreed about the rest: a verb table, a dry-run reader, the regexes in matchers.md and a target resolver that
// looked at the flags it had been told about. The question is ONE: which cluster does this reach, does it read a
// Secret or a credential, does it change something, does it run a program - and a flag VALUE is data, never the flag.
// Every test below states a property of that one answer, with the reviewers' spelling and the neighbours the same
// answer must give; the generated cross-product (corpus.ts, family `k8s`) carries them through every transformation.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluate } from '../src/authority/evaluate.ts';
import { k8sOptionMayTakeValue, k8sOptionTakesValue, optionShape } from '../src/authority/k8s.ts';
import { workspace, verdict, table, ctx } from './support/corpus.ts';

type Expect = 'DENY' | 'ASK' | 'ALLOW' | 'GATED';
type Case = readonly [cmd: string, expect: Expect, files?: Record<string, string>];

const decisive = (cmd: string, dir: string): string =>
  evaluate(table, ctx(dir), { tool: 'Bash', input: { command: cmd } }).decisive?.capability ?? '-';

/** Every case is run and every miss is reported at once: a fix that closes one spelling and leaves its neighbours open
 *  is the history of this family, so the first failure must not hide the rest. */
function run(cases: readonly Case[], common: Record<string, string> = {}): void {
  const misses: string[] = [];
  for (const [cmd, expect, files] of cases) {
    const dir = workspace({ ...common, ...(files ?? {}) });
    const got = verdict(cmd, dir);
    const ok = expect === 'GATED' ? got !== 'ALLOW' : got === expect;
    if (!ok) misses.push(`${expect} expected, ${got} (${decisive(cmd, dir)}): ${cmd.replace(/\n/g, '\\n')}`);
  }
  assert.deepEqual(misses, []);
}

const PROD = 'kubectl --context production';

/* ------------------------------------------------------------------------------------------------------------- *
 * 1. A FLAG VALUE IS DATA (sa10-33, CRITICAL)
 *
 * `set env deploy/x 'A=b --list'` has ONE word that ends in `--list`. The normalizer removes the quoting, the target
 * resolver re-split the text on blanks and read the last two words, and a production mutation was ALLOW.
 * ------------------------------------------------------------------------------------------------------------- */

test('a quoted value that ends in a flag is the value, not the flag (sa10-33)', () => {
  run([
    // the review's reproductions
    [`${PROD} set env deploy/x 'A=b --list'`, 'DENY'],
    [`${PROD} set env deploy/x "A=b --list"`, 'DENY'],
    // ...however the blank is kept inside one word
    [`${PROD} set env deploy/x A=b\\ --list`, 'DENY'],
    [`${PROD} set env deploy/x $'A=b --list'`, 'DENY'],
    [`${PROD} set env deploy/x A="b --list"`, 'DENY'],
    [`${PROD} set env deploy/x --overwrite 'A=b --list'`, 'DENY'],
    [`${PROD} set env deploy/x 'A=--list'`, 'DENY'],
    [`${PROD} set env deploy/x -c app 'A=b --list'`, 'DENY'],
    // the same thing carried by a shell
    [`sh -c "${PROD} set env deploy/x 'A=b --list'"`, 'DENY'],
    [`bash -c '${PROD} set env deploy/x "A=b --list"'`, 'DENY'],
    // the value of an option that takes one is data too
    [`${PROD} set env deploy/x A=b --field-manager --list`, 'DENY'],
    [`${PROD} set env deploy/x A=b --list=false`, 'DENY'],
    // ...and it is one word wherever the tool is reached from
    [`env ${PROD} set env deploy/x 'A=b --list'`, 'DENY'],
    [`sudo ${PROD} set env deploy/x 'A=b --list'`, 'DENY'],
    [`timeout 30 ${PROD} set env deploy/x 'A=b --list'`, 'DENY'],
    [`xargs ${PROD} set env deploy/x 'A=b --list'`, 'DENY'],
    // the oc spelling
    [`oc --context production set env deploy/x 'A=b --list'`, 'DENY'],
  ]);
});

test('a dry-run flag inside one quoted word is not a dry-run flag either', () => {
  run([
    [`${PROD} label pod x 'k=v --dry-run=client'`, 'DENY'],
    [`${PROD} annotate pod x "a=--dry-run=server"`, 'DENY'],
    [`${PROD} create configmap c --from-literal='k=v --dry-run=client'`, 'DENY'],
    [`${PROD} apply -f 'x.yaml --dry-run=client'`, 'DENY'],
    [`${PROD} delete pod 'x --dry-run=client'`, 'DENY'],
    ['helm --kube-context production upgrade app ./chart --set "a=1 --dry-run"', 'DENY'],
    ['helm --kube-context production uninstall app --description "x --dry-run"', 'DENY'],
    ['helm --kube-context production install app ./chart --namespace "x --dry-run"', 'DENY'],
  ]);
});

test('...and the real flags still LOOK at production', () => {
  run(
    [
      [`${PROD} set env deploy/x --list`, 'ALLOW'],
      [`${PROD} set env deploy/x --list -o yaml`, 'ALLOW'],
      [`${PROD} set env deploy/x --list --resolve`, 'ALLOW'],
      [`${PROD} apply -f x.yaml --dry-run=client`, 'ALLOW'],
      [`${PROD} apply -f x.yaml --dry-run=server`, 'ALLOW'],
      [`${PROD} delete pod x --dry-run=client`, 'ALLOW'],
      ['helm --kube-context production upgrade app ./chart --dry-run', 'ALLOW'],
      [`${PROD} rollout status deploy/x`, 'ALLOW'],
      [`${PROD} auth can-i create pods`, 'ALLOW'],
      [`${PROD} delete pod x --help`, 'ALLOW'],
      // cobra parses a flag spelled with `=` by the verb that follows it, and skips the value of one it knows takes one: both
      // stand in front of the verb. A bare flag the tool does not know in front of it swallows the verb, and asks
      [`${PROD} --dry-run=client set env deploy/x A=b`, 'ALLOW'],
      [`${PROD} -o yaml get pods`, 'ALLOW'],
      [`${PROD} --dry-run set env deploy/x A=b`, 'DENY'],
    ],
    { 'x.yaml': 'kind: ConfigMap\nmetadata:\n  name: x\n' },
  );
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 2. EVERY SIGNAL THAT SELECTS THE CLUSTER (r11-68, r11-186, r11-187, r11-74, r11-73, r11-191)
 * ------------------------------------------------------------------------------------------------------------- */

test('--cluster and --user select what the context points at (r11-68, r11-186)', () => {
  run([
    ['kubectl --context kind-foo --cluster production delete deploy x', 'DENY'],
    ['kubectl --context docker-desktop --cluster=production delete deploy api', 'DENY'],
    ['kubectl --cluster production --context kind-foo delete deploy x', 'DENY'],
    ['kubectl delete deploy x --cluster production', 'DENY'],
    ['kubectl --context kind-foo --cluster prod-eu apply -f a.yaml', 'DENY'],
    ['kubectl --context kind-foo --cluster acme-eks delete deploy x', 'DENY'],
    ['kubectl --context kind-foo --user prod-admin delete deploy x', 'DENY'],
    ['oc --context kind-foo --cluster production delete deploy x', 'DENY'],
    ['kubectl --context kind-foo --cluster "$C" delete deploy x', 'ASK'],
    ['kubectl --context kind-foo --cluster kind-foo apply -f a.yaml', 'ALLOW'],
    ['kubectl --context kind-foo --user kind-foo apply -f a.yaml', 'ALLOW'],
  ]);
});

test('the endpoint is judged by its host, wherever it is named (r11-187, r11-74)', () => {
  run([
    // r11-187: minikube's own kubectl takes the cluster flags after the separator
    ['minikube kubectl -- --server=https://10.0.0.5:6443 delete pod x', 'DENY'],
    ['minikube kubectl -- --server https://k8s.prod.acme.com delete pod x', 'DENY'],
    ['minikube -p dev kubectl -- --server https://k8s.prod.acme.com delete pod x', 'DENY'],
    ['minikube kubectl -- --context production delete pod x', 'DENY'],
    ['minikube kubectl -- --kubeconfig /tmp/r.yaml delete pod x', 'DENY'],
    ['minikube kubectl -- delete pod x -n production', 'DENY'],
    ['minikube kubectl -- --cluster production delete pod x', 'DENY'],
    // ...and without one it is minikube's own cluster
    ['minikube kubectl -- get pods', 'ALLOW'],
    ['minikube kubectl -- apply -f a.yaml', 'ALLOW'],
    ['minikube kubectl -- --server=https://127.0.0.1:8443 apply -f a.yaml', 'ALLOW'],
    // r11-74: an exported variable names the API server for every later command of the line
    ['export HELM_KUBEAPISERVER=https://prod.example.com && helm --kube-context kind-foo upgrade x ./c', 'DENY'],
    ['export HELM_KUBEAPISERVER=https://prod.example.com; helm --kube-context kind-foo upgrade x ./c', 'DENY'],
    ['HELM_KUBEAPISERVER=https://prod.example.com helm --kube-context kind-foo upgrade x ./c', 'DENY'],
    ['env HELM_KUBEAPISERVER=https://prod.example.com helm --kube-context kind-foo upgrade x ./c', 'DENY'],
    ['export HELM_KUBEAPISERVER=https://k8s.acme.com && helm --kube-context kind-foo upgrade x ./c', 'DENY'],
    ['export KUBERNETES_MASTER=https://k8s.acme.com && kubectl --context kind-foo apply -f a.yaml', 'DENY'],
    ['export KUBERNETES_SERVICE_HOST=10.1.1.1 && kubectl --context kind-foo apply -f a.yaml', 'DENY'],
    ['export HELM_KUBECONTEXT=production && helm upgrade x ./c', 'DENY'],
    ['export HELM_NAMESPACE=production && helm --kube-context kind-foo upgrade x ./c', 'DENY'],
    ['export HELM_KUBEAPISERVER=https://127.0.0.1:6443 && helm --kube-context kind-foo upgrade x ./c', 'ALLOW'],
    ['helm --kube-context kind-foo --kube-apiserver https://k8s.prod.acme.com upgrade x ./c', 'DENY'],
  ]);
});

const KUBE = (server: string, extra = '', context = 'kind-dev', user = '{token: t}') =>
  `apiVersion: v1\nkind: Config\nclusters:\n- name: c\n  cluster: {server: "${server}"}\ncontexts:\n- name: ${context}\n  context: {cluster: c, user: u}\ncurrent-context: ${context}\nusers:\n- name: u\n  user: ${user}\n${extra}`;
const EXEC_USER = '{exec: {apiVersion: client.authentication.k8s.io/v1, command: aws, args: [eks, get-token, --cluster-name, prod]}}';
const Y = { 'y.yaml': 'kind: ConfigMap\nmetadata: {name: y}\n' };

test('a kubeconfig the workspace holds is read, and the context is judged by its SERVER (r11-73, r11-191)', () => {
  run([
    // r11-73: the context is called kind-dev and points at a production server
    [
      'kubectl --kubeconfig ./kube.conf --context kind-dev apply -f y.yaml',
      'DENY',
      { ...Y, 'kube.conf': KUBE('https://api.prod.example.com:6443', '', 'kind-dev', EXEC_USER) },
    ],
    // r11-191: the same with a local-looking name that the file points elsewhere
    [
      'kubectl --kubeconfig ./other.yaml --context docker-desktop delete deploy api',
      'DENY',
      { 'other.yaml': KUBE('https://k8s.prod.example.com:6443', '', 'docker-desktop') },
    ],
    // a server that is neither local nor production-marked is a shared cluster
    ['kubectl --kubeconfig ./kube.conf --context kind-dev apply -f y.yaml', 'DENY', { ...Y, 'kube.conf': KUBE('https://k8s.acme.example:6443') }],
    // the file is chosen the other ways it can be chosen
    ['KUBECONFIG=./kube.conf kubectl --context kind-dev apply -f y.yaml', 'DENY', { ...Y, 'kube.conf': KUBE('https://api.prod.example.com:6443') }],
    ['export KUBECONFIG=./kube.conf && kubectl --context kind-dev apply -f y.yaml', 'DENY', { ...Y, 'kube.conf': KUBE('https://api.prod.example.com:6443') }],
    ['env KUBECONFIG=./kube.conf kubectl --context kind-dev apply -f y.yaml', 'DENY', { ...Y, 'kube.conf': KUBE('https://api.prod.example.com:6443') }],
    ['kubectl --kubeconfig=./kube.conf --context=kind-dev apply -f y.yaml', 'DENY', { ...Y, 'kube.conf': KUBE('https://api.prod.example.com:6443') }],
    ['helm --kubeconfig ./kube.conf --kube-context kind-dev upgrade x ./c', 'DENY', { 'kube.conf': KUBE('https://api.prod.example.com:6443') }],
    ['KUBECONFIG=./a.conf:./kube.conf kubectl --context kind-dev apply -f y.yaml', 'DENY', { ...Y, 'a.conf': 'apiVersion: v1\nkind: Config\n', 'kube.conf': KUBE('https://api.prod.example.com:6443') }],
    // with no --context the file's own current-context decides
    ['kubectl --kubeconfig ./kube.conf apply -f y.yaml', 'DENY', { ...Y, 'kube.conf': KUBE('https://api.prod.example.com:6443') }],
    // ...a file that cannot be read, or that is being written by this very line, proves nothing
    ['kubectl --kubeconfig ./kube.conf --context kind-dev apply -f y.yaml', 'ASK', { ...Y, 'kube.conf': 'clusters: [\n' }],
    ['kubectl --kubeconfig ./kube.conf --context kind-dev apply -f y.yaml', 'ASK', { ...Y, 'kube.conf': '&anchor\n' }],
    [
      `printf '%s' 'clusters: []' > ./k.conf && kubectl --kubeconfig ./k.conf --context kind-dev apply -f y.yaml`,
      'GATED',
      Y,
    ],
    // a file outside the workspace is not read and is not local
    ['kubectl --kubeconfig /tmp/other.yaml --context kind-dev apply -f y.yaml', 'GATED', Y],
    ['KUBECONFIG=/tmp/other.yaml kubectl --context kind-dev apply -f y.yaml', 'GATED', Y],
    // ...and what the file's server says when it is local keeps the local loop ordinary
    ['kubectl --kubeconfig ./kube.conf --context kind-dev apply -f y.yaml', 'ALLOW', { ...Y, 'kube.conf': KUBE('https://127.0.0.1:35241') }],
    // (a variable that re-points the tool is still the env-override ask it always was; the SERVER is what is local here)
    ['KUBECONFIG=./kube.conf kubectl --context kind-dev apply -f y.yaml', 'ASK', { ...Y, 'kube.conf': KUBE('https://127.0.0.1:35241') }],
    ['kubectl --kubeconfig ./kube.conf apply -f y.yaml', 'ALLOW', { ...Y, 'kube.conf': KUBE('https://0.0.0.0:6443') }],
    ['kubectl --kubeconfig ./kube.conf --context kind-dev get pods', 'ALLOW', { 'kube.conf': KUBE('https://127.0.0.1:35241') }],
    // a file that is not there yet names nothing that contradicts the context
    ['kubectl --kubeconfig ./kube.conf --context kind-dev apply -f y.yaml', 'ALLOW', Y],
    // a credential plugin in the file is a program kubectl runs on every call
    ['kubectl --kubeconfig ./kube.conf --context kind-dev apply -f y.yaml', 'ASK', { ...Y, 'kube.conf': KUBE('https://127.0.0.1:35241', '', 'kind-dev', EXEC_USER) }],
    ['kubectl --kubeconfig ./kube.conf --context kind-dev get pods', 'ASK', { 'kube.conf': KUBE('https://127.0.0.1:35241', '', 'kind-dev', EXEC_USER) }],
  ]);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 3. WHAT IS READ (r11-70, r11-71, r11-72, r11-169, r11-170)
 * ------------------------------------------------------------------------------------------------------------- */

const SECRET = 'apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\n  namespace: prod\n';
const CM = 'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n';

test('a kubeconfig that is dumped with its credentials is a credential read (r11-70)', () => {
  run([
    ['kubectl config view --flatten', 'DENY'],
    ['kubectl --context kind-foo config view --flatten', 'DENY'],
    ['kubectl config view --raw', 'DENY'],
    ['kubectl config view --minify --flatten -o json', 'DENY'],
    ['kubectl config view --flatten --minify', 'DENY'],
    ['kubectl --kubeconfig ./k config view --raw', 'DENY'],
    ['kubectl -n x config view --raw', 'DENY'],
    ['oc config view --flatten', 'DENY'],
    ['kubectl config view --raw=true', 'DENY'],
    ['kubectl config view', 'ALLOW'],
    ['kubectl config view --minify', 'ALLOW'],
    ['kubectl config view --raw=false', 'ALLOW'],
    ['kubectl config get-contexts', 'ALLOW'],
    ['kubectl config current-context', 'ALLOW'],
  ]);
});

test('a Secret named by a manifest, a directory, a stream or a word the shell fills in is a Secret read (r11-71, r11-169, r11-170)', () => {
  const files = { 's.yaml': SECRET, 'cm.yaml': CM, 'k8s/s.yaml': SECRET, 'k8s/cm.yaml': CM, 'only/cm.yaml': CM };
  run(
    [
      // the review's reproduction, and the neighbours: the file is named by every spelling of the option
      [`${PROD} get -f s.yaml -o yaml`, 'DENY'],
      [`${PROD} get --filename s.yaml -o yaml`, 'DENY'],
      [`${PROD} get --filename=s.yaml -o yaml`, 'DENY'],
      [`${PROD} get -fs.yaml -o yaml`, 'DENY'],
      [`${PROD} get -f=s.yaml -o yaml`, 'DENY'],
      [`${PROD} describe -f s.yaml`, 'DENY'],
      [`${PROD} get -f ./s.yaml -o json`, 'DENY'],
      [`${PROD} get -f cm.yaml -f s.yaml -o yaml`, 'DENY'],
      // r11-170: a directory is every file in it
      [`${PROD} get -f . -o yaml`, 'DENY'],
      [`${PROD} get -f k8s -o yaml`, 'DENY'],
      [`${PROD} get -f k8s/ -o yaml`, 'DENY'],
      [`${PROD} get -Rf k8s -o yaml`, 'DENY'],
      // a stream the line itself writes is read
      [`${PROD} get -f - -o yaml <<'EOF'\nkind: Secret\nmetadata: {name: db}\nEOF`, 'DENY'],
      // a source that cannot be read can be a Secret
      [`${PROD} get -f https://example.com/s.yaml -o yaml`, 'DENY'],
      [`${PROD} get -f "$F" -o yaml`, 'DENY'],
      [`${PROD} get -k overlays/prod -o yaml`, 'DENY'],
      [`kustomize build overlays/prod | ${PROD} get -f - -o yaml`, 'DENY'],
      // r11-169: the resource type is a word the shell fills in
      [`${PROD} get $(echo secret) db -o yaml`, 'DENY'],
      [`${PROD} get $R -o yaml`, 'DENY'],
      [`${PROD} get "$R" db -o yaml`, 'DENY'],
      [`${PROD} get \${R:-secret} db`, 'DENY'],
      [`${PROD} get \`echo secret\` db`, 'DENY'],
      [`${PROD} describe $R db`, 'DENY'],
      [`${PROD} get pod/a $X`, 'DENY'],
      ['helm --kube-context production get $X app', 'DENY'],
      ['helm --kube-context production get "$X" app', 'DENY'],
      // ...and the spellings of the type itself
      [`${PROD} get secret.v1. db`, 'DENY'],
      [`${PROD} get Secret db`, 'DENY'],
      [`${PROD} get secrets.v1 db`, 'DENY'],
      [`${PROD} get pods,secrets`, 'DENY'],
      [`${PROD} get --raw /api/v1/namespaces/prod/secrets`, 'DENY'],
      [`${PROD} get --raw "$P"`, 'DENY'],
      [`${PROD} apply view-last-applied secret/db`, 'DENY'],
      // none of which makes an ordinary read of a production cluster a refusal
      [`${PROD} get -f cm.yaml -o yaml`, 'ALLOW'],
      [`${PROD} get -f only -o yaml`, 'ALLOW'],
      [`${PROD} get pods $NAME`, 'ALLOW'],
      [`${PROD} get deploy -n "$NS" -o yaml`, 'ALLOW'],
      // ...and against a local cluster it is nobody's business
      ['kubectl --context kind-dev get -f s.yaml -o yaml', 'ALLOW'],
      ['kubectl --context kind-dev get $R -o yaml', 'ALLOW'],
      ['kubectl --context kind-dev get secrets', 'ALLOW'],
    ],
    files,
  );
});

test('a release that is printed with its values is a credential read (r11-72)', () => {
  run([
    ['helm --kube-context production status rel -o json', 'DENY'],
    ['helm --kube-context production status rel -o yaml', 'DENY'],
    ['helm --kube-context production status rel --output json', 'DENY'],
    ['helm --kube-context production status rel --output=yaml', 'DENY'],
    ['helm --kube-context production status rel -ojson', 'DENY'],
    ['helm --kube-context production status rel -o "$F"', 'DENY'],
    ['helm --kube-context production status rel', 'ALLOW'],
    ['helm --kube-context production status rel -o table', 'ALLOW'],
    ['helm --kube-context production list -o json', 'ALLOW'],
    ['helm --kube-context production history rel -o json', 'ALLOW'],
    ['helm --kube-context kind-dev status rel -o json', 'ALLOW'],
  ]);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 4. WHAT RUNS (r11-69, r11-75, r11-76, r11-206)
 * ------------------------------------------------------------------------------------------------------------- */

test('the kubeconfig is written whatever stands in front of the verb (r11-69)', () => {
  run([
    ['kubectl --context kind-foo config set-credentials u --exec-command=./tok.sh --exec-api-version=client.authentication.k8s.io/v1', 'DENY'],
    ['kubectl -n x config set-cluster c --server=https://k8s.acme.com', 'DENY'],
    ['kubectl --v=2 config set-credentials u --token=abc', 'DENY'],
    ['kubectl --request-timeout 5s config set-context c --cluster=c', 'DENY'],
    ['kubectl --kubeconfig ./k config unset users.u', 'DENY'],
    ['kubectl --context kind-foo config delete-user u', 'DENY'],
    ['kubectl --context kind-foo config rename-context a b', 'DENY'],
    ['oc --context kind-foo config set-credentials u --token=abc', 'DENY'],
    ['kubectl config set-credentials u --exec-command=./tok.sh', 'DENY'],
    ['kubectl --context kind-foo config view', 'ALLOW'],
    ['kubectl --context kind-foo config get-contexts', 'ALLOW'],
  ]);
});

test('a verb the tool does not have is a plugin, and a plugin is a program (r11-75, r11-206)', () => {
  const hp = {
    'hp/evil/plugin.yaml': 'name: evil\nversion: 0.1.0\nusage: x\ndescription: x\ncommand: "$HELM_PLUGIN_DIR/run.sh"\n',
    'hp/evil/run.sh': '#!/bin/sh\nid\n',
  };
  run(
    [
      ['HELM_PLUGINS=./hp helm --kube-context docker-desktop evil a b', 'ASK'],
      ['helm --kube-context docker-desktop evil a b', 'ASK'],
      ['helm evil', 'ASK'],
      ['helm --kube-context kind-dev -n x evil a b', 'ASK'],
      ['helm --debug evil a', 'ASK'],
      ['kubectl --context kind-foo foo bar get pods', 'ASK'],
      ['kubectl --context kind-foo foo', 'ASK'],
      ['kubectl --context kind-foo krew install x', 'ASK'],
      ['kubectl --context kind-foo --no-such-flag get pods', 'ASK'],
      ['oc --context kind-foo frob a', 'ASK'],
      // production is refused whatever it is called
      ['kubectl --context production foo bar get pods', 'DENY'],
      ['helm --kube-context production evil a b', 'DENY'],
      // the plugins helm and kubectl ship with their ecosystem are ordinary
      ['helm --kube-context kind-dev diff upgrade x ./c', 'ALLOW'],
      ['helm --kube-context kind-dev list', 'ALLOW'],
      ['helm --kube-context kind-dev -n dev get values x', 'ALLOW'],
      ['helm template x ./chart', 'ALLOW'],
      ['kubectl --context kind-dev get pods', 'ALLOW'],
    ],
    hp,
  );
});

test('a variable that names a program the tool runs asks (r11-76, r11-28)', () => {
  run([
    ['KUBE_EDITOR=./e.sh kubectl --context kind-foo edit deploy x', 'ASK'],
    ['export KUBE_EDITOR=./e.sh && kubectl --context kind-foo edit deploy x', 'ASK'],
    ['KUBECTL_EXTERNAL_DIFF=/tmp/evil kubectl diff -f x.yaml', 'ASK'],
    ['HELM_PLUGINS=./hp helm --kube-context kind-dev list', 'ASK'],
    ['KUBECTL_PLUGINS_PATH=./p kubectl --context kind-dev get pods', 'ASK'],
  ]);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 5. ORDINARY CLUSTER WORK STAYS ORDINARY
 * ------------------------------------------------------------------------------------------------------------- */

test('ordinary work against a local cluster, and reading a production one, is not gated', () => {
  const files = { 'a.yaml': CM, 'k8s/dev.yaml': CM, 'x.yaml': CM, 'chart/Chart.yaml': 'name: c\nversion: 0.1.0\n', 'overlays/dev/kustomization.yaml': 'resources: []\n' };
  run(
    [
      ['kubectl --context kind-dev apply -f k8s/dev.yaml', 'ALLOW'],
      ['kubectl --context kind-dev get pods -n default', 'ALLOW'],
      ['kubectl --context docker-desktop rollout restart deploy/api', 'ALLOW'],
      ['kubectl --context kind-dev logs deploy/api --tail=50', 'ALLOW'],
      ['kubectl --context kind-dev delete -f k8s/dev.yaml', 'ALLOW'],
      ['kubectl --context kind-dev config view --minify', 'ALLOW'],
      ['kubectl --context kind-dev diff -f x.yaml', 'ALLOW'],
      ['kubectl version --client', 'ALLOW'],
      ['kubectl kustomize overlays/dev', 'ALLOW'],
      ['helm --kube-context kind-dev upgrade --install app ./chart', 'ALLOW'],
      ['helm --kube-context kind-dev template app ./chart --set a=1', 'ALLOW'],
      ['helm template app ./chart', 'ALLOW'],
      ['helm lint ./chart', 'ALLOW'],
      ['kind create cluster --name dev', 'ALLOW'],
      ['k3d cluster create dev', 'ALLOW'],
      ['minikube start', 'ALLOW'],
      ['minikube status', 'ALLOW'],
      ['kustomize build overlays/dev', 'ALLOW'],
      [`${PROD} get pods`, 'ALLOW'],
      [`${PROD} describe deploy/api`, 'ALLOW'],
      [`${PROD} get deploy -o yaml`, 'ALLOW'],
      [`${PROD} logs deploy/api`, 'ALLOW'],
      [`${PROD} diff -f x.yaml`, 'ALLOW'],
      ['helm --kube-context production list', 'ALLOW'],
      ['helm --kube-context production status app', 'ALLOW'],
      ['helm --kube-context production history app', 'ALLOW'],
    ],
    files,
  );
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 6. THE NEIGHBOURS THE ONE READER MUST ALSO GIVE (found while closing the above)
 * ------------------------------------------------------------------------------------------------------------- */

test('the LAST --list decides, and an option of unknown arity may have taken the word after it', () => {
  run([
    [`${PROD} set env deploy/x A=b --list --list=false`, 'DENY'],
    [`${PROD} set env deploy/x A=b --list=false --list`, 'ALLOW'],
    [`${PROD} set env deploy/x --list=$X`, 'DENY'],
    [`${PROD} set env deploy/x '--list'`, 'DENY'],
    [`${PROD} set env deploy/x -e 'A=b --list'`, 'DENY'],
    [`${PROD} set env deploy/x -- A=b --list`, 'DENY'],
    // `--no-such-flag` may take `x` as its value, which moves the type to the next word
    [`${PROD} get --no-such-flag x $R`, 'DENY'],
    [`${PROD} get --no-such-flag secrets`, 'DENY'],
    [`${PROD} get pods $NAME`, 'ALLOW'],
  ]);
});

test('a file named as KEY=PATH is a file the tool reads (r11-77)', () => {
  run(
    [
      ['helm template x ./chart --set-file a=.env', 'ASK'],
      ['helm template x ./chart --set-file a=README.md,b=.env', 'ASK'],
      ['helm template x ./chart --set-file=a=~/.ssh/id_rsa', 'DENY'],
      ['helm template x ./chart --set-file a=$F', 'ASK'],
      ['kubectl --context kind-dev create secret generic x --from-file=k=.env --dry-run=client -o yaml', 'ASK'],
      ['kubectl --context kind-dev create secret generic x --from-file=k=~/.ssh/id_rsa --dry-run=client -o yaml', 'DENY'],
      ['kubectl --context kind-dev create secret generic x --from-env-file=.env', 'ASK'],
      ['helm template x ./chart --set-file a=README.md', 'ALLOW'],
      ['kubectl --context kind-dev create configmap x --from-file=README.md', 'ALLOW'],
    ],
    { '.env': 'TOKEN=abc\n', 'README.md': '# x\n' },
  );
});

test('a manifest that can say Secret without spelling it is not known to declare none', () => {
  const dir = (text: string): Record<string, string> => ({ 's.yaml': text });
  for (const text of [
    '{"kind": "S\\u0065cret", "metadata": {"name": "db"}}',
    'kind: "S\\x65cret"\nmetadata: {name: db}\n',
    'x: &k Secret\nkind: *k\n',
    'kind: !!str Secret\n',
    'kind: Secret\n',
    '{"kind":"Secret"}',
    'apiVersion: v1\nkind:\n  Secret\n',
  ])
    run([[`${PROD} get -f s.yaml -o yaml`, 'DENY', dir(text)]]);
  // ...and the ordinary ones are not
  for (const text of [
    'kind: ConfigMap\ndata:\n  url: https://a/b?x=1&y=2\n',
    'kind: SealedSecret\n',
    'kind: SecretStore\n',
    'kind: Deployment\nspec:\n  secretName: x\n',
  ])
    run([[`${PROD} get -f s.yaml -o yaml`, 'ALLOW', dir(text)]]);
});

test('oc names its kubeconfig --config, and a file that may be rewritten is read and doubted', () => {
  run([
    ['oc --config ./kube.conf --context kind-dev delete pod x', 'DENY', { 'kube.conf': KUBE('https://api.prod.example.com:6443') }],
    ['oc --config /tmp/other.yaml --context kind-dev delete pod x', 'DENY'],
    // a kubeconfig an earlier part of the line may have rewritten: the disk says production, so it is production; the disk
    // says local, and the line may have changed it, so it asks
    [
      'define-function ego; kubectl --kubeconfig ./kube.conf --context kind-dev apply -f y.yaml',
      'DENY',
      { ...Y, 'kube.conf': KUBE('https://api.prod.example.com:6443') },
    ],
    [
      'define-function ego; kubectl --kubeconfig ./kube.conf --context kind-dev apply -f y.yaml',
      'ASK',
      { ...Y, 'kube.conf': KUBE('https://127.0.0.1:35241') },
    ],
  ]);
});

test('the lists the matchers keep and the lists the reader keeps are the same lists', () => {
  const writers = table.matchers.find((m) => m.capability === 'fs.credential-store.write' && /set-credentials/.test(m.command ?? ''));
  assert.ok(writers, 'the kubeconfig-writer matcher exists');
  const re = new RegExp(writers.command!, 'i');
  // every sub-verb the reader treats as a write of the kubeconfig is one the matcher names, and the ones it leaves alone are not
  for (const sub of ['set-credentials', 'set-cluster', 'set-context', 'rename-context', 'delete-context', 'delete-cluster', 'delete-user', 'unset', 'set'])
    assert.ok(re.test(`kubectl config ${sub} x`), sub);
  for (const sub of ['view', 'get-contexts', 'get-clusters', 'get-users', 'current-context', 'use-context'])
    assert.ok(!re.test(`kubectl config ${sub} x`), sub);
  // ...and the reader answers the same way when an option stands in front of the verb, where no anchored regex reads it
  const dir = workspace();
  for (const sub of ['set-credentials u --token=t', 'set-cluster c --server=https://k8s.acme.com', 'set-context c', 'unset users.u'])
    assert.equal(verdict(`kubectl -n x config ${sub}`, dir), 'DENY', sub);
  // switching context is judged by the context it switches to, as it always was: a local one is ordinary work
  assert.equal(verdict('kubectl config use-context kind-dev', dir), 'ALLOW');
  assert.equal(verdict('kubectl config use-context production', dir), 'DENY');
});

test('ONE table says which words are options and which are their values', () => {
  // a value glued to the option, in each of the spellings the tools accept
  assert.deepEqual(optionShape('kubectl', undefined, '--context=x'), { name: '--context', glued: 'x', next: 'no' });
  assert.deepEqual(optionShape('kubectl', undefined, '-nfoo'), { name: '-n', glued: 'foo', next: 'no' });
  assert.deepEqual(optionShape('kubectl', undefined, '-n=foo'), { name: '-n', glued: 'foo', next: 'no' });
  // a cluster of short options ends in the one that takes the next word
  assert.deepEqual(optionShape('kubectl', undefined, '-Rf'), { name: '-f', next: 'yes' });
  assert.deepEqual(optionShape('kubectl', undefined, '-it'), { name: '-it', next: 'no' });
  // a spelling that means two things is read by the verb it stands in: `logs -f` follows, `get -f` names a file
  assert.equal(optionShape('kubectl', 'logs', '-f').next, 'no');
  assert.equal(optionShape('kubectl', 'get', '-f').next, 'yes');
  assert.equal(optionShape('kubectl', 'config', '--raw').next, 'no');
  assert.equal(optionShape('kubectl', 'get', '--raw').next, 'yes');
  // what the table does not know MAY take the next word, and so nothing that needs it to be a flag is granted
  assert.equal(optionShape('kubectl', undefined, '--no-such-flag').next, 'maybe');
  assert.equal(k8sOptionMayTakeValue('kubectl', '--no-such-flag'), true);
  assert.equal(k8sOptionTakesValue('kubectl', '--no-such-flag'), false);
  // the tools differ where they differ: oc names its kubeconfig --config, helm's --version takes a value
  assert.equal(k8sOptionTakesValue('oc', '--config'), true);
  assert.equal(k8sOptionTakesValue('kubectl', '--config'), false);
  assert.equal(k8sOptionTakesValue('helm', '--version'), true);
  assert.equal(k8sOptionTakesValue('helm', '--debug'), false);
});
