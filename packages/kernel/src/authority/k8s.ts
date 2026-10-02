// THE ONE READER OF A CLUSTER COMMAND (closure of RC-K8S: independent reviews 7-11).
//
// A command for kubectl, oc, helm or minikube's own kubectl has four effects that matter to a permission gate, and each
// used to be answered by a different reader that knew a different slice of the command line:
//
//   - WHICH CLUSTER it reaches (a context, a cluster entry, a server, a kubeconfig FILE and what is in it, a namespace),
//   - WHETHER IT READS a Secret or a credential (a resource type, a manifest it is pointed at, a stream, a release),
//   - WHETHER IT CHANGES something (a verb, a sub-verb, a flag that turns the verb into a look),
//   - WHETHER IT RUNS A PROGRAM (a plugin, a credential plugin in a kubeconfig, a post-renderer).
//
// The readers were a verb table, a dry-run scanner, the regexes of matchers.md and a target resolver, and they agreed
// only on the textbook spelling. `kubectl set env deploy/x 'A=b --list'` was a production mutation at ALLOW because the
// resolver took the last blank-separated words of a command line whose quoting had already been removed (sa10-33);
// `--cluster`, a `--server` after minikube's `--`, the CONTENT of a kubeconfig the workspace holds and an exported
// `HELM_KUBEAPISERVER` each selected a cluster that no reader asked (r11-68, 74, 186, 187, 73, 191); a Secret reached
// through `-f s.yaml`, `-f DIR` or a word the shell fills in was not a Secret read (r11-71, 169, 170); and a verb the
// tool does not have is a PLUGIN, which is a program (r11-75, 206).
//
// So there is ONE function, `k8sEffect`, over the words AS THE TOOL RECEIVES THEM: the shell has removed the quoting, and
// a word that held a blank is still one word. It is a positive grammar - what is known to be harmless is ordinary, and
// what cannot be placed asks. The module depends on nothing of the evaluator: it is handed what it needs through
// `K8sHost`, and the evaluator's own option tables are derived from the ones below, so they cannot drift from them.
import type { TargetClass } from '../control-plane/types.ts';
import { parseYaml, type YamlValue } from '../util/yaml.ts';

/** A word of the command line as the shell hands it to the tool. `quoted`: some of it was written inside quotes.
 *  `expands`: the shell fills something in (a variable, a substitution), so the tool receives a word nobody has read. */
export interface K8sWord {
  text: string;
  quoted: boolean;
  expands: boolean;
}

/** What the kernel can say about a file a word names. */
export type K8sFile =
  /** read inside the workspace. `stale`: an earlier part of THIS command line (or an earlier command whose effect is unknown)
   *  may have rewritten it, so what the tool opens is not necessarily what was read - the text is still the worst-case evidence */
  | { state: 'text'; text: string; stale?: boolean }
  /** not there (yet), and nothing earlier in this command line writes it */
  | { state: 'absent' }
  /** there, and the kernel cannot read it: too large, a directory, a device */
  | { state: 'unread' }
  /** not there now, and an earlier part of THIS command line may create it */
  | { state: 'fresh' }
  /** a path the workspace does not own: absolute, under `~`, or climbing out of it */
  | { state: 'outside' }
  /** a path a shell fills in, or a glob */
  | { state: 'dynamic' };

export interface K8sHost {
  /** a context, cluster or user NAME: PRODUCTION when it carries a production marker, LOCAL when it is declared local,
   *  EXTERNAL when it is neither, UNCLASSIFIED when it is built at run time */
  classifyName(name: string): TargetClass;
  /** an API server endpoint, judged by its HOST against the hosts of this machine (a production marker still wins) */
  classifyServer(url: string): TargetClass;
  /** the name carries a production marker */
  productionMarked(name: string): boolean;
  file(word: string): K8sFile;
  /** the manifests a directory holds, as paths `file` can open, or null when it cannot be listed */
  directory(word: string, recursive: boolean): string[] | null;
  /** the text standard input carries, where the command line itself put it (a heredoc) */
  stdin(): string | null;
  /** `[head, ...words]` is a dry run that was PROVED: the last dry-run flag asks for one and nothing a shell fills in can undo it */
  dryRun(head: K8sWord, words: readonly K8sWord[]): boolean;
}

export interface K8sInput {
  /** the program without its directory: kubectl, oc, helm, kustomize, minikube, kind, k3d */
  head: string;
  headWord: K8sWord;
  /** the words after it, redirections removed */
  words: readonly K8sWord[];
  /** the words are exactly the ones written: boundaries and quoting are known. When they are not (the line was carried
   *  through something the reader could not follow), no flag counts as an exception - not `--list`, not a dry run */
  written: boolean;
  /** every value a variable that selects a cluster has in scope (a prefix assignment, an `export` on an earlier command) */
  env: Readonly<Record<string, readonly string[]>>;
  /** where a command that names no cluster goes; minikube's own kubectl: its own cluster */
  ambient?: { cls: TargetClass; target: string };
}

export interface K8sEffect {
  /** the most restrictive of every signal that selects the cluster */
  cls: TargetClass;
  target: string;
  /** changes something on the cluster, or READS a Secret or a credential from it - the target model escalates both */
  mutating: boolean;
  /** prints a Secret or a rendered release: why */
  secret: string | null;
  /** prints the local kubeconfig with its credentials: why */
  kubeconfigDump: string | null;
  /** writes the local kubeconfig, a credential store: why */
  kubeconfigWrite: string | null;
  /** runs a program the kernel has not read: what */
  program: string | null;
  /** files the command reads through an option whose value is `KEY=PATH` (`helm --set-file`, `kubectl create --from-file`).
   *  The path scan of the evaluator reads a word that IS a path; `a=.env` is not one, and the read was invisible */
  reads: Array<{ option: string; path: string }>;
  /** why the API server or the credentials this command uses are NOT the ambient ones the user configured, or null: an API server
   *  named on the line or in the environment that is not a declared local one, or a kubeconfig file the kernel cannot read (it may
   *  name a credential plugin). A read sends the credentials to whatever answers, so a read that is unvouched does not take the
   *  verdict of a read in the mode made for looking at the clusters the developer configured */
  unvouched: string | null;
}

/* ------------------------------------------------------------------------------------------------------------- *
 * OPTIONS: WHICH WORD IS AN OPTION, AND WHICH IS ITS VALUE
 *
 * One table. The verb scan, the dry-run reader, the help-probe reader and `flagFilledInAfter` each kept a list of the
 * options that take a value (`K8S_VALUE_OPTS`, `GLOBAL_OPTIONS`, `K8S_DRY_RUN_VALUED`, `BOOLEAN_BEFORE_DRY_RUN`), and each
 * was complete for the cases its author had met. An option this table does not know has an arity nobody can tell: the
 * word after it MAY be its value, and nothing that rests on that word being a flag is granted.
 * ------------------------------------------------------------------------------------------------------------- */

/** kubectl's PERSISTENT options, the only ones that may stand in front of the verb, and the klog options it still lists */
const KUBECTL_GLOBAL_VALUE = [
  '--as', '--as-group', '--as-uid', '--as-user-extra', '--cache-dir', '--certificate-authority', '--client-certificate',
  '--client-key', '--cluster', '--context', '--kubeconfig', '--kuberc', '--log-flush-frequency', '--namespace', '-n',
  '--password', '--profile', '--profile-output', '--request-timeout', '--server', '-s', '--tls-server-name', '--token',
  '--user', '--username', '-v', '--v', '--vmodule', '--log-backtrace-at', '--log-dir', '--log-file',
  '--log-file-max-size', '--stderrthreshold',
] as const;
const KUBECTL_GLOBAL_FLAG = [
  '--insecure-skip-tls-verify', '--match-server-version', '--disable-compression', '--warnings-as-errors',
  '--add-dir-header', '--alsologtostderr', '--logtostderr', '--one-output', '--skip-headers', '--skip-log-headers',
  '-h', '--help',
] as const;
/** the cadvisor and kubelet options older kubectl builds list among their globals */
const KUBECTL_LEGACY_VALUE =
  /^--(storage-driver-[a-z-]+|docker[a-z-]*|event-storage-[a-z-]+|application-metrics-count-limit|container-hints|global-housekeeping-interval|housekeeping-interval|max-housekeeping-interval|boot-id-file|machine-id-file|default-not-ready-toleration-seconds|default-unreachable-toleration-seconds)$/;

/** `oc` takes kubectl's persistent options, and two of its own: `--config` is its spelling of the kubeconfig file */
const OC_GLOBAL_VALUE = [...KUBECTL_GLOBAL_VALUE, '--config', '--loglevel'] as const;

const HELM_GLOBAL_VALUE = [
  '--burst-limit', '--kube-apiserver', '--kube-as-group', '--kube-as-user', '--kube-ca-file', '--kube-context',
  '--kube-tls-server-name', '--kube-token', '--kubeconfig', '-n', '--namespace', '--qps', '--registry-config',
  '--repository-cache', '--repository-config',
  // helm 4 (read from `helm --help`: each takes a value) - the colour of the output and where fetched charts are cached
  '--color', '--colour', '--content-cache',
] as const;
const HELM_GLOBAL_FLAG = ['--debug', '--kube-insecure-skip-tls-verify', '-h', '--help'] as const;

/** options of the verbs, across kubectl, oc and helm, KNOWN to take one value */
const VERB_VALUE = new Set<string>([
  '-o', '--output', '-f', '--filename', '-k', '--kustomize', '-l', '--selector', '--field-selector', '-L',
  '--label-columns', '--sort-by', '--chunk-size', '--template', '--raw', '--subresource', '-c', '--container',
  '--image', '--replicas', '--current-replicas', '--resource-version', '--type', '--patch', '-p', '--patch-file',
  '--grace-period', '--timeout', '--field-manager', '--overrides', '--port', '--target-port', '--name', '--env',
  '-e', '--limits', '--requests', '--labels', '--annotations', '--description', '--history-max', '--wait-timeout',
  '--max', '--min', '--cpu-percent', '--revision', '--to-revision', '--since', '--since-time', '--tail',
  '--limit-bytes', '--max-log-requests', '--pod-running-timeout', '--for', '--duration', '--audience',
  '--bound-object-kind', '--bound-object-name', '--bound-object-uid', '--address', '--pod-selector', '--restart',
  '--serviceaccount', '--target', '--copy-to', '--image-pull-policy', '--from-literal', '--from-file',
  '--from-env-file', '--docker-server', '--docker-username', '--docker-password', '--docker-email', '--tls-cert',
  '--tls-key', '--key', '--cert', '--role', '--clusterrole', '--resource', '--resource-name', '--verb', '--group',
  '--chart', '--repo', '--version', '--values', '--set', '--set-string', '--set-file', '--set-json', '--set-literal',
  '--cert-file', '--key-file', '--ca-file', '--keyring', '--post-renderer', '--post-renderer-args', '--exec-command',
  '--exec-api-version', '--exec-arg', '--exec-env', '--auth-provider', '--auth-provider-arg', '--show-only', '-s',
  '--output-dir', '--name-template', '--kube-version', '--api-versions', '--offset', '--filter',
  // `kubectl cp`: how many times to retry a failed copy
  '--retries',
]);
/** options KNOWN to take no value */
const VERB_FLAG = new Set<string>([
  '--force', '--wait', '--atomic', '--install', '-i', '--overwrite', '--server-side', '--prune', '--recursive', '-R',
  '--all', '-A', '--all-namespaces', '--record', '--save-config', '--show-managed-fields', '--skip-crds', '--no-hooks',
  '--debug', '--create-namespace', '--dependency-update', '--reuse-values', '--reset-values', '--cascade',
  '--ignore-not-found', '--wait-for-jobs', '--enable-helm', '--delete', '--quiet', '-q', '--verbose', '--validate',
  '--force-conflicts', '--local', '--now', '--devel', '--replace', '--cleanup-on-fail', '--keep-history',
  '--disable-openapi-validation', '--insecure-skip-tls-verify', '--watch', '-w', '--watch-only', '--show-labels',
  '--no-headers', '--show-kind', '--output-watch-events', '--ignore-errors', '--follow', '--previous', '--prefix',
  '--timestamps', '--stdin', '--tty', '-t', '--rm', '--attach', '--minify', '--flatten', '--list', '--resolve',
  '--dry-run', '--client', '--short', '--skip-refresh', '--skip-tests', '--include-crds', '--is-upgrade',
  '--hide-notes', '--show-resources', '--pass-credentials', '--plain-http', '--untar', '--verify',
  '--skip-schema-validation', '--render-subchart-notes', '--no-color', '--all-containers', '--ignore-daemonsets',
  '--delete-emptydir-data', '--disable-eviction', '--keep-annotations', '--rollback-on-failure', '--take-ownership',
  '--embed-certs', '--merge', '--current', '--print-flags', '-it', '-ti',
  // `kubectl cp`: do not keep the ownership and permissions of what is copied out
  '--no-preserve',
]);
/** a spelling that is a flag in one verb and an option with a value in another: `logs -f` follows, `get -f` names a file,
 *  `config view --raw` prints and `get --raw` takes a path */
const FLAG_IN_VERB: Record<string, ReadonlySet<string>> = {
  logs: new Set(['-f', '-p']),
  config: new Set(['--raw', '--flatten', '--minify', '--merge', '--current', '--embed-certs']),
  exec: new Set(['-i', '-t', '-q']),
  attach: new Set(['-i', '-t', '-q']),
};

const globalValues = (head: string): readonly string[] =>
  head === 'helm' ? HELM_GLOBAL_VALUE : head === 'oc' ? OC_GLOBAL_VALUE : KUBECTL_GLOBAL_VALUE;

type Arity = 'value' | 'flag' | 'unknown';

/** What a spelling of an option is, for this tool and verb: it takes the next word, it takes none, or nobody can tell. */
export function optionArity(head: string, verb: string | undefined, name: string): Arity {
  if (verb !== undefined && FLAG_IN_VERB[verb]?.has(name)) return 'flag';
  const helm = head === 'helm';
  if (globalValues(head).includes(name as never)) return 'value';
  if (!helm && KUBECTL_LEGACY_VALUE.test(name)) return 'value';
  if ((helm ? HELM_GLOBAL_FLAG : KUBECTL_GLOBAL_FLAG).includes(name as never)) return 'flag';
  if (VERB_VALUE.has(name)) return 'value';
  if (VERB_FLAG.has(name)) return 'flag';
  return 'unknown';
}

/** How one option word takes its value. `name` is the spelling whose arity it is. */
export interface OptionShape {
  name: string;
  /** the value is part of the word: `--context=x`, `-nfoo`, `-n=foo` */
  glued?: string;
  /** the value is the next word, the next word MAY be the value, or the option takes none */
  next: 'yes' | 'maybe' | 'no';
}

export function optionShape(head: string, verb: string | undefined, text: string): OptionShape {
  if (text.startsWith('--')) {
    const eq = text.indexOf('=');
    if (eq > 0) return { name: text.slice(0, eq), glued: text.slice(eq + 1), next: 'no' };
    const a = optionArity(head, verb, text);
    return { name: text, next: a === 'value' ? 'yes' : a === 'flag' ? 'no' : 'maybe' };
  }
  // a single dash is a cluster of short options (`-it`, `-Rf`), the last of which may take the next word; a spelling the
  // table knows whole (`-it`) is read whole
  const whole = optionArity(head, verb, text);
  if (whole === 'flag') return { name: text, next: 'no' };
  if (whole === 'value') return { name: text, next: 'yes' };
  for (let i = 1; i < text.length; i++) {
    const letter = `-${text[i]!}`;
    const a = optionArity(head, verb, letter);
    if (a === 'value') {
      const rest = text.slice(i + 1).replace(/^=/, '');
      return rest ? { name: letter, glued: rest, next: 'no' } : { name: letter, next: 'yes' };
    }
    if (a === 'unknown') return { name: letter, next: 'maybe' };
  }
  return { name: text, next: 'no' };
}

/** Whether the word after `opt` MAY be its value: the question the dry-run reader asks of the previous word. */
export function k8sOptionMayTakeValue(head: string, opt: string): boolean {
  if (!opt.startsWith('-') || opt === '-' || opt.includes('=')) return false;
  return optionShape(head, undefined, opt).next !== 'no';
}

/** Whether the option is KNOWN to take the next word as its value: that word is data, whatever the shell fills in. */
export function k8sOptionTakesValue(head: string, opt: string): boolean {
  if (!opt.startsWith('-') || opt === '-' || opt.includes('=')) return false;
  return optionShape(head, undefined, opt).next === 'yes';
}

/** The options that may stand in front of the verb, as the help-probe reader keeps them: those with a value, those without. */
export function k8sGlobalOptions(head: string): { value: RegExp; bool: RegExp } {
  const helm = head === 'helm';
  const esc = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const names = (l: readonly string[]): string => l.map(esc).join('|');
  const legacy = helm ? '' : `|${KUBECTL_LEGACY_VALUE.source.slice(1, -1)}`;
  return {
    value: new RegExp(`^(${names(globalValues(head))}${legacy})$`),
    bool: new RegExp(`^(${names((helm ? HELM_GLOBAL_FLAG : KUBECTL_GLOBAL_FLAG).filter((x) => x !== '-h' && x !== '--help'))})$`),
  };
}

/* ------------------------------------------------------------------------------------------------------------- *
 * VERBS
 * ------------------------------------------------------------------------------------------------------------- */

/** every verb kubectl has, so a first word that is none of them is a PLUGIN */
export const KUBECTL_VERBS: ReadonlySet<string> = new Set([
  ...['get', 'describe', 'logs', 'top', 'explain', 'api-resources', 'api-versions', 'version', 'config', 'cluster-info', 'wait', 'diff', 'events', 'kustomize', 'completion', 'options', 'help', 'plugin', 'kuberc'],
  ...['apply', 'create', 'delete', 'patch', 'edit', 'scale', 'rollout', 'replace', 'drain', 'cordon', 'uncordon', 'taint', 'exec', 'cp', 'annotate', 'label', 'set', 'expose', 'run', 'autoscale', 'attach', 'port-forward', 'debug', 'certificate', 'proxy', 'auth', 'apply-set', 'alpha'],
]);
/** the verbs `oc` has beyond kubectl's */
const OC_READ = ['status', 'whoami', 'projects', 'process', 'observe', 'extract', 'image'];
const OC_ACT = [
  'adm', 'login', 'logout', 'project', 'new-app', 'new-build', 'new-project', 'start-build', 'cancel-build',
  'import-image', 'tag', 'policy', 'secrets', 'serviceaccounts', 'registry', 'rsh', 'rsync', 'idle', 'rollback',
];
const OC_VERBS: ReadonlySet<string> = new Set([...KUBECTL_VERBS, ...OC_READ, ...OC_ACT]);

/** Whether `verb` is a verb the tool itself has. Any other first word is a PLUGIN, which the tool RUNS with the words after it - `--help`
 *  among them: `kubectl foo --help` starts `kubectl-foo --help`. ONE answer, asked by this reader and by the help-probe reader. */
export function k8sHasVerb(head: string, verb: string): boolean {
  return (head === 'helm' ? HELM_VERBS : head === 'oc' ? OC_VERBS : KUBECTL_VERBS).has(verb);
}

export const HELM_VERBS: ReadonlySet<string> = new Set([
  ...['list', 'ls', 'status', 'get', 'history', 'hist', 'show', 'inspect', 'search', 'template', 'lint', 'version', 'env', 'dependency', 'dep', 'dependencies', 'diff', 'completion', 'help', 'verify'],
  ...['install', 'upgrade', 'uninstall', 'un', 'del', 'delete', 'rollback', 'push', 'test', 'repo', 'plugin', 'create', 'package', 'pull', 'fetch', 'registry'],
]);

/** the verbs that ACT. A verb is not a mutation in every subcommand it spells, nor with every flag (`--dry-run`,
 *  `set env --list`). `wait` blocks until a condition holds and changes nothing: it is not here. */
export const K8S_MUTATING_VERBS: ReadonlySet<string> = new Set([
  'apply', 'create', 'delete', 'patch', 'edit', 'scale', 'rollout', 'replace', 'drain', 'cordon', 'uncordon', 'taint',
  'exec', 'cp', 'annotate', 'label', 'set', 'expose', 'run', 'autoscale', 'attach', 'port-forward', 'debug',
  'certificate', 'proxy', 'auth', 'apply-set', 'alpha', 'kuberc', ...OC_ACT,
]);
/** `rollout` restarts and undoes - and it also REPORTS, with `status` and `history`; `auth` changes nothing in the
 *  `can-i` and `whoami` forms, which are the two commands an operator runs to find out what they may do */
export const K8S_READ_SUBCOMMANDS: Readonly<Record<string, ReadonlySet<string>>> = {
  rollout: new Set(['status', 'history']),
  auth: new Set(['can-i', 'whoami']),
  // `kubectl kuberc view` prints the preferences file; `set` writes it
  kuberc: new Set(['view']),
  certificate: new Set([]),
};
/** `dependency update|build` FETCHES remote charts into the chart directory, `helm pull` fetches one, and `helm repo add`
 *  records where later fetches come from: none of them touches the cluster, and all bring unreviewed content in */
export const HELM_MUTATING_VERBS: ReadonlySet<string> = new Set([
  ...['install', 'upgrade', 'uninstall', 'un', 'del', 'delete', 'rollback', 'push', 'test'],
  ...['dependency', 'dep', 'dependencies', 'repo', 'plugin', 'registry', 'pull', 'fetch'],
]);

/** the sub-verbs of `kubectl config` that write the kubeconfig, a credential store, without ever naming its path */
export const KUBECONFIG_WRITERS: ReadonlySet<string> = new Set([
  'set-credentials', 'set-cluster', 'set-context', 'rename-context', 'delete-context', 'delete-cluster', 'delete-user',
  'unset', 'set',
]);
/** the `helm get` sub-verbs that print the rendered release - and so whatever the chart templated: database URLs,
 *  tokens, the contents of every Secret it defines */
const HELM_GET_PRINTS = new Set(['values', 'all', 'manifest', 'notes', 'hooks']);

/* ------------------------------------------------------------------------------------------------------------- *
 * THE COMMAND LINE, PARSED ONCE
 * ------------------------------------------------------------------------------------------------------------- */

/** an option, the value of one, a word that MAY be the value of the option before it, an operand (or the verb), or a word
 *  after `--`, which is nobody's option */
type Role = 'option' | 'value' | 'maybe' | 'operand' | 'rest';

interface Parsed {
  head: string;
  words: readonly K8sWord[];
  roles: Role[];
  verbAt: number;
  verb: string | undefined;
  /** the first word is not a verb the tool has: it is a PLUGIN, and so is anything the tool cannot place in front of it */
  plugin: boolean;
  /** why: an option in front of the verb that is none of the persistent ones, or a word a shell fills in where the verb stands */
  unplaced: string | null;
  /** the first operand after the verb, for the verbs that have sub-verbs */
  sub: string | undefined;
  options: Array<{ at: number; shape: OptionShape; value?: K8sWord }>;
  /** the operands after the verb, in order */
  operands: number[];
}

const dynamic = (w: K8sWord): boolean => w.expands || /[$`]/.test(w.text);
const isOptionWord = (w: K8sWord): boolean => w.text.startsWith('-') && w.text.length > 1 && !/^-\d/.test(w.text);

/** the persistent options, in whichever spelling reaches here */
function isGlobalName(head: string, name: string): boolean {
  const helm = head === 'helm';
  if (globalValues(head).includes(name as never)) return true;
  if ((helm ? HELM_GLOBAL_FLAG : KUBECTL_GLOBAL_FLAG).includes(name as never)) return true;
  return !helm && KUBECTL_LEGACY_VALUE.test(name);
}

function parse(head: string, words: readonly K8sWord[]): Parsed {
  const p: Parsed = {
    head,
    words,
    roles: words.map(() => 'operand' as Role),
    verbAt: -1,
    verb: undefined,
    plugin: false,
    unplaced: null,
    sub: undefined,
    options: [],
    operands: [],
  };
  for (let i = 0; i < words.length; i++) {
    const w = words[i]!;
    if (w.text === '--') {
      for (let j = i; j < words.length; j++) p.roles[j] = 'rest';
      break;
    }
    if (isOptionWord(w)) {
      p.roles[i] = 'option';
      const shape = optionShape(head, p.verb, w.text);
      // IN FRONT OF THE VERB, cobra finds the command by skipping the words that are flags. A flag it does not know whole
      // (anything but the persistent options) it takes to have a value when it is spelled without `=`: it skips the NEXT
      // word, and when the flag has none that word is the verb, so the command it finds is another one - and kubectl hands
      // what it finds to a plugin of that name. So in front of the verb stand: a persistent option, an option glued to its
      // value (`--dry-run=client` is parsed by the verb that follows), and one KNOWN to take a value (`-o yaml get pods`)
      if (p.verbAt < 0 && !isGlobalName(head, shape.name) && shape.glued === undefined && shape.next !== 'yes') {
        p.unplaced ??= `an option, ${shape.name}, that ${head} does not have in front of its verb`;
        p.plugin = true;
      }
      const entry: { at: number; shape: OptionShape; value?: K8sWord } = { at: i, shape };
      if (shape.glued !== undefined) entry.value = { text: shape.glued, quoted: w.quoted, expands: w.expands };
      else if (shape.next !== 'no' && i + 1 < words.length && words[i + 1]!.text !== '--') {
        entry.value = words[i + 1]!;
        p.roles[i + 1] = shape.next === 'yes' ? 'value' : 'maybe';
        i++;
      }
      p.options.push(entry);
      continue;
    }
    if (p.verbAt < 0) {
      p.verbAt = i;
      p.verb = w.text;
      if (dynamic(w)) {
        // a word the shell fills in where the verb stands names nothing: it may be an option, a verb or a plugin
        p.plugin = true;
        p.unplaced ??= 'a word a shell fills in where the verb stands';
      } else if (!k8sHasVerb(head, w.text)) p.plugin = true;
      continue;
    }
    p.operands.push(i);
  }
  if (p.operands.length > 0) p.sub = words[p.operands[0]!]!.text;
  return p;
}

/* ------------------------------------------------------------------------------------------------------------- *
 * KUBECONFIG
 * ------------------------------------------------------------------------------------------------------------- */

interface KubeModel {
  contexts: Map<string, { cluster?: string; user?: string; namespace?: string }>;
  clusters: Map<string, { server?: string }>;
  users: Map<string, { program: boolean }>;
  current?: string;
}

const str = (v: YamlValue | undefined): string | undefined => (typeof v === 'string' ? v : undefined);
const asList = (v: YamlValue | undefined): Array<{ [k: string]: YamlValue }> =>
  Array.isArray(v) ? v.filter((x): x is { [k: string]: YamlValue } => typeof x === 'object' && x !== null && !Array.isArray(x)) : [];
const asMap = (v: YamlValue | undefined): { [k: string]: YamlValue } =>
  typeof v === 'object' && v !== null && !Array.isArray(v) ? v : {};

/** The contexts, clusters and users of a kubeconfig, or null when it cannot be read as one. A file this reader does not
 *  fully understand is not guessed at. */
function readKubeconfig(text: string): KubeModel | null {
  let doc: YamlValue;
  try {
    // a kubeconfig may be written as JSON (kubectl reads either; `kubectl config view -o json > kc.json` makes one), which is a document the
    // YAML reader of this kernel was not asked to take
    doc = text.trimStart().startsWith('{') ? (JSON.parse(text) as YamlValue) : parseYaml(text);
  } catch {
    return null;
  }
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) return null;
  const m: KubeModel = { contexts: new Map(), clusters: new Map(), users: new Map() };
  for (const c of asList(doc['clusters'])) {
    const name = str(c['name']);
    if (name === undefined) return null;
    const server = str(asMap(c['cluster'])['server']);
    m.clusters.set(name, server === undefined ? {} : { server });
  }
  for (const c of asList(doc['contexts'])) {
    const name = str(c['name']);
    if (name === undefined) return null;
    const x = asMap(c['context']);
    const entry: { cluster?: string; user?: string; namespace?: string } = {};
    const cluster = str(x['cluster']);
    const user = str(x['user']);
    const namespace = str(x['namespace']);
    if (cluster !== undefined) entry.cluster = cluster;
    if (user !== undefined) entry.user = user;
    if (namespace !== undefined) entry.namespace = namespace;
    m.contexts.set(name, entry);
  }
  for (const u of asList(doc['users'])) {
    const name = str(u['name']);
    if (name === undefined) return null;
    const x = asMap(u['user']);
    // a credential plugin: kubectl RUNS this program on every call, and so does an auth-provider that names a command
    const providerCmd = str(asMap(asMap(x['auth-provider'])['config'])['cmd-path']);
    m.users.set(name, { program: 'exec' in x || providerCmd !== undefined });
  }
  const current = str(doc['current-context']);
  if (current !== undefined && current !== '') m.current = current;
  return m;
}

/** THE OPTIONS A PREFERENCES FILE (kuberc) MAY GIVE A DEFAULT FOR WITHOUT CHOOSING A TARGET: what the output looks like, how a write is
 *  sent, how long a call may take. A positive list - a default for any option not here (`context`, `cluster`, `user`, `server`,
 *  `namespace`, `kubeconfig`, an impersonation, a token, an option nobody listed) can send the command somewhere the line does not
 *  name, and is a question. */
const KUBERC_INERT_OPTIONS = new Set([
  'output', 'o', 'server-side', 'force-conflicts', 'interactive', 'i', 'show-managed-fields', 'show-labels', 'no-headers', 'show-kind',
  'validate', 'wait', 'cascade', 'grace-period', 'field-manager', 'overwrite', 'save-config', 'recursive', 'R', 'prune', 'watch', 'w',
  'chunk-size', 'sort-by', 'timeout', 'dry-run', 'all', 'ignore-not-found', 'template', 'tail', 'since', 'timestamps', 'follow', 'f',
]);

/** Why a preferences file cannot be taken for one that leaves the target alone, or null when it can. */
function kubercProblem(f: K8sFile): string | null {
  if (f.state === 'outside') return 'is outside the workspace, which the kernel cannot read';
  if (f.state === 'absent') return 'is not there';
  if (f.state === 'dynamic') return 'is built at run time';
  if (f.state !== 'text') return 'cannot be read';
  if (f.stale === true) return 'may be rewritten by this command line before it is opened';
  let doc: YamlValue;
  try {
    doc = f.text.trimStart().startsWith('{') ? (JSON.parse(f.text) as YamlValue) : parseYaml(f.text);
  } catch {
    return 'is not a preferences file this reader understands';
  }
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) return 'is not a preferences file this reader understands';
  // (aliases are reached by a first word that is none of the tool's verbs, which already runs a plugin; the defaults and the overrides
  // are what changes a command that names its verb)
  for (const section of ['defaults', 'overrides']) {
    for (const entry of asList(doc[section])) {
      const options = entry['options'];
      if (options === undefined) continue;
      if (!Array.isArray(options)) return 'has options this reader does not understand';
      for (const o of options) {
        const name = typeof o === 'object' && o !== null && !Array.isArray(o) ? str(o['name']) : undefined;
        if (name === undefined || !KUBERC_INERT_OPTIONS.has(name.replace(/^-+/, '')))
          return `sets a default for ${name === undefined ? 'an option this reader cannot name' : `--${name.replace(/^-+/, '')}`}, which can choose where the command goes`;
      }
    }
  }
  return null;
}

/* ------------------------------------------------------------------------------------------------------------- *
 * THE EFFECT
 * ------------------------------------------------------------------------------------------------------------- */

const SEVERITY: Record<TargetClass, number> = { LOCAL: 0, UNCLASSIFIED: 1, EXTERNAL: 2, PRODUCTION: 3 };
interface Signal {
  cls: TargetClass;
  target: string;
}

/** the secret-bearing resource types: `secret`, `secrets`, `Secret`, `secrets.v1`, `secret.v1.` (and `secrets/db`, by its type) */
const SECRET_TYPE = /^secrets?(\.[A-Za-z0-9.-]*)?$/i;
/** a manifest that declares a Secret, in YAML or in JSON, anywhere in the text: over-matching costs one ask, missing it costs a credential */
const SECRET_KIND = /\bkind["']?\s*:\s*["']?Secret(List)?["']?(\s|,|}|$)/i;
/** the constructs with which a manifest can say `Secret` without spelling it where `SECRET_KIND` looks: an escape inside a
 *  string (`"S\u0065cret"`), an anchor or alias (`kind: *k`), a tag (`!!str`). A manifest that uses one is not known to
 *  declare no Secret, so it is read as one that might */
const MANIFEST_OBFUSCATION = /\\[uUx0-7]|(^|[\s:[{,-])[&*!][A-Za-z0-9_!]/;
const declaresSecret = (text: string): string | null =>
  SECRET_KIND.test(text) ? 'it declares a Secret' : MANIFEST_OBFUSCATION.test(text) ? 'it uses an escape, an anchor or a tag this reader does not follow' : null;
/** a listing reads this many files before the kernel gives up and treats the source as unread */
const MANIFEST_FILE_LIMIT = 64;
/** the output formats with which `helm status` prints the whole release object, manifest and values included */
const RELEASE_DUMP_FORMAT = /^(json|yaml)$/i;

export function k8sEffect(input: K8sInput, host: K8sHost): K8sEffect {
  const { head, words, env } = input;
  const plain = (cls: TargetClass, target: string, mutating: boolean): K8sEffect => ({
    cls,
    target,
    mutating,
    secret: null,
    kubeconfigDump: null,
    kubeconfigWrite: null,
    program: null,
    reads: [],
    unvouched: null,
  });
  // `kind` and `k3d` manage their OWN local clusters and are local by construction. minikube also carries kubectl:
  // `minikube kubectl -- ARGS` is kubectl with minikube's cluster as the default and every flag of kubectl after the
  // separator (r11-187), so it is read as kubectl whose AMBIENT cluster is local
  if (head === 'minikube') {
    const at = words.findIndex((w) => w.text === 'kubectl');
    const dd = words.findIndex((w) => w.text === '--');
    if (at >= 0 && (dd < 0 || at < dd)) {
      const rest = words.slice(at + 1);
      return k8sEffect(
        {
          ...input,
          head: 'kubectl',
          headWord: words[at]!,
          words: rest[0]?.text === '--' ? rest.slice(1) : rest,
          ambient: { cls: 'LOCAL', target: 'minikube' },
        },
        host,
      );
    }
    return plain('LOCAL', head, true);
  }
  if (head === 'kind' || head === 'k3d') return plain('LOCAL', head, true);
  // `kustomize build|cfg|fn` RENDERS: it reads kustomization.yaml and writes YAML to stdout, opening no kubeconfig and
  // contacting no cluster, so there is no target to be unclassified about
  if (head === 'kustomize') {
    const verb = words.find((w) => !isOptionWord(w))?.text ?? '';
    return /^(build|cfg|fn|version|edit)$/.test(verb)
      ? plain('LOCAL', 'a local render', false)
      : plain(input.ambient?.cls ?? 'UNCLASSIFIED', input.ambient?.target ?? 'the ambient kubeconfig context', true);
  }

  const p = parse(head, words);
  const { verb, sub } = p;
  const word = (i: number): K8sWord => p.words[i]!;
  /** every value of the options with these names, in every spelling */
  const opt = (...names: string[]): K8sWord[] =>
    p.options.filter((o) => names.includes(o.shape.name) && o.value !== undefined && p.roles[o.at] !== 'rest').map((o) => o.value!);
  const isFlagWord = (at: number): boolean => !words[at]!.quoted && p.roles[at] === 'option';

  /* ---- WHICH CLUSTER ------------------------------------------------------------------------------------------ */
  const signals: Signal[] = [];
  /** see K8sEffect.unvouched: the first reason found */
  let unvouched: string | null = null;
  const dyn = (w: K8sWord | string): boolean => (typeof w === 'string' ? /[$`]/.test(w) : dynamic(w));
  const textOf = (w: K8sWord | string): string => (typeof w === 'string' ? w : w.text);
  /** a name that a shell fills in is not a name: PRODUCTION if the part that is written says so, else unresolved */
  const hidden = (label: string, text: string): Signal => ({
    cls: host.productionMarked(text) ? 'PRODUCTION' : 'UNCLASSIFIED',
    target: label + text,
  });
  const named = (label: string, w: K8sWord | string): void => {
    signals.push(dyn(w) ? hidden(label, textOf(w)) : { cls: host.classifyName(textOf(w)), target: label + textOf(w) });
  };
  const server = (label: string, w: K8sWord | string): void => {
    signals.push(dyn(w) ? hidden(label, textOf(w)) : { cls: host.classifyServer(textOf(w)), target: label + textOf(w) });
  };
  if (p.unplaced !== null) signals.push({ cls: 'UNCLASSIFIED', target: p.unplaced });

  // THE KUBECONFIG FILES THE TOOL WILL READ. A string option given twice is applied ONCE - the last - so each `--kubeconfig` is a file of its
  // own and not part of a list; `KUBECONFIG` is the one that is a LIST, merged, and in it the first file that defines a name wins (K8-05:
  // `--kubeconfig a --kubeconfig b` was read as the pair, the first model answered, and the second file - the one kubectl dialled - was never
  // asked). Which of them the tool really uses is the tool's business: every one is read as the WORLD it could be, and the strictest decides.
  interface KubeFile {
    word: K8sWord | string;
    label: string;
  }
  const worldFiles: KubeFile[][] = [
    ...opt('--kubeconfig', ...(head === 'oc' ? ['--config'] : [])).map((w): KubeFile[] => [{ word: w, label: 'kubeconfig ' }]),
    ...(env['KUBECONFIG'] ?? []).map((v): KubeFile[] => v.split(':').filter(Boolean).map((f) => ({ word: f, label: 'KUBECONFIG=' }))),
  ];
  const worlds: KubeModel[][] = [];
  const absent: string[] = [];
  for (const files of worldFiles) {
    const models: KubeModel[] = [];
    worlds.push(models);
    for (const { word: fw, label } of files) {
      const name = textOf(fw);
      // (every file the kernel does not read is a kubeconfig nobody vouched for: it may name a credential plugin, or another server)
      if (dyn(fw)) {
        signals.push(hidden(label, name));
        unvouched ??= `${label}${name} is a kubeconfig a shell fills in`;
        continue;
      }
      // a path that says production is production, whatever the file holds
      if (host.productionMarked(name)) {
        signals.push({ cls: 'PRODUCTION', target: label + name });
        unvouched ??= `${label}${name} is a kubeconfig the kernel did not read`;
        continue;
      }
      const f = host.file(name);
      if (f.state === 'text') {
        const model = readKubeconfig(f.text);
        if (model === null) {
          signals.push({ cls: 'UNCLASSIFIED', target: `${label}${name} (not a kubeconfig this reader understands)` });
          unvouched ??= `${label}${name} is not a kubeconfig this reader understands`;
        } else models.push(model);
        // what is on the disk is the worst case it can be taken for, not the whole truth: it may be rewritten before the tool opens it
        if (f.stale === true) {
          signals.push({ cls: 'UNCLASSIFIED', target: `${label}${name} (this command line may rewrite it)` });
          unvouched ??= `${label}${name} may be rewritten by this command line before it is opened`;
        }
      } else if (f.state === 'outside') {
        // the workspace does not own it, so it says nothing about where a declared name points
        signals.push({ cls: 'EXTERNAL', target: label + name });
        unvouched ??= `${label}${name} is a kubeconfig outside the workspace, which the kernel cannot read`;
      } else if (f.state === 'absent') {
        absent.push(label + name);
        unvouched ??= `${label}${name} is not there`;
      } else {
        signals.push({ cls: 'UNCLASSIFIED', target: `${label}${name} (${f.state === 'fresh' ? 'this command line writes it' : 'it cannot be read'})` });
        unvouched ??= `${label}${name} cannot be read`;
      }
    }
  }
  const allModels = worlds.flat();
  /** the worlds a context, a cluster or a current-context is looked up in: one per file the line names, or the one with nothing in it */
  const eachWorld = (visit: (models: readonly KubeModel[]) => void): void => {
    for (const models of worlds.length > 0 ? worlds : [[]]) visit(models);
  };
  const selectedUsers = new Set<string>();
  const lookup = <T>(models: readonly KubeModel[], pick: (m: KubeModel) => T | undefined): T | undefined => {
    for (const m of models) {
      const found = pick(m);
      if (found !== undefined) return found;
    }
    return undefined;
  };
  /** a context, judged by its NAME and - where a kubeconfig the kernel read defines it - by the SERVER it points at: a
   *  context that points at a server that is not a declared local one is not local, whatever it is called */
  const context = (label: string, w: K8sWord | string): void => {
    named(label, w);
    if (dyn(w)) return;
    eachWorld((models) => {
      const def = lookup(models, (m) => m.contexts.get(textOf(w)));
      if (def === undefined) return;
      if (def.user !== undefined) selectedUsers.add(def.user);
      const url = lookup(models, (m) => (def.cluster === undefined ? undefined : m.clusters.get(def.cluster)))?.server;
      if (url === undefined) signals.push({ cls: 'UNCLASSIFIED', target: `${label}${textOf(w)} (its cluster names no server)` });
      else server(`${label}${textOf(w)} server `, url);
      if (def.cluster !== undefined && host.productionMarked(def.cluster)) signals.push({ cls: 'PRODUCTION', target: `cluster ${def.cluster}` });
      if (def.namespace !== undefined && host.productionMarked(def.namespace)) signals.push({ cls: 'PRODUCTION', target: `namespace ${def.namespace}` });
    });
  };

  const contextWords = [...opt('--context', '--kube-context')];
  const contextEnv = [...(env['HELM_KUBECONTEXT'] ?? []), ...(env['KUBE_CONTEXT'] ?? [])];
  for (const w of contextWords) context('context ', w);
  for (const v of contextEnv) context(head === 'helm' ? 'HELM_KUBECONTEXT=' : 'KUBE_CONTEXT=', v);
  // `kubectl config use-context X` re-points every later command at that cluster, as `docker context use` does
  const switchesContext = verb === 'config' && sub === 'use-context';
  if (switchesContext && p.operands[1] !== undefined) context('context use ', word(p.operands[1]));
  const contextNamed = contextWords.length > 0 || contextEnv.length > 0 || switchesContext;
  // no context named: the file's own current-context is the one used
  if (!contextNamed)
    for (const models of worlds)
      if (models.length > 0) {
        const current = lookup(models, (m) => m.current);
        if (current !== undefined) context('current-context ', current);
        else signals.push({ cls: 'UNCLASSIFIED', target: 'a kubeconfig that names no current context' });
      }
  // a kubeconfig that is not there yet names nothing that contradicts a context that is local by name. Anything else it
  // would have told us - no context at all, a context that is not local - is not local either
  if (!(contextNamed && signals.every((s) => s.cls === 'LOCAL'))) for (const label of absent) signals.push({ cls: 'EXTERNAL', target: label });

  // `--cluster` replaces the cluster the context names, `--user` the credentials: a name is judged like a context's
  for (const w of opt('--cluster')) {
    named('cluster ', w);
    if (!dyn(w))
      eachWorld((models) => {
        const url = models.length > 0 ? lookup(models, (m) => m.clusters.get(w.text))?.server : undefined;
        if (url !== undefined) server(`cluster ${w.text} server `, url);
      });
  }
  for (const w of [...opt('--user'), ...opt('--kube-as-user', '--as')]) {
    if (!dyn(w)) selectedUsers.add(w.text);
    // credentials are identity, not place: they only matter when the name says production, or when it is not a name
    if (host.productionMarked(w.text)) signals.push({ cls: 'PRODUCTION', target: `user ${w.text}` });
    else if (dyn(w)) signals.push({ cls: 'UNCLASSIFIED', target: `user ${w.text}` });
  }
  // A PREFERENCES FILE NAMED ON THE LINE CAN SET THE DEFAULT OF ANY FLAG, `--context` among them (K8-02: kubectl 1.36 with a kuberc whose
  // defaults give `context: prod-eu` dialled the production cluster while the kubeconfig's current-context said kind-dev). The file is read;
  // a default for an option that is known to leave the cluster and the credentials alone is ordinary, and anything else - a context, a
  // cluster, a user, a server, a namespace, another kubeconfig, an option nobody listed - is a target that was chosen out of sight
  if (head !== 'helm')
    for (const w of opt('--kuberc')) {
      const name = textOf(w);
      const marked = !dyn(w) && host.productionMarked(name);
      const why = dyn(w) ? 'is a preferences file a shell fills in' : marked ? 'is a preferences file the kernel did not read' : kubercProblem(host.file(name));
      if (why === null) continue;
      signals.push(marked ? { cls: 'PRODUCTION', target: `kuberc ${name}` } : { cls: 'UNCLASSIFIED', target: `kuberc ${name} (${why})` });
      unvouched ??= `kuberc ${name} ${why}`;
    }
  // (`-s` is the server of kubectl and the `--show-only` of helm template)
  // (an API server named HERE - on the line or in the environment - is not one the user's kubeconfig defines: unless it is a declared
  // local one, the credentials of the kubeconfig go to a host nobody vouched for)
  const endpoint = (label: string, w: K8sWord | string): void => {
    server(label, w);
    if (dyn(w) || host.classifyServer(textOf(w)) !== 'LOCAL') unvouched ??= `${label}${textOf(w)} is an API server named on the command line, not one a kubeconfig defines`;
  };
  for (const w of opt('--server', ...(head === 'helm' ? [] : ['-s']), '--kube-apiserver')) endpoint('server ', w);
  for (const name of ['KUBERNETES_MASTER', 'HELM_KUBEAPISERVER']) for (const v of env[name] ?? []) endpoint(`${name}=`, v);
  // in-cluster: the service host in the environment is where the API server is
  for (const v of env['KUBERNETES_SERVICE_HOST'] ?? []) endpoint('KUBERNETES_SERVICE_HOST=', v);
  for (const w of opt('--namespace', '-n')) if (host.productionMarked(w.text)) signals.push({ cls: 'PRODUCTION', target: `namespace ${w.text}` });
  for (const v of env['HELM_NAMESPACE'] ?? []) if (host.productionMarked(v)) signals.push({ cls: 'PRODUCTION', target: `HELM_NAMESPACE=${v}` });

  /* ---- WHAT RUNS --------------------------------------------------------------------------------------------- */
  const programs: string[] = [];
  if (p.plugin)
    programs.push(
      p.unplaced !== null
        ? `${head} was given ${p.unplaced}, so what it runs cannot be told`
        : `${head} ${verb ?? ''} is not a ${head} command, so it runs the plugin of that name`,
    );
  if (opt('--post-renderer').length > 0) programs.push('helm --post-renderer runs the program it names on every rendered manifest');
  // a credential plugin in a kubeconfig the kernel read, for the user the command selects (or, when nothing selects one,
  // for any user the file defines)
  const programUsers = allModels.flatMap((m) => [...m.users].filter(([, u]) => u.program).map(([n]) => n));
  if (programUsers.length > 0) {
    const picked = [...selectedUsers].filter((u) => programUsers.includes(u));
    if (picked.length > 0 || selectedUsers.size === 0)
      programs.push(`the kubeconfig names a credential plugin (${(picked.length > 0 ? picked : programUsers).join(', ')}) that ${head} runs on every call`);
  }

  /* ---- WHAT IS READ ------------------------------------------------------------------------------------------ */
  let secret: string | null = null;
  let kubeconfigDump: string | null = null;
  let kubeconfigWrite: string | null = null;
  if (head === 'helm') {
    const first = p.operands[0] !== undefined ? word(p.operands[0]) : undefined;
    if (verb === 'get' && first !== undefined && (dyn(first) || HELM_GET_PRINTS.has(first.text)))
      secret = `helm get ${first.text} prints the rendered release - the values, the manifest and every Secret the chart defines`;
    else if (verb === 'status' && opt('-o', '--output').some((w) => dyn(w) || RELEASE_DUMP_FORMAT.test(w.text)))
      secret = 'helm status -o json|yaml prints the whole release object, its manifest and values included';
  } else {
    if (verb === 'config' && sub === 'view') {
      // `--raw=false` is not `--raw`
      const dumps = p.options.some((o) => (o.shape.name === '--raw' || o.shape.name === '--flatten') && !(o.shape.glued !== undefined && /^(false|f|0)$/i.test(o.shape.glued)));
      if (dumps) kubeconfigDump = `${head} config view --raw|--flatten prints the kubeconfig with its client certificates and tokens`;
    } else if (verb === 'config' && sub !== undefined && KUBECONFIG_WRITERS.has(sub)) {
      kubeconfigWrite = `${head} config ${sub} writes the kubeconfig, which holds the credentials of every cluster the developer can reach`;
    }
    if (verb === 'get' || verb === 'describe' || verb === 'extract' || (verb === 'apply' && sub === 'view-last-applied'))
      secret = secretRead(p, host);
  }

  // the files an option value names as KEY=PATH: `--set-file a=.env` hands helm a file to inline, `--from-file=k=PATH` hands
  // kubectl one to store. Each is a read of that file, judged like any other
  const reads: Array<{ option: string; path: string }> = [];
  if (head === 'helm') {
    for (const w of opt('--set-file'))
      for (const pair of w.text.split(',')) reads.push({ option: '--set-file', path: pair.includes('=') ? pair.slice(pair.indexOf('=') + 1) : pair });
  } else {
    for (const w of opt('--from-file')) reads.push({ option: '--from-file', path: w.text.includes('=') ? w.text.slice(w.text.indexOf('=') + 1) : w.text });
    for (const w of opt('--from-env-file')) reads.push({ option: '--from-env-file', path: w.text });
  }

  /* ---- WHAT CHANGES ------------------------------------------------------------------------------------------ */
  let mutating: boolean;
  if (verb === undefined || p.plugin || switchesContext) mutating = true;
  else {
    const acts = (head === 'helm' ? HELM_MUTATING_VERBS : K8S_MUTATING_VERBS).has(verb);
    const readOnlySub = sub !== undefined && (K8S_READ_SUBCOMMANDS[verb]?.has(sub) ?? false);
    // `kubectl set env … --list` PRINTS the environment and sets nothing - and `--list` is the flag, never a word inside a
    // value (sa10-33): it counts only as an option of its own, written as one
    // ...and the LAST `--list` decides, as the last dry-run flag does: `--list --list=false` sets
    const lastList = [...p.options].reverse().find((o) => o.shape.name === '--list');
    const listing =
      input.written &&
      head !== 'helm' &&
      verb === 'set' &&
      sub === 'env' &&
      lastList !== undefined &&
      isFlagWord(lastList.at) &&
      (lastList.shape.glued === undefined || /^(true|t|1)$/i.test(lastList.shape.glued));
    const dry = input.written && host.dryRun(input.headWord, words);
    mutating = acts && !readOnlySub && !listing && !dry;
  }
  if (secret !== null) mutating = true;

  const w = signals.reduce<Signal | null>((a, b) => (a === null || SEVERITY[b.cls] > SEVERITY[a.cls] ? b : a), null);
  return {
    cls: w?.cls ?? input.ambient?.cls ?? 'UNCLASSIFIED',
    target: w?.target ?? input.ambient?.target ?? 'the ambient kubeconfig context',
    mutating,
    secret,
    kubeconfigDump,
    kubeconfigWrite,
    program: programs[0] ?? null,
    reads,
    unvouched,
  };
}

/** The words of `kubectl cp` / `oc cp` that name a file spec, in order: the operands after the verb, and the words an option of unknown
 *  arity may or may not have taken as its value. Null for any other command. THE ONE READER OF WHERE THE VERB'S OPERANDS ARE, for the
 *  evaluator's judge of the local side of a copy (copy-writes.ts). */
export function k8sCopyOperands(head: string, words: readonly K8sWord[]): string[] | null {
  if (head !== 'kubectl' && head !== 'oc') return null;
  const p = parse(head, words);
  if (p.verb !== 'cp' || p.plugin) return null;
  return p.words.filter((_, i) => i > p.verbAt && (p.roles[i] === 'operand' || p.roles[i] === 'maybe')).map((w) => w.text);
}

/** THE WORDS OF A kubectl COMMAND THAT NAME OBJECTS OF THE CLUSTER, and are therefore not paths: `deploy/$APP`, `pod/$P`, `svc/$SVC`, a pod
 *  called `$POD`, the `ns/pod:/path` of a file spec (K8-04: the generic scan of path-shaped words read `deploy/$APP` as a directory built
 *  at run time and asked, for the most ordinary scripted use of the tool). What a name is is the cluster's to answer, and k8s.ts answers it:
 *  a name a shell fills in is data, and the target it reaches is decided by the context, the cluster and the server. The words that ARE
 *  files stay the generic scan's: the value of `-f`, `--kubeconfig`, `--from-file`, the local side of a copy, a directory a verb renders. */
export function k8sObjectNames(head: string, words: readonly K8sWord[]): string[] {
  if (head !== 'kubectl' && head !== 'oc') return [];
  const p = parse(head, words);
  // a verb the tool does not have is a plugin, whose operands are anything; `kustomize DIR` renders a directory; `proxy` serves one; and
  // the verbs `oc` adds (`rsync`, `new-app ./dir`, `login URL`, `image mirror`) take paths and addresses
  if (p.verb === undefined || p.plugin || p.unplaced !== null || /^(kustomize|completion|plugin|proxy|alpha)$/.test(p.verb) || !KUBECTL_VERBS.has(p.verb)) return [];
  const optionValues = new Set(p.options.flatMap((o) => (o.value === undefined ? [] : [o.value.text])));
  const out: string[] = [];
  for (let i = p.verbAt + 1; i < words.length; i++) {
    if (p.roles[i] !== 'operand') continue;
    const text = words[i]!.text;
    // (the local side of a copy is a file; the side that holds `:` is `[namespace/]pod:path`, a name of the cluster)
    if (p.verb === 'cp' && !(text.indexOf(':') > 0)) continue;
    if (!optionValues.has(text)) out.push(text);
  }
  return out;
}

/** Whether the command prints a Secret: a resource type that is one, a type a shell fills in, the raw API, or a manifest
 *  the command is pointed at that declares one (or cannot be shown not to). */
function secretRead(p: Parsed, host: K8sHost): string | null {
  const what = `${p.head} ${p.verb ?? ''}`;
  // the words that can be a TYPE: the operands after the verb (after the sub-verb, for `apply view-last-applied`), and the
  // words an option of unknown arity may or may not have taken as its value
  const candidates = p.words
    .map((w, i) => ({ w, i }))
    .filter(({ i }) => i > p.verbAt && (p.roles[i] === 'maybe' || (p.roles[i] === 'operand' && !(p.verb === 'apply' && i === p.operands[0]))));
  // `get TYPE NAME…` names one type; `get TYPE/NAME TYPE/NAME…` names a type in every operand. And an option of unknown
  // arity in front of them may or may not have taken the first as its value, which moves the type to the second
  const listForm = candidates[0]?.w.text.includes('/') ?? false;
  const shifted = candidates.some(({ i }) => p.roles[i] === 'maybe');
  for (const [k, { w }] of candidates.entries()) {
    // ONLY THE TYPE POSITION HOLDS A TYPE. `get pod secrets` reads the pod called `secrets` and `get secrets` reads the Secrets:
    // the NAMES after the type are names, whatever they spell (wave 5, K8-03: a pod called `secrets-api` is not a credential read)
    if (!(k === 0 || listForm || shifted)) continue;
    const types = w.text.split(',').map((el) => el.split('/')[0]!);
    if (types.some((t) => SECRET_TYPE.test(t))) return `${what} ${w.text} prints a Secret`;
    // the TYPE of `pod/$NAME` is `pod`: a word that fills in only the name leaves the type written
    if (types.some((t) => /[$`]/.test(t)))
      return `the resource type of ${what} is a word a shell fills in, and it may name Secrets`;
  }
  // the raw API: a path that names secrets, or one a shell fills in
  for (const o of p.options) {
    if (o.shape.name !== '--raw' || o.value === undefined) continue;
    if (dynamic(o.value) || /secret/i.test(o.value.text)) return `${what} --raw ${o.value.text} reads the API directly, and may be the Secrets endpoint`;
  }
  // the sources: -f FILE|DIR|URL|-, -k DIR
  const recursive = p.options.some((o) => o.shape.name === '-R' || o.shape.name === '--recursive' || /^-[A-Za-z]*R[A-Za-z]*$/.test(p.words[o.at]!.text));
  for (const o of p.options.filter((x) => ['-f', '--filename', '-k', '--kustomize'].includes(x.shape.name))) {
    const kustomize = o.shape.name === '-k' || o.shape.name === '--kustomize';
    if (o.value === undefined) return `${what} reads manifests from a source it names no file for`;
    if (dynamic(o.value)) return `${what} reads a source a shell fills in, which may declare a Secret`;
    // a kustomization renders resources and generators the kernel does not follow
    if (kustomize) return `${what} -k renders a kustomization, which can generate Secrets`;
    const why = manifestSecret(o.value.text, recursive, host);
    if (why !== null) return `${what} -f ${o.value.text}: ${why}`;
  }
  return null;
}

/** Why the manifests a source names may declare a Secret; null when they are read and do not. */
function manifestSecret(source: string, recursive: boolean, host: K8sHost): string | null {
  if (source === '-') {
    const text = host.stdin();
    if (text === null) return 'standard input is not text this command line wrote';
    return declaresSecret(text);
  }
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(source)) return 'it is fetched from a URL, which is not read';
  const f = host.file(source);
  if (f.state === 'text') return declaresSecret(f.text) ?? (f.stale === true ? 'this command line may rewrite it' : null);
  if (f.state === 'absent') return null;
  if (f.state === 'unread') {
    const files = host.directory(source, recursive);
    if (files === null) return 'it cannot be read';
    if (files.length > MANIFEST_FILE_LIMIT) return 'it holds more manifests than are read';
    for (const g of files) {
      const gf = host.file(g);
      if (gf.state === 'text') {
        const why = declaresSecret(gf.text);
        if (why !== null) return `${g}: ${why}`;
        if (gf.stale === true) return `${g} may be rewritten by this command line`;
      } else if (gf.state !== 'absent') return `${g} cannot be read`;
    }
    return null;
  }
  return f.state === 'fresh' ? 'this command line writes it' : 'it cannot be read';
}
