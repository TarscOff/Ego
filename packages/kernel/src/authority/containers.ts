// THE CONTAINER-CLI READER: the one place that knows how docker, podman, nerdctl, compose, buildx, builder and bake
// are spelled, which verb a command line carries, which ENGINE it talks to, and what it BUILDS from.
//
// WHY ONE READER. The container tools were read in six places - the help-probe test, the global-option stripper, the
// engine resolver, the image detector, the bake reader and the Dockerfile reader - and each kept its own idea of
// where the verb sits. They drifted, always in the direction that released the act (exit review 11, 25 findings):
// `docker buildx -D build` put an option where the producer looked for `build`; `docker --context production 'exec'`
// made a quoted verb a non-verb for the probe test; `docker debug --host ssh://prod` left the engine flag past the
// point where the resolver stopped looking; `docker pass`, `docker logout` and `docker builder create --driver=remote`
// were verbs nobody had classified, so the catch-all ALLOW answered for them; `docker buildx bake` read one bake file
// and no compose file, no `--set`, no inline Dockerfile, and no output.
//
// WHAT IT IS. A grammar, not a list of spellings: the options of each program with their arity, the management
// groups with the options that belong to them, and a table of the verbs the product has DECIDED about. A verb in
// the table is MODELLED. A verb that is not - a plugin, a verb added next year, a word built at run time - is
// UNMODELLED, and an unmodelled verb is a question to the human (`command.unmodelled-closure`), never an ALLOW by
// default. An option whose arity is unknown where the verb belongs makes the verb unknowable, and that is said
// rather than guessed.
//
// Everything here is a pure function of the words of one command line, except `collectBuildInputs`, which takes the
// file system as a parameter: the evaluator's own readers (the workspace boundary, the freshness ledger) stay the
// only way a file is opened.
import { parseYaml, type YamlValue } from '../util/yaml.ts';

export type ContainerProgram =
  | 'docker'
  | 'podman'
  | 'nerdctl'
  | 'docker-compose'
  | 'podman-compose'
  | 'buildah'
  | 'colima'
  | 'lima';

/* ------------------------------------------------------------------------------------------------------------- *
 * A. OPTION GRAMMAR
 * ------------------------------------------------------------------------------------------------------------- */

export interface Grammar {
  /** options that consume a value: `--name` and `-x`, as written */
  readonly value: ReadonlySet<string>;
  /** options that take none */
  readonly bool: ReadonlySet<string>;
}

const words = (s: string): string[] => s.split(/\s+/).filter(Boolean);
const grammar = (value: string, bool: string): Grammar => ({ value: new Set(words(value)), bool: new Set(words(bool)) });
const union = (...gs: Grammar[]): Grammar => ({
  value: new Set(gs.flatMap((g) => [...g.value])),
  bool: new Set(gs.flatMap((g) => [...g.bool])),
});
const without = (g: Grammar, ...names: string[]): Grammar => ({
  value: new Set([...g.value].filter((n) => !names.includes(n))),
  bool: new Set([...g.bool].filter((n) => !names.includes(n))),
});
const EMPTY: Grammar = grammar('', '');

export interface ReadOption {
  /** where the option stands in the words that were read */
  at: number;
  /** every option the word spells: `-vt` is `-v` and `-t` */
  names: string[];
  /** the option that carries the value, or the last one */
  name: string;
  value: string | null;
  /** how many words it occupies: 1, or 2 when the value is the next word */
  length: number;
  /** false when the grammar does not know the option, so its arity is a guess */
  known: boolean;
  /** the value was glued to the option (`--name=value`, `-xVALUE`) */
  glued: boolean;
}

/** One option at `ws[i]`, read the way pflag/cobra (which every one of these CLIs uses) reads it: `--name=value`,
 *  `--name value` for an option that takes one, a cluster of short flags in which the first value-taking letter
 *  takes the rest of the word (`-Htcp://x`, `-H=tcp://x`) or else the next word. A bare `--name` that is not a known
 *  value option takes none: pflag does not give a boolean flag a space-separated value. */
export function readOption(ws: readonly string[], i: number, g: Grammar): ReadOption {
  const w = ws[i]!;
  if (w.startsWith('--')) {
    const eq = w.indexOf('=');
    const name = eq > 2 ? w.slice(0, eq) : w;
    const known = g.value.has(name) || g.bool.has(name);
    if (eq > 2) return { at: i, names: [name], name, value: w.slice(eq + 1), length: 1, known, glued: true };
    if (g.value.has(name)) {
      const v = ws[i + 1];
      return { at: i, names: [name], name, value: v ?? null, length: v === undefined ? 1 : 2, known: true, glued: false };
    }
    return { at: i, names: [name], name, value: null, length: 1, known, glued: false };
  }
  const letters = w.slice(1);
  const names: string[] = [];
  for (let k = 0; k < letters.length; k++) {
    const flag = `-${letters[k]}`;
    names.push(flag);
    if (g.value.has(flag)) {
      let rest = letters.slice(k + 1);
      if (rest.startsWith('=')) rest = rest.slice(1);
      if (rest !== '') return { at: i, names, name: flag, value: rest, length: 1, known: true, glued: true };
      const v = ws[i + 1];
      return { at: i, names, name: flag, value: v ?? null, length: v === undefined ? 1 : 2, known: true, glued: false };
    }
    if (!g.bool.has(flag)) return { at: i, names, name: flag, value: null, length: 1, known: false, glued: false };
  }
  return { at: i, names, name: names[names.length - 1] ?? w, value: null, length: 1, known: true, glued: false };
}

/* ------------------------------------------------------------------------------------------------------------- *
 * B. THE PROGRAMS: what stands in front of the verb
 * ------------------------------------------------------------------------------------------------------------- */

type EngineKind = 'engine' | 'context' | 'builder' | 'client configuration';

interface ProgramDef {
  root: Grammar;
  /** options that select the ENGINE, before the verb */
  engine: ReadonlyMap<string, EngineKind>;
  /** ...and the ones that still do after it. Global options are accepted past the verb (`docker ps -H tcp://prod`), but
   *  a SHORT letter is only the global option where the verb has no letter of its own: `-a` is nerdctl's address
   *  before the verb and `--all` after it, `-r` is podman's remote switch and nothing else. */
  afterVerb: ReadonlyMap<string, EngineKind>;
}

const DOCKER_ROOT = grammar(
  '--config -c --context -H --host -l --log-level --tlscacert --tlscert --tlskey',
  '-D --debug --tls --tlsverify -v --version -h --help',
);
// `-r/--remote` is a boolean (it switches to a connection named in a file), and `-c` is the connection where
// docker's is the context
const PODMAN_ROOT = grammar(
  '--cgroup-manager --conmon -c --connection --events-backend --hooks-dir --identity --imagestore --log-level --module ' +
    '--network-cmd-path --network-config-dir --out --root --runroot --runtime --runtime-flag --ssh --storage-driver ' +
    '--storage-opt --tmpdir --url -H --host --volumepath --cdi-spec-dir --config --context',
  '-r --remote --syslog --transient-store -h --help -v --version -D --debug',
);
const NERDCTL_ROOT = grammar(
  '-H --host -a --address -n --namespace --cgroup-manager --cni-netconfpath --cni-path --data-root --hosts-dir ' +
    '--host-gateway-ip --snapshotter --storage-driver --bridge-ip --cdi-spec-dirs --global-dns --global-dns-opts ' +
    '--global-dns-search --userns-remap',
  '--debug --debug-full --experimental --insecure-registry --kube-hide-dupe -h --help -v --version -D',
);
const COMPOSE_ROOT = grammar(
  '-f --file -p --project-name --project-directory --env-file --profile --parallel --progress --ansi',
  '--compatibility --dry-run --all-resources --verbose -v --version -h --help',
);
// the standalone compose clients carry the engine options themselves
const DOCKER_COMPOSE_ROOT = union(
  COMPOSE_ROOT,
  grammar('-H --host -c --context --tlscacert --tlscert --tlskey --log-level', '--no-ansi --skip-hostname-check --tls --tlsverify'),
);
const PODMAN_COMPOSE_ROOT = grammar(
  '-f --file -p --project-name --podman-path --podman-args --podman-pull-args --podman-push-args --podman-build-args ' +
    '--podman-inspect-args --podman-run-args --podman-start-args --podman-stop-args --podman-rm-args --podman-volume-args ' +
    '--pod-args --env-file --profile --parallel --in-pod -t --transform_policy',
  '--dry-run -v --version --no-ansi --no-cleanup --verbose -h --help',
);
const BUILDAH_ROOT = grammar(
  '--root --runroot --storage-driver --storage-opt --registries-conf --registries-conf-dir --short-name-alias-conf ' +
    '--cgroup-manager --log-level --runtime --runtime-flag --hooks-dir --tmpdir --userns-uid-map --userns-gid-map ' +
    '--userns-uid-map-user --userns-gid-map-group --default-mounts-file --network-config-dir --cni-config-dir --cni-plugin-path',
  '--debug -h --help -v --version',
);
const COLIMA_ROOT = grammar('-p --profile -r --runtime --cpu -c -m --memory -d --disk', '-h --help -v --verbose --version');

const engineMap = (...pairs: Array<[string, EngineKind]>): ReadonlyMap<string, EngineKind> => new Map(pairs);

const PROGRAMS: Readonly<Record<ContainerProgram, ProgramDef>> = {
  docker: {
    root: DOCKER_ROOT,
    engine: engineMap(['-H', 'engine'], ['--host', 'engine'], ['-c', 'context'], ['--context', 'context'], ['--config', 'client configuration'], ['--builder', 'builder']),
    afterVerb: engineMap(['-H', 'engine'], ['--host', 'engine'], ['-c', 'context'], ['--context', 'context'], ['--config', 'client configuration'], ['--builder', 'builder']),
  },
  podman: {
    root: PODMAN_ROOT,
    engine: engineMap(
      ['--url', 'engine'], ['-H', 'engine'], ['--host', 'engine'], ['-c', 'context'], ['--connection', 'context'],
      ['--context', 'context'], ['--remote', 'client configuration'], ['-r', 'client configuration'], ['--builder', 'builder'],
    ),
    afterVerb: engineMap(
      ['--url', 'engine'], ['-H', 'engine'], ['--host', 'engine'], ['-c', 'context'], ['--connection', 'context'],
      ['--context', 'context'], ['--remote', 'client configuration'], ['--builder', 'builder'],
    ),
  },
  nerdctl: {
    root: NERDCTL_ROOT,
    engine: engineMap(['-H', 'engine'], ['--host', 'engine'], ['-a', 'engine'], ['--address', 'engine'], ['--builder', 'builder']),
    afterVerb: engineMap(['-H', 'engine'], ['--host', 'engine'], ['--address', 'engine'], ['--builder', 'builder']),
  },
  'docker-compose': {
    root: DOCKER_COMPOSE_ROOT,
    engine: engineMap(['-H', 'engine'], ['--host', 'engine'], ['-c', 'context'], ['--context', 'context']),
    afterVerb: engineMap(['-H', 'engine'], ['--host', 'engine'], ['--context', 'context']),
  },
  'podman-compose': { root: PODMAN_COMPOSE_ROOT, engine: new Map(), afterVerb: new Map() },
  buildah: { root: BUILDAH_ROOT, engine: new Map(), afterVerb: new Map() },
  colima: { root: COLIMA_ROOT, engine: new Map(), afterVerb: new Map() },
  lima: { root: EMPTY, engine: new Map(), afterVerb: new Map() },
};

export const CONTAINER_PROGRAMS: ReadonlySet<string> = new Set(Object.keys(PROGRAMS));

/** the options a management group puts between its name and its verb: buildx's `--builder` and `-D`, compose's
 *  project options */
// (a docker CLI PLUGIN is given the words after its name, and the engine options among them are the same selection as the ones in front of
// it: `docker scout --context production quickview` reaches the production engine, and an option stood there whose arity nobody knows
// leaves the verb unplaced)
const PLUGIN_GROUP_OPTIONS = grammar('--context -c -H --host --config --builder', '-D --debug -h --help');
const GROUP_OPTIONS: Readonly<Record<string, Grammar>> = {
  buildx: grammar('--builder', '-D --debug -h --help'),
  builder: grammar('--builder', '-D --debug -h --help'),
  compose: COMPOSE_ROOT,
  scout: PLUGIN_GROUP_OPTIONS,
  model: PLUGIN_GROUP_OPTIONS,
  desktop: PLUGIN_GROUP_OPTIONS,
};

/* ------------------------------------------------------------------------------------------------------------- *
 * C. THE VERBS THE PRODUCT HAS DECIDED ABOUT
 *
 * A word in a table is MODELLED; every other word is not. Flags: r = a READ that stays harmless against a non-local
 * engine (`ps` lists, it does not deploy; `logs` and `inspect` are not here: they print the environment and the
 * mounts, which against a production engine is an act on it), c = hands the words after its first operand to a program
 * in a container (a `--help` there is that program's, and a global option there is not the CLI's), h = takes operands a
 * `--help` after them is not read as a probe, x = also takes a host command after `--`, b = builds, m = builds
 * only with `--build`, B = bake, d = destroys what it names, D = destroys with -v/--volumes/--rmi, p = publishes to a
 * registry, k = rewrites the credential store, n = changes which engine later commands will use.
 * ------------------------------------------------------------------------------------------------------------- */

interface Leaf {
  name: string;
  flags: string;
}

function leaves(src: string): ReadonlyMap<string, Leaf> {
  const out = new Map<string, Leaf>();
  const aliases: Array<[string, string]> = [];
  for (const item of words(src)) {
    const eq = item.indexOf('=');
    if (eq > 0) {
      aliases.push([item.slice(0, eq), item.slice(eq + 1)]);
      continue;
    }
    const colon = item.indexOf(':');
    const name = colon > 0 ? item.slice(0, colon) : item;
    out.set(name, { name, flags: colon > 0 ? item.slice(colon + 1) : '' });
  }
  for (const [alias, target] of aliases) {
    const leaf = out.get(target);
    if (leaf) out.set(alias, leaf);
  }
  return out;
}

const BUILDX_LEAVES = 'bake:B f=bake build:b b=build create:n du:r imagetools inspect ls:r prune:d rm:d remove=rm stop use:n version:r';

/** the verbs docker accepts without a group; most are the group's verb under its short name */
//
// WHAT A VERB PRINTS DECIDES WHETHER IT IS A LOOK (wave 5, CT-03). `r` is a read that stays harmless against a non-local engine
// because it prints NAMES AND NUMBERS: `ps`, `images`, `port`, `stats`, `events`, `diff`, `info`, `version`. `inspect` and `logs` print
// the environment, the mounts and whatever the container logged, and were left out of it for that reason - and `save` (every layer
// of an image), `history` (every build command, so every ARG and ENV a Dockerfile put a secret in) and `top` (every process's
// command line) print the same kind of thing and were in it. They are out of it now. `logout` removes a stored login: at most a
// question, never the absolute refusal that `login`, which WRITES a credential, is.
const DOCKER_TOP = leaves(
  'attach:hx build:b commit cp:h create:c diff:r events:r exec:cx export history images:r import info:r inspect kill load ' +
    'login:k logout:d logs pause port:r ps:r pull push:p rename restart rm:d rmi:d run:c save search:r start:h stats:r stop tag ' +
    'top unpause update version:r wait help:r bake:B init',
);
const PODMAN_TOP = leaves(
  'attach:hx build:b commit cp:h create:c diff:r events:r exec:cx export history images:r import info:r inspect kill load ' +
    'login:k logout:d logs pause port:r ps:r pull push:p rename restart rm:d rmi:d run:c save search:r start:h stats:r stop tag ' +
    'top unpause update version:r wait help:r untag completion checkpoint restore init',
);
const GROUPS: Readonly<Record<string, ReadonlyMap<string, Leaf>>> = {
  container: leaves(
    'attach:hx commit cp:h create:c diff:r exec:cx export inspect kill logs ls:r list=ls ps=ls pause port:r prune:d rename ' +
      'restart rm:d remove=rm run:c start:h stats:r stop top unpause update wait',
  ),
  image: leaves('build:b history import inspect load ls:r list=ls prune:d pull push:p rm:d remove=rm save tag'),
  volume: leaves('create inspect ls:r list=ls prune:d rm:d remove=rm update'),
  network: leaves('connect create disconnect inspect ls:r list=ls prune:d rm:d remove=rm'),
  system: leaves('df:r dial-stdio events:r info:r prune:d'),
  context: leaves('create:n export import:n inspect:r ls:r list=ls rm:d remove=rm show:r update:n use:n'),
  manifest: leaves('annotate create inspect push:p rm'),
  plugin: leaves('create disable enable inspect install ls:r list=ls push:p rm:d remove=rm set upgrade'),
  trust: leaves('inspect key revoke:p sign:p signer'),
  swarm: leaves('ca init join join-token leave unlock unlock-key update'),
  node: leaves('demote inspect ls:r list=ls promote ps rm:d remove=rm update'),
  service: leaves('create:c inspect logs ls:r list=ls ps:r rm:d remove=rm rollback scale update'),
  stack: leaves('config deploy:n up=deploy ls:r list=ls ps:r rm:d remove=rm down=rm services:r'),
  secret: leaves('create inspect ls:r list=ls rm:d remove=rm'),
  config: leaves('create inspect ls:r list=ls rm:d remove=rm'),
  checkpoint: leaves('create ls rm'),
  buildx: leaves(BUILDX_LEAVES),
  // docker's `builder` is buildx under another name; `docker builder bake|create|…` reach the plugin
  builder: leaves(BUILDX_LEAVES),
  compose: leaves(
    'attach:h build:b commit config:r convert=config cp:h create:cm down:D events:r exec:cx export images:r kill logs ls:r list=ls ' +
      'pause port:r ps:r publish:p pull push:p restart rm:d run:cm scale start stats:r stop top unpause up:m version:r volumes:r ' +
      'wait watch:b',
  ),
};
// THE DOCKER CLI PLUGINS (Docker 29) THAT ONLY LOOK. `docker scout`, `model` and `desktop` are verbs of the product as much as
// `compose` is, and a verb nobody modelled asked, so `docker scout quickview` and `docker desktop status` - the first things anyone
// runs - were questions (wave 5, CT-05). What is here is the part of each that reads; every other verb of the plugin (`scout enroll`,
// `model run`, `desktop stop`) is still a verb nobody decided about, and asks. `debug`, `pass`, `ai` and `extension` are not here at all.
const DOCKER_PLUGIN_GROUPS: Readonly<Record<string, ReadonlyMap<string, Leaf>>> = {
  scout: leaves('quickview:r cves:r recommendations:r compare:r sbom:r version:r help:r'),
  model: leaves('ls:r list=ls status:r inspect df:r version:r help:r'),
  desktop: leaves('status:r version:r logs help:r'),
};
const BUILDX_IMAGETOOLS = leaves('create:p inspect:r');

const DOCKER_GROUPS: Readonly<Record<string, ReadonlyMap<string, Leaf>>> = { ...GROUPS, ...DOCKER_PLUGIN_GROUPS };

// podman and nerdctl add groups of their own
const PODMAN_GROUPS: Readonly<Record<string, ReadonlyMap<string, Leaf>>> = {
  ...GROUPS,
  container: leaves(
    'attach:hx commit cp:h create:c diff:r exec:cx export inspect kill logs ls:r list=ls ps=ls pause port:r prune:d rename ' +
      'restart rm:d remove=rm run:c start:h stats:r stop top unpause update wait exists init checkpoint restore cleanup clone',
  ),
  image: leaves('build:b diff:r exists history import inspect load ls:r list=ls prune:d pull push:p rm:d remove=rm save tag untag'),
  healthcheck: leaves('run'),
  pod: leaves('clone create exists inspect kill logs pause prune:d ps:r ls=ps list=ps restart rm:d start stats stop top unpause'),
  machine: leaves('cp info:r init inspect list:r ls=list os reset:d rm:d set ssh:c start stop'),
  system: leaves('check df:r events:r info:r migrate prune:d renumber reset:d connection'),
  kube: leaves('apply down generate play'),
  play: leaves('kube'),
  generate: leaves('kube systemd'),
  volume: leaves('create exists export import inspect ls:r list=ls prune:d rm:d remove=rm unlock'),
};
const PODMAN_SYSTEM_CONNECTION = leaves('add:n default:n list:r ls=list remove:d rm=remove rename');
const NERDCTL_GROUPS: Readonly<Record<string, ReadonlyMap<string, Leaf>>> = {
  ...GROUPS,
  image: leaves('build:b convert decrypt encrypt history import inspect load ls:r list=ls prune:d pull push:p rm:d remove=rm save tag'),
  namespace: leaves('create inspect ls:r list=ls remove:d rm=remove update'),
};
const BUILDAH_TOP = leaves('build:b bud=build build-using-dockerfile=build');
const COMPOSE_TOP = GROUPS['compose']!;
const COLIMA_TOP = leaves(
  'status:r list:r ls=list version:r start stop restart ssh-config:r completion help:r delete:d prune:d template',
);

/* ------------------------------------------------------------------------------------------------------------- *
 * D. THE READER
 * ------------------------------------------------------------------------------------------------------------- */

export interface EngineSignal {
  /** how the engine was named; `client configuration` has no value (the file cannot be read from here) */
  kind: EngineKind | 'context use' | 'podman connection' | 'buildx driver' | 'buildx use';
  value: string | null;
  flag: string;
}

export interface ContainerCommand {
  program: ContainerProgram;
  /** the words after the program, trailing target-environment assignments removed */
  words: string[];
  /** the verb as the CLI parses it, aliases resolved: [], ['run'], ['container','run'], ['buildx','bake'], ['compose','up'] */
  path: string[];
  /** the word that names the management group, or -1 */
  groupAt: number;
  /** the word that is the verb, or -1 */
  verbAt: number;
  /** where the verb's own words begin in `words` */
  argsAt: number;
  /** false when an option of unknown arity stood where the verb belongs, so no word after it can be placed */
  determinate: boolean;
  /** the verb is one the product decided about */
  modelled: boolean;
  /** why it is not determinate or not modelled, for the reason string */
  why: string | null;
  /** the flags of the verb, `''` when unmodelled */
  flags: string;
  /** every way the command line names an engine, in the options that belong to the CLI (not to a container's argv) */
  engines: EngineSignal[];
  /** the options of the verb, up to the point where a program's own argv begins, and where each stands */
  options: ReadOption[];
  optionAt: number[];
  /** the operands of the verb - containers, images, the build context, services - up to the argv boundary */
  operands: string[];
  operandAt: number[];
  /** where a container's own argv begins in `words` (`docker run IMG HERE`), or -1 */
  carriedAt: number;
  /** the options that stood between the group and the verb (compose `-f`, buildx `--builder`), and the program's own */
  groupOptions: ReadOption[];
  rootOptions: ReadOption[];
  /** an option whose arity this grammar does not know stood among the verb's options */
  unknownOption: string | null;
  /** THE ASSIGNMENTS THAT ARE THIS PROCESS'S ENVIRONMENT: the ones in front of the program (`DOCKER_HOST=tcp://x docker ps`) and the
   *  ones the normalizer re-attached after its arguments. An assignment anywhere else is not: `docker run -e DOCKER_HOST=tcp://x alpine`
   *  is the CONTAINER's environment, and reading it as the engine's made every `-e` of that name an engine selection */
  environment: Array<{ name: string; value: string }>;
}

const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
const TRAILING_ENV = /^[A-Z][A-Z0-9_]*=/;
const assignmentOf = (word: string): Array<{ name: string; value: string }> => {
  const m = /^([A-Za-z_][A-Za-z0-9_]*)=([\s\S]*)$/.exec(word);
  return m ? [{ name: m[1]!, value: m[2]!.replace(/^(['"])([\s\S]*)\1$/, '$2') }] : [];
};

/** THE VARIABLES THAT SELECT WHICH ENGINE A CONTAINER TOOL TALKS TO, in ONE table - the same selection as the options of PROGRAMS above,
 *  by environment. The resolver reads the value of each by its kind, and the normalizer's list of the assignments it must re-attach to
 *  the segment is DERIVED from it, so a variable cannot be known to one and not to the other (wave 5, CT-01: `CONTAINER_CONNECTION`, the
 *  podman twin of `DOCKER_CONTEXT`, was in neither, and `export CONTAINER_CONNECTION=production; podman run` was ALLOW).
 *    engine    - the value is an endpoint: `tcp://`, `ssh://`, `unix://`, `npipe://`, `fd://`, or a socket path
 *    context   - the value is the name of a context or a connection
 *    builder   - the value is the name of a buildx builder
 *    client configuration - the value is a FILE or a DIRECTORY that holds the choice (the current context, the connection table, the
 *      builder instances, the credentials of a remote engine): it cannot be read from here, so an engine selected through it is not
 *      known to be the local one, and a verb that changes something asks */
export const CONTAINER_ENGINE_ENV: ReadonlyMap<string, EngineKind> = new Map<string, EngineKind>([
  ['DOCKER_HOST', 'engine'],
  ['CONTAINER_HOST', 'engine'],
  ['CONTAINERD_ADDRESS', 'engine'],
  ['DOCKER_CONTEXT', 'context'],
  ['CONTAINER_CONNECTION', 'context'],
  ['BUILDX_BUILDER', 'builder'],
  ['DOCKER_CONFIG', 'client configuration'],
  ['BUILDX_CONFIG', 'client configuration'],
  ['CONTAINERS_CONF', 'client configuration'],
  ['CONTAINERS_CONF_OVERRIDE', 'client configuration'],
  ['PODMAN_CONNECTIONS_CONF', 'client configuration'],
  ['NERDCTL_TOML', 'client configuration'],
  // the credentials of a remote engine: they only matter to one nobody named on the line
  ['DOCKER_CERT_PATH', 'client configuration'],
  ['DOCKER_TLS_VERIFY', 'client configuration'],
  ['DOCKER_TLS', 'client configuration'],
  ['CONTAINER_SSHKEY', 'client configuration'],
  ['CONTAINER_PASSPHRASE', 'client configuration'],
]);

/** The engine signals a command's own ENVIRONMENT carries: one per variable of the table that is set to something. */
export function environmentEngines(cmd: ContainerCommand): EngineSignal[] {
  const out: EngineSignal[] = [];
  for (const { name, value } of cmd.environment) {
    const kind = CONTAINER_ENGINE_ENV.get(name);
    // (a variable set to nothing is a variable that is not set: `DOCKER_CONFIG= docker ps` selects nothing)
    if (kind === undefined || value === '') continue;
    out.push({ kind, value: kind === 'client configuration' ? null : value, flag: name });
  }
  return out;
}

/** the engine options, as values, wherever the verb's own grammar does not know them */
const ENGINE_VALUES = grammar('-H --host --url --address --context --connection --builder --config', '');
const ENGINE_VALUES_C = grammar('-c', '');
/** a word that is itself an engine-selecting option, whatever stands before it */
const ENGINE_OPTION_WORD = /^(-H|--(host|context|url|connection|builder|config|address)(=|$))/;

function blank(program: ContainerProgram, ws: string[]): ContainerCommand {
  return {
    program,
    words: ws,
    path: [],
    groupAt: -1,
    verbAt: -1,
    argsAt: ws.length,
    determinate: true,
    modelled: true,
    why: null,
    flags: '',
    engines: [],
    options: [],
    optionAt: [],
    operands: [],
    operandAt: [],
    carriedAt: -1,
    groupOptions: [],
    rootOptions: [],
    unknownOption: null,
    environment: [],
  };
}

export function readContainerCommand(tokens: readonly string[]): ContainerCommand | null {
  let at = 0;
  while (at < tokens.length && ASSIGNMENT.test(tokens[at]!)) at++;
  const raw = tokens[at];
  if (raw === undefined) return null;
  const program = raw.slice(raw.lastIndexOf('/') + 1) as ContainerProgram;
  if (!Object.hasOwn(PROGRAMS, program)) return null;
  const def = PROGRAMS[program];
  let ws = tokens.slice(at + 1);
  // the normalizer re-attaches the target-selecting assignments it stripped at the END of the command, after the
  // arguments; they are environment, and they must not become an operand
  const environment = tokens.slice(0, at).flatMap(assignmentOf);
  while (ws.length && TRAILING_ENV.test(ws[ws.length - 1]!)) {
    environment.push(...assignmentOf(ws[ws.length - 1]!));
    ws = ws.slice(0, -1);
  }
  const cmd = blank(program, ws);
  cmd.environment = environment;
  const signal = (o: ReadOption, kind: EngineKind | undefined): void => {
    if (kind !== undefined) cmd.engines.push({ kind, value: kind === 'client configuration' ? null : o.value, flag: o.name });
  };
  const fail = (why: string): ContainerCommand => {
    cmd.determinate = false;
    cmd.modelled = false;
    cmd.why = why;
    return cmd;
  };
  const unmodelled = (path: string[], argsAt: number, why: string): ContainerCommand => {
    cmd.path = path;
    cmd.argsAt = argsAt;
    cmd.modelled = false;
    cmd.why = why;
    // A VERB NOBODY MODELLED STILL TALKS TO AN ENGINE, and the engine is classified FIRST: `docker debug --host
    // ssh://root@prod …` is an act on production whatever `debug` is. The global options are accepted past the verb,
    // so the words after it are searched for them, up to a `--` (what follows is the plugin's own command).
    for (let k = argsAt; k < ws.length; k++) {
      if (ws[k] === '--') break;
      if (!ws[k]!.startsWith('-')) continue;
      const o = readOption(ws, k, ENGINE_VALUES);
      const kind = def.afterVerb.get(o.name);
      if (kind !== undefined && o.known) {
        signal(o, kind);
        k += o.length - 1;
      }
    }
    return cmd;
  };

  // 1. the program's own options, up to the verb
  let i = 0;
  while (i < ws.length && ws[i]!.startsWith('-') && ws[i] !== '-' && ws[i] !== '--') {
    const o = readOption(ws, i, def.root);
    if (!o.known && !o.glued)
      return fail(`the option ${o.name} stands where the verb belongs and its arity is not known, so the verb cannot be placed`);
    cmd.rootOptions.push(o);
    signal(o, def.engine.get(o.name));
    i += o.length;
  }
  if (ws[i] === '--') return fail('a `--` stands where the verb belongs');
  if (i >= ws.length) return cmd; // `docker`, `docker --version`: the tool prints and does nothing
  const first = ws[i]!;
  cmd.verbAt = i;
  cmd.argsAt = i + 1;

  if (program === 'lima') {
    // `lima CMD` runs CMD in the default VM; `lima nerdctl …` is nerdctl in it, with the VM's own engine
    if (/^(nerdctl|docker|podman)$/.test(first)) {
      const inner = readContainerCommand(ws.slice(i));
      if (inner) {
        // (the variables set in front of `lima` are the inner tool's environment too)
        inner.environment = [...cmd.environment, ...inner.environment];
        return inner;
      }
    }
    return unmodelled([first], i + 1, `lima runs ${first} inside a virtual machine`);
  }

  const groups = program === 'podman' ? PODMAN_GROUPS : program === 'nerdctl' ? NERDCTL_GROUPS : program === 'docker' ? DOCKER_GROUPS : GROUPS;
  const standaloneCompose = program === 'docker-compose' || program === 'podman-compose';
  const top =
    program === 'buildah'
      ? BUILDAH_TOP
      : standaloneCompose
        ? COMPOSE_TOP
        : program === 'colima'
          ? COLIMA_TOP
          : program === 'podman'
            ? PODMAN_TOP
            : DOCKER_TOP;
  const label = (...p: string[]): string => `${program} ${p.join(' ')}`.trim();

  if (standaloneCompose) {
    const leaf = top.get(first);
    if (!leaf) return unmodelled(['compose', first], i + 1, `${label(first)} is not a verb this kernel models`);
    cmd.path = ['compose', leaf.name];
    cmd.flags = leaf.flags;
    return finish(cmd, def);
  }
  const topLeaf = top.get(first);
  if (topLeaf && !Object.hasOwn(groups, first)) {
    cmd.path = first === 'bake' ? ['buildx', 'bake'] : program === 'buildah' ? ['build'] : [first];
    cmd.flags = topLeaf.flags;
    return finish(cmd, def);
  }
  if (!Object.hasOwn(groups, first)) return unmodelled([first], i + 1, `${label(first)} is not a verb this kernel models (a plugin, a new verb, or a word built at run time)`);

  // 2. a management group: its own options, then its verb
  const group = first;
  cmd.groupAt = i;
  const gopts = GROUP_OPTIONS[group] ?? EMPTY;
  let j = i + 1;
  while (j < ws.length && ws[j]!.startsWith('-') && ws[j] !== '-' && ws[j] !== '--') {
    const o = readOption(ws, j, gopts);
    if (!o.known && !o.glued) {
      if (/^(-h|--help)$/.test(o.name)) {
        j += o.length;
        continue;
      }
      return fail(`the option ${o.name} stands between \`${group}\` and its verb and its arity is not known`);
    }
    cmd.groupOptions.push(o);
    signal(o, def.engine.get(o.name));
    j += o.length;
  }
  const verbWord = ws[j];
  if (verbWord === undefined) {
    cmd.path = [group];
    cmd.argsAt = ws.length;
    return cmd; // `docker compose`, `docker buildx --help`: prints its help
  }
  cmd.verbAt = j;
  const table = groups[group]!;
  const leaf = table.get(verbWord);
  if (!leaf) return unmodelled([group, verbWord], j + 1, `${label(group, verbWord)} is not a verb this kernel models`);
  // buildx and builder are one tool; `b` and `f` are the short names of `build` and `bake`
  const canonGroup = group === 'builder' ? 'buildx' : group;
  const canonVerb = canonGroup === 'buildx' || canonGroup === 'compose' ? leaf.name : verbWord;
  if (canonGroup === 'buildx' && leaf.name === 'imagetools') {
    const sub = ws[j + 1];
    const subLeaf = sub === undefined ? undefined : BUILDX_IMAGETOOLS.get(sub);
    if (!subLeaf) return unmodelled(['buildx', 'imagetools', sub ?? ''], j + 2, `${label(group, 'imagetools', sub ?? '')} is not a verb this kernel models`);
    cmd.path = ['buildx', 'imagetools', subLeaf.name];
    cmd.flags = subLeaf.flags;
    cmd.argsAt = j + 2;
    return finish(cmd, def);
  }
  if (program === 'podman' && group === 'system' && verbWord === 'connection') {
    const sub = ws[j + 1];
    const subLeaf = sub === undefined ? undefined : PODMAN_SYSTEM_CONNECTION.get(sub);
    if (!subLeaf) return unmodelled(['system', 'connection', sub ?? ''], j + 2, `${label('system connection', sub ?? '')} is not a verb this kernel models`);
    cmd.path = ['system', 'connection', subLeaf.name];
    cmd.flags = subLeaf.flags;
    cmd.argsAt = j + 2;
    return finish(cmd, def);
  }
  cmd.path = [canonGroup, canonVerb];
  cmd.flags = leaf.flags;
  cmd.argsAt = j + 1;
  return finish(cmd, def);
}

/** the verb's own words: options and operands, up to the point where a program's argv begins */
function finish(cmd: ContainerCommand, def: ProgramDef): ContainerCommand {
  const ws = cmd.words;
  const last = cmd.path[cmd.path.length - 1] ?? '';
  const carries = cmd.flags.includes('c');
  // `-c` is docker's context everywhere except where the verb has a `-c` of its own (cpu shares)
  const localC = /^(run|create|build|update)$/.test(last) || cmd.flags.includes('b');
  const g = union(verbGrammar(cmd), ENGINE_VALUES, localC ? EMPTY : ENGINE_VALUES_C);
  for (let i = cmd.argsAt; i < ws.length; i++) {
    const w = ws[i]!;
    if (w === '--') {
      if (carries && cmd.carriedAt < 0) cmd.carriedAt = i + 1;
      break;
    }
    if (w.startsWith('-') && w !== '-') {
      let o = readOption(ws, i, g);
      // AN ENGINE OPTION IS NEVER SOMEBODY'S VALUE. This table gives a letter one meaning for every verb that shares it, and
      // `-t` is a timeout for `stop` and a switch for `logs`, `-s` a signal for `kill` and a switch for `ps`: where the
      // guess is wrong the next word is swallowed, and when that word is `-H` the engine is never seen
      if (o.length === 2 && o.value !== null && ENGINE_OPTION_WORD.test(o.value))
        o = { ...o, value: null, length: 1 };
      cmd.options.push(o);
      cmd.optionAt.push(i);
      if (!o.known && !o.glued && cmd.unknownOption === null) cmd.unknownOption = o.name;
      const kind = def.afterVerb.get(o.name);
      if (kind !== undefined && !(o.name === '-c' && localC))
        cmd.engines.push({ kind, value: kind === 'client configuration' ? null : o.value, flag: o.name });
      i += o.length - 1;
      continue;
    }
    cmd.operands.push(w);
    cmd.operandAt.push(i);
    // a program's argv begins after the first operand: `docker run IMAGE CMD…`, `docker exec CONTAINER CMD…`,
    // `docker compose run SERVICE CMD…`. What follows is that program's, not the CLI's.
    if (carries && cmd.operands.length === 1) {
      cmd.carriedAt = i + 1;
      break;
    }
  }
  // the verb binds the engine for later commands, and its operands name it
  if (cmd.flags.includes('n')) {
    if (cmd.path[0] === 'context' && last === 'use' && cmd.operands[0] !== undefined)
      cmd.engines.push({ kind: 'context use', value: cmd.operands[0], flag: 'use' });
    else if (cmd.path[0] === 'system' && cmd.path[1] === 'connection')
      for (const o of cmd.operands) cmd.engines.push({ kind: 'podman connection', value: o, flag: last });
    else if (cmd.path[0] === 'buildx' && last === 'use' && cmd.operands[0] !== undefined)
      cmd.engines.push({ kind: 'buildx use', value: cmd.operands[0], flag: 'use' });
    else if (cmd.path[0] === 'buildx' && last === 'create') {
      // a builder bound to an ENDPOINT - `create --driver remote tcp://…`, but also `create ssh://prod` with the
      // default driver, where the endpoint is the docker host the container driver runs on - sends every later
      // build there with no flag naming it
      const driver = cmd.options.find((o) => o.name === '--driver');
      const remote = driver !== undefined && /^(remote|kubernetes)$/.test(driver.value ?? '');
      if (cmd.operands.length) for (const o of cmd.operands) cmd.engines.push({ kind: 'buildx driver', value: o, flag: 'create' });
      else if (remote) cmd.engines.push({ kind: 'buildx driver', value: 'an unnamed remote endpoint', flag: 'create' });
    }
  }
  return cmd;
}

/** The operands of a COPY verb (`cp`, `container cp`, `compose cp`, `machine cp`), or null for any other command: the file specs the
 *  verb names, in order, with the options and the words of a program's argv taken out. */
export function copyOperands(cmd: ContainerCommand): string[] | null {
  if (!cmd.determinate || !cmd.modelled || cmd.path[cmd.path.length - 1] !== 'cp') return null;
  return cmd.operands;
}

/** does the verb change which engine later commands use, or write a name-to-engine binding */
export function bindsEngine(cmd: ContainerCommand): boolean {
  return cmd.modelled && cmd.flags.includes('n');
}

/** may the verb be tolerated against a NON-LOCAL engine without being an act on it */
export function isEngineRead(cmd: ContainerCommand): boolean {
  return cmd.determinate && cmd.modelled && cmd.path.length > 0 && cmd.flags.includes('r');
}

/** does the verb hand words to a program in a container, so that a `--help` there is that program's */
export function carriesArgv(cmd: ContainerCommand): boolean {
  return !cmd.determinate || !cmd.modelled || cmd.flags.includes('c') || cmd.flags.includes('h');
}

/** the command a verb takes after `--` and runs: `exec`, `attach`, `compose exec`, and any verb nobody modelled
 *  (`docker pass run -- psql …`, where the plugin runs what follows with secrets in its environment) */
export function carriedHostCommand(cmd: ContainerCommand): string[] | null {
  if (cmd.modelled && !cmd.flags.includes('x')) return null;
  const dd = cmd.words.indexOf('--', Math.max(cmd.argsAt, 0));
  return dd >= 0 && dd + 1 < cmd.words.length ? cmd.words.slice(dd + 1) : null;
}

/* ------------------------------------------------------------------------------------------------------------- *
 * E. THE VERB OPTION GRAMMARS THAT NEED AN ARITY
 *
 * Options that matter to a question asked here (where the argv begins, what the build context is) have their arity
 * written down; any other option is read as taking no value, and `unknownOption` says so when it was seen, which
 * the build reader treats as "the context cannot be placed".
 * ------------------------------------------------------------------------------------------------------------- */

const PASSIVE = grammar(
  '--format --filter -n --tail --since --until --time -t --signal -s --detach-keys --user -u --workdir -w --env -e --env-file ' +
    '--label -l --name --network --platform --pull --restart --limit --index --scale --timeout',
  '-a --all -q --quiet --no-trunc --json -d --detach -i --interactive --privileged --rm -T --no-TTY --force -f --follow --timestamps ' +
    '-v --volumes --help -h -p --pretty --size --latest',
);
const EXEC_OPTIONS = grammar(
  '--detach-keys -e --env --env-file -u --user -w --workdir --index',
  '-d --detach -i --interactive --privileged -t --tty -T --no-TTY --no-tty',
);
const RUN_OPTIONS = grammar(
  '--add-host -a --attach --annotation --blkio-weight --blkio-weight-device --cap-add --cap-drop --cgroup-parent --cgroupns --cidfile ' +
    '--cpu-period --cpu-quota --cpu-rt-period --cpu-rt-runtime -c --cpu-shares --cpus --cpuset-cpus --cpuset-mems --detach-keys ' +
    '--device --device-cgroup-rule --device-read-bps --device-read-iops --device-write-bps --device-write-iops --dns --dns-option ' +
    '--dns-search --domainname --entrypoint -e --env --env-file --expose --gpus --group-add --health-cmd --health-interval ' +
    '--health-retries --health-start-interval --health-start-period --health-timeout -h --hostname --ip --ip6 --ipc --isolation ' +
    '--kernel-memory -l --label --label-file --link --link-local-ip --log-driver --log-opt --mac-address -m --memory ' +
    '--memory-reservation --memory-swap --memory-swappiness --mount --name --network --network-alias --oom-score-adj --pid ' +
    '--pids-limit --platform -p --publish --restart --runtime --security-opt --shm-size --stop-signal --stop-timeout ' +
    '--storage-opt --sysctl --tmpfs --ulimit -u --user --userns --uts -v --volume --volume-driver --volumes-from -w --workdir ' +
    '--arch --authfile --cgroup-conf --chrootdirs --conmon-pidfile --creds --decryption-key --env-merge --gidmap --uidmap ' +
    '--group-entry --hostuser --image-volume --init-path --pod --pod-id-file --preserve-fd --preserve-fds --retry --retry-delay ' +
    '--rootfs --sdnotify --seccomp-policy --secret --subgidname --subuidname --timeout --umask --unsetenv --variant --os --passwd-entry ' +
    '--personality --userns-gid-map --userns-uid-map --net --cpu-count --cpu-percent --io-maxbandwidth --io-maxiops --pull',
  '-d --detach --init -i --interactive --no-healthcheck --oom-kill-disable --privileged -P --publish-all -q --quiet --read-only --rm ' +
    '--sig-proxy -t --tty --disable-content-trust --replace --http-proxy --tls-verify --no-hosts --passwd --read-only-tmpfs --systemd ' +
    '--env-host --unsetenv-all -h --help --help-all --use-api-socket',
);
// (`--pull` of `run` and `create` TAKES a policy - `always`, `missing`, `never` - in docker, podman and nerdctl alike. It stood in the
// switches, so `podman run --pull always --connection production alpine` read `always` as the image and the engine option behind it
// as the container's own words: wave 5, CT-07. `build`'s `--pull` is a switch in docker, and stays one in BUILD_OPTIONS below.)
// every option of `build`, `buildx build`, `podman build`, `nerdctl build` and `buildah build`. `--pull` and `--push`
// are booleans: pflag does not give a boolean a space-separated value.
const BUILD_OPTIONS = grammar(
  '--add-host --allow --annotation --attest --build-arg --build-arg-file --build-context --builder --cache-from --cache-to ' +
    '--call --cap-add --cap-drop --cert-dir --cgroup-parent --cgroupns --cpp-flag --cpu-period --cpu-quota -c --cpu-shares ' +
    '--cpuset-cpus --cpuset-mems --creds --decryption-key --device --dns --dns-option --dns-search -e --env -f --file ' +
    '--format --from --group-add --hooks-dir --iidfile --ignorefile --ipc --isolation -j --jobs --label --logfile -m ' +
    '--memory --memory-swap --manifest --metadata-file --network --no-cache-filter --os --os-feature --os-version -o ' +
    '--output --pid --platform --progress --provenance --retry --retry-delay --runtime --runtime-flag --sbom --secret ' +
    '--security-opt --shm-size --sign-by --source-date-epoch --ssh -t --tag --target --timestamp --ulimit --unsetenv ' +
    '--unsetlabel --userns --userns-gid-map --userns-gid-map-group --userns-uid-map --userns-uid-map-user --uts ' +
    '--variant -v --volume --arch --authfile --buildkit-host --network-alias --config --pull-policy --builder-opt --subid-ignore',
  '--check --compress --disable-compression --disable-content-trust --force-rm --http-proxy --identity-label --layers --load ' +
    '--no-cache --no-hosts --omit-history --pull --pull-always --pull-never --push -q --quiet --rm --skip-unused-stages ' +
    '--squash --squash-all --stdin --tls-verify -D --debug --verbose -h --help --ipfs --no-rm',
);
const BAKE_OPTIONS = grammar(
  '-f --file --set --builder --metadata-file --progress --provenance --sbom --allow --call --list --cap-add',
  '--check --load --no-cache --print --pull --push -D --debug -h --help --dry-run -q --quiet',
);
function composeVerbGrammar(verb: string): Grammar {
  // `-f` is the compose file before the verb and after it, except where the verb has an `-f` of its own: `logs -f`
  // follows, `rm -f` forces
  const root = /^(logs|rm|ls|events)$/.test(verb) ? without(COMPOSE_ROOT, '-f') : COMPOSE_ROOT;
  switch (verb) {
    case 'build':
      return union(root, grammar('--build-arg -m --memory --provenance --sbom --ssh --builder', '--push --pull --no-cache -q --quiet --with-dependencies --check'));
    case 'up':
    case 'create':
      return union(
        root,
        grammar(
          '--scale -t --timeout --exit-code-from --attach --no-attach --pull --wait-timeout --abort-on-container-exit-code',
          '--build --no-build -d --detach --abort-on-container-exit --abort-on-container-failure --wait --watch --menu -V --renew-anon-volumes --remove-orphans --force-recreate --no-recreate --no-deps --no-color --no-log-prefix --no-start --timestamps --attach-dependencies --always-recreate-deps --quiet-pull --quiet-build -y --yes',
        ),
      );
    case 'run':
      return union(
        root,
        grammar(
          '-e --env -l --label -p --publish -u --user -v --volume -w --workdir --name --entrypoint --cap-add --cap-drop --pull',
          '--build -d --detach --no-deps --rm -i -T --no-TTY --service-ports -P --use-aliases --interactive --quiet-pull --quiet-build -q --quiet',
        ),
      );
    case 'down':
      return union(root, grammar('--rmi -t --timeout', '-v --volumes --remove-orphans'));
    case 'exec':
      return union(root, EXEC_OPTIONS);
    default:
      return union(root, grammar('-t --timeout --tail -n --since --until --index --format --filter', '-f --follow -d --detach -a --all -q --quiet'));
  }
}
const BUILDX_CREATE = grammar(
  '--buildkitd-config --buildkitd-flags --config --driver --driver-opt --name --node --platform',
  '--append --bootstrap --leave --use --default',
);
const BUILDX_MISC = grammar(
  '--filter --format --keep-storage --builder',
  '-a --all --all-inactive -f --force --keep-state --verbose --bootstrap --default --global --json --pretty',
);
function verbGrammar(cmd: ContainerCommand): Grammar {
  const last = cmd.path[cmd.path.length - 1] ?? '';
  if (cmd.flags.includes('B')) return BAKE_OPTIONS;
  if (cmd.path[0] === 'buildx' && !cmd.flags.includes('b')) return last === 'create' ? BUILDX_CREATE : BUILDX_MISC;
  if (cmd.path[0] === 'compose') return composeVerbGrammar(last);
  if (cmd.flags.includes('b')) return BUILD_OPTIONS;
  if (/^(run|create)$/.test(last) && cmd.flags.includes('c')) return RUN_OPTIONS;
  if (last === 'exec') return EXEC_OPTIONS;
  return PASSIVE;
}

/* ------------------------------------------------------------------------------------------------------------- *
 * F. WHAT A BUILD PRODUCES: outputs, caches, secrets - the same reading for a flag and for a file
 * ------------------------------------------------------------------------------------------------------------- */

export type BuildEffect =
  | { kind: 'push'; ref: string }
  | { kind: 'write'; dest: string }
  | { kind: 'read'; src: string }
  | { kind: 'isolation'; what: string }
  | { kind: 'gap'; why: string };

/** the CSV `key=value,key=value` form every buildx output, cache and secret flag takes */
function csv(spec: string): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  let cur = '';
  let quoted = false;
  const fields: string[] = [];
  for (const ch of spec) {
    if (ch === '"') quoted = !quoted;
    else if (ch === ',' && !quoted) {
      fields.push(cur);
      cur = '';
    } else cur += ch;
  }
  fields.push(cur);
  for (const f of fields) {
    const eq = f.indexOf('=');
    out.push(eq < 0 ? [f, ''] : [f.slice(0, eq).trim(), f.slice(eq + 1)]);
  }
  return out;
}

const isDynamic = (v: string): boolean => /[$`]|\$\{/.test(v);

/** What an `--output` / bake `output` value does. `-o PATH` is `type=local,dest=PATH`; `type=registry` and
 *  `push=true` publish; a local, tar or oci destination is a host file WRITE; a type this reader does not know is a
 *  gap, because an output that goes somewhere unnamed is a write nobody judged. */
export function outputEffects(spec: string): BuildEffect[] {
  const trimmed = spec.trim();
  if (trimmed === '' || trimmed === '-') return [];
  const fields = csv(trimmed);
  const first = fields[0]!;
  // a bare word with no `=` is a directory: `-o out` is `type=local,dest=out`
  if (fields.length === 1 && !trimmed.includes('=')) return isDynamic(trimmed) ? [{ kind: 'gap', why: `the output destination ${trimmed} is built at run time` }] : [{ kind: 'write', dest: trimmed }];
  void first;
  const kv = new Map(fields);
  const type = kv.get('type');
  const dest = kv.get('dest');
  const effects: BuildEffect[] = [];
  const name = kv.get('name') ?? kv.get('ref') ?? 'build-output';
  const pushes = kv.get('push') === 'true' || kv.get('push') === '1' || kv.has('push-by-digest') && kv.get('push-by-digest') !== 'false';
  if (type === undefined) return [{ kind: 'gap', why: `the output ${trimmed} names no type` }];
  if (isDynamic(trimmed)) return [{ kind: 'gap', why: `the output ${trimmed} is built at run time` }];
  switch (type) {
    case 'registry':
      effects.push({ kind: 'push', ref: name });
      break;
    case 'image':
      if (pushes) effects.push({ kind: 'push', ref: name });
      break;
    case 'docker':
    case 'oci':
    case 'tar':
    case 'local':
      if (dest !== undefined && dest !== '-' && dest !== '') effects.push({ kind: 'write', dest });
      else if (type === 'local') effects.push({ kind: 'gap', why: 'a local output names no destination' });
      break;
    case 'cacheonly':
      break;
    default:
      effects.push({ kind: 'gap', why: `the output type ${type} is not one this kernel models` });
  }
  if (pushes && type !== 'image' && type !== 'registry') effects.push({ kind: 'push', ref: name });
  return effects;
}

/** What a cache destination does: a registry or a remote cache service is a publication, a local one a host write,
 *  `inline` travels inside the image. */
export function cacheToEffects(spec: string): BuildEffect[] {
  const trimmed = spec.trim();
  if (trimmed === '') return [];
  if (isDynamic(trimmed)) return [{ kind: 'gap', why: `the cache destination ${trimmed} is built at run time` }];
  const kv = new Map(csv(trimmed));
  const type = kv.get('type');
  if (type === undefined) return [{ kind: 'gap', why: `the cache destination ${trimmed} names no type` }];
  if (type === 'inline') return [];
  if (type === 'local') {
    const dest = kv.get('dest');
    return dest !== undefined && dest !== '' ? [{ kind: 'write', dest }] : [{ kind: 'gap', why: 'a local cache names no destination' }];
  }
  // registry, gha, s3, azblob: layers are uploaded to a service other people can read
  return [{ kind: 'push', ref: kv.get('ref') ?? `build-cache-${type}` }];
}

/** A build secret reads a host file into the build. */
export function secretEffects(spec: string): BuildEffect[] {
  const kv = new Map(csv(spec));
  const src = kv.get('src') ?? kv.get('source');
  if (src === undefined || src === '') return []; // `env=NAME` forwards a variable, `id=x` alone reads nothing named
  return isDynamic(src) ? [{ kind: 'gap', why: `the secret source ${src} is built at run time` }] : [{ kind: 'read', src }];
}

/** The effects of the build options on a command line, once, for the three verbs that have them (build, bake,
 *  compose build): `-o`, `--output`, `--push`, `--cache-to`, `--secret`, `--network host`, and bake's `--set
 *  SELECTOR.KEY=VALUE`, which is any of them under another spelling. */
export function commandBuildEffects(cmd: ContainerCommand): BuildEffect[] {
  if (!cmd.modelled || !(cmd.flags.includes('b') || cmd.flags.includes('B') || cmd.flags.includes('m'))) return [];
  const out: BuildEffect[] = [];
  const take = (key: string, value: string | null): void => {
    if (value === null) return;
    if (key === 'output') out.push(...outputEffects(value));
    else if (key === 'cache-to') out.push(...cacheToEffects(value));
    else if (key === 'secret') out.push(...secretEffects(value));
    else if (key === 'network' && value === 'host') out.push({ kind: 'isolation', what: 'build network host' });
  };
  for (const o of cmd.options) {
    if (o.name === '--push') out.push({ kind: 'push', ref: 'build-output' });
    else if (o.name === '-o' || o.name === '--output') take('output', o.value);
    else if (o.name === '--cache-to') take('cache-to', o.value);
    else if (o.name === '--secret') take('secret', o.value);
    else if (o.name === '--set') {
      const m = /^([^=]+?)\.([A-Za-z-]+)(?:\.[^=]*)?=([\s\S]*)$/.exec(o.value ?? '');
      if (m) take(m[2]!, m[3]!);
    }
  }
  return out;
}

/** a build effect as the plain host statement that has the same consequence, so one reading of "a push", "a file
 *  written here" and "a file read into the build" serves the flags of the command and the attributes of a file */
export function effectStatement(e: BuildEffect): string | null {
  switch (e.kind) {
    case 'push':
      return `docker push ${e.ref === '' ? 'build-output' : quoteWord(e.ref)}`;
    case 'write':
      return `docker image save -o ${quoteWord(e.dest)} build-output`;
    case 'read':
      return `cat ${quoteWord(e.src)}`;
    case 'isolation':
      return 'docker run --network host build-target';
    case 'gap':
      return null;
  }
}
const quoteWord = (w: string): string => (/[\s;&|<>$`"'\\()*?[\]{}]/.test(w) ? `'${w.replace(/'/g, `'\\''`)}'` : w);

/* ------------------------------------------------------------------------------------------------------------- *
 * G. THE CANONICAL SPELLING: what the matchers and the path rules are shown
 * ------------------------------------------------------------------------------------------------------------- */

const TRUE = /^(1|t|T|true|TRUE|True)$/;
const FALSE = /^(0|f|F|false|FALSE|False)$/;

/** The command with the program's own options taken out, the verb in its canonical spelling and every boolean option
 *  in its bare form - the spelling every matcher is written for. The matchers are anchored on `docker <verb>`; a
 *  global option, an alias (`buildx b`), a glued short value (`-otype=registry`) or a `=true` on a flag each
 *  displaced or hid the word they look for. Returns null when there is nothing to say (the command is already
 *  canonical) or the verb could not be placed. */
export function canonicalCommand(cmd: ContainerCommand, original: readonly string[]): string[] | null {
  if (!cmd.determinate || !cmd.modelled || cmd.path.length === 0) return null;
  const out: string[] = [cmd.program];
  const standaloneCompose = cmd.program === 'docker-compose' || cmd.program === 'podman-compose';
  const spanOf = (o: ReadOption): string[] => cmd.words.slice(o.at, o.at + o.length);
  // a standalone compose client keeps its own options: they select the project, not the engine
  if (standaloneCompose) for (const o of cmd.rootOptions) out.push(...spanOf(o));
  const pathWords = standaloneCompose ? [cmd.path[1]!] : cmd.path;
  if (cmd.groupAt >= 0 && !standaloneCompose) {
    out.push(pathWords[0]!);
    for (const o of cmd.groupOptions) out.push(...spanOf(o));
    out.push(...pathWords.slice(1));
  } else out.push(...pathWords);
  const bools = verbGrammar(cmd).bool;
  for (let k = cmd.argsAt; k < cmd.words.length; k++) {
    const idx = cmd.optionAt.indexOf(k);
    if (idx < 0) {
      out.push(cmd.words[k]!);
      continue;
    }
    const o = cmd.options[idx]!;
    k += o.length - 1;
    // `-oVALUE` and `-o=VALUE` are `--output VALUE`; the matchers read the long spelling
    if (o.glued && o.name === '-o' && o.value !== null) {
      out.push('--output', o.value);
      continue;
    }
    // a boolean flag spelled `--name=true` is the flag, and `--name=false` is no flag at all
    if (o.glued && o.names.length === 1 && o.value !== null && (TRUE.test(o.value) || FALSE.test(o.value)) && bools.has(o.name)) {
      if (TRUE.test(o.value)) out.push(o.name);
      continue;
    }
    out.push(...spanOf(o));
  }
  // what stands after the argv boundary is a program's own words, and is kept as it was
  return out.join(' ') === original.join(' ') ? null : out;
}

/** The markers the evaluator's matchers name for the effects a verb has that no spelling of the command line says: a
 *  destroyed pod, a rewritten credential store. (A PUSH is not here: every spelling of one - `push`, `image push`, `plugin
 *  push`, `manifest push`, `compose publish`, `imagetools create`, `build --push` - already ends in a word the registry
 *  pattern reads, and the approval card names the registry from the decisive hit's own words, which a marker has not got.) */
export function effectMarkers(cmd: ContainerCommand, mark: string): string[] {
  if (!cmd.determinate || !cmd.modelled || cmd.path.length === 0) return [];
  const tag = `${cmd.program} ${cmd.path.join(' ')}`;
  const out: string[] = [];
  if (cmd.flags.includes('d')) out.push(`${mark}container-effect remove ${tag}`);
  if (cmd.flags.includes('D')) {
    const volumes = cmd.options.some((o) => o.names.some((n) => n === '-v' || n === '--volumes') && !(o.glued && o.value !== null && FALSE.test(o.value)));
    const rmi = cmd.options.some((o) => o.name === '--rmi' && /^(all|local)$/.test(o.value ?? ''));
    if (volumes || rmi) out.push(`${mark}container-effect remove ${tag}`);
  }
  if (cmd.flags.includes('k')) out.push(`${mark}container-effect credential ${tag}`);
  return out;
}

/* ------------------------------------------------------------------------------------------------------------- *
 * H. WHAT A BUILD READS: bake files, compose files, Dockerfiles
 * ------------------------------------------------------------------------------------------------------------- */

export interface BuildIO {
  /** the physical path `word` opens when the command runs in `dir`, or null when it is built at run time */
  open(dir: string, word: string): string | null;
  /** the text of a file the kernel may read, or null */
  read(abs: string): string | null;
  /** false only when the path is PROVEN not to be there */
  exists(abs: string): boolean;
  /** the entries of a directory, or null when it cannot be listed */
  list(abs: string): string[] | null;
  /** true when this command line may have written the path or an ancestor before this command runs */
  stale(word: string, abs: string): boolean;
  /** standard input as the command line gives it (a heredoc, a redirected file); undefined when it does not */
  stdin(): string | undefined;
  /** the lines of a Dockerfile that the build EXECUTES */
  shellLines(dockerfile: string): string[];
  fingerprint(text: string): string;
  /** the directory the command runs in */
  cwd: string;
  /** the value of an environment variable the command line sets */
  env(name: string): string | undefined;
}

export interface BuildGap {
  what: 'body' | 'config' | 'context' | 'freshness';
  where: string;
  why: string;
}

export interface BuildResult {
  key: string;
  reason: string;
  resolution: 'RESOLVED_COMPLETE' | 'PARTIAL' | 'UNREADABLE' | 'STALE' | 'ABSENT_VERIFIED';
  /** the RUN lines the build executes, which run in the image */
  body: string[] | null;
  /** statements with the host consequences of what the files declare (a push, a file written, a secret read) */
  hostBody: string[];
  unresolved: BuildGap[];
  provenance?: { source: string; fingerprint: string };
}

const URLISH = /^(-$|https?:|git@|git:|git\+|ssh:|github\.com\/|[a-z][a-z0-9+.-]*:\/\/|docker-image:|target:|oci-layout:)/i;

/** The files a build verb will READ, found and read, and what they make the build execute.
 *
 *  `build`: the Dockerfile `-f` names, or `CONTEXT/Dockerfile` (a Containerfile for podman). `bake`: the definition
 *  files `-f` names or the default ones - compose files and `docker-bake.*` - with `--set` applied on top. `compose
 *  build` (and `up --build`, `run --build`): the compose files. Every file read passes the freshness ledger, and
 *  every one that cannot be read is a gap, never an absence. */
export function collectBuildInputs(cmd: ContainerCommand, io: BuildIO): BuildResult | null {
  if (!cmd.determinate || !cmd.modelled) return null;
  let r: BuildResult | null = null;
  if (cmd.flags.includes('B')) r = collectBake(cmd, io);
  else if (cmd.path[0] === 'compose' && (cmd.flags.includes('b') || (cmd.flags.includes('m') && cmd.options.some((o) => o.name === '--build'))))
    r = collectCompose(cmd, io);
  else if (cmd.flags.includes('b') && cmd.path[0] !== 'compose') r = collectDockerfileBuild(cmd, io);
  if (r === null) return null;
  // an output, a cache or a secret on the command line that this reader cannot place is a gap in the closure of the
  // build, whatever the files said
  const gaps: BuildGap[] = commandBuildEffects(cmd)
    .filter((e): e is Extract<BuildEffect, { kind: 'gap' }> => e.kind === 'gap')
    .map((e) => ({ what: 'config', where: cmd.path.join(' '), why: e.why }));
  if (!gaps.length) return r;
  return {
    ...r,
    resolution: r.resolution === 'RESOLVED_COMPLETE' || r.resolution === 'ABSENT_VERIFIED' ? 'PARTIAL' : r.resolution,
    reason: `${r.reason}; NOT fully resolved: ${gaps[0]!.why}`,
    unresolved: [...r.unresolved, ...gaps],
  };
}

const lastOf = <T>(xs: readonly T[]): T | undefined => xs[xs.length - 1];

/** `docker build`: one Dockerfile, named by `-f` (relative to the working directory) or sitting in the context */
function collectDockerfileBuild(cmd: ContainerCommand, io: BuildIO): BuildResult {
  const fileOptions = cmd.options.filter((o) => o.name === '-f' || o.name === '--file');
  // docker takes the LAST `-f`; podman and buildah build EVERY file they are given. Which tool this is cannot be asked of a
  // word, so each is read, and a build that names two Dockerfiles runs all of them as far as this reader can tell.
  if (fileOptions.length > 1) {
    const parts = fileOptions.map((keep) =>
      collectDockerfileBuild({ ...cmd, options: cmd.options.filter((o) => o === keep || !(o.name === '-f' || o.name === '--file')) }, io),
    );
    const body = parts.flatMap((p) => p.body ?? []);
    const unresolved: BuildGap[] = parts
      .filter((p) => p.resolution !== 'RESOLVED_COMPLETE' && p.resolution !== 'ABSENT_VERIFIED')
      .map((p) => ({ what: 'body', where: p.key, why: p.reason }));
    const sources = parts.flatMap((p) => (p.provenance ? [p.provenance] : []));
    return {
      key: parts.map((p) => p.key).join('+'),
      reason: unresolved.length ? `Dockerfiles; NOT fully resolved: ${unresolved[0]!.why}` : 'Dockerfiles',
      resolution: unresolved.length ? 'PARTIAL' : parts.every((p) => p.resolution === 'ABSENT_VERIFIED') ? 'ABSENT_VERIFIED' : 'RESOLVED_COMPLETE',
      body: parts.every((p) => p.body === null) && !unresolved.length ? null : body,
      hostBody: [],
      unresolved,
      ...(sources.length ? { provenance: { source: sources.map((s) => s.source).join(','), fingerprint: sources.map((s) => s.fingerprint).join(',') } } : {}),
    };
  }
  const named = lastOf(fileOptions.map((o) => o.value))?.replace(/^=/, '') ?? null;
  const result = (r: Omit<BuildResult, 'hostBody' | 'unresolved'> & { unresolved?: BuildGap[] }): BuildResult => ({ hostBody: [], unresolved: [], ...r });
  // `-f -` reads the Dockerfile from STANDARD INPUT. That is a stream - UNLESS the command line holds it, which a
  // heredoc does: `docker build -f - . <<EOF\nFROM alpine\nRUN git push origin main\nEOF` writes the whole Dockerfile in
  // plain sight, and calling it unreadable gave an absolute deny the approvable ASK of opacity (exit review 8).
  if (named === '-') {
    const piped = io.stdin();
    if (piped === undefined)
      return result({ key: 'dockerfile:stdin', body: null, reason: 'the Dockerfile is read from standard input', resolution: 'UNREADABLE' });
    return result({
      key: `dockerfile:stdin:${io.fingerprint(piped)}`,
      body: io.shellLines(piped),
      reason: 'the Dockerfile arrives on standard input and the command line holds it',
      resolution: 'RESOLVED_COMPLETE',
    });
  }
  // The context is the FIRST bare operand, which docker documents as the single PATH|URL|- argument. An option this
  // reader does not know has an arity nobody can tell, so the operand after it may be its value: the position of the
  // context is then unknown, and nothing is claimed about the Dockerfile that sits in it.
  if (cmd.unknownOption !== null)
    return result({
      key: `dockerfile:unplaced:${cmd.unknownOption}`,
      body: null,
      reason: `the option ${cmd.unknownOption} has an arity this kernel does not know, so the build context cannot be placed`,
      resolution: 'UNREADABLE',
    });
  const context = cmd.operands[0] ?? '.';
  // `docker build -` reads the Dockerfile from STANDARD INPUT, and a URL context is fetched: neither is a file this
  // kernel can read, so neither can carry a positive claim. NAMING A FILE WITH `-f` DOES NOT CHANGE THAT: the path is
  // inside the fetched repository or the tarball on standard input (exit review 10).
  if (URLISH.test(context))
    return result({
      key: `dockerfile:${context}`,
      body: null,
      reason: 'the build context is a stream or a remote URL, so its Dockerfile was never read',
      resolution: 'UNREADABLE',
    });
  // PODMAN'S DEFAULT BUILD FILE IS `Containerfile`, and it falls back to `Dockerfile`
  let dockerfile = named ?? `${context}/Dockerfile`;
  const present = (word: string): boolean => {
    const o = io.open(io.cwd, word);
    return o !== null && io.exists(o);
  };
  if (named === null && !present(dockerfile) && present(`${context}/Containerfile`)) dockerfile = `${context}/Containerfile`;
  const abs = io.open(io.cwd, dockerfile);
  if (abs === null)
    return result({ key: `dockerfile:${dockerfile}`, body: null, reason: 'the Dockerfile path is built at run time', resolution: 'UNREADABLE' });
  if (io.stale(dockerfile, abs))
    return result({ key: `dockerfile:${abs}`, body: null, reason: 'the Dockerfile is rewritten earlier in the same command', resolution: 'STALE' });
  const text = io.read(abs);
  if (text === null) {
    // NO DOCKERFILE IS AN ABSENCE THAT WAS OBSERVED, not an opacity: `docker build .` in a directory that holds no
    // Dockerfile fails and executes nothing, and treating it as opaque would gate every `docker build` in a
    // repository that keeps its Dockerfile elsewhere
    const dir = abs.slice(0, abs.lastIndexOf('/'));
    if (!io.exists(abs) && io.list(dir) !== null)
      return result({
        key: `dockerfile:${abs}`,
        body: null,
        reason: `no Dockerfile in ${dockerfile.replace(/\/Dockerfile$/, '') || '.'}`,
        resolution: 'ABSENT_VERIFIED',
      });
    return result({
      key: `dockerfile:${abs}`,
      body: null,
      reason: io.exists(abs) ? 'the Dockerfile is outside the workspace' : 'the build context directory could not be read',
      resolution: 'UNREADABLE',
    });
  }
  return result({
    key: `dockerfile:${abs}`,
    body: io.shellLines(text),
    reason: `Dockerfile ${dockerfile}`,
    resolution: 'RESOLVED_COMPLETE',
    provenance: { source: abs, fingerprint: io.fingerprint(text) },
  });
}

/** one build target as a bake or compose file declares it */
interface Target {
  name: string;
  context: string | null;
  dockerfile: string | null;
  inline: string | null;
  /** attribute values that are not literals: a variable, a function, an interpolation */
  dynamic: string[];
  outputs: string[];
  cacheTo: string[];
  secrets: string[];
  network: string | null;
  inherits: string[];
  /** a context that is not a directory of the workspace: a URL, a repository, `target:`, an image */
  remoteContext: boolean;
}
const emptyTarget = (name: string): Target => ({
  name,
  context: null,
  dockerfile: null,
  inline: null,
  dynamic: [],
  outputs: [],
  cacheTo: [],
  secrets: [],
  network: null,
  inherits: [],
  remoteContext: false,
});

/** Files, targets and the gaps found reading them. */
class Collected {
  targets: Target[] = [];
  gaps: BuildGap[] = [];
  lines: string[] = [];
  hostLines: string[] = [];
  read: Array<{ path: string; text: string }> = [];
  freshness: BuildGap[] = [];
  unreadable = false;
}

/** read a Dockerfile a target names, relative to its context */
function readTargetDockerfile(t: Target, ctxDir: string, io: BuildIO, into: Collected): void {
  if (t.inline !== null) {
    into.lines.push(...io.shellLines(t.inline));
    return;
  }
  const df = t.dockerfile ?? 'Dockerfile';
  const word = /^\//.test(df) ? df : `${ctxDir}/${df}`.replace(/^\.\//, '');
  const abs = io.open(io.cwd, word);
  if (abs === null) {
    into.gaps.push({ what: 'body', where: df, why: `the Dockerfile of target ${t.name} is built at run time` });
    return;
  }
  if (io.stale(word, abs)) {
    into.freshness.push({ what: 'freshness', where: df, why: `${df} is rewritten earlier in the same command` });
    return;
  }
  const text = io.read(abs);
  if (text === null) {
    // a Dockerfile a target names that is not there fails the build and executes nothing - when the directory could be
    // listed and says so; anything else is a file nobody read
    const dir = abs.slice(0, abs.lastIndexOf('/'));
    if (!io.exists(abs) && io.list(dir) !== null) return;
    into.gaps.push({ what: 'body', where: df, why: `the Dockerfile of target ${t.name} could not be read` });
    return;
  }
  into.read.push({ path: abs, text });
  into.lines.push(...io.shellLines(text));
}

/** apply one target's declared outputs, caches and secrets as the host statements they amount to */
function targetEffects(t: Target, into: Collected): void {
  const effects: BuildEffect[] = [
    ...t.outputs.flatMap((s) => outputEffects(s)),
    ...t.cacheTo.flatMap((s) => cacheToEffects(s)),
    ...t.secrets.flatMap((s) => secretEffects(s)),
    ...(t.network === 'host' ? ([{ kind: 'isolation', what: 'network host' }] as BuildEffect[]) : []),
  ];
  for (const e of effects) {
    if (e.kind === 'gap') into.gaps.push({ what: 'config', where: t.name, why: e.why });
    else {
      const s = effectStatement(e);
      if (s !== null) into.hostLines.push(s);
    }
  }
}

function finishCollected(key: string, label: string, into: Collected, io: BuildIO, extraGaps: BuildGap[] = []): BuildResult {
  const unresolved = [...into.gaps, ...into.freshness, ...extraGaps];
  const text = into.read.map((r) => r.text).join('\n');
  const provenance = into.read.length ? { source: into.read.map((r) => r.path).join(','), fingerprint: io.fingerprint(text) } : undefined;
  const hostBody = [...new Set(into.hostLines)];
  if (unresolved.length)
    return {
      key,
      reason: `${label}; NOT fully resolved: ${unresolved[0]!.why}`,
      resolution: 'PARTIAL',
      body: into.lines,
      hostBody,
      unresolved,
      ...(provenance ? { provenance } : {}),
    };
  return { key, reason: label, resolution: 'RESOLVED_COMPLETE', body: into.lines, hostBody, unresolved: [], ...(provenance ? { provenance } : {}) };
}

/* ---- bake ------------------------------------------------------------------------------------------------ */

const BAKE_DEFAULT_FILES = [
  'compose.yaml',
  'compose.yml',
  'docker-compose.yml',
  'docker-compose.yaml',
  'docker-bake.json',
  'docker-bake.override.json',
  'docker-bake.hcl',
  'docker-bake.override.hcl',
];

function collectBake(cmd: ContainerCommand, io: BuildIO): BuildResult {
  const into = new Collected();
  const files = cmd.options.filter((o) => o.name === '-f' || o.name === '--file').map((o) => o.value ?? '');
  const sets = cmd.options.filter((o) => o.name === '--set').map((o) => o.value ?? '');
  const key = `bake:${io.cwd}:${files.join(',')}:${cmd.operands.join(',')}:${sets.join(',')}`;
  // `--print` PRINTS the resolved configuration as JSON and builds nothing (exit review 10)
  if (cmd.options.some((o) => (o.name === '--print' || o.name === '--list') && !(o.glued && FALSE.test(o.value ?? ''))))
    return { key: 'bake:print', reason: 'bake --print renders the configuration and builds nothing', resolution: 'ABSENT_VERIFIED', body: null, hostBody: [], unresolved: [] };
  // a REMOTE DEFINITION - `bake https://github.com/org/repo.git` - is fetched, and the Dockerfiles in it were never read
  const remote = cmd.operands.find((o) => URLISH.test(o) || /\.git(#|$)/.test(o));
  if (remote !== undefined)
    return { key, reason: `the bake definition ${remote} is fetched, so what it builds was never read`, resolution: 'UNREADABLE', body: null, hostBody: [], unresolved: [] };

  const defined: Array<{ name: string; text: string }> = [];
  const candidates = files.length ? files : BAKE_DEFAULT_FILES;
  for (const f0 of candidates) {
    let f = f0.replace(/^cwd:\/\//, '');
    if (f === '-') {
      const piped = io.stdin();
      if (piped === undefined) into.gaps.push({ what: 'body', where: 'standard input', why: 'the bake definition is read from standard input' });
      else defined.push({ name: '-', text: piped });
      continue;
    }
    if (URLISH.test(f)) {
      into.gaps.push({ what: 'body', where: f, why: 'the bake definition is fetched' });
      continue;
    }
    f = f.replace(/^\.\//, '');
    const abs = io.open(io.cwd, f);
    if (abs === null) {
      into.gaps.push({ what: 'body', where: f, why: 'the bake file path is built at run time' });
      continue;
    }
    if (io.stale(f, abs)) {
      into.freshness.push({ what: 'freshness', where: f, why: `${f} is rewritten earlier in the same command` });
      continue;
    }
    const text = io.read(abs);
    if (text !== null) {
      into.read.push({ path: abs, text });
      defined.push({ name: f, text });
    } else if (files.length || io.exists(abs)) into.gaps.push({ what: 'body', where: f, why: 'the bake file could not be read' });
  }
  const targets = new Map<string, Target>();
  for (const d of defined) {
    const parsed = parseDefinition(d.name, d.text);
    for (const g of parsed.gaps) into.gaps.push(g);
    for (const t of parsed.targets) {
      const prev = targets.get(t.name);
      targets.set(t.name, prev ? mergeTargets(prev, t) : t);
    }
  }
  const resolved = [...targets.values()].map((t) => resolveInheritance(t, targets));
  // `--set SELECTOR.KEY=VALUE` is applied on top, to every target it matches. Whether it matches one is not asked: the
  // override is read as if it did, which can only read more
  const overrides: Target[] = [];
  for (const s of sets) {
    const m = /^([^=]+?)\.([A-Za-z-]+)(?:\.[^=]*)?=([\s\S]*)$/.exec(s);
    if (!m) {
      into.gaps.push({ what: 'config', where: s, why: 'a --set override this reader cannot parse' });
      continue;
    }
    const key2 = m[2]!;
    const value = m[3]!;
    const o = emptyTarget(`--set ${m[1]!}`);
    if (isDynamic(value) && /^(dockerfile|context|dockerfile-inline)$/.test(key2)) {
      into.gaps.push({ what: 'config', where: s, why: `the value of ${key2} is built at run time` });
      continue;
    }
    if (key2 === 'dockerfile') o.dockerfile = value;
    else if (key2 === 'dockerfile-inline') o.inline = value;
    else if (key2 === 'context') {
      o.context = value;
      o.remoteContext = URLISH.test(value);
    } else if (key2 === 'output') o.outputs.push(value);
    else if (key2 === 'cache-to') o.cacheTo.push(value);
    else if (key2 === 'secret') o.secrets.push(value);
    else if (key2 === 'network') o.network = value;
    else continue;
    overrides.push(o);
  }
  // nothing defines a target: the build fails and executes nothing - when every file that could define one was read
  if (!resolved.length && !overrides.some((o) => o.dockerfile || o.inline) && !into.gaps.length && !into.freshness.length) {
    return { key, reason: defined.length ? 'the bake files define no target' : 'no bake file', resolution: 'ABSENT_VERIFIED', body: null, hostBody: [], unresolved: [] };
  }
  const contextOverrides = overrides.filter((o) => o.context !== null).map((o) => o.context!);
  const dfNames = new Set<string>(['Dockerfile']);
  for (const t of resolved) if (t.dockerfile) dfNames.add(t.dockerfile);
  for (const o of overrides) if (o.dockerfile) dfNames.add(o.dockerfile);
  const seenReads = new Set<string>();
  const readOnce = (t: Target, ctxDir: string): void => {
    const k = `${ctxDir}\0${t.dockerfile ?? ''}\0${t.inline ?? ''}`;
    if (seenReads.has(k)) return;
    seenReads.add(k);
    readTargetDockerfile(t, ctxDir, io, into);
  };
  for (const t of resolved) {
    if (t.dynamic.length) into.gaps.push({ what: 'config', where: t.name, why: `${t.dynamic.join(', ')} of target ${t.name} is not a literal` });
    if (t.remoteContext) {
      into.gaps.push({ what: 'context', where: t.name, why: `the context of target ${t.name} is remote` });
      continue;
    }
    // a --set dockerfile / inline replaces the target's own, but which target it reaches is not asked: both are read
    readOnce(t, t.context ?? '.');
    for (const c of contextOverrides) {
      if (URLISH.test(c)) {
        into.gaps.push({ what: 'context', where: c, why: `the context ${c} is remote` });
        continue;
      }
      for (const n of dfNames) readOnce({ ...t, dockerfile: t.dockerfile === null ? null : n }, c);
    }
    targetEffects(t, into);
  }
  for (const o of overrides) {
    if (o.remoteContext) {
      into.gaps.push({ what: 'context', where: o.name, why: `${o.name} sets a remote context` });
      continue;
    }
    if (o.dockerfile !== null || o.inline !== null) {
      readOnce(o, '.');
      for (const t of resolved) if (t.context !== null && t.context !== '.') readOnce(o, t.context);
      for (const c of contextOverrides) if (!URLISH.test(c)) readOnce(o, c);
    }
    // (an override's outputs, caches and secrets are the command line's own, judged once from the flags: see
    // commandBuildEffects)
  }
  return finishCollected(key, 'bake targets', into, io);
}

function mergeTargets(a: Target, b: Target): Target {
  return {
    name: a.name,
    context: b.context ?? a.context,
    dockerfile: b.dockerfile ?? a.dockerfile,
    inline: b.inline ?? a.inline,
    dynamic: [...a.dynamic, ...b.dynamic],
    outputs: b.outputs.length ? b.outputs : a.outputs,
    cacheTo: b.cacheTo.length ? b.cacheTo : a.cacheTo,
    secrets: b.secrets.length ? b.secrets : a.secrets,
    network: b.network ?? a.network,
    inherits: [...new Set([...a.inherits, ...b.inherits])],
    remoteContext: a.remoteContext || b.remoteContext,
  };
}

/** a target inherits what it does not set from the targets it names, nearest first */
function resolveInheritance(t: Target, all: ReadonlyMap<string, Target>, depth = 0): Target {
  if (!t.inherits.length || depth > 8) return t;
  let out: Target = { ...t };
  for (const name of [...t.inherits].reverse()) {
    const parent = all.get(name);
    if (!parent) continue;
    const p = resolveInheritance(parent, all, depth + 1);
    out = {
      ...out,
      context: out.context ?? p.context,
      dockerfile: out.dockerfile ?? p.dockerfile,
      inline: out.inline ?? p.inline,
      dynamic: [...out.dynamic, ...p.dynamic],
      outputs: out.outputs.length ? out.outputs : p.outputs,
      cacheTo: out.cacheTo.length ? out.cacheTo : p.cacheTo,
      secrets: out.secrets.length ? out.secrets : p.secrets,
      network: out.network ?? p.network,
      remoteContext: out.remoteContext || p.remoteContext,
    };
  }
  return out;
}

/** one definition file, by what it is: HCL, JSON or a compose file */
function parseDefinition(name: string, source: string): { targets: Target[]; gaps: BuildGap[] } {
  // a byte order mark is not part of the first key: left in, it made `services` another word and the file empty
  const text = source.charCodeAt(0) === 0xfeff ? source.slice(1) : source;
  const base = name.slice(name.lastIndexOf('/') + 1);
  const yaml = /\.ya?ml$/i.test(base) || (!/\.(json|hcl)$/i.test(base) && /^\s*(services|name|version|x-[\w-]+)\s*:/m.test(text));
  if (yaml) return parseComposeAsTargets(name, text);
  // a file with no extension is read by what it holds: bake takes JSON or HCL from `-f` whatever it is called
  if (/\.json$/i.test(base) || (!/\.hcl$/i.test(base) && /^\s*\{/.test(text))) return parseBakeJson(name, text);
  return parseBakeHcl(name, text);
}

/* ---- bake JSON -------------------------------------------------------------------------------------------- */

/** An attribute value that is not a literal: an interpolation, a variable, a function call. */
class Dyn {
  readonly raw: string;
  constructor(raw: string) {
    this.raw = raw;
  }
}
type AttrValue = string | string[] | Dyn;

/** HCL and its JSON form interpolate `${…}` and `%{…}` and escape them by doubling the first character. A `$` that is
 *  not followed by a brace is just a dollar sign - a Dockerfile's `RUN echo $HOME` is a literal. */
const INTERPOLATES = /(^|[^$])\$\{|(^|[^%])%\{/;
function hclJsonValue(v: unknown): AttrValue {
  const lit = (s: string): AttrValue => (INTERPOLATES.test(s) ? new Dyn(s) : s.replace(/\$\$\{/g, '${').replace(/%%\{/g, '%{'));
  if (typeof v === 'string') return lit(v);
  if (Array.isArray(v) && v.every((x) => typeof x === 'string')) {
    const items = (v as string[]).map(lit);
    return items.some((x) => x instanceof Dyn) ? new Dyn(v.join(',')) : (items as string[]);
  }
  return new Dyn(String(v));
}

function targetFromAttrs(name: string, attrs: Map<string, AttrValue>, gaps: BuildGap[], where: string): Target {
  const t = emptyTarget(name);
  // a path or a spec with a dollar sign in it is read as built at run time; the Dockerfile text is not
  const lit = (key: string, text = false): string | null => {
    const v = attrs.get(key);
    if (v === undefined) return null;
    if (typeof v === 'string' && (text || !isDynamic(v))) return v;
    t.dynamic.push(key);
    return null;
  };
  const list = (key: string): string[] => {
    const v = attrs.get(key);
    if (v === undefined) return [];
    const s = typeof v === 'string' ? [v] : Array.isArray(v) ? v : null;
    if (s === null || s.some(isDynamic)) {
      t.dynamic.push(key);
      return [];
    }
    return s;
  };
  t.context = lit('context');
  const ctx = attrs.get('context');
  t.remoteContext = typeof ctx === 'string' && URLISH.test(ctx);
  t.dockerfile = lit('dockerfile');
  t.inline = lit('dockerfile-inline', true);
  t.outputs = list('output');
  t.cacheTo = list('cache-to');
  t.secrets = list('secret');
  t.network = lit('network');
  t.inherits = list('inherits');
  // an attribute that builds more targets from variables, or names contexts that are images, is beyond this reader
  if (attrs.has('matrix')) gaps.push({ what: 'config', where: `${where} target ${name}`, why: 'a matrix generates targets this reader does not expand' });
  return t;
}

function parseBakeJson(name: string, text: string): { targets: Target[]; gaps: BuildGap[] } {
  const gaps: BuildGap[] = [];
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return { targets: [], gaps: [{ what: 'body', where: name, why: 'the bake JSON could not be parsed' }] };
  }
  const targets: Target[] = [];
  const tg = (doc as { target?: unknown } | null)?.target;
  if (tg && typeof tg === 'object' && !Array.isArray(tg))
    for (const [n, body] of Object.entries(tg as Record<string, unknown>)) {
      if (!body || typeof body !== 'object' || Array.isArray(body)) {
        gaps.push({ what: 'config', where: `${name} target ${n}`, why: 'a target that is not an object' });
        continue;
      }
      targets.push(
        targetFromAttrs(n, new Map(Object.entries(body as Record<string, unknown>).map(([k, v]) => [k, hclJsonValue(v)])), gaps, name),
      );
    }
  return { targets, gaps };
}

/* ---- bake HCL ---------------------------------------------------------------------------------------------- */

type Tok = { t: 'id' | 'str' | 'heredoc' | 'punct' | 'nl' | 'num'; v: string; dyn?: boolean };

/** A tolerant lexer for the part of HCL a bake file uses. Anything it cannot lex is reported by the caller as a gap. */
function lexHcl(src: string): Tok[] | null {
  const toks: Tok[] = [];
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i]!;
    if (c === '\n') {
      toks.push({ t: 'nl', v: '\n' });
      i++;
    } else if (c === ' ' || c === '\t' || c === '\r') i++;
    else if (c === '#' || (c === '/' && src[i + 1] === '/')) {
      while (i < n && src[i] !== '\n') i++;
    } else if (c === '/' && src[i + 1] === '*') {
      const e = src.indexOf('*/', i + 2);
      if (e < 0) return null;
      i = e + 2;
    } else if (c === '"') {
      let s = '';
      let dyn = false;
      i++;
      let closed = false;
      while (i < n) {
        const d = src[i]!;
        if (d === '\\') {
          const e = src[i + 1] ?? '';
          const map: Record<string, string> = { n: '\n', t: '\t', r: '\r', '"': '"', '\\': '\\' };
          if (e === 'u' || e === 'U') {
            const len = e === 'u' ? 4 : 8;
            const hex = src.slice(i + 2, i + 2 + len);
            if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length !== len) return null;
            s += String.fromCodePoint(parseInt(hex, 16));
            i += 2 + len;
            continue;
          }
          if (!(e in map)) return null;
          s += map[e]!;
          i += 2;
          continue;
        }
        if (d === '$' && src[i + 1] === '$' && src[i + 2] === '{') {
          s += '${';
          i += 3;
          continue;
        }
        if (d === '%' && src[i + 1] === '%' && src[i + 2] === '{') {
          s += '%{';
          i += 3;
          continue;
        }
        if ((d === '$' || d === '%') && src[i + 1] === '{') {
          // an interpolation runs to its matching brace and may hold braces and quoted strings of its own: `"${join(",", x)}"`
          dyn = true;
          let depth = 0;
          let j = i + 1;
          for (; j < n; j++) {
            const e = src[j]!;
            if (e === '{') depth++;
            else if (e === '}') {
              if (--depth === 0) {
                j++;
                break;
              }
            } else if (e === '"') {
              j++;
              while (j < n && src[j] !== '"' && src[j] !== '\n') j += src[j] === '\\' ? 2 : 1;
            } else if (e === '\n') return null;
          }
          if (depth !== 0) return null;
          s += src.slice(i, j);
          i = j;
          continue;
        }
        if (d === '"') {
          closed = true;
          i++;
          break;
        }
        if (d === '\n') return null;
        s += d;
        i++;
      }
      if (!closed) return null;
      toks.push({ t: 'str', v: s, ...(dyn ? { dyn } : {}) });
    } else if (c === '<' && src[i + 1] === '<') {
      const m = /^<<(-?)([A-Za-z_][A-Za-z0-9_]*)[ \t]*\r?\n/.exec(src.slice(i));
      if (!m) return null;
      const id = m[2]!;
      const bodyStart = i + m[0].length;
      const re = new RegExp(`^[ \\t]*${id}[ \\t]*\\r?$`, 'm');
      const rest = src.slice(bodyStart);
      const end = re.exec(rest);
      if (!end) return null;
      let body = rest.slice(0, end.index);
      if (m[1] === '-') {
        const lines = body.split('\n');
        const indent = Math.min(...lines.filter((l) => l.trim() !== '').map((l) => /^[ \t]*/.exec(l)![0].length), Infinity);
        body = lines.map((l) => l.slice(Number.isFinite(indent) ? indent : 0)).join('\n');
      }
      // `$${` and `%%{` are HCL's escapes for a literal `${` and `%{`; any other `${` is an interpolation
      const escaped = body.replace(/\$\$\{/g, '\uE001{').replace(/%%\{/g, '\uE002{');
      toks.push({ t: 'heredoc', v: escaped.replace(/\uE001/g, '$').replace(/\uE002/g, '%'), dyn: /[$%]\{/.test(escaped) });
      i = bodyStart + end.index + end[0].length;
    } else if (/[A-Za-z_]/.test(c)) {
      let j = i + 1;
      while (j < n && /[A-Za-z0-9_.-]/.test(src[j]!)) j++;
      toks.push({ t: 'id', v: src.slice(i, j) });
      i = j;
    } else if (/[0-9]/.test(c)) {
      let j = i + 1;
      while (j < n && /[0-9.eE+-]/.test(src[j]!)) j++;
      toks.push({ t: 'num', v: src.slice(i, j) });
      i = j;
    } else if ('{}[]()=,:?.*+-/%<>!&|'.includes(c)) {
      toks.push({ t: 'punct', v: c });
      i++;
    } else return null;
  }
  return toks;
}

function parseBakeHcl(name: string, src: string): { targets: Target[]; gaps: BuildGap[] } {
  const gaps: BuildGap[] = [];
  const toks = lexHcl(src);
  const fail = (why: string): { targets: Target[]; gaps: BuildGap[] } => ({ targets: [], gaps: [{ what: 'body', where: name, why }] });
  if (toks === null) return fail('the bake file uses HCL syntax this reader does not lex');
  let p = 0;
  const peek = (): Tok | undefined => toks[p];
  const skipNl = (): void => {
    while (peek()?.t === 'nl') p++;
  };
  const targets: Target[] = [];

  // an expression runs to the first newline or closing brace at depth zero
  const readExpr = (): Tok[] => {
    const out: Tok[] = [];
    let depth = 0;
    while (p < toks.length) {
      const t = toks[p]!;
      if (depth === 0 && (t.t === 'nl' || (t.t === 'punct' && t.v === '}'))) break;
      if (t.t === 'punct' && (t.v === '[' || t.v === '(' || t.v === '{')) depth++;
      if (t.t === 'punct' && (t.v === ']' || t.v === ')' || t.v === '}')) depth--;
      if (depth < 0) break;
      out.push(t);
      p++;
    }
    return out;
  };
  const strValue = (e: Tok[]): { value: string; dyn: boolean } | null =>
    e.length === 1 && (e[0]!.t === 'str' || e[0]!.t === 'heredoc') ? { value: e[0]!.v, dyn: e[0]!.dyn === true } : null;
  const listValue = (e: Tok[]): Array<{ value: string; dyn: boolean }> | null => {
    if (!(e[0]?.t === 'punct' && e[0].v === '[' && e[e.length - 1]?.t === 'punct' && e[e.length - 1]!.v === ']')) return null;
    const items: Array<{ value: string; dyn: boolean }> = [];
    let cur: Tok[] = [];
    const flush = (): boolean => {
      if (!cur.length) return true;
      const s = strValue(cur);
      if (!s) return false;
      items.push(s);
      cur = [];
      return true;
    };
    for (const t of e.slice(1, -1)) {
      if (t.t === 'nl') continue;
      if (t.t === 'punct' && t.v === ',') {
        if (!flush()) return null;
        continue;
      }
      cur.push(t);
    }
    return flush() ? items : null;
  };

  // block bodies, recursively; only `target` blocks at the top level matter, but every body is walked so that a
  // brace is matched
  const readBody = (): Map<string, AttrValue> | null => {
    const attrs = new Map<string, AttrValue>();
    for (;;) {
      skipNl();
      const t = peek();
      if (t === undefined) return null;
      if (t.t === 'punct' && t.v === '}') {
        p++;
        return attrs;
      }
      if (t.t !== 'id' && t.t !== 'str') return null;
      p++;
      const nx = peek();
      if (nx?.t === 'punct' && (nx.v === '=' || nx.v === ':')) {
        p++;
        const e = readExpr();
        const s = strValue(e);
        if (s) attrs.set(t.v, s.dyn ? new Dyn(s.value) : s.value);
        else {
          const l = listValue(e);
          if (l) attrs.set(t.v, l.some((x) => x.dyn) ? new Dyn(l.map((x) => x.value).join(',')) : l.map((x) => x.value));
          else attrs.set(t.v, new Dyn(e.map((x) => x.v).join(' ')));
        }
        continue;
      }
      // a nested block: labels, then a body
      while (peek() && peek()!.t !== 'punct' && peek()!.t !== 'nl') p++;
      if (!(peek()?.t === 'punct' && peek()!.v === '{')) return null;
      p++;
      if (readBody() === null) return null;
    }
  };

  for (;;) {
    skipNl();
    const t = peek();
    if (t === undefined) break;
    if (t.t !== 'id') return fail('the bake file has a top-level construct this reader does not parse');
    p++;
    const labels: string[] = [];
    while (peek() && (peek()!.t === 'str' || peek()!.t === 'id')) labels.push(toks[p++]!.v);
    if (peek()?.t === 'punct' && peek()!.v === '=') {
      // a top-level attribute is not a block of any kind bake uses; skip the expression
      p++;
      readExpr();
      continue;
    }
    if (!(peek()?.t === 'punct' && peek()!.v === '{')) return fail(`the bake file has a malformed ${t.v} block`);
    p++;
    const attrs = readBody();
    if (attrs === null) return fail('the bake file has braces this reader cannot match');
    if (t.v === 'target' && labels[0] !== undefined) targets.push(targetFromAttrs(labels[0], attrs, gaps, name));
  }
  return { targets, gaps };
}

/* ---- compose ---------------------------------------------------------------------------------------------- */

const COMPOSE_DEFAULTS = ['compose.yaml', 'compose.yml', 'docker-compose.yaml', 'docker-compose.yml'];
const COMPOSE_OVERRIDES = ['compose.override.yaml', 'compose.override.yml', 'docker-compose.override.yaml', 'docker-compose.override.yml'];

function isMap(v: YamlValue | undefined): v is { [key: string]: YamlValue } {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}
/** a YAML value that is a string or a list of strings */
function asStrings(v: unknown): string[] | null {
  if (typeof v === 'string') return [v];
  if (Array.isArray(v) && v.every((x) => typeof x === 'string')) return v as string[];
  return null;
}

/** The block scalars (`key: |` and `key: >`) a YAML file holds under a key, read from the TEXT. The subset parser strips
 *  comment lines and indentation inside a block scalar and drops its blank lines, which is the text of an inline
 *  Dockerfile: a `# syntax=` line is its first line and the blank line is what a folded scalar turns into a newline. */
function rawBlockScalars(text: string, key: string): Array<{ line: number; folded: boolean; text: string }> {
  const lines = text.split(/\r?\n/);
  const out: Array<{ line: number; folded: boolean; text: string }> = [];
  const header = new RegExp(`^(\\s*)(?:- )?["']?${key}["']?\\s*:\\s*([|>])[0-9+-]*\\s*(?:#.*)?$`);
  const indentOf = (l: string): number => l.length - l.trimStart().length;
  for (let i = 0; i < lines.length; i++) {
    const m = header.exec(lines[i]!);
    if (!m) continue;
    const base = m[1]!.length;
    const body: string[] = [];
    let j = i + 1;
    while (j < lines.length && (lines[j]!.trim() === '' || indentOf(lines[j]!) > base)) body.push(lines[j++]!);
    const first = body.find((l) => l.trim() !== '');
    const cut = first === undefined ? 0 : indentOf(first);
    out.push({ line: i + 1, folded: m[2] === '>', text: body.map((l) => (l.trim() === '' ? '' : l.slice(cut))).join('\n') });
    i = j - 1;
  }
  return out;
}

/** a compose file's services that BUILD, as targets */
function parseComposeAsTargets(name: string, text: string): { targets: Target[]; gaps: BuildGap[] } {
  const gaps: BuildGap[] = [];
  // YAML ANCHORS, ALIASES AND MERGE KEYS build a service out of another one; the subset parser reads `<<: *base` as a
  // key and would drop the `build:` it carries. An include or an extends pulls in another file.
  const stripped = text
    .split('\n')
    .map((l) => l.replace(/(^|\s)#.*$/, ''))
    .join('\n');
  // ...AND SO DO THE MERGE TAGS (`!override`, `!reset`) and every other YAML tag: the subset parser reads `!override {context:
  // ., dockerfile: Evil}` as one string, and the service's real build is the map behind it
  if (/(^|[\s:[,-])(&|\*)[A-Za-z0-9_-]+|(^|[\s:[,-])!+[A-Za-z]|<<\s*:|^\s*include\s*:|^\s*extends\s*:/m.test(stripped))
    return {
      targets: [],
      gaps: [{ what: 'body', where: name, why: 'the compose file uses anchors, merge keys, tags, include or extends, which this reader does not follow' }],
    };
  let doc: YamlValue;
  try {
    doc = parseYaml(text.replace(/^---\s*$/m, ''));
  } catch (e) {
    return { targets: [], gaps: [{ what: 'body', where: name, why: `the compose file could not be parsed (${(e as Error).message})` }] };
  }
  const targets: Target[] = [];
  const services = isMap(doc) ? doc['services'] : undefined;
  if (services === undefined || services === null) {
    // a `services:` key the parser did not find is a file it did not understand, not a file with nothing to build
    if (/^\s*["']?services["']?\s*:/m.test(stripped))
      return { targets, gaps: [{ what: 'body', where: name, why: 'the compose file has a services section this reader could not parse' }] };
    return { targets, gaps };
  }
  if (!isMap(services)) return { targets, gaps: [{ what: 'body', where: name, why: 'the compose services are not a map' }] };
  for (const [svc, body] of Object.entries(services)) {
    if (!isMap(body)) continue;
    const b = body['build'];
    // the bake extension attributes override the compose ones
    const xb = isMap(body['x-bake']) ? (body['x-bake'] as { [key: string]: YamlValue }) : null;
    if (b === undefined || b === null) continue;
    const t = emptyTarget(svc);
    // compose interpolates `$VAR` and `${VAR}` in every value and writes a literal dollar as `$$`
    const dynamicOf = (v: YamlValue | undefined): string | null =>
      typeof v === 'string' && !/\$[{A-Za-z_]/.test(v.replace(/\$\$/g, '')) ? v.replace(/\$\$/g, '$') : null;
    if (typeof b === 'string') {
      if (isDynamic(b)) t.dynamic.push('build');
      else {
        t.context = b;
        t.remoteContext = URLISH.test(b);
      }
    } else if (isMap(b)) {
      const ctx = b['context'];
      if (ctx !== undefined) {
        const c = dynamicOf(ctx);
        if (c === null) t.dynamic.push('context');
        else {
          t.context = c;
          t.remoteContext = URLISH.test(c);
        }
      }
      for (const [key, field] of [['dockerfile', 'dockerfile'], ['dockerfile_inline', 'inline']] as const) {
        const v = b[key];
        if (v === undefined || v === null) continue;
        const s = dynamicOf(v);
        if (s === null) t.dynamic.push(key);
        else if (field === 'dockerfile') t.dockerfile = s;
        else t.inline = s;
      }
      const ct = b['cache_to'];
      if (ct !== undefined && ct !== null) {
        const s = asStrings(ct as unknown);
        if (s === null || s.some(isDynamic)) t.dynamic.push('cache_to');
        else t.cacheTo = s;
      }
      if (b['network'] === 'host') t.network = 'host';
      // BUILD SECRETS read host files by name through the top-level `secrets`; entitlements and a privileged build lift
      // the builder's isolation. Neither is modelled for a file, so they are said.
      if (b['secrets'] !== undefined) t.dynamic.push('secrets');
      if (b['entitlements'] !== undefined) t.dynamic.push('entitlements');
      if (b['privileged'] === true) t.dynamic.push('privileged');
      if (b['additional_contexts'] !== undefined) {
        const ac = b['additional_contexts'];
        const values = isMap(ac) ? Object.values(ac) : Array.isArray(ac) ? ac.map((x) => (typeof x === 'string' ? x.slice(x.indexOf('=') + 1) : '')) : [];
        if (values.some((v) => typeof v !== 'string' || URLISH.test(v) || isDynamic(v))) t.dynamic.push('additional_contexts');
      }
    } else t.dynamic.push('build');
    if (xb) {
      const o = xb['output'];
      if (o !== undefined) {
        const s = asStrings(o as unknown);
        if (s === null || s.some(isDynamic)) t.dynamic.push('x-bake output');
        else t.outputs = s;
      }
      const ct = xb['cache-to'];
      if (ct !== undefined) {
        const s = asStrings(ct as unknown);
        if (s === null || s.some(isDynamic)) t.dynamic.push('x-bake cache-to');
        else t.cacheTo = [...t.cacheTo, ...s];
      }
    }
    targets.push(t);
  }
  // an inline Dockerfile written as a block scalar is read from the text: every one is a Dockerfile some service builds
  for (const b of rawBlockScalars(text, 'dockerfile_inline')) {
    if (b.folded) {
      gaps.push({ what: 'body', where: name, why: `the folded dockerfile_inline at line ${b.line} is not unfolded by this reader` });
      continue;
    }
    if (/\$[{A-Za-z_]/.test(b.text.replace(/\$\$/g, ''))) {
      gaps.push({ what: 'config', where: name, why: `the dockerfile_inline at line ${b.line} is interpolated` });
      continue;
    }
    const t = emptyTarget(`inline Dockerfile at line ${b.line}`);
    t.inline = b.text.replace(/\$\$/g, '$');
    targets.push(t);
  }
  return { targets, gaps };
}

function collectCompose(cmd: ContainerCommand, io: BuildIO): BuildResult {
  const into = new Collected();
  const named = [...cmd.groupOptions, ...cmd.options, ...rootFileOptions(cmd)]
    .filter((o) => o.name === '-f' || o.name === '--file')
    .map((o) => o.value ?? '');
  const fromEnv = io.env('COMPOSE_FILE');
  const sep = io.env('COMPOSE_PATH_SEPARATOR') ?? ':';
  const envFiles = fromEnv !== undefined && !isDynamic(fromEnv) ? fromEnv.split(sep).filter(Boolean) : [];
  const files = named.length ? named : envFiles;
  const key = `compose:${io.cwd}:${files.join(',')}`;
  const projectDir = lastOf(cmd.options.filter((o) => o.name === '--project-directory').map((o) => o.value ?? '')) ?? lastOf(cmd.groupOptions.filter((o) => o.name === '--project-directory').map((o) => o.value ?? ''));
  const defined: Array<{ name: string; text: string }> = [];
  const load = (f: string, required: boolean): void => {
    if (f === '-') {
      const piped = io.stdin();
      if (piped === undefined) into.gaps.push({ what: 'body', where: 'standard input', why: 'the compose file is read from standard input' });
      else defined.push({ name: f, text: piped });
      return;
    }
    if (URLISH.test(f)) {
      into.gaps.push({ what: 'body', where: f, why: 'the compose file is fetched' });
      return;
    }
    const abs = io.open(io.cwd, f);
    if (abs === null) {
      into.gaps.push({ what: 'body', where: f, why: 'the compose file path is built at run time' });
      return;
    }
    if (io.stale(f, abs)) {
      into.freshness.push({ what: 'freshness', where: f, why: `${f} is rewritten earlier in the same command` });
      return;
    }
    const text = io.read(abs);
    if (text !== null) {
      into.read.push({ path: abs, text });
      defined.push({ name: f, text });
    } else if (required || io.exists(abs)) into.gaps.push({ what: 'body', where: f, why: 'the compose file could not be read' });
  };
  // where the project is: the directory of the first file named, or of the first default file found (a relative context is
  // relative to it, not to the directory the command runs in)
  let projectBase = (files[0] ?? '').replace(/\/?[^/]*$/, '');
  if (files.length) for (const f of files) load(f, true);
  else {
    // compose looks in the working directory and then in each PARENT, and takes the first directory that has a file
    let dir = io.cwd;
    let found = false;
    for (let hops = 0; hops < 64 && !found; hops++) {
      const rel = hops === 0 ? '' : `${'../'.repeat(hops)}`;
      for (const c of [...COMPOSE_DEFAULTS, ...COMPOSE_OVERRIDES]) {
        const word = `${rel}${c}`;
        const abs = io.open(io.cwd, word);
        if (abs === null) continue;
        if (io.stale(word, abs)) {
          into.freshness.push({ what: 'freshness', where: word, why: `${word} is rewritten earlier in the same command` });
          continue;
        }
        if (!io.exists(abs)) continue;
        found = true;
        projectBase = rel.replace(/\/$/, '');
        load(word, false);
      }
      const up = dir.slice(0, dir.lastIndexOf('/')) || '/';
      if (up === dir) break;
      dir = up;
    }
    if (!found && !into.freshness.length)
      return { key, reason: 'no compose file', resolution: 'ABSENT_VERIFIED', body: null, hostBody: [], unresolved: [] };
  }
  const targets: Target[] = [];
  for (const d of defined) {
    const parsed = parseComposeAsTargets(d.name, d.text);
    for (const g of parsed.gaps) into.gaps.push(g);
    targets.push(...parsed.targets);
  }
  // compose resolves a relative context against the PROJECT directory: the directory of the first file, or the one named
  const base = projectDir ?? projectBase;
  const seen = new Set<string>();
  for (const t0 of targets) {
    const t = { ...t0 };
    if (t.dynamic.length) into.gaps.push({ what: 'config', where: t.name, why: `${t.dynamic.join(', ')} of service ${t.name} is not read` });
    if (t.remoteContext) {
      into.gaps.push({ what: 'context', where: t.name, why: `the context of service ${t.name} is remote` });
      continue;
    }
    const ctx = joinDir(base, t.context ?? '.');
    const k = `${ctx}\0${t.dockerfile ?? ''}\0${t.inline ?? ''}`;
    if (!seen.has(k)) {
      seen.add(k);
      readTargetDockerfile(t, ctx, io, into);
    }
    targetEffects(t, into);
  }
  return finishCollected(key, 'compose build', into, io);
}

function rootFileOptions(cmd: ContainerCommand): ReadOption[] {
  return cmd.rootOptions;
}

function joinDir(base: string, rel: string): string {
  if (rel.startsWith('/') || rel.startsWith('~')) return rel;
  if (base === '' || base === '.') return rel;
  return rel === '.' ? base : `${base}/${rel}`.replace(/\/\.\//g, '/');
}
