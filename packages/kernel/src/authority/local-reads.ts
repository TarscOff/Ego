// THE ONE TABLE OF "THIS INVOCATION ONLY LOOKS": the forms of a program that read local state, print it and change nothing
// the kernel governs (closure audit wave 5, U-15, U-19, AUTH-13).
//
// A command no matcher names is `command.unknown`, an ASK, and a program the bounded vocabulary does not list is an
// unmodelled closure on top of it. That is the right default for a program nobody modelled, and it was also the answer for
// `go list ./...`, `cargo tree`, `gem list`, `git symbolic-ref --short HEAD`, `git config -l --show-origin`, `gh run list`,
// `helm repo list` and `ego status`: the first command of every session in the ecosystems the matchers never reached, read
// by nobody as an act. The kernel's own diagnostics asked too, although the session start text tells the agent to run them.
//
// The shape is a POSITIVE GRAMMAR, because a list of the dangerous spellings is wrong by omission: a form names the words
// that select it, the options it knows to be inert, and how many operands of what shape it takes. Everything else - an
// option the row does not list, a word that is a glob or an expansion, a second operand where the form takes one - is not
// the form, and the command is judged as it was before this table existed. A row is added only for a form that
//   - executes nothing the repository wrote (no build script, no task, no `Gemfile`, no hook, no configured program),
//   - writes nothing outside the tool's own cache, and
//   - prints nothing that is a credential.
// Each row says which of the three it earned in `why`, and the test derives its cases from the rows: every `example` is
// ALLOW, every `acts` line beside it is not, and where the real tool is installed the row is run for real and the tree is
// compared before and after (closure-usability-b.test.ts).
//
// What is deliberately NOT here, and why: `bundle show|list|outdated|info` evaluate the `Gemfile`, which is Ruby (shown with
// the real bundler: a `system` call in the Gemfile runs on `bundle show`); `mvn` reads `.mvn/jvm.config` and hands it to the
// JVM even for `-v`; `./gradlew` is a script of the repository; `dotnet list` evaluates the project through MSBuild; `npm
// doctor`, `npm help` and `npm fund <n>` start a program that npm's configuration names; `yarn` runs the `yarnPath` the
// repository's rc file names; `python -m pip` finds a `pip` in the working directory first; `npm config get` prints tokens.

/** What a row is classified as: the plain read, or the forge read the matcher for the same family would have named. */
export type ReadCapability = 'command.read-only' | 'forge.repo.read' | 'forge.checks.read';

interface Form {
  /** the words after the program that select the form, as written: `['mod', 'graph']` */
  verb: readonly string[];
  /** options that take no value */
  flags?: readonly string[];
  /** options that take one, as a separate word or after `=`, and what the value may be */
  values?: Readonly<Record<string, RegExp>>;
  /** the operands after the options: how many, and what each may look like */
  operands?: { max: number; shape?: RegExp };
  capability?: ReadCapability;
  /** why the row is a read: what it executes, what it writes, what it prints */
  why: string;
  /** a command line the row accepts, run by the test (against the real tool when it is installed) */
  example: string;
  /** the row talks to a server (a registry, the forge): the test that runs the real tool leaves it out */
  network?: true;
  /** a neighbouring ACT the row must not accept, with the word that makes it one */
  acts?: readonly string[];
}

/** a name, a version, a package path or a relative path: no option, no glob, no expansion, no quote */
const NAME = /^[A-Za-z0-9_./~@][A-Za-z0-9_.@%+=:,~^/-]*$/;
/** a template or a jq expression is TEXT the tool evaluates itself; what it must not carry is a shell expansion */
const TEXT = /^[^$`\n\r\0*?]*$/;
const COUNT = /^\d+$/;
const LIST = /^[\w.,-]+$/;
const VARIABLE = /^[A-Za-z_][A-Za-z0-9_]*$/;

const FORMS: Readonly<Record<string, readonly Form[]>> = {
  // `go list|env|doc|mod graph` load packages and print. `go env -w|-u` WRITE the go env file, `go list -toolexec|-compiled|
  // -export|-cgo` run a compiler or a wrapper program, and `-mod=mod` / `-modfile` rewrite go.mod, so none of them is a flag here
  go: [
    { verb: ['list'], flags: ['-m', '-e', '-json', '-deps', '-test', '-find', '-versions', '-u', '-retracted'], values: { '-f': TEXT, '-tags': LIST }, operands: { max: 64, shape: NAME }, why: 'loads package metadata; no compiler, no wrapper', example: 'go list -m all', acts: ['go list -toolexec ./evil ./...', 'go list -export ./...'] },
    { verb: ['env'], flags: ['-json', '-changed'], operands: { max: 32, shape: VARIABLE }, why: 'prints the go environment', example: 'go env GOPATH', acts: ['go env -w GOFLAGS=-toolexec=./evil', 'go env -u GOFLAGS'] },
    { verb: ['doc'], flags: ['-all', '-c', '-cmd', '-short', '-src', '-u'], operands: { max: 3, shape: NAME }, why: 'prints documentation from source', example: 'go doc fmt.Println' },
    { verb: ['mod', 'graph'], operands: { max: 0 }, why: 'prints the module graph from go.mod', example: 'go mod graph' },
    { verb: ['mod', 'why'], flags: ['-m', '-vendor'], operands: { max: 32, shape: NAME }, why: 'prints why a package is needed', example: 'go mod why golang.org/x/text' },
    { verb: ['mod', 'verify'], operands: { max: 0 }, why: 'compares the module cache with go.sum', example: 'go mod verify' },
    { verb: ['help'], operands: { max: 2, shape: NAME }, why: 'prints a manual page of the tool itself', example: 'go help modules' },
  ],
  // `cargo tree|metadata|locate-project|pkgid` resolve the manifest and print. `cargo install|build|run|vendor|update` act,
  // and `cargo metadata --offline` stays a read: the manifest is data and a build script is never run by these verbs
  cargo: [
    {
      verb: ['tree'],
      flags: ['-d', '--duplicates', '--workspace', '--all-features', '--no-default-features', '--offline', '--locked', '--frozen', '-q', '--quiet', '--no-dedupe'],
      values: { '-p': NAME, '--package': NAME, '-i': NAME, '--invert': NAME, '-e': LIST, '--edges': LIST, '-f': TEXT, '--format': TEXT, '--depth': /^(\d+|workspace)$/, '--prefix': /^(depth|indent|none)$/, '--charset': /^(utf8|ascii)$/, '-F': LIST, '--features': LIST, '--target': LIST, '--manifest-path': NAME },
      operands: { max: 0 },
      why: 'resolves the dependency graph from the manifests and prints it',
      example: 'cargo tree --depth 1',
      acts: ['cargo install ripgrep', 'cargo tree --config build.rustc=./evil'],
    },
    { verb: ['metadata'], flags: ['--no-deps', '--all-features', '--no-default-features', '--offline', '--locked', '--frozen', '-q', '--quiet'], values: { '--format-version': COUNT, '-F': LIST, '--features': LIST, '--filter-platform': LIST, '--manifest-path': NAME }, operands: { max: 0 }, why: 'prints the resolved workspace as JSON; runs no build script', example: 'cargo metadata --format-version 1' },
    { verb: ['locate-project'], flags: ['--workspace'], values: { '--message-format': /^(plain|json)$/, '--manifest-path': NAME }, operands: { max: 0 }, why: 'prints where the manifest is', example: 'cargo locate-project' },
    { verb: ['pkgid'], values: { '-p': NAME, '--package': NAME, '--manifest-path': NAME }, operands: { max: 1, shape: NAME }, why: 'prints a package id', example: 'cargo pkgid' },
    { verb: ['search'], values: { '--limit': COUNT }, operands: { max: 8, shape: NAME }, why: 'queries the default registry index and prints', network: true, example: 'cargo search serde --limit 5' },
  ],
  // `gem list|env|which|contents|dependency|specification|search` read the installed gems and the registry index. The rubygems
  // plugins of INSTALLED gems load on every invocation, which is the installed environment and not the repository; `gem
  // install|uninstall|update|build|push|cleanup|pristine` act
  gem: [
    { verb: ['list'], flags: ['-a', '--all', '-d', '--details', '-e', '--exact', '-i', '--installed', '-l', '--local', '-r', '--remote', '--no-versions'], operands: { max: 4, shape: NAME }, why: 'lists installed gems', example: 'gem list', acts: ['gem install rails'] },
    { verb: ['env'], operands: { max: 1, shape: /^(home|path|version|gemdir|gempath|remotesources|platform|packageversion)$/ }, why: 'prints the rubygems environment', example: 'gem env' },
    { verb: ['environment'], operands: { max: 1, shape: /^(home|path|version|gemdir|gempath|remotesources|platform|packageversion)$/ }, why: 'prints the rubygems environment', example: 'gem environment home' },
    { verb: ['which'], flags: ['-a', '--all', '--no-all'], operands: { max: 4, shape: NAME }, why: 'prints where a library file is', example: 'gem which rake' },
    { verb: ['contents'], flags: ['-l', '--lib-only'], operands: { max: 1, shape: NAME }, why: 'lists the files of an installed gem', example: 'gem contents rake' },
    { verb: ['dependency'], flags: ['-R', '--reverse-dependencies', '-l', '--local', '-r', '--remote'], operands: { max: 1, shape: NAME }, why: 'prints the dependencies of a gem', example: 'gem dependency rake' },
    { verb: ['specification'], operands: { max: 1, shape: NAME }, why: 'prints the gemspec of an installed gem', example: 'gem specification rake' },
    { verb: ['search'], flags: ['-a', '--all', '-d', '--details', '-e', '--exact', '-r', '--remote', '-l', '--local'], operands: { max: 4, shape: NAME }, why: 'queries the registry index', network: true, example: 'gem search rake' },
  ],
  // `bundle config` reads `.bundle/config` and the rc files and evaluates no Gemfile; `bundle show|list|outdated|info|exec`
  // all evaluate the Gemfile, which is Ruby, and are not here
  bundle: [
    { verb: ['config', 'list'], operands: { max: 0 }, why: 'prints the bundler settings; does not load the Gemfile', example: 'bundle config list' },
    { verb: ['config', 'get'], operands: { max: 1, shape: /^[A-Za-z_][\w.]*$/ }, why: 'prints one bundler setting; does not load the Gemfile', example: 'bundle config get path' },
  ],
  // the dotnet host answers these without loading a project or an SDK command; `dotnet list|build|test|run|restore|tool` do
  dotnet: [
    { verb: ['--version'], operands: { max: 0 }, why: 'the host prints the SDK version global.json selects', example: 'dotnet --version' },
    { verb: ['--info'], operands: { max: 0 }, why: 'prints the SDKs and runtimes installed', example: 'dotnet --info' },
    { verb: ['--list-sdks'], operands: { max: 0 }, why: 'lists the SDKs installed', example: 'dotnet --list-sdks' },
    { verb: ['--list-runtimes'], operands: { max: 0 }, why: 'lists the runtimes installed', example: 'dotnet --list-runtimes' },
  ],
  // `git` global options were already taken off the line by the normalizer; what is left is the verb. Each form below is the
  // READ spelling of a verb that has a writing one: the number of operands is what tells `symbolic-ref HEAD` from `symbolic-ref
  // HEAD refs/heads/x`, and a list option is not a set option
  git: [
    { verb: ['symbolic-ref'], flags: ['-q', '--quiet', '--short', '--no-recurse'], operands: { max: 1, shape: NAME }, why: 'prints what one symbolic ref points at; a second operand would move it', example: 'git symbolic-ref --short HEAD', acts: ['git symbolic-ref HEAD refs/heads/other', 'git symbolic-ref -d HEAD'] },
    { verb: ['submodule'], operands: { max: 0 }, why: 'a bare `git submodule` is `status`', example: 'git submodule', acts: ['git submodule update --init', 'git submodule foreach make'] },
    { verb: ['submodule', 'status'], flags: ['--cached', '--recursive'], operands: { max: 16, shape: NAME }, why: 'prints the commit each submodule is at', example: 'git submodule status --recursive' },
    { verb: ['submodule', 'summary'], flags: ['--cached', '--files'], values: { '-n': COUNT, '--summary-limit': COUNT }, operands: { max: 16, shape: NAME }, why: 'prints the commits between the index and the submodules', example: 'git submodule summary' },
    {
      verb: ['config'],
      flags: ['-l', '--list', '--show-origin', '--show-scope', '--name-only', '-z', '--null', '--global', '--system', '--local', '--worktree', '--includes', '--no-includes', '--get', '--get-all', '--get-regexp', '--bool', '--int', '--bool-or-int'],
      values: { '--file': NAME, '-f': NAME, '--default': TEXT, '--type': /^(bool|int|bool-or-int|path|expiry-date|color)$/ },
      operands: { max: 1, shape: /^[A-Za-z0-9._^+-]+$/ },
      why: 'prints configuration; one operand is a key to READ (two would set it), and no option here writes, edits or unsets',
      example: 'git config --list --show-origin',
      acts: ['git config user.name Someone', 'git config --unset user.name', 'git config --edit', 'git config --add alias.x !evil'],
    },
    { verb: ['notes', 'list'], operands: { max: 1, shape: NAME }, why: 'lists notes', example: 'git notes list' },
    { verb: ['notes', 'show'], operands: { max: 1, shape: NAME }, why: 'prints a note', example: 'git notes show' },
  ],
  // GitHub CLI reads of the repository's own runs, releases and workflows, and of who is signed in. `--web` and `--show-token`
  // are not listed: one starts a browser, the other prints the token
  gh: [
    { verb: ['run', 'list'], capability: 'forge.checks.read', flags: ['-a', '--all'], values: { '-L': COUNT, '--limit': COUNT, '-b': NAME, '--branch': NAME, '-w': TEXT, '--workflow': TEXT, '-s': NAME, '--status': NAME, '-u': NAME, '--user': NAME, '-e': NAME, '--event': NAME, '-c': NAME, '--commit': NAME, '--json': LIST, '-q': TEXT, '--jq': TEXT, '-t': TEXT, '--template': TEXT }, operands: { max: 0 }, why: 'lists workflow runs through the forge API', example: 'gh run list -L 5 --json status', acts: ['gh run rerun 1', 'gh run cancel 1', 'gh run delete 1'] },
    { verb: ['run', 'view'], capability: 'forge.checks.read', flags: ['--log', '--log-failed', '-v', '--verbose', '--exit-status'], values: { '-j': COUNT, '--job': COUNT, '--json': LIST, '-q': TEXT, '--jq': TEXT, '-t': TEXT, '--template': TEXT, '-a': COUNT, '--attempt': COUNT }, operands: { max: 1, shape: COUNT }, why: 'prints one workflow run', example: 'gh run view 123 --log-failed' },
    { verb: ['workflow', 'list'], capability: 'forge.checks.read', flags: ['-a', '--all'], values: { '-L': COUNT, '--limit': COUNT, '--json': LIST, '-q': TEXT, '--jq': TEXT }, operands: { max: 0 }, why: 'lists workflows', example: 'gh workflow list', acts: ['gh workflow run ci.yml', 'gh workflow enable ci.yml'] },
    { verb: ['workflow', 'view'], capability: 'forge.checks.read', flags: ['-y', '--yaml'], values: { '-r': NAME, '--ref': NAME }, operands: { max: 1, shape: NAME }, why: 'prints one workflow', example: 'gh workflow view ci.yml --yaml' },
    { verb: ['release', 'list'], capability: 'forge.repo.read', flags: ['--exclude-drafts', '--exclude-pre-releases'], values: { '-L': COUNT, '--limit': COUNT, '--json': LIST, '-q': TEXT, '--jq': TEXT }, operands: { max: 0 }, why: 'lists releases', example: 'gh release list', acts: ['gh release create v1', 'gh release delete v1'] },
    { verb: ['release', 'view'], capability: 'forge.repo.read', values: { '--json': LIST, '-q': TEXT, '--jq': TEXT }, operands: { max: 1, shape: NAME }, why: 'prints one release', example: 'gh release view v1.0.0' },
    { verb: ['repo', 'list'], capability: 'forge.repo.read', values: { '-L': COUNT, '--limit': COUNT, '--json': LIST, '-q': TEXT, '--jq': TEXT }, operands: { max: 1, shape: NAME }, why: 'lists repositories', example: 'gh repo list --limit 10', acts: ['gh repo delete x', 'gh repo create x'] },
    { verb: ['auth', 'status'], flags: ['--active'], operands: { max: 0 }, why: 'prints who is signed in, with the token masked', example: 'gh auth status', acts: ['gh auth status --show-token', 'gh auth token'] },
  ],
  // `helm repo list|update`, `helm plugin list` and `helm dependency list` never contact a cluster, so the kubeconfig context is
  // not a question about them (k8s.ts asks this table before it asks which context). `repo add` records where charts come
  // from, and `dependency update|build` and `pull` bring charts the kernel has never read into the chart directory: those
  // stay the decision they were (the corpus class "a tool that fetches ... a chart from somewhere else")
  helm: [
    { verb: ['repo', 'list'], values: { '-o': /^(table|json|yaml)$/, '--output': /^(table|json|yaml)$/ }, operands: { max: 0 }, why: 'prints the repositories helm knows', example: 'helm repo list', acts: ['helm repo add x https://x.test', 'helm repo remove x'] },
    { verb: ['repo', 'update'], flags: ['--fail-on-repo-update-fail'], operands: { max: 16, shape: NAME }, why: 'refreshes the index of repositories the developer already added; index files are data', network: true, example: 'helm repo update' },
    { verb: ['plugin', 'list'], operands: { max: 0 }, why: 'lists installed plugins', example: 'helm plugin list', acts: ['helm plugin install https://x.test/p'] },
    { verb: ['dependency', 'list'], operands: { max: 1, shape: NAME }, why: 'prints the dependencies a chart declares', example: 'helm dependency list charts/app', acts: ['helm dependency update charts/app', 'helm dependency build charts/app'] },
    { verb: ['dep', 'list'], operands: { max: 1, shape: NAME }, why: 'an alias of dependency list', example: 'helm dep list charts/app' },
    { verb: ['dependencies', 'list'], operands: { max: 1, shape: NAME }, why: 'an alias of dependency list', example: 'helm dependencies list charts/app' },
    { verb: ['dependency', 'ls'], operands: { max: 1, shape: NAME }, why: 'an alias of dependency list', example: 'helm dependency ls charts/app' },
  ],
  // pip's own read verbs; `pip config list` is absent because it prints index URLs with the credentials they carry
  pip: [
    { verb: ['check'], operands: { max: 0 }, why: 'checks installed distributions', example: 'pip check' },
    { verb: ['cache', 'dir'], operands: { max: 0 }, why: 'prints the cache directory', example: 'pip cache dir', acts: ['pip cache purge'] },
    { verb: ['cache', 'info'], operands: { max: 0 }, why: 'prints cache statistics', example: 'pip cache info' },
    { verb: ['cache', 'list'], operands: { max: 1, shape: NAME }, why: 'lists cached wheels', example: 'pip cache list' },
    { verb: ['inspect'], operands: { max: 0 }, why: 'prints the installed environment as JSON', example: 'pip inspect' },
  ],
  // npm's read verbs that start nothing: `npm audit fix`, `npm pkg set`, `npm doctor` and `npm help` are not these
  npm: [
    { verb: ['root'], flags: ['-g', '--global'], operands: { max: 0 }, why: 'prints the node_modules directory', example: 'npm root' },
    { verb: ['prefix'], flags: ['-g', '--global'], operands: { max: 0 }, why: 'prints the project prefix', example: 'npm prefix' },
    { verb: ['pkg', 'get'], operands: { max: 16, shape: NAME }, why: 'prints fields of package.json', example: 'npm pkg get name version', acts: ['npm pkg set scripts.x=evil', 'npm pkg delete name'] },
    { verb: ['audit'], flags: ['--json', '--production', '--omit-dev'], values: { '--audit-level': /^(info|low|moderate|high|critical|none)$/, '--omit': LIST }, operands: { max: 0 }, why: 'sends the lockfile to the registry and prints the advisories', network: true, example: 'npm audit --json', acts: ['npm audit fix', 'npm audit fix --force'] },
    { verb: ['search'], flags: ['--json', '-l', '--long', '--parseable'], operands: { max: 8, shape: NAME }, why: 'queries the registry', network: true, example: 'npm search left-pad' },
  ],
  // EGO's own command line. The session start text tells the agent to run `ego help`, `ego status` and `ego explain capability`,
  // and the generated slash commands pre-approve `Bash(ego:*)`; each of these reads the control plane and the runtime state and
  // prints. `ego init`, `ego sync`, `ego modes set`, `ego sources add|remove`, `ego budget extend`, `ego decision answer` and
  // `ego hook` are the acts, and each has a rule of its own above
  ego: [
    { verb: ['version'], operands: { max: 0 }, why: 'prints the version', example: 'ego version' },
    { verb: ['help'], operands: { max: 1, shape: NAME }, why: 'prints what can be done here', example: 'ego help' },
    { verb: ['status'], operands: { max: 0 }, why: 'prints the pin, the runtime root and the live sessions', example: 'ego status' },
    { verb: ['doctor'], flags: ['--offline', '--capabilities'], values: { '--host': /^(claude-code|codex-cli)$/ }, operands: { max: 0 }, why: 'checks the installation and prints', example: 'ego doctor --offline' },
    { verb: ['check'], operands: { max: 0 }, why: 'checks the project against the control plane and prints', example: 'ego check' },
    { verb: ['capabilities'], values: { '--profile': NAME, '--mode': NAME }, operands: { max: 1, shape: NAME }, why: 'prints the capability table in force', example: 'ego capabilities git' },
    { verb: ['explain', 'capability'], values: { '--profile': NAME, '--mode': NAME }, operands: { max: 1, shape: NAME }, why: 'prints why a capability has its verdict', example: 'ego explain capability git.remote.push' },
    { verb: ['authority', 'diff'], flags: ['--fail-on-widening'], operands: { max: 2, shape: NAME }, why: 'prints the changes between two authority tables and applies none', example: 'ego authority diff core current' },
    { verb: ['modes'], operands: { max: 0 }, why: 'lists the modes; `modes set` is the act', example: 'ego modes', acts: ['ego modes set EGO_MAINTENANCE --session s'] },
    { verb: ['context', 'explain'], operands: { max: 0 }, why: 'prints what the session start loads', example: 'ego context explain' },
    { verb: ['sources'], operands: { max: 0 }, why: 'lists the release sources; `add` and `remove` are the act', example: 'ego sources', acts: ['ego sources add file:/x'] },
    { verb: ['sources', 'list'], operands: { max: 0 }, why: 'lists the release sources', example: 'ego sources list' },
  ],
};

/** what the table says about one invocation */
export interface LocalRead {
  program: string;
  /** the words that selected the row */
  form: string;
  capability: ReadCapability;
}

/** the row whose `verb` is the longest prefix of the words after the program, or undefined */
function rowFor(program: string, words: readonly string[]): Form | undefined {
  let best: Form | undefined;
  for (const f of FORMS[program] ?? [])
    if (f.verb.length <= words.length && f.verb.every((v, i) => words[i] === v) && (best === undefined || f.verb.length > best.verb.length)) best = f;
  return best;
}

/** whether the words after the verb are the options and operands of the row, and nothing else */
function fits(f: Form, rest: readonly string[]): boolean {
  const flags = new Set(f.flags ?? []);
  const values = f.values ?? {};
  let operands = 0;
  for (let i = 0; i < rest.length; i++) {
    const w = rest[i]!;
    if (w.startsWith('-') && w.length > 1) {
      const eq = w.indexOf('=');
      const name = eq > 0 && w.startsWith('--') ? w.slice(0, eq) : w;
      if (flags.has(w)) continue;
      const shape = Object.hasOwn(values, name) ? values[name] : undefined;
      if (shape === undefined) return false;
      const value = eq > 0 && w.startsWith('--') ? w.slice(eq + 1) : rest[++i];
      if (value === undefined || !shape.test(value)) return false;
      continue;
    }
    operands++;
    if (operands > (f.operands?.max ?? 0) || !(f.operands?.shape ?? NAME).test(w)) return false;
  }
  return true;
}

/**
 * Whether `tokens` (the program and the words after it, quotes already removed) is a form this table knows to be a read.
 * The program must be the bare name: a path names a file of the repository, which is not the tool the row describes.
 */
export function localRead(tokens: readonly string[]): LocalRead | null {
  const program = tokens[0];
  if (program === undefined || !Object.hasOwn(FORMS, program)) return null;
  const words = tokens.slice(1);
  const row = rowFor(program, words);
  if (row === undefined || !fits(row, words.slice(row.verb.length))) return null;
  return { program, form: row.verb.join(' '), capability: row.capability ?? 'command.read-only' };
}

/** the rows, for the test that derives its cases from them */
export function localReadRows(): Array<{ program: string; verb: string; example: string; acts: readonly string[]; why: string; network: boolean }> {
  // (every `gh` row talks to the forge)
  return Object.entries(FORMS).flatMap(([program, rows]) =>
    rows.map((r) => ({ program, verb: r.verb.join(' '), example: r.example, acts: r.acts ?? [], why: r.why, network: r.network === true || program === 'gh' })),
  );
}
