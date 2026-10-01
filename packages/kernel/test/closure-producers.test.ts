// CLOSURE AUDIT 2026-10-01, SECOND WAVE - THE PRODUCER AND PROFILE LEFTOVERS OF THE FIRST WAVE.
//
// Each group below pins one thing the first wave found and could not close inside its own task. They share a file
// because they share a shape: a READER that answers one question in two places and is right in one of them, or a
// table that is stricter in one profile than in the stricter one. A group names the verdict a reader must give
// (never "the same as before"), tries the neighbouring spellings, and keeps one control that must stay as it was.
//
//   1. a make target whose name carries a space, a colon or a hash is the target make finds, not the shell's reading
//   2. the environment spelling of an npm option is the option
//   3. lint-staged configurations below the working directory
//   4. a stricter profile is never looser than a weaker one, for any capability
//   5. a dynamic word after the last dry-run flag
//   6. a file a command WRITES is not a program it runs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { evaluate, listIndexedPaths } from '../src/authority/evaluate.ts';
import { compileAuthority, PROFILE_ORDER } from '../src/authority/compile.ts';
import { loadControlPlane } from '../src/control-plane/load.ts';
import { ControlPlaneValidationError, VERDICT_RANK } from '../src/control-plane/types.ts';
import { RANK, ctx, table, workspace, verdict } from './support/corpus.ts';

/** what the recipes below would do if they were READ: an absolute-class act, so "read" (DENY) and "hidden" (ALLOW)
 *  and "gated unread" (ASK) are three different answers */
const ACT = 'git push --force origin main';

const v = (command: string, files: Record<string, string> = {}): string => verdict(command, workspace(files));

/* ------------------------------------------------------------------------------------------------------------- *
 * 1. MAKE'S TARGET-NAME GRAMMAR IS NOT THE SHELL'S
 *
 * make splits a rule's target list on unescaped blanks, ends it at an unescaped colon, and reads a backslash in
 * front of a blank, a colon or a hash as part of the name - `a\ b:` defines ONE target, `a b`. A command-line goal
 * is one name whatever it contains: `make 'a b'` asks for that target. The parser split the rule line on every
 * whitespace and cut the target at the first colon, so the target it registered was never the one make looked up,
 * the goal came out "absent", and the recipe ran under ALLOW.
 *
 * Verified against GNU make 3.81 (the macOS make): the run of backslashes in front of a blank or a colon halves
 * (`k\\\ l` is the name `k\ l`; `q\\:` is the name `q\`), a backslash in front of anything else stays.
 * ------------------------------------------------------------------------------------------------------------- */

const MAKE_NAMES: Array<[label: string, makefileTarget: string, goal: string]> = [
  ['an escaped space', 'a\\ b', "'a b'"],
  ['the same goal in double quotes', 'a\\ b', '"a b"'],
  ['the same goal with the space escaped for the shell', 'a\\ b', 'a\\ b'],
  ['an escaped colon', 'a\\:b', "'a:b'"],
  ['an escaped hash', 'a\\#b', "'a#b'"],
  ['two escaped spaces', 'a\\ b\\ c', "'a b c'"],
  ['an escaped space after a path', 'dist/a\\ b', "'dist/a b'"],
  ['a leading ./ on the rule', './a\\ b', "'a b'"],
  ['a pair of backslashes then a blank: the pair is ONE backslash and the blank ends the name', 'e\\\\ f', "'e\\'"],
  ['three backslashes then a blank: a backslash and an escaped blank', 'k\\\\\\ l', "'k\\ l'"],
  ['an escaped space inside a rule with two targets', 'x a\\ b', "'a b'"],
  ['a target made of an escaped space only after a plain one', 'plain a\\ b', 'plain'],
];

test('make: a target whose name holds an escaped special character is found by the goal that names it', () => {
  const wrong: string[] = [];
  for (const [label, target, goal] of MAKE_NAMES) {
    const got = v(`make ${goal}`, { Makefile: `${target}:\n\t${ACT}\n` });
    if (got !== 'DENY') wrong.push(`${label}: make ${goal} with the rule "${target}:" must read the recipe, got ${got}`);
  }
  assert.deepEqual(wrong, []);
});

test('make: the same rule reached as a prerequisite is read by the same grammar', () => {
  const rows: Array<[string, string]> = [
    ['all: a\\ b\na\\ b:\n', 'make all'],
    ['all: a\\:b\na\\:b:\n', 'make all'],
    ['all: a\\#b\na\\#b:\n', 'make all'],
    ['all: x a\\ b | y\na\\ b:\n', 'make all'],
    ['.DEFAULT_GOAL := a\\ b\na\\ b:\n', 'make'],
    ['a\\ b:\n', 'make'],
  ];
  const wrong: string[] = [];
  for (const [head, command] of rows) {
    const got = v(command, { Makefile: `${head}\t${ACT}\n` });
    if (got !== 'DENY') wrong.push(`${command} with ${JSON.stringify(head)} must read the recipe, got ${got}`);
  }
  assert.deepEqual(wrong, []);
});

test('make: the escaped-name rule is read however the makefile is reached and the rule is written', () => {
  const own = `a\\ b:\n\t${ACT}\n`;
  const rows: Array<[command: string, files: Record<string, string>]> = [
    ["make -f other.mk 'a b'", { 'other.mk': own }],
    ["make -C sub 'a b'", { 'sub/Makefile': own }],
    ["cd sub && make 'a b'", { 'sub/Makefile': own }],
    ["make -- 'a b'", { Makefile: own }],
    ["make -n 'a b'", { Makefile: `a\\ b:\n\t+${ACT}\n` }], // `+` still runs under -n
    ["make 'a b'", { Makefile: `a\\ b: ; ${ACT}\n` }],
    ["make 'a b'", { Makefile: `a\\ b:: \n\t${ACT}\n` }],
    ["make 'a b'", { Makefile: `a\\ b: # the comment\n\t${ACT}\n` }],
    ["make 'a b'", { Makefile: `  a\\ b:\n\t${ACT}\n` }],
    ["make 'a b'", { Makefile: `a\\ b:\n\techo hi\na\\ b:\n\t${ACT}\n` }],
    ["make 'a b'", { Makefile: `.DEFAULT_GOAL := a b\na\\ b:\n\t${ACT}\n` }],
    ['make', { Makefile: `.DEFAULT_GOAL := a b\na\\ b:\n\t${ACT}\n` }],
    ["make 'a b'", { Makefile: `a\\ b: V = x\na\\ b:\n\t${ACT}\n` }],
    ["make all", { Makefile: `all: sub\\ dir/a\\ b\nsub\\ dir/a\\ b:\n\t${ACT}\n` }],
    ["make 'dir/a b'", { Makefile: `dir/a\\ b:\n\t${ACT}\n` }],
    ["make -f 'my file.mk' 'a b'", { 'my file.mk': own }],
  ];
  const wrong: string[] = [];
  for (const [command, files] of rows) {
    const got = v(command, files);
    if (got !== 'DENY') wrong.push(`${command} over ${JSON.stringify(files)}: must read the recipe, got ${got}`);
  }
  assert.deepEqual(wrong, []);
});

test('make: an included makefile whose name holds an escaped space is the file make includes', () => {
  assert.equal(
    v('make x', { Makefile: '-include a\\ b.mk\nx:\n\techo hi\n', 'a b.mk': `x:\n\t${ACT}\n` }),
    'DENY',
    'an optional include of "a b.mk" must be read, not treated as two absent files',
  );
  assert.equal(v('make x', { Makefile: 'include a\\ b.mk\nx:\n\techo hi\n', 'a b.mk': `y:\n\t${ACT}\n` }), 'ALLOW');
});

test('make: the reader is exact, not only careful - a goal the rule does not name stays what it was', () => {
  const mk = { Makefile: `a\\ b:\n\t${ACT}\n` };
  // `a b` is ONE target: neither word of it is a target on its own
  assert.equal(v('make a', mk), 'ALLOW');
  assert.equal(v('make b', mk), 'ALLOW');
  // the backslash is part of the name only on the Makefile side; on the command line it is a character like any other
  assert.equal(v("make 'a\\ b'", mk), 'ALLOW');
  // a benign recipe under the escaped name stays what it was
  assert.equal(v("make 'a b'", { Makefile: 'a\\ b:\n\techo hi\n' }), 'ALLOW');
  // and the unescaped two-target rule still defines two targets
  assert.equal(v('make b', { Makefile: `a b:\n\t${ACT}\n` }), 'DENY');
  assert.equal(v("make 'a b'", { Makefile: `a b:\n\t${ACT}\n` }), 'ALLOW');
});

test('make: a wildcard in a target or prerequisite names no literal target, so the makefile is not read as complete', () => {
  // make expands `*`, `?` and `[` in a rule's names against the files that exist; the text names no target at all
  for (const head of ['dep*:', 'd?ploy:', '[d]eploy:', 'deploy dep*:']) {
    const got = v('make deploy', { Makefile: `${head}\n\t${ACT}\n`, deploy: 'x' });
    assert.notEqual(got, 'ALLOW', `${head} is a rule for whatever files match: make deploy cannot be proved to run nothing`);
  }
  assert.notEqual(
    v('make all', { Makefile: `all: dep*\ndeploy:\n\t${ACT}\n`, deploy: 'x' }),
    'ALLOW',
    'a wildcard prerequisite names whatever files exist, and one of them may have a rule',
  );
  // a makefile without any of it is unchanged
  assert.equal(v('make deploy', { Makefile: 'deploy:\n\techo hi\n' }), 'ALLOW');
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 2. THE ENVIRONMENT SPELLING OF AN npm OPTION IS THE OPTION
 *
 * npm turns every `npm_config_<name>` variable into the configuration key `<name>` (prefix in any case, the
 * underscores after the first character become hyphens, the rest is lower-cased), so `npm_config_node_options` is
 * `--node-options` and `NPM_CONFIG_ONLOAD_SCRIPT` is `--onload-script`. The reading of that family was an
 * enumeration of the dangerous names - and `node-options`, the one the flag and the `.npmrc` readers already knew,
 * was not on it. What is accepted now is a short list of keys known to execute nothing and redirect nothing;
 * every other key asks.
 * ------------------------------------------------------------------------------------------------------------- */

const BUILD = { 'package.json': JSON.stringify({ scripts: { build: 'tsc -p .', test: 'tsc -p .' } }), 'evil.js': '1' };

test('npm: the environment spelling of a key that loads code is the key', () => {
  const rows: string[] = [
    "npm_config_node_options='--require ./evil.js' npm run build",
    "NPM_CONFIG_NODE_OPTIONS='--require ./evil.js' npm run build",
    "Npm_Config_Node_Options='--require ./evil.js' npm run build",
    "NPM_config_node_options='--require ./evil.js' npm run build",
    "npm_config_node_options='--require ./evil.js' npm test",
    "npm_config_node_options='--require ./evil.js' pnpm build",
    "npm_config_node_options='--require ./evil.js' yarn build",
    "npm_config_node_options='--require ./evil.js' npx tsc",
    "env npm_config_node_options='--require ./evil.js' npm run build",
    "env -i npm_config_node_options='--require ./evil.js' npm run build",
    "export npm_config_node_options='--require ./evil.js' && npm run build",
    "npm_config_node_options='--require ./evil.js'; npm run build",
    'npm_config_onload_script=./evil.js npm run build',
    'npm_config_init_module=./evil.js npm run build',
    'npm_config_node_gyp=./evil.sh npm run build',
    'npm_config_scripts_prepend_node_path=true npm run build',
    'npm_config_editor=./evil.sh npm run build',
    'npm_config_git=./evil.sh npm run build',
    'npm_config_browser=./evil.sh npm run build',
    'npm_config_script_shell=./evil.sh npm run build',
    'npm_config_shell=./evil.sh npm run build',
  ];
  const wrong: string[] = [];
  for (const command of rows) {
    const got = v(command, BUILD);
    if (got === 'ALLOW') wrong.push(`${command} -> ${got}`);
  }
  assert.deepEqual(wrong, []);
});

test('npm: a key nobody listed asks, because the family is read by what npm accepts and not by what was thought of', () => {
  const wrong: string[] = [];
  for (const name of ['npm_config_somethingnew', 'npm_config_unsafe_perm', 'npm_config_x1', 'npm_config_user_agent', 'npm_config_yes', 'npm_config_store_dir', 'npm_config_pnpmfile'])
    if (v(`${name}=1 npm run build`, BUILD) === 'ALLOW') wrong.push(name);
  assert.deepEqual(wrong, []);
});

test('npm: the keys that execute nothing and redirect nothing stay ordinary', () => {
  const ordinary = [
    'npm_config_loglevel=silent npm run build',
    'npm_config_loglevel=warn npm test',
    'npm_config_color=false npm test',
    'NPM_CONFIG_COLOR=false npm test',
    'npm_config_progress=false npm run build',
    'npm_config_update_notifier=false npm run build',
    'npm_config_fund=false npm_config_audit=false npm run build',
    'npm_config_legacy_peer_deps=true npm run build',
    'npm_config_engine_strict=true npm run build',
    'npm_config_prefer_offline=true npm run build',
    'npm_config_fetch_retries=5 npm run build',
    'npm_config_omit=dev npm run build',
    'npm_config_json=true npm test',
    // npm ignores an empty value: nothing is set
    'npm_config_node_options= npm run build',
  ];
  const wrong: string[] = [];
  for (const command of ordinary) {
    const got = v(command, BUILD);
    if (got !== 'ALLOW') wrong.push(`${command} -> ${got}`);
  }
  assert.deepEqual(wrong, []);
});

test('npm: a key that runs code is one key whether it arrives as a flag, as an .npmrc line or as a variable', () => {
  const keys = ['onload-script', 'node-gyp', 'init-module', 'editor', 'git', 'browser', 'scripts-prepend-node-path', 'node-options', 'script-shell', 'shell'];
  const wrong: string[] = [];
  for (const key of keys) {
    const spellings: Array<[string, string, Record<string, string>]> = [
      ['flag', `npm run build --${key}=./x`, BUILD],
      ['rc', 'npm run build', { ...BUILD, '.npmrc': `${key}=./x\n` }],
      ['variable', `npm_config_${key.replaceAll('-', '_')}=./x npm run build`, BUILD],
    ];
    for (const [how, command, files] of spellings) {
      const got = v(command, files);
      if (got === 'ALLOW') wrong.push(`${key} as a ${how}: ${command} -> ${got}`);
    }
  }
  assert.deepEqual(wrong, []);
  // the same file with harmless keys stays ordinary
  assert.equal(v('npm run build', { ...BUILD, '.npmrc': 'loglevel=silent\nfund=false\naudit=false\n' }), 'ALLOW');
  assert.equal(v('npm run build --loglevel=silent --if-present', BUILD), 'ALLOW');
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 3. lint-staged CONFIGURATIONS BELOW THE WORKING DIRECTORY
 *
 * Since lint-staged 13 the tool takes the configuration nearest to EACH staged file, and it finds them with
 * `git ls-files` - the tracked files and the untracked ones git does not ignore. A `.lintstagedrc` under `packages/a`
 * therefore runs on the files staged there even when lint-staged is started at the repository root. The producer
 * walked UP from the working directory only, so a nested configuration was never read: its commands ran under the
 * root configuration's ALLOW.
 *
 * The universe lint-staged sees is read the way git does, WITHOUT running git: the classifier never starts a program the
 * repository's own configuration can name (core.fsmonitor), so the tracked paths come from the index file and the
 * untracked ones from a walk that skips what the ignore files provably exclude. Both are bounded; a reached bound is
 * an ask that says so, never "nothing there".
 * ------------------------------------------------------------------------------------------------------------- */

const GIT_ENV = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' };
function git(dir: string, ...args: string[]): string {
  return execFileSync('git', args, { cwd: dir, env: GIT_ENV, stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 64 * 1024 * 1024 }).toString();
}
/** a workspace that is a real repository: `tracked` paths are in its index, added with -f so an ignored one can be tracked */
function repo(files: Record<string, string>, tracked: string[] = [], indexVersion?: number): string {
  const dir = workspace(files);
  git(dir, 'init', '-q');
  if (tracked.length) git(dir, 'add', '-f', '--', ...tracked);
  if (indexVersion) git(dir, 'update-index', '--index-version', String(indexVersion));
  return dir;
}
const BAD_RC = JSON.stringify({ '*.js': ACT });
const OK_RC = JSON.stringify({ '*.js': 'eslint --fix' });
const BAD_PKG = JSON.stringify({ name: 'a', 'lint-staged': { '*.ts': ACT } });
const OK_PKG = JSON.stringify({ name: 'a', 'lint-staged': { '*.ts': 'eslint --fix' } });

test('lint-staged: a configuration below the working directory is read, whether git tracks it or not', () => {
  const rows: Array<[label: string, command: string, files: Record<string, string>, tracked: string[]]> = [
    ['an untracked rc one level down', 'npx lint-staged', { '.lintstagedrc.json': OK_RC, 'packages/a/.lintstagedrc.json': BAD_RC }, []],
    ['the bare rc name', 'npx lint-staged', { '.lintstagedrc.json': OK_RC, 'packages/a/.lintstagedrc': BAD_RC }, []],
    ['four levels down', 'npx lint-staged', { '.lintstagedrc.json': OK_RC, 'a/b/c/d/.lintstagedrc.json': BAD_RC }, []],
    ['with no configuration at the root at all', 'npx lint-staged', { 'sub/.lintstagedrc.json': BAD_RC }, []],
    ['a nested manifest that names lint-staged', 'npx lint-staged', { '.lintstagedrc.json': OK_RC, 'packages/a/package.json': BAD_PKG }, []],
    ['the same, run as the binary', 'lint-staged', { '.lintstagedrc.json': OK_RC, 'packages/a/.lintstagedrc.json': BAD_RC }, []],
    ['started in a directory above the nested one', 'cd packages && npx lint-staged', { '.lintstagedrc.json': OK_RC, 'packages/a/b/.lintstagedrc.json': BAD_RC }, []],
    ['a tracked rc', 'npx lint-staged', { '.lintstagedrc.json': OK_RC, 'packages/a/.lintstagedrc.json': BAD_RC }, ['packages/a/.lintstagedrc.json']],
    ['a tracked manifest', 'npx lint-staged', { '.lintstagedrc.json': OK_RC, 'packages/a/package.json': BAD_PKG }, ['packages/a/package.json']],
    ['one of several nested, the others harmless', 'npx lint-staged', { '.lintstagedrc.json': OK_RC, 'packages/a/package.json': OK_PKG, 'packages/b/package.json': '{"name":"b"}', 'packages/c/.lintstagedrc.json': BAD_RC }, []],
    // a configuration that is tracked inside a directory the ignore file excludes: only the index knows it
    ['tracked under an ignored directory', 'npx lint-staged', { '.gitignore': 'vendor/\n', '.lintstagedrc.json': OK_RC, 'vendor/x/.lintstagedrc.json': BAD_RC }, ['.gitignore', 'vendor/x/.lintstagedrc.json']],
    // a dot-directory, a directory named like an ignored one in another place, a pattern the walk does not understand
    ['inside a dot-directory', 'npx lint-staged', { '.lintstagedrc.json': OK_RC, '.tools/x/.lintstagedrc.json': BAD_RC }, []],
    ['under a name the ignore file lists only at the root', 'npx lint-staged', { '.gitignore': '/dist\n', '.lintstagedrc.json': OK_RC, 'pkg/dist/.lintstagedrc.json': BAD_RC }, []],
    ['under a directory a wildcard pattern ignores', 'npx lint-staged', { '.gitignore': 'build*\n', '.lintstagedrc.json': OK_RC, 'build-x/.lintstagedrc.json': BAD_RC }, []],
    ['under a directory a negation could re-include', 'npx lint-staged', { '.gitignore': 'out/\n!out/keep/\n', '.lintstagedrc.json': OK_RC, 'out/keep/.lintstagedrc.json': BAD_RC }, []],
    // a node_modules the ignore file does not mention is not special
    ['inside node_modules that nothing ignores', 'npx lint-staged', { '.lintstagedrc.json': OK_RC, 'node_modules/p/.lintstagedrc.json': BAD_RC }, []],
  ];
  const wrong: string[] = [];
  for (const [label, command, files, tracked] of rows) {
    const got = verdict(command, repo(files, tracked));
    if (got !== 'DENY') wrong.push(`${label}: ${command} must read the nested configuration, got ${got}`);
  }
  assert.deepEqual(wrong, []);
});

test('lint-staged: a nested configuration that is code or is not readable is the human gate, as the root one is', () => {
  const rows: Array<[string, Record<string, string>]> = [
    ['a JavaScript module', { '.lintstagedrc.json': OK_RC, 'packages/a/lint-staged.config.js': 'module.exports = {}' }],
    ['an rc module', { '.lintstagedrc.json': OK_RC, 'packages/a/.lintstagedrc.cjs': 'module.exports = {}' }],
    ['a YAML rc', { '.lintstagedrc.json': OK_RC, 'packages/a/.lintstagedrc.yaml': "'*.js': eslint\n" }],
    ['a manifest that is not JSON', { '.lintstagedrc.json': OK_RC, 'packages/a/package.json': '{ "lint-staged": ' }],
    ['a package.yaml that names lint-staged', { '.lintstagedrc.json': OK_RC, 'packages/a/package.yaml': "lint-staged:\n  '*.js': eslint\n" }],
    ['a rc that is not an object', { '.lintstagedrc.json': OK_RC, 'packages/a/.lintstagedrc.json': '[1]' }],
  ];
  const wrong: string[] = [];
  for (const [label, files] of rows) {
    const got = verdict('npx lint-staged', repo(files));
    if (got !== 'ASK') wrong.push(`${label}: got ${got}`);
  }
  assert.deepEqual(wrong, []);
});

test('lint-staged: what stays as it was - a root configuration alone, harmless nested ones, everything git does not see', () => {
  const same: Array<[label: string, command: string, files: Record<string, string>, tracked?: string[]]> = [
    ['a root configuration only', 'npx lint-staged', { '.lintstagedrc.json': OK_RC }],
    ['a root manifest only', 'npx lint-staged', { 'package.json': OK_PKG }],
    ['nested manifests that name no lint-staged', 'npx lint-staged', { '.lintstagedrc.json': OK_RC, 'packages/a/package.json': '{"name":"a"}', 'packages/b/package.json': '{"name":"b","scripts":{}}' }],
    ['a harmless nested configuration', 'npx lint-staged', { '.lintstagedrc.json': OK_RC, 'packages/a/.lintstagedrc.json': OK_RC }],
    ['a sibling directory of the working directory', 'cd packages/b && npx lint-staged', { '.lintstagedrc.json': OK_RC, 'packages/b/src/x.ts': '1', 'packages/a/.lintstagedrc.json': BAD_RC }],
    // git does not list an untracked file in an ignored directory, so lint-staged never meets it
    ['an untracked file in an ignored directory', 'npx lint-staged', { '.gitignore': 'node_modules/\n', '.lintstagedrc.json': OK_RC, 'node_modules/p/.lintstagedrc.json': BAD_RC }],
    ['the same, spelled /name', 'npx lint-staged', { '.gitignore': '/node_modules\n', '.lintstagedrc.json': OK_RC, 'node_modules/p/.lintstagedrc.json': BAD_RC }],
    ['the same, spelled **/name', 'npx lint-staged', { '.gitignore': '**/node_modules\n', '.lintstagedrc.json': OK_RC, 'a/node_modules/p/.lintstagedrc.json': BAD_RC }],
    ['the same, spelled name/*', 'npx lint-staged', { '.gitignore': 'node_modules/*\n', '.lintstagedrc.json': OK_RC, 'node_modules/p/.lintstagedrc.json': BAD_RC }],
    ['an ignore file in the directory itself', 'npx lint-staged', { '.lintstagedrc.json': OK_RC, 'packages/.gitignore': 'gen\n', 'packages/gen/x/.lintstagedrc.json': BAD_RC }],
    // a nested repository is another repository: git lists it as one entry and lint-staged never goes in
    ['a nested repository', 'npx lint-staged', { '.lintstagedrc.json': OK_RC, 'vendor/lib/.git/HEAD': 'ref: refs/heads/main\n', 'vendor/lib/.git/objects/.keep': '', 'vendor/lib/.git/refs/.keep': '', 'vendor/lib/.lintstagedrc.json': BAD_RC }],
    ['a name that is not a configuration', 'npx lint-staged', { '.lintstagedrc.json': OK_RC, 'packages/a/lintstagedrc.json': BAD_RC, 'packages/a/.lintstaged.json': BAD_RC }],
  ];
  const wrong: string[] = [];
  for (const [label, command, files, tracked] of same) {
    const got = verdict(command, repo(files, tracked ?? []));
    if (got !== 'ALLOW') wrong.push(`${label}: ${command} -> ${got}`);
  }
  assert.deepEqual(wrong, []);
  // a directory that merely LOOKS like a nested repository is walked: git only skips a real one
  const fake = repo({ '.lintstagedrc.json': OK_RC, 'vendor/lib/.git/placeholder': '', 'vendor/lib/.lintstagedrc.json': BAD_RC });
  assert.equal(verdict('npx lint-staged', fake), 'DENY');
  // a link is a file to git and is not followed
  const target = workspace({ '.lintstagedrc.json': BAD_RC });
  const linked = repo({ '.lintstagedrc.json': OK_RC });
  execFileSync('ln', ['-s', target, join(linked, 'elsewhere')]);
  assert.equal(verdict('npx lint-staged', linked), 'ALLOW');
});

test('lint-staged: the commit hook that runs it reads the nested configuration too', () => {
  const files = {
    '.lintstagedrc.json': OK_RC,
    'packages/a/.lintstagedrc.json': BAD_RC,
    '.git/hooks/pre-commit': '#!/bin/sh\nnpx lint-staged\n',
  };
  assert.notEqual(verdict('git commit -m x', repo(files)), 'ALLOW');
  assert.equal(verdict('git commit -m x', repo({ ...files, 'packages/a/.lintstagedrc.json': OK_RC })), 'ALLOW');
});

test('lint-staged: a shell it is told to use runs every task, so the configuration was not read to its end', () => {
  const files = { '.lintstagedrc.json': OK_RC };
  const wrong: string[] = [];
  for (const command of ['npx lint-staged --shell /tmp/evil', 'npx lint-staged -x /tmp/evil', 'npx lint-staged --shell=/tmp/evil', 'lint-staged --shell ./evil.sh'])
    if (verdict(command, repo(files)) === 'ALLOW') wrong.push(command);
  assert.deepEqual(wrong, []);
  // the other options of the tool select nothing that runs
  for (const command of ['npx lint-staged --diff main', 'npx lint-staged --concurrent false', 'npx lint-staged --quiet'])
    assert.equal(verdict(command, repo(files)), 'ALLOW', command);
});

test('lint-staged: a configuration this command writes below the working directory is not the one that was there', () => {
  const base = { '.lintstagedrc.json': OK_RC, 'evil/.lintstagedrc.json': BAD_RC, 'evil/x': '1' };
  const stale: string[] = [
    `mkdir -p sub && printf '%s' '${BAD_RC}' > sub/.lintstagedrc.json && npx lint-staged`,
    `printf '%s' '${BAD_RC}' > packages/a/.lintstagedrc && npx lint-staged`,
    `cp -r evil sub && npx lint-staged`,
    `cp evil/.lintstagedrc.json sub-rc && npx lint-staged`,
    `mv evil sub && npx lint-staged`,
    `cp -R evil newdir && npx lint-staged`,
    `printf '%s' '${BAD_PKG}' > packages/package.json && npx lint-staged`,
  ];
  const wrong: string[] = [];
  for (const command of stale) {
    const got = verdict(command, repo(base));
    if (got === 'ALLOW') wrong.push(command);
  }
  assert.deepEqual(wrong, []);
  // a write that cannot be a configuration is not a reason to ask
  assert.equal(verdict("mkdir -p src && printf 'x' > src/a.ts && npx lint-staged", repo({ '.lintstagedrc.json': OK_RC })), 'ALLOW');
  assert.equal(verdict("printf 'x' > notes.txt && npx lint-staged", repo({ '.lintstagedrc.json': OK_RC })), 'ALLOW');
});

test('lint-staged: a bound that is reached is an ask that says so - never "nothing there"', () => {
  // 20001 untracked files git does not ignore: the walk gives up before it can show there is no configuration among them
  const big: Record<string, string> = { '.lintstagedrc.json': OK_RC };
  for (let i = 0; i < 20_001; i++) big[`big/d${i % 50}/f${i}.txt`] = '';
  const dir = repo(big);
  const r = evaluate(table, ctx(dir), { tool: 'Bash', input: { command: 'npx lint-staged' } });
  assert.equal(r.verdict, 'ASK');
  assert.match(JSON.stringify(r.hits), /bound/, 'the reason names the bound');
  // the same tree with the directory ignored is not walked, and the answer is the ordinary one
  const ignored = repo({ ...big, '.gitignore': 'big/\n' });
  assert.equal(verdict('npx lint-staged', ignored), 'ALLOW');
});

test('lint-staged: more tracked configurations than the bound is an ask that says so', () => {
  const many: Record<string, string> = { '.lintstagedrc.json': OK_RC };
  const entries: string[] = [];
  for (let i = 0; i < 20_001; i++) {
    many[`p${i}/package.json`] = '{}';
    entries.push(`100644 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 0\tp${i}/package.json`);
  }
  const dir = repo(many);
  // the entries go straight into the index, as `git add` of twenty thousand files would put them, without the cost
  execFileSync('git', ['update-index', '--add', '--index-info'], { cwd: dir, env: GIT_ENV, input: entries.join('\n') + '\n' });
  const r = evaluate(table, ctx(dir), { tool: 'Bash', input: { command: 'npx lint-staged' } });
  assert.equal(r.verdict, 'ASK');
  assert.match(JSON.stringify(r.hits), /bound/);
});

test('lint-staged: a repository whose index this resolver cannot read is an ask, and a fresh one is not', () => {
  // a fresh repository has no index file yet: nothing is tracked
  assert.equal(verdict('npx lint-staged', repo({ '.lintstagedrc.json': OK_RC })), 'ALLOW');
  // a file that is not an index is "I could not tell", which is not "no configuration"
  const broken = repo({ '.lintstagedrc.json': OK_RC });
  writeFileSync(join(broken, '.git', 'index'), 'not an index');
  assert.equal(verdict('npx lint-staged', broken), 'ASK');
  const truncated = repo({ '.lintstagedrc.json': OK_RC, a: '1' }, ['a']);
  const bytes = execFileSync('head', ['-c', '40', join(truncated, '.git', 'index')]);
  writeFileSync(join(truncated, '.git', 'index'), bytes);
  assert.equal(verdict('npx lint-staged', truncated), 'ASK');
});

test('lint-staged: a worktree whose .git is a file reads the index of its own git directory', () => {
  const main = repo({ '.lintstagedrc.json': OK_RC, a: '1' }, ['.lintstagedrc.json', 'a']);
  git(main, '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '-m', 'x');
  const wt = join(main, '..', `wt-${Date.now()}`);
  git(main, 'worktree', 'add', '-q', '-b', 'wt-branch', wt);
  mkdirSync(join(wt, 'vendor', 'x'), { recursive: true });
  writeFileSync(join(wt, '.gitignore'), 'vendor/\n');
  writeFileSync(join(wt, 'vendor', 'x', '.lintstagedrc.json'), BAD_RC);
  git(wt, 'add', '-f', '--', 'vendor/x/.lintstagedrc.json');
  assert.equal(evaluate(table, ctx(wt), { tool: 'Bash', input: { command: 'npx lint-staged' } }).verdict, 'DENY');
});

test('the index reader lists what git ls-files lists, in every layout', () => {
  const files: Record<string, string> = {
    'a.txt': '1',
    'dir/b.txt': '2',
    'dir/sub/c.txt': '3',
    'dir/sub/deeper/d.txt': '4',
    'dir/sub/deeper/evenmore/e.txt': '5',
    'dir/sub2/f.txt': '6',
    'unicodé/ñ/ü.txt': '7',
    'with space/g h.txt': '8',
    [`long/${'x'.repeat(120)}/${'y'.repeat(120)}.txt`]: '9',
    '.lintstagedrc.json': OK_RC,
  };
  for (const version of [2, 3, 4]) {
    const dir = repo(files, Object.keys(files), version === 3 ? 2 : version);
    if (version === 3) {
      // an intent-to-add entry carries the extended flags only layout 3 has room for
      writeFileSync(join(dir, 'intent.txt'), 'x');
      git(dir, 'add', '-N', '--', 'intent.txt');
    }
    const want = git(dir, 'ls-files', '-z').split('\0').filter(Boolean).sort();
    const got = listIndexedPaths(join(dir, '.git', 'index'));
    assert.ok('paths' in got, `layout ${version}: ${'problem' in got ? got.problem : ''}`);
    assert.deepEqual([...got.paths].sort(), want, `layout ${version}`);
    // the layout the file actually has is the one asked for
    const header = execFileSync('head', ['-c', '8', join(dir, '.git', 'index')]);
    assert.equal(header.readUInt32BE(4), version, `layout ${version} is the one under test`);
  }
  // a file that is not there is an empty index; one that is damaged is a problem
  const none = listIndexedPaths(join(workspace(), 'no-index'));
  assert.deepEqual(none, { paths: [] });
  const dir = workspace({ 'index': 'DIRC\0\0\0\u0002\0\0\0\u0009' });
  assert.ok('problem' in listIndexedPaths(join(dir, 'index')));
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 4. A STRICTER PROFILE IS NEVER LOOSER THAN A WEAKER ONE
 *
 * A profile's `narrow` list moves capabilities toward DENY and is NOT inherited: HIGH_ASSURANCE lists what it narrows
 * itself. STRICT had `git.local.merge` and `git.local.cherry-pick` added to its list in exit review 10; the
 * HIGH_ASSURANCE list was not touched, so `git merge --no-ff topic` was ASK under STRICT and ALLOW under
 * HIGH_ASSURANCE - the strongest profile permitting what the middle one asks about. Each list is written by hand, so
 * "the stricter one lists at least what the weaker one does" cannot be left to whoever edits the next page: the
 * compiler refuses a control plane in which STANDARD <= STRICT <= HIGH_ASSURANCE fails for any capability in any mode.
 * ------------------------------------------------------------------------------------------------------------- */

const CONTROL_PLANE = new URL('../../../control-plane/', import.meta.url).pathname;
const withProfile = (file: string, edit: (text: string) => string): ReturnType<typeof loadControlPlane> => {
  const dir = mkdtempSync(join(tmpdir(), 'ego-profile-order-'));
  cpSync(CONTROL_PLANE, dir, { recursive: true });
  const f = join(dir, 'profiles', file);
  writeFileSync(f, edit(readFileSync(f, 'utf8')));
  return loadControlPlane(dir);
};

test('the shipped table is ordered: for every capability in every mode, STANDARD <= STRICT <= HIGH_ASSURANCE', () => {
  assert.deepEqual([...PROFILE_ORDER], ['STANDARD', 'STRICT', 'HIGH_ASSURANCE']);
  const wrong: string[] = [];
  for (const mode of Object.keys(table.profiles['STANDARD']!.modes))
    for (const cap of Object.keys(table.capabilities))
      for (let i = 1; i < PROFILE_ORDER.length; i++) {
        const weaker = table.profiles[PROFILE_ORDER[i - 1]!]!.modes[mode]![cap]!;
        const stricter = table.profiles[PROFILE_ORDER[i]!]!.modes[mode]![cap]!;
        if (VERDICT_RANK[stricter] < VERDICT_RANK[weaker])
          wrong.push(`${cap} in ${mode}: ${PROFILE_ORDER[i]} is ${stricter}, ${PROFILE_ORDER[i - 1]} is ${weaker}`);
      }
  assert.deepEqual(wrong, []);
});

test('git merge and git cherry-pick ask under every profile that asks for a commit', () => {
  const dir = workspace();
  const at = (profile: string, command: string): string =>
    evaluate(table, { ...ctx(dir), profile }, { tool: 'Bash', input: { command } }).verdict;
  for (const command of ['git merge --no-ff topic', 'git merge topic', 'git cherry-pick abc1234', 'git commit -m x']) {
    assert.equal(at('STRICT', command), 'ASK', `${command} under STRICT`);
    assert.equal(at('HIGH_ASSURANCE', command), 'ASK', `${command} under HIGH_ASSURANCE`);
  }
  // and the verdict of a whole command never falls from a weaker profile to a stricter one, whatever it is
  const wrong: string[] = [];
  for (const command of [
    'git merge --no-ff topic', 'git cherry-pick abc1234', 'git commit -m x', 'git revert HEAD', 'git rebase main', 'git stash',
    'git tag v1', 'git branch feat', 'git pull', 'npm install', 'curl https://example.com', 'make build', 'rm -rf build',
    'sed -i s/a/b/ src/x.ts', 'touch x', 'docker run img',
  ]) {
    const got = PROFILE_ORDER.map((p) => RANK[at(p, command)]!);
    if (!(got[0]! <= got[1]! && got[1]! <= got[2]!)) wrong.push(`${command}: ${PROFILE_ORDER.map((p, i) => `${p}=${got[i]}`).join(' ')}`);
  }
  assert.deepEqual(wrong, []);
});

test('the compiler refuses a control plane in which a stricter profile is looser than a weaker one', () => {
  // HIGH_ASSURANCE forgets what STRICT narrows
  const forgetting = withProfile('high-assurance.md', (t) => t.replace(/  - capability: git\.local\.merge\n    verdict: ASK\n/, ''));
  assert.throws(
    () => compileAuthority(forgetting),
    (e: unknown) =>
      e instanceof ControlPlaneValidationError &&
      e.problems.some((p) => /git\.local\.merge/.test(p) && /HIGH_ASSURANCE/.test(p) && /STRICT/.test(p) && /looser/.test(p)),
  );
  // STANDARD narrows something further than STRICT does
  const inverted = withProfile('standard.md', (t) => t.replace('narrow: []', 'narrow:\n  - capability: git.local.commit\n    verdict: DENY'));
  assert.throws(
    () => compileAuthority(inverted),
    (e: unknown) => e instanceof ControlPlaneValidationError && e.problems.some((p) => /git\.local\.commit/.test(p) && /STRICT/.test(p) && /STANDARD/.test(p)),
  );
  // every violation is listed, not the first
  const both = withProfile('high-assurance.md', (t) =>
    t.replace(/  - capability: git\.local\.merge\n    verdict: ASK\n/, '').replace(/  - capability: git\.local\.cherry-pick\n    verdict: ASK\n/, ''),
  );
  assert.throws(
    () => compileAuthority(both),
    (e: unknown) =>
      e instanceof ControlPlaneValidationError &&
      e.problems.some((p) => /git\.local\.merge/.test(p)) &&
      e.problems.some((p) => /git\.local\.cherry-pick/.test(p)),
  );
  // a control plane that obeys the order still compiles
  assert.doesNotThrow(() => compileAuthority(withProfile('high-assurance.md', (t) => t)));
});

test('the profile documents say what the narrowing lists do', () => {
  const page = (f: string): string => readFileSync(join(CONTROL_PLANE, 'profiles', f), 'utf8');
  const high = page('high-assurance.md');
  assert.match(high, /merges?,? and cherry-picks?|merges?, cherry-picks?/i, 'the HIGH_ASSURANCE page names the merge and cherry-pick narrowing');
  assert.match(high, /looser\s+than\s+STRICT/i, 'the HIGH_ASSURANCE page says the profiles are ordered and the compiler checks it');
  assert.match(high, /`network\.external-write`/, 'the HIGH_ASSURANCE page lists what its narrow list denies');
  assert.match(page('strict.md'), /merges?, cherry-picks?/i);
  assert.match(page('standard.md'), /weaker|ordered|never looser/i, 'the STANDARD page says narrowing is ordered across profiles');
});
