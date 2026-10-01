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
import { workspace, verdict } from './support/corpus.ts';

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
