// CLOSURE OF THE DATABASE-CLIENT READERS, SECOND PASS (wave-5 review: RV-DB-1, RV-DB-2, RV-DB-3).
//
// Three findings, one lesson each. RV-DB-2 (a psql script whose `\o |program` line the scanner read as the inside of a
// string): the scanner and the client must agree where a token starts, and the client's rules are the ones to copy - so the
// lexical rules are written once (`sql-lex.ts`), checked against the REAL psql where there is one, and fuzzed against it.
// RV-DB-1 (`psql --ho=prod-db.acme.com` was the local socket while `--host=` was a production host) and RV-DB-3 (the user
// `john.doe` was read as a host): the target of a database command was found by a scan of its own that knew neither which
// words of the line are options and which are their values, nor which spellings of an option the client accepts. The grammar
// that already read the STATEMENTS of every client (`parseDbArgs`) now reads the TARGET too, and a test here is a property of
// the grammar (every unambiguous prefix of every host option, in every glued, spaced and clustered spelling), not a list of
// the spellings that were found.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  DB_GRAMMAR,
  REDIS_OPTIONS,
  SQLITE_OPTIONS,
  parseDbArgs,
  readDbTarget,
  type DbWord,
} from '../src/authority/db-options.ts';
import { sqlScan } from '../src/authority/sql-lex.ts';
import { verdict, workspace } from './support/corpus.ts';
import { PSQL_LEXICAL_CASES, runInLocalImage, startPsqlOracle } from './support/psql-oracle.ts';

const notAllowed = (cmds: readonly string[], dir: string): void => {
  for (const c of cmds) assert.notEqual(verdict(c, dir), 'ALLOW', c);
};
const allowed = (cmds: readonly string[], dir: string): void => {
  for (const c of cmds) assert.equal(verdict(c, dir), 'ALLOW', c);
};
/** a tool that is not bounded asks wherever it points; what it must never be is the refusal a (wrongly) read host would be */
const notRefused = (cmds: readonly string[], dir: string): void => {
  for (const c of cmds) assert.notEqual(verdict(c, dir), 'DENY', c);
};
/** the ways a script reaches the client's standard input from the command line: all of them are the script psql lexes */
const viaStdin = (script: string): string[] => [
  `cat <<'EOF' | psql\n${script}EOF`,
  `printf '%s' '${script.replace(/'/g, `'\\''`)}' | psql`,
  `echo '${script.replace(/'/g, `'\\''`)}' | psql`,
];

/* ------------------------------------------------------------------------------------------------------------- *
 * RV-DB-2. THE SCANNER READS A SCRIPT THE WAY THE CLIENT DOES.
 *
 * `select 1 as a$$$` followed by a `\o |touch` line: the scanner took the second `$` for the start of a dollar quote (a `$`
 * continues a NAME, and the test for "a name ends here" did not know it), swallowed the next line as a string, and the
 * program psql really runs was never seen. Ground truth is the lexer of the real client, so the rules are those of
 * `sql-lex.ts` and the table the cases come from (`support/psql-oracle.ts`) is itself checked against the real psql below.
 * ------------------------------------------------------------------------------------------------------------- */

test('RV-DB-2: a command psql runs is a command the scanner reports, and a line a string swallows is not invented', () => {
  for (const c of PSQL_LEXICAL_CASES) {
    const scan = sqlScan(c.script.replaceAll('@MARK@', '/tmp/x'), 'pg');
    assert.ok(
      !('refused' in scan),
      `${JSON.stringify(c.script)} (${c.why}) was refused: ${'refused' in scan ? scan.refused : ''}`,
    );
    const reported = scan.metas.some((m) => m.name === 'o' && m.args === '|touch /tmp/x');
    assert.equal(
      reported,
      c.runs,
      `${JSON.stringify(c.script)}: ${c.why} - psql ${c.runs ? 'runs' : 'does not run'} the \\o line`,
    );
  }
});

test('RV-DB-2: the cases above are what the real psql does (skipped without docker and a postgres image already on the machine)', (t) => {
  const oracle = startPsqlOracle();
  if (oracle === null) return t.skip('no docker, or no postgres image on this machine');
  try {
    const got = oracle.runs(PSQL_LEXICAL_CASES.map((c) => c.script));
    const wrong = PSQL_LEXICAL_CASES.filter((c, i) => got[i] !== c.runs).map(
      (c) => `${JSON.stringify(c.script)} (${c.why})`,
    );
    assert.deepEqual(wrong, [], `${oracle.version} disagrees with the table of what psql does`);
  } finally {
    oracle.stop();
  }
});

test('RV-DB-2: the script reaches the verdict - every spelling of stdin, every seam of the table', () => {
  const dir = workspace();
  // the finding itself, as the reviewer ran it
  notAllowed(
    [
      `printf 'select 1 as a$$$\\n\\\\o |touch /tmp/marker\\n$$\\n' | psql`,
      `cat <<'X' | psql\nselect 1 as a$$$\n\\o |touch /tmp/marker\n$$\nX`,
    ],
    dir,
  );
  for (const c of PSQL_LEXICAL_CASES.filter((x) => x.runs))
    notAllowed(viaStdin(c.script.replaceAll('@MARK@', '/tmp/x')), dir);
  // ...and a line the client never lexes as a command is not made one: a dollar-quoted body keeps its backslash as text
  assert.equal(verdict(`cat <<'EOF' | psql\nselect $$ \\o |touch /tmp/x $$\nEOF`, dir), 'ALLOW');
});

test('RV-DB-2: a form the older and the newer clients lex differently is refused, not guessed', () => {
  // psql 14 and earlier lex `1e5$$` as a number and a dollar quote, 15 and later as one token; `1e'x'` is an escape string to the
  // earlier and junk plus a plain string to the later. The scanner cannot know the version, so it asks
  for (const s of ['select 1e5$$ x\n', "select 1e'x'\n", 'select 12E34$a$ x\n'])
    assert.ok('refused' in sqlScan(s, 'pg'), s);
  // the ordinary neighbours are not refused
  for (const s of ['select 1e5, 2.5e-3\n', "select 15 || 'e'\n", 'select 1 as e5\n', 'select a1e5$ from t\n'])
    assert.ok(!('refused' in sqlScan(s, 'pg')), s);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * The siblings: the same invariant (every command psql runs is reported) from other places the scanner was blind.
 * ------------------------------------------------------------------------------------------------------------- */

test('RV-DB-2 siblings: a psql variable is lexed as part of the script, so what it holds is read', () => {
  const dir = workspace();
  // psql replaces `:x` with the variable's text and lexes THAT: a value that is a command is a command (verified against the real psql)
  notAllowed(
    [
      `echo ':x' | psql -v 'x=\\o |touch /tmp/q'`,
      `psql -v 'x=\\o |touch /tmp/q' -c ':x'`,
      `psql --set='x=\\o |touch /tmp/q' -c ':x'`,
      `psql --variable 'x=\\o |touch /tmp/q' -c ':x'`,
      `cat <<'EOF' | psql\n\\set x '\\\\o |touch /tmp/q'\n:x\nEOF`,
      // a value a query result, the environment or the user sets is not on the line at all
      `cat <<'EOF' | psql\nselect '\\o |touch /tmp/q' as x \\gset\n:x\nEOF`,
      `cat <<'EOF' | psql\n\\getenv x HOME\n:x\nEOF`,
      // an unquoted reference to a variable nothing on the line sets is the same question
      `psql -c 'select :x'`,
      // a value that completes a statement the reader would have judged: the call it names is the call
      `psql -v f=pg_read_file -c "select :f('/etc/hostname')"`,
      `psql -v 'q=copy t to program' -c ":q 'cmd'"`,
      // a variable built at run time
      `psql -v "x=$VALUE" -c ':x'`,
    ],
    dir,
  );
  allowed(
    [
      // the value is on the line and is a word: it is substituted and read like the rest
      `psql -v tbl=users -c 'select count(*) from :tbl'`,
      `psql -v ON_ERROR_STOP=1 -v schema=public -c 'set search_path to :schema'`,
      `cat <<'EOF' | psql\n\\set n 5\nselect * from t limit :n;\nEOF`,
      // a QUOTED reference is a literal (psql escapes the value), a cast and a slice are no references
      `psql -v 'pat=^a\\d+$' -c "select * from t where a ~ :'pat'"`,
      `psql -v name=x -c 'select :"name"'`,
      `psql -c "select 1::int, a[1:2] from t"`,
      `psql -c "select ':x'"`,
    ],
    dir,
  );
});

test('RV-DB-2 siblings: what the real psql does with a variable, and what the scanner says of it (skipped without docker)', (t) => {
  const oracle = startPsqlOracle();
  if (oracle === null) return t.skip('no docker, or no postgres image on this machine');
  try {
    // [script, the variables the command line sets, whether psql runs the \o line]
    const cases: Array<[string, Record<string, string>, boolean]> = [
      [':x\n', { x: '\\o |touch @MARK@' }, true],
      ['select 1 :x\n', { x: '\\o |touch @MARK@' }, true],
      ["select :'x'\n", { x: '\\o |touch @MARK@' }, false],
      ['select :"x"\n', { x: '\\o |touch @MARK@' }, false],
      ['select :x\n\\o |touch @MARK@\n', { x: '1' }, true],
      ["\\set x '\\\\o |touch @MARK@'\n:x\n", {}, true],
      ["select '\\o |touch @MARK@' as x \\gset\n:x\n", {}, true],
      ["select '\\o |touch @MARK@' as x \\gset\nselect :'x'\n", {}, false],
      // the arguments of a command are interpolated as well: `\o :x` is the program the variable holds, `\o :'x'` and `\o ':x'` are not
      ['\\o :x\n', { x: '|touch @MARK@' }, true],
      ['\\set y :x\n\\o :y\n', { x: '|touch @MARK@' }, true],
      ["\\o :'x'\n", { x: '|touch @MARK@' }, false],
      ["\\o ':x'\n", { x: '|touch @MARK@' }, false],
    ];
    const got = oracle.runs(
      cases.map(([script, vars]) => ({
        script,
        args: Object.entries(vars).flatMap(([k, v]) => ['-v', `${k}=${v}`]),
      })),
    );
    cases.forEach(([script, vars, runs], i) => {
      assert.equal(got[i], runs, `${oracle.version}: ${JSON.stringify(script)} with ${JSON.stringify(vars)}`);
      const scan = sqlScan(
        script.replaceAll('@MARK@', '/tmp/x'),
        'pg',
        new Map(Object.entries(vars).map(([k, v]) => [k, v.replaceAll('@MARK@', '/tmp/x')])),
      );
      if ('refused' in scan) return;
      // a program psql runs is reported (a `\o` whose target is a pipe), or the script asks about a variable whose text it cannot see
      const program = scan.metas.some((m) => m.name === 'o' && m.args.startsWith('|'));
      const seen =
        program || scan.metas.some((m) => m.name === 'o' && m.args === '') || scan.variables.length > 0;
      if (runs) assert.ok(seen, `${JSON.stringify(script)} runs a command the scanner did not see`);
      else assert.ok(!program, `${JSON.stringify(script)} runs nothing, yet the scanner reports a program`);
    });
  } finally {
    oracle.stop();
  }
});

test('RV-DB-2 siblings: a backslash-semicolon is a semicolon, and a backquote is no quote', () => {
  const dir = workspace();
  notAllowed(
    [
      ...viaStdin('select 1 \\; \\o |touch /tmp/q\n'),
      ...viaStdin('select 1\\;\\o |touch /tmp/q\n'),
      ...viaStdin('select `\n\\o |touch /tmp/q\n`\n'),
      // `\;` does not end the line: SQL goes on behind it, and it is read as SQL
      ...viaStdin("select 1 \\; select lo_import('x')\n"),
      ...viaStdin("select 1 \\; select pg_ls_dir('.')\n"),
    ],
    dir,
  );
  allowed(viaStdin('select 1 \\; select 2\n'), dir);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * THE FUZZ. Seeded, bounded, and checked two ways: against the real client where there is one, and against the scanner's own
 * invariants everywhere.
 * ------------------------------------------------------------------------------------------------------------- */

/** the fragments the scripts are built from: every seam between two lexers that was found, and the characters around it */
const POOL = [
  'select 1',
  ' as ',
  'a',
  'x',
  'e',
  'E',
  'a$',
  'a$$',
  'a$$$',
  'x$y',
  '$$',
  '$a$',
  '$a$ q $a$',
  '$$ q $$',
  '$$ ',
  "'",
  "''",
  "'x'",
  "'\\'",
  "'a\\'b'",
  "e'x'",
  "E'\\''",
  "e'\\\\'",
  "a$e'x'",
  "a$E'\\'",
  "_e'\\''",
  '"',
  '"x"',
  '"\'"',
  '"\\"',
  '"a""b"',
  "U&'x'",
  'U&"x"',
  '1$$',
  '1',
  '1.',
  '.5',
  '1.5',
  'é',
  'é$$',
  'é$a$',
  ';',
  '\n',
  ' ',
  '\t',
  '\\\\',
  ':',
  ':x',
  ":'x'",
  ':"x"',
  '::',
  '::int',
  '`',
  "b'1'",
  "x'1'",
  "n'x'",
  "1e'x'",
  "1e'\\'",
  '1e5',
  '1e5$$',
  '1e+5',
  '0x1F',
  '0x1F$$',
  '1_0',
  '1_0$$',
  '(',
  ')',
  ',',
  '.',
  '\\g',
  '$1',
  '$1$$',
  '$1a',
  '$1a$',
  '@',
  '#',
  '%',
  '[',
  ']',
  '{',
  '}',
  '[1:2]',
  '\r',
  '\f',
  '\v',
  '\\q',
  'x$$',
  'U&',
  "$q$'$q$",
  '$$\\$$',
  '1.5$$',
  '.$$',
  ')$$',
  ']$$',
  "'x'$$",
  '"x"$$',
  ':$$',
  '+$$',
  '1$a$',
  'e1$$',
  '_$$',
  'a1$$',
  'a_$$',
  'é1$$',
  '$_$',
  '$é$',
  '$é$ q $é$',
  "E'a'$$",
  '\\\\$$',
  ' $x$ ',
  '$X$',
  '$x$ $X$',
  'x$x$',
  ',$$',
  '=$$',
  '*$$',
  '~$$',
  '<$$',
  '>$$',
  '-$$',
  '/$$',
  '|$$',
  '&$$',
  '^$$',
  '!$$',
  '?$$',
  '@$$',
  '#$$',
  '%$$',
  '`$$',
  '\\;',
  '\\: ',
  ' \\; ',
  '\\;\\;',
  "\\; '",
  '\\:x',
  "x'",
  "'\n",
  '$$\n',
  "\n'",
  'e ',
  ' e',
  '1a',
  '1a$$',
  '15$$',
  '15 $$',
  '2e',
  '3e$$',
  'éé',
  '😀$$',
  '😀',
  'z$',
];
const CLOSERS = [
  '',
  '',
  '$$',
  "'",
  '"',
  '$a$',
  "$$ '",
  "$$'",
  "'$$",
  '"$$',
  "e'",
  'x$$',
  "$$\n'",
  "'\\'",
  '\n',
  ' \\; ',
  '`',
];

/** a deterministic generator: the same seed is the same scripts on every machine */
function generator(seed: number): () => number {
  let s = seed >>> 0;
  return () => (s = (Math.imul(s, 1664525) + 1013904223) >>> 0) / 4294967296;
}
function scripts(seed: number, count: number, tail: (i: number) => string): string[] {
  const rnd = generator(seed);
  const pick = <T>(a: readonly T[]): T => a[Math.floor(rnd() * a.length)]!;
  const out: string[] = [];
  for (let i = 0; i < count; i++) {
    let p = '';
    for (let k = 1 + Math.floor(rnd() * 6); k > 0; k--) p += pick(POOL) + (rnd() < 0.3 ? ' ' : '');
    // (a comment is refused whole, and refused text proves nothing about the lexer)
    out.push(p.replaceAll('--', '- -') + tail(i) + pick(CLOSERS));
  }
  return out;
}

test('RV-DB-2 fuzz: 600 seeded scripts, run by the real psql: every program it runs is a command the scanner reports', (t) => {
  const oracle = startPsqlOracle();
  if (oracle === null) return t.skip('no docker, or no postgres image on this machine');
  try {
    const all = scripts(20261002, 600, () => '\n\\o |touch @MARK@\n');
    const ran = oracle.runs(all);
    const unsound: string[] = [];
    all.forEach((s, i) => {
      if (!ran[i]) return;
      const scan = sqlScan(s.replaceAll('@MARK@', '/tmp/x'), 'pg');
      if ('refused' in scan) return; // asking is an answer
      if (!scan.metas.some((m) => m.name === 'o')) unsound.push(JSON.stringify(s));
    });
    assert.deepEqual(unsound, [], `${oracle.version} ran a program the scanner did not report`);
    assert.ok(ran.filter(Boolean).length > 100, 'the fuzz reached too few scripts that run');
  } finally {
    oracle.stop();
  }
});

test('RV-DB-2 fuzz: 2,000 seeded statements: every backslash command on a line of its own is reported, wherever the statement before it ends', () => {
  const MARK = '\\o |touch /tmp/x';
  const all = scripts(7, 2000, () => `\n${MARK}\n`);
  let closed = 0;
  for (const s of all) {
    const cut = s.indexOf(`\n${MARK}\n`);
    // the lines in front of the command read alone: when they are a closed statement, nothing they hold can reach into the next
    // line, so a command that begins it is outside every string - and the scanner has to say so, whatever the fragments were
    const before = sqlScan(s.slice(0, cut), 'pg');
    if ('refused' in before) continue;
    closed++;
    const whole = sqlScan(s, 'pg');
    if ('refused' in whole) continue; // only text AFTER the command can make it ask
    const reported = whole.metas.filter((m) => m.name === 'o' && m.args === '|touch /tmp/x');
    assert.equal(reported.length, 1, `a command on a line of its own is not reported: ${JSON.stringify(s)}`);
    // the commands in front of it are the same ones the statement alone has (a later line changes nothing before it)
    assert.deepEqual(whole.metas.slice(0, before.metas.length), before.metas, JSON.stringify(s));
  }
  assert.ok(closed > 300, `the fuzz reached too few closed statements (${closed})`);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * RV-DB-1. THE TARGET IS READ BY THE CLIENT'S OWN GRAMMAR.
 *
 * `psql --ho=prod-db.acme.com -c 'update users set active=false'` was ALLOW and `--host=` was an absolute deny: the host was
 * found by a scan that matched the exact word `--host` and knew nothing of getopt's prefixes, which psql, mysql and
 * clickhouse-client all accept. The statements of the same line had been read by the client's table for two waves. Every
 * property below is stated over the TABLES (`DB_GRAMMAR`), not over the spellings the reviewer tried: a client added to the
 * table without a case here fails the test that counts them.
 * ------------------------------------------------------------------------------------------------------------- */

/** a statement that acts, spelled for each client: it is what makes the host the whole question */
const ACTS: Record<string, string> = {
  psql: "-c 'update users set active=false'",
  mysql: "-e 'update users set active=0'",
  mariadb: "-e 'update users set active=0'",
  mysqlsh: "-e 'update users set active=0'",
  mysqladmin: 'drop appdb',
  mysqldump: 'app',
  mysqlpump: 'app',
  mongosh: "--eval 'db.users.deleteMany({})'",
  mongo: "--eval 'db.users.deleteMany({})'",
  mongodump: '--db app --out dump',
  mongorestore: '--db app dump/app',
  mongoexport: '--db app --collection users',
  mongoimport: '--db app --collection users --file users.json',
  'redis-cli': 'FLUSHALL',
  'valkey-cli': 'FLUSHALL',
  'clickhouse-client': "-q 'alter table t delete where 1'",
  cqlsh: "-e 'drop table t'",
  influx: "-execute 'drop database x'",
  pg_dump: 'app',
  pg_restore: '-d app dump.sql',
  pg_dumpall: '',
  pgbench: 'app',
  createdb: 'app',
  dropdb: 'app',
  createuser: 'bob',
  dropuser: 'bob',
};
const PROD = 'prod-db.acme.com';
/** every prefix of a long option name, the name itself last */
const prefixes = (name: string): string[] =>
  Array.from({ length: name.length }, (_, i) => name.slice(0, i + 1));

test('RV-DB-1: every client has a case, and every host option of every table is a production host in every spelling the client accepts', () => {
  const dir = workspace();
  const heads = Object.keys(DB_GRAMMAR);
  assert.deepEqual(
    heads.filter((h) => ACTS[h] === undefined),
    [],
    'a client in DB_GRAMMAR needs a statement that acts here',
  );
  const failures: string[] = [];
  let checked = 0;
  for (const head of heads) {
    const spec = DB_GRAMMAR[head]!;
    for (const name of spec.host ?? []) {
      // a short letter that is its own name (redis-cli `-h`), or a long option: its unambiguous prefixes where the client takes them
      const spellings =
        name.length === 1 ? [`-${name}`] : (spec.abbreviate ? prefixes(name) : [name]).map((p) => `--${p}`);
      // ...and the short letter the table gives it, glued and spaced
      const letter = Object.entries(spec.alias ?? {}).find(([, long]) => long === name)?.[0];
      const forms: string[] = [];
      for (const sp of spellings)
        forms.push(sp.startsWith('--') ? `${sp}=${PROD}` : `${sp}${PROD}`, `${sp} ${PROD}`);
      if (letter !== undefined) forms.push(`-${letter}${PROD}`, `-${letter} ${PROD}`, `-${letter}=${PROD}`);
      for (const f of forms) {
        checked++;
        // (the host is the whole question, so it goes in front of the statement and behind it - except for a client whose first bare word
        // ends its options: redis-cli's `FLUSHALL -h x` hands `-h x` to the command)
        for (const cmd of [
          `${head} ${f} ${ACTS[head]}`,
          ...(spec.stopAtPositional ? [] : [`${head} ${ACTS[head]} ${f}`]),
        ]) {
          const got = verdict(cmd, dir);
          if (got !== 'DENY') failures.push(`${got}: ${cmd}`);
        }
      }
    }
  }
  assert.ok(checked > 150, `the matrix collapsed: only ${checked} spellings`);
  assert.deepEqual(
    failures,
    [],
    `a spelling of a host option the client accepts was not read as the host:\n  ${failures.join('\n  ')}`,
  );
});

test("RV-DB-1: the reviewer's three commands, and the same host spelled the way every other tool would", () => {
  const dir = workspace();
  const deny = [
    `psql --ho=prod-db.acme.com -c "update users set active=false"`,
    `mysql --hos=prod-db.acme.com -e 'update users set active=0'`,
    `clickhouse-client --ho=prod-ch.acme.com -q 'alter table t delete where 1'`,
    `clickhouse client --ho=prod-ch.acme.com -q 'alter table t delete where 1'`,
    // a short letter beside other letters, a host list, a second host option, a value after a space
    `psql -qAt -hprod-db.acme.com -c 'update t set a=1'`,
    `psql -h localhost -h ${PROD} -c 'update t set a=1'`,
    `psql --host localhost --hos ${PROD} -c 'update t set a=1'`,
    `psql -h localhost,${PROD} -c 'update t set a=1'`,
    `mongosh --host=prod-mongo.acme.com:27017 --eval 'db.users.deleteMany({})'`,
    `mongosh --host localhost:27017,prod-mongo.acme.com:27017 --eval 'db.users.deleteMany({})'`,
    // an ambiguous prefix is refused by the real client, and read as every candidate here: the host is one
    `psql --h=${PROD} -c 'update t set a=1'`,
  ];
  for (const c of deny) assert.equal(verdict(c, dir), 'DENY', c);
  // a local host in any of the same spellings stays the local work it is
  allowed(
    [
      `psql --ho=localhost -c 'update t set a=1'`,
      `psql --host=127.0.0.1 -c 'update t set a=1'`,
      `psql -h ::1 -c 'update t set a=1'`,
      `psql -h /tmp -c 'update t set a=1'`,
      `psql --hos /tmp -c 'update t set a=1'`,
      `mysql --hos=localhost -e 'update t set a=0'`,
      `mongosh --host=localhost:27017 --eval 'db.users.deleteMany({})'`,
      `mongosh --host localhost --port 27017 --eval 'db.users.deleteMany({})'`,
      `redis-cli -h localhost -p 6379 FLUSHALL`,
    ],
    dir,
  );
  // the exception for a plain SELECT is the same exception whatever the host spelling is, and a second statement still ends it
  assert.equal(verdict(`psql --ho=${PROD} -U ro -c 'select 1'`, dir), 'ALLOW');
  assert.equal(verdict(`psql --ho=${PROD} -c 'select 1' -c 'drop table t'`, dir), 'DENY');
  assert.equal(verdict(`psql --ho=${PROD} -Atl`, dir), 'ALLOW');
  assert.equal(verdict(`psql --ho=${PROD} --li`, dir), 'ALLOW');
});

test('RV-DB-1: a connection string in the place of a database name is a target, and one the shell fills in is a target nobody read', () => {
  const dir = workspace();
  // every option a table says may hold a whole connection string, every prefix of it, glued and spaced
  const cases: string[] = [];
  for (const head of Object.keys(DB_GRAMMAR)) {
    const spec = DB_GRAMMAR[head]!;
    for (const name of spec.connection ?? []) {
      const spellings =
        name.length === 1
          ? [`-${name}`]
          : (spec.abbreviate ? prefixes(name).filter((p) => p.length >= 3) : [name]).map((p) => `--${p}`);
      for (const sp of spellings) {
        const glue = sp.startsWith('--') ? '=' : ' ';
        cases.push(`${head} ${sp}${glue}"$DATABASE_URL" ${ACTS[head]}`);
        cases.push(`${head} ${sp} "$DATABASE_URL" ${ACTS[head]}`);
        // ...and the production host in it is read, whatever the option was written
        cases.push(`${head} ${sp}${glue}'postgres://u@${PROD}/app' ${ACTS[head]}`);
      }
    }
  }
  assert.ok(cases.length > 30, 'the matrix collapsed');
  notAllowed(cases, dir);
  for (const c of cases.filter((x) => x.includes(PROD))) assert.equal(verdict(c, dir), 'DENY', c);
  // the first operand of psql is a database or a connection string, and libpq lets it override -h
  notAllowed(
    [
      `psql "$DB" -c 'drop table t'`,
      `psql -h localhost "$DATABASE_URL" -c 'drop table t'`,
      `pg_dump "$DATABASE_URL"`,
    ],
    dir,
  );
  allowed(
    [`psql -d app -c 'drop table t'`, `psql --dbname=app_test -c 'drop table t'`, `pg_dump -d app`],
    dir,
  );
});

test('RV-DB-1: a connection profile is a target nobody read, in every abbreviation the client takes', () => {
  const dir = workspace();
  const cases: string[] = [];
  for (const head of Object.keys(DB_GRAMMAR)) {
    const spec = DB_GRAMMAR[head]!;
    for (const name of (spec.profile ?? []).filter((n) => (spec.value as readonly string[]).includes(n))) {
      // the prefixes that mean this option and no other
      const longs = [...spec.value, ...spec.flag, ...(spec.escaping ?? [])];
      for (const p of prefixes(name).filter(
        (p) => spec.abbreviate && longs.filter((l) => l.startsWith(p)).every((l) => l === name),
      ))
        cases.push(`${head} --${p}=prod ${ACTS[head]}`);
      cases.push(`${head} --${name}=prod ${ACTS[head]}`);
    }
  }
  assert.ok(cases.length > 8, 'the matrix collapsed');
  notAllowed(cases, dir);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * RV-DB-3. A WORD THAT IS AN OPTION'S VALUE, OR A DATABASE NAME, IS NOT A HOST.
 *
 * `mongosh -u john.doe`, `mysql -u app.user -e 'drop table x'` and `psql -U app my.app` were absolute denials of ordinary local
 * work: the bare-operand scan skipped the values of the options it had a list of, and read every other dotted word as a server.
 * Now the parser says which words are values (for every option of every table), and the table says what an operand is.
 * ------------------------------------------------------------------------------------------------------------- */

test("RV-DB-3: the reviewer's commands, and the same dotted name wherever a name goes", () => {
  const dir = workspace();
  allowed(
    [
      `mongosh -u john.doe --eval 'db.stats()'`,
      `mongosh --username john.doe -p x --eval 'db.stats()'`,
      `mongosh --username=john.doe --eval 'db.users.deleteMany({})'`,
      `mysql -u app.user -e 'drop table x'`,
      `mysql --user app.user -e 'drop table x'`,
      `mysql -uapp.user -p -e 'drop table x'`,
      `psql -U app my.app`,
      `psql -U app my.app -c 'drop table x'`,
      `psql -Uapp.user my.app -c 'drop table x'`,
      `psql --username app.user -d my.app -c 'drop table x'`,
      `psql my.app -c 'select 1'`,
      // the glued letter after an option letter is the option's value, not a second option (`-Uhenry` is not `-U` and `-h enry`)
      `psql -Uhenry -c 'update t set a=1'`,
      `mysql -uhenry -e 'update t set a=0'`,
      `pg_dump -Uhenry app`,
      // a password, a key pattern, a table, a role, a tablespace, a locale: values whatever they look like
      `redis-cli -a pass.word FLUSHALL`,
      `redis-cli --pass pass.word FLUSHALL`,
      `redis-cli --scan --pattern session.2024.x`,
      `pg_dump -t public.users app`,
      `pg_dump --table=public.users --schema=my.schema app`,
      `pg_dump --role=app.owner app`,
      `mysqldump -u app.user --ignore-table=db.logs app`,
      `mysqldump -u root --result-file=dump.sql app.v2`,
      `clickhouse-client --user app.user -q 'alter table t delete where 1'`,
      `clickhouse-client --max_threads 4 --log_comment my.app -q 'alter table t delete where 1'`,
      // a database NAME is a name in mysql, psql, the dump tools: `prod-db.acme.com` there is a database on the local socket
      `mysql prod-db.acme.com -e 'drop table x'`,
      `psql prod-db.acme.com -c 'drop table x'`,
      `pg_dump prod-db.acme.com`,
    ],
    dir,
  );
  notRefused(
    [
      `pg_restore -t public.users -d app app.dump`,
      `pg_restore db.backup -d app`,
      `createdb -T template.dev -O app.owner newdb`,
      `mysqladmin -u app.user status`,
      `influx -username app.user -execute 'drop database x'`,
      `cqlsh -u app.user -e 'drop table t'`,
    ],
    dir,
  );
});

test("RV-DB-3: an option's value is never a host - for every value option of every table, in every spelling", () => {
  const dir = workspace();
  const skip = (head: string, name: string): boolean => {
    const spec = DB_GRAMMAR[head]!;
    // the values that ARE judged: a host, a connection string, a profile, a statement, a file the client reads or writes, something it runs
    const judged = [
      ...(spec.host ?? []),
      ...(spec.connection ?? []),
      ...(spec.address ?? []),
      ...(spec.profile ?? []),
      ...(spec.escaping ?? []),
      spec.output ?? '',
    ];
    return (
      judged.includes(name) ||
      /^(command|execute|eval|query|file|output|log-file|tee|init-command|rdb|functions-rdb|import|cmd|set|variable|pset|config-file|queries-file)$/.test(
        name,
      )
    );
  };
  const failures: string[] = [];
  let checked = 0;
  for (const head of Object.keys(DB_GRAMMAR)) {
    const spec = DB_GRAMMAR[head]!;
    for (const name of spec.value) {
      if (skip(head, name)) continue;
      const letter = Object.entries(spec.alias ?? {}).find(([, long]) => long === name)?.[0];
      const spell = (v: string): string[] => [
        `${head} --${name}=${v} ${ACTS[head]}`,
        `${head} --${name} ${v} ${ACTS[head]}`,
        ...(letter !== undefined && (spec.shortValue.includes(letter) || spec.shortGlued?.includes(letter))
          ? [`${head} -${letter}${v} ${ACTS[head]}`]
          : []),
      ];
      const dotted = spell('app.user');
      const plain = spell('appuser');
      dotted.forEach((c, i) => {
        checked++;
        const a = verdict(c, dir);
        const b = verdict(plain[i]!, dir);
        if (a !== b) failures.push(`${a} (not ${b}): ${c}`);
      });
    }
  }
  assert.ok(checked > 150, `the matrix collapsed: only ${checked} spellings`);
  assert.deepEqual(
    failures,
    [],
    `a dotted value changed the verdict, so it was read as something other than a value:\n  ${failures.join('\n  ')}`,
  );
});

test("RV-DB-3: what a client's operand IS decides whether it can be a server", () => {
  const dir = workspace();
  // mongosh's first operand is an ADDRESS (`host/db`, `host:port`, a dotted host) and the rest are scripts; cqlsh's is a HOST
  for (const c of [
    `mongosh prod.example.com/app --eval 'db.users.deleteMany({})'`,
    `mongosh prod-mongo.acme.com --eval 'db.users.deleteMany({})'`,
    `mongosh --eval 'db.users.deleteMany({})' prod-mongo:27017`,
    `cqlsh prod-cass.acme.com -e 'drop table t'`,
    `cqlsh prod-cass -e 'drop table t'`,
    `cqlsh prod-cass 9042 -e 'drop table t'`,
    `clickhouse-client prod-ch.acme.com -q 'alter table t delete where 1'`,
    // MySQL Shell's operand and `--uri` are an address with a user in front of the host: what follows the `@` is the server
    `mysqlsh root@prod-db.acme.com`,
    `mysqlsh root@prod-db`,
    `mysqlsh --uri=root@prod-db.acme.com -e 'select 1'`,
    `mysqlsh --uri root@prod-db -e 'select 1'`,
    `mysqlsh mysqlx://root@prod-db.acme.com/app`,
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
  allowed(
    [
      `mongosh app --eval 'db.users.deleteMany({})'`,
      `mongosh localhost/app --eval 'db.users.deleteMany({})'`,
    ],
    dir,
  );
  // (cqlsh is not a bounded tool, so it asks wherever it points - but a local host is not a refusal)
  for (const c of [
    `cqlsh localhost -e 'drop table t'`,
    `cqlsh 127.0.0.1 9042 -e 'drop table t'`,
    `cqlsh -e 'drop table t'`,
  ])
    assert.equal(verdict(c, dir), 'ASK', c);
  // a script handed over as an operand (standard input carried onto the command line) is never taken for the operand it sits in
  assert.equal(verdict(`echo 'select * from t' | psql`, dir), 'ALLOW');
  assert.equal(verdict(`echo 'select * from t where a = :x' | psql -v x=1`, dir), 'ALLOW');
  assert.equal(verdict(`echo 'delete from t where a ~ 1' | psql -h ${PROD}`, dir), 'DENY');
});

/* ------------------------------------------------------------------------------------------------------------- *
 * The other questions the same table answers: which file a dump tool writes, whether `-l` lists, whether redis-cli only looks.
 * ------------------------------------------------------------------------------------------------------------- */

test("the table answers the file question too: a dump tool's output option, in every spelling it accepts", () => {
  const dir = workspace();
  notAllowed(
    [
      `pg_dump -f .git/hooks/pre-commit app`,
      `pg_dump --file=.git/hooks/pre-commit app`,
      `pg_dump --fil=.git/hooks/pre-commit app`,
      `pg_dump --fi .git/hooks/pre-commit app`,
      `pg_dump -f.git/hooks/pre-commit app`,
      `pg_dump -vf .git/hooks/pre-commit app`,
      `pg_dump -Cf.git/hooks/pre-commit app`,
      `pg_dump -Fc -f.git/hooks/pre-commit app`,
      `mysqldump -r .git/hooks/pre-commit app`,
      `mysqldump --result-f=.git/hooks/pre-commit app`,
      `mysqldump --res .git/hooks/pre-commit app`,
    ],
    dir,
  );
  allowed(
    [
      `pg_dump -f dump.sql app`,
      `pg_dump --fil=dump.sql app`,
      `pg_dump -Fc -f dump.dump app`,
      `mysqldump --result-file=dump.sql app`,
      `mysqldump -r dump.sql app`,
    ],
    dir,
  );
});

test('the table answers the exception questions too: psql -l lists, redis-cli INFO looks - and a value is not a flag', () => {
  const dir = workspace();
  // `-l` is a flag in a cluster, abbreviated, behind another flag; in `-U -l` it is the user's NAME and there is a statement after it
  allowed(
    [
      `psql -h ${PROD} -l`,
      `psql -h ${PROD} -Atl`,
      `psql -h ${PROD} --list`,
      `psql -h ${PROD} --lis`,
      `psql -h ${PROD} -qlX`,
    ],
    dir,
  );
  assert.equal(verdict(`psql -h ${PROD} -U -l -c 'drop table t'`, dir), 'DENY');
  assert.equal(verdict(`psql -h ${PROD} -l -c 'drop table t'`, dir), 'DENY');
  // redis-cli: the first bare word after the options is the command
  allowed(
    [
      `redis-cli -h ${PROD} INFO`,
      `redis-cli -h ${PROD} -p 6380 -a x --raw ping`,
      `redis-cli -u redis://${PROD}:6379 dbsize`,
      `redis-cli -h ${PROD} --no-auth-warning ttl k`,
    ],
    dir,
  );
  for (const c of [
    `redis-cli -h ${PROD} -c DEL k`,
    `redis-cli -h ${PROD} --scan`,
    `redis-cli -h ${PROD} -x set k`,
    `redis-cli -h ${PROD} --some-new-option info`,
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * The pipe edge: standard input is a script only where the client was given no statement of its own.
 *
 * The condition was a PREFIX TEST of the words (`-c`, `-e`, `-f`, `--query`...), a third scan of the line with a third idea of
 * which words are options: `mysql -c` (comments) and `mysql -f` (force) are flags and leave standard input the script it was,
 * `sqlite3 -cmd '.tables'` is not a statement and sqlite3 goes on to read standard input - `echo '.shell id' | sqlite3 -cmd .tables`
 * ran the program at ALLOW (checked against the real sqlite3) - and `psql -qc 'x'` is the statement option in a cluster.
 * ------------------------------------------------------------------------------------------------------------- */

test('the pipe edge: a flag is not a statement, a statement in a cluster or an abbreviation is one', () => {
  const dir = workspace();
  notAllowed(
    [
      `echo 'system id' | mysql -c`,
      `echo 'system id' | mysql -f`,
      `echo 'system id' | mysql --force`,
      `echo 'system id' | mysql --comments`,
      `echo 'system id' | mysql -D app`,
      `printf '\\\\! id\\n' | psql -F x`,
      `printf '\\\\! id\\n' | psql -X`,
      `printf '\\\\! id\\n' | psql -At`,
      `printf '\\\\! id\\n' | psql --field-separator=x`,
      `echo '.shell id' | sqlite3 -cmd '.tables' app.db`,
      `echo '.shell id' | sqlite3 -init /dev/null app.db`,
      `echo '.shell id' | sqlite3 -header -column app.db`,
      `echo 'load("x")' | mongosh --quiet`,
      `echo 'load("x")' | mongosh --norc`,
      `echo 'config set dir /tmp' | redis-cli --raw`,
    ],
    dir,
  );
  // a statement of the client's own replaces what is piped to it - in whatever spelling the table accepts
  allowed(
    [
      `echo 'system id' | mysql -e'select 1'`,
      `echo 'system id' | mysql --exe='select 1'`,
      `printf '\\\\! id\\n' | psql -qc 'select 1'`,
      `printf '\\\\! id\\n' | psql --comm 'select 1'`,
      `printf '\\\\! id\\n' | psql -Atc 'select 1'`,
      `echo '.shell id' | sqlite3 app.db 'select 1'`,
      `echo 'load("x")' | mongosh --eval 'db.stats()'`,
    ],
    dir,
  );
});

test('the pipe edge: a flag of any modelled client leaves standard input a script', () => {
  const dir = workspace();
  // the script that is not ordinary, spelled for each client whose escape reader reads a piped script
  const SCRIPT: Record<string, string> = {
    psql: '\\! id',
    mysql: 'system id',
    mariadb: 'system id',
    mongosh: 'load("x")',
    mongo: 'load("x")',
    'redis-cli': 'config set dir /tmp',
  };
  const failures: string[] = [];
  let checked = 0;
  for (const [head, script] of Object.entries(SCRIPT)) {
    const spec = DB_GRAMMAR[head]!;
    // the flags that take no value and so cannot be the statement; the probes (`--help`, `--version`) are judged apart
    const flags = [
      ...spec.flag.filter((f) => !/^(help|version)$/.test(f)).map((f) => `--${f}`),
      ...spec.shortFlag
        .split('')
        .filter((c) => !'?VvhH'.includes(c))
        .map((c) => `-${c}`),
    ];
    for (const f of flags) {
      checked++;
      const cmd = `printf '${script.replace(/\\/g, '\\\\')}\\n' | ${head} ${f}`;
      if (verdict(cmd, dir) === 'ALLOW') failures.push(cmd);
    }
  }
  assert.ok(checked > 100, `the matrix collapsed: only ${checked} flags`);
  assert.deepEqual(
    failures,
    [],
    'a flag was read as the statement that replaces standard input:\n  ' + failures.join('\n  '),
  );
});

test('the pipe edge, against the real sqlite3: every random spelling in which sqlite3 runs a piped dot-command is one the evaluator does not allow (skipped without sqlite3)', (t) => {
  const probe = spawnSync('sqlite3', ['-version'], { encoding: 'utf8' });
  if (probe.status !== 0) return t.skip('no sqlite3 on this machine');
  const dir = workspace();
  const work = mkdtempSync(join(tmpdir(), 'ego-sqlite-diff-'));
  try {
    const rnd = generator(20261002);
    const pick = <T>(a: readonly T[]): T => a[Math.floor(rnd() * a.length)]!;
    // options that change nothing about whether standard input is read, and ones that do (a statement operand)
    const OPTS = [
      '-header',
      '-noheader',
      '-column',
      '-csv',
      '-line',
      '-list',
      '-json',
      '-echo',
      '-bail',
      '-batch',
      '-readonly',
      '-nullvalue X',
      '-separator ,',
      "-cmd '.tables'",
      "--cmd '.tables'",
      "-cmd 'select 1'",
      '-init /dev/null',
      '--init /dev/null',
      '-safe',
      '-nofollow',
      '-interactive',
    ];
    const SQL = ['', '', '', "'select 1'", "'.tables'", "'.headers on'"];
    let ran = 0;
    let allowedAndRan = 0;
    for (let i = 0; i < 120; i++) {
      const opts: string[] = [];
      for (let k = Math.floor(rnd() * 4); k > 0; k--) opts.push(pick(OPTS));
      const marker = join(work, `m${i}`);
      const cmd = `echo '.shell touch ${marker}' | sqlite3 ${opts.join(' ')} :memory: ${pick(SQL)}`.replace(
        / +/g,
        ' ',
      );
      spawnSync('sh', ['-c', cmd], { cwd: work, encoding: 'utf8', timeout: 20000 });
      const didRun = existsSync(marker);
      if (didRun) ran++;
      if (didRun && verdict(cmd, dir) === 'ALLOW') {
        allowedAndRan++;
        assert.fail(`sqlite3 ran the piped .shell and the evaluator allows it: ${cmd}`);
      }
    }
    assert.ok(ran > 20, `the fuzz reached too few commands that run the script (${ran})`);
    assert.equal(allowedAndRan, 0);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});

/* ------------------------------------------------------------------------------------------------------------- *
 * THE TABLES AGAINST THE REAL CLIENTS. A table is a copy of an option parser; the original is the check. The PostgreSQL tools and
 * redis-cli are on this machine's docker images (nothing is pulled, there is no network); the others (mysql, mongosh,
 * clickhouse-client, cqlsh, influx) are written from their documentation and have no binary to ask here.
 * ------------------------------------------------------------------------------------------------------------- */

const word = (text: string): DbWord => ({ text, quoted: false, expands: false });

test('the PostgreSQL tools: every prefix of --host that a real binary takes for the host is read as the host (skipped without docker)', (t) => {
  const TOOLS: Record<string, string> = {
    psql: "-c 'select 1'",
    pg_dump: '',
    pg_dumpall: '',
    // (pg_restore opens its archive before it connects, so it cannot be asked here without a valid archive)
    createdb: 'app',
    dropdb: 'app',
    createuser: 'bob',
    dropuser: 'bob',
    pgbench: '',
  };
  const PREFIXES = ['h', 'ho', 'hos', 'host'];
  const script = Object.entries(TOOLS)
    .flatMap(([tool, tail]) =>
      PREFIXES.map((p) => `echo "@@ ${tool} ${p}"; ${tool} --${p}=127.0.0.2 ${tail} 2>&1 | head -2`),
    )
    .join('; ');
  const out = runInLocalImage(/^postgres:\d+(-alpine)?$/, script);
  if (out === null) return t.skip('no docker, or no postgres image on this machine');
  const blocks = new Map<string, string>();
  for (const b of out.split('@@ ').slice(1)) blocks.set(b.split('\n')[0]!.trim(), b);
  assert.equal(
    blocks.size,
    Object.keys(TOOLS).length * PREFIXES.length,
    'the container printed less than it was asked',
  );
  for (const tool of Object.keys(TOOLS))
    for (const p of PREFIXES) {
      const real = blocks.get(`${tool} ${p}`)!;
      const takenForHost = /server at "127\.0\.0\.2"/.test(real);
      const spec = DB_GRAMMAR[tool]!;
      const read = readDbTarget(spec, parseDbArgs([word(`--${p}=127.0.0.2`)], spec)).hosts.length > 0;
      // what the real tool takes for the host, the table must; an ambiguous prefix the tool refuses may be read as the host too
      if (takenForHost)
        assert.ok(read, `${tool} --${p}= is the host to the real tool and not to the table\n${real}`);
      else
        assert.match(
          real,
          /ambiguous|unrecognized|invalid option/i,
          `${tool} --${p}=: neither the host nor a refusal\n${real}`,
        );
    }
  // ...and the full name is the host to every one of them
  for (const tool of Object.keys(TOOLS))
    assert.match(blocks.get(`${tool} host`)!, /server at "127\.0\.0\.2"/, tool);
});

test("redis-cli: -h is the host, --host is no option, and an option after the command is the command's argument (skipped without docker)", (t) => {
  const run = (args: string): string => `echo "@@ ${args}"; redis-cli ${args} 2>&1 | head -1`;
  const body = (key: string): string => blocks.get(key)!.split('\n').slice(1).join('\n');
  const cases = [
    '-h 127.0.0.2 ping',
    '-h127.0.0.2 ping',
    '--host=127.0.0.2 ping',
    '--ho=127.0.0.2 ping',
    'ping -h 127.0.0.2',
  ];
  const out = runInLocalImage(/^redis:\d+(-alpine)?$/, cases.map(run).join('; '));
  if (out === null) return t.skip('no docker, or no redis image on this machine');
  const blocks = new Map<string, string>();
  for (const b of out.split('@@ ').slice(1)) blocks.set(b.split('\n')[0]!.trim(), b);
  const hostOf = (args: string): boolean => {
    const words = args.split(' ').map(word);
    return readDbTarget(REDIS_OPTIONS, parseDbArgs(words, REDIS_OPTIONS)).hosts.length > 0;
  };
  // the host: the real client tries to reach it, and so does the table's reading
  for (const a of ['-h 127.0.0.2 ping', '-h127.0.0.2 ping']) {
    assert.match(body(a), /127\.0\.0\.2/, a);
    assert.ok(hostOf(a), a);
  }
  // not an option of redis-cli at all (the table has no --host, and the text net still reads the word for a host)
  for (const a of ['--host=127.0.0.2 ping', '--ho=127.0.0.2 ping']) {
    assert.match(body(a), /Unrecognized option/i, a);
    assert.ok(!hostOf(a), a);
  }
  // after the command, `-h x` is an argument of the command: the client connects to the default host
  assert.doesNotMatch(body('ping -h 127.0.0.2'), /127\.0\.0\.2/);
  assert.ok(!hostOf('ping -h 127.0.0.2'));
});

test("the PostgreSQL tools' tables list every long option of the real binary's --help, with its arity (skipped without docker)", (t) => {
  const TOOLS = [
    'psql',
    'pg_dump',
    'pg_dumpall',
    'pg_restore',
    'createdb',
    'dropdb',
    'createuser',
    'dropuser',
    'pgbench',
  ];
  const script = TOOLS.map(
    (tool) => `echo "@@ ${tool}"; ${tool} ${tool === 'psql' ? '--help=options' : '--help'} 2>&1`,
  ).join('; ');
  const out = runInLocalImage(/^postgres:\d+(-alpine)?$/, script);
  if (out === null) return t.skip('no docker, or no postgres image on this machine');
  const problems: string[] = [];
  for (const block of out.split('@@ ').slice(1)) {
    const tool = block.split('\n')[0]!.trim();
    const spec = DB_GRAMMAR[tool]!;
    const takes = new Set(spec.value);
    const none = new Set([...spec.flag, ...(spec.escaping ?? [])]);
    // the options column: a line that begins with an option, `-x, --name=ARG` or `--name`, several names on one line (`--set=, --variable=`)
    for (const line of block
      .split('\n')
      .slice(1)
      .filter((l) => /^\s+-/.test(l))) {
      // (the options end where the description's column begins: two spaces)
      for (const m of line
        .trim()
        .split(/\s{2,}/)[0]!
        .matchAll(/--([a-z][a-z0-9-]*)(\[?=)?/g)) {
        const name = m[1]!;
        // (`--help=commands` and `--help=variables` are topics of a flag that takes none)
        if (name === 'help') continue;
        // a `--name=` the help shows with a value takes one; a bare name takes none
        const valued = m[2] !== undefined && m[2] !== '[=';
        if (!takes.has(name) && !none.has(name))
          problems.push(`${tool}: --${name} is in the real --help and not in the table`);
        else if (valued && !takes.has(name))
          problems.push(
            `${tool}: --${name} takes a value in the real --help and the table says it takes none`,
          );
        else if (!valued && m[2] === undefined && takes.has(name))
          problems.push(`${tool}: --${name} takes no value in the real --help and the table says it does`);
      }
    }
  }
  assert.deepEqual(problems, [], 'a table disagrees with the real tool:\n  ' + problems.join('\n  '));
});

test("the PostgreSQL tools' tables give every short option of the real binary's --help the right arity (skipped without docker)", (t) => {
  const TOOLS = [
    'psql',
    'pg_dump',
    'pg_dumpall',
    'pg_restore',
    'createdb',
    'dropdb',
    'createuser',
    'dropuser',
    'pgbench',
  ];
  const script = TOOLS.map(
    (tool) => `echo "@@ ${tool}"; ${tool} ${tool === 'psql' ? '--help=options' : '--help'} 2>&1`,
  ).join('; ');
  const out = runInLocalImage(/^postgres:\d+(-alpine)?$/, script);
  if (out === null) return t.skip('no docker, or no postgres image on this machine');
  const problems: string[] = [];
  let seen = 0;
  for (const block of out.split('@@ ').slice(1)) {
    const tool = block.split('\n')[0]!.trim();
    const spec = DB_GRAMMAR[tool]!;
    for (const line of block
      .split('\n')
      .slice(1)
      .filter((l) => /^\s+-/.test(l))) {
      const text = line.trim().split(/\s{2,}/)[0]!;
      // `-x, --name=ARG` takes a value; `-x, --name` takes none; `-x ARG` (no long name) takes one; `-1 ("one")` is a digit with a note
      if (text.startsWith('--')) continue;
      const m = /^-(\S)(?:\s+\([^)]*\))?(?:,\s+--[a-z0-9-]+(\[?=)?|\s+[A-Z]+)?/.exec(text);
      if (!m) continue;
      seen++;
      const letter = m[1]!;
      const valued = m[2] !== undefined ? m[2] === '=' : /^-\S\s+[A-Z]+/.test(text);
      if (letter === '?' || (letter === 'h' && tool === 'psql' && false)) continue;
      const inValue = spec.shortValue.includes(letter);
      const inFlag = spec.shortFlag.includes(letter);
      if (!inValue && !inFlag)
        problems.push(`${tool}: -${letter} is in the real --help and not in the table`);
      else if (valued && !inValue)
        problems.push(
          `${tool}: -${letter} takes a value in the real --help and the table says it takes none`,
        );
      else if (!valued && inValue)
        problems.push(`${tool}: -${letter} takes no value in the real --help and the table says it does`);
    }
  }
  assert.ok(seen > 100, `the help parse collapsed (${seen} short options)`);
  assert.deepEqual(problems, [], 'a table disagrees with the real tool:\n  ' + problems.join('\n  '));
});

test("redis-cli's table lists every option of the real binary's --help, with its arity - but the ones that act on the server (skipped without docker)", (t) => {
  const out = runInLocalImage(/^redis:\d+(-alpine)?$/, 'redis-cli --help 2>&1');
  if (out === null) return t.skip('no docker, or no redis image on this machine');
  // the options the table leaves out ON PURPOSE, so that they stay a question: they act on the server or the cluster
  const ASKED = new Set([
    '--cluster',
    '--replica',
    '--lru-test',
    '--vset-recall',
    '--vset-recall-count',
    '--vset-recall-ef',
    '--vset-recall-ele',
  ]);
  const problems: string[] = [];
  let seen = 0;
  for (const line of out.split('\n')) {
    const m = /^ {2}(-[A-Za-z0-9]|--[a-z][a-z0-9-]*)( <[^>]*>)?(?:\s|$)/.exec(line);
    if (!m) continue;
    const name = m[1]!;
    if (ASKED.has(name) || name === '-X') continue; // (-X takes the tag, which its help line does not show)
    seen++;
    const valued = m[2] !== undefined;
    const short = !name.startsWith('--');
    const bare = name.replace(/^-+/, '');
    const inValue = short ? REDIS_OPTIONS.shortValue.includes(bare) : REDIS_OPTIONS.value.includes(bare);
    const inFlag = short
      ? REDIS_OPTIONS.shortFlag.includes(bare)
      : [...REDIS_OPTIONS.flag, ...(REDIS_OPTIONS.escaping ?? [])].includes(bare);
    if (!inValue && !inFlag) problems.push(`${name} is in the real --help and not in the table`);
    else if (valued && !inValue)
      problems.push(`${name} takes a value in the real --help and the table says it takes none`);
    else if (!valued && inValue && !(REDIS_OPTIONS.escaping ?? []).includes(bare))
      problems.push(`${name} takes no value in the real --help and the table says it does`);
  }
  assert.ok(seen > 40, `the help parse collapsed (${seen} options)`);
  assert.deepEqual(problems, [], 'the table disagrees with the real tool:\n  ' + problems.join('\n  '));
});

test('a word the table does not know leaves the arity around it unproven, so the text net reads the line for a host as it did before the table', () => {
  const dir = workspace();
  // `--lru-test 100` takes a value the table cannot place (it is not in the table on purpose), so `100` looks like the command and
  // `-h` like one of its arguments: the net still finds the host
  for (const c of [
    `redis-cli --lru-test 100 -h ${PROD}`,
    `redis-cli --replica -h ${PROD}`,
    `psql --some-new-option -yhprod-db.acme.com -c 'update t set a=1'`,
    `mysql --some-new-option value -h ${PROD} -e 'update t set a=0'`,
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
  // ...and a table that was not surprised does not read a user named henry as a host
  assert.equal(verdict(`psql -Uhenry -c 'update t set a=1'`, dir), 'ALLOW');
});

test("sqlite3's table lists every option of the real binary's -help, with its arity (skipped without sqlite3)", (t) => {
  const help = spawnSync('sqlite3', ['-help'], { encoding: 'utf8' });
  const text = `${help.stdout ?? ''}${help.stderr ?? ''}`;
  if (!/^Usage: sqlite3/m.test(text)) return t.skip('no sqlite3 on this machine');
  // the options the table does not model on purpose: they take several words or run an archive command, and are opaque (sqliteEscape)
  const SPECIAL = new Set(['A', 'lookaside', 'pagecache', 'unsafe-testing']);
  const known = new Set([...SQLITE_OPTIONS.value, ...SQLITE_OPTIONS.flag]);
  const problems: string[] = [];
  let seen = 0;
  for (const line of text.split('\n')) {
    const m = /^ {3}-(\[no\])?([A-Za-z][A-Za-z-]*)(?: ([A-Z][A-Z.]*))?(?:\s|$)/.exec(line);
    if (!m || SPECIAL.has(m[2]!)) continue;
    seen++;
    const names = m[1] !== undefined ? [m[2]!, `no${m[2]!}`] : [m[2]!];
    for (const name of names) {
      if (!known.has(name)) problems.push(`-${name} is in the real -help and not in the table`);
      else if (m[3] !== undefined && !SQLITE_OPTIONS.value.includes(name))
        problems.push(`-${name} takes a value in the real -help and the table says it takes none`);
      else if (m[3] === undefined && SQLITE_OPTIONS.value.includes(name))
        problems.push(`-${name} takes no value in the real -help and the table says it does`);
    }
  }
  assert.ok(seen > 30, `the help parse collapsed (${seen} options)`);
  assert.deepEqual(problems, [], 'the table disagrees with the real tool:\n  ' + problems.join('\n  '));
  // sqlite3 takes `--name` for `-name`, and nothing shorter: `-hea` is not `-header`
  const abbreviated = spawnSync('sqlite3', ['-hea', ':memory:', 'select 1'], { encoding: 'utf8' });
  assert.notEqual(abbreviated.status, 0, 'sqlite3 takes an abbreviation of an option');
});
