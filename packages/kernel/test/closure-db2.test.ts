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
import { sqlScan } from '../src/authority/sql-lex.ts';
import { verdict, workspace } from './support/corpus.ts';
import { PSQL_LEXICAL_CASES, startPsqlOracle } from './support/psql-oracle.ts';

const notAllowed = (cmds: readonly string[], dir: string): void => {
  for (const c of cmds) assert.notEqual(verdict(c, dir), 'ALLOW', c);
};
const allowed = (cmds: readonly string[], dir: string): void => {
  for (const c of cmds) assert.equal(verdict(c, dir), 'ALLOW', c);
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
    assert.ok(!('refused' in scan), `${JSON.stringify(c.script)} (${c.why}) was refused: ${'refused' in scan ? scan.refused : ''}`);
    const reported = scan.metas.some((m) => m.name === 'o' && m.args === '|touch /tmp/x');
    assert.equal(reported, c.runs, `${JSON.stringify(c.script)}: ${c.why} - psql ${c.runs ? 'runs' : 'does not run'} the \\o line`);
  }
});

test('RV-DB-2: the cases above are what the real psql does (skipped without docker and a postgres image already on the machine)', (t) => {
  const oracle = startPsqlOracle();
  if (oracle === null) return t.skip('no docker, or no postgres image on this machine');
  try {
    const got = oracle.runs(PSQL_LEXICAL_CASES.map((c) => c.script));
    const wrong = PSQL_LEXICAL_CASES.filter((c, i) => got[i] !== c.runs).map((c) => `${JSON.stringify(c.script)} (${c.why})`);
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
  for (const c of PSQL_LEXICAL_CASES.filter((x) => x.runs)) notAllowed(viaStdin(c.script.replaceAll('@MARK@', '/tmp/x')), dir);
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
    ];
    const got = oracle.runs(cases.map(([script, vars]) => ({ script, args: Object.entries(vars).flatMap(([k, v]) => ['-v', `${k}=${v}`]) })));
    cases.forEach(([script, vars, runs], i) => {
      assert.equal(got[i], runs, `${oracle.version}: ${JSON.stringify(script)} with ${JSON.stringify(vars)}`);
      const scan = sqlScan(script.replaceAll('@MARK@', '/tmp/x'), 'pg', new Map(Object.entries(vars).map(([k, v]) => [k, v.replaceAll('@MARK@', '/tmp/x')])));
      if ('refused' in scan) return;
      // a command psql runs is reported, or the script asks about a variable whose text it cannot see
      const seen = scan.metas.some((m) => m.name === 'o') || scan.variables.length > 0;
      if (runs) assert.ok(seen, `${JSON.stringify(script)} runs a command the scanner did not see`);
      else assert.ok(!scan.metas.some((m) => m.name === 'o'), `${JSON.stringify(script)} runs nothing, yet the scanner reports a command`);
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
      ...viaStdin('select 1 \\; select pg_ls_dir(\'.\')\n'),
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
  'select 1', ' as ', 'a', 'x', 'e', 'E', 'a$', 'a$$', 'a$$$', 'x$y', '$$', '$a$', '$a$ q $a$', '$$ q $$', '$$ ', "'", "''", "'x'",
  "'\\'", "'a\\'b'", "e'x'", "E'\\''", "e'\\\\'", "a$e'x'", "a$E'\\'", "_e'\\''", '"', '"x"', '"\'"', '"\\"', '"a""b"', "U&'x'",
  'U&"x"', '1$$', '1', '1.', '.5', '1.5', 'é', 'é$$', 'é$a$', ';', '\n', ' ', '\t', '\\\\', ':', ':x', ":'x'", ':"x"', '::', '::int',
  '`', "b'1'", "x'1'", "n'x'", "1e'x'", "1e'\\'", '1e5', '1e5$$', '1e+5', '0x1F', '0x1F$$', '1_0', '1_0$$', '(', ')', ',', '.', '\\g',
  '$1', '$1$$', '$1a', '$1a$', '@', '#', '%', '[', ']', '{', '}', '[1:2]', '\r', '\f', '\v', '\\q', 'x$$', 'U&', "$q$'$q$", '$$\\$$',
  '1.5$$', '.$$', ')$$', ']$$', "'x'$$", '"x"$$', ':$$', '+$$', '1$a$', 'e1$$', '_$$', 'a1$$', 'a_$$', 'é1$$', '$_$', '$é$', '$é$ q $é$',
  "E'a'$$", '\\\\$$', ' $x$ ', '$X$', '$x$ $X$', 'x$x$', ',$$', '=$$', '*$$', '~$$', '<$$', '>$$', '-$$', '/$$', '|$$', '&$$', '^$$',
  '!$$', '?$$', '@$$', '#$$', '%$$', '`$$', '\\;', '\\: ', ' \\; ', '\\;\\;', "\\; '", '\\:x', "x'", "'\n", '$$\n', "\n'", 'e ', ' e',
  '1a', '1a$$', '15$$', '15 $$', '2e', '3e$$', 'éé', '😀$$', '😀', 'z$',
];
const CLOSERS = ['', '', '$$', "'", '"', '$a$', "$$ '", "$$'", "'$$", '"$$', "e'", 'x$$', "$$\n'", "'\\'", '\n', ' \\; ', '`'];

/** a deterministic generator: the same seed is the same scripts on every machine */
function generator(seed: number): () => number {
  let s = seed >>> 0;
  return () => ((s = (Math.imul(s, 1664525) + 1013904223) >>> 0) / 4294967296);
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
