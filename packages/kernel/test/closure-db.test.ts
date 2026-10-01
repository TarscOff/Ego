// CLOSURE OF THE DATABASE-CLIENT FAMILY (independent audit of 2026-10-01, items 5, C3, C4, C10, D25; exit review 11
// findings #102, #130 and #131).
//
// THE CLASS: a database client is handed something that makes it RUN A PROGRAM, WRITE A FILE OUTSIDE ITS DATABASE or
// LOAD NATIVE CODE, and the verdict stays the plain-client ALLOW. It is the fourth rule of the contract
// (docs/architecture/security-model.md) - a known class plus an operand the class does not bound - and the earlier fixes
// each closed one SPELLING: `.shell` was asked and `.sh` was not.
//
// So the reader is a GRAMMAR, not a list of bad words: what is positively known to be harmless is ordinary, and the rest
// asks. These tests pin the properties (one representative per channel, and the ordinary work that must stay ordinary),
// not a collection of spellings; the generated cross-product (corpus.ts) carries the spellings through every
// transformation.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { workspace, verdict } from './support/corpus.ts';

/** every command asks (or is refused): none is the plain-client ALLOW */
function notAllowed(cmds: readonly string[], dir: string): void {
  for (const c of cmds) assert.notEqual(verdict(c, dir), 'ALLOW', c);
}
function allowed(cmds: readonly string[], dir: string): void {
  for (const c of cmds) assert.equal(verdict(c, dir), 'ALLOW', c);
}

test('sqlite3: a statement is ordinary only when it is a read or ordinary DDL/DML that touches no file', () => {
  const dir = workspace();
  notAllowed(
    [
      // review-11 #102 / #130: the SQL function writes a file, here an executable git hook
      `sqlite3 :memory: "select writefile('.git/hooks/pre-commit', 'x')"`,
      `sqlite3 app.db "select readfile('.env')"`,
      `sqlite3 app.db "select * from fsdir('/etc')"`,
      `sqlite3 app.db "select edit('a')"`,
      // a second database file, or a copy of this one, written wherever the statement says
      `sqlite3 app.db "attach database 'other.db' as o"`,
      `sqlite3 app.db "vacuum into 'copy.db'"`,
      `sqlite3 app.db "create virtual table t using csv(filename='x.csv')"`,
      // a function nobody listed is not known to be pure
      `sqlite3 app.db "select some_function(1)"`,
    ],
    dir,
  );
  // a dot-command is ordinary only on the short read-only list, and ONLY by its whole name: sqlite3 accepts any
  // unambiguous prefix, so an abbreviation of a command that runs a program is that command
  notAllowed(
    [
      `sqlite3 app.db '.sh id'`,
      `sqlite3 app.db '.syste id'`,
      `sqlite3 app.db '.ou out.txt'`,
      `sqlite3 app.db '.on out.txt'`,
      `sqlite3 app.db '.read script.sql'`,
      `sqlite3 app.db '.backup copy.db'`,
      `sqlite3 -cmd '.sh id' app.db 'select 1'`,
      `sqlite3 app.db 'select 1' '.sh id'`,
      // the same statement handed over on standard input
      `echo "select writefile('.git/hooks/pre-commit', 'x')" | sqlite3 app.db`,
    ],
    dir,
  );
  // the real binary does not appear in the evaluation: nothing was written
  assert.equal(existsSync(join(dir, '.git', 'hooks', 'pre-commit')), false);
  allowed(
    [
      `sqlite3 app.db "select count(*) from users"`,
      `sqlite3 app.db .tables`,
      `sqlite3 app.db ".schema users"`,
      `sqlite3 app.db ".dump"`,
      `sqlite3 -header -column app.db "select * from t"`,
      `sqlite3 -json app.db "select * from t where a < 10"`,
      `sqlite3 :memory: "select sqlite_version()"`,
      `sqlite3 app.db "create table t (id integer primary key, name text not null, at datetime default current_timestamp)"`,
      `sqlite3 app.db "create index idx_t_name on t(name)"`,
      `sqlite3 app.db "insert into t(name) values ('a'), ('b')"`,
      `sqlite3 app.db "update t set name = upper(name) where id < 10"`,
      `sqlite3 ./dev.db "delete from t"`,
      `sqlite3 app.db "pragma table_info(t)"`,
      `sqlite3 app.db "select datetime('now'), strftime('%Y', 'now'), typeof(1)"`,
      `echo "select 1" | sqlite3 app.db`,
    ],
    dir,
  );
});

test('sqlite3: the database file operand is a file the client WRITES, judged like any other write', () => {
  const dir = workspace();
  mkdirSync(join(dir, 'data'), { recursive: true });
  assert.notEqual(verdict(`sqlite3 .git/hooks/pre-commit "create table t(a)"`, dir), 'ALLOW');
  assert.equal(verdict(`sqlite3 data/app.db "create table t(a)"`, dir), 'ALLOW');
  // opened read-only, nothing is written
  assert.equal(verdict(`sqlite3 -readonly .git/hooks/pre-commit "select 1"`, dir), 'ALLOW');
});
