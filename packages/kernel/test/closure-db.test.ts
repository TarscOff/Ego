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

test('mongosh and mongo: an inline script is ordinary only when it is a single expression of a known database shape', () => {
  const dir = workspace();
  notAllowed(
    [
      // review-11 #131: an alias of `require` defeated the old rule, which looked for the literal word
      `mongosh --eval 'const r = require; r("child_process").execSync("cmd")'`,
      `mongosh --eval 'require("child_process").execSync("cmd")'`,
      `mongosh --eval 'globalThis["req" + "uire"]("fs")'`,
      `mongosh --eval 'Function("return 1")()'`,
      `mongo --eval 'run("cmd")'`,
      // server-side JavaScript hidden in an otherwise ordinary query, and a write into another collection
      `mongosh --eval 'db.users.find({$where: "sleep(1000)"})'`,
      `mongosh --eval 'db.users.aggregate([{$match: {a: 1}}, {$out: "copy"}])'`,
      `mongosh --eval 'db.users.aggregate([{$addFields: {x: {$function: {body: "function(){}", args: [], lang: "js"}}}}])'`,
      // a callback is code
      `mongosh --eval 'db.users.find().forEach(function (d) { print(d) })'`,
      `mongosh --eval 'db.users.find().map(d => d)'`,
      // a database command is not a shape this reader knows
      `mongosh --eval 'db.runCommand({shutdown: 1})'`,
      `mongosh --eval 'load("script.js")'`,
      `mongosh script.js`,
      `mongosh --file script.js`,
      `mongosh --eval "$SCRIPT"`,
      `mongosh --some-new-option --eval 'db.stats()'`,
    ],
    dir,
  );
  assert.equal(verdict(`mongosh prod-mongo:27017 --eval 'require("fs")'`, dir), 'DENY');
  allowed(
    [
      `mongosh --eval "db.users.find()"`,
      `mongosh --eval 'db.stats()'`,
      `mongosh --quiet --eval 'db.users.countDocuments({active: true})'`,
      `mongosh app --eval "db.users.insertOne({name: 'a', at: new Date()})"`,
      `mongosh --eval "show collections"`,
      `mongosh mongodb://localhost:27017/app --eval "db.getCollectionNames()"`,
      `mongosh --eval 'db.users.drop()'`,
      `mongosh --eval 'db.users.find({_id: ObjectId("507f1f77bcf86cd799439011")}).sort({a: -1}).limit(5).toArray()'`,
      `mongosh --eval 'printjson(db.users.aggregate([{$match: {a: {$gt: 1}}}, {$group: {_id: "$b", n: {$sum: 1}}}]).toArray())'`,
      `mongosh --eval 'use app; db.users.find()'`,
      `echo "db.users.find()" | mongosh`,
    ],
    dir,
  );
});

test('mysql and mariadb: client commands, option files and plugin options are judged, not spelled', () => {
  const dir = workspace();
  notAllowed(
    [
      // the client's own commands, in the statement text and in their backslash form
      `mysql -e 'pager cmd; select 1'`,
      `mysql -e '\\P cmd'`,
      `mysql -e 'system cmd'`,
      `mysql -e '\\! cmd'`,
      `mysql -e 'edit'`,
      `mysql -e 'source script.sql'`,
      `mysql -e 'delimiter //'`,
      `mysql -e 'tee .git/hooks/pre-commit; select 1'`,
      // options that hand the client a program, a library, a startup file or a statement to run first
      `mysql --pager=cmd -e 'select 1'`,
      `mysql --tee=.git/hooks/pre-commit -e 'select 1'`,
      `mysql --plugin-dir=plugins --default-auth=x -e 'select 1'`,
      `mysql --defaults-extra-file=extra.cnf -e 'select 1'`,
      `mysql --init-command='system cmd' -e 'select 1'`,
      // an abbreviation is the option it abbreviates
      `mysql --pag=cmd -e 'select 1'`,
      // the server reads or writes a file on this machine
      `mysql -e "select load_file('/etc/hostname')"`,
      `mysql -e "select 1 into outfile '/tmp/out'"`,
      `mysql -e "load data infile '/tmp/in' into table t"`,
      `mysql -e "set global general_log_file = '/tmp/log'"`,
      `mysql -e "$STATEMENT"`,
      `mariadb -e 'pager cmd; select 1'`,
      `LIBMYSQL_PLUGIN_DIR=plugins mysql -e 'select 1'`,
    ],
    dir,
  );
  assert.equal(verdict(`mysql -h prod-db.acme.com -e 'select 1' --pager=cmd`, dir), 'DENY');
  assert.equal(verdict(`mysql -h prod-db.acme.com -e 'select 1'`, dir), 'ALLOW');
  allowed(
    [
      `mysql -e "show tables"`,
      `mysql -u root -e "select 1"`,
      `mysql -h 127.0.0.1 -P 3306 -uroot -psecret app -e "select 1"`,
      `mysql -u root -p -e "select 1"`,
      `mysql --batch --skip-column-names -e "select count(*) from t"`,
      `mysql --default-character-set=utf8mb4 --ssl-mode=DISABLED -e "select 1"`,
      `mysql -e "insert into t values (1)"`,
      `mysql -e "drop table t"`,
      `mysql -u root app -e "create table t (id int primary key, name varchar(10))"`,
      `mysql -e "select * from t where id < 10 \\G"`,
      `mariadb -e "select 1"`,
      `mysql --version`,
    ],
    dir,
  );
});

test('psql: output, meta-commands, startup files and statements that leave the database are judged, not spelled', () => {
  const dir = workspace();
  notAllowed(
    [
      // output handed to a program, by option and in-band
      `psql -o '|cmd' -c 'select 1'`,
      `psql --output='|cmd' -c 'select 1'`,
      `psql -c '\\o |cmd'`,
      `psql -c '\\w |cmd'`,
      `psql -c 'select 1 \\g |cmd'`,
      // an editor, an include, an environment write, a program in a COPY
      `psql -c '\\e'`,
      `psql -c '\\i script.sql'`,
      `psql -c '\\setenv EDITOR cmd'`,
      `psql -c "\\copy t to program 'cmd'"`,
      // a file the client writes is a write like any other: the path decides
      `psql -c '\\o .git/hooks/pre-commit'`,
      `psql -L .git/hooks/pre-commit -c 'select 1'`,
      `psql -c "\\copy t to '.git/hooks/pre-commit'"`,
      // the server reads or writes a file on this machine
      `psql -c "copy t to '/tmp/out'"`,
      `psql -c "select pg_read_file('/etc/hostname')"`,
      `psql -c "select lo_export(1, '/tmp/x')"`,
      `psql -c "do \\$\\$ begin perform 1; end \\$\\$"`,
      // a statement built at run time is a statement nobody read
      `psql -c "$STATEMENT"`,
      `psql -c "$(cat statement.txt)"`,
      // an option this reader does not know
      `psql --some-new-option -c 'select 1'`,
    ],
    dir,
  );
  // the environment makes the client run a startup script, a pager, an editor or write a history file
  notAllowed(
    [
      `PSQLRC=rc.sql psql -c 'select 1'`,
      `PSQL_PAGER=cmd psql -c 'select 1'`,
      `PSQL_EDITOR=cmd psql -c '\\e'`,
      `PSQL_HISTORY=.git/hooks/pre-commit psql -c 'select 1'`,
      `PGSYSCONFDIR=conf psql -c 'select 1'`,
      `export PSQLRC=rc.sql; psql -c 'select 1'`,
      `env PSQLRC=rc.sql psql -c 'select 1'`,
    ],
    dir,
  );
  // a program-valued option on a PRODUCTION host is not the read the plain SELECT decision covers
  assert.equal(verdict(`psql -h prod-db.acme.com -U ro -c 'select 1' -o '|cmd'`, dir), 'DENY');
  assert.equal(verdict(`psql -h prod-db.acme.com -U ro -c 'select 1'`, dir), 'ALLOW');
  allowed(
    [
      `psql -c "select 1"`,
      `psql -h localhost -U app -d app -c "select count(*) from users"`,
      `psql -c "\\dt"`,
      `psql -c "\\d users"`,
      `psql -c "\\l"`,
      `psql -At -c "select 1"`,
      `psql -X -q -c "select 1"`,
      `psql -v ON_ERROR_STOP=1 -c "select 1"`,
      `psql --csv -c "select * from users"`,
      `psql -c "insert into t values (1)"`,
      `psql -c "create table t (id serial primary key, name text)"`,
      `psql -c "update t set a = a + 1 where id < 10"`,
      `psql -c "drop table t"`,
      `psql "postgres://localhost:5432/app_dev" -c "select 1"`,
      `psql -o out.txt -c "select 1"`,
      `psql -c "\\copy users to 'users.csv' csv header"`,
      `psql -h /tmp -c 'select 1'`,
      `psql --version`,
      `echo "select 1" | psql`,
    ],
    dir,
  );
});
