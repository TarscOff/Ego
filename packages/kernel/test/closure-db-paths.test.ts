// CLOSURE OF FIVE ROOT CAUSES OF THE PHASE-1 FINDINGS REGISTER (closure audit wave 3): RC-DB, RC-PTH, RC-RED, RC-CWD and the
// segment-structure cause (cause-S). Each section names the finding that was reported, then pins the READER that now answers
// the dimension - not the one spelling that was reported - with the neighbours a second reviewer would try next. The history
// of this repository is that a fix at one spelling leaves its siblings open, so a test here is a property of a dimension
// (every statement-bearing option of a client, every name a wildcard can match, every nest of a wrapper), not a list of
// strings that happened to be found.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { workspace, verdict } from './support/corpus.ts';

/** every command is judged at least `floor`: nothing here may be the plain ALLOW */
function atLeast(floor: 'ASK' | 'DENY', cmds: readonly string[], dir: string): void {
  const rank = { ALLOW: 0, ASK: 1, DENY: 2 } as const;
  for (const c of cmds) {
    const got = verdict(c, dir) as keyof typeof rank;
    assert.ok(rank[got] >= rank[floor], `${c}: ${got}, floor ${floor}`);
  }
}
function allowed(cmds: readonly string[], dir: string): void {
  for (const c of cmds) assert.equal(verdict(c, dir), 'ALLOW', c);
}

/* ------------------------------------------------------------------------------------------------------------- *
 * RC-DB. ONE READER OF "WHAT STATEMENTS WILL THIS CLIENT RUN".
 *
 * Findings: sa10-34 (CRITICAL: `clickhouse-client --host prod-ch --query 'show tables' -q 'drop table t'` was a production
 * DROP TABLE at ALLOW), r11-84 (`mysql -uroot -e'DROP DATABASE app'`: the glued value hid the word from the drop matcher),
 * r11-86 (a connection URL held in a variable that a FLAG names: `dbmate --env PROD_URL`).
 * ------------------------------------------------------------------------------------------------------------- */

test('RC-DB: every statement a client is given is read, whichever option spelling carried it', () => {
  const dir = workspace();
  // against a production host the read exception needs ALL the statements to be reads: a second one given by the
  // client's SHORT option (`-q`), glued, repeated or abbreviated must be seen exactly like the first
  const prod = [
    // sa10-34 and the order, glue and repetition around it
    `clickhouse-client --host prod-ch --query 'show tables' -q 'drop table t'`,
    `clickhouse-client --host prod-ch -q 'show tables' --query 'drop table t'`,
    `clickhouse-client --host prod-ch --query='show tables' -q'drop table t'`,
    `clickhouse-client --host prod-ch -q 'select 1' -q 'drop table t'`,
    `clickhouse-client --host prod-ch -q 'select 1' -q 'select 2' -q 'truncate table t'`,
    `clickhouse-client --host prod-ch --query 'show tables' --que 'drop table t'`,
    `clickhouse-client --host prod-ch --query 'show tables' --quer='drop table t'`,
    `clickhouse-client --host prod-ch -n -q 'select 1; drop table t'`,
    `clickhouse client --host prod-ch -q 'select 1' -q 'truncate table t'`,
    `clickhouse-client -h prod-ch -q 'select 1' --query 'alter table t delete where 1'`,
    // the other clients, in the spellings their parsers accept
    `mysql -h prod-db -e 'show tables' -e 'drop table t'`,
    `mysql -h prod-db -e'show tables' -e'drop table t'`,
    `mysql -h prod-db -e 'show tables' --exe 'drop table t'`,
    `mysql -h prod-db --execute='show tables' --execute='drop table t'`,
    `mariadb -h prod-db -e 'select 1' --execute 'delete from t'`,
    `psql -h prod-db -c 'select 1' -c 'drop table t'`,
    `psql -h prod-db -c'select 1' -c'drop table t'`,
    `psql -h prod-db -c 'show all' --comm='delete from t'`,
    `influx -host prod-influx -execute 'show databases' -execute 'drop database x'`,
    `cqlsh -u u -p p -e 'describe tables' -e 'truncate t' prod-cass.acme.com`,
    `cqlsh -e 'describe tables' --execute 'truncate t' prod-cass.acme.com`,
    // a statement in a file or an include is still a script nobody read
    `clickhouse-client --host prod-ch -q 'select 1' --queries-file /tmp/payload`,
  ];
  atLeast('ASK', prod, dir);
  // the ones that name a host that is production by its name are refused outright: a human cannot approve them
  for (const c of prod.filter((x) => /prod-(ch|db|influx)/.test(x))) assert.equal(verdict(c, dir), 'DENY', c);
  // ...and the read exception is not lost for the inspection an operator performs BEFORE deciding. `-q` is the whole
  // spelling of the query in clickhouse, and a plain read given by it was an absolute deny
  assert.notEqual(verdict(`clickhouse-client --host prod-ch -q 'show tables'`, dir), 'DENY');
  assert.notEqual(verdict(`clickhouse-client --host prod-ch -q 'select 1' -q 'select 2'`, dir), 'DENY');
  assert.notEqual(verdict(`clickhouse-client --host prod-ch --query='select count(*) from t'`, dir), 'DENY');
  assert.notEqual(verdict(`mysql -h prod-db -e'show tables' -e'select 1'`, dir), 'DENY');
  assert.notEqual(verdict(`psql -h prod-db -c'select 1' -c'select 2'`, dir), 'DENY');
});

test('RC-DB: dropping a DATABASE or a SCHEMA is the drop capability in every spelling of the statement option', () => {
  const dir = workspace();
  // r11-84 and its neighbours: the statement is one word, glued to its option, abbreviated, repeated, or one of several
  atLeast(
    'ASK',
    [
      `mysql -uroot -e'DROP DATABASE app'`,
      `mysql -uroot -e 'DROP SCHEMA app'`,
      `mysql -uroot -e"drop database app"`,
      `mysql --exe='DROP DATABASE app'`,
      `mysql -e 'select 1; drop database app'`,
      `mysql -e 'select 1' -e 'drop schema if exists app'`,
      `mariadb -e'drop schema if exists app'`,
      `psql -c 'DROP DATABASE app'`,
      `psql -c'DROP DATABASE app'`,
      `psql --command='DROP SCHEMA public CASCADE'`,
      `psql --comm 'drop database app'`,
      `psql -d postgres -c 'select 1' -c 'DROP DATABASE app'`,
      `clickhouse-client -q 'DROP DATABASE app'`,
      `clickhouse-client --query='drop database app'`,
      `clickhouse-client -q 'select 1' -q'drop database app'`,
      `cqlsh -e 'DROP KEYSPACE ks'`,
      `dropdb app`,
    ],
    dir,
  );
  // the class decides, not the host: the same statement at a production host is the production deny
  for (const c of [`mysql -h prod-db -e'DROP DATABASE app'`, `psql -h prod-db -c'DROP SCHEMA public'`])
    assert.equal(verdict(c, dir), 'DENY', c);
  // ordinary local DDL stays ordinary: only a DATABASE, a SCHEMA and a KEYSPACE are "a database" (a table is the database's own
  // contents). The text net of the `db.local.drop` matcher also asks for a literal that spells the words
  // (`select 'drop database x'`): the one false positive it accepts, and an ASK.
  allowed(
    [
      `mysql -e 'drop table t'`,
      `mysql -e'drop table if exists t'`,
      `psql -c 'drop index i'`,
      `clickhouse-client -q 'drop table t'`,
      `sqlite3 app.db 'drop table t'`,
      `mysql -e 'show databases'`,
      `psql -c 'select schema_name from information_schema.schemata'`,
    ],
    dir,
  );
});

test('RC-DB: the statement reader and the drop matcher list the same objects', () => {
  // the reader (dbDropsDatabase) is the authority for a statement given by an option; the matcher is the text net for one
  // that is not (a here-string). If one list grows and the other does not, a form of the statement stops being the drop.
  const dir = workspace();
  for (const object of ['DATABASE', 'SCHEMA', 'KEYSPACE']) {
    const stmt = `DROP ${object} app`;
    for (const form of [
      `psql -c '${stmt}'`,
      `psql -c'${stmt}'`,
      `mysql --execute='${stmt}'`,
      `clickhouse-client --query '${stmt}'`,
      `cqlsh -e '${stmt}'`,
      `psql <<< '${stmt}'`,
      `echo '${stmt}' | mysql`,
    ])
      assert.equal(verdict(form, dir), 'ASK', form);
  }
});

test('RC-DB: a connection URL held in a variable that a flag NAMES is followed to its value, and asks when the value is unknown', () => {
  const dir = workspace();
  const prodUrl = 'postgres://u@prod-db.acme.com/app';
  // r11-86 and the spellings of the flag and of the assignment
  for (const c of [
    `PROD_URL=${prodUrl} dbmate --env PROD_URL up`,
    `PROD_URL=${prodUrl} dbmate -e PROD_URL up`,
    `PROD_URL=${prodUrl} dbmate --env=PROD_URL up`,
    `PROD_URL=${prodUrl} dbmate --env PROD_URL drop`,
    `export PROD_URL=${prodUrl}; dbmate --env PROD_URL up`,
    `PROD_URL=${prodUrl}\ndbmate --env PROD_URL up`,
    `env PROD_URL=${prodUrl} dbmate --env PROD_URL up`,
    `PROD_URL=${prodUrl} npx dbmate --env PROD_URL up`,
    `PROD_URL=${prodUrl} bash -c 'dbmate --env PROD_URL up'`,
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
  // a variable the command does not define holds something nobody can read: it asks, it is never the local socket
  for (const c of [`dbmate --env STAGING_URL up`, `dbmate -e STAGING_URL migrate`, `dbmate --env=DATABASE_URL up`, 'dbmate --env "$TARGET" up'])
    assert.equal(verdict(c, dir), 'ASK', c);
  // ...and a name that itself carries a production marker is the production database whatever the value is
  assert.equal(verdict(`dbmate --env PROD_URL up`, dir), 'DENY');
  // a variable that names a declared local database is local work, and an unnamed target is the ordinary dev loop
  allowed(
    [
      `LOCAL_URL=postgres://u@localhost/app dbmate --env LOCAL_URL up`,
      `DEV_URL=postgres://u@127.0.0.1:5432/app dbmate -e DEV_URL status`,
      `dbmate up`,
      `dbmate status`,
      `dbmate new add_users`,
    ],
    dir,
  );
  // an ENVIRONMENT NAME is data about the target too: a runner that takes one is judged by the name it was given
  for (const c of [`knex migrate:latest --env production`, `npx knex migrate:rollback --env=production`])
    assert.equal(verdict(c, dir), 'DENY', c);
});
