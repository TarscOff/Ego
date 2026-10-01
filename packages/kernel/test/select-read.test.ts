// PRODUCT DECISION (2026-09-30): a plain SELECT against a production database is a READ - ALLOW, not ASK and not an
// absolute DENY ("it is only a select"). What is accepted is a strict GRAMMAR (isPlainSelect in evaluate.ts): a short
// lexical set, one statement, no comment, and no call to a function that is not on the pure list. Everything a SELECT
// can do besides read - write a file, take a lock, call a function that acts - stays exactly what it was: the act it is.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { workspace, verdict } from './support/corpus.ts';

const PROD = 'psql -h prod-db.acme.com -U ro -c';
/** the statement as ONE shell word: single quotes when it has none of its own, otherwise double quotes with the four
 *  characters the shell would otherwise read escaped - so what reaches the evaluator is what the operator typed */
const word = (q: string): string =>
  q.includes("'") ? `"${q.replace(/(["\\$`])/g, '\\$1')}"` : `'${q}'`;
const prod = (q: string): string => `${PROD} ${word(q)}`;

test('a plain SELECT against a production database is ALLOW', () => {
  const dir = workspace();
  for (const q of [
    'SELECT 1',
    'select * from users',
    "select id, email from users where created_at > now() - 1 and plan <> 'free' order by id desc limit 10 offset 20",
    'select count(*) from orders',
    'select u.id, count(o.id) as n from users u left join orders o on o.user_id = u.id group by u.id having count(o.id) > 3',
    'select lower(email), coalesce(nickname, name) from users where id in (1, 2, 3)',
    'select * from (select id from users where active) t',
    'select id from users where exists (select 1 from orders o where o.user_id = users.id)',
    "select data->>'name' from events where kind = 'signup'",
    'select id, row_number() over (partition by org order by id) from users',
    'select cast(total as numeric(10,2)) from orders',
    'select "User".id from "User"',
    'select `id` from `users`',
    'select @@version',
    'select * from information_schema.tables',
    "select 'it''s' as s",
    'select case when n > 1 then 1 else 0 end from t',
    'select 1;',
  ])
    assert.equal(verdict(prod(q), dir), 'ALLOW', q);
  // the other clients spell the flag their own way
  for (const c of [
    'mysql -h prod-db.acme.com -e "select 1"',
    'mysql -h prod-db.acme.com --execute="select id from users"',
    "psql -h prod-db.acme.com -c 'select 1' -c 'select 2'",
    'PGHOST=prod-db.acme.com psql -c "select 1"',
  ])
    assert.equal(verdict(c, dir), 'ALLOW', c);
  // and a host nobody could classify reads the same way a SHOW does
  assert.equal(verdict('psql service=prod -c "select 1"', dir), 'ALLOW');
});

test('a SELECT that does anything but read keeps the verdict of the act', () => {
  const dir = workspace();
  const acts: string[] = [
    // functions that act
    'select pg_terminate_backend(pid) from pg_stat_activity',
    "select nextval('s')",
    "select setval('s', 1)",
    "select lo_import('/etc/passwd')",
    "select pg_read_file('/etc/passwd')",
    "select dblink_exec('dbname=x', 'drop table t')",
    "select query_to_xml('delete from t', true, true, '')",
    "select set_config('x', 'y', false)",
    'select pg_sleep(60)',
    'select sleep(60)',
    "select load_file('/etc/passwd')",
    "select get_lock('x', 100)",
    'select benchmark(100000000, md5(1))',
    // a call the allowlist cannot read
    'select pg_catalog.pg_terminate_backend(1)',
    'select "pg_terminate_backend"(1)',
    'select count (*) from t where pg_terminate_backend (1)',
    'select myschema.count(x) from t',
    // clauses that write or lock
    "select * from users into outfile '/tmp/u'",
    "select * from users into dumpfile '/tmp/u'",
    'select * from users into @v',
    'select * into newtable from users',
    'select * from users for update',
    'select * from users for share',
    'select * from users lock in share mode',
    'select * from users procedure analyse()',
    'with d as (delete from users returning *) select * from d',
    // more than one statement, or text the server reads as something else
    'select 1; drop table users',
    'select 1 -- x',
    'select /*! drop table users */ 1',
    'select /* x */ 1',
    'select 1 # x',
    "select $$x$$",
    'select $1',
    'select @x := 1',
    "select E'\\x41'",
    'select 1 \\g',
    "select * from users where name = 'a\\'b'",
    'select "unterminated',
    'select (1',
    'select 1)',
    'select é from t',
  ];
  for (const q of acts) {
    assert.notEqual(verdict(prod(q), dir), 'ALLOW', q);
  }
  // where the act is a production mutation, it is still the absolute deny
  for (const q of [
    'select pg_terminate_backend(pid) from pg_stat_activity',
    "select * from users into outfile '/tmp/u'",
    'select * from users for update',
    'select 1; drop table users',
  ])
    assert.equal(verdict(prod(q), dir), 'DENY', q);
});

test('the grammar is one statement: a second read does not launder a write, in any flag', () => {
  const dir = workspace();
  for (const c of [
    `${PROD} "select 1" -c "drop table users"`,
    'mysql -h prod-db.acme.com -e "select 1" --init-command="drop table users"',
    'psql -h prod-db.acme.com -c "select 1" -f migrate.sql',
    'psql -h prod-db.acme.com -c "select 1; select 2"',
    'psql -h prod-db.acme.com <<< "select 1"',
  ])
    assert.notEqual(verdict(c, dir), 'ALLOW', c);
});

test('a bound is not an absence: a very long statement is not proved a read', () => {
  const dir = workspace();
  const long = `select ${Array.from({ length: 700 }, (_, n) => `c${n}`).join(', ')} from t`;
  assert.ok(long.length > 4000);
  assert.notEqual(verdict(prod(long), dir), 'ALLOW');
});

test('a comparison inside the statement is not a shell redirection, and a real input redirection still is one', () => {
  const dir = workspace();
  // `>` and `<` in a WHERE clause asked for approval - even against the local socket - because the statement was read as
  // a shell body (the carrier test) and as a program file (the `<` test)
  for (const c of [
    `psql -h localhost -c 'select * from t where a > 1'`,
    `psql -c 'select * from t where a < 1 and b <> 2'`,
    `mysql -e 'select * from t where a >= 1'`,
    `mysql --execute='select * from t where a <= 1'`,
    `psql -h prod-db.acme.com -c 'select 1 < 2'`,
  ])
    assert.equal(verdict(c, dir), 'ALLOW', c);
  // ...and the same `<` as the SHELL reads it hands the client a script nobody has read
  for (const c of [
    'mysql -h prod-db.acme.com < /tmp/payload.sql',
    'mysql -h localhost </tmp/payload',
    "mysql -h prod-db.acme.com -e 'select 1' </tmp/payload",
    "psql -h prod-db.acme.com -c 'select 1' < x.sql",
    // a flag that is not the client's statement flag hides nothing: `mysql -c` is --comments, `redis-cli -e` a boolean
    'mysql -c </tmp/payload',
    'redis-cli -e </tmp/payload',
    // behind a wrapper the redirection belongs to the same segment
    'kubectl --context kind-dev exec pod -- mysql </tmp/payload',
    "bash -c 'mysql -h localhost </tmp/payload'",
  ])
    assert.notEqual(verdict(c, dir), 'ALLOW', c);
});

test('a grammar word followed by a parenthesis is the grammar only where it can be: elsewhere it is a call', () => {
  const dir = workspace();
  // PostgreSQL accepts `by`, `over` and `join` as function names (an independent attack on the grammar, 2026-10-01), so a
  // lexical "this word may precede a parenthesis" let a call named like one of them through
  for (const q of [
    'select join(1, 2)',
    'select filter(1)',
    'select group(1)',
    'select over(1, 2)',
    'select by(1, 2)',
    'select a, join(1) from t',
    'select f(x), over(1) from t',
    'select any(1)',
    'select all(1)',
    'select some(1)',
    'select a from t where join(1)',
    'select a from t where a = by(1)',
    'select a from t order by over(1)',
  ])
    assert.notEqual(verdict(prod(q), dir), 'ALLOW', q);
  // ...and in their own position they are the grammar, as ordinary reports are written
  for (const q of [
    'select a, sum(b) over (partition by a order by c) from t',
    'select a from t group by (a)',
    'select a from t order by (a, b)',
    'select a from t o join (select id from u) x on x.id = o.id',
    'select a from t left join (select id from u) x on x.id = t.id',
    'select a from t cross join (select 1) x',
    'select a from t where b = any (select id from u)',
    'select a from t where b > all (select id from u)',
    'select a from t where b in (1, 2, 3) and c not in (select id from u)',
    'select a from t where exists (select 1 from u where u.t = t.id)',
    'select a from t union (select b from u)',
    'select count(*) filter (where b > 1) from t',
    'select percentile_cont(0.5) within group (order by b) from t',
    'select a from t where b between (1) and (2)',
  ])
    assert.equal(verdict(prod(q), dir), 'ALLOW', q);
});

test('the ordinary reads an engineer types are reads, in PostgreSQL and in MySQL', () => {
  const dir = workspace();
  for (const q of [
    'select lag(amount) over (partition by customer_id order by created_at) from orders',
    'select json_agg(id) from t',
    'select jsonb_build_object(1, 2)',
    "select split_part(email, '@', 2) from users",
    "select regexp_replace(email, '@.*', '') from users",
    'select format(total, 2) from orders',
    'select age(created_at) from users',
    'select stddev(total), percentile_cont(0.5) within group (order by total) from orders',
    'select pg_size_pretty(pg_database_size(current_database()))',
    "select current_setting('server_version')",
    'select * from generate_series(1, 10)',
    "select if(total > 100, 1, 0), ifnull(nickname, name) from orders",
    'select date_add(created_at, interval 1 day), datediff(now(), created_at) from orders',
    'select user_id, group_concat(id) from orders group by user_id',
    "select json_extract(data, '$.name') from profiles",
    'select convert(total, decimal(10,2)) from orders',
    'select unix_timestamp(created_at) from orders',
  ])
    assert.equal(verdict(`mysql -h prod-db.acme.com -e ${word(q)}`, dir), 'ALLOW', q);
});

test('a name that acts is not on the list - in any engine the evaluator routes through the same exception', () => {
  const dir = workspace();
  for (const f of [
    'pg_terminate_backend', 'pg_cancel_backend', 'pg_reload_conf', 'pg_rotate_logfile', 'pg_switch_wal', 'pg_create_restore_point',
    'pg_read_file', 'pg_read_binary_file', 'pg_ls_dir', 'pg_stat_file', 'pg_advisory_lock', 'pg_advisory_xact_lock',
    'pg_try_advisory_lock', 'pg_sleep', 'pg_sleep_for', 'pg_notify', 'pg_logical_emit_message', 'pg_replication_slot_advance',
    'nextval', 'setval', 'lastval', 'currval', 'set_config', 'lo_import', 'lo_export', 'lo_unlink', 'lo_create', 'lowrite',
    'dblink', 'dblink_exec', 'dblink_connect', 'query_to_xml', 'table_to_xml', 'xpath', 'txid_current', 'pg_backend_pid',
    'load_file', 'sleep', 'benchmark', 'get_lock', 'release_lock', 'master_pos_wait', 'source_pos_wait', 'sys_exec', 'sys_eval',
    'openrowset', 'opendatasource', 'xp_cmdshell', 'url', 'file', 'remote', 's3', 'hdfs', 'executable', 'mysql', 'postgresql',
    'readfile', 'writefile', 'edit', 'load_extension', 'fileio_read', 'zipfile', 'sqlar_compress',
  ])
    assert.notEqual(verdict(prod(`select ${f}(1)`), dir), 'ALLOW', f);
});
