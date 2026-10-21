// THE COMMAND LINE OF EACH DATABASE CLIENT, ONCE.
//
// A database command is read for four questions: which statements will the client run, what else does it do besides talk to its
// database (a program, a script, a file), which files does it write, and WHERE does it connect. Each used to have a scan of its
// own over the same words, and the scans disagreed about what an option is: the statement reader knew that psql takes
// `--comm='drop table t'` for `--command`, and the target reader did not know that `--ho=prod-db.acme.com` is `--host` - the
// production host was the local socket (wave-5 review, RV-DB-1). The same scan took the value of `-u john.doe` for a host
// (RV-DB-3), because nothing told it which words are an option's value.
//
// So the options of a client are data, in ONE table per client (below), and ONE parser (`parseDbArgs`) reads a command line by it:
// the client's long options with their arity, any unambiguous prefix of them where the client accepts one, a value glued with `=` or
// following, a cluster of short letters, the same option twice. Every question is asked of what that parser returns.
// `readDbTarget` answers the fourth from the table's roles: which options name the server, which may hold a whole connection
// string, which name a profile, and what each operand of the client is.

/** a word of the command line as the shell will deliver it, and whether the shell fills something into it */
export interface DbWord {
  text: string;
  quoted: boolean;
  expands: boolean;
}

/** What an operand is, by the grammar of the client that reads it. A database, a user, a table, a file, a command or a port is a
 *  `name` and never a server; a `connection` is a database name that is a whole connection string when it is written like one
 *  (libpq: `postgres://…`, `host=… dbname=…`) and is never a bare host; an `address` (mongosh, clickhouse-client) is a server when it
 *  is written like one - `host:port`, `host/db`, a dotted name, a URI - and a database name otherwise; a `host` always is one. */
export type DbOperand = 'name' | 'connection' | 'address' | 'host';

/** The options of one client, in the grammar its parser really has. */
export interface DbOptionSpec {
  /** long options that take a value */
  value: readonly string[];
  /** long options that take none */
  flag: readonly string[];
  /** short letters that take a value (glued or as the next word) */
  shortValue: string;
  /** short letters that take none */
  shortFlag: string;
  /** short letters whose value may only be GLUED (`mysql -psecret`); alone, the letter takes nothing */
  shortGlued?: string;
  /** Go/sqlite style: `-name` is the long option `name` */
  singleDash?: boolean;
  /** GNU style: any unambiguous prefix of a long option is that option */
  abbreviate?: boolean;
  /** a short letter's long name, so one name is judged however it was spelled */
  alias?: Readonly<Record<string, string>>;
  /** the first word that is not an option ends them (redis-cli: the rest is the command) */
  stopAtPositional?: boolean;
  /** MySQL accepts `--skip_column_names` for `--skip-column-names`: an underscore is a dash */
  underscoreIsDash?: boolean;
  /** long options KNOWN to run a program, load a library or read a script of the client's own: they resolve like the rest
   *  (an abbreviation is the option it abbreviates) but are never ordinary. One that is also in `value` takes the next word. */
  escaping?: readonly string[];
  /** what the words that are no option and no option's value are, in order; the last role goes on for the words after it */
  operands: readonly DbOperand[];
  /** the options (by the name they resolve to) whose value NAMES THE SERVER: a host, a list of hosts, `host:port` */
  host?: readonly string[];
  /** the options whose value may be a whole CONNECTION STRING (a URI, `host=… dbname=…`) where a database name is expected: a value
   *  the shell fills in there is a target nobody can read */
  connection?: readonly string[];
  /** the options whose value is an ADDRESS - a server when it is written like one (`user@host:port/db`, `host:port`, a dotted name) */
  address?: readonly string[];
  /** the options that name a connection PROFILE, resolved through a file of the client's own that this kernel never reads */
  profile?: readonly string[];
  /** the option that names the file the client WRITES its output to (a dump tool's `-f`): the path rules judge it */
  output?: string;
}
export interface DbOption {
  name: string;
  value: DbWord | null;
  /** the first and the last of the words the option took (indices into the words it was read from): the option itself, and its
   *  value when that was the next word - so a caller can take exactly those words out of the line */
  at: number;
  to: number;
}
export interface DbArgs {
  options: DbOption[];
  /** the options of `spec.escaping` that were given, by their full names */
  escaping: string[];
  positional: DbWord[];
  /** the words that are not an option this client has */
  unknown: string[];
}

export function parseDbArgs(args: readonly DbWord[], spec: DbOptionSpec): DbArgs {
  const out: DbArgs = { options: [], escaping: [], positional: [], unknown: [] };
  const longs = [...spec.value, ...spec.flag, ...(spec.escaping ?? [])];
  const takesValue = new Set(spec.value);
  // The options a written name may be. An EXACT name is never ambiguous (`--execute` is not short for `--execute-file`); an
  // abbreviation that two options share is refused by the client - and read here as EVERY one of them, because the reading that
  // lets a statement or a script through is the one a reader that refuses it too misses (`psql --fi=x.sql` is a file as much as
  // it is a field separator): whatever it is, each candidate that carries something to run is judged as given.
  const resolve = (name: string): string[] => {
    if (longs.includes(name)) return [name];
    if (!spec.abbreviate) return [];
    return longs.filter((l) => l.startsWith(name));
  };
  const synthetic = (text: string): DbWord => ({ text, quoted: true, expands: false });
  for (let i = 0; i < args.length; i++) {
    const w = args[i]!;
    const t = w.text;
    const at = i;
    if (t === '--') {
      out.positional.push(...args.slice(i + 1));
      break;
    }
    if (!t.startsWith('-') || t === '-') {
      out.positional.push(w);
      if (spec.stopAtPositional) {
        out.positional.push(...args.slice(i + 1));
        break;
      }
      continue;
    }
    const whole = t.replace(/^--?/, '');
    const eq = whole.indexOf('=');
    const rawName = eq < 0 ? whole : whole.slice(0, eq);
    const bare = spec.underscoreIsDash === true ? rawName.replace(/_/g, '-') : rawName;
    const glued = eq < 0 ? null : whole.slice(eq + 1);
    // `--name` and, for Go-style parsers, `-name`
    const asLong = t.startsWith('--') || spec.singleDash === true ? resolve(bare) : [];
    if (asLong.length > 0 && (t.startsWith('--') || bare.length > 1)) {
      // the word takes a value when ANY candidate does; each candidate that takes one is given it, one that does not is given none
      const valued = asLong.some((n) => takesValue.has(n));
      let value: DbWord | null = null;
      if (valued) {
        if (glued !== null) value = { text: glued, quoted: w.quoted, expands: w.expands };
        else if (args[i + 1] !== undefined) value = args[++i]!;
      }
      for (const name of asLong) {
        if (spec.escaping?.includes(name)) out.escaping.push(name);
        else if (takesValue.has(name)) out.options.push({ name, value, at, to: i });
        else out.options.push({ name, value: glued === null ? null : synthetic(glued), at, to: i });
      }
      continue;
    }
    if (t.startsWith('--')) {
      out.unknown.push(t);
      continue;
    }
    // a cluster of short letters, the first valued one taking the rest of the word (or the next word)
    let consumed = false;
    const first = out.options.length;
    for (let k = 1; k < t.length && !consumed; k++) {
      const c = t[k]!;
      const name = spec.alias?.[c] ?? c;
      if (spec.shortGlued?.includes(c)) {
        const rest = t.slice(k + 1);
        out.options.push({ name, value: rest === '' ? null : { text: rest, quoted: w.quoted, expands: w.expands }, at, to: i });
        consumed = true;
      } else if (spec.shortValue.includes(c)) {
        const rest = t.slice(k + 1);
        let value: DbWord | null = null;
        if (rest !== '') value = { text: rest.replace(/^=/, ''), quoted: w.quoted, expands: w.expands };
        else if (args[i + 1] !== undefined) value = args[++i]!;
        // (a short letter that runs a program or reads a script of the client's own is reported as that, as the long form is)
        if (spec.escaping?.includes(name)) out.escaping.push(name);
        else out.options.push({ name, value, at, to: i });
        consumed = true;
      } else if (spec.shortFlag.includes(c)) out.options.push({ name, value: null, at, to: i });
      else {
        out.unknown.push(t);
        consumed = true;
      }
    }
    // (an option whose value was the next word spans both words, whichever letter of the cluster took it)
    for (let q = first; q < out.options.length; q++) out.options[q]!.to = i;
  }
  return out;
}

// ---------------------------------------------------------------------------------------------------------------
// THE TABLES. One per client, from the client's own option list (`--help`, and the real binary where there is one).
// ---------------------------------------------------------------------------------------------------------------

export const PSQL_OPTIONS: DbOptionSpec = {
  value: ['command', 'dbname', 'file', 'field-separator', 'host', 'log-file', 'output', 'port', 'pset', 'record-separator', 'set', 'table-attr', 'username', 'variable'],
  flag: [
    'no-align', 'echo-all', 'echo-errors', 'echo-queries', 'echo-hidden', 'quiet', 'single-step', 'single-line', 'tuples-only',
    'expanded', 'html', 'csv', 'list', 'no-password', 'password', 'no-psqlrc', 'no-readline', 'single-transaction', 'version', 'help',
    'field-separator-zero', 'record-separator-zero',
  ],
  shortValue: 'cdfFhLopPRTUv',
  shortFlag: 'aAbeElnqsStVwWxXz01H?',
  abbreviate: true,
  alias: {
    c: 'command', d: 'dbname', f: 'file', F: 'field-separator', h: 'host', L: 'log-file', o: 'output', p: 'port', P: 'pset',
    R: 'record-separator', T: 'table-attr', U: 'username', v: 'variable', l: 'list',
  },
  // the first operand is the database - or a connection string, which psql takes there; the second is the user
  operands: ['connection', 'name'],
  host: ['host'],
  connection: ['dbname'],
};

export const MYSQL_OPTIONS: DbOptionSpec = {
  value: [
    'host', 'user', 'port', 'socket', 'database', 'execute', 'protocol', 'default-character-set', 'character-sets-dir',
    'connect-timeout', 'max-allowed-packet', 'net-buffer-length', 'select-limit', 'max-join-size', 'bind-address', 'prompt',
    'ssl-mode', 'ssl-ca', 'ssl-capath', 'ssl-cert', 'ssl-cipher', 'ssl-key', 'ssl-crl', 'ssl-crlpath', 'tls-version',
    'tls-ciphersuites', 'server-public-key-path', 'histignore', 'login-path', 'compression-algorithms', 'zstd-compression-level',
    // the two that carry something to RUN or to WRITE: a statement before the first one, and a log file
    'init-command', 'tee',
  ],
  flag: [
    'batch', 'skip-column-names', 'column-names', 'raw', 'silent', 'table', 'vertical', 'html', 'xml', 'auto-vertical-output',
    'force', 'verbose', 'quiet', 'compress', 'unbuffered', 'line-numbers', 'skip-line-numbers', 'comments', 'skip-comments',
    'reconnect', 'skip-reconnect', 'named-commands', 'no-auto-rehash', 'auto-rehash', 'binary-mode', 'binary-as-hex',
    'secure-auth', 'show-warnings', 'sigint-ignore', 'no-beep', 'wait', 'one-database', 'safe-updates', 'i-am-a-dummy', 'ssl',
    'skip-ssl', 'ssl-verify-server-cert', 'get-server-public-key', 'enable-cleartext-plugin', 'version', 'help', 'no-defaults',
    'print-defaults', 'connect-expired-password', 'ignore-spaces', 'password',
  ],
  shortValue: 'DehPSu',
  shortFlag: 'AbBcCEfGgHiLnNoqrstTUvVwWXa?I',
  shortGlued: 'p',
  abbreviate: true,
  underscoreIsDash: true,
  escaping: [
    'pager', 'plugin-dir', 'default-auth', 'defaults-file', 'defaults-extra-file', 'defaults-group-suffix', 'local-infile',
    'debug', 'debug-check', 'debug-info', 'delimiter',
  ],
  alias: { D: 'database', e: 'execute', h: 'host', P: 'port', S: 'socket', u: 'user' },
  // the operand is a database (and, for the dump and administration tools that share this table, tables and commands)
  operands: ['name'],
  host: ['host'],
  profile: ['login-path', 'defaults-file', 'defaults-extra-file', 'defaults-group-suffix'],
};

/** MySQL Shell: mysql's connection options, and a first operand that is an address - `mysqlsh user@host:port/schema` or a `mysqlx://` URI -
 *  with the `--uri` option beside it. (It runs scripts of its own, which is why every use of it asks.) */
export const MYSQLSH_OPTIONS: DbOptionSpec = {
  ...MYSQL_OPTIONS,
  value: [...MYSQL_OPTIONS.value, 'uri', 'file', 'js', 'py', 'sql'],
  operands: ['address'],
  address: ['uri'],
};

/** mysqldump: its short letters are not mysql's (`-r` is the result file, `-T` a directory, `-w` a condition, `-e` extended inserts) */
export const MYSQLDUMP_OPTIONS: DbOptionSpec = {
  value: [
    'host', 'user', 'port', 'socket', 'protocol', 'result-file', 'tab', 'where', 'character-sets-dir', 'default-character-set',
    'fields-terminated-by', 'fields-enclosed-by', 'fields-optionally-enclosed-by', 'fields-escaped-by', 'lines-terminated-by',
    'ignore-table', 'ignore-error', 'master-data', 'source-data', 'dump-slave', 'dump-replica', 'max-allowed-packet',
    'net-buffer-length', 'login-path', 'ssl-mode', 'ssl-ca', 'ssl-capath', 'ssl-cert', 'ssl-cipher', 'ssl-key', 'tls-version',
    'compression-algorithms', 'zstd-compression-level', 'init-command', 'set-gtid-purged', 'add-drop-trigger', 'plugin-dir',
    'default-auth', 'defaults-file', 'defaults-extra-file', 'defaults-group-suffix', 'bind-address', 'server-public-key-path',
  ],
  flag: [
    'single-transaction', 'routines', 'triggers', 'events', 'no-data', 'no-create-info', 'no-create-db', 'databases',
    'all-databases', 'add-drop-table', 'add-drop-database', 'add-locks', 'create-options', 'complete-insert', 'extended-insert',
    'hex-blob', 'quick', 'opt', 'skip-opt', 'compact', 'force', 'verbose', 'compress', 'lock-tables', 'lock-all-tables', 'flush-logs',
    'flush-privileges', 'disable-keys', 'insert-ignore', 'replace', 'set-charset', 'skip-set-charset', 'skip-triggers',
    'skip-add-drop-table', 'skip-comments', 'comments', 'dump-date', 'skip-dump-date', 'tz-utc', 'skip-tz-utc', 'order-by-primary',
    'quote-names', 'skip-quote-names', 'column-statistics', 'no-tablespaces', 'tables', 'xml', 'version', 'help', 'ssl', 'skip-ssl',
    'password', 'delete-master-logs', 'apply-slave-statements', 'include-master-host-port', 'all-tablespaces', 'allow-keywords',
    'delayed-insert', 'no-autocommit', 'no-set-names', 'skip-add-locks', 'skip-disable-keys', 'skip-extended-insert',
    'skip-lock-tables', 'skip-quick', 'skip-routines', 'skip-events', 'get-server-public-key', 'enable-cleartext-plugin',
    'no-defaults', 'print-defaults', 'debug', 'debug-check', 'debug-info', 'delete-source-logs', 'apply-replica-statements',
  ],
  shortValue: 'huPSrTw',
  shortFlag: 'AaBcCdEeFfKklNnqQRtvVxXy?I',
  shortGlued: 'p',
  abbreviate: true,
  underscoreIsDash: true,
  alias: { h: 'host', u: 'user', P: 'port', S: 'socket', r: 'result-file', T: 'tab', w: 'where' },
  operands: ['name'],
  host: ['host'],
  profile: ['login-path', 'defaults-file', 'defaults-extra-file', 'defaults-group-suffix'],
  output: 'result-file',
};

export const MONGO_OPTIONS: DbOptionSpec = {
  value: [
    'eval', 'host', 'port', 'username', 'password', 'authenticationDatabase', 'authenticationMechanism', 'apiVersion',
    'tlsCAFile', 'tlsCertificateKeyFile', 'tlsCertificateKeyFilePassword', 'tlsCRLFile', 'tlsDisabledProtocols',
    'tlsCipherSuites', 'sslCAFile', 'sslPEMKeyFile', 'sslPEMKeyPassword', 'sslCRLFile', 'gssapiServiceName', 'gssapiHostName',
  ],
  flag: [
    'quiet', 'nodb', 'norc', 'json', 'tls', 'ssl', 'version', 'help', 'tlsAllowInvalidCertificates', 'tlsAllowInvalidHostnames',
    'tlsUseSystemCA', 'sslAllowInvalidCertificates', 'sslAllowInvalidHostnames', 'retryWrites', 'apiStrict',
    'apiDeprecationErrors', 'disableImplicitSessions', 'verbose',
  ],
  shortValue: 'up',
  shortFlag: 'h',
  alias: { u: 'username', p: 'password' },
  escaping: ['file'],
  // the first operand is the "db address": a database, `host/db`, `host:port/db` or a connection string; the rest are scripts
  operands: ['address', 'name'],
  host: ['host'],
};

// --- MongoDB's database tools (mongodump, mongorestore, mongoexport, mongoimport): Go's go-flags, so an option is its exact name -----
// (from their documentation: there is no binary of them to ask here)
export const MONGO_TOOLS_OPTIONS: DbOptionSpec = {
  value: [
    'host', 'port', 'uri', 'config', 'username', 'password', 'authenticationDatabase', 'authenticationMechanism', 'awsSessionToken',
    'gssapiServiceName', 'gssapiHostName', 'db', 'collection', 'query', 'queryFile', 'readPreference', 'out', 'archive',
    'excludeCollection', 'excludeCollectionsWithPrefix', 'numParallelCollections', 'numInsertionWorkersPerCollection',
    'numInsertionWorkers', 'oplogLimit', 'oplogFile', 'dir', 'writeConcern', 'nsExclude', 'nsInclude', 'nsFrom', 'nsTo', 'fields',
    'fieldFile', 'type', 'jsonFormat', 'skip', 'limit', 'sort', 'file', 'mode', 'upsertFields', 'parseGrace', 'sslCAFile',
    'sslPEMKeyFile', 'sslPEMKeyPassword', 'sslCRLFile', 'tlsCAFile', 'tlsCertificateKeyFile', 'tlsCertificateKeyFilePassword',
    'tlsCRLFile', 'tlsCertificateSelector', 'tlsDisabledProtocols',
  ],
  flag: [
    'help', 'version', 'quiet', 'verbose', 'ssl', 'tls', 'sslAllowInvalidCertificates', 'sslAllowInvalidHostnames', 'sslFIPSMode',
    'tlsInsecure', 'forceTableScan', 'gzip', 'oplog', 'dumpDbUsersAndRoles', 'viewsAsCollections', 'objcheck', 'oplogReplay',
    'restoreDbUsersAndRoles', 'drop', 'dryRun', 'noIndexRestore', 'noOptionsRestore', 'keepIndexVersion', 'maintainInsertionOrder',
    'stopOnError', 'bypassDocumentValidation', 'preserveUUID', 'convertLegacyIndexes', 'fixDottedHashIndex', 'jsonArray', 'pretty',
    'noHeaderLine', 'slaveOk', 'assertExists', 'ignoreBlanks', 'headerline', 'useArrayIndexFields', 'columnsHaveTypes', 'legacy',
  ],
  shortValue: 'hupdcqofj',
  shortFlag: 'v',
  alias: { h: 'host', u: 'username', p: 'password', d: 'db', c: 'collection', q: 'query', o: 'out', f: 'fields', j: 'numParallelCollections' },
  operands: ['name'],
  host: ['host'],
  connection: ['uri'],
  profile: ['config'],
};

// (written from redis-cli 8's own --help. NOT in it on purpose: --cluster, --replica, --lru-test and --vset-recall*, which act on the
// server or the cluster - an option the table does not know is a question, so they stay one)
export const REDIS_OPTIONS: DbOptionSpec = {
  value: [
    'user', 'pass', 'name', 'sni', 'cacert', 'cacertdir', 'cert', 'key', 'tls-ciphers', 'tls-ciphersuites', 'show-pushes',
    'latency-percentiles', 'pattern', 'quoted-pattern', 'count', 'cursor', 'top', 'memkeys-samples', 'keystats-samples',
    'pipe-timeout', 'intrinsic-latency',
    // a dump of the server written to a path: judged as the write it is
    'rdb', 'functions-rdb',
    // the Lua script it sends (and that is what makes it escaping: the file is a program)
    'eval',
  ],
  flag: [
    'tls', 'askpass', 'no-auth-warning', 'insecure', 'raw', 'no-raw', 'quoted-input', 'csv', 'json', 'quoted-json', 'verbose',
    'version', 'help', 'stat', 'latency', 'latency-history', 'latency-dist', 'scan', 'bigkeys', 'memkeys', 'keystats', 'hotkeys',
  ],
  shortValue: 'hptsaurinDdX',
  shortFlag: 'ce23456x?',
  // the first word that is not an option is the command, and everything after it belongs to the command
  stopAtPositional: true,
  escaping: ['pipe', 'eval', 'ldb', 'ldb-sync-mode'],
  // (a short letter is its own name here: `-h` is the host, `-u` the URI)
  operands: ['name'],
  host: ['h'],
  connection: ['u'],
};

export const CQLSH_OPTIONS: DbOptionSpec = {
  value: [
    'execute', 'file', 'keyspace', 'username', 'password', 'cqlshrc', 'credentials', 'browser', 'encoding', 'connect-timeout',
    'request-timeout', 'protocol-version', 'cqlversion', 'secure-connect-bundle', 'consistency-level', 'serial-consistency-level',
  ],
  flag: ['color', 'no-color', 'ssl', 'tty', 'debug', 'coverage', 'no-file-io', 'disable-history', 'version', 'help'],
  shortValue: 'efukbp',
  shortFlag: 'Ctvh',
  abbreviate: true,
  alias: { e: 'execute', f: 'file', u: 'username', p: 'password', k: 'keyspace', b: 'secure-connect-bundle' },
  // `cqlsh [options] [host [port]]`
  operands: ['host', 'name'],
  profile: ['cqlshrc'],
};

export const INFLUX_OPTIONS: DbOptionSpec = {
  value: ['execute', 'import', 'path', 'host', 'port', 'username', 'password', 'database', 'format', 'precision', 'pps', 'type'],
  flag: ['ssl', 'unsafeSsl', 'compressed', 'pretty', 'version', 'help'],
  shortValue: '',
  shortFlag: '',
  singleDash: true,
  operands: ['name'],
  host: ['host'],
};

/** What clickhouse-client takes as an option is boost::program_options': any unambiguous prefix of a long name, `-` or `_` between
 *  its words, and every server setting besides (`--max_threads 4`), which this table cannot list - such a word is simply not one
 *  of these options, and its value is an operand like any other. */
export const CLICKHOUSE_OPTIONS: DbOptionSpec = {
  value: [
    'query', 'host', 'port', 'user', 'database', 'format', 'connection', 'query-id', 'quota-key', 'stage', 'log-level',
    'compression', 'ssh-key-passphrase', 'jwt', 'interleave-queries-file',
    // the ones that name a program, a script, a configuration or a file: asked about, never ordinary
    'config-file', 'queries-file', 'query-file', 'history-file', 'pager', 'server-logs-file', 'external', 'log-file',
    'log-level-file', 'client-logs-file', 'ssh-key-file',
  ],
  // (`--password` takes its value glued only: `--password secret` leaves `secret` as an operand)
  flag: [
    'password', 'multiquery', 'multiline', 'time', 'vertical', 'secure', 'ask-password', 'progress', 'echo', 'verbose', 'version',
    'help', 'highlight', 'no-warnings', 'fake-drop', 'testmode', 'disable-suggestion', 'accept-invalid-certificate',
    'hardware-utilization', 'print-profile-events', 'processed-rows', 'stacktrace', 'memory-usage', 'login',
  ],
  shortValue: 'qhudfC',
  shortFlag: 'ntvVEmMsAT?',
  abbreviate: true,
  underscoreIsDash: true,
  alias: { q: 'query', h: 'host', u: 'user', d: 'database', f: 'format', C: 'config-file' },
  escaping: ['config-file', 'queries-file', 'query-file', 'history-file', 'pager', 'server-logs-file', 'external', 'log-file', 'log-level-file', 'client-logs-file', 'ssh-key-file'],
  // `clickhouse-client [options] [connection string]`
  operands: ['address', 'name'],
  host: ['host'],
  profile: ['connection'],
};

// --- PostgreSQL's own tools: getopt_long, so any unambiguous prefix of a long option is that option -------------------
// (the lists are the real binaries' `--help`, PostgreSQL 17; a tool that lacks an option the table has loses nothing, and one the
// table lacks has its word read as an unknown option)

const PG_CONNECTION_VALUE = ['host', 'port', 'username'];
const PG_CONNECTION_FLAG = ['no-password', 'password', 'help', 'version'];

export const PG_DUMP_OPTIONS: DbOptionSpec = {
  value: [
    'file', 'format', 'jobs', 'compress', 'lock-wait-timeout', 'sync-method', 'extension', 'encoding', 'schema', 'exclude-schema',
    'superuser', 'table', 'exclude-table', 'exclude-extension', 'exclude-table-and-children', 'exclude-table-data',
    'exclude-table-data-and-children', 'extra-float-digits', 'filter', 'include-foreign-data', 'restrict-key', 'rows-per-insert',
    'section', 'snapshot', 'table-and-children', 'dbname', 'role', ...PG_CONNECTION_VALUE,
  ],
  flag: [
    'verbose', 'no-sync', 'data-only', 'large-objects', 'blobs', 'no-large-objects', 'no-blobs', 'clean', 'create', 'no-owner',
    'schema-only', 'no-privileges', 'no-acl', 'binary-upgrade', 'column-inserts', 'attribute-inserts', 'disable-dollar-quoting',
    'disable-triggers', 'enable-row-security', 'if-exists', 'inserts', 'load-via-partition-root', 'no-comments', 'no-publications',
    'no-security-labels', 'no-subscriptions', 'no-table-access-method', 'no-tablespaces', 'no-toast-compression',
    'no-unlogged-table-data', 'on-conflict-do-nothing', 'quote-all-identifiers', 'serializable-deferrable', 'strict-names',
    'use-set-session-authorization', ...PG_CONNECTION_FLAG,
  ],
  shortValue: 'fFjZeEnNStTdhpU',
  shortFlag: 'vVabBcCOsxwW?',
  abbreviate: true,
  alias: { f: 'file', h: 'host', p: 'port', U: 'username', d: 'dbname' },
  operands: ['connection'],
  host: ['host'],
  connection: ['dbname'],
  output: 'file',
};

export const PG_RESTORE_OPTIONS: DbOptionSpec = {
  value: [
    'dbname', 'file', 'format', 'index', 'jobs', 'use-list', 'schema', 'exclude-schema', 'function', 'superuser', 'table',
    'trigger', 'transaction-size', 'filter', 'section', 'restrict-key', 'role', ...PG_CONNECTION_VALUE,
  ],
  flag: [
    'list', 'verbose', 'data-only', 'clean', 'create', 'exit-on-error', 'no-owner', 'schema-only', 'no-privileges', 'no-acl',
    'single-transaction', 'disable-triggers', 'enable-row-security', 'if-exists', 'no-comments', 'no-data-for-failed-tables',
    'no-publications', 'no-security-labels', 'no-subscriptions', 'no-table-access-method', 'no-tablespaces', 'strict-names',
    'use-set-session-authorization', ...PG_CONNECTION_FLAG,
  ],
  shortValue: 'dfFIjLnNPStThpU',
  shortFlag: 'lvVacCeOsx1wW?',
  abbreviate: true,
  alias: { f: 'file', h: 'host', p: 'port', U: 'username', d: 'dbname' },
  // the operand is the ARCHIVE to restore; the database is `-d`
  operands: ['name'],
  host: ['host'],
  connection: ['dbname'],
  output: 'file',
};

export const PG_DUMPALL_OPTIONS: DbOptionSpec = {
  value: [
    'file', 'lock-wait-timeout', 'encoding', 'superuser', 'exclude-database', 'extra-float-digits', 'filter', 'restrict-key',
    'rows-per-insert', 'dbname', 'database', 'role', ...PG_CONNECTION_VALUE,
  ],
  flag: [
    'verbose', 'data-only', 'clean', 'globals-only', 'no-owner', 'roles-only', 'schema-only', 'tablespaces-only', 'no-privileges',
    'no-acl', 'binary-upgrade', 'column-inserts', 'attribute-inserts', 'disable-dollar-quoting', 'disable-triggers', 'if-exists',
    'inserts', 'load-via-partition-root', 'no-comments', 'no-publications', 'no-role-passwords', 'no-security-labels',
    'no-subscriptions', 'no-sync', 'no-table-access-method', 'no-tablespaces', 'no-toast-compression', 'no-unlogged-table-data',
    'on-conflict-do-nothing', 'quote-all-identifiers', 'use-set-session-authorization', ...PG_CONNECTION_FLAG,
  ],
  shortValue: 'fESdhlpU',
  shortFlag: 'vVacgOrstx?wW',
  abbreviate: true,
  alias: { f: 'file', h: 'host', p: 'port', U: 'username', d: 'dbname', l: 'database' },
  operands: ['name'],
  host: ['host'],
  connection: ['dbname'],
  output: 'file',
};

export const PGBENCH_OPTIONS: DbOptionSpec = {
  value: [
    'init-steps', 'fillfactor', 'scale', 'index-tablespace', 'partition-method', 'partitions', 'tablespace', 'builtin', 'file',
    'client', 'define', 'jobs', 'latency-limit', 'protocol', 'progress', 'rate', 'transactions', 'time', 'aggregate-interval',
    'log-prefix', 'max-tries', 'random-seed', 'sampling-rate', 'show-script', 'dbname', ...PG_CONNECTION_VALUE,
  ],
  flag: [
    'initialize', 'no-vacuum', 'quiet', 'foreign-keys', 'unlogged-tables', 'skip-some-updates', 'select-only', 'connect', 'log',
    'report-per-command', 'vacuum-all', 'exit-on-abort', 'failures-detailed', 'progress-timestamp', 'verbose-errors', 'debug',
    'help', 'version',
  ],
  shortValue: 'IFsbfcDjLMPRtTdhpU',
  shortFlag: 'nNSClrviqV?',
  abbreviate: true,
  alias: { h: 'host', p: 'port', U: 'username', d: 'dbname' },
  operands: ['connection'],
  host: ['host'],
  connection: ['dbname'],
};

const PG_ADMIN = (extraValue: readonly string[], extraFlag: readonly string[], shortValue: string, shortFlag: string): DbOptionSpec => ({
  value: [...extraValue, ...PG_CONNECTION_VALUE, 'maintenance-db'],
  flag: [...extraFlag, ...PG_CONNECTION_FLAG],
  shortValue: shortValue + 'hpU',
  shortFlag: shortFlag + 'wW?V',
  abbreviate: true,
  alias: { h: 'host', p: 'port', U: 'username' },
  operands: ['name'],
  host: ['host'],
  connection: ['maintenance-db'],
});
export const CREATEDB_OPTIONS = PG_ADMIN(
  ['tablespace', 'encoding', 'locale', 'lc-collate', 'lc-ctype', 'builtin-locale', 'icu-locale', 'icu-rules', 'locale-provider', 'owner', 'strategy', 'template'],
  ['echo'],
  'DElOST',
  'e',
);
export const DROPDB_OPTIONS = PG_ADMIN([], ['echo', 'force', 'interactive', 'if-exists'], '', 'efi');
export const CREATEUSER_OPTIONS = PG_ADMIN(
  ['with-admin', 'connection-limit', 'member-of', 'role', 'with-member', 'valid-until'],
  ['createdb', 'no-createdb', 'echo', 'inherit', 'no-inherit', 'login', 'no-login', 'pwprompt', 'createrole', 'no-createrole', 'superuser', 'no-superuser', 'interactive', 'bypassrls', 'no-bypassrls', 'replication', 'no-replication'],
  'acgmv',
  'dDeiIlLPrRsS',
);
export const DROPUSER_OPTIONS = PG_ADMIN([], ['echo', 'interactive', 'if-exists'], '', 'ei');

// --- sqlite3: no server, a FILE - so its table is not in DB_GRAMMAR below, and the path rules govern the file. Go-style: `-name`, and `--name` is the same ---
export const SQLITE_OPTIONS: DbOptionSpec = {
  value: ['cmd', 'init', 'newline', 'separator', 'nullvalue', 'vfs', 'escape', 'hexkey', 'key', 'textkey', 'maxsize', 'nonce', 'screen-width'],
  flag: [
    'append', 'ascii', 'bail', 'batch', 'box', 'column', 'csv', 'deserialize', 'echo', 'header', 'noheader', 'html', 'interactive',
    'json', 'line', 'list', 'markdown', 'quote', 'readonly', 'safe', 'stats', 'table', 'tabs', 'version', 'help', 'zip', 'nofollow',
    'memtrace', 'pcachetrace', 'vfstrace', 'no-rowid-in-view', 'errorstop',
  ],
  shortValue: '',
  shortFlag: '',
  singleDash: true,
  // (the first operand is the database FILE and the rest are statements: no operand is a server)
  operands: ['name'],
};

/** THE CLIENT → ITS TABLE. A head that is not here has no grammar of its own in this kernel (the migration runners take their target
 *  from a file or a URL option, and have their own readers); `sqlite3` opens a FILE, which the path rules govern. */
export const DB_GRAMMAR: Readonly<Record<string, DbOptionSpec>> = {
  psql: PSQL_OPTIONS,
  mysql: MYSQL_OPTIONS,
  mariadb: MYSQL_OPTIONS,
  mysqladmin: MYSQL_OPTIONS,
  mysqlsh: MYSQLSH_OPTIONS,
  mysqlpump: MYSQL_OPTIONS,
  mysqldump: MYSQLDUMP_OPTIONS,
  mongosh: MONGO_OPTIONS,
  mongo: MONGO_OPTIONS,
  mongodump: MONGO_TOOLS_OPTIONS,
  mongorestore: MONGO_TOOLS_OPTIONS,
  mongoexport: MONGO_TOOLS_OPTIONS,
  mongoimport: MONGO_TOOLS_OPTIONS,
  'redis-cli': REDIS_OPTIONS,
  'valkey-cli': REDIS_OPTIONS,
  'clickhouse-client': CLICKHOUSE_OPTIONS,
  cqlsh: CQLSH_OPTIONS,
  influx: INFLUX_OPTIONS,
  pg_dump: PG_DUMP_OPTIONS,
  pg_restore: PG_RESTORE_OPTIONS,
  pg_dumpall: PG_DUMPALL_OPTIONS,
  pgbench: PGBENCH_OPTIONS,
  createdb: CREATEDB_OPTIONS,
  dropdb: DROPDB_OPTIONS,
  createuser: CREATEUSER_OPTIONS,
  dropuser: DROPUSER_OPTIONS,
};

// ---------------------------------------------------------------------------------------------------------------
// WHERE THE CLIENT CONNECTS, read from the parsed line.
// ---------------------------------------------------------------------------------------------------------------

export interface DbTargetReading {
  /** the servers named by a host option, in every spelling the client accepts (the client uses the last one; every one is judged) */
  hosts: string[];
  /** the values of the options that may hold a whole connection string */
  connections: DbWord[];
  /** the operands that are a server by the client's grammar, always (cqlsh's host) */
  hostOperands: DbWord[];
  /** the first operand and what the client reads it as */
  first: { word: DbWord; role: DbOperand } | null;
  /** the operands that are an address: a server when they are written like one */
  addresses: DbWord[];
  /** the values of the options that are an address: the same, wherever on the line they stand */
  addressValues: DbWord[];
  /** whether an option that names a connection profile was given */
  profile: boolean;
  /** the words this client's table does not know: a text net reads them for what a table cannot place */
  unknown: string[];
}

/** The server names a host option's value holds: libpq takes a list (`a,b`), mongosh takes `host:port` (and a list of them), and a
 *  bracketed address is an IPv6 literal. A URL is read whole, like every other URL on the line. */
export function hostNames(value: string): string[] {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) return [value];
  const names: string[] = [];
  for (const part of value.split(',')) {
    const p = part.trim();
    if (p === '') continue;
    const bracketed = /^\[([^\]]*)\](?::\d+)?$/.exec(p);
    // (more than one colon is an IPv6 literal with no brackets: `::1` is a host, not a host with a port)
    const withPort = /^([^:]+):\d+$/.exec(p);
    names.push(bracketed ? bracketed[1]! : withPort ? withPort[1]! : p);
  }
  return names.length > 0 ? names : [value];
}

/** A word that is a SCRIPT handed to the client as one word - standard input that was carried onto the command line, or a statement given
 *  as an operand - and not an operand: it has a line break, a semicolon, a backslash or a parenthesis, or several words that are not a
 *  connection string. A URI and a `key=value` connection string are operands, whatever they hold. */
export function isScriptWord(text: string): boolean {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) return false;
  if (DB_CONNINFO.test(text)) return false;
  return /[\s;\\()]/.test(text);
}

/** A libpq `key=value key='quoted value'` connection string, with blanks allowed around the `=`. The segments are separated by blanks and
 *  a value ends at a blank or is quoted, so there is exactly one way to read a string and the test takes linear time on any input (the
 *  form `(\w+=\S+\s*)+` it replaces took exponential time on `a=a=a=…=a b`). */
export const DB_CONNINFO = /^\s*\w+\s*=\s*(?:'[^']*'|[^\s']+)(?:\s+\w+\s*=\s*(?:'[^']*'|[^\s']+))*\s*$/;

export function readDbTarget(spec: DbOptionSpec, parsed: DbArgs): DbTargetReading {
  const hosts: string[] = [];
  const connections: DbWord[] = [];
  const addressValues: DbWord[] = [];
  for (const o of parsed.options) {
    if (o.value === null) continue;
    if (spec.host?.includes(o.name)) hosts.push(o.value.text);
    if (spec.connection?.includes(o.name)) connections.push(o.value);
    if (spec.address?.includes(o.name)) addressValues.push(o.value);
  }
  const role = (i: number): DbOperand => spec.operands[Math.min(i, spec.operands.length - 1)] ?? 'name';
  const hostOperands: DbWord[] = [];
  const addresses: DbWord[] = [];
  // (a word that is a script handed over as one word is the statement the client reads, not an operand)
  const operands = parsed.positional.filter((w) => !isScriptWord(w.text));
  operands.forEach((w, i) => {
    if (role(i) === 'host') hostOperands.push(w);
    else if (role(i) === 'address') addresses.push(w);
  });
  const first = operands[0];
  const profile =
    (spec.profile ?? []).some((p) => parsed.escaping.includes(p) || parsed.options.some((o) => o.name === p));
  return {
    hosts,
    connections,
    hostOperands,
    first: first === undefined ? null : { word: first, role: role(0) },
    addresses,
    addressValues,
    profile,
    unknown: parsed.unknown,
  };
}
