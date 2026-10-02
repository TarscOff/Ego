// THE REAL psql, WHERE IT CAN BE HAD, AS THE ORACLE FOR WHAT THE CLIENT'S LEXER DOES.
//
// The scanner in `src/authority/sql-lex.ts` is a copy of one half of psql: the half that finds the backslash commands psql
// runs. A copy is checked against the original, so the differential tests here run a script through the real client and ask
// whether the program in its `\o |touch MARK` line ran. The oracle needs a server (psql does not read a script without one):
// a throwaway PostgreSQL in a container with no network, made from an image that is ALREADY on this machine - nothing is
// pulled, so with no docker, no daemon or no postgres image the oracle is simply absent and the tests that need it skip.
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export interface PsqlOracle {
  /** the client's version line, so a failure says which psql disagreed */
  readonly version: string;
  /** for each script (and the options psql is given with it), whether psql RAN the program its `\o |touch @MARK@` line names (the
   *  marker is a file in the container) */
  runs(scripts: ReadonlyArray<string | { script: string; args: readonly string[] }>): boolean[];
  stop(): void;
}

const docker = (args: string[], input?: string): { ok: boolean; out: string } => {
  const r = spawnSync('docker', args, { encoding: 'utf8', timeout: 120_000, input });
  return { ok: r.status === 0, out: `${r.stdout ?? ''}` };
};

export function startPsqlOracle(): PsqlOracle | null {
  if (process.env.EGO_NO_DOCKER_TESTS) return null;
  if (!docker(['info', '--format', '{{.ServerVersion}}']).ok) return null;
  const images = docker(['image', 'ls', '--format', '{{.Repository}}:{{.Tag}}']).out.split('\n');
  const image = ['17', '16', '15', '18']
    .map((v) => images.find((i) => new RegExp(`^postgres:${v}(\\.\\d+)?(-alpine)?$`).test(i)))
    .find(Boolean);
  if (image === undefined) return null;
  const name = `ego-psql-oracle-${process.pid}-${Date.now() % 100000}`;
  // --network none: the server answers on its own socket and can reach nothing; --rm: the container is gone when it stops
  if (
    !docker([
      'run',
      '-d',
      '--rm',
      '--name',
      name,
      '--network',
      'none',
      '-e',
      'POSTGRES_HOST_AUTH_METHOD=trust',
      image,
    ]).ok
  )
    return null;
  const stop = (): void => void spawnSync('docker', ['rm', '-f', name], { stdio: 'ignore' });
  process.once('exit', stop);
  let ready = false;
  for (let i = 0; i < 80 && !ready; i++) {
    ready = docker(['exec', name, 'pg_isready', '-U', 'postgres']).ok;
    // (the image restarts the server once after initialising: ready twice in a row is ready)
    if (ready) {
      spawnSync('sleep', ['1']);
      ready = docker(['exec', name, 'pg_isready', '-U', 'postgres']).ok;
    } else spawnSync('sleep', ['0.5']);
  }
  if (!ready) {
    stop();
    return null;
  }
  const version = docker(['exec', name, 'psql', '--version']).out.trim();
  return {
    version,
    runs(scripts) {
      if (scripts.length === 0) return [];
      const dir = mkdtempSync(join(tmpdir(), 'ego-psql-oracle-'));
      try {
        const quote = (w: string): string => `'${w.replaceAll("'", "'\\''")}'`;
        const lines: string[] = [];
        scripts.forEach((c, i) => {
          const { script, args } = typeof c === 'string' ? { script: c, args: [] as readonly string[] } : c;
          writeFileSync(join(dir, `s_${i}.sql`), script.replaceAll('@MARK@', `/tmp/mk_${i}`));
          // each script is its own psql, read from a file with no terminal: its lexer is the one that reads standard input
          lines.push(
            `timeout 20 psql -U postgres -X -q ${args.map((a) => quote(a.replaceAll('@MARK@', `/tmp/mk_${i}`))).join(' ')} -f /tmp/fz/s_${i}.sql </dev/null >/dev/null 2>&1`,
          );
        });
        writeFileSync(join(dir, 'run.sh'), lines.join('\n') + '\n');
        docker(['exec', name, 'sh', '-c', 'rm -rf /tmp/fz /tmp/mk_*; mkdir -p /tmp/fz']);
        execFileSync('docker', ['cp', `${dir}/.`, `${name}:/tmp/fz`]);
        docker(['exec', name, 'sh', '/tmp/fz/run.sh']);
        const ran = new Set(
          docker(['exec', name, 'sh', '-c', 'ls /tmp | grep ^mk_ || true'])
            .out.split('\n')
            .filter(Boolean)
            .map((l) => Number(l.replace('mk_', ''))),
        );
        return scripts.map((_, i) => ran.has(i));
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    },
    stop,
  };
}

/** A script and what the REAL psql (15, 16 and 17 agree on every one) does with its `\o |touch @MARK@` line: `runs` when the line
 *  is outside every string and so a command, `hides` when a string or a dollar-quoted body swallows it. Each is a seam between
 *  two lexers that read a character differently - the cases the scanner's rules were written from. */
export const PSQL_LEXICAL_CASES: ReadonlyArray<{ runs: boolean; script: string; why: string }> = [
  // a `$` continues a name (RV-DB-2): nothing inside `a$$$` opens a quote, and an `e` that ends a name makes no escape string
  { runs: true, script: 'select 1 as a$$$\n\\o |touch @MARK@\n', why: 'a$$$ is one name' },
  {
    runs: true,
    script: "select a$e'\\'\n\\o |touch @MARK@\n",
    why: 'a$e is one name, so the quote is a plain string and the backslash is a character',
  },
  { runs: true, script: "select a$E'\\'\n\\o |touch @MARK@\n", why: 'the same, upper case' },
  { runs: true, script: "select _e'\\'\n\\o |touch @MARK@\n", why: '_e is one name' },
  { runs: true, script: "select ée'\\'\n\\o |touch @MARK@\n", why: 'a non-ASCII letter continues a name' },
  {
    runs: false,
    script: "select a$$ ' $$\n\\o |touch @MARK@\n'\n",
    why: 'a$$ is a name, the quote after it opens a string',
  },
  {
    runs: false,
    script: "select e'\\'\n\\o |touch @MARK@\n'\n",
    why: 'a lone e makes an escape string: the backslash escapes the quote',
  },
  { runs: false, script: "select E'\\'\n\\o |touch @MARK@\n'\n", why: 'a lone E, the same' },
  {
    runs: false,
    script: "select x.e'\\'\n\\o |touch @MARK@\n'\n",
    why: 'a dot ends the name, so the e is alone',
  },
  { runs: false, script: "select 'a'e'\\'\n\\o |touch @MARK@\n'\n", why: 'a string ends before the e' },
  { runs: false, script: "select (e'\\'\n\\o |touch @MARK@\n'\n", why: 'a bracket ends before the e' },
  {
    runs: false,
    script: "select e'a\\'b\n\\o |touch @MARK@\n'\n",
    why: 'the escaped quote stays inside the string',
  },
  // a dollar quote starts where a TOKEN starts (psql reads the lexer's own rules: a name takes its `$`s with it)
  { runs: true, script: "select $é$ ' $é$\n\\o |touch @MARK@\n", why: 'a tag may hold a non-ASCII letter' },
  {
    runs: true,
    script: "select $1$a$ ' $a$\n\\o |touch @MARK@\n",
    why: '$1 is a parameter, then a dollar quote',
  },
  { runs: true, script: "select $1$$ ' $$\n\\o |touch @MARK@\n", why: 'a parameter and then $$' },
  {
    runs: true,
    script: "select $x $a$ ' $a$\n\\o |touch @MARK@\n",
    why: 'a $name that never closes is a token of its own',
  },
  {
    runs: true,
    script: "select 15$a$ ' $a$\n\\o |touch @MARK@\n",
    why: 'a number ends where its digits end',
  },
  {
    runs: true,
    script: "select 1.5$a$ ' $a$\n\\o |touch @MARK@\n",
    why: 'a decimal ends where its digits end',
  },
  { runs: true, script: "select .5$a$ ' $a$\n\\o |touch @MARK@\n", why: 'a leading-dot decimal likewise' },
  { runs: true, script: "select 'x'$a$ ' $a$\n\\o |touch @MARK@\n", why: 'a string ends a token' },
  { runs: true, script: "select a $a$ ' $a$\n\\o |touch @MARK@\n", why: 'a space ends a name' },
  { runs: true, script: "select ($a$ ' $a$\n\\o |touch @MARK@\n", why: 'a bracket ends a token' },
  { runs: true, script: "select $a$ x $a$$b$ ' $b$\n\\o |touch @MARK@\n", why: 'two dollar quotes in a row' },
  {
    runs: false,
    script: "select 1a$a$ ' $a$\n\\o |touch @MARK@\n'\n",
    why: 'a number that runs into a letter is one token with the name, $ included',
  },
  { runs: false, script: "select 12ab$a$ ' $a$\n\\o |touch @MARK@\n'\n", why: 'the same, longer' },
  {
    runs: false,
    script: "select 0x1F$a$ ' $a$\n\\o |touch @MARK@\n'\n",
    why: 'a hex-looking number is 0 and a name',
  },
  {
    runs: false,
    script: "select 1_0$a$ ' $a$\n\\o |touch @MARK@\n'\n",
    why: 'a digit separator is a name character',
  },
  { runs: false, script: "select a1$a$ ' $a$\n\\o |touch @MARK@\n'\n", why: 'a name with a digit' },
  {
    runs: false,
    script: "select a.b$a$ ' $a$\n\\o |touch @MARK@\n'\n",
    why: 'the name after a dot takes its $',
  },
  {
    runs: false,
    script: "select 😀$a$ ' $a$\n\\o |touch @MARK@\n'\n",
    why: 'a character outside the BMP is a letter',
  },
  { runs: false, script: "select $1a$a$ ' $a$\n\\o |touch @MARK@\n'\n", why: '$1 and a name behind it' },
  {
    runs: false,
    script: 'select $$ \\o |touch @MARK@ $$\n',
    why: 'inside a dollar quote a backslash is text',
  },
  { runs: false, script: 'select $a$\n\\o |touch @MARK@\n$a$\n', why: 'a tagged body, the same' },
  // a backquote is no quote; `\;` and `\:` are characters of the statement and end nothing
  {
    runs: true,
    script: 'select `\n\\o |touch @MARK@\n`\n',
    why: 'a backquote is an ordinary character in PostgreSQL',
  },
  {
    runs: true,
    script: 'select 1 \\; \\o |touch @MARK@\n',
    why: '\\; puts a semicolon in the statement and the line goes on',
  },
  { runs: true, script: 'select 1\\;\\o |touch @MARK@\n', why: 'the same without spaces' },
  { runs: true, script: "select ':x' \\; \\o |touch @MARK@\n", why: 'after a string' },
  // plain strings and names
  {
    runs: true,
    script: "select 'a\\'\n\\o |touch @MARK@\n",
    why: 'a plain string: the backslash is a character and the quote closes it',
  },
  { runs: true, script: 'select a[1:2]\n\\o |touch @MARK@\n', why: 'a slice is no variable' },
  { runs: true, script: 'select 1::int\n\\o |touch @MARK@\n', why: 'a cast is no variable' },
  {
    runs: true,
    script: "select U&'\\0041'\n\\o |touch @MARK@\n",
    why: 'a unicode string closes at its quote',
  },
  { runs: false, script: "select '\n\\o |touch @MARK@\n'\n", why: 'a string may hold a line break' },
  { runs: false, script: 'select "a\n\\o |touch @MARK@\n"\n', why: 'a quoted name may hold a line break' },
];

/** Runs a shell script inside a throwaway container with NO NETWORK, made from an image that is already on this machine (the first
 *  one whose name matches `image`), and returns what it printed - or null when there is no docker, no daemon or no such image. For
 *  the clients' own option parsers: a tool reports what it took an option for before it ever connects. */
export function runInLocalImage(image: RegExp, script: string): string | null {
  if (process.env.EGO_NO_DOCKER_TESTS) return null;
  if (!docker(['info', '--format', '{{.ServerVersion}}']).ok) return null;
  // (the newest of the matching images: a tool's options change between versions, and the tables are written from the current ones)
  const found = docker(['image', 'ls', '--format', '{{.Repository}}:{{.Tag}}'])
    .out.split('\n')
    .filter((i) => image.test(i))
    .sort((a, b) => Number(/:(\d+)/.exec(b)?.[1] ?? 0) - Number(/:(\d+)/.exec(a)?.[1] ?? 0))[0];
  if (found === undefined) return null;
  const r = spawnSync(
    'docker',
    ['run', '--rm', '--network', 'none', '--entrypoint', 'sh', found, '-c', script],
    { encoding: 'utf8', timeout: 120_000 },
  );
  return r.status === null ? null : `${r.stdout ?? ''}`;
}
