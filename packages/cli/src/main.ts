// Single entry point of the EGO distribution (dist/ego.js). Exports `main` for the launcher shim and for in-process
// delegation between runtimes (exec contract ego.exec/1); runs itself when invoked directly.
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { launch, type DelegationInfo } from './launcher.ts';
import type { CliIo } from './io.ts';

export interface MainOptions {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  stdin?: string;
  out?: (s: string) => void;
  err?: (s: string) => void;
  now?: () => string;
  delegatedBy?: DelegationInfo;
}

export async function main(argv: string[], opts: MainOptions = {}): Promise<number> {
  const io: CliIo = {
    cwd: opts.cwd ?? process.cwd(),
    env: opts.env ?? process.env,
    stdin: opts.stdin ?? '',
    out: opts.out ?? ((s) => process.stdout.write(s + '\n')),
    err: opts.err ?? ((s) => process.stderr.write(s + '\n')),
    now: opts.now ?? (() => new Date().toISOString()),
  };
  try {
    const launchOpts: Parameters<typeof launch>[2] = {};
    if (opts.delegatedBy) launchOpts.delegatedBy = opts.delegatedBy;
    return await launch(argv, io, launchOpts);
  } catch (e) {
    const err = e as Error;
    io.err(`EGO: ${err.message}`);
    if (io.env['EGO_DEBUG'] === '1' && err.stack) io.err(err.stack);
    return 2;
  }
}

async function readStdin(): Promise<string> {
  if (process.stdin.isTTY) return '';
  const chunks: Buffer[] = [];
  return new Promise((resolve) => {
    process.stdin.on('data', (c: Buffer) => chunks.push(c));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    process.stdin.on('error', () => resolve(''));
    // a host always closes stdin after the payload; a pipe that never closes yields an empty payload, which fails closed
    setTimeout(() => resolve(''), 10_000).unref();
  });
}

function isDirectRun(): boolean {
  try {
    return (
      Boolean(process.argv[1]) &&
      realpathSync(process.argv[1]!) === realpathSync(fileURLToPath(import.meta.url))
    );
  } catch {
    return false;
  }
}

export async function runFromProcess(): Promise<void> {
  const argv = process.argv.slice(2);
  const needsStdin = argv[0] === 'hook' || argv[0] === 'redact';
  const stdin = needsStdin ? await readStdin() : '';
  process.exitCode = await main(argv, { stdin });
}

if (isDirectRun()) await runFromProcess();
