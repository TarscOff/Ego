// Single entry point of the EGO distribution (dist/ego.js). Exports `main` for the launcher shim and for in-process
// delegation between runtimes (exec contract ego.exec/1); runs itself when invoked directly.
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { launch, type DelegationInfo } from './launcher.ts';
import type { CliIo } from './io.ts';
import { POLICY_INVALID_RULE, renderFailure } from '../../kernel/src/authority/reasons.ts';
import { terminalSafe } from '../../kernel/src/util/shown-text.ts';

export interface MainOptions {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  stdin?: string;
  out?: (s: string) => void;
  err?: (s: string) => void;
  now?: () => string;
  delegatedBy?: DelegationInfo;
}

/**
 * WHAT A FAILURE LOOKS LIKE TO A PERSON. A policy that does not load or compile (a malformed control-plane or layer file,
 * a layer that widens what it may not) is POLICY_INVALID, named with its code, the file in the message and what can fix
 * it, wherever it surfaced: a command, a hook (which then fails closed with exit 2) or a delegated runtime. The check is
 * by name because a delegated runtime carries its own copy of the class.
 */
export function describeFailure(err: Error): string {
  return err.name === 'ControlPlaneValidationError'
    ? `EGO: ${renderFailure('POLICY_INVALID', err.message, POLICY_INVALID_RULE)}`
    : `EGO: ${err.message}`;
}

export async function main(argv: string[], opts: MainOptions = {}): Promise<number> {
  // THE BOUNDARY (AUTH-6): whoever supplies the writer, what is written has had every control character, escape sequence and invisible
  // character turned into a visible escape. A command prints paths, names and patterns that came from a repository, a layer file or a
  // command line; none of them is allowed to move the cursor, retitle the window or rewrite the line a person is about to answer.
  const rawOut = opts.out ?? ((s: string) => process.stdout.write(s + '\n'));
  const rawErr = opts.err ?? ((s: string) => process.stderr.write(s + '\n'));
  const io: CliIo = {
    cwd: opts.cwd ?? process.cwd(),
    env: opts.env ?? process.env,
    stdin: opts.stdin ?? '',
    out: (s) => rawOut(terminalSafe(s)),
    err: (s) => rawErr(terminalSafe(s)),
    now: opts.now ?? (() => new Date().toISOString()),
  };
  try {
    const launchOpts: Parameters<typeof launch>[2] = {};
    if (opts.delegatedBy) launchOpts.delegatedBy = opts.delegatedBy;
    return await launch(argv, io, launchOpts);
  } catch (e) {
    const err = e as Error;
    io.err(describeFailure(err));
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
