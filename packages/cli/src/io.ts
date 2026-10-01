export interface CliIo {
  cwd: string;
  env: NodeJS.ProcessEnv;
  stdin: string;
  out: (s: string) => void;
  err: (s: string) => void;
  now: () => string;
}

export function parseFlags(argv: string[]): {
  positional: string[];
  flags: Record<string, string | boolean>;
} {
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq > 0) flags[a.slice(2, eq)] = a.slice(eq + 1);
      else if (i + 1 < argv.length && !argv[i + 1]!.startsWith('--')) flags[a.slice(2)] = argv[++i]!;
      else flags[a.slice(2)] = true;
    } else positional.push(a);
  }
  return { positional, flags };
}

export function flagString(flags: Record<string, string | boolean>, name: string): string | undefined {
  const v = flags[name];
  return typeof v === 'string' ? v : undefined;
}

/**
 * Every value of a REPEATABLE flag, in the order given: `--local-target kube:a --local-target=db:b`. `parseFlags` keeps
 * the last value of a flag, which is right for `--profile` and wrong for a flag that is a list. Throws when the flag is
 * given with no value, because a flag that silently collected nothing would read as "declined".
 */
export function flagValues(argv: string[], name: string): string[] {
  const out: string[] = [];
  const long = `--${name}`;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === long) {
      const v = argv[i + 1];
      if (v === undefined || v.startsWith('--')) throw new Error(`${long} needs a value`);
      out.push(v);
      i++;
    } else if (a.startsWith(`${long}=`)) {
      const v = a.slice(long.length + 1);
      if (v === '') throw new Error(`${long} needs a value`);
      out.push(v);
    }
  }
  return out;
}
