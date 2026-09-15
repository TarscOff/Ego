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
