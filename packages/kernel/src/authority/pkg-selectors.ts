// THE SELECTORS OF A PACKAGE MANAGER THAT ONLY CHANGE THE DIRECTORY IT RUNS IN (closure audit wave 5, U-12).
//
// `npm --prefix backend run build`, `npm -C backend test`, `pnpm -C backend test` and `yarn --cwd frontend test` run the script of
// the manifest in another directory, and that is all they do: the monorepo layout (backend/, frontend/, sdk/) is how a great many
// repositories are laid out, and the producer answered every one of them "the selector chooses a manifest outside the resolved
// working directory" - an ask for each script run through one. Another directory is not another WORKSPACE: a workspace or a filter
// picks packages out of a graph this kernel does not model, and a `cd backend &&` in front of the same words was resolved all along.
// So a selector that is only a directory is read as the `cd` it is - the producer asks the same question of the directory - and
// every other selector stays what it was.
//
// Verified against npm 11 (`npm --prefix d run x`, `npm -C d run x` and `npm run x --prefix d` all run the script with `d` as the
// working directory); the other three tools document the same option (`pnpm -C|--dir <path>`, `yarn --cwd <path>`, `bun --cwd <path>`).

/** the options that name the directory the tool starts in, per tool */
const DIRECTORY_OPTIONS: Readonly<Record<string, readonly string[]>> = {
  npm: ['--prefix', '-C'],
  pnpm: ['-C', '--dir'],
  yarn: ['--cwd'],
  bun: ['--cwd'],
};

export interface DirectorySelector {
  /** the directory word as written */
  dir: string;
  /** the command line without the option and its value */
  rest: string[];
}

/**
 * The directory selector of a package-manager command line, or null when there is none, when there are two (which one wins is
 * the tool's business), or when its value is not a plain word. Only the words in front of a `--` count: after it they are the
 * script's own arguments.
 */
export function directorySelector(head: string, tokens: readonly string[]): DirectorySelector | null {
  const options = DIRECTORY_OPTIONS[head];
  if (options === undefined) return null;
  const end = tokens.indexOf('--');
  const limit = end < 0 ? tokens.length : end;
  let found: { at: number; width: number; dir: string } | null = null;
  for (let i = 1; i < limit; i++) {
    const t = tokens[i]!;
    let hit: { width: number; dir: string } | null = null;
    if (options.includes(t)) {
      const value = tokens[i + 1];
      if (i + 1 < limit && value !== undefined && value !== '' && !value.startsWith('-')) hit = { width: 2, dir: value };
      else return null;
    } else {
      const eq = /^(--[a-z-]+)=(.+)$/.exec(t);
      if (eq !== null && options.includes(eq[1]!)) hit = { width: 1, dir: eq[2]! };
    }
    if (hit === null) continue;
    if (found !== null) return null;
    found = { at: i, ...hit };
  }
  if (found === null) return null;
  return { dir: found.dir, rest: [...tokens.slice(0, found.at), ...tokens.slice(found.at + found.width)] };
}
