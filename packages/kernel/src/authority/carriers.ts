// ONE CARRIER UNWRAPPER, DRIVEN BY ONE TABLE.
//
// A carrier is a command whose job is to run another command: `timeout`, `env`, `nice`, `nohup`, `stdbuf`, `time`, `watch`,
// `sudo`, `flock`, `su`, `npx`, `yarn exec`... What the carried command IS - and so what it writes, which flags it was given,
// where it runs - depends on locating it, and locating it means consuming exactly the carrier's OWN options: `timeout -s
// KILL 5 sed ...` has a value-taking `-s` and a duration in front of `sed`; `env --unset A sed ...` and `env -iuA sed ...`
// have a value-taking `-u` spelled three ways; `env -S'git commit -m x' -n` hands env a command LINE and the `-n` after it
// belongs to the line.
//
// The kernel had FIVE readers of that fact, each with a regex of the carriers and options its author had met: the
// normalizer's wrapper loop, the head finder the raw-text scanners use (commandHeadIndex), a copy of that loop inside the awk
// scanner, the environment-input scan, and the directory finder (runDirectory). They disagreed - `timeout -s KILL 5 sed -n
// '1w .claude/settings.json'` was a plain read to the sed scanner because it took KILL for the command - and every
// disagreement was a way to carry a governed effect past one of them (independent reviews 7-11: RC-CAR). Each wrapper added
// to one list had to be added to four others, and was not.
//
// This module is the single reader. The table says, for every carrier, which options it has and what each takes; the peel
// consumes exactly those, iterates to a fixed point (a carrier carrying a carrier), and reports what it could not place:
//   - an own option that is NOT in a strict carrier's table makes the result `partial` - the carried command's position is
//     unknown, so nothing may be granted on it (the caller asks);
//   - a chain deeper than MAX_STEPS is `partial` too;
//   - a command string (`env -S`, `su -c`, `flock -c`) is returned as a STRING with the words the carrier appends to it.
// A LENIENT carrier is one whose documented options this table lists only in part (the rarely used wrappers): an unknown
// option is read as a flag, which is what the old loop did for every one of them. Completing a row and dropping `lenient`
// from it is the whole change needed to make that carrier ask on an option it does not know.

import { type Grammar, type ParsedOption, has, parseOptions, valuesOf } from './options.ts';

export const MAX_STEPS = 12;

export interface Carrier {
  grammar: Grammar;
  /** how many positional operands precede the carried command (timeout's DURATION, flock's LOCKFILE), as a function of the
   *  options that were given */
  operands?: number | ((given: ParsedOption[]) => number);
  /** leading operands recognised by SHAPE, any number (chrt's priority, taskset's mask), interleaved with options */
  operandShape?: RegExp;
  /** `NAME=value` words follow the options (env, sudo) */
  assign?: boolean;
  /** an unknown own option is a flag instead of `partial` (see the file header) */
  lenient?: boolean;
  /** the rest of the line is ONE SHELL STRING (`watch cmd args` is `sh -c 'cmd args'`) unless this option is on */
  shellString?: { unlessOption?: string };
  /** the command string option may also follow the operands (`flock FILE -c CMD`, `su USER -c CMD`) */
  commandAfterOperands?: boolean;
  /** the carrier keeps its own head in the normalized command (sudo): command.privileged must still see it */
  retains?: boolean;
  /** the carried command is a PAYLOAD run per match or per input line (xargs): the normalizer's payload reader owns it, so
   *  the normalizer stops here, while the raw-text readers look through */
  payload?: boolean;
  /** options that make the carrier a LOOKUP of the name that follows, not a carrier (`command -v NAME`) */
  lookupOptions?: readonly string[];
}

const gnu = (options: string[], extra: Partial<Grammar> = {}): Grammar => ({ style: 'gnu', stopAtOperand: true, options, ...extra });
const HELP = ['--help', '--version'];

const CARRIERS: Record<string, Carrier> = {
  // coreutils env (-S/-C/-u/-a and the signal options), BSD env (-P -L -U -v). A lone `-` is `-i`.
  env: {
    grammar: gnu(
      ['-i|--ignore-environment', '-0|--null', '-v|--debug', '-u|--unset:v', '-C|--chdir:v', '-S|--split-string:c', '-a|--argv0:v',
        '-P:v', '-L:v', '-U:v', '--default-signal:o', '--ignore-signal:o', '--block-signal:o', '--list-signal-handling', ...HELP],
      { dash: 'i' },
    ),
    assign: true,
  },
  timeout: {
    grammar: gnu(['-f|--foreground', '-k|--kill-after:v', '-p|--preserve-status', '-s|--signal:v', '-v|--verbose', ...HELP]),
    operands: 1,
  },
  nice: { grammar: gnu(['-n|--adjustment:v', ...HELP], { numeric: true }) },
  nohup: { grammar: gnu([...HELP]) },
  stdbuf: { grammar: gnu(['-i|--input:v', '-o|--output:v', '-e|--error:v', ...HELP]) },
  // /usr/bin/time (GNU and BSD) and the shell keyword
  // (the keyword takes assignments after it: `time VAR=x make`)
  time: { grammar: gnu(['-f|--format:v', '-o|--output:v', '-a|--append', '-v|--verbose', '-p|--portability', '-q|--quiet', '-l', '-h', '-V', ...HELP]), assign: true },
  command: { grammar: gnu(['-p', '-v', '-V']), lookupOptions: ['v', 'V'] },
  exec: { grammar: gnu(['-c', '-l', '-a:v']) },
  builtin: { grammar: gnu([]) },
  // zsh precommand modifiers: `noglob VAR=x cmd`
  nocorrect: { grammar: gnu([]), assign: true },
  noglob: { grammar: gnu([]), assign: true },
  // procps watch: the command is a shell string unless -x/--exec
  watch: {
    grammar: gnu(
      ['-b|--beep', '-c|--color', '-C|--no-color', '-d|--differences', '-e|--errexit', '-g|--chgexit', '-n|--interval:v', '-p|--precise',
        '-q|--equexit:v', '-r|--no-rerun', '-t|--no-title', '-w|--no-wrap', '-x|--exec', '-h|--help', '-v|--version'],
    ),
    shellString: { unlessOption: 'exec' },
  },
  // GNU parallel's semaphore: `sem [--id ID] [-j N] cmd` is a shell string too
  sem: { grammar: gnu(['-j|--jobs:v', '--id:v', '-u|--ungroup', '-q|--quote', '--fg', '--bg', ...HELP]), shellString: {}, lenient: true },
  ionice: { grammar: gnu(['-c|--class:v', '-n|--classdata:v', '-p|--pid:v', '-P|--pgid:v', '-u|--uid:v', '-t|--ignore', '-h|--help', '-V|--version']), lenient: true },
  setsid: { grammar: gnu(['-c|--ctty', '-f|--fork', '-w|--wait', '-h|--help', '-V|--version']), lenient: true },
  caffeinate: { grammar: gnu(['-d', '-i', '-m', '-s', '-u', '-t:v', '-w:v']), lenient: true },
  chronic: { grammar: gnu(['-e', '-v']), lenient: true },
  unbuffer: { grammar: gnu(['-p']), lenient: true },
  strace: { grammar: gnu(['-o:v', '-p:v', '-e:v', '-s:v', '-E:v', '-u:v']), lenient: true },
  ltrace: { grammar: gnu(['-o:v', '-p:v', '-e:v', '-s:v', '-u:v']), lenient: true },
  valgrind: { grammar: gnu(['--tool:v']), lenient: true },
  chrt: { grammar: gnu(['-p|--pid:v']), operandShape: /^\d+$/, lenient: true },
  taskset: { grammar: gnu(['-p|--pid:v']), operandShape: /^(0x[0-9a-fA-F]+|[0-9,-]+)$/, lenient: true },
  numactl: { grammar: gnu(['-C|--physcpubind:v', '-N|--cpunodebind:v', '-m|--membind:v', '-p|--preferred:v']), lenient: true },
  prlimit: { grammar: gnu(['-p|--pid:v']), lenient: true },
  cpulimit: { grammar: gnu(['-l|--limit:v', '-p|--pid:v', '-e|--exe:v']), lenient: true },
  'xvfb-run': { grammar: gnu(['-n|--server-num:v', '-s|--server-args:v', '-e|--error-file:v', '-f|--auth-file:v']), lenient: true },
  'systemd-run': { grammar: gnu(['-p|--property:v', '-u|--unit:v', '-E|--setenv:v', '-M|--machine:v']), lenient: true },
  'sandbox-exec': { grammar: gnu(['-f:v', '-p:v', '-n:v', '-D:v']), lenient: true },
  nsenter: { grammar: gnu(['-t|--target:v']), lenient: true },
  // macOS arch: `-arch NAME` selects the slice, `-d NAME` deletes a variable, `-e NAME=VALUE` sets one, `-arm64` is a flag
  arch: { grammar: gnu(['-arch:v', '-d:v', '-e:v']), operandShape: /^-?(arm64|arm64e|x86_64|i386)$/, lenient: true },
  gtimeout: {
    grammar: gnu(['-f|--foreground', '-k|--kill-after:v', '-p|--preserve-status', '-s|--signal:v', '-v|--verbose', ...HELP]),
    operands: 1,
  },
  eatmydata: { grammar: gnu([]), lenient: true },
  fakeroot: { grammar: gnu(['-l:v', '-i:v', '-s:v', '-u', '-b:v']), lenient: true },
  proxychains: { grammar: gnu(['-q', '-f:v']), lenient: true },
  proxychains4: { grammar: gnu(['-q', '-f:v']), lenient: true },
  torsocks: { grammar: gnu([]), lenient: true },
  rlwrap: { grammar: gnu(['-a', '-c', '-f:v', '-n', '-s:v', '-H:v']), lenient: true },
  daemonize: { grammar: gnu(['-a', '-c:v', '-e:v', '-E:v', '-o:v', '-p:v', '-u:v', '-l:v', '-v']), lenient: true },
  firejail: { grammar: gnu([]), lenient: true },
  unshare: { grammar: gnu([]), lenient: true },
  busybox: { grammar: gnu([]), lenient: true },
  // privilege: the head is kept (command.privileged must fire), the command behind it is analysed on its own
  sudo: {
    grammar: gnu(
      ['-A|--askpass', '-b|--background', '-B|--bell', '-C|--close-from:v', '-D|--chdir:v', '-E|--preserve-env', '-e|--edit', '-g|--group:v',
        '-H|--set-home', '-h|--host:v', '-i|--login', '-K|--remove-timestamp', '-k|--reset-timestamp', '-l|--list', '-n|--non-interactive',
        '-P|--preserve-groups', '-p|--prompt:v', '-R|--chroot:v', '-r|--role:v', '-S|--stdin', '-s|--shell', '-T|--command-timeout:v',
        '-t|--type:v', '-U|--other-user:v', '-u|--user:v', '-V|--version', '-v|--validate', '--help', '-N|--no-update', '-I'],
    ),
    assign: true,
    retains: true,
  },
  doas: { grammar: gnu(['-C:v', '-n', '-s', '-u:v']), retains: true },
  // lock and user-switching carriers: the command may be an operand or a command STRING (`-c`)
  flock: {
    grammar: gnu(['-s|--shared', '-x|--exclusive', '-u|--unlock', '-n|--nonblock|--nb', '-w|--timeout|--wait:v', '-E|--conflict-exit-code:v',
      '-o|--close', '-F|--no-fork', '-c|--command:c', '-v|--verbose', '-h|--help', '-V|--version', '--fcntl']),
    operands: 1,
    commandAfterOperands: true,
  },
  su: {
    grammar: gnu(['-m|-p|--preserve-environment', '-P|--pty', '-g|--group:v', '-G|--supp-group:v', '-c|--command:c', '--session-command:c', '-f|--fast',
      '-l|--login', '-s|--shell:v', '-w|--whitelist-environment:v', '-h|--help', '-V|--version'], { dash: 'l' }),
    operands: 1,
    commandAfterOperands: true,
    lenient: true,
  },
  runuser: {
    grammar: gnu(['-u|--user:v', '-g|--group:v', '-G|--supp-group:v', '-c|--command:c', '--session-command:c', '-f|--fast', '-l|--login',
      '-m|-p|--preserve-environment', '-s|--shell:v', '-w|--whitelist-environment:v', '-P|--pty', '-h|--help', '-V|--version'], { dash: 'l' }),
    operands: (given) => (given.some((o) => o.name === 'user') ? 0 : 1),
    commandAfterOperands: true,
    lenient: true,
  },
  // package-manager runners resolve a name to a local or fetched binary and exec it
  npx: {
    grammar: gnu(['-p|--package:v', '-c|--call:c', '-w|--workspace:v', '--prefix:v', '--cache:v', '--registry:v', '--userconfig:v', '--node-arg:v', '-y|--yes', '--no',
      '--no-install', '--ignore-existing', '-q|--quiet', '--shell:v', '--shell-auto-fallback', '--include-workspace-root', '-ws|--workspaces', '--loglevel:v']),
    lenient: true,
  },
  xargs: {
    grammar: gnu(
      ['-0|--null', '-a|--arg-file:v', '-d|--delimiter:v', '-E:v', '-e|--eof:o', '-I:v', '-i|--replace:o', '-L:v', '-l|--max-lines:o', '-n|--max-args:v',
        '-P|--max-procs:v', '-p|--interactive', '-r|--no-run-if-empty', '-s|--max-chars:v', '-t|--verbose', '-x|--exit', '-o|--open-tty', '-J:v',
        '-R:v', '-S:v', '--process-slot-var:v', '--show-limits', ...HELP],
    ),
    payload: true,
    lenient: true,
  },
};
CARRIERS['bunx'] = CARRIERS['npx']!;

/** the carriers that are written as two words: `yarn exec`, `pnpm exec`, `npm exec`, `npm x`, `bun x` */
const TWO_WORD: ReadonlyArray<readonly [string, string]> = [
  ['yarn', 'exec'],
  ['pnpm', 'exec'],
  ['npm', 'exec'],
  ['npm', 'x'],
  ['bun', 'x'],
];

export const CARRIER_NAMES: ReadonlySet<string> = new Set(Object.keys(CARRIERS));
/** the carriers the normalizer strips as TRANSPARENT: everything but the ones that keep their head or own a payload */
export const TRANSPARENT_CARRIERS: ReadonlySet<string> = new Set(
  Object.entries(CARRIERS).filter(([, c]) => !c.retains && !c.payload).map(([n]) => n),
);

const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
const SYSTEM_BIN = /^\/(?:usr\/)?(?:local\/)?s?bin\/|^\/opt\/homebrew\/s?bin\//;

/** The carrier a word names: the bare name, or an absolute path into a system directory (`/usr/bin/env`). */
export function carrierNamed(word: string): string | null {
  if (Object.hasOwn(CARRIERS, word)) return word;
  if (SYSTEM_BIN.test(word)) {
    const base = word.slice(word.lastIndexOf('/') + 1);
    if (Object.hasOwn(CARRIERS, base)) return base;
  }
  return null;
}

export interface PeelStep {
  carrier: string;
  /** the index of the carrier's own word */
  at: number;
  options: ParsedOption[];
  /** own options the table could not place (`--future-flag`, an unknown letter in a cluster) */
  unknown: string[];
  /** the positional operands the carrier took (the duration, the lock file) */
  operands: string[];
  /** `NAME=value` words between the carrier and the command */
  assignments: string[];
}

export interface Peeled {
  steps: PeelStep[];
  /** `NAME=value` words in front of the whole chain */
  leading: string[];
  /** the index of the first word of the carried command; `words.length` when the chain ends in a string or in nothing */
  at: number;
  /** command STRINGS the chain hands to a shell or to env's own splitter, with the words the carrier appends to each */
  strings: Array<{ carrier: string; body: string; appended: string[] }>;
  /** the rest of the line, joined, when a carrier runs it as ONE shell string (`watch`, `sem`) */
  shellString: string | null;
  /** where that string's first word is (the caller may read the words as an argv instead) */
  shellAt: number;
  /** why the position of the carried command is not certain, or null */
  partial: string | null;
  /** the chain ended in `command -v NAME` / `-V`: a lookup, which runs nothing */
  lookup: boolean;
}

export interface PeelOptions {
  /** words to skip in front of a command (`if`, `then`, `do`, `!`...) - shell structure, owned by the caller */
  prefixes?: ReadonlySet<string>;
  /** stop BEFORE the first carrier for which this holds (the normalizer keeps `sudo` and leaves `xargs` to its payload reader) */
  stopAt?: (carrier: string, spec: Carrier) => boolean;
  /** peel at most this many carriers */
  maxSteps?: number;
}

/** The values of an own option of one step (`env -C DIR`, `timeout -s SIG`), whatever the spelling. */
export function stepValues(step: PeelStep, name: string): string[] {
  return valuesOf({ options: step.options, operands: [], unknown: [], end: 0, dashDashAt: -1 }, name);
}

/**
 * Locates the command a chain of carriers carries. `words` are the argument words of the segment (quotes already removed);
 * `from` is where the chain starts.
 */
export function peelCarriers(words: readonly string[], from = 0, opts: PeelOptions = {}): Peeled {
  const out: Peeled = { steps: [], leading: [], at: from, strings: [], shellString: null, shellAt: 0, partial: null, lookup: false };
  let i = from;
  for (;;) {
    // shell structure and bare assignments in front of a command: `if VAR=x timeout 5 cmd`
    while (i < words.length) {
      const w = words[i]!;
      if (ASSIGNMENT.test(w) && out.steps.length === 0) {
        out.leading.push(w);
        i++;
        continue;
      }
      if (opts.prefixes?.has(w) && carrierNamed(w) === null) {
        i++;
        continue;
      }
      break;
    }
    const w = words[i];
    if (w === undefined) break;
    const pair = TWO_WORD.some((p) => p[0] === w && p[1] === words[i + 1]);
    const name = pair ? `${w} ${words[i + 1]}` : carrierNamed(w);
    const spec = name === null ? undefined : CARRIERS[pair ? 'npx' : name];
    if (name === null || spec === undefined) break;
    if (opts.stopAt?.(name, spec)) break;
    if (out.steps.length >= MAX_STEPS) {
      out.partial ??= `carriers nested more than ${MAX_STEPS} deep`;
      break;
    }
    const p = parseOptions(spec.grammar, words, i + (pair ? 2 : 1));
    const step: PeelStep = { carrier: name, at: i, options: [...p.options], unknown: p.unknown.map((u) => u.raw), operands: [], assignments: [] };
    out.steps.push(step);
    let next = p.end;
    // `command -v NAME` / `-V NAME` LOOKS THE NAME UP; it runs nothing
    if (spec.lookupOptions?.some((l) => has(p, l))) {
      out.lookup = true;
      out.at = words.length;
      return out;
    }
    // a command STRING: env -S, su -c, flock -c, npx -c. The parse ended at it, and env appends what follows to the string
    const cmd = p.options.find((o) => o.arity === 'command' && o.value !== null);
    if (cmd) {
      if (step.unknown.length && !spec.lenient) out.partial ??= `${name} has an option this kernel does not model (${step.unknown[0]})`;
      out.strings.push({ carrier: name, body: cmd.value!, appended: name === 'env' ? words.slice(next) : [] });
      out.at = words.length;
      return out;
    }
    const want = typeof spec.operands === 'function' ? spec.operands(p.options) : (spec.operands ?? 0);
    for (let k = 0; k < want && next < words.length; k++) step.operands.push(words[next++]!);
    if (spec.operandShape)
      while (next < words.length && spec.operandShape.test(words[next]!)) {
        step.operands.push(words[next++]!);
        // a shape operand may be followed by more options (`taskset -c 0 cmd`, `arch -arm64 -d X cmd`)
        const more = parseOptions(spec.grammar, words, next);
        step.options.push(...more.options);
        step.unknown.push(...more.unknown.map((u) => u.raw));
        next = more.end;
      }
    if (spec.commandAfterOperands && next < words.length && words[next]!.startsWith('-') && words[next] !== '--') {
      const more = parseOptions(spec.grammar, words, next);
      step.options.push(...more.options);
      step.unknown.push(...more.unknown.map((u) => u.raw));
      const late = more.options.find((o) => o.arity === 'command' && o.value !== null);
      if (late) {
        out.strings.push({ carrier: name, body: late.value!, appended: [] });
        out.at = words.length;
        return out;
      }
      next = more.end;
    }
    if (step.unknown.length && !spec.lenient) out.partial ??= `${name} has an option this kernel does not model (${step.unknown[0]})`;
    if (spec.assign) while (next < words.length && ASSIGNMENT.test(words[next]!)) step.assignments.push(words[next++]!);
    // a shell string: `watch cmd args` is `sh -c 'cmd args'`, unless -x asks for a plain exec
    if (spec.shellString && !(spec.shellString.unlessOption && has(p, spec.shellString.unlessOption))) {
      out.shellString = words.slice(next).join(' ');
      out.shellAt = next;
      out.at = words.length;
      return out;
    }
    i = next;
    out.at = i;
    if (opts.maxSteps !== undefined && out.steps.length >= opts.maxSteps) return out;
  }
  out.at = Math.min(i, words.length);
  return out;
}
