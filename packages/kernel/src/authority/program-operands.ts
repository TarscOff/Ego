// WHICH OPTION OF WHICH TOOL NAMES A PROGRAM.
//
// A command of a class the table calls bounded (`grep`, `make`, `gcc`, `go build`, `tar`) executes what its arguments name - unless one of
// its options hands it a PROGRAM: `tar -I prog`, `gcc -B dir`, `clang -Xclang -load -Xclang plugin.so`, `go build -toolexec wrap`, `rsync -e
// prog`. Such a command is not the bounded one it looked like, and the evaluator treats it as an opaque program (`command.script-opaque`).
//
// The question used to be answered by ONE regex over the text of ANY segment, with the options of every tool in it. An option is a property
// of a TOOL, not of a letter, and the letters collide: `-B` is the directory of sub-programs to gcc and clang, the lines of context BEFORE a
// match to grep, ripgrep and `git grep`, ignore-blank-lines to diff and always-make to make; `-ldflags` hands go's linker its flags and is
// no program; `-e sh` is the pattern `sh` to grep. `grep -B 3 foo README.md` asked, as did `make -B build` and every `go build -ldflags
// "-s -w"` (wave 5, OT-01). So the options are read PER TOOL, as the tools.ts tables already read them for the tools they model.
//
//   - an option whose name is unambiguous in every tool that has it (a long option: `--use-compress-program`, `--rsh`, `--pre`,
//     `--upload-pack`) is one list;
//   - the rest are the options of one family of heads, each with the heads that have them;
//   - and the one whose value is a LIST OF FLAGS handed to another program (go's `-ldflags`) is read by what the flags are: the ones
//     known to leave the program alone are ordinary, everything else - a linker, a file written, a flag nobody listed - is a program.
import { CC_HEADS } from './tools.ts';

/** The options that name a program in every tool that has them. */
const UNIVERSAL =
  '--use-compress-program|--checkpoint-action|--to-command|--rsh-command|--rsh|--exec|--ok-dir|--unzip-command|--filter=.*command|--pre|' +
  '--hostname-bin|--upload-pack|--receive-pack|--editor|--pager|--ssh-command|--proxy-command|--post-renderer|--exec-path|' +
  '--compress-program|--wrapper|--specs|--plugin|--preprocessor';

interface Family {
  heads: RegExp;
  /** the options, as a pattern; each is also read glued to its value (`-B/tmp/evil`) when `glued` */
  options: string;
  glued: boolean;
}

const FAMILIES: readonly Family[] = [
  // the compiler drivers and linkers: a directory of sub-programs, a wrapper, a specs file, a plugin, a frontend option that loads one
  { heads: CC_HEADS, options: '-B|-wrapper|-fplugin|-fplugin-arg-[\\w-]+|-specs|-Xclang|-fpass-plugin|-load|-no-integrated-cpp', glued: true },
  // the JVM and its compilers: an annotation processor, a compiler plugin, an agent
  { heads: /^(javac|java|kotlinc|kotlin|scalac|scala)$/, options: '-processor|-processorpath|-Xplugin|-agentlib|-agentpath|-javaagent', glued: true },
  { heads: /^(zip|zipcloak|zipnote|zipsplit)$/, options: '-TT', glued: false },
  { heads: /^(tar|bsdtar|gtar|pax)$/, options: '-I', glued: false },
  // rsync's `-e` names a remote SHELL; the lookahead keeps `-e` of the tools that mean a pattern or a statement out of it, and an
  // ASSIGNMENT is not a program name (`docker run -e SHELL=/bin/sh`)
  { heads: /^(rsync)$/, options: '-e(?=\\s+(?![A-Za-z_][A-Za-z0-9_]*=)(?:\\S*/)?(ssh|sh|bash|zsh|dash|python3?|perl|ruby|node)(\\s|$))', glued: false },
  { heads: /^go$/, options: '-toolexec|-gccgo', glued: false },
];

const UNIVERSAL_RE = new RegExp(`\\s(${UNIVERSAL})(=|\\s)`);
const compiled = FAMILIES.map((f) => ({
  f,
  long: new RegExp(`\\s(${f.options})(=|\\s)`),
  glued: f.glued ? new RegExp(`\\s(${f.options})[:=]?\\S`) : null,
}));

/** the flags of go's linker that leave the program alone: what the binary says about itself, and how it is linked internally */
const LINKER_SWITCHES = new Set(['-s', '-w', '-v', '-d', '-race', '-msan', '-asan']);
/** ...and the flags of the EXTERNAL linker that go's `-extldflags` may carry: how it links, not what it runs */
const EXTLD_FLAG = /^(-static|-static-pie|-pie|-no-pie|-pthread|-fPIC|-fPIE|-l[\w.+-]+|-L[\w./+-]+|-O[0-3s]?)$/;

/** Split a flag list the way go's `quoted.Split` does: blanks separate, a quote keeps its contents in one word. */
function flagWords(list: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quote = '';
  let has = false;
  for (const ch of list) {
    if (quote) {
      if (ch === quote) quote = '';
      else cur += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      has = true;
    } else if (/\s/.test(ch)) {
      if (cur !== '' || has) out.push(cur);
      cur = '';
      has = false;
    } else {
      cur += ch;
      has = true;
    }
  }
  if (cur !== '' || has) out.push(cur);
  return out;
}

/** The first flag in a linker flag list that is not known to leave the program alone, or null. */
function linkerFlagProblem(list: string): string | null {
  if (/[$`]/.test(list)) return list;
  // (`-ldflags=all=-s -w` names the packages the flags apply to before an `=`)
  const words = flagWords(list.replace(/^[^\s=-][^\s=]*=(?=-)/, ''));
  for (let i = 0; i < words.length; i++) {
    const w = words[i]!;
    const eq = w.indexOf('=');
    const name = w.startsWith('-') && eq > 0 ? w.slice(0, eq) : w;
    const glued = w.startsWith('-') && eq > 0 ? w.slice(eq + 1) : undefined;
    const value = (): string | undefined => glued ?? words[++i];
    if (LINKER_SWITCHES.has(name) && glued === undefined) continue;
    if (name === '-X') {
      if (!/^[\w./-]+=/.test(value() ?? '')) return w;
    } else if (name === '-linkmode') {
      if (!/^(internal|external|auto)$/.test(value() ?? '')) return w;
    } else if (name === '-buildid') value();
    else if (name === '-H') {
      if (!/^[a-z0-9]+$/.test(value() ?? '')) return w;
    } else if (name === '-extldflags') {
      if (!flagWords(value() ?? '').every((f) => EXTLD_FLAG.test(f))) return w;
    } else return w;
  }
  return null;
}

/** The linker flags go was given, and why one of them is a program or a thing nobody listed. `words` are the words of the command AS WRITTEN:
 *  the value of `-ldflags` is one quoted word there, and the normalized text has already lost the quoting that made it one. */
function goLinkerProblem(words: readonly string[]): string | null {
  for (let i = 0; i < words.length; i++) {
    const m = /^--?ldflags(?:=([\s\S]*))?$/.exec(words[i]!);
    if (!m) continue;
    const bad = linkerFlagProblem(m[1] ?? words[i + 1] ?? '');
    if (bad !== null) return `-ldflags (${bad})`;
  }
  return null;
}

/** The option of `seg` that names a program to the tool it is the command of, or null. `head` is the command's own name; `words` are the words as
 *  written, for the one option whose value is a list of flags. */
export function programOperand(head: string, seg: string, words: readonly string[] = []): string | null {
  const base = head.replace(/^.*\//, '');
  const universal = UNIVERSAL_RE.exec(seg);
  if (universal) return universal[1]!;
  for (const { f, long, glued } of compiled) {
    if (!f.heads.test(base)) continue;
    const hit = long.exec(seg) ?? glued?.exec(seg);
    if (hit) return hit[1]!;
  }
  return base === 'go' ? goLinkerProblem(words) : null;
}
