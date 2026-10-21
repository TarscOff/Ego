// THE SED SCRIPT, READ AS A SCRIPT.
//
// A sed script is a small program: addresses, commands, a `{ }` block, and four commands that touch the world outside the
// pattern space - `w`/`W` WRITE a file, `r`/`R` READ one into the output, `e` RUNS a shell command, and a substitution can do
// the same with its `w` and `e` flags. The kernel found them with regexes over the script text, and each regex knew the
// spelling its author had met: `w FILE` with whitespace before the name. sed accepts `w.claude/settings.json` - the file name
// glued to the command letter - and `1{w.env\n}`, and `s/a/b/gw.env`, and every one of them wrote a governed file at ALLOW
// (independent review 11: r11-16, r11-91).
//
// This is a scanner with the grammar's own states, so the question "which file does this script write" is answered by reading
// the script the way sed does: skip the address, take the command letter, take its argument by that command's rule (a file
// name runs to the END OF THE LINE, a label to the next `;`, text of `a`/`i`/`c` to the end of the line and past a trailing
// backslash, a substitution's parts by its delimiter). It does not model what each command DOES, only where the arguments of
// the four dangerous ones are, which is all a destination reader needs.

export interface SedEffects {
  /** files the script writes: `w`, `W`, and the `w` flag of `s` */
  writes: string[];
  /** files the script reads into the output: `r`, `R` */
  reads: string[];
  /** shell command lines the script runs: `e COMMAND` */
  commands: string[];
  /** the script executes the PATTERN SPACE as a command (`e` alone, `s///e`): content this kernel has not seen */
  executesPatternSpace: boolean;
  /** the scanner lost the thread (an unterminated command, a command letter sed does not have) - the script may do more than
   *  this says, and the caller should fall back to its coarser reading */
  confused: boolean;
}

/** Commands with no argument: they end at `;`, `}`, a newline or a comment. */
const NO_ARG = new Set(['=', 'd', 'D', 'F', 'g', 'G', 'h', 'H', 'n', 'N', 'p', 'P', 'x', 'z']);
/** Commands whose argument is a number or nothing */
const NUMERIC_ARG = new Set(['l', 'L', 'q', 'Q']);

/** The names a file argument can mean. sed's rule is that the name runs to the end of the line - `w out.txt;p` writes a file
 *  called `out.txt;p` - but a script is written by someone who means `out.txt` and then `p`, and which of them the shell
 *  and sed agree on is the author's to know, not ours: both are judged, so the governed file is never the one left out. */
function fileNames(raw: string): string[] {
  if (raw === '') return [];
  const names = [raw];
  for (const cut of [';', '}']) {
    const at = raw.indexOf(cut);
    if (at > 0) names.push(raw.slice(0, at).trim());
  }
  return [...new Set(names)].filter((x) => x !== '');
}

export function scanSedScript(script: string): SedEffects {
  const out: SedEffects = { writes: [], reads: [], commands: [], executesPatternSpace: false, confused: false };
  const n = script.length;
  let i = 0;
  const isSpace = (c: string | undefined): boolean => c === ' ' || c === '\t';
  const skipSpace = (): void => {
    while (i < n && isSpace(script[i])) i++;
  };
  /** the rest of the line from here, the way a file name or a shell command is taken */
  const restOfLine = (): string => {
    skipSpace();
    let j = i;
    while (j < n && script[j] !== '\n') j++;
    const text = script.slice(i, j);
    i = j;
    return text.trim();
  };
  /** one delimited part of `s` or `y`: text up to the next UNESCAPED delimiter; a backslash keeps the next character */
  const part = (delim: string): string | null => {
    let j = i;
    while (j < n) {
      const c = script[j]!;
      if (c === '\\') {
        j += 2;
        continue;
      }
      if (c === delim) {
        const text = script.slice(i, j);
        i = j + 1;
        return text;
      }
      j++;
    }
    return null;
  };
  /** an address: a number (`3`, `0~4`), `$`, a regex (`/re/I`, `\cREc`), then `,` and a second one (`+N`, `~N`) */
  const address = (): boolean => {
    const one = (): boolean => {
      const c = script[i];
      if (c === undefined) return false;
      if (/[0-9]/.test(c)) {
        while (i < n && /[0-9]/.test(script[i]!)) i++;
        if (script[i] === '~') {
          i++;
          while (i < n && /[0-9]/.test(script[i]!)) i++;
        }
        return true;
      }
      if (c === '$') {
        i++;
        return true;
      }
      if (c === '/' || c === '\\') {
        let delim = '/';
        if (c === '\\') {
          delim = script[i + 1] ?? '/';
          i += 2;
        } else i++;
        if (part(delim) === null) {
          out.confused = true;
          i = n;
          return true;
        }
        while (i < n && (script[i] === 'I' || script[i] === 'M')) i++;
        return true;
      }
      return false;
    };
    skipSpace();
    if (!one()) return false;
    skipSpace();
    if (script[i] === ',') {
      i++;
      skipSpace();
      if (script[i] === '+' || script[i] === '~') {
        i++;
        while (i < n && /[0-9]/.test(script[i]!)) i++;
      } else if (!one()) out.confused = true;
    }
    return true;
  };
  while (i < n) {
    // between commands: whitespace, separators, and comments (`#` to the end of the line)
    while (i < n && (isSpace(script[i]) || script[i] === ';' || script[i] === '\n')) i++;
    if (i >= n) break;
    if (script[i] === '#') {
      while (i < n && script[i] !== '\n') i++;
      continue;
    }
    address();
    skipSpace();
    while (script[i] === '!') {
      i++;
      skipSpace();
    }
    const cmd = script[i++];
    if (cmd === undefined) break;
    if (cmd === '{' || cmd === '}') continue;
    if (NO_ARG.has(cmd)) continue;
    if (NUMERIC_ARG.has(cmd)) {
      skipSpace();
      while (i < n && /[0-9]/.test(script[i]!)) i++;
      continue;
    }
    if (cmd === 'w' || cmd === 'W') {
      out.writes.push(...fileNames(restOfLine()));
      continue;
    }
    if (cmd === 'r' || cmd === 'R') {
      out.reads.push(...fileNames(restOfLine()));
      continue;
    }
    if (cmd === 'e') {
      const c = restOfLine();
      if (c === '') out.executesPatternSpace = true;
      else out.commands.push(c);
      continue;
    }
    if (cmd === 'a' || cmd === 'i' || cmd === 'c') {
      // text: to the end of the line, and onto the next line while the line ends in an odd run of backslashes
      for (;;) {
        let j = i;
        while (j < n && script[j] !== '\n') j++;
        let backslashes = 0;
        for (let k = j - 1; k >= i && script[k] === '\\'; k--) backslashes++;
        i = j;
        if (backslashes % 2 === 1 && i < n) {
          i++;
          continue;
        }
        break;
      }
      continue;
    }
    if (cmd === 'b' || cmd === 't' || cmd === 'T') {
      skipSpace();
      while (i < n && script[i] !== ';' && script[i] !== '\n' && script[i] !== '}' && !isSpace(script[i])) i++;
      continue;
    }
    if (cmd === ':') {
      skipSpace();
      while (i < n && script[i] !== ';' && script[i] !== '\n' && !isSpace(script[i])) i++;
      continue;
    }
    if (cmd === 'v') {
      restOfLine();
      continue;
    }
    if (cmd === 's') {
      const delim = script[i++];
      if (delim === undefined || delim === '\n' || delim === '\\') {
        out.confused = true;
        break;
      }
      if (part(delim) === null || part(delim) === null) {
        out.confused = true;
        break;
      }
      // the flags: g p i I m M e, a number, and `w FILE`, which takes the rest of the line - glued or not
      for (;;) {
        const c = script[i];
        if (c === undefined) break;
        if (c === 'w') {
          i++;
          out.writes.push(...fileNames(restOfLine()));
          break;
        }
        if (c === 'e') out.executesPatternSpace = true;
        if (/[gpiImMe0-9]/.test(c)) {
          i++;
          continue;
        }
        break;
      }
      continue;
    }
    if (cmd === 'y') {
      const delim = script[i++];
      if (delim === undefined || delim === '\n' || delim === '\\' || part(delim) === null || part(delim) === null) {
        out.confused = true;
        break;
      }
      continue;
    }
    // a command letter sed does not have: the thread is lost
    out.confused = true;
    break;
  }
  return out;
}
