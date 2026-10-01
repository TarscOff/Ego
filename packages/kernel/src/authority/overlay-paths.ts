// HOW A PROJECT'S PATH RULE IS READ (closure audit 2026-10-01, wave 3, "overlay").
//
// A project overlay may add rules, and may only narrow: `{capability: fs.credential-store.read, tool: Read, path: 'secrets/**'}` says
// that tree is a credential store. The rule is a glob over the path relative to the workspace root, and the evaluator's glob is a
// whole-path match - which is not what the person who wrote `secrets/**` or `service-account.json` meant, and not what a
// `.gitignore` line means either. Written as they would write it in a `.gitignore`, every one of these protected nothing:
//
//   service-account.json   matched only a file of that name at the ROOT        (it is a name: it matches at any depth)
//   secrets/**             matched the files in it, never `secrets` itself        (`grep -r x secrets`, `cp -r secrets /tmp`)
//   secrets                matched a file named `secrets`, never what is below it (a directory's contents are the directory's)
//   vault/   ./certs/**    matched nothing at all                                  (a trailing slash is a directory; `./` is nothing)
//   config/{prod,stage}.yml  braces were literal characters                        (a brace is a choice)
//   [Pp]rivate/**          brackets were literal characters                        (a bracket is a class)
//
// So the rule is read ONCE, here, when the overlay is compiled, and the table holds the globs it means. The grammar is
// the one a `.gitignore` has, because it is the one an author already knows:
//
//   - a pattern with no `/` in it (after a trailing one is taken off) is a NAME and matches at any depth;
//   - a pattern with a `/` in it is anchored to the workspace root (`~/` to the home directory, `/` to the filesystem);
//   - a pattern that names a directory - it ends in `/` or `/**` - is the directory ITSELF and everything below it;
//   - every other pattern is a file or a directory, and what is below it is protected with it;
//   - `{a,b}` is a choice and `[abc]` a class.
//
// WHAT THIS MODULE DOES NOT DO is decide what a rule costs: it turns the text an author wrote into the globs the evaluator matches.

/** how many alternatives one pattern may expand to: a brace is a choice, not a way to make the table large */
const MAX_ALTERNATIVES = 64;

/** `{a,b}{c,d}` -> ac, ad, bc, bd. Nested braces are expanded innermost-first; a brace with no comma is literal. */
export function expandPatternBraces(pattern: string): string[] {
  const open = pattern.indexOf('{');
  if (open < 0) return [pattern];
  let depth = 0;
  let close = -1;
  const commas: number[] = [];
  for (let i = open; i < pattern.length; i++) {
    const c = pattern[i]!;
    if (c === '{') depth++;
    else if (c === '}' && --depth === 0) {
      close = i;
      break;
    } else if (c === ',' && depth === 1) commas.push(i);
  }
  // an unclosed brace, or one with a single alternative, is text
  if (close < 0 || commas.length === 0) {
    const rest = expandPatternBraces(pattern.slice(open + 1));
    return rest.map((r) => pattern.slice(0, open + 1) + r);
  }
  const cuts = [open, ...commas, close];
  const head = pattern.slice(0, open);
  const tail = pattern.slice(close + 1);
  const out: string[] = [];
  for (let k = 0; k < cuts.length - 1; k++) {
    const alt = pattern.slice(cuts[k]! + 1, cuts[k + 1]!);
    for (const expanded of expandPatternBraces(head + alt + tail)) {
      out.push(expanded);
      if (out.length >= MAX_ALTERNATIVES) return out;
    }
  }
  return out;
}

/** The globs the evaluator matches for one path rule of an overlay. Never empty; the first is the one that names the rule. */
export function overlayPathGlobs(pattern: string): string[] {
  const out: string[] = [];
  for (const alt of expandPatternBraces(pattern.trim())) {
    let p = alt.replace(/\/{2,}/g, '/');
    // the anchor: `~/` is the home directory, `/` the filesystem, anything else the workspace
    let anchor = '';
    if (p.startsWith('~/')) {
      anchor = '~/';
      p = p.slice(2);
    } else if (p.startsWith('/')) {
      anchor = '/';
      p = p.slice(1);
    }
    p = p.replace(/^(\.\/)+/, '');
    const directory = p.endsWith('/');
    p = p.replace(/\/+$/, '');
    if (p === '') continue;
    // a NAME - no slash left - is matched at any depth, as a `.gitignore` line is; a path with a slash in it is anchored
    const anchored = anchor !== '' || p.includes('/') || p.startsWith('**');
    const base = anchored ? p : `**/${p}`;
    const globs = base.endsWith('/**') ? [base, base.slice(0, -3)] : directory || !base.endsWith('**') ? [base, `${base}/**`] : [base];
    for (const g of globs) out.push(anchor + g);
  }
  return [...new Set(out)];
}
