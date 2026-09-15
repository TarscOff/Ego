// Minimal deterministic YAML subset parser for control-plane frontmatter.
// Supported: block maps, block lists, nested indentation, scalars (string, number, boolean, null),
// single/double quoted strings, inline flow lists `[a, b]` and flow maps `{a: 1}` (one level), comments.
// Unsupported constructs raise a ControlPlaneSyntaxError so a malformed file fails closed (decision Q10).

export class YamlSyntaxError extends Error {
  readonly line: number;
  constructor(message: string, line: number) {
    super(`${message} (line ${line})`);
    this.name = 'YamlSyntaxError';
    this.line = line;
  }
}

export type YamlValue = string | number | boolean | null | YamlValue[] | { [key: string]: YamlValue };

interface Line {
  indent: number;
  text: string;
  no: number;
}

function stripComment(text: string): string {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    else if (ch === '#' && !inSingle && !inDouble && (i === 0 || /\s/.test(text[i - 1] ?? ''))) {
      return text.slice(0, i).trimEnd();
    }
  }
  return text.trimEnd();
}

function tokenize(source: string): Line[] {
  const out: Line[] = [];
  const raw = source.split(/\r?\n/);
  for (let i = 0; i < raw.length; i++) {
    const original = raw[i] ?? '';
    if (original.includes('\t')) throw new YamlSyntaxError('tabs are not allowed for indentation', i + 1);
    const text = stripComment(original);
    if (text.trim() === '') continue;
    const indent = text.length - text.trimStart().length;
    out.push({ indent, text: text.trim(), no: i + 1 });
  }
  return out;
}

export function parseScalar(raw: string, line: number): YamlValue {
  const s = raw.trim();
  if (s === '' || s === '~' || s === 'null') return null;
  if (s === 'true') return true;
  if (s === 'false') return false;
  if (/^-?\d+$/.test(s)) return Number.parseInt(s, 10);
  if (/^-?\d+\.\d+$/.test(s)) return Number.parseFloat(s);
  if (s.startsWith('"')) {
    if (!s.endsWith('"') || s.length < 2)
      throw new YamlSyntaxError('unterminated double-quoted string', line);
    return JSON.parse(s) as string;
  }
  if (s.startsWith("'")) {
    if (!s.endsWith("'") || s.length < 2)
      throw new YamlSyntaxError('unterminated single-quoted string', line);
    return s.slice(1, -1).replace(/''/g, "'");
  }
  if (s.startsWith('[')) return parseFlowList(s, line);
  if (s.startsWith('{')) return parseFlowMap(s, line);
  if (s.startsWith('&') || s.startsWith('*') || s.startsWith('!') || s.startsWith('|') || s.startsWith('>')) {
    throw new YamlSyntaxError(`unsupported YAML construct: ${s[0]}`, line);
  }
  return s;
}

function splitFlow(inner: string, line: number): string[] {
  const parts: string[] = [];
  let depth = 0;
  let cur = '';
  let inSingle = false;
  let inDouble = false;
  for (const ch of inner) {
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    if (!inSingle && !inDouble) {
      if (ch === '[' || ch === '{') depth++;
      if (ch === ']' || ch === '}') depth--;
      if (ch === ',' && depth === 0) {
        parts.push(cur);
        cur = '';
        continue;
      }
    }
    cur += ch;
  }
  if (depth !== 0 || inSingle || inDouble) throw new YamlSyntaxError('unbalanced flow collection', line);
  if (cur.trim() !== '') parts.push(cur);
  return parts;
}

function parseFlowList(s: string, line: number): YamlValue[] {
  if (!s.endsWith(']')) throw new YamlSyntaxError('unterminated flow list', line);
  const inner = s.slice(1, -1).trim();
  if (inner === '') return [];
  return splitFlow(inner, line).map((p) => parseScalar(p, line));
}

function parseFlowMap(s: string, line: number): { [key: string]: YamlValue } {
  if (!s.endsWith('}')) throw new YamlSyntaxError('unterminated flow map', line);
  const inner = s.slice(1, -1).trim();
  const out: { [key: string]: YamlValue } = {};
  if (inner === '') return out;
  for (const part of splitFlow(inner, line)) {
    const idx = part.indexOf(':');
    if (idx < 0) throw new YamlSyntaxError('flow map entry without colon', line);
    const key = part
      .slice(0, idx)
      .trim()
      .replace(/^['"]|['"]$/g, '');
    out[key] = parseScalar(part.slice(idx + 1), line);
  }
  return out;
}

const KEY_RE = /^([A-Za-z0-9_.\-/$@]+|"[^"]*"|'[^']*')\s*:(?:\s+(.*))?$/;

function parseBlock(lines: Line[], start: number, indent: number): { value: YamlValue; next: number } {
  const first = lines[start];
  if (!first) return { value: null, next: start };
  if (first.text.startsWith('- ') || first.text === '-') return parseList(lines, start, indent);
  return parseMap(lines, start, indent);
}

function parseList(lines: Line[], start: number, indent: number): { value: YamlValue[]; next: number } {
  const out: YamlValue[] = [];
  let i = start;
  while (i < lines.length) {
    const ln = lines[i]!;
    if (ln.indent < indent) break;
    if (ln.indent > indent) throw new YamlSyntaxError('unexpected indentation in list', ln.no);
    if (!(ln.text.startsWith('- ') || ln.text === '-')) break;
    const rest = ln.text === '-' ? '' : ln.text.slice(2).trim();
    if (rest === '') {
      const next = lines[i + 1];
      if (next && next.indent > indent) {
        const sub = parseBlock(lines, i + 1, next.indent);
        out.push(sub.value);
        i = sub.next;
      } else {
        out.push(null);
        i++;
      }
      continue;
    }
    const m = KEY_RE.exec(rest);
    if (
      m &&
      !rest.startsWith('[') &&
      !rest.startsWith('{') &&
      !rest.startsWith('"') &&
      !rest.startsWith("'")
    ) {
      // inline map item: "- key: value" possibly followed by more keys at indent+2
      const virtualIndent = indent + 2;
      const synthetic: Line = { indent: virtualIndent, text: rest, no: ln.no };
      const following: Line[] = [synthetic];
      let j = i + 1;
      while (j < lines.length && lines[j]!.indent >= virtualIndent) {
        following.push(lines[j]!);
        j++;
      }
      const sub = parseMap(following, 0, virtualIndent);
      out.push(sub.value);
      i = j;
      continue;
    }
    out.push(parseScalar(rest, ln.no));
    i++;
  }
  return { value: out, next: i };
}

function parseMap(
  lines: Line[],
  start: number,
  indent: number,
): { value: { [key: string]: YamlValue }; next: number } {
  const out: { [key: string]: YamlValue } = {};
  let i = start;
  while (i < lines.length) {
    const ln = lines[i]!;
    if (ln.indent < indent) break;
    if (ln.indent > indent) throw new YamlSyntaxError('unexpected indentation in map', ln.no);
    if (ln.text.startsWith('- ')) throw new YamlSyntaxError('list item where a map key was expected', ln.no);
    const m = KEY_RE.exec(ln.text);
    if (!m) throw new YamlSyntaxError(`cannot parse map entry: ${ln.text}`, ln.no);
    const key = m[1]!.replace(/^['"]|['"]$/g, '');
    if (Object.prototype.hasOwnProperty.call(out, key))
      throw new YamlSyntaxError(`duplicate key: ${key}`, ln.no);
    const inline = m[2];
    if (inline !== undefined && /^[|>][+-]?$/.test(inline.trim())) {
      // block scalar: collect following lines indented deeper than the key
      const folded = inline.trim().startsWith('>');
      const chomp = inline.trim().endsWith('-') ? 'strip' : inline.trim().endsWith('+') ? 'keep' : 'clip';
      const parts: string[] = [];
      let j = i + 1;
      while (j < lines.length && lines[j]!.indent > indent) {
        parts.push(lines[j]!.text);
        j++;
      }
      let text = folded ? parts.join(' ') : parts.join('\n');
      if (chomp !== 'strip' && !folded) text += '\n';
      out[key] = text;
      i = j;
      continue;
    }
    if (inline !== undefined && inline.trim() !== '') {
      out[key] = parseScalar(inline, ln.no);
      i++;
      continue;
    }
    const next = lines[i + 1];
    if (next && next.indent > indent) {
      const sub = parseBlock(lines, i + 1, next.indent);
      out[key] = sub.value;
      i = sub.next;
    } else if (next && next.indent === indent && (next.text.startsWith('- ') || next.text === '-')) {
      // list at the same indentation as the key (common YAML style)
      const sub = parseList(lines, i + 1, indent);
      out[key] = sub.value;
      i = sub.next;
    } else {
      out[key] = null;
      i++;
    }
  }
  return { value: out, next: i };
}

export function parseYaml(source: string): YamlValue {
  const lines = tokenize(source);
  if (lines.length === 0) return {};
  const first = lines[0]!;
  const { value, next } = parseBlock(lines, 0, first.indent);
  if (next < lines.length) {
    throw new YamlSyntaxError(`trailing content could not be parsed: ${lines[next]!.text}`, lines[next]!.no);
  }
  return value;
}

/** Deterministic YAML emitter for generated files (sorted keys, block style). */
export function stringifyYaml(value: YamlValue, indent = 0): string {
  const pad = ' '.repeat(indent);
  if (value === null) return 'null';
  if (typeof value === 'boolean' || typeof value === 'number') return String(value);
  if (typeof value === 'string') return needsQuotes(value) ? JSON.stringify(value) : value;
  if (Array.isArray(value)) {
    if (value.length === 0) return '[]';
    return value
      .map((v) => {
        if (v !== null && typeof v === 'object') {
          const body = stringifyYaml(v, indent + 2);
          return `${pad}- ${body.trimStart()}`;
        }
        return `${pad}- ${stringifyYaml(v, indent + 2)}`;
      })
      .join('\n');
  }
  const keys = Object.keys(value).sort();
  if (keys.length === 0) return '{}';
  return keys
    .map((k) => {
      const v = value[k]!;
      if (
        v !== null &&
        typeof v === 'object' &&
        (Array.isArray(v) ? v.length > 0 : Object.keys(v).length > 0)
      ) {
        return `${pad}${k}:\n${stringifyYaml(v, indent + 2)}`;
      }
      return `${pad}${k}: ${stringifyYaml(v, indent + 2)}`;
    })
    .join('\n');
}

function needsQuotes(s: string): boolean {
  if (s === '') return true;
  if (/^(true|false|null|~|-?\d+(\.\d+)?)$/.test(s)) return true;
  if (/^[\s\-?:,[\]{}#&*!|>'"%@`]/.test(s)) return true;
  if (/[:#]\s|\s$|^\s|\n/.test(s)) return true;
  return false;
}
