// Structured parsing and redaction of curl invocations (decision Q18: structured parsers run before pattern detectors).
// Never logs or returns the original secret value.

export interface CurlRedaction {
  text: string;
  findings: Array<{ kind: string; count: number }>;
}

const AUTH_HEADER_RE = /^(authorization|proxy-authorization|x-api-key|x-auth-token|x-access-token|api-key|apikey|x-token|cookie|set-cookie)\s*:\s*/i;
const SENSITIVE_KEYS = /^(token|access_token|refresh_token|id_token|api_key|apikey|key|secret|client_secret|password|passwd|pwd|auth|session|sig|signature)$/i;

function shellTokens(s: string): Array<{ raw: string; value: string; start: number; end: number }> {
  const out: Array<{ raw: string; value: string; start: number; end: number }> = [];
  let i = 0;
  while (i < s.length) {
    while (i < s.length && /\s/.test(s[i]!)) i++;
    if (i >= s.length) break;
    const start = i;
    let value = '';
    let quote: string | null = null;
    while (i < s.length) {
      const ch = s[i]!;
      if (quote) {
        if (ch === quote) {
          quote = null;
          i++;
          continue;
        }
        if (ch === '\\' && quote === '"' && i + 1 < s.length) {
          value += s[i + 1]!;
          i += 2;
          continue;
        }
        value += ch;
        i++;
        continue;
      }
      if (ch === "'" || ch === '"') {
        quote = ch;
        i++;
        continue;
      }
      if (ch === '\\' && i + 1 < s.length) {
        value += s[i + 1]!;
        i += 2;
        continue;
      }
      if (/\s/.test(ch)) break;
      value += ch;
      i++;
    }
    out.push({ raw: s.slice(start, i), value, start, end: i });
  }
  return out;
}

function redactHeaderValue(v: string): string | null {
  const m = AUTH_HEADER_RE.exec(v);
  if (!m) return null;
  const name = v.slice(0, m[0].length);
  return `${name}[REDACTED:${m[1]!.toLowerCase()}]`;
}

function redactUserPass(v: string): string {
  const idx = v.indexOf(':');
  return idx < 0 ? '[REDACTED:credentials]' : `${v.slice(0, idx)}:[REDACTED:password]`;
}

function redactDataBody(v: string): { text: string; hit: boolean } {
  let hit = false;
  let text = v;
  // key=value pairs
  text = text.replace(/(^|[&\s])([A-Za-z0-9_.-]+)=([^&\s]+)/g, (all, pre: string, key: string, val: string) => {
    if (SENSITIVE_KEYS.test(key) || /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(val)) {
      hit = true;
      return `${pre}${key}=[REDACTED:${key.toLowerCase()}]`;
    }
    return all;
  });
  // JSON string values for sensitive keys
  text = text.replace(/"([A-Za-z0-9_.-]+)"\s*:\s*"([^"]*)"/g, (all, key: string, _val: string) => {
    if (SENSITIVE_KEYS.test(key)) {
      hit = true;
      return `"${key}": "[REDACTED:${key.toLowerCase()}]"`;
    }
    return all;
  });
  return { text, hit };
}

function redactUrl(v: string): { text: string; hit: boolean } {
  let hit = false;
  let text = v.replace(/^([a-z][a-z0-9+.-]*:\/\/[^:\/\s@]+:)([^@\/\s]+)(@)/i, (_all, pre: string, _pass: string, at: string) => {
    hit = true;
    return `${pre}[REDACTED:url-password]${at}`;
  });
  text = text.replace(/([?&])([A-Za-z0-9_.-]+)=([^&\s]+)/g, (all, sep: string, key: string, _val: string) => {
    if (SENSITIVE_KEYS.test(key)) {
      hit = true;
      return `${sep}${key}=[REDACTED:${key.toLowerCase()}]`;
    }
    return all;
  });
  return { text, hit };
}

const HEADER_FLAGS = new Set(['-H', '--header']);
const USER_FLAGS = new Set(['-u', '--user', '--proxy-user', '-U']);
const COOKIE_FLAGS = new Set(['-b', '--cookie']);
const DATA_FLAGS = new Set(['-d', '--data', '--data-raw', '--data-binary', '--data-urlencode', '-F', '--form', '--form-string', '--json']);
const OAUTH_FLAGS = new Set(['--oauth2-bearer']);

/** Redacts every curl invocation found in `text`. Lines that do not invoke curl are returned unchanged. */
export function redactCurl(text: string): CurlRedaction {
  const counts = new Map<string, number>();
  const bump = (k: string) => counts.set(k, (counts.get(k) ?? 0) + 1);
  const lines = text.split('\n');
  const outLines = lines.map((line) => {
    if (!/(^|[\s;&|(])curl(\s|$)/.test(line)) return line;
    const tokens = shellTokens(line);
    let out = '';
    let last = 0;
    let expect: 'header' | 'user' | 'cookie' | 'data' | 'bearer' | null = null;
    for (const t of tokens) {
      let replacement: string | null = null;
      if (expect === 'header') {
        const r = redactHeaderValue(t.value);
        if (r) {
          replacement = r;
          bump('curl.header');
        }
        expect = null;
      } else if (expect === 'user') {
        replacement = redactUserPass(t.value);
        bump('curl.user');
        expect = null;
      } else if (expect === 'cookie') {
        replacement = '[REDACTED:cookie]';
        bump('curl.cookie');
        expect = null;
      } else if (expect === 'bearer') {
        replacement = '[REDACTED:bearer]';
        bump('curl.bearer');
        expect = null;
      } else if (expect === 'data') {
        const r = redactDataBody(t.value);
        if (r.hit) {
          replacement = r.text;
          bump('curl.data');
        }
        expect = null;
      } else if (HEADER_FLAGS.has(t.value)) expect = 'header';
      else if (USER_FLAGS.has(t.value)) expect = 'user';
      else if (COOKIE_FLAGS.has(t.value)) expect = 'cookie';
      else if (DATA_FLAGS.has(t.value)) expect = 'data';
      else if (OAUTH_FLAGS.has(t.value)) expect = 'bearer';
      else if (/^-H(.+)/.test(t.raw) && t.raw.length > 2 && !t.raw.startsWith('-H ')) {
        const r = redactHeaderValue(t.value.slice(2));
        if (r) {
          replacement = `-H${r}`;
          bump('curl.header');
        }
      } else if (/^-u.+/.test(t.raw) && !t.raw.startsWith('--')) {
        replacement = `-u${redactUserPass(t.value.slice(2))}`;
        bump('curl.user');
      } else if (/^[a-z][a-z0-9+.-]*:\/\//i.test(t.value)) {
        const r = redactUrl(t.value);
        if (r.hit) {
          replacement = r.text;
          bump('curl.url');
        }
      } else if (t.value.startsWith('--user=') || t.value.startsWith('--header=') || t.value.startsWith('--data=')) {
        const [flag, ...rest] = t.value.split('=');
        const v = rest.join('=');
        if (flag === '--user') {
          replacement = `--user=${redactUserPass(v)}`;
          bump('curl.user');
        } else if (flag === '--header') {
          const r = redactHeaderValue(v);
          if (r) {
            replacement = `--header=${r}`;
            bump('curl.header');
          }
        } else {
          const r = redactDataBody(v);
          if (r.hit) {
            replacement = `--data=${r.text}`;
            bump('curl.data');
          }
        }
      }
      out += line.slice(last, t.start);
      out += replacement !== null ? quoteIfNeeded(replacement, t.raw) : t.raw;
      last = t.end;
    }
    out += line.slice(last);
    return out;
  });
  return { text: outLines.join('\n'), findings: [...counts.entries()].map(([kind, count]) => ({ kind, count })) };
}

function quoteIfNeeded(value: string, originalRaw: string): string {
  if (originalRaw.startsWith("'") || originalRaw.startsWith('"')) return `${originalRaw[0]}${value}${originalRaw[0]}`;
  return /[\s;&|]/.test(value) ? `'${value}'` : value;
}
