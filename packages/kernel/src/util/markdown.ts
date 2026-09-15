// Markdown control-plane document model: YAML frontmatter + headed sections + checklist items.
// Deterministic, dependency-free. Malformed documents throw so enforcement never silently weakens (Q10).
import { parseYaml, type YamlValue, YamlSyntaxError } from './yaml.ts';

export class ControlPlaneSyntaxError extends Error {
  readonly file: string;
  readonly line: number;
  constructor(file: string, message: string, line: number) {
    super(`${file}:${line}: ${message}`);
    this.name = 'ControlPlaneSyntaxError';
    this.file = file;
    this.line = line;
  }
}

export interface ChecklistItem {
  /** true = [x], false = [ ] */
  checked: boolean;
  /** stable machine identifier taken from the first inline code span; null when the item has none */
  id: string | null;
  /** text after the identifier (description) */
  text: string;
  line: number;
}

export interface Section {
  level: number;
  title: string;
  /** normalized: lowercase, trimmed, punctuation collapsed */
  key: string;
  line: number;
  items: ChecklistItem[];
  bullets: string[];
  paragraphs: string[];
  children: Section[];
}

export interface MarkdownDoc {
  file: string;
  frontmatter: { [key: string]: YamlValue };
  title: string | null;
  sections: Section[];
  /** flat list of all sections in document order */
  allSections: Section[];
  body: string;
}

export function sectionKey(title: string): string {
  return title
    .toLowerCase()
    .replace(/`/g, '')
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();
}

const CHECK_RE = /^\s*[-*]\s+\[( |x|X)\]\s+(.*)$/;
const BULLET_RE = /^\s*[-*]\s+(?!\[( |x|X)\])(.*)$/;
const HEADING_RE = /^(#{1,6})\s+(.*?)\s*#*\s*$/;
const CODE_ID_RE = /`([^`]+)`/;

export function parseMarkdown(file: string, source: string): MarkdownDoc {
  const lines = source.split(/\r?\n/);
  let i = 0;
  let frontmatter: { [key: string]: YamlValue } = {};
  if (lines[0]?.trim() === '---') {
    const end = lines.indexOf('---', 1);
    if (end < 0) throw new ControlPlaneSyntaxError(file, 'unterminated frontmatter', 1);
    const fm = lines.slice(1, end).join('\n');
    try {
      const parsed = parseYaml(fm);
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new ControlPlaneSyntaxError(file, 'frontmatter must be a map', 1);
      }
      frontmatter = parsed;
    } catch (e) {
      if (e instanceof YamlSyntaxError)
        throw new ControlPlaneSyntaxError(file, `frontmatter: ${e.message}`, e.line + 1);
      throw e;
    }
    i = end + 1;
  }
  const body = lines.slice(i).join('\n');
  const root: Section = {
    level: 0,
    title: '',
    key: '',
    line: i + 1,
    items: [],
    bullets: [],
    paragraphs: [],
    children: [],
  };
  const stack: Section[] = [root];
  const all: Section[] = [];
  let title: string | null = null;
  let inFence = false;
  let para: string[] = [];
  const flushPara = () => {
    if (para.length) {
      stack[stack.length - 1]!.paragraphs.push(para.join(' ').trim());
      para = [];
    }
  };
  for (; i < lines.length; i++) {
    const ln = lines[i] ?? '';
    const no = i + 1;
    if (/^\s*(```|~~~)/.test(ln)) {
      inFence = !inFence;
      flushPara();
      continue;
    }
    if (inFence) continue;
    const h = HEADING_RE.exec(ln);
    if (h) {
      flushPara();
      const level = h[1]!.length;
      const t = h[2]!.trim();
      if (level === 1 && title === null) title = t;
      const sec: Section = {
        level,
        title: t,
        key: sectionKey(t),
        line: no,
        items: [],
        bullets: [],
        paragraphs: [],
        children: [],
      };
      while (stack.length > 1 && stack[stack.length - 1]!.level >= level) stack.pop();
      stack[stack.length - 1]!.children.push(sec);
      stack.push(sec);
      all.push(sec);
      continue;
    }
    const c = CHECK_RE.exec(ln);
    if (c) {
      flushPara();
      const text = c[2]!.trim();
      const idm = CODE_ID_RE.exec(text);
      const id = idm ? idm[1]!.trim() : null;
      const rest = idm
        ? text
            .replace(idm[0], '')
            .replace(/^\s*[—–-]\s*/, '')
            .trim()
        : text;
      stack[stack.length - 1]!.items.push({ checked: c[1] !== ' ', id, text: rest, line: no });
      continue;
    }
    const b = BULLET_RE.exec(ln);
    if (b) {
      flushPara();
      stack[stack.length - 1]!.bullets.push(b[2]!.trim());
      continue;
    }
    if (ln.trim() === '') {
      flushPara();
      continue;
    }
    para.push(ln.trim());
  }
  flushPara();
  return { file, frontmatter, title, sections: root.children, allSections: all, body };
}

export function findSection(doc: MarkdownDoc, ...keys: string[]): Section | undefined {
  const wanted = keys.map(sectionKey);
  return doc.allSections.find((s) => wanted.includes(s.key));
}

export function requireString(doc: MarkdownDoc, key: string): string {
  const v = doc.frontmatter[key];
  if (typeof v !== 'string' || v.trim() === '') {
    throw new ControlPlaneSyntaxError(doc.file, `frontmatter field "${key}" must be a non-empty string`, 1);
  }
  return v;
}

export function optionalString(doc: MarkdownDoc, key: string): string | undefined {
  const v = doc.frontmatter[key];
  if (v === undefined || v === null) return undefined;
  if (typeof v !== 'string')
    throw new ControlPlaneSyntaxError(doc.file, `frontmatter field "${key}" must be a string`, 1);
  return v;
}

export function optionalStringList(doc: MarkdownDoc, key: string): string[] {
  const v = doc.frontmatter[key];
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v) || !v.every((x) => typeof x === 'string')) {
    throw new ControlPlaneSyntaxError(doc.file, `frontmatter field "${key}" must be a list of strings`, 1);
  }
  return v as string[];
}

export function optionalBoolean(doc: MarkdownDoc, key: string, def = false): boolean {
  const v = doc.frontmatter[key];
  if (v === undefined || v === null) return def;
  if (typeof v !== 'boolean')
    throw new ControlPlaneSyntaxError(doc.file, `frontmatter field "${key}" must be a boolean`, 1);
  return v;
}

export function optionalNumber(doc: MarkdownDoc, key: string): number | undefined {
  const v = doc.frontmatter[key];
  if (v === undefined || v === null) return undefined;
  if (typeof v !== 'number')
    throw new ControlPlaneSyntaxError(doc.file, `frontmatter field "${key}" must be a number`, 1);
  return v;
}
