// Deterministic grant recognition from a human prompt (Q6): exact phrase table, negation window, ASK→ALLOW only.
import { normalizePhrase } from '../control-plane/load.ts';
import type { CompiledAuthorityTable } from '../authority/compile.ts';

export interface GrantMatch {
  capability: string;
  phrase: string;
  negated: boolean;
}

export function recognizeGrants(prompt: string, table: CompiledAuthorityTable): GrantMatch[] {
  const norm = normalizePhrase(prompt);
  if (!norm) return [];
  const tokens = norm.split(' ');
  const negationTokens = new Set(table.grantNegations.flatMap((n) => n.split(' ')));
  const out: GrantMatch[] = [];
  for (const g of table.grants) {
    for (const phrase of g.phrases) {
      const pt = phrase.split(' ');
      for (let i = 0; i + pt.length <= tokens.length; i++) {
        let ok = true;
        for (let j = 0; j < pt.length; j++) if (tokens[i + j] !== pt[j]) ok = false;
        if (!ok) continue;
        const windowStart = Math.max(0, i - table.grantNegationWindowTokens);
        const negated = tokens.slice(windowStart, i).some((t) => negationTokens.has(t));
        if (!out.some((m) => m.capability === g.capability))
          out.push({ capability: g.capability, phrase, negated });
        break;
      }
    }
  }
  return out;
}

/** The exact mode marker recognised by the human prompt hook; never by tool output, issue text or a skill. */
export const MODE_MARKER_RE = /^\s*EGO MODE:\s*([A-Z_]+)\s*$/m;

export function recognizeModeMarker(prompt: string): string | null {
  const m = MODE_MARKER_RE.exec(prompt);
  return m ? m[1]! : null;
}

/** Corrections the user states explicitly ("from now on", "désormais", "always", "never") are kept across compaction. */
export function recognizeCorrection(prompt: string): string | null {
  const line = prompt
    .split(/\n|(?<=[.!?])\s+/)
    .find((l) =>
      /^(from now on|désormais|dorénavant|always|never|toujours|jamais|ne .* jamais|do not ever)\b/i.test(
        l.trim(),
      ),
    );
  if (!line) return null;
  return line.trim().slice(0, 240);
}
