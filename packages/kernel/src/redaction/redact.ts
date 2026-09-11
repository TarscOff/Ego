// Redaction engine: structured passes (curl, URLs) then taxonomy detectors. The original value is never included in
// findings or logs; only detector ids and counts are reported (decision Q18 and section 6 of the master prompt).
import type { SecretDetector, SecretsDoc, Severity } from '../control-plane/types.ts';
import { redactCurl } from './curl.ts';

export interface RedactionFinding {
  detector: string;
  family: string;
  severity: Severity;
  count: number;
}

export interface RedactionResult {
  text: string;
  findings: RedactionFinding[];
  /** true when any finding has severity block */
  blocked: boolean;
  changed: boolean;
}

export interface RedactOptions {
  /** treat the input as file content (enables file-only detectors) */
  isFile?: boolean;
  /** overlay severities by detector id; may raise but never lower a locked minimum */
  overlaySeverities?: Record<string, Severity>;
  /** additional detectors from an overlay */
  extraDetectors?: SecretDetector[];
}

export function allDetectors(docs: SecretsDoc[], extra: SecretDetector[] = []): SecretDetector[] {
  return [...docs.flatMap((d) => d.detectors), ...extra];
}

function effectiveSeverity(d: SecretDetector, overlay?: Record<string, Severity>): Severity {
  const requested = overlay?.[d.id];
  if (!requested) return d.severity;
  if (d.locked && d.severity === 'block' && requested === 'warn') return 'block'; // never lower a locked minimum
  return requested;
}

export function redact(input: string, detectors: SecretDetector[], opts: RedactOptions = {}): RedactionResult {
  const findings = new Map<string, RedactionFinding>();
  const note = (id: string, family: string, severity: Severity, n = 1) => {
    const f = findings.get(id);
    if (f) f.count += n;
    else findings.set(id, { detector: id, family, severity, count: n });
  };
  const curl = redactCurl(input);
  let text = curl.text;
  for (const f of curl.findings) note(f.kind, 'http', 'block', f.count);
  const list = [...detectors, ...(opts.extraDetectors ?? [])];
  for (const d of list) {
    if (d.onlyForFiles && !opts.isFile) continue;
    const severity = effectiveSeverity(d, opts.overlaySeverities);
    const re = new RegExp(d.pattern.source, d.pattern.flags.includes('g') ? d.pattern.flags : d.pattern.flags + 'g');
    if (d.wholeDocument) {
      if (re.test(text)) {
        note(d.id, d.family, severity);
        text = d.replacement;
        break;
      }
      continue;
    }
    let count = 0;
    text = text.replace(re, (...args: unknown[]) => {
      const match = args[0] as string;
      if (d.group > 0) {
        const groups = args.slice(1, -2) as Array<string | undefined>;
        const target = groups[d.group - 1];
        if (!target) return match;
        count++;
        return match.replace(target, d.replacement);
      }
      count++;
      return d.replacement;
    });
    if (count > 0) note(d.id, d.family, severity, count);
  }
  const all = [...findings.values()].sort((a, b) => a.detector.localeCompare(b.detector));
  return { text, findings: all, blocked: all.some((f) => f.severity === 'block'), changed: text !== input };
}

/** Returns true when a file name matches the sensitive-file patterns of the taxonomy. */
export function isSensitiveFileName(name: string, docs: SecretsDoc[]): boolean {
  const base = name.split('/').pop() ?? name;
  for (const doc of docs) {
    for (const pat of doc.sensitiveFiles) {
      if (pat === 'config') continue; // only sensitive under ~/.kube; handled by the path matchers
      const re = new RegExp('^' + pat.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$');
      if (re.test(base)) return true;
    }
  }
  return false;
}
