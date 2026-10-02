// Loads and validates the authored control plane. Every problem is collected and reported together; any problem
// fails the load so a malformed file can never silently weaken enforcement (decision Q10).
import { join, basename, relative } from 'node:path';
import { readdirSync } from 'node:fs';
import {
  parseMarkdown,
  requireString,
  optionalBoolean,
  optionalNumber,
  optionalString,
  optionalStringList,
  type MarkdownDoc,
  type Section,
} from '../util/markdown.ts';
import type { BoundedCommands } from './types.ts';
import { readText, isFile, isDir, toPosix } from '../util/fs.ts';
import { sha256Hex } from '../util/hash.ts';
import type { YamlValue } from '../util/yaml.ts';
import {
  CONTROL_KINDS,
  ControlPlaneValidationError,
  type AuthorityMode,
  type BudgetExceedAction,
  type CapabilityDecl,
  type CapabilityLock,
  type ContainmentControl,
  type ControlKind,
  type ExecutionBudgets,
  type CapabilityDoc,
  type ControlPlane,
  type CoordinationConstants,
  type GrantsDoc,
  type Intent,
  type LayerName,
  type LocalTargets,
  type Matcher,
  type MatcherTool,
  type ModelFlagPolicy,
  type OwnerWeakeningPolicy,
  type Profile,
  type ReleaseKey,
  type ReleaseKeysDoc,
  type SecretDetector,
  type SecretsDoc,
  type ShellUncertainPolicy,
  type SupportStatus,
  type UnavailablePolicy,
  type Verdict,
} from './types.ts';
import { HOST_IDS } from '../hosts/matrix.ts';
import { legacyNamingNotice, readFamilyValue, readLockValue } from './legacy-names.ts';

const SECTION_VERDICTS: Array<{ keys: string[]; verdict: Verdict }> = [
  { keys: ['allowed', 'allow'], verdict: 'ALLOW' },
  { keys: ['requires human approval', 'ask', 'requires approval', 'human approval'], verdict: 'ASK' },
  { keys: ['denied', 'deny'], verdict: 'DENY' },
];

const CAP_ID_RE = /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/;

/** Checklist items that sit before the first heading of the source (the title heading starts the first section). */
function preambleItems(source: string): Array<{ id: string; line: number }> {
  const out: Array<{ id: string; line: number }> = [];
  const lines = source.split('\n');
  let inFrontmatter = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (i === 0 && line.trim() === '---') {
      inFrontmatter = true;
      continue;
    }
    if (inFrontmatter) {
      if (line.trim() === '---') inFrontmatter = false;
      continue;
    }
    if (/^#{1,6}\s/.test(line)) break;
    const m = /^\s*[-*+]\s+(?:\[[ xX]\]\s+)?`([^`]+)`/.exec(line);
    if (m) out.push({ id: m[1]!, line: i + 1 });
  }
  return out;
}

function listMarkdown(dir: string): string[] {
  if (!isDir(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith('.md') && f.toLowerCase() !== 'readme.md')
    .sort()
    .map((f) => join(dir, f));
}

function asRecord(v: YamlValue | undefined): Record<string, YamlValue> | null {
  return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, YamlValue>) : null;
}

export function parseCapabilityDoc(
  file: string,
  source: string,
  layer: LayerName,
  problems: string[],
  notices: string[] = [],
): CapabilityDoc | null {
  let doc: MarkdownDoc;
  try {
    doc = parseMarkdown(file, source);
  } catch (e) {
    problems.push((e as Error).message);
    return null;
  }
  const schema = optionalString(doc, 'schema');
  if (schema !== 'ego.capabilities/1') {
    problems.push(`${file}: schema must be ego.capabilities/1`);
    return null;
  }
  const id = requireString(doc, 'id');
  // THE PREVIOUS SPELLING OF THE ADMIN_GOVERNED TIER IS A READ ALIAS (issue #16 section 12): a control-plane fork or an
  // organization file written under it keeps its meaning, and the file is named once in `notices` so it gets renamed.
  // The alias is translated here and nowhere else; everything below sees only the canonical values.
  const familyRead = readFamilyValue(requireString(doc, 'family'));
  const family = familyRead.value;
  const title = doc.title ?? optionalString(doc, 'title') ?? id;
  const absolute = optionalBoolean(doc, 'absolute', false);
  const lockRead = readLockValue(optionalString(doc, 'lock') ?? (absolute ? 'absolute' : 'none'));
  const lockRaw = lockRead.value;
  const spelled = [familyRead.legacy && 'family', lockRead.legacy && 'lock'].filter((x): x is string => !!x);
  if (spelled.length) notices.push(legacyNamingNotice(file, spelled.map((k) => `\`${k}:\``)));
  if (lockRaw !== 'absolute' && lockRaw !== 'admin-governed' && lockRaw !== 'none')
    problems.push(
      `${file}: lock must be absolute, admin-governed or none (HARD_LOCK and ADMIN_GOVERNED name the tiers; a file spells them absolute and admin-governed)`,
    );
  const lock: CapabilityLock = lockRaw === 'absolute' || lockRaw === 'admin-governed' ? lockRaw : 'none';
  if (absolute && lock !== 'absolute') problems.push(`${file}: absolute: true requires lock: absolute`);
  if (lock === 'absolute' && !absolute) problems.push(`${file}: lock: absolute requires absolute: true`);
  if (lock !== 'none' && layer !== 'core') problems.push(`${file}: only the core layer may declare a lock`);
  const capabilities: CapabilityDecl[] = [];
  const seen = new Map<string, Verdict>();
  const visit = (sec: Section) => {
    const match = SECTION_VERDICTS.find((s) => s.keys.includes(sec.key));
    if (!match) {
      // a checklist item with an identifier outside a verdict section would otherwise vanish silently (fail closed)
      for (const item of sec.items)
        if (item.id && CAP_ID_RE.test(item.id))
          problems.push(
            `${file}:${item.line}: capability "${item.id}" sits under heading "${sec.title}", which is not Allowed, Requires human approval or Denied`,
          );
    }
    if (match) {
      // a bullet that names a capability without a checkbox would vanish silently: fail closed
      for (const b of sec.bullets) {
        const bm = /^`([^`]+)`/.exec(b);
        if (bm && CAP_ID_RE.test(bm[1]!))
          problems.push(
            `${file}: capability "${bm[1]}" under "${sec.title}" has no checkbox (write \`- [x]\` to activate it or \`- [ ]\` to document it)`,
          );
        // a bullet whose checkbox is malformed (`- [-]`, `- [~]`, `- [ x]`, `- [xx]`) is not parsed as active and would
        // vanish: only `[ ]`, `[x]`, `[X]` count. Fail closed rather than silently drop the capability.
        const mm = /^\[[^\]]*\]\s*`([^`]+)`/.exec(b);
        if (mm && CAP_ID_RE.test(mm[1]!))
          problems.push(
            `${file}: capability "${mm[1]}" under "${sec.title}" has a malformed checkbox (only \`[ ]\`, \`[x]\`, \`[X]\` are valid)`,
          );
      }
      // a capability declaration written with an unsupported marker (ordered list `1.`/`1)`, or a stray checkbox) is
      // parsed as prose and would vanish with no error: fail closed rather than silently drop a deny
      for (const para of sec.paragraphs) {
        const pm = /^(\d+[.)]\s+)?(\[[ xX]\]\s+)?`([^`]+)`/.exec(para);
        if (pm && (pm[1] || pm[2]) && CAP_ID_RE.test(pm[3]!))
          problems.push(
            `${file}: capability "${pm[3]}" under "${sec.title}" uses an unsupported list marker or layout (write it as \`- [x]\` / \`- [ ]\`); as written it would not be enforced`,
          );
      }
      if (lock !== 'none' && match.verdict !== 'DENY')
        problems.push(`${file}:${sec.line}: a locked file may only contain a Denied section`);
      for (const item of sec.items) {
        if (!item.id) {
          problems.push(`${file}:${item.line}: checklist item has no \`identifier\``);
          continue;
        }
        if (!CAP_ID_RE.test(item.id)) {
          problems.push(`${file}:${item.line}: invalid capability identifier "${item.id}"`);
          continue;
        }
        if (seen.has(item.id)) {
          problems.push(`${file}:${item.line}: capability "${item.id}" appears in more than one section`);
          continue;
        }
        seen.set(item.id, match.verdict);
        if (!item.checked) {
          // an inactive item in a locked file would silently drop a deny: locked files carry active items only
          if (lock !== 'none')
            problems.push(
              `${file}:${item.line}: "${item.id}" is unchecked in a locked file; a locked deny is always active (remove the line to retire it, a MAJOR change)`,
            );
          continue; // documented but inactive at this layer
        }
        capabilities.push({
          id: item.id,
          verdict: match.verdict,
          description: item.text,
          family,
          file,
          line: item.line,
          absolute,
          lock,
        });
      }
    }
    sec.children.forEach(visit);
  };
  doc.sections.forEach(visit);
  // items before the first heading belong to no section: fail closed rather than vanish
  for (const item of preambleItems(source))
    if (item.id && CAP_ID_RE.test(item.id))
      problems.push(`${file}:${item.line}: capability "${item.id}" appears before the first heading`);
  if (lock !== 'none' && capabilities.length === 0)
    problems.push(`${file}: a locked file must declare at least one deny`);
  return { id, family, title, absolute, lock, layer, file, capabilities };
}

const BUDGET_KEYS: Array<{
  key: string;
  field: keyof Omit<ExecutionBudgets, 'onExceed' | 'maxTokens' | 'maxCostUsd'>;
  def: number;
}> = [
  { key: 'max_duration_minutes', field: 'maxDurationMinutes', def: 240 },
  { key: 'max_iterations', field: 'maxIterations', def: 60 },
  { key: 'max_tool_calls', field: 'maxToolCalls', def: 1500 },
  { key: 'max_retries_per_step', field: 'maxRetriesPerStep', def: 3 },
  { key: 'max_delegation_depth', field: 'maxDelegationDepth', def: 2 },
  { key: 'max_concurrent_subagents', field: 'maxConcurrentSubagents', def: 3 },
  { key: 'max_network_operations', field: 'maxNetworkOperations', def: 200 },
];

function parseBudgets(file: string, raw: YamlValue | undefined, problems: string[]): ExecutionBudgets {
  const r = asRecord(raw);
  if (!r) {
    problems.push(`${file}: budgets block is required (execution budgets are part of every profile)`);
    return {
      maxDurationMinutes: 240,
      maxIterations: 60,
      maxToolCalls: 1500,
      maxRetriesPerStep: 3,
      maxDelegationDepth: 2,
      maxConcurrentSubagents: 3,
      maxNetworkOperations: 200,
      maxTokens: null,
      maxCostUsd: null,
      onExceed: 'BLOCK',
    };
  }
  const out: Record<string, number | null | BudgetExceedAction> = {};
  for (const { key, field, def } of BUDGET_KEYS) {
    const v = r[key];
    if (v === undefined) {
      problems.push(`${file}: budgets.${key} is required`);
      out[field] = def;
    } else if (typeof v !== 'number' || !Number.isFinite(v) || v <= 0 || !Number.isInteger(v)) {
      problems.push(`${file}: budgets.${key} must be a positive integer`);
      out[field] = def;
    } else out[field] = v;
  }
  for (const [key, field] of [
    ['max_tokens', 'maxTokens'],
    ['max_cost_usd', 'maxCostUsd'],
  ] as const) {
    const v = r[key];
    if (v === undefined || v === null) out[field] = null;
    else if (typeof v !== 'number' || !Number.isFinite(v) || v <= 0) {
      problems.push(`${file}: budgets.${key} must be a positive number or null`);
      out[field] = null;
    } else out[field] = v;
  }
  const on = r['on_exceed'];
  if (on !== 'BLOCK' && on !== 'ESCALATE') {
    problems.push(`${file}: budgets.on_exceed must be BLOCK or ESCALATE`);
    out['onExceed'] = 'BLOCK';
  } else out['onExceed'] = on;
  for (const k of Object.keys(r))
    if (!BUDGET_KEYS.some((b) => b.key === k) && !['max_tokens', 'max_cost_usd', 'on_exceed'].includes(k))
      problems.push(`${file}: unknown budgets key "${k}"`);
  return out as unknown as ExecutionBudgets;
}

const SUPPORT: readonly SupportStatus[] = ['SUPPORTED', 'PARTIAL', 'UNAVAILABLE', 'UNVERIFIED'];

function parseContainment(file: string, problems: string[]): ContainmentControl[] {
  const doc = parseMarkdown(file, readText(file));
  if (optionalString(doc, 'schema') !== 'ego.containment/1') {
    problems.push(`${file}: schema must be ego.containment/1`);
    return [];
  }
  const raw = doc.frontmatter['controls'];
  if (!Array.isArray(raw)) {
    problems.push(`${file}: frontmatter "controls" must be a list`);
    return [];
  }
  const out: ContainmentControl[] = [];
  raw.forEach((entry, i) => {
    const c = asRecord(entry);
    if (!c || typeof c['id'] !== 'string' || typeof c['description'] !== 'string') {
      problems.push(`${file}: control #${i + 1} must have id and description`);
      return;
    }
    if (!CAP_ID_RE.test(c['id'])) problems.push(`${file}: invalid control identifier "${c['id']}"`);
    // Required, with no default: a control that did not say what it is would be reported under the word the loader
    // happened to pick, and "containment" is the word a reader trusts most.
    const kind = c['kind'];
    if (typeof kind !== 'string' || !(CONTROL_KINDS as readonly string[]).includes(kind))
      problems.push(`${file}: control ${c['id']} kind must be one of ${CONTROL_KINDS.join(', ')}`);
    const list = (k: string): string[] => {
      const v = c[k];
      if (v === undefined || v === null) return [];
      if (!Array.isArray(v) || !v.every((x) => typeof x === 'string')) {
        problems.push(`${file}: control ${c['id']} ${k} must be a list of profile ids`);
        return [];
      }
      return v as string[];
    };
    const hosts: Record<string, SupportStatus> = {};
    const h = asRecord(c['hosts']);
    if (!h) problems.push(`${file}: control ${c['id']} must declare hosts`);
    else {
      for (const id of HOST_IDS)
        if (!(id in h)) problems.push(`${file}: control ${c['id']} has no status for host ${id}`);
      for (const [hid, st] of Object.entries(h)) {
        if (!(HOST_IDS as readonly string[]).includes(hid))
          problems.push(`${file}: control ${c['id']} references unknown host "${hid}"`);
        else if (typeof st !== 'string' || !SUPPORT.includes(st as SupportStatus))
          problems.push(
            `${file}: control ${c['id']} host ${hid} status must be one of ${SUPPORT.join(', ')}`,
          );
        else hosts[hid] = st as SupportStatus;
      }
    }
    out.push({
      id: c['id'],
      kind: kind as ControlKind,
      description: c['description'],
      requiredIn: list('required_in'),
      recommendedIn: list('recommended_in'),
      hosts,
      file,
    });
  });
  return out;
}

function parseMatchers(file: string, problems: string[]): Matcher[] {
  const doc = parseMarkdown(file, readText(file));
  if (optionalString(doc, 'schema') !== 'ego.matchers/1') {
    problems.push(`${file}: schema must be ego.matchers/1`);
    return [];
  }
  const raw = doc.frontmatter['matchers'];
  if (!Array.isArray(raw)) {
    problems.push(`${file}: frontmatter "matchers" must be a list`);
    return [];
  }
  const out: Matcher[] = [];
  raw.forEach((entry, index) => {
    const m = asRecord(entry);
    if (!m) {
      problems.push(`${file}: matcher #${index + 1} is not a map`);
      return;
    }
    const capability = typeof m['capability'] === 'string' ? m['capability'] : '';
    const tool = typeof m['tool'] === 'string' ? (m['tool'] as MatcherTool) : 'any';
    if (!capability) problems.push(`${file}: matcher #${index + 1} has no capability`);
    if (!['Bash', 'Read', 'Write', 'Edit', 'WebFetch', 'any'].includes(tool))
      problems.push(`${file}: matcher #${index + 1} has invalid tool "${tool}"`);
    const matcher: Matcher = { capability, tool, index, file };
    // An ADDITIVE matcher describes something a segment ALSO does — a write destination, an extra effect — not
    // what the segment IS. It contributes a hit and never wins first-match for the segment's semantic class,
    // because a class that describes only a destination cannot bound the rest of the command.
    if (m['additive'] === true) matcher.additive = true;
    const cmd = m['command'];
    const path = m['path'];
    const url = m['url'];
    if (typeof cmd === 'string') {
      try {
        matcher.command = new RegExp(cmd, 'i');
        matcher.commandSource = cmd;
      } catch (e) {
        problems.push(`${file}: matcher #${index + 1} has an invalid command regex: ${(e as Error).message}`);
      }
    }
    if (typeof path === 'string') matcher.path = path;
    if (typeof url === 'string') {
      try {
        matcher.url = new RegExp(url, 'i');
        matcher.urlSource = url;
      } catch (e) {
        problems.push(`${file}: matcher #${index + 1} has an invalid url regex: ${(e as Error).message}`);
      }
    }
    if (!matcher.command && !matcher.path && !matcher.url)
      problems.push(`${file}: matcher #${index + 1} has no command, path or url`);
    out.push(matcher);
  });
  return out;
}

function parseGrants(file: string, problems: string[]): GrantsDoc {
  const doc = parseMarkdown(file, readText(file));
  if (optionalString(doc, 'schema') !== 'ego.grants/1') problems.push(`${file}: schema must be ego.grants/1`);
  const negations = optionalStringList(doc, 'negations').map((n) => normalizePhrase(n));
  const window = optionalNumber(doc, 'negation_window_tokens') ?? 4;
  const raw = doc.frontmatter['grants'];
  const grants: GrantsDoc['grants'] = [];
  if (!Array.isArray(raw)) problems.push(`${file}: frontmatter "grants" must be a list`);
  else {
    raw.forEach((entry, i) => {
      const g = asRecord(entry);
      if (!g || typeof g['capability'] !== 'string' || !Array.isArray(g['phrases'])) {
        problems.push(`${file}: grant #${i + 1} must have capability and phrases`);
        return;
      }
      const phrases = (g['phrases'] as YamlValue[])
        .filter((p): p is string => typeof p === 'string')
        .map(normalizePhrase);
      if (phrases.length === 0) problems.push(`${file}: grant #${i + 1} has no phrases`);
      grants.push({ capability: g['capability'], phrases });
    });
  }
  return { negationWindowTokens: window, negations, grants, file };
}

/** Normalization shared by the grant recogniser: lowercase, accents folded, punctuation collapsed to spaces. */
export function normalizePhrase(s: string): string {
  return s
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();
}

function parseProfile(file: string, problems: string[]): Profile | null {
  const doc = parseMarkdown(file, readText(file));
  if (optionalString(doc, 'schema') !== 'ego.profile/1') {
    problems.push(`${file}: schema must be ego.profile/1`);
    return null;
  }
  const id = requireString(doc, 'id');
  const enumField = <T extends string>(key: string, allowed: readonly T[], def: T): T => {
    const v = optionalString(doc, key) ?? def;
    if (!allowed.includes(v as T)) {
      problems.push(`${file}: ${key} must be one of ${allowed.join(', ')}`);
      return def;
    }
    return v as T;
  };
  const narrow: Profile['narrow'] = [];
  const rawNarrow = doc.frontmatter['narrow'];
  if (Array.isArray(rawNarrow)) {
    rawNarrow.forEach((n, i) => {
      const r = asRecord(n);
      const cap = r?.['capability'];
      const verdict = r?.['verdict'];
      if (typeof cap !== 'string' || (verdict !== 'ASK' && verdict !== 'DENY')) {
        problems.push(`${file}: narrow #${i + 1} must have capability and verdict ASK or DENY`);
        return;
      }
      narrow.push({ capability: cap, verdict });
    });
  } else if (rawNarrow !== undefined) {
    problems.push(`${file}: narrow must be a list (write \`narrow: []\` for none)`);
  }
  return {
    id,
    title: doc.title ?? id,
    budgets: parseBudgets(file, doc.frontmatter['budgets'], problems),
    contextBudgetTokens: optionalNumber(doc, 'context_budget_tokens') ?? 2500,
    organizationCeilingTokens: optionalNumber(doc, 'organization_ceiling_tokens') ?? 4000,
    requiresSignedReleaseTrust: optionalBoolean(doc, 'requires_signed_release_trust', false),
    requiresManagedTier: optionalBoolean(doc, 'requires_managed_tier', false),
    requiresRemoteVerifyBackstop: optionalBoolean(doc, 'requires_remote_verify_backstop', false),
    grillingReviewUnavailable: enumField<UnavailablePolicy>(
      'grilling_review_unavailable',
      ['CONTINUE_WITH_DISCLOSURE', 'BLOCK_DONE'],
      'CONTINUE_WITH_DISCLOSURE',
    ),
    forgeUnreachableAtDone: enumField<UnavailablePolicy>(
      'forge_unreachable_at_done',
      ['CONTINUE_WITH_DISCLOSURE', 'BLOCK_DONE'],
      'CONTINUE_WITH_DISCLOSURE',
    ),
    shellUncertainMutation: enumField<ShellUncertainPolicy>(
      'shell_uncertain_mutation_with_foreign_live_session',
      ['DETECT_AFTER', 'DENY', 'REQUIRE_ISOLATION'],
      'DETECT_AFTER',
    ),
    ownerWeakeningPlainPolicy: enumField<OwnerWeakeningPolicy>(
      'owner_weakening_plain_policy',
      ['AUTO_WITH_INFORM', 'DECISION'],
      'AUTO_WITH_INFORM',
    ),
    modelFlaggedConflictOnControl: enumField<ModelFlagPolicy>(
      'model_flagged_conflict_on_control',
      ['INFORM', 'DECISION_WITH_KEEP'],
      'INFORM',
    ),
    narrow,
    file,
  };
}

function parseMode(file: string, problems: string[]): AuthorityMode | null {
  const doc = parseMarkdown(file, readText(file));
  if (optionalString(doc, 'schema') !== 'ego.mode/1') {
    problems.push(`${file}: schema must be ego.mode/1`);
    return null;
  }
  if (optionalString(doc, 'kind') !== 'authority')
    problems.push(`${file}: kind must be "authority" for a mode`);
  const overrides: AuthorityMode['overrides'] = [];
  const raw = doc.frontmatter['overrides'];
  if (raw !== undefined && !Array.isArray(raw))
    problems.push(`${file}: overrides must be a list (write \`overrides: []\` for none)`);
  if (Array.isArray(raw)) {
    raw.forEach((n, i) => {
      const r = asRecord(n);
      const cap = r?.['capability'];
      const verdict = r?.['verdict'];
      if (typeof cap !== 'string' || (verdict !== 'ALLOW' && verdict !== 'ASK' && verdict !== 'DENY')) {
        problems.push(`${file}: override #${i + 1} must have capability and verdict`);
        return;
      }
      overrides.push({ capability: cap, verdict });
    });
  }
  return {
    id: requireString(doc, 'id'),
    title: doc.title ?? requireString(doc, 'id'),
    isDefault: optionalBoolean(doc, 'default', false),
    onlyInEgoRepository: optionalBoolean(doc, 'only_in_ego_repository', false),
    overrides,
    file,
  };
}

function parseIntent(file: string, problems: string[]): Intent | null {
  const doc = parseMarkdown(file, readText(file));
  if (optionalString(doc, 'schema') !== 'ego.intent/1') {
    problems.push(`${file}: schema must be ego.intent/1`);
    return null;
  }
  if (optionalBoolean(doc, 'changes_authority', false))
    problems.push(`${file}: an intent may not change authority`);
  return {
    id: requireString(doc, 'id'),
    title: doc.title ?? requireString(doc, 'id'),
    routesSkills: optionalStringList(doc, 'routes_skills'),
    file,
  };
}

function parseSecrets(file: string, problems: string[], layer: LayerName): SecretsDoc | null {
  const doc = parseMarkdown(file, readText(file));
  if (optionalString(doc, 'schema') !== 'ego.secrets/1') {
    problems.push(`${file}: schema must be ego.secrets/1`);
    return null;
  }
  const family = requireString(doc, 'family');
  const detectors: SecretDetector[] = [];
  const raw = doc.frontmatter['detectors'];
  if (!Array.isArray(raw))
    problems.push(
      `${file}: detectors must be a list (a secrets file without detectors would silently weaken redaction)`,
    );
  else if (raw.length === 0 && layer === 'core')
    problems.push(`${file}: a core secrets file must declare at least one detector`);
  if (Array.isArray(raw)) {
    raw.forEach((entry, i) => {
      const d = asRecord(entry);
      if (!d || typeof d['id'] !== 'string' || typeof d['pattern'] !== 'string') {
        problems.push(`${file}: detector #${i + 1} must have id and pattern`);
        return;
      }
      const severity = d['severity'] === 'warn' ? 'warn' : d['severity'] === 'block' ? 'block' : null;
      if (!severity) {
        problems.push(`${file}: detector ${d['id']} severity must be block or warn`);
        return;
      }
      const flags = typeof d['flags'] === 'string' ? d['flags'] : 'gi';
      let re: RegExp;
      try {
        re = new RegExp(d['pattern'], flags.includes('g') ? flags : `g${flags}`);
      } catch (e) {
        problems.push(`${file}: detector ${d['id']} has an invalid pattern: ${(e as Error).message}`);
        return;
      }
      detectors.push({
        id: d['id'],
        family,
        name: typeof d['name'] === 'string' ? d['name'] : d['id'],
        pattern: re,
        patternSource: d['pattern'],
        flags: re.flags,
        group: typeof d['group'] === 'number' ? d['group'] : 0,
        severity,
        locked: layer === 'core' ? d['locked'] !== false : false,
        replacement: typeof d['replacement'] === 'string' ? d['replacement'] : '[REDACTED]',
        wholeDocument: d['whole_document'] === true,
        onlyForFiles: d['only_for_files'] === true,
        file,
      });
    });
  }
  return {
    family,
    title: doc.title ?? family,
    sensitiveFiles: optionalStringList(doc, 'sensitive_files'),
    detectors,
    file,
  };
}

function parseReleaseKeys(file: string, problems: string[]): ReleaseKeysDoc {
  const doc = parseMarkdown(file, readText(file));
  if (optionalString(doc, 'schema') !== 'ego.release-keys/1')
    problems.push(`${file}: schema must be ego.release-keys/1`);
  if (!optionalBoolean(doc, 'absolute', false))
    problems.push(`${file}: release-keys must be marked absolute: true`);
  const keys: ReleaseKey[] = [];
  const raw = doc.frontmatter['keys'];
  if (Array.isArray(raw)) {
    raw.forEach((entry, i) => {
      const k = asRecord(entry);
      if (
        !k ||
        typeof k['id'] !== 'string' ||
        typeof k['publicKey'] !== 'string' ||
        typeof k['fingerprint'] !== 'string'
      ) {
        problems.push(`${file}: key #${i + 1} must have id, publicKey and fingerprint`);
        return;
      }
      const status = k['status'];
      if (status !== 'active' && status !== 'standby' && status !== 'revoked') {
        problems.push(`${file}: key ${k['id']} status must be active, standby or revoked`);
        return;
      }
      if (k['algorithm'] !== 'ed25519') problems.push(`${file}: key ${k['id']} algorithm must be ed25519`);
      const key: ReleaseKey = {
        id: k['id'],
        algorithm: 'ed25519',
        publicKey: k['publicKey'],
        fingerprint: k['fingerprint'].toLowerCase(),
        status,
      };
      if (typeof k['validFrom'] === 'string') key.validFrom = k['validFrom'];
      keys.push(key);
    });
  } else if (raw !== undefined && raw !== null) {
    problems.push(`${file}: keys must be a list`);
  }
  return { keys, independentChannel: optionalString(doc, 'independent_channel') ?? '', file };
}

function parseCoordination(file: string, problems: string[]): CoordinationConstants {
  const doc = parseMarkdown(file, readText(file));
  if (optionalString(doc, 'schema') !== 'ego.coordination/1')
    problems.push(`${file}: schema must be ego.coordination/1`);
  const num = (key: string, def: number) => {
    const v = optionalNumber(doc, key);
    if (v !== undefined && v <= 0) problems.push(`${file}: ${key} must be positive`);
    return v ?? def;
  };
  return {
    heartbeatTtlSeconds: num('heartbeat_ttl_seconds', 900),
    heartbeatTtlWithoutPidSeconds: num('heartbeat_ttl_without_pid_seconds', 3600),
    handoffGraceSeconds: num('handoff_grace_seconds', 1800),
    lockTimeoutMs: num('lock_timeout_ms', 3000),
    lockStaleBreakMs: num('lock_stale_break_ms', 30000),
    gcEndedSessionsDays: num('gc_ended_sessions_days', 7),
    gcUnheldClaimsDays: num('gc_unheld_claims_days', 30),
    file,
  };
}

/** Decision Q98: the authored local-development targets. Fails closed — a malformed or empty list is a problem, not a
 *  silently empty set, because an empty `k8s_local_contexts` would make every cluster unclassified. */
function parseLocalTargets(file: string, problems: string[]): LocalTargets {
  const doc = parseMarkdown(file, readText(file));
  if (optionalString(doc, 'schema') !== 'ego.local-targets/1')
    problems.push(`${file}: schema must be ego.local-targets/1`);
  const list = (key: string): string[] => {
    const v = optionalStringList(doc, key);
    if (v.length === 0) problems.push(`${file}: ${key} must list at least one entry`);
    return v;
  };
  return {
    k8sLocalContexts: list('k8s_local_contexts'),
    dbLocalHosts: list('db_local_hosts'),
    productionMarkers: list('production_markers'),
    file,
    // what the project and the organization declare is merged in by the compiler (`mergeLocalTargets`), not here
    declared: [],
    ignored: [],
  };
}

/** The authored bounded/discovering command vocabulary. Fails closed: an empty `discovers` list would silently
 *  restore the defect this file exists to close. */
function parseBoundedCommands(file: string, problems: string[]): BoundedCommands {
  const doc = parseMarkdown(file, readText(file));
  if (optionalString(doc, 'schema') !== 'ego.bounded-commands/1')
    problems.push(`${file}: schema must be ego.bounded-commands/1`);
  const list = (key: string): string[] => {
    const v = optionalStringList(doc, key);
    if (v.length === 0) problems.push(`${file}: ${key} must list at least one entry`);
    return v;
  };
  return {
    bounded: list('bounded'),
    installsDependencies: list('installs_dependencies'),
    discoversContent: list('discovers_content'),
    discoversConfig: list('discovers_config'),
    file,
  };
}

export function loadControlPlane(rootAsGiven: string): ControlPlane {
  // THE SAME CONTROL PLANE GIVEN AS `/x/control-plane` AND AS `/x/control-plane/` IS THE SAME TABLE: a trailing separator cost the
  // first character of every source-hash key and changed the table hash (AUTH-11)
  const root = rootAsGiven.length > 1 ? rootAsGiven.replace(/[\\/]+$/, '') : rootAsGiven;
  const problems: string[] = [];
  const sourceHashes: Record<string, string> = {};
  const rec = (file: string) => {
    sourceHashes[toPosix(relative(root, file))] = sha256Hex(readText(file));
  };
  const req = (rel: string): string => {
    const f = join(root, rel);
    if (!isFile(f)) {
      problems.push(`missing required control-plane file: ${rel}`);
      return '';
    }
    rec(f);
    return f;
  };

  const notices: string[] = [];
  const absFile = req('permissions/absolute-denies.md');
  const absoluteDenies = absFile
    ? parseCapabilityDoc(absFile, readText(absFile), 'core', problems, notices)
    : null;
  if (absoluteDenies && !absoluteDenies.absolute) problems.push(`${absFile}: must declare absolute: true`);

  const capabilityDocs: CapabilityDoc[] = [];
  let adminGoverned: CapabilityDoc | null = null;
  for (const f of listMarkdown(join(root, 'permissions', 'capabilities'))) {
    rec(f);
    const d = parseCapabilityDoc(f, readText(f), 'core', problems, notices);
    if (d) {
      if (d.absolute) problems.push(`${f}: only absolute-denies.md may be absolute`);
      if (d.lock === 'admin-governed') {
        if (adminGoverned)
          problems.push(`${f}: only one admin-governed file is allowed (also ${adminGoverned.file})`);
        adminGoverned = d;
      }
      capabilityDocs.push(d);
    }
  }
  if (capabilityDocs.length === 0)
    problems.push('no capability documents found under permissions/capabilities/');
  const containmentFile = req('containment/controls.md');
  const containment = containmentFile ? parseContainment(containmentFile, problems) : [];

  const matchersFile = req('permissions/matchers.md');
  const matchers = matchersFile ? parseMatchers(matchersFile, problems) : [];
  const grantsFile = req('permissions/grants.md');
  const grants = grantsFile
    ? parseGrants(grantsFile, problems)
    : { negationWindowTokens: 4, negations: [], grants: [], file: '' };
  const keysFile = req('permissions/release-keys.md');
  const releaseKeys = keysFile
    ? parseReleaseKeys(keysFile, problems)
    : { keys: [], independentChannel: '', file: '' };

  const profiles = listMarkdown(join(root, 'profiles'))
    .map((f) => (rec(f), parseProfile(f, problems)))
    .filter((p): p is Profile => p !== null);
  const modes = listMarkdown(join(root, 'modes'))
    .map((f) => (rec(f), parseMode(f, problems)))
    .filter((m): m is AuthorityMode => m !== null);
  const intents = listMarkdown(join(root, 'intents'))
    .map((f) => (rec(f), parseIntent(f, problems)))
    .filter((m): m is Intent => m !== null);
  const secrets = listMarkdown(join(root, 'secrets'))
    .map((f) => (rec(f), parseSecrets(f, problems, 'core')))
    .filter((s): s is SecretsDoc => s !== null);
  const coordFile = req('workspace/coordination.md');
  const coordination = coordFile ? parseCoordination(coordFile, problems) : parseCoordinationDefaults();
  const boundedFile = req('workspace/bounded-commands.md');
  const boundedCommands = boundedFile
    ? parseBoundedCommands(boundedFile, problems)
    : { bounded: [], installsDependencies: [], discoversContent: [], discoversConfig: [], file: '' };
  const targetsFile = req('workspace/local-targets.md');
  const localTargets = targetsFile
    ? parseLocalTargets(targetsFile, problems)
    : { k8sLocalContexts: [], dbLocalHosts: [], productionMarkers: [], file: '', declared: [], ignored: [] };

  // cross-document validation
  const allIds = new Map<string, string>();
  const register = (doc: CapabilityDoc | null) => {
    if (!doc) return;
    for (const c of doc.capabilities) {
      const prev = allIds.get(c.id);
      if (prev) problems.push(`${c.file}:${c.line}: capability "${c.id}" is already declared in ${prev}`);
      else allIds.set(c.id, `${c.file}:${c.line}`);
    }
  };
  register(absoluteDenies);
  capabilityDocs.forEach(register);
  for (const m of matchers)
    if (m.capability && !allIds.has(m.capability))
      problems.push(`${m.file}: matcher #${m.index + 1} references unknown capability "${m.capability}"`);
  for (const g of grants.grants)
    if (!allIds.has(g.capability))
      problems.push(`${grants.file}: grant references unknown capability "${g.capability}"`);
  for (const p of profiles)
    for (const n of p.narrow)
      if (!allIds.has(n.capability))
        problems.push(`${p.file}: narrow references unknown capability "${n.capability}"`);
  const absoluteIds = new Set(absoluteDenies?.capabilities.map((c) => c.id) ?? []);
  const lockedIds = new Set(adminGoverned?.capabilities.map((c) => c.id) ?? []);
  for (const m of modes) {
    for (const o of m.overrides) {
      if (!allIds.has(o.capability))
        problems.push(`${m.file}: override references unknown capability "${o.capability}"`);
      if (absoluteIds.has(o.capability))
        problems.push(`${m.file}: mode may not override absolute deny "${o.capability}"`);
      if (lockedIds.has(o.capability))
        problems.push(`${m.file}: mode may not override ADMIN_GOVERNED capability "${o.capability}"`);
    }
  }
  for (const g of grants.grants) {
    if (absoluteIds.has(g.capability))
      problems.push(`${grants.file}: grant may not reference absolute deny "${g.capability}"`);
    if (lockedIds.has(g.capability))
      problems.push(`${grants.file}: grant may not reference ADMIN_GOVERNED capability "${g.capability}"`);
  }
  const profileIds = new Set(profiles.map((p) => p.id));
  for (const c of containment)
    for (const pid of [...c.requiredIn, ...c.recommendedIn])
      if (!profileIds.has(pid))
        problems.push(`${c.file}: control ${c.id} references unknown profile "${pid}"`);
  if (profiles.length === 0) problems.push('no profiles found under profiles/');
  if (!modes.some((m) => m.isDefault)) problems.push('no default authority mode declared (default: true)');
  const dup = (items: Array<{ id: string; file: string }>, kind: string) => {
    const seen = new Map<string, string>();
    for (const it of items) {
      if (seen.has(it.id))
        problems.push(`${it.file}: duplicate ${kind} id "${it.id}" (also in ${seen.get(it.id)})`);
      seen.set(it.id, it.file);
    }
  };
  dup(profiles, 'profile');
  dup(modes, 'mode');
  dup(intents, 'intent');
  dup(
    secrets.flatMap((s) => s.detectors),
    'detector',
  );
  for (const s of secrets)
    for (const d of s.detectors)
      if (d.group > 0 && !/\(/.test(d.patternSource))
        problems.push(`${d.file}: detector ${d.id} declares group ${d.group} but has no capture group`);

  if (problems.length) throw new ControlPlaneValidationError(problems);
  return {
    root,
    absoluteDenies: absoluteDenies!,
    adminGoverned,
    capabilityDocs,
    containment,
    matchers,
    grants,
    profiles,
    modes,
    intents,
    secrets,
    releaseKeys,
    coordination,
    localTargets,
    boundedCommands,
    sourceHashes,
    notices,
  };
}

function parseCoordinationDefaults(): CoordinationConstants {
  return {
    heartbeatTtlSeconds: 900,
    heartbeatTtlWithoutPidSeconds: 3600,
    handoffGraceSeconds: 1800,
    lockTimeoutMs: 3000,
    lockStaleBreakMs: 30000,
    gcEndedSessionsDays: 7,
    gcUnheldClaimsDays: 30,
    file: '',
  };
}

/** Loads an overlay capability document (organization policy or product overlay). Returns null when the file is absent. */
export function loadOverlayCapabilities(
  file: string,
  layer: 'organization' | 'overlay',
  notices: string[] = [],
): CapabilityDoc | null {
  if (!isFile(file)) return null;
  const problems: string[] = [];
  const doc = parseCapabilityDoc(file, readText(file), layer, problems, notices);
  if (problems.length) throw new ControlPlaneValidationError(problems);
  if (doc && (doc.absolute || doc.lock !== 'none'))
    throw new ControlPlaneValidationError([`${file}: an overlay may not be absolute or locked`]);
  return doc;
}

export function overlayFileName(file: string): string {
  return basename(file);
}
