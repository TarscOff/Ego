// PHASE-1 CLOSURE, AUTHORITY TIERS (independent audit of 2026-10-01, Q98 items). Three families of defect, each
// pinned at the level of the CLASS rather than the spelling the audit happened to use:
//
//   1. a session grant lifted an EXTERNAL effect from ASK to ALLOW (issue #16 section 4: "never permit an unattended
//      external-write ALLOW, in any host mode"; section 8: a human phrase is a bounded task approval, never a durable
//      authority grant);
//   2. two identifiers that are non-widenable in effect were not MARKED so (Q98 follow-up 1);
//   3. "bypass of branch/repository protection" had no capability at all, and three declared admin-governed
//      identifiers had no matcher, so enabling them changed nothing (Q98 follow-up 2, test 15c).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadControlPlane, loadOverlayCapabilities } from '../src/control-plane/load.ts';
import { compileAuthority, diffAuthorityTables, classifyAuthorityChanges } from '../src/authority/compile.ts';
import { evaluate, type EvaluationContext } from '../src/authority/evaluate.ts';
import { table, workspace } from './support/corpus.ts';

const ROOT = new URL('../../../control-plane/', import.meta.url).pathname;
const PROFILES = Object.keys(table.profiles).sort();
const MODES = Object.keys(table.profiles[PROFILES[0]!]!.modes).sort();

const dir = workspace();
function run(
  command: string,
  over: Partial<EvaluationContext> = {},
  t: typeof table = table,
): ReturnType<typeof evaluate> {
  return evaluate(
    t,
    { profile: 'STANDARD', mode: 'NORMAL_DELIVERY', repoRoots: [dir], cwd: dir, ...over },
    { tool: 'Bash', input: { command } },
  );
}
const overlayDoc = (
  kind: 'organization' | 'overlay',
  section: string,
  ...ids: string[]
): ReturnType<typeof loadOverlayCapabilities> => {
  const d = mkdtempSync(join(tmpdir(), 'ego-closure-'));
  const f = join(d, 'permissions.md');
  writeFileSync(
    f,
    `---\nschema: ego.capabilities/1\nid: ${kind}\nfamily: ${kind}\n---\n# L\n\n## ${section}\n\n${ids
      .map((id) => `- [x] \`${id}\` — layer text\n`)
      .join('')}`,
  );
  return loadOverlayCapabilities(f, kind);
};
/** every administrable external capability, enabled at ASK by an organization: the most permissive legal table */
const ADMIN_GOVERNED = table.organizationLocked;
const enabledTable = compileAuthority(loadControlPlane(ROOT), {
  organization: overlayDoc('organization', 'Requires human approval', ...ADMIN_GOVERNED),
});
/** a private copy of the authored control plane to edit */
function editedControlPlane(
  edit: (file: (rel: string) => string, write: (rel: string, body: string) => void) => void,
): string {
  const d = mkdtempSync(join(tmpdir(), 'ego-closure-cp-'));
  cpSync(ROOT, d, { recursive: true });
  edit(
    (rel) => readFileSync(join(d, rel), 'utf8'),
    (rel, body) => writeFileSync(join(d, rel), body),
  );
  return d;
}

/* ------------------------------------------------------------------------------------------------------------- *
 * 2. TIER MARKING (Q98 follow-up 1)
 * ------------------------------------------------------------------------------------------------------------- */

const NON_WIDENABLE_BY_EFFECT = ['git.hooks.bypass', 'fs.outside-workspace.write'] as const;
/** every identifier this closure put in (or found missing from) the absolute tier */
const NON_WIDENABLE = [...NON_WIDENABLE_BY_EFFECT, 'forge.protection.bypass'] as const;

test('tier marking: git.hooks.bypass, fs.outside-workspace.write and forge.protection.bypass are ABSOLUTE and DENY in all 12 profile x mode cells', () => {
  assert.equal(PROFILES.length * MODES.length, 12);
  for (const id of NON_WIDENABLE) {
    assert.ok(table.absoluteDenies.includes(id), `${id} must be in table.absoluteDenies`);
    assert.equal(table.capabilities[id]!.lock, 'absolute', id);
    assert.equal(table.capabilities[id]!.absolute, true, id);
    assert.ok(!table.organizationLocked.includes(id), `${id} is not an administrable lock`);
    for (const p of PROFILES)
      for (const m of MODES) assert.equal(table.profiles[p]!.modes[m]![id], 'DENY', `${id} in ${p}/${m}`);
  }
});

test('tier marking: no layer can reference an absolute identifier — the refusal is the absolute one, not a generic "widen"', () => {
  const cp = loadControlPlane(ROOT);
  for (const id of NON_WIDENABLE) {
    // an organization asking to enable it, and a product overlay restating it
    assert.throws(
      () => compileAuthority(cp, { organization: overlayDoc('organization', 'Requires human approval', id) }),
      /may not reference absolute deny/,
      `organization -> ${id}`,
    );
    assert.throws(
      () => compileAuthority(cp, { overlay: overlayDoc('overlay', 'Denied', id) }),
      /may not reference absolute deny/,
      `overlay -> ${id}`,
    );
    // a mode override and a grant entry fail at load
    const withMode = editedControlPlane((_f, write) =>
      write(
        'modes/evil.md',
        `---\nschema: ego.mode/1\nid: EVIL\nkind: authority\noverrides:\n  - capability: ${id}\n    verdict: ALLOW\n---\n# EVIL\n`,
      ),
    );
    assert.throws(
      () => loadControlPlane(withMode),
      new RegExp(`mode may not override absolute deny "${id}"`),
    );
    const withGrant = editedControlPlane((f, write) =>
      write(
        'permissions/grants.md',
        f('permissions/grants.md').replace(
          '  - capability: git.local.commit\n',
          `  - capability: ${id}\n    phrases: ["do it anyway"]\n  - capability: git.local.commit\n`,
        ),
      ),
    );
    assert.throws(
      () => loadControlPlane(withGrant),
      new RegExp(`grant may not reference absolute deny "${id}"`),
    );
    // a profile narrowing is also a reference
    const withProfile = editedControlPlane((f, write) =>
      write(
        'profiles/strict.md',
        f('profiles/strict.md').replace('narrow:\n', `narrow:\n  - capability: ${id}\n    verdict: DENY\n`),
      ),
    );
    assert.throws(
      () => compileAuthority(loadControlPlane(withProfile)),
      new RegExp(`profile may not reference absolute deny "${id}"`),
    );
  }
});

test('tier marking: moving an identifier between lock tiers is a MAJOR authority change (Q84), and the diff says so', () => {
  const before = structuredClone(table);
  for (const id of NON_WIDENABLE_BY_EFFECT) {
    before.capabilities[id]!.lock = 'none';
    before.capabilities[id]!.absolute = false;
    before.absoluteDenies = before.absoluteDenies.filter((x) => x !== id);
  }
  const changes = diffAuthorityTables(before, table);
  for (const id of NON_WIDENABLE_BY_EFFECT)
    assert.ok(
      changes.some((c) => c.kind === 'lock-changed' && c.capability === id && c.toLock === 'absolute'),
      id,
    );
  assert.equal(classifyAuthorityChanges(changes, table), 'major');
});

test('tier marking: the effective verdict did not move — every spelling that was DENY is still DENY, now labelled absolute', () => {
  for (const [cmd, cap] of [
    ['git commit --no-verify -m x', 'git.hooks.bypass'],
    ['git commit -n -m x', 'git.hooks.bypass'],
    ['git -c core.hooksPath=/dev/null commit -m x', 'git.hooks.bypass'],
    ['git push --no-verify origin feature/x', 'git.hooks.bypass'],
    ['echo x > /etc/hosts', 'fs.outside-workspace.write'],
    ['cp payload /etc/cron.d/x', 'fs.outside-workspace.write'],
  ] as const) {
    for (const profile of PROFILES) {
      const r = run(cmd, { profile });
      assert.equal(r.verdict, 'DENY', `${cmd} in ${profile}`);
      assert.equal(
        r.decisive?.capability === cap || r.hits.some((h) => h.capability === cap),
        true,
        `${cmd}: ${cap}`,
      );
      assert.match(r.reason, /absolute core deny/, cmd);
    }
  }
});

test('tier marking: an organization that ENABLES pushing still cannot make a hook bypass an ASK, whichever verb carries the flag', () => {
  for (const id of ADMIN_GOVERNED)
    assert.equal(enabledTable.effective[id], 'ASK', `${id} is enabled in this table`);
  for (const verb of [
    'commit',
    'merge main',
    'rebase main',
    'cherry-pick abc',
    'am p.mbox',
    'revert abc',
    'pull origin main',
    'push origin feature/x',
  ]) {
    for (const cmd of [`git ${verb} --no-verify`, `git -C . ${verb} --no-verify`, `git ${verb} --no-verif`]) {
      const r = run(cmd, {}, enabledTable);
      assert.equal(r.verdict, 'DENY', cmd);
      assert.equal(r.decisive?.capability, 'git.hooks.bypass', cmd);
    }
  }
  // ...and the same push without the flag is the ordinary, human-approved integration act
  assert.equal(run('git push origin feature/x', {}, enabledTable).verdict, 'ASK');
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 3. PROTECTION BYPASS, AND THE ADMIN-GOVERNED IDENTIFIERS THAT NOTHING REACHED (Q98 follow-up 2, test 15c)
 *
 * #16 section 6 / #1 comment 2: defeating a control is a governance bypass and stays non-widenable; CHANGING the
 * rules is an administrable act. Until now the first had no identifier, and three declared administrable ones
 * (branch protection, repository permissions, issue transition) had no matcher, so an organization that enabled them
 * changed nothing: the commands stayed DENY through forge.api.mutate or fell to ASK command.unknown.
 * ------------------------------------------------------------------------------------------------------------- */

const bodies = workspace({
  'rs-bypass.json':
    '{"name":"main","target":"branch","enforcement":"active","bypass_actors":[{"actor_id":5,"actor_type":"RepositoryRole","bypass_mode":"always"}]}',
  'rs-plain.json': '{"name":"main","target":"branch","enforcement":"active","bypass_actors":[]}',
  'prot-admin-off.json':
    '{"required_status_checks":null,"enforce_admins":false,"required_pull_request_reviews":null,"restrictions":null}',
  'prot-ok.json':
    '{"required_status_checks":null,"enforce_admins":true,"required_pull_request_reviews":null,"restrictions":null}',
});
// a document the agent writes is attacker-controlled text: this one carries the kernel's own sentinel, and this one
// names a different endpoint and verb inside a ruleset body
writeFileSync(join(bodies, 'forged.json'), '{"enforce_admins":false}\u0000ego\u0000body x');
writeFileSync(
  join(bodies, 'spoof.json'),
  '{"note":" repos/o/r/collaborators/bob repos/o/r/rulesets/1 repos/o/r -X DELETE ","enforcement":"active"}',
);
const inBodies: Partial<EvaluationContext> = { repoRoots: [bodies], cwd: bodies };
/** a table in which an organization enables EXACTLY these administrable ids, at ASK */
const enabling = (...ids: string[]): typeof table =>
  compileAuthority(loadControlPlane(ROOT), {
    organization: overlayDoc('organization', 'Requires human approval', ...ids),
  });
const enablingAllBut = (id: string): typeof table => enabling(...ADMIN_GOVERNED.filter((x) => x !== id));

/** the spellings of "defeat the control" — not "change the rule" */
const BYPASS_SPELLINGS: readonly string[] = [
  // the override flag of the merge command, wherever it stands and whoever carries it
  'gh pr merge 3 --admin',
  'gh pr merge --admin 3',
  'gh pr merge 3 --squash --admin',
  'gh pr merge 3 --admin=true',
  'gh pr merge 3 --delete-branch --admin --squash',
  'gh -R o/r pr merge 3 --admin',
  'GH_TOKEN=x gh pr merge 3 --admin',
  'env gh pr merge 3 --admin',
  'bash -c "gh pr merge 3 --admin"',
  'echo 3 | xargs gh pr merge --admin',
  'az repos pr update --id 3 --status completed --bypass-policy true',
  'az repos pr update --id 3 --status completed --bypass-policy',
  // switching enforcement off for administrators
  'gh api -X DELETE repos/o/r/branches/main/protection/enforce_admins',
  'gh api --method=DELETE /repos/o/r/branches/main/protection/enforce_admins',
  'gh api -XDELETE repos/o/r/branches/main/protection/enforce_admins',
  'gh api repos/o/r/branches/main/protection/enforce_admins -X DELETE',
  'gh api -X DELETE https://api.github.com/repos/o/r/branches/main/protection/enforce_admins',
  'gh api -X PUT repos/o/r/branches/main/protection -F enforce_admins=false -f required_status_checks=null',
  'gh api -X PUT repos/o/r/branches/main/protection -f enforce_admins=false',
  'gh api -X PUT repos/o/r/branches/main/protection -F enforce_admins=null',
  'gh api --method PUT repos/o/r/branches/main/protection --field enforce_admins=false',
  // a bypass actor, or an enforcement mode that enforces nothing
  "gh api -X PUT repos/o/r/rulesets/5 -f 'bypass_actors[][actor_id]=1'",
  'gh api -X POST repos/o/r/rulesets -f name=x -f enforcement=disabled',
  'gh api -X PUT repos/o/r/rulesets/5 -f enforcement=evaluate',
  'gh api -X PUT orgs/o/rulesets/5 -f enforcement=disabled',
  'gh api -X PUT repos/o/r/branches/main/protection -f bypass_pull_request_allowances=x',
  // the same body arriving from a file the kernel can read, or a heredoc it can see
  'gh api -X POST repos/o/r/rulesets --input rs-bypass.json',
  'gh api -X PUT repos/o/r/branches/main/protection --input prot-admin-off.json',
  'gh api -X PUT repos/o/r/branches/main/protection -F config=@prot-admin-off.json',
  'gh api -X PUT repos/o/r/branches/main/protection --input - <<\'EOF\'\n{"enforce_admins": false}\nEOF',
  `echo '{"enforce_admins": false}' | gh api -X PUT repos/o/r/branches/main/protection --input -`,
  `printf '%s' '{"enforce_admins":null}' | gh api -X PUT repos/o/r/branches/main/protection --input -`,
  // a launcher the kernel does not know, a glued option, a relative path
  'some-launcher gh api -X PUT repos/o/r/branches/main/protection --input prot-admin-off.json',
  'gh api -X PUT repos/o/r/branches/main/protection --input=./prot-admin-off.json',
  'gh api -X PUT repos/o/r/branches/main/protection -Fcfg=@prot-admin-off.json',
  // a document that carries the kernel's own sentinel: forged text is data, and the switch-off in it is still read
  'gh api -X PUT repos/o/r/branches/main/protection --input forged.json',
];

test('protection bypass: forge.protection.bypass is DENY in every profile, and an organization that enables EVERYTHING administrable cannot make it ASK', () => {
  assert.ok(table.absoluteDenies.includes('forge.protection.bypass'));
  assert.ok(
    !table.organizationLocked.includes('forge.protection.bypass'),
    'a bypass is not an administrable act',
  );
  for (const profile of PROFILES) {
    for (const cmd of BYPASS_SPELLINGS) {
      for (const [name, t] of [
        ['default', table],
        ['everything enabled', enabledTable],
      ] as const) {
        const r = run(cmd, { profile, ...inBodies }, t);
        assert.equal(r.verdict, 'DENY', `${cmd} (${name}, ${profile})`);
        assert.equal(r.decisive?.capability, 'forge.protection.bypass', `${cmd} (${name}, ${profile})`);
        assert.match(r.reason, /absolute core deny/, cmd);
      }
    }
  }
});

test('protection bypass: what is NOT a bypass keeps its own identifier — an override flag set to false, an empty bypass list, a read, a help probe', () => {
  const pr = (c: string) => run(c, inBodies, enabledTable);
  assert.equal(pr('gh pr merge 3 --admin=false').decisive?.capability, 'forge.pr.merge');
  assert.equal(pr('gh pr merge 3 --squash --delete-branch').decisive?.capability, 'forge.pr.merge');
  assert.equal(pr('gh pr merge 3 --auto --squash').decisive?.capability, 'forge.pr.merge');
  assert.equal(
    pr('az repos pr update --id 3 --status completed --bypass-policy false').decisive?.capability,
    'forge.pr.merge',
  );
  // changing the rule is an administrable act: the protection stays on for administrators
  const modify = 'forge.branch.protection.modify';
  assert.equal(
    pr('gh api -X PUT repos/o/r/branches/main/protection -F enforce_admins=true').decisive?.capability,
    modify,
  );
  assert.equal(
    pr('gh api -X PUT repos/o/r/branches/main/protection --input prot-ok.json').decisive?.capability,
    modify,
  );
  assert.equal(pr('gh api -X POST repos/o/r/rulesets --input rs-plain.json').decisive?.capability, modify);
  assert.equal(
    pr('gh api -X POST repos/o/r/rulesets -f name=x -f enforcement=active').decisive?.capability,
    modify,
  );
  // a body the kernel cannot read is not a bypass it can prove: it is the administrable act, behind the human gate
  assert.equal(pr('gh api -X POST repos/o/r/rulesets --input missing.json').decisive?.capability, modify);
  assert.equal(pr('gh api -X POST repos/o/r/rulesets --input /etc/hosts').decisive?.capability, modify);
  // reading a protection, a ruleset, a help text, is not touching it
  for (const read of [
    'gh api repos/o/r/branches/main/protection',
    'gh api repos/o/r/branches/main/protection/enforce_admins',
    'gh api -X GET repos/o/r/rulesets',
    'gh api repos/o/r/rulesets/5',
    'gh pr merge --help',
    'gh pr merge 3 --help',
  ])
    assert.equal(pr(read).verdict, 'ALLOW', read);
  // a force push is NOT this: it is the remote history rewrite, with its own identifier and its own gate
  assert.equal(
    run('git push --force origin main', {}, enabledTable).decisive?.capability,
    'git.remote.push.force',
  );
  assert.equal(run('git push --force origin main', {}, enabledTable).verdict, 'ASK');
});

/** the administrable identifiers that no matcher reached, and the one-per-act identifiers added with them */
const REACHED: Readonly<Record<string, readonly string[]>> = {
  'forge.branch.protection.modify': [
    'gh api -X PUT repos/o/r/branches/main/protection -F enforce_admins=true -f required_status_checks=null',
    'gh api -X PUT repos/o/r/branches/main/protection --input prot-ok.json',
    'gh api -X DELETE repos/o/r/branches/main/protection',
    'gh api -X POST repos/o/r/branches/main/protection/enforce_admins',
    'gh api --method PATCH repos/o/r/branches/main/protection/required_pull_request_reviews -F required_approving_review_count=2',
    'gh api -X DELETE repos/o/r/branches/main/protection/required_status_checks',
    'gh api -X POST repos/o/r/rulesets -f name=x -f enforcement=active',
    'gh api -X PUT repos/o/r/rulesets/5 --input rs-plain.json',
    'gh api -X DELETE repos/o/r/rulesets/5',
    'gh api -X POST orgs/o/rulesets -f name=x',
    'gh api -X POST repos/o/r/tags/protection -f pattern=v*',
    'gh api -X DELETE /repos/o/r/branches/release/1.x/protection',
    'gh -R o/r api -X PUT "repos/{owner}/{repo}/branches/main/protection" -F enforce_admins=true',
    'GH_HOST=ghe.corp gh api -X DELETE api/v3/repos/o/r/branches/main/protection',
    'glab api -X DELETE projects/1/protected_branches/main',
    'glab api -X POST projects/1/protected_branches -f name=main',
    'glab api -X PUT projects/1/approval_rules/7 -f approvals_required=0',
    'az repos policy approver-count update --id 7 --minimum-approver-count 0',
    'az repos policy delete --id 7',
  ],
  'forge.repo.permissions.modify': [
    'gh api -X PUT repos/o/r/collaborators/bob -f permission=admin',
    'gh api -X DELETE repos/o/r/collaborators/bob',
    'gh api -X POST repos/o/r/keys -f key=ssh-rsa -f title=ci',
    'gh api -X DELETE repos/o/r/keys/12',
    'gh api -X PUT orgs/o/teams/t/repos/o/r -f permission=push',
    'gh api -X PUT teams/9/repos/o/r -f permission=push',
    'gh api -X PUT orgs/o/memberships/bob -f role=admin',
    'gh api -X PATCH repos/o/r -f visibility=public',
    'gh api -X PATCH repos/o/r -F private=false',
    'gh repo edit o/r --visibility public --accept-visibility-change-consequences',
    'gh repo edit --enable-secret-scanning-push-protection=false',
    'gh repo rename new-name',
    'gh repo archive o/r --yes',
    'gh repo unarchive o/r --yes',
    'gh repo deploy-key add key.pub',
    'gh repo deploy-key delete 12',
    'glab api -X POST projects/1/members -f user_id=3 -f access_level=40',
    'glab api -X DELETE projects/1/deploy_keys/4',
    'glab repo transfer o/r newns',
  ],
  'forge.issue.transition': [
    'gh issue reopen 3',
    'gh issue reopen 3 --comment back',
    'gh -R o/r issue reopen 3',
    'glab issue reopen 3',
    'gh project item-edit --id PVTI_x --field-id F --project-id P --single-select-option-id O',
    'gh project item-add 1 --owner o --url https://github.com/o/r/issues/3',
    'gh project item-archive 1 --owner o --id PVTI_x',
  ],
  'forge.repo.delete': [
    'gh repo delete o/r --yes',
    'gh repo delete --yes',
    'glab repo delete o/r',
    'gh api -X DELETE repos/o/r',
    'gh api -i -X DELETE repos/o/r',
    'gh api -X DELETE repos/acme/graphql-gateway',
    'gh api -X DELETE repos/o/r?x=1',
    'gh api -X DELETE https://api.github.com/repos/o/r',
    'glab api -X DELETE projects/1',
  ],
  'forge.release.delete': [
    'gh release delete v1.0.0 --yes',
    'gh release delete v1.0.0 --cleanup-tag',
    'gh release delete-asset v1.0.0 a.zip',
    'glab release delete v1.0.0',
    'gh api -X DELETE repos/o/r/releases/12',
    'gh api -X DELETE repos/o/r/releases/assets/9',
  ],
  'forge.issue.delete': ['gh issue delete 3 --yes', 'gh -R o/r issue delete 3', 'glab issue delete 3'],
  // the raw-API spelling of the integration decision is the integration decision (the organization locks the act)
  'forge.pr.merge': [
    'gh api -X PUT repos/o/r/pulls/3/merge',
    'gh api -X PUT repos/o/r/pulls/3/merge -f merge_method=squash',
    'gh api --method PUT /repos/o/r/pulls/3/merge',
    'glab api -X PUT projects/1/merge_requests/3/merge',
  ],
};

test('administrable forge identifiers are REACHED: enabling exactly one turns its spellings to ASK, and enabling everything else leaves them DENY', () => {
  for (const [id, spellings] of Object.entries(REACHED)) {
    assert.ok(table.organizationLocked.includes(id), `${id} is administrable`);
    assert.ok(!table.absoluteDenies.includes(id), `${id} is not absolute`);
    assert.ok(
      table.matchers.some((m) => m.capability === id),
      `${id} must have at least one matcher`,
    );
    const only = enabling(id);
    const rest = enablingAllBut(id);
    for (const cmd of spellings) {
      for (const profile of PROFILES) {
        const d = run(cmd, { profile, ...inBodies });
        assert.equal(d.verdict, 'DENY', `${cmd}: DENY by default (${profile})`);
        assert.equal(d.decisive?.capability, id, `${cmd} -> ${d.decisive?.capability}, wanted ${id}`);
      }
      const on = run(cmd, inBodies, only);
      assert.equal(on.verdict, 'ASK', `${cmd}: ASK when exactly ${id} is enabled`);
      assert.equal(on.decisive?.capability, id, cmd);
      const off = run(cmd, inBodies, rest);
      assert.equal(off.verdict, 'DENY', `${cmd}: still DENY when everything BUT ${id} is enabled`);
    }
  }
});

test('a request body cannot steer WHICH act a request is: the endpoint and the verb are read from the command, the body only for what it switches off', () => {
  // the body of a ruleset write names another endpoint and another verb; only the identifier the endpoint names applies,
  // so an organization that enabled the identifier the body points at gets nothing
  const onlyPermissions = enabling('forge.repo.permissions.modify');
  const onlyDelete = enabling('forge.repo.delete');
  for (const t of [onlyPermissions, onlyDelete]) {
    const r = run('gh api -X PUT repos/o/r/rulesets/1 --input spoof.json', inBodies, t);
    assert.equal(r.verdict, 'DENY');
    assert.equal(r.decisive?.capability, 'forge.branch.protection.modify');
  }
  // the other direction: a collaborators write whose body names a ruleset endpoint is a permissions change, whichever
  // identifier is listed first among the patterns
  for (const t of [enabling('forge.branch.protection.modify'), onlyDelete]) {
    const r = run('gh api -X PUT repos/o/r/collaborators/bob --input spoof.json', inBodies, t);
    assert.equal(r.verdict, 'DENY');
    assert.equal(r.decisive?.capability, 'forge.repo.permissions.modify');
  }
  // ...and the same document under the endpoint it really belongs to is the administrable act, once enabled
  assert.equal(
    run(
      'gh api -X PUT repos/o/r/rulesets/1 --input spoof.json',
      inBodies,
      enabling('forge.branch.protection.modify'),
    ).verdict,
    'ASK',
  );
  // a piped literal that does NOT switch anything off is the administrable act, not a bypass
  assert.equal(
    run(
      `echo '{"enforce_admins": true}' | gh api -X PUT repos/o/r/branches/main/protection --input -`,
      inBodies,
      enabledTable,
    ).decisive?.capability,
    'forge.branch.protection.modify',
  );
});

test('administrable forge identifiers: an organization asking for ALLOW gets ASK with the clamp recorded; no other layer may widen them', () => {
  for (const id of Object.keys(REACHED)) {
    const asks = compileAuthority(loadControlPlane(ROOT), {
      organization: overlayDoc('organization', 'Allowed', id),
    });
    assert.equal(asks.effective[id], 'ASK', id);
    assert.match(asks.provenance[id]!.at(-1)!.layer, /clamped to the ASK ceiling/, id);
    for (const cmd of REACHED[id]!.slice(0, 2))
      assert.notEqual(run(cmd, inBodies, asks).verdict, 'ALLOW', cmd);
    assert.throws(
      () => compileAuthority(loadControlPlane(ROOT), { overlay: overlayDoc('overlay', 'Allowed', id) }),
      /widen/,
      `overlay -> ${id}`,
    );
    const withMode = editedControlPlane((_f, write) =>
      write(
        'modes/evil.md',
        `---\nschema: ego.mode/1\nid: EVIL\nkind: authority\noverrides:\n  - capability: ${id}\n    verdict: ALLOW\n---\n# EVIL\n`,
      ),
    );
    assert.throws(() => loadControlPlane(withMode), /organization-locked deny/, `mode -> ${id}`);
  }
});

test('administrable forge identifiers: reads of the same endpoints and ordinary forge work stay as they were', () => {
  for (const cmd of [
    'gh api repos/o/r/collaborators',
    'gh api repos/o/r/keys',
    'gh api repos/o/r/releases',
    'gh api -X GET repos/o/r',
    'gh repo view o/r',
    'gh issue view 3',
    'gh issue list',
    'glab api projects/1/members',
  ])
    assert.equal(run(cmd, inBodies).verdict, 'ALLOW', cmd);
  // the narrow, administrable-at-ASK writes are untouched
  assert.equal(run('gh issue comment 3 -b hi').verdict, 'ASK');
  assert.equal(run('gh pr comment 3 -b hi').verdict, 'ASK');
  assert.equal(run('gh issue edit 3 --title x').decisive?.capability, 'forge.issue.edit');
  assert.equal(run('gh issue close 3').decisive?.capability, 'forge.issue.close');
  assert.equal(run('gh pr merge 3 --squash').decisive?.capability, 'forge.pr.merge');
  assert.equal(run('gh api -X POST repos/o/r/issues -f title=x').decisive?.capability, 'forge.api.mutate');
});
