import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadControlPlane } from '../src/control-plane/load.ts';
import { redact, allDetectors, isSensitiveFileName } from '../src/redaction/redact.ts';
import { redactCurl } from '../src/redaction/curl.ts';

const ROOT = new URL('../../../control-plane/', import.meta.url).pathname;
const detectors = allDetectors(loadControlPlane(ROOT).secrets);

const SECRETS: Array<[string, string, string]> = [
  ['github pat', 'token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'],
  ['gitlab pat', 'export GITLAB_TOKEN=glpat-abcdefghijklmnopqrst', 'glpat-abcdefghijklmnopqrst'],
  ['aws key', 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE', 'AKIAIOSFODNN7EXAMPLE'],
  ['aws secret', 'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'],
  ['jwt', 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'],
  ['postgres url', 'DATABASE_URL=postgres://app:s3cr3tpw@db.internal:5432/app', 's3cr3tpw'],
  ['mongodb url', 'mongodb+srv://user:hunter22@cluster0.example.net/db', 'hunter22'],
  ['redis url', 'redis://:redispass123@cache:6379/0', 'redispass123'],
  ['openai', 'OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz1234567890', 'sk-proj-abcdefghijklmnopqrstuvwxyz1234567890'],
  ['anthropic', 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz', 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz'],
  ['stripe', 'sk_live_4eC39HqLyjWDarjtT1zdp7dc', 'sk_live_4eC39HqLyjWDarjtT1zdp7dc'],
  ['slack', 'xoxb-123456789012-abcdefghijklmnop', 'xoxb-123456789012-abcdefghijklmnop'],
  ['private key', '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ==\n-----END OPENSSH PRIVATE KEY-----', 'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ=='],
  ['signed url', 'https://bucket.s3.amazonaws.com/key?X-Amz-Signature=deadbeefdeadbeefdeadbeef&X-Amz-Expires=3600', 'deadbeefdeadbeefdeadbeef'],
  ['url creds', 'https://alice:Pa55word!@git.example.com/repo.git', 'Pa55word!'],
  ['client secret', 'client_secret: "abcd1234efgh5678"', 'abcd1234efgh5678'],
  ['vault token', 'VAULT_TOKEN=hvs.CAESIJlmnopqrstuvwxyz0123456789ABCDEF', 'hvs.CAESIJlmnopqrstuvwxyz0123456789ABCDEF'],
  ['password kv', 'password=SuperSecret99', 'SuperSecret99'],
  ['nested json', '{"config":{"db":{"password":"n3st3dpw"}}}', 'n3st3dpw'],
  ['ado pat', 'AZURE_DEVOPS_PAT=abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop', 'abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop'],
];

for (const [name, input, secret] of SECRETS) {
  test(`redacts ${name}`, () => {
    const r = redact(input, detectors);
    assert.ok(!r.text.includes(secret), `secret leaked for ${name}: ${r.text}`);
    assert.ok(r.findings.length > 0, `no finding for ${name}`);
    for (const f of r.findings) assert.ok(!JSON.stringify(f).includes(secret));
  });
}

test('curl parsing redacts headers, basic auth, cookies, data and urls but keeps structure', () => {
  const cmd = `curl -X POST -H 'Authorization: Bearer abc.def.ghi123456' -H "X-API-Key: k9k9k9k9k9k9" -u alice:s3cret --cookie "session=abcdef123456" -d 'password=pw123&user=bob' https://user:pw@api.example.com/v1?token=tok123456789`;
  const r = redactCurl(cmd);
  assert.ok(!r.text.includes('abc.def.ghi123456'));
  assert.ok(!r.text.includes('k9k9k9k9k9k9'));
  assert.ok(!r.text.includes('s3cret'));
  assert.ok(!r.text.includes('abcdef123456'));
  assert.ok(!r.text.includes('pw123'));
  assert.ok(!r.text.includes('tok123456789'));
  assert.ok(r.text.includes('-u alice:[REDACTED:password]'));
  assert.ok(r.text.includes("'Authorization: [REDACTED:authorization]'"));
  assert.ok(r.text.includes('user=bob'));
  assert.ok(r.findings.some((f) => f.kind === 'curl.header'));
});

test('false positives: ordinary code and prose are untouched', () => {
  const samples = [
    'const token = await getToken(); // fetch from vault at runtime',
    'git commit -m "add password reset flow"',
    'password: string; // TypeScript field declaration',
    'https://example.com/docs?page=2&sort=asc',
    'export const MAX_RETRIES = 3;',
    'The bearer of this letter is authorized.',
    'AKIA is a prefix, not a key.',
  ];
  for (const s of samples) {
    const r = redact(s, detectors);
    assert.equal(r.text, s, `false positive on: ${s}`);
    assert.equal(r.blocked, false);
  }
});

test('locked minimum severity cannot be lowered by an overlay but can be raised', () => {
  const input = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const lowered = redact(input, detectors, { overlaySeverities: { 'oauth.jwt': 'warn' } });
  assert.ok(lowered.findings.filter((f) => f.detector === 'oauth.jwt').every((f) => f.severity === 'block'));
  const raised = redact('Cookie: sid=abcdefghijklmnop', detectors, { overlaySeverities: { 'http.cookie': 'block' } });
  assert.ok(raised.blocked);
});

test('sensitive file names', () => {
  assert.ok(isSensitiveFileName('.env', loadControlPlane(ROOT).secrets));
  assert.ok(isSensitiveFileName('service-account-prod.json', loadControlPlane(ROOT).secrets));
  assert.ok(!isSensitiveFileName('README.md', loadControlPlane(ROOT).secrets));
});
