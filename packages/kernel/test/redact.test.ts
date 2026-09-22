import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadControlPlane } from '../src/control-plane/load.ts';
import { redact, allDetectors, isSensitiveFileName } from '../src/redaction/redact.ts';
import { redactCurl } from '../src/redaction/curl.ts';

const ROOT = new URL('../../../control-plane/', import.meta.url).pathname;
const detectors = allDetectors(loadControlPlane(ROOT).secrets);

const SECRETS: Array<[string, string, string]> = [
  [
    'github pat',
    'token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
  ],
  ['gitlab pat', 'export GITLAB_TOKEN=glpat-abcdefghijklmnopqrst', 'glpat-abcdefghijklmnopqrst'],
  ['aws key', 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE', 'AKIAIOSFODNN7EXAMPLE'],
  [
    'aws secret',
    'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  ],
  [
    'jwt',
    'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
  ],
  ['postgres url', 'DATABASE_URL=postgres://app:s3cr3tpw@db.internal:5432/app', 's3cr3tpw'],
  ['mongodb url', 'mongodb+srv://user:hunter22@cluster0.example.net/db', 'hunter22'],
  ['redis url', 'redis://:redispass123@cache:6379/0', 'redispass123'],
  [
    'openai',
    'OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz1234567890',
    'sk-proj-abcdefghijklmnopqrstuvwxyz1234567890',
  ],
  ['anthropic', 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz', 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz'],
  ['stripe', 'sk_live_4eC39HqLyjWDarjtT1zdp7dc', 'sk_live_4eC39HqLyjWDarjtT1zdp7dc'],
  ['slack', 'xoxb-123456789012-abcdefghijklmnop', 'xoxb-123456789012-abcdefghijklmnop'],
  [
    'private key',
    '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ==\n-----END OPENSSH PRIVATE KEY-----',
    'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ==',
  ],
  [
    'signed url',
    'https://bucket.s3.amazonaws.com/key?X-Amz-Signature=deadbeefdeadbeefdeadbeef&X-Amz-Expires=3600',
    'deadbeefdeadbeefdeadbeef',
  ],
  ['url creds', 'https://alice:Pa55word!@git.example.com/repo.git', 'Pa55word!'],
  ['client secret', 'client_secret: "abcd1234efgh5678"', 'abcd1234efgh5678'],
  [
    'vault token',
    'VAULT_TOKEN=hvs.CAESIJlmnopqrstuvwxyz0123456789ABCDEF',
    'hvs.CAESIJlmnopqrstuvwxyz0123456789ABCDEF',
  ],
  ['password kv', 'password=SuperSecret99', 'SuperSecret99'],
  ['nested json', '{"config":{"db":{"password":"n3st3dpw"}}}', 'n3st3dpw'],
  [
    'ado pat',
    'AZURE_DEVOPS_PAT=abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop',
    'abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop',
  ],
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
  const input =
    'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const lowered = redact(input, detectors, { overlaySeverities: { 'oauth.jwt': 'warn' } });
  assert.ok(lowered.findings.filter((f) => f.detector === 'oauth.jwt').every((f) => f.severity === 'block'));
  const raised = redact('Cookie: sid=abcdefghijklmnop', detectors, {
    overlaySeverities: { 'http.cookie': 'block' },
  });
  assert.ok(raised.blocked);
});

test('sensitive file names', () => {
  assert.ok(isSensitiveFileName('.env', loadControlPlane(ROOT).secrets));
  assert.ok(isSensitiveFileName('service-account-prod.json', loadControlPlane(ROOT).secrets));
  assert.ok(!isSensitiveFileName('README.md', loadControlPlane(ROOT).secrets));
});

test('round-8: the exact password span is redacted even when it equals the username or scheme', () => {
  for (const s of [
    'psql postgres://admin:admin@db.internal:5432/app',
    'DATABASE_URL=postgres://postgres:postgres@localhost:5432/app',
    'mysql://root:root@127.0.0.1:3306/db',
  ]) {
    const r = redact(s, detectors);
    assert.ok(r.blocked, `${s} blocked`);
    // the credential between ':' and '@' must be gone; nothing after the redaction marker leaks a raw ':<pw>@'
    assert.ok(r.text.includes('[REDACTED'), s);
    assert.doesNotMatch(r.text, /:(admin|postgres|root)@/, `raw password still present in: ${r.text}`);
  }
  // a distinct username:password still redacts only the password
  const d = redact('postgres://appuser:S3cr3tPw99@db/app', detectors);
  assert.ok(!d.text.includes('S3cr3tPw99'));
  assert.ok(d.text.includes('appuser')); // the username is not a secret
});

test('round-8: Slack app-level (xapp-) and refresh (xoxe-) tokens are blocked like xoxb-/xoxp-', () => {
  for (const tok of [
    'xapp-1-A01234567-1234567890123-abcdefabcdef',
    'xoxe-1-My0abcdefghijklmnopqrstuvwxyz012345',
    'xoxb-123456789012-abcdefghijklmnop',
    'xoxp-123456789012-abcdefghijklmnop',
  ]) {
    const r = redact(`const t = "${tok}";`, detectors);
    assert.ok(r.blocked, `${tok} must be blocked`);
    assert.ok(!r.text.includes(tok), `${tok} must be redacted`);
  }
});

test('round-9: npm / PyPI / Azure SAS / DigitalOcean / Docker Hub tokens are blocked', () => {
  const cases: Array<[string, string]> = [
    ['npm', 'authToken=npm_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'],
    ['pypi', 'pypi-AgEIcHlwaS5vcmcCJDU2ZWY3YjE4LWFiY2Q'],
    ['azure-sas', 'Endpoint=sb://x.servicebus.windows.net/;SharedAccessKey=aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uVwXyZ12345a='],
    ['digitalocean', 'dop_v1_' + '0123456789abcdef'.repeat(4)],
    ['dockerhub', 'dckr_pat_aBcDeFgHiJkLmNoPqRsTuVwXyZ01'],
  ];
  for (const [name, s] of cases) {
    const r = redact(s, detectors, { isFile: true });
    assert.ok(r.blocked, `${name} must be blocked`);
  }
  // a plain version string is not a secret
  assert.ok(!redact('const v = "1.2.3";', detectors).blocked);
});

test('round-10: additional distinctive-prefix provider tokens are blocked', () => {
  const toks: Array<[string, string]> = [
    ['databricks', 'dapi' + '0'.repeat(32)],
    ['shopify', 'shpat_' + 'a'.repeat(32)],
    ['terraform', 'a1b2c3d4e5f6g7.atlasv1.' + 'z'.repeat(64)],
    ['newrelic', 'NRAK-' + 'A'.repeat(27)],
    ['grafana', 'glsa_' + 'a'.repeat(32) + '_0a1b2c3d'],
    ['square', 'sq0atp-' + 'a'.repeat(22)],
    ['google-oauth', 'GOCSPX-' + 'a'.repeat(28)],
    ['stripe-webhook', 'whsec_' + 'a'.repeat(40)],
    ['github-pat', 'github_pat_' + 'A'.repeat(60)],
    ['github-app', 'gho_' + 'a'.repeat(36)],
    ['linear', 'lin_api_' + 'a'.repeat(40)],
    ['notion', 'ntn_' + 'a'.repeat(40)],
    ['figma', 'figd_' + 'a'.repeat(40)],
    ['doppler', 'dp.pt.' + 'a'.repeat(40)],
    ['planetscale', 'pscale_pw_' + 'a'.repeat(40)],
    ['sentry', 'sntrys_' + 'a'.repeat(40)],
  ];
  for (const [name, t] of toks) {
    const r = redact('token = "' + t + '"', detectors, { isFile: true });
    assert.ok(r.blocked, `${name} must be blocked`);
    assert.ok(!r.text.includes(t), `${name} must be redacted`);
  }
  // ordinary code that merely starts with a prefix-like word is not a secret
  for (const s of ['const dapiClient = 1;', 'npm install lodash', 'const figure = 3;']) {
    assert.ok(!redact(s, detectors).blocked, s);
  }
});

test('round-11: Postman / Tailscale / Supabase / Atlassian tokens blocked; a secret curl -u username is redacted', () => {
  const toks: Array<[string, string]> = [
    ['postman', 'PMAK-' + '0'.repeat(24) + '-' + '0'.repeat(34)],
    ['tailscale', 'tskey-auth-kAbCdEfG-' + '0'.repeat(40)],
    ['supabase', 'sbp_' + '0'.repeat(40)],
    ['atlassian', 'ATATT3xFfGF0' + 'A'.repeat(184)],
  ];
  for (const [name, t] of toks) {
    const r = redact('cred = "' + t + '"', detectors, { isFile: true });
    assert.ok(r.blocked, `${name} must be blocked`);
    assert.ok(!r.text.includes(t), `${name} must be redacted`);
  }
  // curl -u where the username is itself the secret (Stripe) must not leak the key
  const K = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc';
  const s = redact('curl -u' + K + ':x https://api.stripe.com/v1/charges', detectors);
  assert.ok(!s.text.includes(K), 'the secret -u username must be redacted');
  // a short human username is still kept
  assert.ok(redact('curl -u alice:s3cret https://x', detectors).text.includes('-u alice:[REDACTED:password]'));
});

test('round-12: an AWS secret key inside JSON (and STS SecretAccessKey) is blocked', () => {
  const AWS = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
  for (const s of [
    `{"aws_secret_access_key": "${AWS}"}`,
    `{"SecretAccessKey": "${AWS}"}`,
    `aws_secret_access_key=${AWS}`,
    `aws_secret_access_key: ${AWS}`,
  ]) {
    const r = redact(s, detectors, { isFile: true });
    assert.ok(r.blocked, `must block: ${s}`);
    assert.ok(!r.text.includes(AWS), `must redact: ${s}`);
  }
});

test('round-13 residuals: provider detectors, sensitive file names and curl credential spellings', () => {
  // every one of these is a real provider format that passed through unredacted
  const NEW_SECRETS: Array<[string, string]> = [
    ['google oauth access token', 'ya29.a0AfB_byC9f3a2b1c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c8d7e6f5a4b3c'],
    ['gitlab cluster agent token', 'glcbt-64_7dKxPq3mVn2LwRt9sYbA'],
    ['gitlab oauth token', 'gloas-9f3a2b1c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c8d7e6f5a4b3c2d1e0f9a'],
    ['docker hub org token', 'dckr_oat_9f3a2b1c8d7e6f5a4b3c2d1e0f9a8b7c'],
    ['replicate token', 'r8_Nv3QpZ7bKf2sYxLmTgWd8AcJeRh1UoBi5nDq4'],
    ['groq key', 'gsk_8ZqLm4TnPxWvRb2KcYdA1WGdyb3FYs7HgJkQeUiOpNzXvTrMlCa'],
    ['mailgun key', 'key-3ax6xnjp29jd6fds4gc373sgvjxteol0'],
    ['braintree token', 'access_token$production$8p9bxz4cq7fkxr2d$0123456789abcdef0123456789abcdef'],
    ['netlify token', 'nfp_abcdefghijklmnopqrstuvwxyz0123456789ab'],
    ['render key', 'rnd_abcdefghijklmnopqrstuvwx'],
    ['rubygems key', 'rubygems_0123456789abcdef0123456789abcdef0123456789abcdef'],
    ['nuget key', 'oy2abcdefghijklmnopqrstuvwxyz234567abcdefghi'],
    ['slack trigger webhook', 'https://hooks.slack.com/triggers/T0ABCDE1234/1234567890123/abcdef1234567890abcdef12'],
    ['slack session token', 'xoxc-511111111-31111111111-3111111111111-e039d02840a0b9379c'],
  ];
  for (const [name, secret] of NEW_SECRETS) {
    const r = redact(`value: ${secret}`, detectors);
    assert.ok(r.blocked, `must block: ${name}`);
    assert.ok(!r.text.includes(secret), `must redact: ${name}`);
  }
  // `aws configure set aws_secret_access_key <key>` separates the key with whitespace, not : or =
  const AWS = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
  const cfg = redact(`aws configure set aws_secret_access_key ${AWS}`, detectors);
  assert.ok(cfg.blocked && !cfg.text.includes(AWS), 'aws configure set form must be blocked');
  // a PuTTY key is a private key like any other, and *.ppk is a secret-bearing file name
  const ppk = redact(
    'PuTTY-User-Key-File-3: ssh-rsa\nEncryption: none\nPublic-Lines: 1\nAAAA\nPrivate-Lines: 1\nBBBB\nPrivate-MAC: 0123abcd',
    detectors,
  );
  assert.ok(ppk.blocked && !ppk.text.includes('BBBB'), 'PuTTY private key must be blocked');
  assert.ok(isSensitiveFileName('server.ppk', loadControlPlane(ROOT).secrets));

  // curl: a short-option CLUSTER ending in u, glued credentials, and a curl inside a substitution
  const PW = 'Hq7Rt2Wx9Lm4Pz6Kd8Vb';
  for (const line of [
    `curl -sSu svc-deploy:${PW} https://api.example.com/v1/export`,
    `RESP=\`curl -u svc-deploy:${PW} https://api.example.com/v1/export\``,
    `x=$(curl -u alice:${PW} https://api.example.com)`,
    `curl -ualice:${PW} https://api.example.com`,
    `curl -fsSLuadmin:${PW} https://api.example.com`,
  ]) {
    const r = redactCurl(line);
    assert.ok(!r.text.includes(PW), `must redact credentials: ${line}`);
    assert.ok(r.findings.some((f) => f.kind === 'curl.user'), `must report curl.user: ${line}`);
  }
  assert.equal(redactCurl('curl https://example.com/plain').findings.length, 0);
});

test('round-14 residuals: aliased and spaced secret key names, more providers, curl continuation and -U', () => {
  const AWS = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
  // the key name may be spaced (an `aws configure` transcript), carry a CLI prompt default, or use a short alias
  for (const s of [
    `AWS Secret Access Key [None]: ${AWS}`,
    `AWS_SECRET_KEY=${AWS}`,
    `aws_secret_key: ${AWS}`,
  ]) {
    const r = redact(s, detectors);
    assert.ok(r.blocked && !r.text.includes(AWS), `must block: ${s.slice(0, 40)}`);
  }
  // a warn-level generic assignment must not swallow a PEM block and destroy its anchor
  const pem =
    'GOOGLE_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n-----END PRIVATE KEY-----';
  const r = redact(pem, detectors);
  assert.ok(r.blocked && !r.text.includes('MIIEvQIBADAN'), 'the private key block must still be found');
  assert.ok(r.findings.some((f) => f.detector === 'infra.private-key-block'));

  const MORE: Array<[string, string]> = [
    ['gitlab feature-flag token', 'glffct-9f3a2b1c8d7e6f5a4b3c2d1e0f9a8b7c'],
    ['notion internal token', 'secret_9f3a2b1c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2bX'],
    ['linear oauth token', 'lin_oauth_0123456789abcdef0123456789abcdef01234567890a'],
    ['xai key', 'xai-9f3a2b1c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c8d7e6f5a4b3c2d1e0f9a8b7c6d5e'],
    ['perplexity key', 'pplx-9f3a2b1c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c'],
    ['sonarqube token', 'sqp_0123456789abcdef0123456789abcdef01234567'],
    ['cloudinary url', 'cloudinary://123456789012345:abcdefghijklmnopqrstuvwxyz1@mycloud'],
    ['authorization with a scheme', 'Authorization: SSWS 00QCjAl4MlV-WPXMRNmFwVzp8QMNvHOK0F5IGKtGiE'],
    ['kube token as JSON', '{"user":{"token":"kubernetes-dashboard-token-abcdefghij"}}'],
  ];
  for (const [name, secret] of MORE) {
    const out = redact(secret, detectors);
    assert.ok(out.blocked, `must block: ${name}`);
  }
  assert.equal(redact('normal text with no secret at all', detectors).blocked, false);

  // curl: a backslash-newline continuation is one logical command, and -U is --proxy-user
  const PW = 'Qp7nRt3Wz9Lk2Vb4';
  for (const line of [
    `curl -sS \\\n  -u svc-ci:${PW} \\\n  https://artifacts.example.com/y.tgz`,
    `curl -sSU svc-proxy:${PW} -x proxy.corp:3128 https://artifacts.example.com`,
    `curl --proxy-user alice:${PW} https://x`,
  ]) {
    const out = redactCurl(line);
    assert.ok(!out.text.includes(PW), `must redact: ${line.slice(0, 40)}`);
    assert.ok(out.findings.some((f) => f.kind === 'curl.user'));
  }
});

test('round-15 residuals: the -u/-U option letter is the first one, not the last', () => {
  // Math.max(indexOf('u'), indexOf('U')) could pick a letter INSIDE the credential and split the secret in two,
  // leaving part of it visible. The option letter is the first u/U whose cluster prefix is itself option letters.
  for (const PW of ['UPPERCASEinside123', 'lowerUthenUmore456', 'Qp7nRt3Wz9Lk2Vb4']) {
    for (const line of [`curl -u alice:${PW} https://x`, `curl -sSualice:${PW} https://x`, `curl -Ualice:${PW} https://x`]) {
      const r = redactCurl(line);
      assert.ok(!r.text.includes(PW), `must not leak any part of the credential: ${line}`);
    }
  }
});
