// SYNTHETIC FIXTURES FOR THE SECRET DETECTOR CATALOGUE (receipt finding 18).
//
// One entry per detector in `control-plane/secrets/`, keyed by detector id. closure-evidence.test.ts loads the
// catalogue and fails when a detector has no fixture here, when a fixture names a detector that is gone, and when a
// fixture is not reported BY ITS OWN DETECTOR in the full ordered set - so a detector that a bad edit empties, that
// an earlier detector shadows, or that someone deletes, turns a named test red instead of passing silently.
//
// THESE ARE NOT CREDENTIALS. Every value is a prefix that matches the detector's format plus a body CYCLED from a
// fixed alphabet (`abcdefg…`), which is deterministic, plainly artificial, and never something a provider issued.
// No literal below matches a detector: each is assembled from pieces, because the repository's own pre-commit and
// pre-push scans run these same detectors over this file (closure-evidence.test.ts scans this source to prove it).

const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const UPPER = LOWER.toUpperCase();
const DIGITS = '0123456789';
const HEX = '0123456789abcdef';
const ALNUM = LOWER + UPPER + DIGITS;
const LOWER_DIGITS = LOWER + DIGITS;
const UPPER_DIGITS = UPPER + DIGITS;
const BASE64 = ALNUM + '+/';

/** `n` characters of `alphabet`, cycled: the body of every synthetic value */
const fill = (alphabet: string, n: number): string => alphabet.repeat(Math.ceil(n / alphabet.length)).slice(0, n);

export interface SecretFixture {
  /** the text handed to redact() */
  readonly input: string;
  /** the part of `input` that must be GONE from the redacted text: the whole input for a distinctive-prefix token,
   *  the value alone for a detector keyed on the name that precedes it */
  readonly secret: string;
  /** the text is file content, which enables the file-only detectors */
  readonly isFile?: boolean;
}

/** a token whose whole text is the secret */
const token = (value: string): SecretFixture => ({ input: value, secret: value });
/** a secret introduced by a name: only the value is the secret, the name stays readable */
const named = (name: string, value: string): SecretFixture => ({ input: name + value, secret: value });

const pem = (kind: string, body: string): SecretFixture => ({
  input: ['-----' + 'BEGIN ' + kind + '-----', body, '-----' + 'END ' + kind + '-----'].join('\n'),
  secret: body,
});

export const FIXTURES: Readonly<Record<string, SecretFixture>> = {
  /* ---- application ---------------------------------------------------------------------------------------- */
  'app.password-kv': named('pass' + 'word=', fill(ALNUM, 14)),
  'app.secret-kv': named('session_' + 'secret: ', fill(ALNUM, 24)),
  'app.generic-secret-assignment': named('DEPLOY_' + 'TOKEN=', fill(ALNUM, 20)),

  /* ---- cloud ---------------------------------------------------------------------------------------------- */
  'cloud.aws.access-key': token('ASIA' + fill(UPPER_DIGITS, 16)),
  'cloud.aws.secret-key': named('aws_secret_access_' + 'key = ', fill(BASE64, 40)),
  'cloud.aws.session-token': named('aws_session_' + 'token=', fill(BASE64, 48)),
  'cloud.gcp.service-account': {
    input: '{"type": "service_' + 'account", "project_id": "synthetic-project", "client_email": "svc@synthetic.example"}',
    secret: 'synthetic-project',
  },
  'cloud.gcp.oauth-access-token': token('ya29' + '.' + fill(ALNUM + '_-', 40)),
  'cloud.gcp.api-key': token('AIza' + fill(ALNUM + '_-', 35)),
  'cloud.azure.client-secret': named('azure_client_' + 'secret=', fill(ALNUM + '._~-', 30)),
  'cloud.azure.storage-key': named('Account' + 'Key=', fill(BASE64, 43) + '='),
  'cloud.digitalocean.token': token('dop_' + 'v1_' + fill(HEX, 64)),
  'cloud.signed-url': named('https://bucket.example/object?X-Amz-' + 'Signature=', fill(HEX, 32)),

  /* ---- database ------------------------------------------------------------------------------------------- */
  'db.url-credentials': named('mysql://app:', fill(ALNUM, 12) + '@db.internal:3306/app'),
  'db.password-kv': named('database_' + 'password: ', fill(ALNUM, 14)),
  // a value that BEGINS with `$` is a variable reference to the generic key-value rule and a password to this one
  // (a key that ends in the word the generic rule looks for is itself a match, so these two keys are assembled too)
  ['db.jdbc-' + 'password']: named('jdbc:sqlserver://db.internal:1433;databaseName=app;pass' + 'word=', '$' + fill(ALNUM, 12)),

  /* ---- files ---------------------------------------------------------------------------------------------- */
  'file.env-line': { ...named('SYNTHETIC_' + 'SETTING=', fill(ALNUM, 16)), isFile: true },

  /* ---- git and forges ------------------------------------------------------------------------------------- */
  'forge.github.pat': token('ghp' + '_' + fill(ALNUM, 36)),
  'forge.github.fine-grained': token('github' + '_pat_' + fill(ALNUM, 30)),
  'forge.gitlab.token': token('glpat' + '-' + fill(ALNUM, 20)),
  'forge.azure-devops.pat': named('ado_' + 'pat=', fill(ALNUM, 46)),
  'forge.bitbucket.token': named('bitbucket_' + 'token=', fill(ALNUM, 24)),
  'forge.github.fine-grained-pat': token('github' + '_pat_' + fill(ALNUM, 82)),
  'forge.github.app-token': token('ghs' + '_' + fill(ALNUM, 36)),

  /* ---- http ----------------------------------------------------------------------------------------------- */
  'http.authorization.bearer': named('Authorization: ' + 'Bearer ', fill(ALNUM, 24)),
  'http.authorization.basic': named('Authorization: ' + 'Basic ', fill(BASE64, 24)),
  'http.authorization.generic': named('Proxy-Authorization: ' + 'Negotiate ', fill(ALNUM, 24)),
  'http.api-key-header': named('x-api-' + 'key: ', fill(ALNUM, 24)),
  'http.cookie': named('Set-' + 'Cookie: ', 'session=' + fill(ALNUM, 24)),

  /* ---- infrastructure ------------------------------------------------------------------------------------- */
  'infra.dockerhub.pat': token('dckr' + '_pat_' + fill(ALNUM, 28)),
  'infra.private-key-block': pem('RSA PRIVATE ' + 'KEY', fill(BASE64, 64)),
  'infra.flyio': token('FlyV1 ' + fill(ALNUM, 44)),
  'infra.sonarqube': token('sqa' + '_' + fill(HEX, 40)),
  'infra.putty-private-key': {
    input: ['PuTTY-User-Key-File-' + '3: ssh-rsa', 'Encryption: none', 'Private-Lines: 1', fill(BASE64, 48), 'Private-MAC: ' + fill(HEX, 16)].join('\n'),
    secret: fill(BASE64, 48),
  },
  'infra.kube.token': named('to' + 'ken: ', fill(ALNUM, 40)),
  'infra.kube.client-key-data': named('client-key-' + 'data: ', fill(BASE64, 48)),
  'infra.vault.token': token('hvs' + '.' + fill(ALNUM, 26)),
  'infra.argocd.token': named('argocd_auth_' + 'token=', fill(ALNUM, 30)),
  ['infra.helm.registry-' + 'password']: named('registry_' + 'password=', fill(ALNUM, 14)),
  'infra.terraform-cloud': token(fill(LOWER_DIGITS, 14) + '.atlas' + 'v1.' + fill(ALNUM, 64)),
  'infra.planetscale': token('pscale' + '_pw_' + fill(ALNUM, 40)),
  'infra.tailscale': token('tskey' + '-auth-' + fill(ALNUM, 24)),
  'infra.supabase': token('sbp' + '_' + fill(HEX, 40)),

  /* ---- more providers, with distinctive prefixes ---------------------------------------------------------- */
  'saas.databricks': token('dapi' + fill(HEX, 32)),
  'saas.shopify': token('shpat' + '_' + fill(HEX, 32)),
  'saas.newrelic': token('NRAK' + '-' + fill(UPPER_DIGITS, 27)),
  'saas.grafana-sa': token('glsa' + '_' + fill(ALNUM, 32) + '_' + fill(HEX, 8)),
  'saas.grafana-cloud': token('glc' + '_' + fill(ALNUM, 40)),
  'saas.square': token('sq0atp' + '-' + fill(ALNUM, 24)),
  'oauth.google-client-secret': token('GOCSPX' + '-' + fill(ALNUM, 28)),
  'saas.stripe-webhook': token('whsec' + '_' + fill(ALNUM, 40)),
  'saas.linear': token('lin_api' + '_' + fill(ALNUM, 40)),
  'saas.notion': token('ntn' + '_' + fill(ALNUM, 40)),
  'saas.figma': token('figd' + '_' + fill(ALNUM, 40)),
  'saas.doppler': token('dp.pt' + '.' + fill(ALNUM, 40)),
  'saas.sentry-auth': token('sntrys' + '_' + fill(ALNUM, 40)),
  'saas.postman': token('PMAK' + '-' + fill(HEX, 24) + '-' + fill(HEX, 34)),
  'payments.braintree': token('access_token' + '$production$' + fill(LOWER_DIGITS, 16) + '$' + fill(HEX, 32)),
  'saas.netlify': token('nfp' + '_' + fill(ALNUM, 38)),
  'saas.render': token('rnd' + '_' + fill(ALNUM, 24)),
  'registry.rubygems': token('rubygems' + '_' + fill(HEX, 48)),
  'registry.nuget': token('oy2' + fill(LOWER_DIGITS, 42)),
  'saas.atlassian': token('ATATT3xFfGF0' + fill(ALNUM, 190)),
  'saas.xai': token('xai' + '-' + fill(ALNUM, 64)),
  'saas.perplexity': token('pplx' + '-' + fill(ALNUM, 44)),
  'saas.langsmith': token('lsv2' + '_pt_' + fill(ALNUM, 32) + '_' + fill(ALNUM, 10)),
  'saas.pinecone': token('pcsk' + '_' + fill(ALNUM, 44)),
  'saas.notion-internal': token('secret' + '_' + fill(ALNUM, 43)),
  'saas.linear-oauth': token('lin_oauth' + '_' + fill(ALNUM, 44)),
  'saas.newrelic-license': token(fill(HEX, 35) + 'NR' + 'AL'),
  'saas.hubspot': token('pat' + '-na1-' + [8, 4, 4, 4, 12].map((n) => fill(HEX, n)).join('-')),
  'saas.airtable': token('pat' + fill(ALNUM, 14) + '.' + fill(HEX, 64)),
  'saas.dropbox': token('sl' + '.' + fill(ALNUM, 74)),
  'saas.dynatrace': token('dt0c01' + '.' + fill(UPPER_DIGITS, 24) + '.' + fill(HEX, 64)),
  'saas.meta-graph': token('EAA' + fill(ALNUM, 94)),
  'saas.replicate': token('r8' + '_' + fill(ALNUM, 40)),
  'saas.groq': token('gsk' + '_' + fill(ALNUM, 44)),
  'saas.mailgun': token('key' + '-' + fill(LOWER_DIGITS, 32)),
  'saas.slack': token('xoxb' + '-' + fill(DIGITS, 12) + '-' + fill(ALNUM, 24)),
  'saas.discord': token('M' + fill(ALNUM, 23) + '.' + fill(ALNUM, 6) + '.' + fill(ALNUM, 27)),
  'saas.telegram': token(fill(DIGITS, 9) + ':' + fill(ALNUM, 35)),

  /* ---- oauth and identity --------------------------------------------------------------------------------- */
  'oauth.jwt': token('eyJ' + fill(ALNUM, 20) + '.' + fill(ALNUM, 24) + '.' + fill(ALNUM, 32)),
  'oauth.client-secret': named('client_' + 'secret: ', fill(ALNUM, 24)),
  'oauth.tokens': named('access_' + 'token=', fill(ALNUM, 32)),
  'oauth.authorization-code': named('https://idp.example/callback?' + 'code=', fill(ALNUM, 24)),

  /* ---- saas and AI providers ------------------------------------------------------------------------------ */
  'saas.stripe': token('sk' + '_live_' + fill(ALNUM, 24)),
  'saas.npm-token': token('npm' + '_' + fill(ALNUM, 36)),
  'saas.pypi-token': token('pypi' + '-' + fill(ALNUM, 40)),
  'saas.twilio': token('SK' + fill(HEX, 32)),
  'saas.sendgrid': token('SG' + '.' + fill(ALNUM, 22) + '.' + fill(ALNUM, 43)),
  'ai.openai': token('sk' + '-proj-' + fill(ALNUM, 40)),
  'ai.anthropic': token('sk' + '-ant-api03-' + fill(ALNUM, 40)),
  'ai.huggingface': token('hf' + '_' + fill(ALNUM, 34)),
  'ai.generic-provider-key': named('mistral_api_' + 'key=', fill(ALNUM, 32)),
  'ci.secret-kv': named('ci_' + 'secret=', fill(ALNUM, 24)),

  /* ---- urls ----------------------------------------------------------------------------------------------- */
  'url.embedded-credentials': named('https://alice:', fill(ALNUM, 14) + '@git.example.com/repo.git'),
  'url.sensitive-query': named('https://api.example.com/v1/items?api_' + 'key=', fill(ALNUM, 24)),
};
