// CLOSURE AUDIT 2026-10-01, THIRD WAVE - RC-CTR: THE CONTAINER-CLI VERB AND ENGINE READER (17 findings, all HIGH).
//
// The history of this root cause is one reader answering one question in six places and being right in some of them:
// the help-probe test asked where the verb is on the words that were not quoted, the global-option stripper skipped
// dash-words, the engine resolver stopped at the first bare word, the image detector and the Dockerfile producer
// searched for `build` after `tokens[i - 1]`, and `docker buildx bake` read one bake file. Each fix moved the hole to
// the next spelling. They now ask ONE reader (`containers.ts`), and the groups below pin what it must answer:
//
//   1. the verb is the verb: a quoted one, an abbreviated one (`buildx b`), one behind a group option (`buildx -D build`)
//   2. a build reads the files the tool reads: bake files, compose files, `--set` overrides, inline Dockerfiles
//   3. a file the same command line writes is not the file that was there
//   4. an engine named past the verb is the engine, and a verb nobody modelled is a question
//   5. a builder bound to an endpoint is a binding to that engine
//   6. an output, a cache and a secret are the writes, pushes and reads they are, whatever flag or file says them
//   7. what the same cause left at MEDIUM: login/logout, compose -e, `down --volumes=true`, pods, machines, remote bake
//   8. ordinary container development is untouched
//
// Every group names the verdict a command must reach (never "the same as before"), tries the neighbouring spellings,
// and keeps controls that must stay as they were.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { RANK, verdict, workspace } from './support/corpus.ts';
import { canonicalCommand, carriedHostCommand, readContainerCommand } from '../src/authority/containers.ts';

type Row = [command: string, files: Record<string, string> | undefined, floor: 'ALLOW' | 'ASK' | 'DENY'];

/** the verdict must not fall under the floor: a stricter layer may deny what a row asks for */
function underFloor(rows: readonly Row[]): string[] {
  const out: string[] = [];
  for (const [command, files, floor] of rows) {
    const got = verdict(command, workspace(files ?? {}));
    if (RANK[got]! < RANK[floor]!) out.push(`${floor} <- ${got}: ${command}`);
  }
  return out;
}
/** the verdict must be exactly this, for the controls: they are the proportionality half of the contract */
function notExactly(rows: readonly Row[]): string[] {
  const out: string[] = [];
  for (const [command, files, want] of rows) {
    const got = verdict(command, workspace(files ?? {}));
    if (got !== want) out.push(`${want} <- ${got}: ${command}`);
  }
  return out;
}

const PUSH = 'git push origin main';
const EVIL = `FROM alpine\nRUN ${PUSH}\n`;
const OK = 'FROM alpine\nRUN echo ok\n';
const BAKE_DEFAULT = 'target "default" {\n}\n';

/* ------------------------------------------------------------------------------------------------------------- *
 * 1. THE VERB IS THE VERB
 *
 * r11-166: `docker --context production 'exec' box sh /app/reset.sh --help` was a help probe, because the probe test
 * asked for the verb among the words that were not quoted. A quote is the shell's: by the time docker runs, the word
 * is `exec`. r11-221 / r11-56: `docker buildx -D build .` put an option where the producer looked for `build`, and
 * `buildx b` is `buildx build` under its short name.
 * ------------------------------------------------------------------------------------------------------------- */

test('a quoted verb on a production engine is the verb it spells (r11-166)', () => {
  const rows: Row[] = [
    ["docker --context production 'exec' box sh /app/reset.sh --help", undefined, 'DENY'],
    ["docker '--context' production exec box sh /app/reset.sh --help", undefined, 'DENY'],
    ["docker -H tcp://prod.example.com:2375 'exec' box sh /app/reset.sh --help", undefined, 'DENY'],
    ["docker --context production 'run' alpine ./deploy.sh --help", undefined, 'DENY'],
    ["podman --url tcp://prod.example.com:2375 'exec' box sh /app/reset.sh --help", undefined, 'DENY'],
    ["nerdctl -H tcp://prod.example.com:2375 'exec' box sh /app/reset.sh --help", undefined, 'DENY'],
    ["docker --context production 'exec' box python3 /app/flush.py --help", undefined, 'DENY'],
    ['docker --context production "exec" box sh /app/reset.sh --help', undefined, 'DENY'],
    ['docker --context production e\\xec box sh /app/reset.sh --help', undefined, 'DENY'],
  ];
  assert.deepEqual(underFloor(rows), []);
});

test('a help request is still a probe, quoted verb or not, and never on the strength of a verb that carries words', () => {
  const rows: Row[] = [
    ['docker --context production ps --help', undefined, 'ALLOW'],
    ["docker --context production 'ps' --help", undefined, 'ALLOW'],
    ['docker --context production run --help', undefined, 'ALLOW'],
    ['docker --context production container --help', undefined, 'ALLOW'],
    ['docker --context production compose up --help', undefined, 'ALLOW'],
    ['docker exec --help', undefined, 'ALLOW'],
    ['docker buildx build --help', undefined, 'ALLOW'],
    ['docker compose --help', undefined, 'ALLOW'],
    // the words after the image are the container program's: `--help` there is its flag
    ['docker run --rm alpine ls --help', undefined, 'ALLOW'],
    // a probe performs no verb: the effects the reader names for `login`, `push` and `rm` are not done by asking for the manual
    ['docker login --help', undefined, 'ALLOW'],
    ['podman logout --help', undefined, 'ALLOW'],
    ['docker push --help', undefined, 'ALLOW'],
    ['docker plugin push --help', undefined, 'ALLOW'],
    ['docker rm --help', undefined, 'ALLOW'],
    ['podman pod rm --help', undefined, 'ALLOW'],
    // a plugin gets `--help` as its own argument and may do anything with it
    ['docker pass --help', undefined, 'ASK'],
    ['docker --context production pass --help', undefined, 'DENY'],
  ];
  assert.deepEqual(notExactly(rows), []);
});

test('a build is a build behind a group option, a short name or a management group (r11-221, r11-56)', () => {
  const files = { Dockerfile: EVIL };
  const rows: Row[] = [
    ['docker buildx -D build .', files, 'DENY'],
    ['docker buildx --debug build .', files, 'DENY'],
    ['docker buildx --builder mine build .', files, 'DENY'],
    ['docker -D buildx build .', files, 'DENY'],
    ['docker --debug buildx -D build .', files, 'DENY'],
    ['docker buildx b .', files, 'DENY'],
    ['docker buildx -D b .', files, 'DENY'],
    ['docker builder build .', files, 'DENY'],
    ['docker image build .', files, 'DENY'],
    ['docker buildx build --file Dockerfile.evil .', { 'Dockerfile.evil': EVIL }, 'DENY'],
    ['docker build --no-cache-filter src .', files, 'DENY'],
    ['docker build --build-arg "X=1 2" .', files, 'DENY'],
    ['podman build .', files, 'DENY'],
    ['nerdctl build .', files, 'DENY'],
    // podman builds every file it is given, docker takes the last: each is read
    ['podman build -f ok.df -f evil.df .', { 'ok.df': OK, 'evil.df': EVIL }, 'DENY'],
    ['podman build -f evil.df -f ok.df .', { 'ok.df': OK, 'evil.df': EVIL }, 'DENY'],
    ['docker build -f=evil.df .', { 'evil.df': EVIL }, 'DENY'],
    ['docker build -fevil.df .', { 'evil.df': EVIL }, 'DENY'],
  ];
  assert.deepEqual(underFloor(rows), []);
  // what is not a Dockerfile with a push in it is not gated
  assert.deepEqual(
    notExactly([
      ['docker buildx -D build .', { Dockerfile: OK }, 'ALLOW'],
      ['docker buildx b .', { Dockerfile: OK }, 'ALLOW'],
      ['docker build -t app .', {}, 'ALLOW'],
    ]),
    [],
  );
});

test('an option this reader cannot place in front of the verb, or in front of the build context, is said and not guessed', () => {
  assert.deepEqual(
    notExactly([
      ['docker -x ps', undefined, 'ASK'],
      ['docker --some-future-flag value ps', undefined, 'ASK'],
      ['docker $VERB ps', undefined, 'ASK'],
      ['docker build --some-future-flag value .', { Dockerfile: EVIL }, 'ASK'],
    ]).filter((l) => !/DENY/.test(l)),
    [],
  );
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 2. A BUILD READS THE FILES THE TOOL READS
 *
 * r11-39 40 41 54 55 220 222: the bake reader looked for `docker-bake.hcl` and a compose file named in one place, and
 * never read a compose file, a `--set dockerfile=`, an inline Dockerfile or the Dockerfile a compose service names.
 * ------------------------------------------------------------------------------------------------------------- */

test('bake reads the Dockerfile a compose file names, whichever compose file name the tool finds (r11-39, 54, 55, 222)', () => {
  const rows: Row[] = [
    ['docker buildx bake', { 'compose.yaml': 'services:\n  a:\n    build:\n      context: .\n      dockerfile: Evil\n', Evil: EVIL }, 'DENY'],
    ['docker buildx bake', { 'compose.yaml': 'services:\n  app:\n    build: .\n', Dockerfile: EVIL }, 'DENY'],
    ['docker buildx bake', { 'compose.yml': 'services:\n  a:\n    build: .\n', Dockerfile: EVIL }, 'DENY'],
    ['docker buildx bake', { 'docker-compose.yml': 'services:\n  app:\n    build:\n      context: .\n      dockerfile: Dockerfile.evil\n', Dockerfile: OK, 'Dockerfile.evil': EVIL }, 'DENY'],
    ['docker buildx bake', { 'docker-compose.yaml': 'services:\n  a:\n    build: ./svc\n', 'svc/Dockerfile': EVIL }, 'DENY'],
    ['docker buildx bake', { 'compose.yaml': 'services:\n  a:\n    build:\n      dockerfile_inline: |\n        FROM alpine\n        RUN git push origin main\n' }, 'DENY'],
    ['docker buildx bake', { 'compose.yaml': 'services:\n  a:\n    build:\n      context: ./svc\n      dockerfile: ../Evil\n', Evil: EVIL }, 'DENY'],
  ];
  assert.deepEqual(underFloor(rows), []);
});

test('bake reads the Dockerfile an HCL or JSON target names, its inline Dockerfile and the one it inherits (r11-40)', () => {
  const rows: Row[] = [
    ['docker buildx bake', { 'docker-bake.hcl': 'target "default" {\n  dockerfile-inline = "FROM alpine\\nRUN git push origin main"\n}\n', Dockerfile: OK }, 'DENY'],
    ['docker buildx bake', { 'docker-bake.hcl': 'target "default" {\n  dockerfile-inline = <<EOT\nFROM alpine\nRUN git push origin main\nEOT\n}\n' }, 'DENY'],
    ['docker buildx bake', { 'docker-bake.hcl': 'target "default" {\n  dockerfile = "Evil"\n}\n', Evil: EVIL }, 'DENY'],
    ['docker buildx bake', { 'docker-bake.json': '{"target":{"default":{"dockerfile":"Evil"}}}', Evil: EVIL }, 'DENY'],
    ['docker buildx bake', { 'docker-bake.hcl': 'target "web" {\n  inherits = ["base"]\n}\ntarget "base" {\n  dockerfile = "Evil"\n}\n', Evil: EVIL }, 'DENY'],
    ['docker buildx bake web', { 'docker-bake.hcl': 'target "web" {\n  context = "./app"\n  dockerfile = "build/Dockerfile"\n}\n', 'app/build/Dockerfile': EVIL }, 'DENY'],
    ['docker buildx bake -f ci.hcl', { 'ci.hcl': 'target "x" { dockerfile = "Evil" }', Evil: EVIL }, 'DENY'],
    ['docker buildx bake --file=ci.hcl', { 'ci.hcl': 'target "x" { dockerfile = "Evil" }', Evil: EVIL }, 'DENY'],
    ['docker buildx bake -fci.hcl', { 'ci.hcl': 'target "x" { dockerfile = "Evil" }', Evil: EVIL }, 'DENY'],
    // a file is read by what it holds, whatever it is called, and a byte order mark is not part of its first key
    ['docker buildx bake -f Bakefile', { Bakefile: '{"target":{"x":{"dockerfile":"Evil"}}}', Evil: EVIL }, 'DENY'],
    ['docker buildx bake -f Bakefile', { Bakefile: 'target "x" {\n  dockerfile = "Evil"\n}\n', Evil: EVIL }, 'DENY'],
    ['docker buildx bake', { 'compose.yaml': '\uFEFFservices:\n  a:\n    build: .\n', Dockerfile: EVIL }, 'DENY'],
    ['docker buildx bake', { 'docker-bake.hcl': '\uFEFFtarget "default" {\n  dockerfile = "Evil"\n}\n', Evil: EVIL }, 'DENY'],
    // a `$` that HCL does not interpolate is a dollar sign in a Dockerfile, not a gap in the file
    ['docker buildx bake', { 'docker-bake.hcl': 'target "default" {\n  dockerfile-inline = "FROM alpine\\nRUN echo $HOME"\n}\n' }, 'ALLOW'],
  ];
  assert.deepEqual(rows.filter((r) => r[2] === 'DENY').flatMap((r) => underFloor([r])), []);
  assert.deepEqual(notExactly(rows.filter((r) => r[2] === 'ALLOW')), []);
});

test('bake applies --set on top: a Dockerfile, a context or an inline Dockerfile it names is read (r11-41)', () => {
  const base = { 'docker-bake.hcl': BAKE_DEFAULT, Dockerfile: OK };
  const rows: Row[] = [
    ['docker buildx bake --set default.dockerfile=Evil', { ...base, Evil: EVIL }, 'DENY'],
    ['docker buildx bake --set=default.dockerfile=Evil', { ...base, Evil: EVIL }, 'DENY'],
    ["docker buildx bake --set '*.dockerfile=Evil'", { ...base, Evil: EVIL }, 'DENY'],
    ['docker buildx bake --set default.context=sub', { ...base, 'sub/Dockerfile': EVIL }, 'DENY'],
    ['docker buildx bake --set default.context=sub --set default.dockerfile=Evil', { ...base, 'sub/Evil': EVIL }, 'DENY'],
    ["docker buildx bake --set default.dockerfile-inline=$'FROM alpine\\nRUN git push origin main'", base, 'DENY'],
    ['docker bake --set default.dockerfile=Evil', { ...base, Evil: EVIL }, 'DENY'],
  ];
  assert.deepEqual(underFloor(rows), []);
});

test('bake is `bake` under every spelling of the tool: docker bake, builder bake, buildx f, behind a group option (r11-220)', () => {
  const files = { 'docker-bake.hcl': BAKE_DEFAULT, Dockerfile: EVIL };
  const rows: Row[] = [
    ['docker bake', files, 'DENY'],
    ['docker builder bake', files, 'DENY'],
    ['docker buildx f', files, 'DENY'],
    ['docker -D buildx bake', files, 'DENY'],
    ['docker buildx -D bake', files, 'DENY'],
    ['docker buildx --builder mine bake', files, 'DENY'],
    ['docker buildx bake default', files, 'DENY'],
    ['docker buildx bake --load', files, 'DENY'],
  ];
  assert.deepEqual(underFloor(rows), []);
});

test('the controls: a bake file whose Dockerfiles are ordinary, no file at all, --print and an image-only compose file stay ALLOW', () => {
  assert.deepEqual(
    notExactly([
      ['docker buildx bake', { 'docker-bake.hcl': BAKE_DEFAULT, Dockerfile: OK }, 'ALLOW'],
      ['docker buildx bake', { 'compose.yaml': 'services:\n  a:\n    build: .\n', Dockerfile: OK }, 'ALLOW'],
      ['docker buildx bake', { 'compose.yaml': 'services:\n  a:\n    image: redis\n' }, 'ALLOW'],
      ['docker buildx bake', { 'compose.yaml': 'services:\n  a:\n    build:\n      dockerfile_inline: |\n        FROM alpine\n        RUN echo $$HOME\n' }, 'ALLOW'],
      ['docker buildx bake', {}, 'ALLOW'],
      ['docker buildx bake --print', { 'docker-bake.hcl': BAKE_DEFAULT, Dockerfile: EVIL }, 'ALLOW'],
      ['docker buildx bake --load', { 'docker-bake.hcl': BAKE_DEFAULT, Dockerfile: OK }, 'ALLOW'],
    ]),
    [],
  );
});

test('what the reader cannot read is an ask: a variable, a matrix, an anchor, an include, a remote definition', () => {
  const rows: Row[] = [
    ['docker buildx bake', { 'docker-bake.hcl': 'variable "DF" { default = "Dockerfile" }\ntarget "default" {\n  dockerfile = DF\n}\n', Dockerfile: OK }, 'ASK'],
    ['docker buildx bake', { 'docker-bake.hcl': 'target "default" {\n  dockerfile = "${DF}"\n}\n', Dockerfile: OK }, 'ASK'],
    ['docker buildx bake', { 'docker-bake.hcl': 'target "default" {\n  matrix = { x = ["a"] }\n}\n' }, 'ASK'],
    ['docker buildx bake', { 'compose.yaml': 'x-base: &base\n  build: .\nservices:\n  a:\n    <<: *base\n', Dockerfile: OK }, 'ASK'],
    ['docker buildx bake', { 'compose.yaml': 'include:\n  - other.yaml\nservices:\n  a:\n    image: redis\n' }, 'ASK'],
    // compose interpolates `$VAR`; `$$` is a literal dollar. A services section the parser cannot read is not an empty one
    ['docker buildx bake', { 'compose.yaml': 'services:\n  a:\n    build:\n      dockerfile_inline: |\n        FROM alpine\n        RUN echo $HOME\n' }, 'ASK'],
    ['docker buildx bake', { 'compose.yaml': 'services:\n\ta:\n\t\tbuild: .\n', Dockerfile: EVIL }, 'ASK'],
    ['docker buildx bake', { 'compose.yaml': 'services: {a: {build: {context: ., dockerfile: Evil}}}\n', Evil: EVIL }, 'ASK'],
    ['docker buildx bake https://github.com/evil/repo.git', undefined, 'ASK'],
    ['docker buildx bake -f https://github.com/evil/repo.git', undefined, 'ASK'],
    ['docker buildx bake git@github.com:evil/repo.git', undefined, 'ASK'],
    ['docker buildx bake github.com/evil/repo', undefined, 'ASK'],
    ['docker build https://github.com/evil/repo.git', undefined, 'ASK'],
  ];
  assert.deepEqual(underFloor(rows), []);
});

test('compose build reads the compose file the same way, and is never weaker than the build it runs', () => {
  const svc = 'services:\n  app:\n    build: .\n';
  const rows: Row[] = [
    ['docker compose build', { 'compose.yaml': svc, Dockerfile: EVIL }, 'DENY'],
    ['docker compose -f ci.yaml build', { 'ci.yaml': svc, Dockerfile: EVIL }, 'DENY'],
    ['docker compose up --build', { 'compose.yaml': svc, Dockerfile: EVIL }, 'DENY'],
    ['docker compose run --build app', { 'compose.yaml': svc, Dockerfile: EVIL }, 'DENY'],
    ['docker-compose build', { 'docker-compose.yml': svc, Dockerfile: EVIL }, 'DENY'],
    ['docker compose --profile x build', { 'compose.yaml': svc, Dockerfile: EVIL }, 'DENY'],
    // compose looks in each parent directory for its file, and a relative context is relative to the project, not to where it ran
    ['cd sub && docker compose build', { 'compose.yaml': svc, Dockerfile: EVIL, 'sub/x.txt': 'x' }, 'DENY'],
    ['cd sub && docker compose build', { 'compose.yaml': 'services:\n  app:\n    build: ./sub\n', 'sub/Dockerfile': EVIL }, 'DENY'],
    ['docker compose --project-directory sub build', { 'compose.yaml': svc, 'sub/Dockerfile': EVIL }, 'DENY'],
    ['COMPOSE_FILE=ci.yaml docker compose build', { 'ci.yaml': svc, Dockerfile: EVIL }, 'DENY'],
    ['docker compose build', { 'compose.yaml': 'services:\n  app:\n    build:\n      context: .\n      cache_to:\n        - type=registry,ref=r/x\n', Dockerfile: OK }, 'ASK'],
  ];
  assert.deepEqual(underFloor(rows), []);
  // a plain `docker compose up` is the accepted product behaviour, with or without a build section
  assert.deepEqual(notExactly([['docker compose up -d', { 'compose.yaml': svc, Dockerfile: EVIL }, 'ALLOW']]), []);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 3. A FILE THE SAME COMMAND LINE WRITES IS NOT THE FILE THAT WAS THERE
 * ------------------------------------------------------------------------------------------------------------- */

test('a Dockerfile, a bake file or a compose file written earlier in the same command is not read as it was (r11-38)', () => {
  const rows: Row[] = [
    [`printf 'FROM a\\nRUN ${PUSH}\\n' > Dockerfile && docker buildx bake`, { 'docker-bake.hcl': BAKE_DEFAULT, Dockerfile: OK }, 'ASK'],
    [`printf 'target "default" {dockerfile="Evil"}' > docker-bake.hcl && docker buildx bake`, { Evil: EVIL }, 'ASK'],
    [`printf 'services:\\n a:\\n  build: .\\n' > compose.yaml && docker buildx bake`, { Dockerfile: EVIL }, 'ASK'],
    [`printf 'FROM a\\nRUN ${PUSH}\\n' > Evil && docker buildx bake --set default.dockerfile=Evil`, { 'docker-bake.hcl': BAKE_DEFAULT }, 'ASK'],
    [`printf 'FROM a\\nRUN ${PUSH}\\n' > Dockerfile && docker buildx -D build .`, { Dockerfile: OK }, 'ASK'],
    [`printf 'FROM a\\nRUN ${PUSH}\\n' > Dockerfile && docker compose build`, { 'compose.yaml': 'services:\n  a:\n    build: .\n', Dockerfile: OK }, 'ASK'],
    [`cp evil.df Dockerfile && docker buildx bake`, { 'docker-bake.hcl': BAKE_DEFAULT, Dockerfile: OK, 'evil.df': EVIL }, 'ASK'],
  ];
  assert.deepEqual(underFloor(rows), []);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 4. AN ENGINE NAMED PAST THE VERB IS THE ENGINE, AND A VERB NOBODY MODELLED IS A QUESTION
 *
 * r11-223 225 226: `docker debug --host ssh://prod`, `docker pass get`, `docker pass run -- psql -h prod`. The engine
 * resolver stopped at the first bare word; the catch-all `container.run` ALLOW answered for every word after `docker`.
 * ------------------------------------------------------------------------------------------------------------- */

test('a verb nobody modelled, on a production engine named before or after it, is an act on that engine (r11-223)', () => {
  const rows: Row[] = [
    ['docker debug --host ssh://root@prod.acme.com app', undefined, 'DENY'],
    ['docker debug -H tcp://prod.acme.com:2375 app', undefined, 'DENY'],
    ['docker debug --context production app', undefined, 'DENY'],
    ['docker debug --host=ssh://root@prod.acme.com app', undefined, 'DENY'],
    ['docker --host ssh://root@prod.acme.com debug app', undefined, 'DENY'],
    ['docker pass --host tcp://prod.acme.com get X', undefined, 'DENY'],
    ['docker scout --context production quickview', undefined, 'DENY'],
    ['docker init --context production', undefined, 'DENY'],
    ['DOCKER_HOST=tcp://prod.acme.com:2375 docker debug app', undefined, 'DENY'],
    ['DOCKER_CONTEXT=production docker pass get X', undefined, 'DENY'],
  ];
  assert.deepEqual(underFloor(rows), []);
});

test('a verb nobody modelled asks, locally: debug, pass, scout, init, a plugin (r11-224, r11-225)', () => {
  assert.deepEqual(
    notExactly([
      ['docker debug app', undefined, 'ASK'],
      ['docker pass get GH_TOKEN', undefined, 'ASK'],
      ['docker pass set X=1', undefined, 'ASK'],
      ['docker pass run -- ls', undefined, 'ASK'],
      ['docker scout quickview', undefined, 'ASK'],
      ['docker init', undefined, 'ASK'],
      ['docker buildx history ls', undefined, 'ASK'],
      ['docker container frobnicate x', undefined, 'ASK'],
      ['podman farm list', undefined, 'ASK'],
    ]),
    [],
  );
});

test('the command a plugin verb takes after `--` is analysed as the command it is (r11-226)', () => {
  const rows: Row[] = [
    ['docker pass run -- psql -h prod.acme.com -c "drop table x"', undefined, 'DENY'],
    ['docker pass run -- kubectl --context production delete pod x', undefined, 'DENY'],
    ['docker pass run -- git push origin main', undefined, 'DENY'],
    ['docker --context production pass run -- ls', undefined, 'DENY'],
    ['docker exec box -- git push origin main', undefined, 'DENY'],
    ['docker compose exec web -- git push origin main', undefined, 'DENY'],
  ];
  assert.deepEqual(underFloor(rows), []);
});

test('a global option is accepted past the verb, and means what it means before it', () => {
  const rows: Row[] = [
    ['docker run -H tcp://prod.acme.com:2375 alpine ls', undefined, 'DENY'],
    ['docker run --host tcp://prod.acme.com:2375 --rm alpine ls', undefined, 'DENY'],
    ['docker exec --context production box ls', undefined, 'DENY'],
    ['docker logs --context production app', undefined, 'DENY'],
    ['docker rm -f --host tcp://prod.acme.com:2375 x', undefined, 'DENY'],
    ['docker container rm -H tcp://prod.acme.com:2375 x', undefined, 'DENY'],
    ['docker system prune -f --context production', undefined, 'DENY'],
    // an option the table gives a value it does not take (`-t` is a switch for `logs`, `-s` for `ps`) does not swallow the engine
    ['docker logs -t --host tcp://prod.acme.com:2375 app', undefined, 'DENY'],
    ['docker logs -t -Htcp://prod.acme.com:2375 app', undefined, 'DENY'],
    ['docker inspect -s --context production app', undefined, 'DENY'],
    ['docker rm -v -H tcp://prod.acme.com:2375 x', undefined, 'DENY'],
    // a verb whose operands are not a program's argv keeps looking to the end of the line
    ['docker cp app:/x ./x --context production', undefined, 'DENY'],
    ['docker start app --host tcp://prod.acme.com:2375', undefined, 'DENY'],
    ['docker attach app -H tcp://prod.acme.com:2375', undefined, 'DENY'],
    ['podman run --connection prod alpine ls', undefined, 'DENY'],
  ];
  assert.deepEqual(underFloor(rows), []);
  // ...a read of a production engine is still a read, and the words a container program is given are not the CLI's
  assert.deepEqual(
    notExactly([
      ['docker ps -H tcp://prod.acme.com:2375', undefined, 'ALLOW'],
      ['docker images --context production', undefined, 'ALLOW'],
      ['docker --context production compose version', undefined, 'ALLOW'],
      ['docker run alpine ls --context production', undefined, 'ALLOW'],
      ["docker run alpine curl -H 'X: y' http://localhost:8080", undefined, 'ALLOW'],
      ['docker run --rm node:22 tool --builder prod', undefined, 'ALLOW'],
      ['docker run -c 512 --rm alpine sh', undefined, 'ALLOW'],
      ['podman run -c 5 alpine ls', undefined, 'ALLOW'],
      ['nerdctl ps -a', undefined, 'ALLOW'],
    ]),
    [],
  );
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 5. A BUILDER BOUND TO AN ENDPOINT IS A BINDING TO THAT ENGINE
 *
 * r11-227 228: `buildx create --driver=remote tcp://prod…` and `builder create --driver remote …`. The scan looked for
 * the exact token `--driver` after the exact word `buildx`.
 * ------------------------------------------------------------------------------------------------------------- */

test('a builder created against a production endpoint is a production deploy (r11-227, r11-228)', () => {
  const rows: Row[] = [
    ['docker buildx create --driver=remote tcp://prod.acme.com:1234', undefined, 'DENY'],
    ['docker buildx create --driver remote tcp://prod.acme.com:1234', undefined, 'DENY'],
    ['docker builder create --driver remote tcp://prod.acme.com:1234', undefined, 'DENY'],
    ['docker builder create --driver=remote tcp://prod.acme.com:1234', undefined, 'DENY'],
    ['docker buildx create ssh://root@prod.acme.com', undefined, 'DENY'],
    ['docker buildx create --name b --use --driver remote tcp://prod.acme.com:1234', undefined, 'DENY'],
    ['docker buildx --builder x create --driver=remote tcp://prod.acme.com:1234', undefined, 'DENY'],
    ['docker buildx create --driver kubernetes --driver-opt namespace=prod', undefined, 'DENY'],
    ['docker buildx create --driver remote', undefined, 'DENY'],
    ['docker builder use remote-prod', undefined, 'DENY'],
    ['docker buildx use remote-prod', undefined, 'DENY'],
  ];
  assert.deepEqual(underFloor(rows), []);
  assert.deepEqual(
    notExactly([
      ['docker buildx create --name local --use', undefined, 'ALLOW'],
      ['docker buildx create --driver docker-container --name local', undefined, 'ALLOW'],
      ['docker buildx create --driver remote unix:///var/run/buildkit/buildkitd.sock', undefined, 'ALLOW'],
      ['docker buildx create --driver=remote tcp://localhost:1234', undefined, 'ALLOW'],
      ['docker buildx ls', undefined, 'ALLOW'],
      ['docker buildx inspect', undefined, 'ALLOW'],
    ]),
    [],
  );
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 6. AN OUTPUT, A CACHE AND A SECRET ARE THE WRITES, PUSHES AND READS THEY ARE
 *
 * r11-229 230, sa10-100: `bake --set '*.output=type=registry'` skipped the registry gate, `--set default.output=/etc`
 * wrote outside the workspace, and `-otype=registry` glued the value to the flag. A flag and a file say the same
 * things, and are read by the same function.
 * ------------------------------------------------------------------------------------------------------------- */

test('an output that publishes asks, however the flag, the --set or the file spells it (r11-229)', () => {
  const baked = { 'docker-bake.hcl': BAKE_DEFAULT, Dockerfile: 'FROM alpine\n' };
  const built = { Dockerfile: 'FROM alpine\n' };
  const rows: Row[] = [
    ['docker buildx bake --set "*.output=type=registry"', baked, 'ASK'],
    ["docker buildx bake --set '*.output=type=registry'", baked, 'ASK'],
    ['docker buildx bake --set web.output=type=registry', { 'docker-bake.hcl': 'target "web" {}\n' }, 'ASK'],
    ['docker buildx bake --set=*.output=type=registry', baked, 'ASK'],
    ["docker buildx bake --set '*.output=type=image,name=reg.example/x,push=true'", baked, 'ASK'],
    ["docker buildx bake --set '*.cache-to=type=registry,ref=reg.example/x:cache'", baked, 'ASK'],
    ["docker buildx bake --set '*.cache-to=type=gha'", baked, 'ASK'],
    ['docker buildx bake --push', baked, 'ASK'],
    ['docker buildx build -otype=registry .', built, 'ASK'],
    ['docker buildx build -o=type=registry .', built, 'ASK'],
    ['docker buildx build -o type=image,name=reg.example/x,push=true .', built, 'ASK'],
    ['docker buildx build --output=type=registry .', built, 'ASK'],
    ['docker build -otype=registry .', built, 'ASK'],
    ['docker buildx b -otype=registry .', built, 'ASK'],
    ['docker build --cache-to type=registry,ref=r/x .', built, 'ASK'],
    ['docker buildx bake', { 'docker-bake.hcl': 'target "default" {\n  output = ["type=registry"]\n}\n' }, 'ASK'],
    ['docker buildx bake', { 'docker-bake.hcl': 'target "default" {\n  output = ["type=image,push=true"]\n}\n' }, 'ASK'],
    ['docker buildx bake', { 'docker-bake.hcl': 'target "default" {\n  cache-to = ["type=registry,ref=r/x"]\n}\n' }, 'ASK'],
    ['docker buildx bake', { 'docker-bake.json': '{"target":{"default":{"output":["type=registry"]}}}' }, 'ASK'],
    ['docker buildx bake', { 'compose.yaml': 'services:\n  a:\n    build: .\n    x-bake:\n      output: type=registry\n' }, 'ASK'],
    ['docker buildx build -o type=weird .', built, 'ASK'],
    ['docker buildx bake', { 'docker-bake.hcl': 'target "default" {\n  output = ["type=weird"]\n}\n' }, 'ASK'],
  ];
  assert.deepEqual(underFloor(rows), []);
});

test('an output that writes outside the workspace is a write there (r11-230)', () => {
  const baked = { 'docker-bake.hcl': BAKE_DEFAULT, Dockerfile: 'FROM alpine\n' };
  const rows: Row[] = [
    ['docker buildx bake --set default.output=/etc', baked, 'DENY'],
    ['docker buildx bake --set default.output=type=local,dest=/etc', baked, 'DENY'],
    ["docker buildx bake --set '*.output=type=tar,dest=/etc/x.tar'", baked, 'DENY'],
    ["docker buildx bake --set '*.output=type=oci,dest=/etc/x.tar'", baked, 'DENY'],
    ["docker buildx bake --set '*.output=~/.ssh'", baked, 'DENY'],
    ["docker buildx bake --set '*.output=.git/hooks'", baked, 'DENY'],
    ['docker buildx build -otype=local,dest=/etc .', baked, 'DENY'],
    ['docker buildx build -o /etc .', baked, 'DENY'],
    ['docker buildx build --output type=local,dest=.git/hooks .', baked, 'DENY'],
    ['docker buildx bake', { 'docker-bake.hcl': 'target "default" {\n  output = ["type=local,dest=/etc"]\n}\n' }, 'DENY'],
    ['docker buildx bake', { 'docker-bake.hcl': 'target "default" {\n  output = ["/etc"]\n}\n' }, 'DENY'],
    ['docker buildx bake', { 'docker-bake.json': '{"target":{"default":{"output":["type=local,dest=/etc"]}}}' }, 'DENY'],
    ['docker buildx bake', { 'docker-bake.hcl': 'target "default" {\n  secret = ["id=aws,src=/Users/x/.aws/credentials"]\n}\n' }, 'DENY'],
  ];
  assert.deepEqual(underFloor(rows), []);
  // ...and an output that stays here, or in the local engine, is not
  assert.deepEqual(
    notExactly([
      ['docker buildx bake --set default.output=type=docker', baked, 'ALLOW'],
      ["docker buildx bake --set '*.platform=linux/arm64'", baked, 'ALLOW'],
      ['docker buildx bake --set default.tags=x:1', baked, 'ALLOW'],
      ['docker buildx bake --set default.args.A=1', baked, 'ALLOW'],
      ['docker buildx bake --load', baked, 'ALLOW'],
      ['docker buildx build -o out .', baked, 'ALLOW'],
      ['docker buildx build --output type=local,dest=out .', baked, 'ALLOW'],
      ['docker buildx build -o type=cacheonly .', baked, 'ALLOW'],
      ['docker buildx build --cache-to type=inline .', baked, 'ALLOW'],
      ['docker buildx build --cache-to type=local,dest=/tmp/cache .', baked, 'ALLOW'],
      ['docker buildx build --load -t app .', baked, 'ALLOW'],
      ['docker buildx bake', { 'docker-bake.hcl': 'target "default" {\n  output = ["type=docker"]\n}\n' }, 'ALLOW'],
    ]),
    [],
  );
  assert.deepEqual(
    underFloor([
      ['docker buildx bake --set default.network=host', { 'docker-bake.hcl': BAKE_DEFAULT }, 'ASK'],
      ['docker buildx bake', { 'docker-bake.hcl': 'target "default" {\n  network = "host"\n}\n' }, 'ASK'],
    ]),
    [],
  );
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 7. WHAT THE SAME CAUSE LEFT AT MEDIUM
 * ------------------------------------------------------------------------------------------------------------- */

test('login and logout rewrite the credential store, for every program that has them (r11-188)', () => {
  const rows: Row[] = [
    ['docker logout', undefined, 'DENY'],
    ['docker --debug logout', undefined, 'DENY'],
    ['docker logout registry.example.com', undefined, 'DENY'],
    ['podman logout', undefined, 'DENY'],
    ['podman login registry.example.com', undefined, 'DENY'],
    ['nerdctl login', undefined, 'DENY'],
    ['nerdctl logout', undefined, 'DENY'],
    ['docker login', undefined, 'DENY'],
  ];
  assert.deepEqual(underFloor(rows), []);
});

test('compose forwards a credential like docker does, and a boolean spelled with a value is the boolean (r11-232, sa10-101)', () => {
  const rows: Row[] = [
    ['docker compose run -e AWS_SECRET_ACCESS_KEY svc env', undefined, 'ASK'],
    ['docker compose run --rm -e AWS_SECRET_ACCESS_KEY=x svc env', undefined, 'ASK'],
    ['docker-compose run -e GITHUB_TOKEN web env', undefined, 'ASK'],
    ['docker compose -f x.yml exec -e VAULT_TOKEN web env', undefined, 'ASK'],
    ['docker compose down --volumes=true', undefined, 'ASK'],
    ['docker compose down -v=true', undefined, 'ASK'],
    ['docker-compose down --volumes=true', undefined, 'ASK'],
    ['docker compose down -vt 1', undefined, 'ASK'],
    ['docker compose down -tv 1', undefined, 'ASK'],
    ['docker compose down --rmi all', undefined, 'ASK'],
    ['docker compose rm -f', undefined, 'ASK'],
  ];
  assert.deepEqual(underFloor(rows), []);
  assert.deepEqual(
    notExactly([
      ['docker compose run -e FOO=bar svc env', undefined, 'ALLOW'],
      ['docker compose down --volumes=false', undefined, 'ALLOW'],
      ['docker compose down', undefined, 'ALLOW'],
      ['docker compose down -t 5', undefined, 'ALLOW'],
    ]),
    [],
  );
});

test('the destructive verbs of podman, nerdctl and colima are the destruction the docker ones are (sa10-103)', () => {
  const rows: Row[] = [
    ['podman pod rm -f p', undefined, 'ASK'],
    ['podman pod prune', undefined, 'ASK'],
    ['podman machine rm m', undefined, 'ASK'],
    ['podman machine reset', undefined, 'ASK'],
    ['nerdctl namespace rm ns', undefined, 'ASK'],
    ['colima delete -f', undefined, 'ASK'],
    ['colima prune', undefined, 'ASK'],
    ['podman system reset --force', undefined, 'ASK'],
    ['podman system prune -a', undefined, 'ASK'],
    ['docker plugin push acme/plugin', undefined, 'ASK'],
  ];
  assert.deepEqual(underFloor(rows), []);
  assert.deepEqual(
    notExactly([
      ['podman pod ps', undefined, 'ALLOW'],
      ['podman machine list', undefined, 'ALLOW'],
      ['podman machine start', undefined, 'ALLOW'],
      ['colima status', undefined, 'ALLOW'],
      ['colima start', undefined, 'ALLOW'],
    ]),
    [],
  );
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 8. THE READER ITSELF
 * ------------------------------------------------------------------------------------------------------------- */

const read = (...words: string[]) => readContainerCommand(words)!;

test('the reader places the verb past every kind of option, in front of or behind a group', () => {
  const rows: Array<[string[], string]> = [
    [['docker', 'ps'], 'ps'],
    [['docker', '-D', 'ps'], 'ps'],
    [['docker', '--context', 'production', 'ps'], 'ps'],
    [['docker', '-Htcp://prod', 'ps'], 'ps'],
    [['docker', '-H=tcp://prod', 'ps'], 'ps'],
    [['docker', '--host=tcp://prod', 'ps'], 'ps'],
    [['docker', 'container', 'ls'], 'container ls'],
    [['docker', 'container', 'list'], 'container list'],
    [['docker', 'buildx', '-D', 'b', '.'], 'buildx build'],
    [['docker', 'buildx', '--builder', 'x', 'f'], 'buildx bake'],
    [['docker', 'bake'], 'buildx bake'],
    [['docker', 'builder', 'build', '.'], 'buildx build'],
    [['docker', 'compose', '-f', 'a.yml', '-p', 'p', 'up', '-d'], 'compose up'],
    [['docker-compose', '-f', 'a.yml', 'up'], 'compose up'],
    [['podman', 'system', 'connection', 'add', 'prod', 'ssh://x'], 'system connection add'],
    [['podman', '--remote', 'ps'], 'ps'],
    [['nerdctl', '-n', 'k8s.io', 'ps'], 'ps'],
    [['docker', 'buildx', 'imagetools', 'create', '-t', 'a', 'b'], 'buildx imagetools create'],
  ];
  const wrong = rows.flatMap(([w, want]) => {
    const c = read(...w);
    return c.determinate && c.modelled && c.path.join(' ') === want ? [] : [`${w.join(' ')} -> ${c.path.join(' ')} (${c.why ?? 'ok'}), wanted ${want}`];
  });
  assert.deepEqual(wrong, []);
});

test('the reader does not guess: an unknown option before the verb, a plugin, a word built at run time', () => {
  for (const w of [['docker', '-x', 'ps'], ['docker', '--nope', 'v', 'ps'], ['docker', 'buildx', '--nope', 'build', '.'], ['docker', '--', 'ps']]) {
    const c = read(...w);
    assert.equal(c.determinate, false, w.join(' '));
    assert.equal(c.modelled, false, w.join(' '));
  }
  for (const w of [['docker', 'debug', 'app'], ['docker', 'pass', 'get', 'X'], ['docker', '$V', 'ps'], ['docker', 'container', 'frobnicate']]) {
    const c = read(...w);
    assert.equal(c.determinate, true, w.join(' '));
    assert.equal(c.modelled, false, w.join(' '));
  }
});

test('the reader knows where a container program\'s own words begin, so a flag there is not the CLI\'s', () => {
  const c = read('docker', 'run', '--rm', '-e', 'A=b', 'alpine', 'sh', '-c', 'x', '--context', 'production');
  assert.deepEqual(c.engines, []);
  assert.equal(c.carriedAt, 5);
  const d = read('docker', 'run', '--host', 'tcp://prod', 'alpine', '--host', 'tcp://other');
  assert.deepEqual(d.engines.map((e) => e.value), ['tcp://prod']);
  assert.deepEqual(carriedHostCommand(read('docker', 'pass', 'run', '--', 'psql', '-h', 'prod')), ['psql', '-h', 'prod']);
  assert.equal(carriedHostCommand(read('docker', 'run', 'alpine', '--', 'ls')), null);
});

test('the canonical spelling puts every verb where the matchers look for it', () => {
  const rows: Array<[string[], string | null]> = [
    [['docker', '-D', 'ps'], 'docker ps'],
    [['docker', 'buildx', 'b', '-otype=registry', '.'], 'docker buildx build --output type=registry .'],
    [['docker', 'bake'], 'docker buildx bake'],
    [['docker', 'builder', 'create', '--name', 'b'], 'docker buildx create --name b'],
    [['docker', 'compose', 'down', '--volumes=true'], 'docker compose down --volumes'],
    [['docker', 'compose', 'down', '--volumes=false'], 'docker compose down'],
    [['docker', 'compose', 'up', '-d'], null],
    [['docker', 'run', '--rm', 'alpine', 'ls'], null],
  ];
  const wrong = rows.flatMap(([w, want]) => {
    const got = canonicalCommand(read(...w), w);
    const text = got === null ? null : got.join(' ');
    return text === want ? [] : [`${w.join(' ')} -> ${text}, wanted ${want}`];
  });
  assert.deepEqual(wrong, []);
});

test('there is one place that knows where the verb is: the evaluator carries no second table of container verbs', () => {
  const src = readFileSync(new URL('../src/authority/evaluate.ts', import.meta.url), 'utf8');
  for (const gone of ['DOCKER_GROUPS', 'DOCKER_GLOBAL_VALUE_OPTS', 'DOCKER_BUILD_VALUE_OPTS', 'const bakeAt', 'const buildAt', 'const runAt'])
    assert.ok(!src.includes(gone), `${gone} was a second reader of the container verb`);
  assert.ok(src.includes("from './containers.ts'"), 'the evaluator asks the container reader');
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 9. ORDINARY CONTAINER DEVELOPMENT IS UNTOUCHED
 * ------------------------------------------------------------------------------------------------------------- */

test('the commands a developer runs all day against a local engine stay ALLOW', () => {
  const ordinary = [
    'docker ps',
    'docker ps -a',
    'docker images',
    'docker logs app',
    'docker logs -f --tail 100 app',
    'docker inspect app',
    'docker compose up -d',
    'docker compose down',
    'docker compose ps',
    'docker compose logs -f web',
    'docker compose config',
    'docker compose -f docker-compose.dev.yml up -d',
    'docker compose --profile debug up',
    'docker compose -p app up -d',
    'docker compose run --rm web npm test',
    'docker run --rm alpine echo hi',
    'docker run -d -p 8080:80 --name web nginx',
    'docker pull alpine',
    'docker stop app',
    'docker build -t app .',
    'docker buildx ls',
    'docker buildx build --load -t app .',
    'docker network ls',
    'docker volume ls',
    'docker info',
    'docker version',
    'docker system df',
    'docker tag app reg/app',
    'docker cp app:/x ./x',
    'docker top app',
    'docker stats --no-stream',
    'docker --debug ps',
    'docker -D ps -a',
    'docker -H unix:///var/run/docker.sock ps',
    'docker --context default ps',
    'docker --context desktop-linux run --rm alpine ls',
    'podman ps',
    'podman run --rm alpine echo hi',
    'podman build -t x .',
    'nerdctl ps',
    'nerdctl run --rm alpine echo',
    'docker-compose up -d',
    'docker-compose logs web',
    'colima start',
    'colima status',
  ];
  const wrong = ordinary.filter((c) => verdict(c, workspace()) !== 'ALLOW').map((c) => `${verdict(c, workspace())}: ${c}`);
  assert.deepEqual(wrong, []);
});
