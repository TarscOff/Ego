---
schema: ego.bounded-commands/1
id: bounded-commands
title: Bounded commands and commands that discover executable content
bounded:
  # shell structure and no-op builtins: bounded by definition — they execute nothing beyond what they name.
  # `source`, `.`, `eval` and `trap` are deliberately ABSENT: those run code, and have their own handling.
  - 'cd'
  - 'pushd'
  - 'popd'
  - 'dirs'
  - 'set'
  - 'shift'
  - 'unset'
  - 'export'
  - 'readonly'
  - 'local'
  - 'declare'
  - 'typeset'
  - 'true'
  - 'false'
  - ':'
  - 'jobs'
  - 'wait'
  - 'type'
  # `local-function` is the marker the analyzer puts on a call to a function DEFINED IN THE SAME UNIT: the body it
  # runs was handed to the analyzer at the definition, so the call introduces no closure of its own.
  - "\u0000ego\u0000local-function"
  # `help-probe` is the marker a HELP PROBE normalizes to. It is emitted only where the position proves the tool is
  # being asked for its manual - the flag is last, not an option's value, after no `--` - so there is no program
  # behind it to bound (exit review 10).
  - "\u0000ego\u0000help-probe"
  # `command` is a builtin that names another command; the normalizer hands that command over on its own, so the
  # only form in which this head survives is the LOOKUP `command -v NAME`, which executes nothing (exit review 4)
  - 'command'
  # READ-ONLY TOOLS NAMED BY THEIR REAL IMPLEMENTATION, and the pure readers the list simply never reached.
  # `gawk`, `gsed` and `gtar` are what Homebrew installs on macOS — the platform this kernel runs on — and
  # `awk '{print $1}'` being ALLOW while `gawk '{print $1}'` asked is a difference in spelling, not in effect.
  # A linter that reads a file and prints diagnostics executes nothing of what it reads (exit review 7).
  - 'gawk'
  - 'mawk'
  - 'nawk'
  - 'gsed'
  - 'ggrep'
  - 'printenv'
  - 'shellcheck'
  - 'shfmt'
  - 'hadolint'
  - 'yamllint'
  - 'markdownlint'
  - 'staticcheck'
  - 'mariadb'
  - 'biome'
  - 'oxlint'
  - 'dprint'
  # `kind`, `k3d` and `minikube` manage their OWN local clusters; `control-plane/workspace/local-targets.md`
  # already says so, and a status read of one is the most ordinary local-development probe there is.
  - 'kind'
  - 'k3d'
  - 'minikube'
  - 'colima'
  # `flock FILE -c CMD` takes a lock and runs CMD — the standard idiom for serializing a build. CMD is handed to
  # the analyzer on its own by the normalizer; the carrier itself opens one file and executes nothing else.
  - 'flock'
  - 'kustomize'
  - 'env'
  # `read` is the shell's own line reader: it assigns a variable and executes nothing. It became visible once
  # `while` was stripped as the prefix keyword it is, and `while read -r l; do …; done < list.txt` — the standard
  # line loop — asked (exit review 8).
  - 'read'
  - 'umask'
  - 'ulimit'
  - 'read'
  - 'alias'
  - 'unalias'
  - 'for'
  - 'while'
  - 'until'
  - 'case'
  - 'esac'
  - 'done'
  - 'fi'
  - 'then'
  - 'else'
  - 'elif'
  - 'do'
  - 'continue'
  - 'break'
  - 'return'
  - 'exit'
  - 'shopt'
  - 'caller'
  - 'times'
  - 'suspend'
  - 'ls'
  - 'cat'
  - 'head'
  - 'tail'
  - 'wc'
  - 'grep'
  - 'egrep'
  - 'fgrep'
  - 'rg'
  - 'tree'
  - 'bat'
  - 'delta'
  - 'hexdump'
  - 'xxd'
  - 'od'
  - 'strings'
  - 'column'
  - 'fold'
  - 'rev'
  - 'nl'
  - 'tac'
  - 'shuf'
  - 'realpath'
  # the ordinary utilities a real script, hook or CI step is made of. None executes anything it is not named for,
  # and once a script body is classified line by line an undeclared one makes the whole script ask (exit review 4).
  - 'mktemp'
  - 'nproc'
  - 'cmp'
  - 'tput'
  - 'hostname'
  - 'getconf'
  - 'locale'
  - 'numfmt'
  - 'cksum'
  - 'sha1sum'
  - '['
  - '[['
  - ']]'
  - 'pwd'
  - 'echo'
  - 'printf'
  - 'which'
  - 'whoami'
  - 'id'
  - 'uname'
  - 'date'
  - 'df'
  - 'du'
  - 'stat'
  - 'file'
  - 'diff'
  - 'uniq'
  - 'cut'
  - 'sort'
  - 'jq'
  - 'yq'
  - 'find'
  - 'fd'
  - 'basename'
  - 'dirname'
  - 'realpath'
  - 'readlink'
  - 'touch'
  - 'mkdir'
  - 'cp'
  - 'mv'
  - 'rm'
  - 'ln'
  - 'chmod'
  - 'tee'
  - 'git'
  - 'go'
  - 'cargo'
  - 'rustc'
  - 'node'
  - 'nodejs'
  - 'deno'
  - 'bun'
  - 'python'
  - 'python3'
  - 'ruby'
  - 'perl'
  - 'php'
  - 'swift'
  - 'kotlinc'
  - 'scalac'
  - 'dart'
  - 'elixir'
  - 'erl'
  - 'java'
  - 'javac'
  - 'gcc'
  - 'g++'
  - 'c++'
  - 'clang'
  - 'clang++'
  - 'cc'
  - 'ld'
  - 'ar'
  - 'strip'
  - 'objdump'
  - 'nm'
  - 'make'
  - 'gmake'
  - 'cmake --version'
  - 'ninja --version'
  - 'ninja -t'
  - 'npm'
  - 'pnpm'
  - 'yarn'
  - 'pip'
  - 'pip3'
  - 'poetry'
  - 'uv'
  - 'terraform'
  - 'aws'
  - 'gcloud'
  - 'az'
  - 'ssh'
  - 'scp'
  - 'rsync'
  - 'systemctl'
  - 'brew'
  - 'apt'
  - 'apt-get'
  # the other system package managers: what a Dockerfile's RUN lines install with. `apk add` and `yum install` acquire third-party
  # code exactly as `apt-get install` does (below); on this machine they ask, in an image they are what an image is for
  - 'apk'
  - 'yum'
  - 'dnf'
  - 'microdnf'
  - 'zypper'
  # ...and the account, ownership and system-setup programs a Dockerfile's RUN lines are made of. None of them executes anything it was
  # not named for; no rule classifies them, so on this machine they still ask (no matcher), and in an image build they are the image's
  - 'install'
  - 'chown'
  - 'chgrp'
  - 'useradd'
  - 'groupadd'
  - 'adduser'
  - 'addgroup'
  - 'usermod'
  - 'groupmod'
  - 'update-ca-certificates'
  - 'ldconfig'
  - 'locale-gen'
  - 'update-alternatives'
  - 'open'
  - 'code'
  - 'less'
  - 'more'
  - 'ps'
  - 'kill'
  - 'top'
  - 'lsof'
  - 'netstat'
  - 'ping'
  - 'dig'
  - 'host'
  - 'nc'
  - 'openssl'
  - 'gpg'
  - 'sha256sum'
  - 'shasum'
  - 'md5sum'
  - 'base64'
  - 'tr'
  - 'tee'
  - 'split'
  - 'paste'
  - 'join'
  - 'comm'
  - 'seq'
  - 'expr'
  - 'test'
  - 'sleep'
  - 'time'
  - 'watch'
  - 'gh'
  - 'glab'
  - 'tsc'
  - 'gofmt'
  - 'goimports'
  - 'rustfmt'
  - 'shfmt'
  - 'clang-format'
  - 'black'
  - 'isort'
  - 'ruff'
  - 'golangci-lint'
  - 'esbuild'
  - 'swc'
  - 'yamllint'
  - 'markdownlint'
  - 'hadolint'
  - 'docker'
  - 'kubectl'
  - 'helm'
  # database and cluster clients. Their closure is the statements or manifests their arguments name; WHERE they
  # point is governed separately by the Q98 target classification, which is the settled decision for them.
  - 'psql'
  - 'mysql'
  - 'mysqldump'
  - 'pg_dump'
  - 'mongosh'
  - 'mongo'
  - 'redis-cli'
  - 'sqlite3'
  - 'sqlcmd'
  - 'clickhouse-client'
  - 'flyway'
  - 'dbmate'
  - 'liquibase'
  - 'goose'
  - 'migrate'
  - 'atlas'
  - 'k9s'
  - 'kustomize'
  - 'skaffold'
  - 'argocd'
  - 'flux'
  - 'docker-compose'
  - 'podman'
  - 'nerdctl'
  # the OpenShift client is kubectl with verbs of its own, and the container clients below read like docker: the cluster reader
  # (k8s.ts) and the container reader (containers.ts) model each of them, and their branches for these programs were unreachable
  # while the vocabulary had never heard of them (wave 5, K8-06)
  - 'oc'
  - 'podman-compose'
  - 'lima'
  - 'buildah'
  - 'curl'
  - 'wget'
  # the other HTTP clients the network matcher reads by request: a client the evaluator reads cannot be "an unmodelled
  # closure" (Q98 closure; the request is judged, see `networkWriteHits`)
  - 'wget2'
  - 'http'
  - 'https'
  - 'xh'
  - 'xhs'
  - 'tar'
  - 'zip'
  - 'unzip'
  - 'sed'
  - 'awk'
  - 'xargs'
  - 'env'
  - 'sleep'
  - 'true'
  - 'false'
installs_dependencies:
  - 'pip install'
  - 'pip3 install'
  - 'pip install -r'
  - 'pipenv install'
  - 'poetry install'
  - 'poetry add'
  - 'poetry update'
  - 'uv sync'
  - 'uv pip install'
  - 'uv add'
  - 'conda install'
  - 'bundle install'
  - 'bundle update'
  - 'gem install'
  - 'composer install'
  - 'composer update'
  - 'composer require'
  - 'cargo install'
  - 'go install'
  - 'mix deps.get'
  - 'nuget restore'
  - 'dotnet restore'
  - 'swift package resolve'
  - 'brew install'
  - 'npm init'
  - 'yarn create'
  - 'pnpm create'
  - 'bun create'
  - 'npm exec'
  - 'npx --package'
  - 'npx -p'
  - 'bunx --package'
  - 'bunx -p'
  - 'docker plugin install'
  - 'podman plugin install'
  - 'helm plugin install'
  - 'kubectl krew install'
  - 'gh extension install'
  - 'code --install-extension'
  - 'apt-get install'
  - 'apt install'
  - 'apk add'
  - 'yum install'
  - 'dnf install'
  - 'microdnf install'
  - 'zypper install'
discovers_content:
  # build-system drivers: `cmake -P x.cmake` runs a CMake script (execute_process and all), `cmake --build` and
  # `ninja` run the edges a generated build file names. They were in `bounded`, which claimed their closure was
  # what their arguments name — it is whatever the repository's build files say.
  - 'cmake'
  - 'ninja'
  - 'node --test'
  - 'go test'
  - 'bun test'
  - 'deno test'
  - 'cargo test'
  - 'dotnet test'
  - 'swift test'
  - 'python -m pytest'
  - 'python3 -m pytest'
  - 'python -m unittest'
  - 'python3 -m unittest'
  - 'pytest'
  - 'tox'
  - 'nox'
  - 'vitest'
  - 'jest'
  - 'mocha'
  - 'ava'
  - 'tap'
  - 'karma'
  - 'playwright'
  - 'cypress'
  - 'turbo'
  - 'nx'
  - 'lerna'
  - 'rake'
  - 'pre-commit'
discovers_config:
  - 'eslint eslint.config.js eslint.config.mjs eslint.config.cjs eslint.config.ts .eslintrc.js .eslintrc.cjs'
  - 'prettier prettier.config.js prettier.config.mjs prettier.config.cjs .prettierrc.js .prettierrc.cjs .prettierrc.mjs'
  - 'stylelint stylelint.config.js stylelint.config.mjs stylelint.config.cjs .stylelintrc.js'
  - 'vite vite.config.js vite.config.mjs vite.config.cjs vite.config.ts'
  - 'rollup rollup.config.js rollup.config.mjs rollup.config.cjs rollup.config.ts'
  - 'webpack webpack.config.js webpack.config.mjs webpack.config.cjs webpack.config.ts'
  - 'parcel .parcelrc'
  - 'next next.config.js next.config.mjs next.config.cjs next.config.ts'
  - 'ng angular.json'
  - 'tsup tsup.config.js tsup.config.mjs tsup.config.cjs tsup.config.ts'
  - 'gulp gulpfile.js gulpfile.mjs gulpfile.cjs gulpfile.ts'
  - 'grunt Gruntfile.js Gruntfile.cjs'
  # these tools have no executable config file of their own; what they load is named INSIDE a data config, which
  # the data-config check finds. Listing an ordinary `setup.cfg` or `.rubocop.yml` as code gated every Python and
  # Ruby repository for nothing (challenge 8, findings 12 and 15).
  - 'mypy conftest_plugin.py'
  - 'pylint pylint_plugins.py'
  - 'flake8 flake8_plugin.py'
  - 'rubocop rubocop_ext.rb'
image_setup:
  # what a container image is SET UP with. Each is also in `bounded` (it executes nothing it was not named for); none has a rule of its own, so
  # on this machine each is `command.unknown` and asks - and in the RUN lines of a Dockerfile, which run in the image being built, each
  # is the image's own work (wave 5, CT-02)
  - 'apt'
  - 'apt-get'
  - 'apk'
  - 'yum'
  - 'dnf'
  - 'microdnf'
  - 'zypper'
  - 'install'
  - 'chown'
  - 'chgrp'
  - 'useradd'
  - 'groupadd'
  - 'adduser'
  - 'addgroup'
  - 'usermod'
  - 'groupmod'
  - 'update-ca-certificates'
  - 'ldconfig'
  - 'locale-gen'
  - 'update-alternatives'
---

# Bounded commands

Decision of 2026-09-23, closing the UNCLAIMED-HEAD CLOSURE class: **a producer table that does not claim a command
head must not mean that nothing else executes.** Before this file, a head no producer modelled was reported as
`ABSENT_VERIFIED` — the strongest claim in the resolution ladder — so every program that *discovers its own
executable content* carried a positive ALLOW over a closure nobody ever looked for.

The two lists below make the distinction explicit and administrable, rather than leaving it to the silence of a
lookup table.

## `bounded`

Commands whose execution closure is exactly what their arguments name. They read and write files, they talk to a
network or a cluster, they may be `DENY` for what they *do* — but they do not go and find further code to run.
Their other effects are governed by the ordinary matchers; membership here says nothing about whether they are
allowed, only that analysing the command text is analysing the whole of what executes.

`git` is bounded in this sense: the executable content it *can* pull in — hooks and configured helper programs —
has its own producer, which resolves it explicitly.

## `installs_dependencies`

Commands that ACQUIRE third-party code and run it — a `setup.py`, a build backend, a gemspec, a `composer`
script, a formula. This is the same execution surface as an `npm install` lifecycle script, and it was gating for
npm while `pip install -r requirements.txt` and `poetry install` reached ALLOW. The inconsistency is closed here
rather than argued away: acquiring and running third-party code is a human gate in every ecosystem.

The seam with a BUILD is deliberate and is stated in
`docs/architecture/phase-1-residuals.md`: acquiring code is a gate, compiling code already acquired is a
containment dependency. `cargo build` sits on the build side and carries a documented residual risk, because a
cold cache makes it acquire too.

## `discovers_content` and `discovers_config`

A discovering tool has one of two shapes, and conflating them was costing ordinary work for nothing.

`discovers_content` runs repository code it locates by PATTERN — test files, a task graph, another package's
scripts. EGO cannot bound that without emulating the tool, so these never hold a positive semantic claim.

`discovers_config` runs whatever its CONFIGURATION names. Each entry is the tool followed by the configuration
files that would be CODE. When none of them is present the tool's configuration is data, the closure is bounded and
the command is ordinary work; when one is present the tool imports and runs it, and the claim is not earned. This
is the same configuration-closure rule EGO applies to git, make and lint-staged, applied to a tool.

Membership is a statement about the tool, not a guess. `ruff`, `golangci-lint`, `esbuild` and `swc` are bounded
because they load no external code: their configuration is data. `eslint`, `prettier`, `vite`, `rollup`, `webpack`,
`next` and `mypy` are not, because their configuration is JavaScript or names plugins the tool imports and runs.

Commands that locate and execute code EGO has not been shown: test files matched by a pattern, a configuration file
and the plugins it loads, or another package's scripts. EGO does not model their closure and will not emulate them,
so they cannot hold a positive semantic claim. They resolve to `command.unmodelled-closure`, which is a governed
capability like any other: an organization that accepts the risk for a given tool moves it to `bounded` in its own
overlay, and that decision is recorded rather than assumed.

An entry may name a head alone (`pytest`) or a head and the arguments that make it discover (`node --test`,
`go test`): the longer form is matched against the start of the normalized command, so `go build` stays bounded
while `go test` does not.

A head in neither list is simply unmodelled and reaches `command.unknown` as before.

## `image_setup`

The programs a container image is set up with: the system package managers, and the account and ownership tools a
Dockerfile's `RUN` lines are made of (`apt-get update`, `useradd`, `chown`). They are bounded, and no rule classifies
them, so a bare `apt-get update` on this machine is a question. A `RUN` line runs in the image being built, not here:
what it does to a path is the image's, and a program on this list that nothing classifies is the image's own work. It
is a list of heads and not a rule about unknown programs, because the fallback for an unclassified command is also
what gates a form nobody classified on purpose (`git -c man.man.path=…` names a program to run).
