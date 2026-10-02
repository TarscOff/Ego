---
schema: ego.local-targets/1
id: local-targets
title: Local development targets
k8s_local_contexts:
  # the container runtime's own names for the LOCAL daemon. Naming the local engine explicitly — which is what
  # `docker --context default` and `docker context use desktop-linux` do — was classified EXTERNAL and DENIED
  # (exit review 3).
  # NOTE: `default`, `desktop-linux`, `unix`, `npipe` and `rootless` are the CONTAINER runtime's own names for the
  # local daemon. Kubernetes has no such convention — a kubeconfig context called `default` is whatever the
  # operator's file says, which may be a shared cluster — so those five are recognised for container tools only
  # (exit review 7). The kind/k3d/minikube/desktop names below are local for both.
  - 'default'
  - 'desktop-linux'
  - 'desktop-windows'
  - 'unix'
  - 'npipe'
  - 'rootless'
  - 'kind-*'
  - 'k3d-*'
  - 'minikube'
  - 'docker-desktop'
  - 'docker-for-desktop'
  - 'rancher-desktop'
  - 'colima'
  - 'orbstack'
  - 'microk8s'
  - 'k3s-local'
db_local_hosts:
  - 'localhost'
  # LocalStack's own documented endpoint host, which resolves to 127.0.0.1 and is how its docs tell you to
  # reach it; denying it absolutely was the exact case the cloud de-escalation exists for (exit review 5)
  - 'localhost.localstack.cloud'
  - '*.localhost.localstack.cloud'
  - '127.0.0.1'
  - '::1'
  - '[::1]'
  - '0.0.0.0'
  - '*.localhost'
  - 'host.docker.internal'
  # Docker Desktop's own name for the machine's Kubernetes API server: it writes the name into the kubeconfig of the `docker-desktop`
  # context and into /etc/hosts as the loopback (wave 5, K8-06)
  - 'kubernetes.docker.internal'
production_markers:
  - 'prod'
  - 'production'
  - 'prd'
  - 'live'
  # a pre-production environment is shared and mirrors production's data and integrations; `pre-prod` is already the word
  # `prod`, and the one-word spelling is the same environment (wave 5, AUTH-1)
  - 'preprod'
---
# Local development targets

Decision Q98. EGO must not interrupt normal local development, and it must not infer that an operation is local from
the name of the tool that performs it. `kubectl apply` against a kind cluster is the agent's working material; the
same command against a shared cluster is an external effect. The difference is the **target**, so the target has to be
resolved before the verdict is chosen.

This file is the authored default. It lists the targets that are recognised as repository-owned local development
surfaces without any further configuration. A project or an organization may **add** targets it owns (below); neither
may remove one, and neither may classify a production-marked target as local.

## How a target is resolved

For Kubernetes tools (`kubectl`, `oc`, `helm`, `kustomize`) ONE reader (`authority/k8s.ts`) collects every signal that
selects the cluster and the most restrictive decides: the context (`--context` / `--kube-context`, `HELM_KUBECONTEXT`,
`config use-context`), the cluster entry (`--cluster`), the credentials' name (`--user`, `--as`), the API server
(`--server` / `-s` / `--kube-apiserver`, `KUBERNETES_MASTER`, `HELM_KUBEAPISERVER`, `KUBERNETES_SERVICE_HOST`), the
namespace and the kubeconfig FILE (`--kubeconfig`, `oc --config`, `KUBECONFIG`). A kubeconfig the workspace holds is READ:
a context is judged by its name and by the SERVER it points at — a context whose server is not a declared local host is
not local, whatever it is called — and a credential plugin in it is a program the tool runs. A file outside the
workspace, or one the kernel cannot read as a kubeconfig, says nothing about where a declared name points; one this very
command line writes may be anything. `minikube kubectl -- ARGS` is `kubectl ARGS` with minikube's own cluster as the
default. `kind` and `k3d` manage their own local clusters and are local by construction.

The same reader answers the other questions a Kubernetes command raises: whether it READS a Secret or a credential (a
resource type, a `-f` / `-k` source or stream, a word a shell fills in, `helm get` and `helm status -o json|yaml`, `config
view --raw|--flatten`), whether it changes anything (a flag value is data, never the flag), and whether it RUNS a
program (a verb the tool does not have is a plugin).

For database clients (`psql`, `mysql`, `mongosh`, `redis-cli`, …) the target is the host in the connection URI or in
`-h` / `--host`, in every spelling the client itself accepts: an unambiguous abbreviation (`--ho=`), a value glued to the
letter or to a cluster (`-qAt -hdb`), a list (`-h a,b`), an option given twice (every host is judged and the strongest
decides). The client's own grammar says which words are options, which are their values and what an operand is: the first
operand of `psql`, `mysql` and the dump tools is a database NAME (`my.app` is a database, never a host), `cqlsh`'s is a host,
and `mongosh`'s and `clickhouse-client`'s is an address that is a host when it is written like one. A connection string where
a database name goes (`psql -d "$URL"`) or a profile resolved from a file of the client's own (`--login-path`) is a target
this kernel cannot read, which is UNCLASSIFIED. With no host at all these clients connect to the local socket or to
localhost, which is local. `sqlite3` operates on a file, which the path rules already govern.

For container tools (`docker`, `podman`, `buildx`, …) the target is the engine named by `-H` / `--host`, by `--context`,
by `DOCKER_HOST` / `DOCKER_CONTEXT`, or by `docker context use`. With no explicit selection the local daemon is used.

The four classifications:

- **LOCAL** — matches a local-context or local-host entry for that family of tools. Ordinary local development: no
  human approval.
- **PRODUCTION** — a `production_markers` entry is a WORD of the target name. The absolute production denies apply. ONE
  reader (`hasProductionMarker`) answers this for every family of tools: a name is cut at every character that is not a
  letter or a digit, between a letter and a digit, and where the case changes, so `prod`, `prd-1`, `prd1`, `prod01`,
  `live2`, `eu-prod`, `eksProd` and `aks-prd1-weu` are production, and `products`, `product-catalog`, `reproduce`,
  `liveness` and `delivery` are not (they contain the letters, not the word). A marker that is several words (a layer's
  `sandbox-eu`) is those words in a row. It is asked of the fields that NAME A TARGET - a context, a cluster, a user, an API
  server, a namespace, a kubeconfig path, a database host, a container engine or connection - and of nothing else: a release,
  an image, a resource name or a statement says what is done, not where.
- **EXTERNAL** — a resolved target that is neither. A named remote cluster or database host is a shared system:
  mutating it is denied by `k8s.nonlocal.mutate` / `db.nonlocal.mutate`, and the refusal names the command a human can
  use to declare it a development target.
- **TARGET_UNCLASSIFIED** — no target could be resolved, because none was given (the ambient kubeconfig context is not
  knowable to the kernel) or because it is hidden behind a variable. A high-impact operation against an unknown target
  is never guessed local: it asks a human, and the reason says the target could not be resolved.

Read-only verbs are not re-targeted: `kubectl get`, `helm list` and a bare connection keep the verdict they already
had. Only mutating operations are judged against the target class. When several signals resolve (`--context` and
`--server` and `--namespace` and `KUBECONFIG`), the most restrictive one decides.

## The registry: three layers

| layer | file | who writes it |
| --- | --- | --- |
| kernel default | `control-plane/workspace/local-targets.md` (this file) | EGO |
| organization | `policies/organization/local-targets.md` | the organization; a protected path for agents |
| project | `.harness/local-targets.md` | a human, or `ego init --local-target`; asks when an agent writes it |

The organization and project files use the same format as this one (`schema: ego.local-targets/1`, markdown
frontmatter lists) and may carry four keys, all optional:

- `k8s_local_contexts` — kube contexts that are local for `kubectl`, `helm` and `kustomize`.
- `db_local_hosts` — hosts that are local for database clients.
- `container_local_contexts` — docker / podman contexts and connection names that are local for the container tools.
- `production_markers` — extra tokens that mark a name as production.

An unknown key, a key that is not a list and a wrong schema are errors, not no-ops. A name is a context or host name,
optionally with `*` wildcards; it may not contain whitespace, quotes, `$`, a backtick or `?`.

The rules every layer lives under:

1. **A layer adds.** It adds local targets and production markers. It cannot remove a production marker, and it cannot
   remove anything from the kernel's lists.
2. **Production wins.** A declaration whose name carries a production marker (the kernel's or any layer's) is ignored,
   with a diagnostic in `ego doctor` and `ego init`, even after it was accepted. A marker added by a layer narrows at
   once.
3. **Each declaration answers one question for one family of tools.** A declared kube context is local for Kubernetes
   tools and not for `docker`; a declared database host is local for database clients and is **not** a local Docker
   engine, cloud endpoint, network destination or cluster API server. Those four read the kernel's own `db_local_hosts`
   (this machine) and nothing a layer adds. An engine reached by `-H tcp://host` cannot be declared; declare a Docker context for it.
4. **A pattern must fix something.** A kube or container pattern needs at least three literal characters before its
   first `*` (`dev-*`, not `*` or `d*`); a database host pattern is one wildcard label in front of at least two domain
   labels (`*.dev.acme.test`, not `*.com` or `10.*`).
5. **Declaring a target local is a widening.** It turns a refusal into an allowed operation, so a hook never applies it
   from the working tree: a change to either file stays pending, `ego doctor` reports it, and it takes effect only when
   a human runs `ego init` from their own terminal and accepts it — the mechanism every organization-policy widening
   already uses. Removing a declaration, or adding a production marker, is a narrowing and applies at once; removing a
   marker a layer added is a widening again.
6. **Nothing is guessed.** An operation whose target cannot be resolved stays `TARGET_UNCLASSIFIED`, whatever is
   declared. A layer file that is a link out of the repository is not read.

The compiled authority table carries the merged result (`localTargets.declared`, `localTargets.ignored`, the merged
`productionMarkers`) and its hash covers it, so a pin or a cache reflects the registry; `diffAuthorityTables` reports a
declared target as `local-target-added` (a MAJOR change) and `ego init` prints that line under its AUTHORITY DIFF.

## `ego init`: proposals and adoption

`ego init` reads only files inside the repository — Compose files, kind and k3d cluster configs, `skaffold.yaml`,
`Tiltfile`, the devcontainer, `.env.example`-style templates — and prints what it found:

```text
local development surfaces (read from files in this repository only):
  detected: skaffold.yaml: kubeContext team-dev
  proposed LOCAL_DEV: kube:team-dev (skaffold.yaml: kubeContext) - adopt with: ego init --local-target kube:team-dev
```

It never reads `~/.kube/config`, `~/.docker`, the environment or a file a link points out of the repository, and it
prints a name only as one short token of letters, digits and `-_.:@/`. A single-label host from an env template (`db`)
is proposed only when a Compose service of that name exists; a production-marked name is listed as not proposed.

- `ego init --local-target kube:<context>` | `db:<host>` | `container:<context>` (repeatable) writes the entry into
  `.harness/local-targets.md` and accepts it. It is a human act: refused from an agent shell exactly as `--profile` and
  `--repin` changes are, refused for a production-marked name, and nothing is written when any one of the requests is
  refused. A name that is already local (the kernel default, or already declared) is reported and not written.
- `ego init --no-local-targets` declines the proposals (nothing is listed or adopted).
- On a human terminal (stdin and stdout both TTYs), widenings already waiting in the layer files are listed and
  confirmed before they are accepted. No other run ever asks anything.

After any change `ego init` prints the AUTHORITY DIFF against the previously accepted table, widenings first.
