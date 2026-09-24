---
schema: ego.local-targets/1
id: local-targets
title: Local development targets
k8s_local_contexts:
  # the container runtime's own names for the LOCAL daemon. Naming the local engine explicitly — which is what
  # `docker --context default` and `docker context use desktop-linux` do — was classified EXTERNAL and DENIED
  # (exit review 3).
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
production_markers:
  - 'prod'
  - 'production'
  - 'prd'
  - 'live'
---
# Local development targets

Decision Q98. EGO must not interrupt normal local development, and it must not infer that an operation is local from
the name of the tool that performs it. `kubectl apply` against a kind cluster is the agent's working material; the
same command against a shared cluster is an external effect. The difference is the **target**, so the target has to be
resolved before the verdict is chosen.

This file is the authored default. It lists the targets that are recognised as repository-owned local development
surfaces without any further configuration. A project or an organization may **add** targets it owns; neither may
remove one, and neither may classify a production-marked target as local.

## How a target is resolved

For Kubernetes tools (`kubectl`, `oc`, `helm`, `kustomize`) the target is the context named by `--context` /
`--kube-context`, the `--kubeconfig` file, the `--server` endpoint or the namespace. `kind`, `k3d` and `minikube`
manage their own local clusters and are local by construction.

For database clients (`psql`, `mysql`, `mongosh`, `redis-cli`, …) the target is the host in the connection URI or in
`-h` / `--host`. With no host at all these clients connect to the local socket or to localhost, which is local.
`sqlite3` operates on a file, which the path rules already govern.

The four classifications:

- **LOCAL** — matches `k8s_local_contexts` or `db_local_hosts`. Ordinary local development: no human approval.
- **PRODUCTION** — the target name carries a `production_markers` token. The absolute production denies apply.
- **EXTERNAL** — a resolved target that is neither. A named remote cluster or database host is a shared system:
  mutating it is denied by `k8s.nonlocal.mutate` / `db.nonlocal.mutate`.
- **TARGET_UNCLASSIFIED** — no target could be resolved, because none was given (the ambient kubeconfig context is not
  knowable to the kernel) or because it is hidden behind a variable. A high-impact operation against an unknown target
  is never guessed local: it asks a human, and the reason says the target could not be resolved.

Read-only verbs are not re-targeted: `kubectl get`, `helm list` and a bare connection keep the verdict they already
had. Only mutating operations are judged against the target class.
