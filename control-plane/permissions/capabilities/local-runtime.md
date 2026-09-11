---
schema: ego.capabilities/1
id: local-runtime
family: local-runtime
title: Local databases, containers and Kubernetes
---
# Local databases, containers and Kubernetes

Local and development infrastructure is the agent's working material. Anything that resolves to a production context
(profile, namespace, cluster, connection string or endpoint class marked production) is covered by the absolute
production denies, not by these capabilities.

## Allowed

- [x] `db.local.start` — start a local database.
- [x] `db.local.create` — create a local disposable database.
- [x] `db.local.migrate` — run migrations against a local database.
- [x] `db.local.seed` — seed local data.
- [x] `db.local.query` — query a local database.
- [x] `db.local.analyze` — EXPLAIN and performance analysis locally.
- [x] `db.local.backup` — back up a local database.
- [x] `db.local.restore` — restore a local database.
- [x] `db.local.schema` — schema manipulation locally.
- [x] `container.build` — build images locally.
- [x] `container.run` — run containers, compose stacks, local registries, networks, volumes.
- [x] `container.inspect` — inspect images and containers.
- [x] `k8s.local.apply` — apply manifests, Helm charts, operators and CRDs to a local cluster (kind, k3d, minikube, Docker Desktop).
- [x] `k8s.local.test` — network policy, ingress and egress tests against a local cluster.

## Requires human approval

- [x] `db.local.drop` — drop a local database.
- [x] `container.prune` — prune images, containers, volumes.
- [x] `k8s.local.delete` — delete local namespaces or clusters.

## Denied

- [x] `db.nonlocal.mutate` — any mutation of a database whose connection is not classified local or development.
- [x] `k8s.nonlocal.mutate` — any mutation of a cluster or context not classified local.
