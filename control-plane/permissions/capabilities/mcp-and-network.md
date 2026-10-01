---
schema: ego.capabilities/1
id: mcp-and-network
family: mcp-network
title: MCP servers and network classes
---
# MCP servers and network classes

Reachability never implies trust. MCP servers are trusted only when listed in the consumer's `.harness/mcp-trust.md`
with per-tool capability grants; an unknown server or tool is denied. Secret-bearing MCP payloads pass redaction before
transmission. Network endpoints are classified; the class decides.

## Allowed

- [x] `mcp.local.discover` — list tools of a trusted local MCP server.
- [x] `mcp.local.read` — read-only tools of a trusted local MCP server.
- [x] `mcp.local.filesystem` — filesystem tools of a trusted local server inside registered repositories.
- [x] `mcp.local.browser` — browser automation tools of a trusted local server.
- [x] `mcp.local.container` — local container tools of a trusted local server.
- [x] `network.localhost` — connections to localhost.

## Requires human approval

- [x] `mcp.local.write` — mutating tools of a trusted local server.
- [x] `mcp.local.execute` — command-executing tools of a trusted local server.
- [x] `mcp.local.database` — database tools of a trusted local server.
- [x] `mcp.local.kubernetes` — Kubernetes tools of a trusted local server.
- [x] `mcp.remote.discover` — list tools of a trusted remote MCP server.
- [x] `mcp.remote.read` — read-only tools of a trusted remote MCP server.
- [x] `mcp.remote.narrow-write` — narrow writes through a trusted remote MCP server.
- [x] `network.external-write` — a request that SENDS to a host that is not a declared local target: a mutating HTTP request from `curl`, `wget` or an HTTP client (`-X POST|PUT|PATCH|DELETE`, `-d`, `--json`, `-F`, `-T`, `--post-data`), a file copy or remote shell (`scp`, `sftp`, `rsync` to a host, `ssh`), a raw socket (`nc`, `telnet`, `/dev/tcp`), or a tool pointed at an endpoint that is in no lockfile (`--registry`, `https_proxy=`). A fetch is `command.network-tool`; a request to a forge API host is the forge act it spells. The ceiling is ASK: no session grant lifts it, because an effect that leaves the machine is never an unattended ALLOW (issue #16 sections 4 and 8).
- [x] `network.internal-dev` — internal development network endpoints.
- [x] `network.public-read` — public read-only fetches (documentation, registries).

## Denied

- [x] `mcp.unknown` — any server or tool not listed in the trust file.
- [x] `mcp.local.privileged` — privileged or destructive tools of a local server (host mutation, credential access, deletion of non-disposable data).
- [x] `mcp.remote.privileged` — privileged or destructive tools of a remote server.
- [x] `network.public-write` — public write endpoints.
- [x] `network.production` — production endpoints.
- [x] `network.unknown` — endpoints that match no configured class.
