---
schema: ego.capabilities/1
id: mcp-and-network
family: mcp-network
title: MCP servers and network classes
---
# MCP servers and network classes

Reachability never implies trust. **Today no MCP server is trusted:** nothing reads the consumer's
`.harness/mcp-trust.md` (`ego init` writes it, no code parses it), so every `mcp__<server>__<tool>` call resolves to
`mcp.unknown` and is denied, whether the server is listed or not. The resolver that would grant a listed server its
per-tool `mcp.local.*` / `mcp.remote.*` capabilities is phase-2 work (issue #10). The classes below that name a
*trusted* server describe that intended contract and are **NOT YET REACHABLE**: no evaluation can return them. Secret-bearing
MCP payloads pass redaction before transmission. Network endpoints are classified; the class decides.

## Allowed

- [x] `mcp.local.discover` — list tools of a trusted local MCP server. *Not yet reachable (needs the trust resolver, issue #10).*
- [x] `mcp.local.read` — read-only tools of a trusted local MCP server. *Not yet reachable.*
- [x] `mcp.local.filesystem` — filesystem tools of a trusted local server inside registered repositories. *Not yet reachable.*
- [x] `mcp.local.browser` — browser automation tools of a trusted local server. *Not yet reachable.*
- [x] `mcp.local.container` — local container tools of a trusted local server. *Not yet reachable.*
- [x] `network.localhost` — connections to localhost.

## Requires human approval

- [x] `mcp.local.write` — mutating tools of a trusted local server. *Not yet reachable.*
- [x] `mcp.local.execute` — command-executing tools of a trusted local server. *Not yet reachable.*
- [x] `mcp.local.database` — database tools of a trusted local server. *Not yet reachable.*
- [x] `mcp.local.kubernetes` — Kubernetes tools of a trusted local server. *Not yet reachable.*
- [x] `mcp.remote.discover` — list tools of a trusted remote MCP server. *Not yet reachable.*
- [x] `mcp.remote.read` — read-only tools of a trusted remote MCP server. *Not yet reachable.*
- [x] `mcp.remote.narrow-write` — narrow writes through a trusted remote MCP server. *Not yet reachable.*
- [x] `network.external-write` — a request that SENDS to a host that is not a declared local target: a mutating HTTP request from `curl`, `wget` or an HTTP client (`-X POST|PUT|PATCH|DELETE`, `-d`, `--json`, `-F`, `-T`, `--post-data`), a file copy or remote shell (`scp`, `sftp`, `rsync` to a host, `ssh`), a raw socket (`nc`, `telnet`, `/dev/tcp`), or a tool pointed at an endpoint that is in no lockfile (`--registry`, `https_proxy=`). A fetch is `command.network-tool`; a request to a forge API host is the forge act it spells. The ceiling is ASK: no session grant lifts it, because an effect that leaves the machine is never an unattended ALLOW (issue #16 sections 4 and 8).
- [x] `network.internal-dev` — internal development network endpoints.
- [x] `network.public-read` — public read-only fetches (documentation, registries).

## Denied

- [x] `mcp.unknown` — any MCP server or tool: today that is every one, because the trust file is not read (issue #10).
- [x] `mcp.local.privileged` — privileged or destructive tools of a local server (host mutation, credential access, deletion of non-disposable data).
- [x] `mcp.remote.privileged` — privileged or destructive tools of a remote server.
- [x] `network.public-write` — public write endpoints.
- [x] `network.production` — production endpoints.
- [x] `network.unknown` — endpoints that match no configured class.
