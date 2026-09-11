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
- [x] `network.internal-dev` — internal development network endpoints.
- [x] `network.public-read` — public read-only fetches (documentation, registries).

## Denied

- [x] `mcp.unknown` — any server or tool not listed in the trust file.
- [x] `network.public-write` — public write endpoints.
- [x] `network.production` — production endpoints.
- [x] `network.unknown` — endpoints that match no configured class.
