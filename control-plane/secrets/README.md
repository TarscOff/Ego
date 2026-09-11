# Secrets taxonomy

Each file in this directory declares a family of secret detectors in its frontmatter (`schema: ego.secrets/1`).
A detector has `id`, `name`, `pattern` (a JavaScript regular expression source; flags `gi` unless `flags` is given),
`severity` (`block`: the prompt or payload is refused and a redacted copy is returned; `warn`: redacted and disclosed),
`locked` (core detectors whose minimum severity an overlay may raise but never lower), and `replacement` (the label
written in place of the secret; the original value is never logged). Detectors run before logging, telemetry-free
diagnostics, subagent delegation, evidence persistence, MCP transmission, generated documentation, diagnostic bundles
and error reports, and in the prompt hook (decision Q18). `harness redact` applies the same taxonomy to any input.

Structured parsers (curl commands, URLs, JSON bodies, `.env` files) run before the pattern detectors so a bearer token
inside `-H 'Authorization: Bearer …'` is redacted as a header value even when the token itself matches no vendor
format.
