# Security TODO (from audit 2026-09-19)

Done (round 2): tests (`test/security.test.mjs`), untrusted marker + cap on resources, `GSC_ALLOWED_SITES`,
sandbox server now shares tool definitions via `buildServer(sandbox)`; logic in `src/security.ts`.

Done (round 1): untrusted-data marker + output truncation, MCP annotations, `GSC_READ_ONLY` mode,
input validation (http(s) URLs, siteUrl format, dates, language code), `rowLimit` max 5000,
sanitized token-refresh errors, Node 22 + non-root Dockerfile, pinned version in docs/smithery,
`npm audit fix`.

## Pending
- [x] Worker: OAuth 2.1 (dynamic client registration, PKCE) so claude.ai web connectors can connect. Needs `OAUTH_KV`.
- [x] Worker: per-client scopes (`gsc:read` = read-only) + audit log of tool calls (`console.log`).
- [x] Worker: native rate limiting per IP (`MCP_RATE_LIMITER`, also covers login brute force). Needs paid plan.
- [ ] Worker: stateless only; no server-initiated notifications or resource subscriptions.
- [x] Worker: CI workflow (`.github/workflows/deploy.yml`) — build+test+dry-run gate, then `wrangler deploy`. Needs `CLOUDFLARE_API_TOKEN` repo secret.
- [ ] Prompt injection is only mitigated, not solved: the marker is advisory. A client-side
      confirmation for destructive tools (`destructiveHint`) is still required.
- [ ] `assertIndexingEligibility` is cosmetic: `contentType` is model-declared and never verified on the page.
      Consider fetching the page and checking for JobPosting/BroadcastEvent JSON-LD (adds SSRF risk: needs allowlist).
- [x] `sites_list` / `gsc://sites` still list every property even when `GSC_ALLOWED_SITES` is set; filter the output.
- [x] Rate limit (`TOOL_RATE_LIMITER`) / per-session cap on destructive calls and batch indexing (quota burn).
- [x] Remaining error text from Google API bodies (`toolResult`) is passed through as data; consider redacting project IDs.
- [x] Docs pin `npx -y ...@1.4.0`. Still open: npm provenance on publish.
- [x] `package.json` `engines` raised to >=20.
- [x] Bumped to 1.4.0 (package, `SERVER_VERSION`, pinned docs). Publish to npm before the pin resolves.
