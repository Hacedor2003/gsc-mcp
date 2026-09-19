# Security TODO (from audit 2026-09-19)

Done (round 2): tests (`test/security.test.mjs`), untrusted marker + cap on resources, `GSC_ALLOWED_SITES`,
sandbox server now shares tool definitions via `buildServer(sandbox)`; logic in `src/security.ts`.

Done (round 1): untrusted-data marker + output truncation, MCP annotations, `GSC_READ_ONLY` mode,
input validation (http(s) URLs, siteUrl format, dates, language code), `rowLimit` max 5000,
sanitized token-refresh errors, Node 22 + non-root Dockerfile, pinned version in docs/smithery,
`npm audit fix`.

## Pending
- [ ] Worker: OAuth 2.1 (dynamic client registration) so claude.ai web connectors can connect; today only static bearer.
- [ ] Worker: several tokens with different scopes per client (for example one read-only token) + audit log of tool calls.
- [ ] Worker: native rate limiting / failed-auth lockout (today: document a WAF rule).
- [ ] Worker: stateless only; no server-initiated notifications or resource subscriptions.
- [ ] Worker: deploy is manual (`npm run worker:deploy`); add a CI workflow if wanted.
- [ ] Prompt injection is only mitigated, not solved: the marker is advisory. A client-side
      confirmation for destructive tools (`destructiveHint`) is still required.
- [ ] `assertIndexingEligibility` is cosmetic: `contentType` is model-declared and never verified on the page.
      Consider fetching the page and checking for JobPosting/BroadcastEvent JSON-LD (adds SSRF risk: needs allowlist).
- [ ] `sites_list` / `gsc://sites` still list every property even when `GSC_ALLOWED_SITES` is set; filter the output.
- [ ] Rate limit / per-session cap on destructive calls and batch indexing (quota burn).
- [ ] Remaining error text from Google API bodies (`toolResult`) is passed through as data; consider redacting project IDs.
- [ ] Replace `npx -y` docs with a lockfile/integrity-checked install; consider npm provenance on publish.
- [ ] `package.json` `engines` still says node >=18 (EOL); raise to >=20 after checking users.
- [ ] Bump `SERVER_VERSION`/package version and update pinned `@1.3.3` in docs when releasing.
