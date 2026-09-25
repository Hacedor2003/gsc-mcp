# gsc-mcp

[![npm version](https://img.shields.io/npm/v/@mikusnuz%2Fgsc-mcp)](https://www.npmjs.com/package/@mikusnuz/gsc-mcp)

[English](README.md) | [한국어](README.ko.md)

[![MCP Badge](https://lobehub.com/badge/mcp/mikusnuz-gsc-mcp)](https://lobehub.com/mcp/mikusnuz-gsc-mcp)

MCP server for **Google Search Console API** and **Google Indexing API** — full API coverage.

## When to Use

| Task | Tool |
|------|------|
| "Check which queries my site ranks for" | `search_analytics_query` |
| "Notify Google about an eligible job posting or livestream URL" | `indexing_publish` |
| "Find pages with indexing errors" | `url_inspection_inspect` |
| "Get search performance data for the last 30 days" | `search_analytics_query` |
| "Compare click-through rates between mobile and desktop" | `search_analytics_query` (group by `device`) |
| "Submit my sitemap to Google" | `sitemaps_submit` |
| "Batch notify eligible job posting/livestream URLs" | `indexing_batch_publish` |

> **For AI agents:** See [`llms.txt`](llms.txt) for a machine-readable summary. Copy [`templates/CLAUDE.md`](templates/CLAUDE.md) or [`templates/AGENTS.md`](templates/AGENTS.md) into your project to teach your agent about this MCP.

Unlike other GSC MCP servers that only wrap `searchAnalytics.query`, this server exposes **every endpoint** available in the Google Search Console and Indexing APIs.

## Tools (13)

### Sites
| Tool | Description |
|------|-------------|
| `sites_list` | List all sites (properties) in your Search Console |
| `sites_get` | Get details of a specific site |
| `sites_add` | Add a new site (property) |
| `sites_delete` | Remove a site |

### Sitemaps
| Tool | Description |
|------|-------------|
| `sitemaps_list` | List all submitted sitemaps for a site |
| `sitemaps_get` | Get details of a specific sitemap |
| `sitemaps_submit` | Submit a sitemap |
| `sitemaps_delete` | Delete a sitemap |

### Search Analytics
| Tool | Description |
|------|-------------|
| `search_analytics_query` | Query search performance data (clicks, impressions, CTR, position) with filtering and grouping. Supports hourly data with the `hour` dimension. |

### URL Inspection
| Tool | Description |
|------|-------------|
| `url_inspection_inspect` | Inspect a URL's index status, crawl info, rich results, and AMP (the deprecated mobile-usability field may be absent) |

### Indexing API
| Tool | Description |
|------|-------------|
| `indexing_publish` | Notify Google about an eligible `JobPosting` or `BroadcastEvent` URL update/removal |
| `indexing_get_metadata` | Get latest notification metadata for an eligible URL (requires `contentType`; not index status) |
| `indexing_batch_publish` | Batch notify up to 100 eligible URLs and report every embedded request status |

> **Indexing API eligibility:** Google supports this API only for pages with
> `JobPosting` structured data or livestream pages with `BroadcastEvent`
> embedded in a `VideoObject`. The tools require `contentType` so callers must
> identify which supported type applies. A successful API response confirms
> receipt of the notification; it does not guarantee that Google indexed the
> URL. Use `url_inspection_inspect` to check index status. See Google's
> [Indexing API usage guide](https://developers.google.com/search/apis/indexing-api/v3/using-api).

## Authentication

Two authentication methods are supported:

### Option 1: OAuth2 Refresh Token

```json
{
  "mcpServers": {
    "gsc-mcp": {
      "command": "npx",
      "args": ["-y", "@mikusnuz/gsc-mcp@1.4.0"],
      "env": {
        "GSC_CLIENT_ID": "your-client-id",
        "GSC_CLIENT_SECRET": "your-client-secret",
        "GSC_REFRESH_TOKEN": "your-refresh-token"
      }
    }
  }
}
```

Required OAuth2 scopes:
- `https://www.googleapis.com/auth/webmasters`
- `https://www.googleapis.com/auth/indexing`

### Security options

- `GSC_READ_ONLY=1` — registers only read tools and requests only the `webmasters.readonly` scope. Recommended when you only need analytics or inspection. Set it in the `env` block of the config above.
- All tool output is prefixed with an untrusted-data marker, and is capped at 100,000 characters. Search queries and URLs in results come from third parties: review before acting on them.
- `GSC_ALLOWED_SITES` — comma-separated properties/URL prefixes tools may touch (e.g. `sc-domain:example.com,https://blog.other.com/posts/`). Anything outside is rejected before any API call. Empty = unrestricted.
- Write tools (`sites_delete`, `sitemaps_delete`, `indexing_publish`, ...) carry MCP `destructiveHint` annotations. Keep confirmation prompts enabled in your client.
- Pin the package version (as in the examples) instead of using `npx -y @mikusnuz/gsc-mcp` unpinned.

### Option 2: Service Account

```json
{
  "mcpServers": {
    "gsc-mcp": {
      "command": "npx",
      "args": ["-y", "@mikusnuz/gsc-mcp@1.4.0"],
      "env": {
        "GSC_SERVICE_ACCOUNT_KEY_PATH": "/path/to/service-account-key.json"
      }
    }
  }
}
```

For Search Console read/write tools, add the service account as an owner or user
with sufficient permission. For **Indexing API** tools, Google requires the
service account to be added as a **delegated owner** of the property; user-level
access is not sufficient.

## Remote deployment (Cloudflare Workers)

Full step-by-step guide (Spanish): [docs/DEPLOY.md](docs/DEPLOY.md).

Run the server online so AI clients connect over HTTPS (Streamable HTTP, stateless) instead of spawning a local process.

```bash
npm install
npx wrangler login
openssl rand -hex 32                      # generate a token, then:
npx wrangler secret put MCP_AUTH_TOKEN    # paste it (min 32 chars)

# Google credentials: pick one
npx wrangler secret put GSC_SERVICE_ACCOUNT_JSON     # paste the service account key JSON
# or: GSC_CLIENT_ID, GSC_CLIENT_SECRET, GSC_REFRESH_TOKEN (three secrets)

npm run worker:deploy
```

Endpoint: `https://gsc-mcp.<your-subdomain>.workers.dev/mcp` (health check: `/health`).

Connect a client:

```bash
claude mcp add --transport http gsc https://gsc-mcp.<your-subdomain>.workers.dev/mcp \
  --header "Authorization: Bearer <MCP_AUTH_TOKEN>"
```

Clients without remote HTTP support can use [`mcp-remote`](https://www.npmjs.com/package/mcp-remote) with the same URL and header.

Security notes:

- Every request needs `Authorization: Bearer <MCP_AUTH_TOKEN>`. If the secret is missing or shorter than 32 chars the Worker answers `503` and serves nothing (fail closed).
- The Worker holds your Google credentials with **write access** (delete sites, sitemaps, indexing notifications). Anyone with the token has the same power. Set `GSC_ALLOWED_SITES` (Worker variable) to limit which properties can be touched, or `GSC_READ_ONLY=1` for a read-only server.
- Rotate the token with `npx wrangler secret put MCP_AUTH_TOKEN`, then update your clients.
- Per-IP rate limiting on `/mcp` and OAuth routes, plus a stricter limit for write/batch tools, via the `MCP_RATE_LIMITER` / `TOOL_RATE_LIMITER` bindings (paid plan; see `docs/DEPLOY.md`). Every `tools/call` is audit-logged (tool, client, IP; no arguments).
- Browser requests (an `Origin` header) are rejected unless listed in `MCP_ALLOWED_ORIGINS`.
- OAuth 2.1 (dynamic client registration + PKCE) is supported for claude.ai custom connectors when the `OAUTH_KV` binding exists; scope `gsc:read` gives a read-only session.
- Local testing: copy `.dev.vars.example` to `.dev.vars`, then `npm run worker:dev`.

## Setup Guide

### OAuth2 Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a project (or select existing)
3. Enable **Search Console API** and **Indexing API**
4. Create OAuth 2.0 credentials (Desktop app type)
5. Use the [OAuth Playground](https://developers.google.com/oauthplayground/) to generate a refresh token with scopes:
   - `https://www.googleapis.com/auth/webmasters`
   - `https://www.googleapis.com/auth/indexing`

### Service Account Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a service account
3. Download the JSON key file
4. Enable **Search Console API** and **Indexing API**
5. In Search Console, add the service account email as an owner for your sites

## License

MIT
