#!/usr/bin/env node

import {
  McpServer,
  ResourceTemplate,
} from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { GoogleAuth } from "google-auth-library";
import { parseIndexingBatchResponse } from "./indexing-batch.js";
import {
  createSchemas,
  isToolEnabled,
  parseAllowedSites,
  truncateError,
  untrusted,
  untrustedJson,
} from "./security.js";

// ── Config ──

const CLIENT_ID = process.env.GSC_CLIENT_ID || "";
const CLIENT_SECRET = process.env.GSC_CLIENT_SECRET || "";
const REFRESH_TOKEN = process.env.GSC_REFRESH_TOKEN || "";
const SERVICE_ACCOUNT_KEY_PATH = process.env.GSC_SERVICE_ACCOUNT_KEY_PATH || "";
// Read-only mode: no write/destructive tools registered, read-only OAuth scope.
const READ_ONLY = /^(1|true|yes)$/i.test(process.env.GSC_READ_ONLY || "");

const WEBMASTERS_BASE = "https://www.googleapis.com/webmasters/v3";
const INSPECTION_BASE = "https://searchconsole.googleapis.com/v1";
const INDEXING_BASE = "https://indexing.googleapis.com/v3";
const TOKEN_URL = "https://oauth2.googleapis.com/token";
const SERVER_VERSION = "1.3.3";
const HTTP_TIMEOUT_MS = 30_000;

const SCOPES = READ_ONLY
  ? ["https://www.googleapis.com/auth/webmasters.readonly"]
  : [
      "https://www.googleapis.com/auth/webmasters",
      "https://www.googleapis.com/auth/indexing",
    ];

// Optional allowlist of properties/URLs tools may touch (empty = unrestricted).
const ALLOWED_SITES = parseAllowedSites(process.env.GSC_ALLOWED_SITES);
const { siteUrlSchema, httpUrlSchema } = createSchemas(ALLOWED_SITES);

// ── Auth ──

let cachedOAuthToken: { access_token: string; expires_at: number } | null =
  null;
let googleAuth: GoogleAuth | null = null;

async function getAccessToken(): Promise<string> {
  // Service Account auth (preferred if key path is set)
  if (SERVICE_ACCOUNT_KEY_PATH) {
    if (!googleAuth) {
      googleAuth = new GoogleAuth({
        keyFile: SERVICE_ACCOUNT_KEY_PATH,
        scopes: SCOPES,
        clientOptions: {
          transporterOptions: { timeout: HTTP_TIMEOUT_MS },
        },
      });
    }
    const client = await googleAuth.getClient();

    // Retry once on transient network errors (e.g. "Premature close" from
    // keep-alive socket reuse) before failing the tool call.
    let token;
    try {
      token = await withTimeout(
        client.getAccessToken(),
        "Service account token request",
      );
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      if (!/premature close/i.test(message)) throw e;
      await new Promise((r) => setTimeout(r, 300));
      token = await withTimeout(
        client.getAccessToken(),
        "Service account token retry",
      );
    }

    if (!token.token) throw new Error("Failed to get service account token");
    return token.token;
  }

  // OAuth2 refresh token auth
  if (!CLIENT_ID || !CLIENT_SECRET || !REFRESH_TOKEN) {
    throw new Error(
      "Missing credentials. Set GSC_SERVICE_ACCOUNT_KEY_PATH for service account auth, " +
        "or GSC_CLIENT_ID + GSC_CLIENT_SECRET + GSC_REFRESH_TOKEN for OAuth2.",
    );
  }

  if (cachedOAuthToken && Date.now() < cachedOAuthToken.expires_at - 60_000) {
    return cachedOAuthToken.access_token;
  }

  const body = new URLSearchParams({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    refresh_token: REFRESH_TOKEN,
    grant_type: "refresh_token",
  });

  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
    signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
  });

  if (!res.ok) {
    let detail = "";
    try {
      const err = JSON.parse(await res.text()) as { error?: string };
      detail = typeof err.error === "string" ? `: ${err.error}` : "";
    } catch {
      // ignore non-JSON error bodies
    }
    throw new Error(`Token refresh failed (${res.status})${detail}`);
  }

  const data = (await res.json()) as {
    access_token: string;
    expires_in: number;
  };
  cachedOAuthToken = {
    access_token: data.access_token,
    expires_at: Date.now() + data.expires_in * 1000,
  };

  return cachedOAuthToken.access_token;
}

// ── Helpers ──

async function withTimeout<T>(promise: Promise<T>, label: string): Promise<T> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timeout = setTimeout(
          () => reject(new Error(`${label} timed out after ${HTTP_TIMEOUT_MS}ms`)),
          HTTP_TIMEOUT_MS,
        );
      }),
    ]);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

function encodeSiteUrl(siteUrl: string): string {
  return encodeURIComponent(siteUrl);
}

async function apiCall(
  url: string,
  options: RequestInit = {},
): Promise<{ ok: boolean; status: number; body: string }> {
  const token = await getAccessToken();
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
    ...((options.headers as Record<string, string>) || {}),
  };

  const res = await fetch(url, {
    ...options,
    headers,
    signal: options.signal || AbortSignal.timeout(HTTP_TIMEOUT_MS),
  });
  const body = await res.text();
  return { ok: res.ok, status: res.status, body };
}

function toolResult(result: { ok: boolean; body: string }) {
  return {
    content: [{ type: "text" as const, text: untrusted(result.body) }],
    isError: !result.ok,
  };
}

function errorResult(e: unknown) {
  const raw = e instanceof Error ? e.message : String(e);
  const message = truncateError(raw);
  return {
    content: [{ type: "text" as const, text: `Error: ${message}` }],
    isError: true,
  };
}

function buildServer(sandbox: boolean): McpServer {
  // ── MCP Server ──

  const server = new McpServer({
    name: "gsc-mcp",
    version: SERVER_VERSION,
  });

  // Sandbox mode (Smithery scanning): same tool definitions, stubbed handlers.
  const sandboxView: McpServer = sandbox
    ? new Proxy(server, {
        get(target, prop) {
          if (prop === "tool") {
            return (...args: unknown[]) => {
              args[args.length - 1] = async () => ({
                content: [{ type: "text" as const, text: "sandbox" }],
              });
              return (target.tool as (...a: unknown[]) => unknown)(...args);
            };
          }
          const value = Reflect.get(target, prop, target);
          return typeof value === "function" ? value.bind(target) : value;
        },
      })
    : server;

  const ANNOTATIONS = {
    READ: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    // Needs the Indexing API scope, so it is dropped in read-only mode.
    INDEXING_READ: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    WRITE: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    DESTRUCTIVE: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
  };

  // Write tools go to a throwaway server in read-only mode, so they are never exposed.
  const discardServer = new McpServer({ name: "discard", version: "0.0.0" });
  function toolServer(name: string): McpServer {
    return isToolEnabled(name, READ_ONLY) ? sandboxView : discardServer;
  }

  // ════════════════════════════════════════════
  // SITES
  // ════════════════════════════════════════════

  // ── sites_list ──
  toolServer("sites_list").tool(
    "sites_list",
    "List all sites (properties) you have access to in Google Search Console.",
    {},
    ANNOTATIONS.READ,
    async () => {
      try {
        const result = await apiCall(`${WEBMASTERS_BASE}/sites`, {
          method: "GET",
        });
        return toolResult(result);
      } catch (e) {
        return errorResult(e);
      }
    },
  );

  // ── sites_get ──
  toolServer("sites_get").tool(
    "sites_get",
    "Retrieve information about a specific site (property) in Google Search Console.",
    {
      siteUrl: siteUrlSchema.describe(
          "The site URL (e.g. 'https://example.com/' or 'sc-domain:example.com')",
        ),
    },
    ANNOTATIONS.READ,
    async ({ siteUrl }) => {
      try {
        const result = await apiCall(
          `${WEBMASTERS_BASE}/sites/${encodeSiteUrl(siteUrl)}`,
          { method: "GET" },
        );
        return toolResult(result);
      } catch (e) {
        return errorResult(e);
      }
    },
  );

  // ── sites_add ──
  toolServer("sites_add").tool(
    "sites_add",
    "Add a site (property) to Google Search Console. Verification may still be required.",
    {
      siteUrl: siteUrlSchema.describe(
          "The site URL to add (e.g. 'https://example.com/' or 'sc-domain:example.com')",
        ),
    },
    ANNOTATIONS.WRITE,
    async ({ siteUrl }) => {
      try {
        const result = await apiCall(
          `${WEBMASTERS_BASE}/sites/${encodeSiteUrl(siteUrl)}`,
          { method: "PUT" },
        );
        return {
          content: [
            {
              type: "text" as const,
              text: result.ok
                ? `Site "${siteUrl}" added successfully.`
                : result.body,
            },
          ],
          isError: !result.ok,
        };
      } catch (e) {
        return errorResult(e);
      }
    },
  );

  // ── sites_delete ──
  toolServer("sites_delete").tool(
    "sites_delete",
    "Remove a site (property) from Google Search Console.",
    {
      siteUrl: siteUrlSchema.describe("The site URL to remove"),
    },
    ANNOTATIONS.DESTRUCTIVE,
    async ({ siteUrl }) => {
      try {
        const result = await apiCall(
          `${WEBMASTERS_BASE}/sites/${encodeSiteUrl(siteUrl)}`,
          { method: "DELETE" },
        );
        return {
          content: [
            {
              type: "text" as const,
              text: result.ok
                ? `Site "${siteUrl}" removed successfully.`
                : result.body,
            },
          ],
          isError: !result.ok,
        };
      } catch (e) {
        return errorResult(e);
      }
    },
  );

  // ════════════════════════════════════════════
  // SITEMAPS
  // ════════════════════════════════════════════

  // ── sitemaps_list ──
  toolServer("sitemaps_list").tool(
    "sitemaps_list",
    "List all sitemaps submitted for a site in Google Search Console.",
    {
      siteUrl: siteUrlSchema.describe("The site URL"),
      sitemapIndex: httpUrlSchema
        .optional()
        .describe(
          "Optional: URL of a sitemap index to list only sitemaps in that index",
        ),
    },
    ANNOTATIONS.READ,
    async ({ siteUrl, sitemapIndex }) => {
      try {
        let url = `${WEBMASTERS_BASE}/sites/${encodeSiteUrl(siteUrl)}/sitemaps`;
        if (sitemapIndex) {
          url += `?sitemapIndex=${encodeURIComponent(sitemapIndex)}`;
        }
        const result = await apiCall(url, { method: "GET" });
        return toolResult(result);
      } catch (e) {
        return errorResult(e);
      }
    },
  );

  // ── sitemaps_get ──
  toolServer("sitemaps_get").tool(
    "sitemaps_get",
    "Retrieve information about a specific sitemap.",
    {
      siteUrl: siteUrlSchema.describe("The site URL"),
      feedpath: httpUrlSchema.describe("The URL of the sitemap (e.g. 'https://example.com/sitemap.xml')"),
    },
    ANNOTATIONS.READ,
    async ({ siteUrl, feedpath }) => {
      try {
        const result = await apiCall(
          `${WEBMASTERS_BASE}/sites/${encodeSiteUrl(siteUrl)}/sitemaps/${encodeURIComponent(feedpath)}`,
          { method: "GET" },
        );
        return toolResult(result);
      } catch (e) {
        return errorResult(e);
      }
    },
  );

  // ── sitemaps_submit ──
  toolServer("sitemaps_submit").tool(
    "sitemaps_submit",
    "Submit a sitemap for a site to Google Search Console.",
    {
      siteUrl: siteUrlSchema.describe("The site URL"),
      feedpath: httpUrlSchema.describe(
          "The URL of the sitemap to submit (e.g. 'https://example.com/sitemap.xml')",
        ),
    },
    ANNOTATIONS.WRITE,
    async ({ siteUrl, feedpath }) => {
      try {
        const result = await apiCall(
          `${WEBMASTERS_BASE}/sites/${encodeSiteUrl(siteUrl)}/sitemaps/${encodeURIComponent(feedpath)}`,
          { method: "PUT" },
        );
        return {
          content: [
            {
              type: "text" as const,
              text: result.ok
                ? `Sitemap "${feedpath}" submitted successfully.`
                : result.body,
            },
          ],
          isError: !result.ok,
        };
      } catch (e) {
        return errorResult(e);
      }
    },
  );

  // ── sitemaps_delete ──
  toolServer("sitemaps_delete").tool(
    "sitemaps_delete",
    "Delete a sitemap from Google Search Console.",
    {
      siteUrl: siteUrlSchema.describe("The site URL"),
      feedpath: httpUrlSchema.describe("The URL of the sitemap to delete"),
    },
    ANNOTATIONS.DESTRUCTIVE,
    async ({ siteUrl, feedpath }) => {
      try {
        const result = await apiCall(
          `${WEBMASTERS_BASE}/sites/${encodeSiteUrl(siteUrl)}/sitemaps/${encodeURIComponent(feedpath)}`,
          { method: "DELETE" },
        );
        return {
          content: [
            {
              type: "text" as const,
              text: result.ok
                ? `Sitemap "${feedpath}" deleted successfully.`
                : result.body,
            },
          ],
          isError: !result.ok,
        };
      } catch (e) {
        return errorResult(e);
      }
    },
  );

  // ════════════════════════════════════════════
  // SEARCH ANALYTICS
  // ════════════════════════════════════════════

  const dimensionEnum = z.enum([
    "country",
    "device",
    "page",
    "query",
    "searchAppearance",
    "date",
    "hour",
  ]);

  const filterOperatorEnum = z.enum([
    "contains",
    "equals",
    "notContains",
    "notEquals",
    "includingRegex",
    "excludingRegex",
  ]);

  const searchTypeEnum = z.enum(["web", "image", "video", "news", "discover", "googleNews"]);

  const dataStateEnum = z.enum(["all", "final", "hourly_all"]);

  const dimensionFilterGroupSchema = z.object({
    groupType: z.enum(["and"]).optional().describe("How filters are combined (only 'and' is supported)"),
    filters: z.array(
      z.object({
        dimension: dimensionEnum.describe("The dimension to filter on"),
        operator: filterOperatorEnum
          .optional()
          .describe("Filter operator (default: 'equals')"),
        expression: z
          .string()
          .describe("The value to filter by"),
      }),
    ),
  });

  // ── search_analytics_query ──
  toolServer("search_analytics_query").tool(
    "search_analytics_query",
    "Query search traffic data from Google Search Console. Returns clicks, impressions, CTR, and position data with flexible filtering and grouping.",
    {
      siteUrl: siteUrlSchema.describe("The site URL"),
      startDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "Expected YYYY-MM-DD")
        .describe("Start date in YYYY-MM-DD format"),
      endDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "Expected YYYY-MM-DD")
        .describe("End date in YYYY-MM-DD format"),
      dimensions: z
        .array(dimensionEnum)
        .optional()
        .describe(
          "Dimensions to group by: country, device, page, query, searchAppearance, date, hour (hour requires dataState='hourly_all')",
        ),
      type: searchTypeEnum
        .optional()
        .describe(
          "Search type filter: web, image, video, news, discover, googleNews (default: web)",
        ),
      dimensionFilterGroups: z
        .array(dimensionFilterGroupSchema)
        .optional()
        .describe("Filter groups to apply to the query"),
      aggregationType: z
        .enum(["auto", "byPage", "byProperty", "byNewsShowcasePanel"])
        .optional()
        .describe("How data is aggregated (default: auto)"),
      rowLimit: z
        .number()
        .min(1)
        .max(5000)
        .optional()
        .describe("Maximum number of rows to return (1-5000, default: 1000; use startRow to paginate)"),
      startRow: z
        .number()
        .min(0)
        .optional()
        .describe("Zero-based row offset for pagination"),
      dataState: dataStateEnum
        .optional()
        .describe(
          "'all' includes fresh (possibly incomplete) data, 'final' only finalized data, 'hourly_all' required when using 'hour' dimension",
        ),
    },
    ANNOTATIONS.READ,
    async ({
      siteUrl,
      startDate,
      endDate,
      dimensions,
      type,
      dimensionFilterGroups,
      aggregationType,
      rowLimit,
      startRow,
      dataState,
    }) => {
      try {
        const body: Record<string, unknown> = { startDate, endDate };
        if (dimensions) body.dimensions = dimensions;
        if (type) body.type = type;
        if (dimensionFilterGroups)
          body.dimensionFilterGroups = dimensionFilterGroups;
        if (aggregationType) body.aggregationType = aggregationType;
        if (rowLimit !== undefined) body.rowLimit = rowLimit;
        if (startRow !== undefined) body.startRow = startRow;
        if (dataState) body.dataState = dataState;

        const result = await apiCall(
          `${WEBMASTERS_BASE}/sites/${encodeSiteUrl(siteUrl)}/searchAnalytics/query`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
          },
        );
        return toolResult(result);
      } catch (e) {
        return errorResult(e);
      }
    },
  );

  // ════════════════════════════════════════════
  // URL INSPECTION
  // ════════════════════════════════════════════

  // ── url_inspection_inspect ──
  toolServer("url_inspection_inspect").tool(
    "url_inspection_inspect",
    "Inspect a URL in Google's index. Returns the current URL Inspection API result, including indexing status, crawl info, rich results, and AMP status. The deprecated mobileUsabilityResult field may be absent.",
    {
      inspectionUrl: httpUrlSchema.describe("The fully-qualified URL to inspect (must be under the site)"),
      siteUrl: siteUrlSchema.describe(
          "The site URL (property) the inspected URL belongs to",
        ),
      languageCode: z
        .string()
        .regex(/^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$/, "Invalid BCP-47 language code")
        .optional()
        .describe(
          "Optional BCP-47 language code for localized results (e.g. 'en-US', 'ko')",
        ),
    },
    ANNOTATIONS.READ,
    async ({ inspectionUrl, siteUrl, languageCode }) => {
      try {
        const body: Record<string, string> = { inspectionUrl, siteUrl };
        if (languageCode) body.languageCode = languageCode;

        const result = await apiCall(
          `${INSPECTION_BASE}/urlInspection/index:inspect`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
          },
        );
        return toolResult(result);
      } catch (e) {
        return errorResult(e);
      }
    },
  );

  // ════════════════════════════════════════════
  // INDEXING API
  // ════════════════════════════════════════════

  const eligibleIndexingContentTypeEnum = z.enum([
    "JobPosting",
    "BroadcastEvent",
  ]);

  function assertIndexingEligibility(
    contentType: "JobPosting" | "BroadcastEvent",
  ): void {
    if (contentType !== "JobPosting" && contentType !== "BroadcastEvent") {
      throw new Error(
        "Google Indexing API supports only JobPosting pages and livestream pages with BroadcastEvent embedded in VideoObject.",
      );
    }
  }

  // ── indexing_publish ──
  toolServer("indexing_publish").tool(
    "indexing_publish",
    "Notify Google about an eligible URL update or removal via the Indexing API. Google supports only JobPosting pages and livestream pages with BroadcastEvent embedded in VideoObject; this notification does not guarantee indexing.",
    {
      url: httpUrlSchema.describe("The fully-qualified URL to notify about"),
      contentType: eligibleIndexingContentTypeEnum.describe(
        "Eligible structured-data type on the page: JobPosting, or BroadcastEvent embedded in VideoObject",
      ),
      type: z
        .enum(["URL_UPDATED", "URL_DELETED"])
        .describe("Notification type: URL_UPDATED or URL_DELETED"),
    },
    ANNOTATIONS.DESTRUCTIVE,
    async ({ url, contentType, type }) => {
      try {
        assertIndexingEligibility(contentType);
        const result = await apiCall(
          `${INDEXING_BASE}/urlNotifications:publish`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url, type }),
          },
        );
        return toolResult(result);
      } catch (e) {
        return errorResult(e);
      }
    },
  );

  // ── indexing_get_metadata ──
  toolServer("indexing_get_metadata").tool(
    "indexing_get_metadata",
    "Get the latest Indexing API notification metadata for an eligible JobPosting or BroadcastEvent URL. This reports notification history, not whether Google indexed the URL.",
    {
      url: httpUrlSchema.describe("The fully-qualified URL to check notification status for"),
      contentType: eligibleIndexingContentTypeEnum.describe(
        "Eligible structured-data type on the page: JobPosting, or BroadcastEvent embedded in VideoObject",
      ),
    },
    ANNOTATIONS.INDEXING_READ,
    async ({ url, contentType }) => {
      try {
        assertIndexingEligibility(contentType);
        const result = await apiCall(
          `${INDEXING_BASE}/urlNotifications/metadata?url=${encodeURIComponent(url)}`,
          { method: "GET" },
        );
        return toolResult(result);
      } catch (e) {
        return errorResult(e);
      }
    },
  );

  // ── indexing_batch_publish ──
  toolServer("indexing_batch_publish").tool(
    "indexing_batch_publish",
    "Batch notify Google about up to 100 eligible JobPosting or BroadcastEvent URL updates/removals. Each embedded response is checked independently; a successful notification does not guarantee indexing.",
    {
      notifications: z
        .array(
          z.object({
            url: httpUrlSchema.describe("The fully-qualified URL"),
            contentType: eligibleIndexingContentTypeEnum.describe(
              "Eligible page type: JobPosting, or BroadcastEvent embedded in VideoObject",
            ),
            type: z
              .enum(["URL_UPDATED", "URL_DELETED"])
              .describe("Notification type: URL_UPDATED or URL_DELETED"),
          }),
        )
        .min(1)
        .max(100)
        .describe(
          "Array of eligible URL notifications (1-100 items). Each item has url, contentType, and type.",
        ),
    },
    ANNOTATIONS.DESTRUCTIVE,
    async ({ notifications }) => {
      try {
        notifications.forEach(({ contentType }) =>
          assertIndexingEligibility(contentType),
        );
        const token = await getAccessToken();
        const boundary = `batch_gsc_mcp_${Date.now()}`;

        const parts = notifications.map((n, i) => {
          const body = JSON.stringify({ url: n.url, type: n.type });
          return [
            `--${boundary}`,
            "Content-Type: application/http",
            "Content-Transfer-Encoding: binary",
            `Content-ID: <item-${i + 1}>`,
            "",
            "POST /v3/urlNotifications:publish HTTP/1.1",
            "Content-Type: application/json",
            "accept: application/json",
            `content-length: ${Buffer.byteLength(body)}`,
            "",
            body,
          ].join("\r\n");
        });

        const batchBody = parts.join("\r\n") + `\r\n--${boundary}--`;

        const res = await fetch("https://indexing.googleapis.com/batch", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": `multipart/mixed; boundary=${boundary}`,
          },
          body: batchBody,
          signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
        });

        const responseText = await res.text();
        if (!res.ok) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Batch request failed (${res.status}):\n${responseText}`,
              },
            ],
            isError: true,
          };
        }

        const results = parseIndexingBatchResponse(
          responseText,
          res.headers.get("content-type") || "",
          notifications,
        );
        const failed = results.filter((result) => !result.ok).length;
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  total: results.length,
                  succeeded: results.length - failed,
                  failed,
                  results,
                },
                null,
                2,
              ),
            },
          ],
          isError: failed > 0,
        };
      } catch (e) {
        return errorResult(e);
      }
    },
  );

  // ════════════════════════════════════════════
  // PROMPTS
  // ════════════════════════════════════════════

  server.prompt(
    "seo_audit",
    "Run an SEO audit for a site — checks indexing status, sitemap health, and recent search performance.",
    {
      siteUrl: siteUrlSchema.describe(
          "The site URL (e.g. 'https://example.com/' or 'sc-domain:example.com')",
        ),
    },
    ({ siteUrl }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: [
              `Perform a comprehensive SEO audit for ${siteUrl}. Follow these steps:`,
              "",
              "1. Use sites_get to check the site's verification status",
              "2. Use sitemaps_list to check submitted sitemaps",
              "3. Use search_analytics_query with dimensions=['date'] for the last 28 days to get traffic trends",
              "4. Use search_analytics_query with dimensions=['page'] and rowLimit=10 to find top pages",
              "5. Use search_analytics_query with dimensions=['query'] and rowLimit=10 to find top queries",
              "",
              "Summarize findings including:",
              "- Site verification status",
              "- Sitemap health (count, errors, last submitted)",
              "- Traffic overview (total clicks, impressions, avg CTR, avg position)",
              "- Traffic trend (up/down over 28 days)",
              "- Top performing pages and queries",
              "- Recommendations for improvement",
            ].join("\n"),
          },
        },
      ],
    }),
  );

  server.prompt(
    "index_url",
    "Notify Google about an eligible JobPosting or BroadcastEvent URL and inspect its current index status.",
    {
      url: httpUrlSchema.describe("The fully-qualified URL to index"),
      siteUrl: siteUrlSchema.describe("The site URL this page belongs to"),
      contentType: eligibleIndexingContentTypeEnum.describe(
        "Eligible page type: JobPosting, or BroadcastEvent embedded in VideoObject",
      ),
    },
    ({ url, siteUrl, contentType }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: [
              `Notify Google about the eligible ${contentType} URL ${url} (site: ${siteUrl}). Follow these steps:`,
              "",
              "1. Use url_inspection_inspect to check the current index status",
              `2. Use indexing_publish with type URL_UPDATED and contentType ${contentType}`,
              `3. Use indexing_get_metadata with contentType ${contentType} to confirm the notification was received`,
              "",
              "Report current index status and notification confirmation separately. Explain that notification acceptance does not guarantee indexing.",
            ].join("\n"),
          },
        },
      ],
    }),
  );

  // ════════════════════════════════════════════
  // RESOURCES
  // ════════════════════════════════════════════

  server.resource(
    "sites",
    "gsc://sites",
    {
      description:
        "List of all verified sites (properties) in Google Search Console",
      mimeType: "application/json",
    },
    async () => {
      const result = await apiCall(`${WEBMASTERS_BASE}/sites`, {
        method: "GET",
      });
      return {
        contents: [
          {
            uri: "gsc://sites",
            mimeType: "application/json",
            text: untrustedJson(result.body),
          },
        ],
      };
    },
  );

  server.resource(
    "sitemaps",
    new ResourceTemplate("gsc://sitemaps/{siteUrl}", { list: undefined }),
    {
      description: "List of all sitemaps for a specific site",
      mimeType: "application/json",
    },
    async (uri, variables) => {
      const rawSiteUrl = variables.siteUrl;
      if (Array.isArray(rawSiteUrl)) {
        throw new Error("The sitemap resource expects exactly one siteUrl");
      }
      let decoded: string;
      try {
        decoded = decodeURIComponent(rawSiteUrl);
      } catch {
        throw new Error("Invalid siteUrl encoding in resource URI");
      }
      const siteUrl = siteUrlSchema.parse(decoded);
      const result = await apiCall(
        `${WEBMASTERS_BASE}/sites/${encodeSiteUrl(siteUrl)}/sitemaps`,
        { method: "GET" },
      );
      return {
        contents: [
          {
            uri: uri.href,
            mimeType: "application/json",
            text: untrustedJson(result.body),
          },
        ],
      };
    },
  );

  return server;
}

const server = buildServer(false);

// ── Start ──

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  process.stderr.write(`Fatal: ${err.message}\n`);
  process.exit(1);
});

// ── Smithery Sandbox ──

export function createSandboxServer() {
  return buildServer(true);
}
