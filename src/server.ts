import {
  McpServer,
  ResourceTemplate,
} from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { HTTP_TIMEOUT_MS, getAccessToken as fetchAccessToken } from "./auth.js";
import { parseIndexingBatchResponse } from "./indexing-batch.js";
import {
  createSchemas,
  filterSitesBody,
  isToolEnabled,
  parseAllowedSites,
  redactProjectIds,
  truncateError,
  untrusted,
  untrustedJson,
} from "./security.js";

// ── Config ──

// Read-only mode: no write/destructive tools registered, read-only OAuth scope.
// Env var sets the default (stdio, static-bearer worker requests); an OAuth
// access token's scope can override this per request via buildServer's param.
const ENV_READ_ONLY = /^(1|true|yes)$/i.test(process.env.GSC_READ_ONLY || "");

// Verify indexing_publish/indexing_batch_publish's contentType against the page's
// own JSON-LD before notifying Google. Off by default: it fetches the target URL,
// which adds latency and assumes the Worker can reach it. The URL is already
// constrained by httpUrlSchema + GSC_ALLOWED_SITES, so this doesn't widen SSRF exposure.
const VERIFY_INDEXING_CONTENT = /^(1|true|yes)$/i.test(
  process.env.GSC_VERIFY_INDEXING_CONTENT || "",
);

const WEBMASTERS_BASE = "https://www.googleapis.com/webmasters/v3";
const INSPECTION_BASE = "https://searchconsole.googleapis.com/v1";
const INDEXING_BASE = "https://indexing.googleapis.com/v3";
const SERVER_VERSION = "1.4.0";

// Optional allowlist of properties/URLs tools may touch (empty = unrestricted).
const ALLOWED_SITES = parseAllowedSites(process.env.GSC_ALLOWED_SITES);
const { siteUrlSchema, httpUrlSchema } = createSchemas(ALLOWED_SITES);

// ── Helpers ──

function encodeSiteUrl(siteUrl: string): string {
  return encodeURIComponent(siteUrl);
}

function toolResult(result: { ok: boolean; body: string }) {
  const body = result.ok ? result.body : redactProjectIds(result.body);
  return {
    content: [{ type: "text" as const, text: untrusted(body) }],
    isError: !result.ok,
  };
}

function errorResult(e: unknown) {
  const raw = e instanceof Error ? e.message : String(e);
  const message = redactProjectIds(truncateError(raw));
  return {
    content: [{ type: "text" as const, text: `Error: ${message}` }],
    isError: true,
  };
}

/**
 * @param readOnly Overrides GSC_READ_ONLY for this server instance (e.g. an
 *   OAuth access token scoped to `gsc:read`). Defaults to the env var.
 */
function buildServer(sandbox: boolean, readOnly: boolean = ENV_READ_ONLY): McpServer {
  // ── MCP Server ──

  const SCOPES = readOnly
    ? ["https://www.googleapis.com/auth/webmasters.readonly"]
    : [
        "https://www.googleapis.com/auth/webmasters",
        "https://www.googleapis.com/auth/indexing",
      ];

  function getAccessToken(): Promise<string> {
    return fetchAccessToken(SCOPES);
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
    return isToolEnabled(name, readOnly) ? sandboxView : discardServer;
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
        if (result.ok) result.body = filterSitesBody(result.body, ALLOWED_SITES);
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
                : redactProjectIds(result.body),
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
                : redactProjectIds(result.body),
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
                : redactProjectIds(result.body),
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
                : redactProjectIds(result.body),
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

  function jsonLdMatchesType(node: unknown, contentType: string): boolean {
    if (!node || typeof node !== "object") return false;
    const obj = node as Record<string, unknown>;
    const types = ([] as unknown[]).concat(obj["@type"] as never);
    if (types.includes(contentType)) return true;
    if (contentType !== "BroadcastEvent" || !types.includes("VideoObject")) return false;
    const publications = ([] as unknown[]).concat(obj["publication"] as never);
    return publications.some(
      (p) =>
        p &&
        typeof p === "object" &&
        ([] as unknown[]).concat((p as Record<string, unknown>)["@type"] as never).includes("BroadcastEvent"),
    );
  }

  /**
   * When GSC_VERIFY_INDEXING_CONTENT is set, fetch the page and require its own
   * JSON-LD to declare the notified contentType, since `contentType` is otherwise
   * model-declared and never checked against the page. `url` is already validated
   * by httpUrlSchema and GSC_ALLOWED_SITES, so this doesn't widen SSRF exposure.
   */
  async function verifyIndexingContent(
    url: string,
    contentType: "JobPosting" | "BroadcastEvent",
  ): Promise<void> {
    if (!VERIFY_INDEXING_CONTENT) return;

    let html: string;
    try {
      const res = await fetch(url, {
        redirect: "follow",
        signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
      });
      html = await res.text();
    } catch (e) {
      const raw = e instanceof Error ? e.message : String(e);
      throw new Error(`Could not fetch ${url} to verify contentType: ${truncateError(raw)}`);
    }

    const blocks = [
      ...html.matchAll(/<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi),
    ].map((m) => m[1]);
    const declared = blocks.some((block) => {
      try {
        const data = JSON.parse(block);
        return ([] as unknown[]).concat(data).some((node) => jsonLdMatchesType(node, contentType));
      } catch {
        return false;
      }
    });
    if (!declared) {
      throw new Error(
        `Page ${url} has no JSON-LD declaring ${contentType}; Google Indexing API will reject or ignore this notification.`,
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
        await verifyIndexingContent(url, contentType);
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
        await Promise.all(
          notifications.map(({ url, contentType }) => verifyIndexingContent(url, contentType)),
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
            `content-length: ${new TextEncoder().encode(body).length}`,
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
      const body = result.ok ? filterSitesBody(result.body, ALLOWED_SITES) : result.body;
      return {
        contents: [
          {
            uri: "gsc://sites",
            mimeType: "application/json",
            text: untrustedJson(body),
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

export { buildServer };
