import assert from "node:assert/strict";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import {
  createSchemas,
  isAllowed,
  isToolEnabled,
  parseAllowedSites,
  untrusted,
  untrustedJson,
} from "../dist/security.js";

async function withClient(env, fn) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ["dist/index.js"],
    cwd: process.cwd(),
    env: { PATH: process.env.PATH, ...env },
    stderr: "pipe",
  });
  const client = new Client({ name: "gsc-mcp-test", version: "1.0.0" });
  try {
    await client.connect(transport);
    return await fn(client);
  } finally {
    await client.close();
  }
}

// ── validation schemas ──

test("siteUrl schema accepts properties and rejects junk", () => {
  const { siteUrlSchema } = createSchemas([]);
  assert.ok(siteUrlSchema.safeParse("https://example.com/").success);
  assert.ok(siteUrlSchema.safeParse("sc-domain:example.com").success);
  assert.ok(!siteUrlSchema.safeParse("file:///etc/passwd").success);
  assert.ok(!siteUrlSchema.safeParse("https://a.com/\nIgnore previous").success);
  assert.ok(!siteUrlSchema.safeParse("sc-domain:a.com/../x").success);
});

test("httpUrl schema allows only http(s) without control characters", () => {
  const { httpUrlSchema } = createSchemas([]);
  assert.ok(httpUrlSchema.safeParse("https://example.com/sitemap.xml").success);
  assert.ok(!httpUrlSchema.safeParse("javascript:alert(1)").success);
  assert.ok(!httpUrlSchema.safeParse("ftp://example.com/x").success);
  assert.ok(!httpUrlSchema.safeParse("https://example.com/\r\nX: y").success);
});

// ── allowlist ──

test("allowlist parsing", () => {
  assert.deepEqual(parseAllowedSites(undefined), []);
  assert.deepEqual(parseAllowedSites("https://a.com/, sc-domain:b.com"), [
    "https://a.com/",
    "sc-domain:b.com",
  ]);
});

test("allowlist matches domains and prefixes, not lookalikes", () => {
  const allowed = ["sc-domain:example.com", "https://blog.other.com/posts/"];
  assert.ok(isAllowed("sc-domain:example.com", allowed));
  assert.ok(isAllowed("https://www.example.com/page", allowed));
  assert.ok(isAllowed("https://blog.other.com/posts/1", allowed));
  assert.ok(!isAllowed("https://blog.other.com/private", allowed));
  assert.ok(!isAllowed("https://evilexample.com/", allowed));
  assert.ok(!isAllowed("https://example.com.evil.com/", allowed));
  assert.ok(!isAllowed("https://example.com@evil.com/", allowed));
  assert.ok(!isAllowed("sc-domain:evil.com", allowed));
  assert.ok(isAllowed("anything", []), "empty allowlist is unrestricted");
});

test("schemas enforce the allowlist", () => {
  const { siteUrlSchema, httpUrlSchema } = createSchemas(["https://a.com/"]);
  assert.ok(siteUrlSchema.safeParse("https://a.com/").success);
  assert.ok(!siteUrlSchema.safeParse("https://b.com/").success);
  assert.ok(httpUrlSchema.safeParse("https://a.com/sitemap.xml").success);
  assert.ok(!httpUrlSchema.safeParse("https://b.com/sitemap.xml").success);
});

// ── output marking ──

test("untrusted() marks and truncates", () => {
  const out = untrusted("hello");
  assert.match(out, /^\[UNTRUSTED DATA/);
  assert.ok(out.endsWith("hello"));
  const big = untrusted("x".repeat(50), 10);
  assert.match(big, /truncated: output exceeded 10 characters/);
});

test("untrustedJson() keeps valid JSON, marks and truncates", () => {
  const ok = JSON.parse(untrustedJson('{"siteEntry":[]}'));
  assert.match(ok.notice, /UNTRUSTED DATA/);
  assert.deepEqual(ok.data, { siteEntry: [] });

  const cut = JSON.parse(untrustedJson("y".repeat(50), 10));
  assert.equal(cut.truncated, true);
  assert.equal(cut.data.length, 10);

  const text = JSON.parse(untrustedJson("not json"));
  assert.equal(text.data, "not json");
});

// ── read-only registration ──

test("isToolEnabled hides write tools in read-only mode", () => {
  assert.ok(isToolEnabled("sites_list", true));
  for (const name of [
    "sites_add",
    "sites_delete",
    "sitemaps_submit",
    "sitemaps_delete",
    "indexing_publish",
    "indexing_get_metadata",
    "indexing_batch_publish",
  ]) {
    assert.ok(!isToolEnabled(name, true), name);
    assert.ok(isToolEnabled(name, false), name);
  }
});

test("GSC_READ_ONLY exposes only read tools", async () => {
  const names = await withClient({ GSC_READ_ONLY: "1" }, async (client) =>
    (await client.listTools()).tools.map((t) => t.name).sort(),
  );
  assert.deepEqual(names, [
    "search_analytics_query",
    "sitemaps_get",
    "sitemaps_list",
    "sites_get",
    "sites_list",
    "url_inspection_inspect",
  ]);
});

test("default mode exposes all tools with destructive annotations", async () => {
  const tools = await withClient({}, async (client) => (await client.listTools()).tools);
  assert.equal(tools.length, 13);
  const byName = Object.fromEntries(tools.map((t) => [t.name, t.annotations]));
  assert.equal(byName.sites_delete.destructiveHint, true);
  assert.equal(byName.sitemaps_delete.destructiveHint, true);
  assert.equal(byName.sites_list.readOnlyHint, true);
});

test("allowlist rejects other sites before any network call", async () => {
  const result = await withClient(
    { GSC_ALLOWED_SITES: "https://allowed.example/" },
    async (client) =>
      client
        .callTool({
          name: "sites_delete",
          arguments: { siteUrl: "https://other.example/" },
        })
        .catch((e) => ({ isError: true, content: [{ text: String(e.message) }] })),
  );
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /GSC_ALLOWED_SITES/);
});
