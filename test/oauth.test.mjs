import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test, { before } from "node:test";

const TOKEN = "t".repeat(48);
process.env.MCP_AUTH_TOKEN = TOKEN;
delete process.env.MCP_ALLOWED_ORIGINS;

class FakeKV {
  m = new Map();
  async get(k) { return this.m.get(k) ?? null; }
  async put(k, v) { this.m.set(k, v); }
  async delete(k) { this.m.delete(k); }
}

let worker;
before(async () => {
  worker = (await import("../dist/worker.js")).default;
});

const HOST = "https://gsc.example";
const REDIRECT = "https://claude.ai/cb";
const MCP = {
  "Content-Type": "application/json",
  Accept: "application/json, text/event-stream",
};
const rpc = (id, method, params) => JSON.stringify({ jsonrpc: "2.0", id, method, params });
const mcp = (env, token, body, ip = "1.1.1.1") =>
  worker.fetch(
    new Request(`${HOST}/mcp`, {
      method: "POST",
      headers: { ...MCP, Authorization: `Bearer ${token}`, "cf-connecting-ip": ip },
      body,
    }),
    env,
  );
const form = (path, data, env) =>
  worker.fetch(
    new Request(`${HOST}${path}`, { method: "POST", body: new URLSearchParams(data) }),
    env,
  );

/** Runs register → authorize → token; returns the token response JSON. */
async function oauthFlow(env, scope) {
  const reg = await worker.fetch(
    new Request(`${HOST}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ redirect_uris: [REDIRECT], client_name: "t" }),
    }),
    env,
  );
  assert.equal(reg.status, 201);
  const { client_id } = await reg.json();

  const verifier = "v".repeat(50);
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const auth = await form(
    "/authorize",
    { client_id, redirect_uri: REDIRECT, code_challenge: challenge, state: "s", scope, token: TOKEN },
    env,
  );
  assert.equal(auth.status, 302);
  const code = new URL(auth.headers.get("location")).searchParams.get("code");

  const tok = await form(
    "/token",
    { grant_type: "authorization_code", code, redirect_uri: REDIRECT, client_id, code_verifier: verifier },
    env,
  );
  assert.equal(tok.status, 200);
  return { client_id, ...(await tok.json()) };
}

test("OAuth: metadata, PKCE flow, refresh rotation, revoke", async () => {
  const env = { OAUTH_KV: new FakeKV() };
  const meta = await worker.fetch(new Request(`${HOST}/.well-known/oauth-authorization-server`), env);
  assert.equal((await meta.json()).token_endpoint, `${HOST}/token`);

  const t = await oauthFlow(env, "gsc:full");
  const list = await mcp(env, t.access_token, rpc(1, "tools/list"));
  assert.equal((await list.json()).result.tools.length, 13);

  const ref = await form(
    "/token",
    { grant_type: "refresh_token", refresh_token: t.refresh_token, client_id: t.client_id },
    env,
  );
  assert.equal(ref.status, 200);
  const replay = await form(
    "/token",
    { grant_type: "refresh_token", refresh_token: t.refresh_token, client_id: t.client_id },
    env,
  );
  assert.equal(replay.status, 400);

  await form("/revoke", { token: t.access_token }, env);
  assert.equal((await mcp(env, t.access_token, rpc(2, "tools/list"))).status, 401);
});

test("OAuth: wrong PKCE verifier and wrong login token are rejected", async () => {
  const env = { OAUTH_KV: new FakeKV() };
  const reg = await worker.fetch(
    new Request(`${HOST}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ redirect_uris: [REDIRECT] }),
    }),
    env,
  );
  const { client_id } = await reg.json();
  const base = { client_id, redirect_uri: REDIRECT, code_challenge: "x", state: "", scope: "gsc:full" };
  assert.equal((await form("/authorize", { ...base, token: "nope" }, env)).status, 401);

  const auth = await form("/authorize", { ...base, token: TOKEN }, env);
  const code = new URL(auth.headers.get("location")).searchParams.get("code");
  const bad = await form(
    "/token",
    { grant_type: "authorization_code", code, redirect_uri: REDIRECT, client_id, code_verifier: "wrong" },
    env,
  );
  assert.equal(bad.status, 400);
});

test("OAuth routes 503 without OAUTH_KV; /mcp 401 advertises metadata only with KV", async () => {
  assert.equal((await form("/token", {}, {})).status, 503);
  const without = await mcp({}, "bad", rpc(1, "tools/list"));
  assert.equal(without.headers.get("www-authenticate"), "Bearer");
  const withKv = await mcp({ OAUTH_KV: new FakeKV() }, "bad", rpc(1, "tools/list"));
  assert.match(withKv.headers.get("www-authenticate"), /resource_metadata=/);
});

test("gsc:read scope hides write tools", async () => {
  const env = { OAUTH_KV: new FakeKV() };
  const t = await oauthFlow(env, "gsc:read");
  const res = await mcp(env, t.access_token, rpc(1, "tools/list"));
  const names = (await res.json()).result.tools.map((x) => x.name);
  assert.ok(names.includes("sites_list"));
  assert.ok(!names.includes("sites_delete"));
  assert.ok(!names.includes("indexing_batch_publish"));
});

test("rate limits: /mcp per IP, stricter for write and batch tools", async () => {
  const seen = [];
  const limiter = (allow) => ({
    limit: async ({ key }) => (seen.push(key), { success: allow(key) }),
  });
  const env = {
    MCP_RATE_LIMITER: limiter((k) => !k.endsWith("9.9.9.9")),
    TOOL_RATE_LIMITER: limiter(() => false),
  };
  assert.equal((await mcp(env, TOKEN, rpc(1, "tools/list"), "9.9.9.9")).status, 429);
  assert.equal((await mcp(env, TOKEN, rpc(1, "tools/list"))).status, 200);

  const write = await mcp(env, TOKEN, rpc(2, "tools/call", { name: "sites_delete", arguments: {} }));
  assert.equal(write.status, 429);
  const batch = await mcp(env, TOKEN, JSON.stringify([
    { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "indexing_batch_publish" } },
  ]));
  assert.equal(batch.status, 429);
  // read tools never touch the tool limiter
  const before = seen.filter((k) => k.startsWith("tool:")).length;
  await mcp(env, TOKEN, rpc(4, "tools/call", { name: "sites_list", arguments: {} }));
  assert.equal(seen.filter((k) => k.startsWith("tool:")).length, before);
});

test("audit log records each tools/call without arguments", async (t) => {
  const logs = t.mock.method(console, "log", () => {});
  await mcp({}, TOKEN, rpc(1, "tools/call", { name: "sites_list", arguments: { secret: "x" } }));
  const line = logs.mock.calls.map((c) => c.arguments[0]).find((l) => l.includes("tools/call"));
  const entry = JSON.parse(line);
  assert.equal(entry.tool, "sites_list");
  assert.equal(entry.client, "static");
  assert.ok(!line.includes("secret"));
});
