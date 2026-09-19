import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test, { before } from "node:test";

const TOKEN = "t".repeat(48);
process.env.MCP_AUTH_TOKEN = TOKEN;
delete process.env.MCP_ALLOWED_ORIGINS;

let worker;
before(async () => {
  worker = (await import("../dist/worker.js")).default;
});

const MCP_HEADERS = {
  "Content-Type": "application/json",
  Accept: "application/json, text/event-stream",
};

function call(path, { method = "POST", headers = {}, body, token = TOKEN } = {}) {
  return worker.fetch(
    new Request(`https://gsc.example${path}`, {
      method,
      headers: {
        ...MCP_HEADERS,
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...headers,
      },
      body: method === "GET" ? undefined : (body ?? "{}"),
    }),
  );
}

const rpc = (id, method, params) =>
  JSON.stringify({ jsonrpc: "2.0", id, method, params });

test("/health is open and reveals nothing", async () => {
  const res = await call("/health", { method: "GET", token: null });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true });
});

test("unknown paths return 404", async () => {
  assert.equal((await call("/other")).status, 404);
});

test("missing or wrong token returns 401", async () => {
  const none = await call("/mcp", { token: null });
  assert.equal(none.status, 401);
  assert.equal(none.headers.get("www-authenticate"), "Bearer");
  assert.equal((await call("/mcp", { token: "x".repeat(48) })).status, 401);
  assert.equal((await call("/mcp", { token: TOKEN.slice(0, -1) })).status, 401);
});

test("fails closed when MCP_AUTH_TOKEN is unset or short", async () => {
  process.env.MCP_AUTH_TOKEN = "";
  assert.equal((await call("/mcp", { token: "" })).status, 503);
  process.env.MCP_AUTH_TOKEN = "short";
  assert.equal((await call("/mcp", { token: "short" })).status, 503);
  process.env.MCP_AUTH_TOKEN = TOKEN;
});

test("rejects browser Origins that are not allowed", async () => {
  const res = await call("/mcp", {
    headers: { Origin: "https://evil.example" },
    body: rpc(1, "tools/list"),
  });
  assert.equal(res.status, 403);

  process.env.MCP_ALLOWED_ORIGINS = "https://ok.example";
  const ok = await call("/mcp", {
    headers: { Origin: "https://ok.example" },
    body: rpc(1, "tools/list"),
  });
  assert.equal(ok.status, 200);
  delete process.env.MCP_ALLOWED_ORIGINS;
});

test("only POST is accepted", async () => {
  const res = await call("/mcp", { method: "GET" });
  assert.equal(res.status, 405);
  assert.equal(res.headers.get("allow"), "POST");
});

test("rejects oversized and malformed bodies", async () => {
  const big = await call("/mcp", { body: "x".repeat(1_048_577) });
  assert.equal(big.status, 413);
  assert.equal((await call("/mcp", { body: "{not json" })).status, 400);
});

test("authorized client can initialize and list all tools", async () => {
  const init = await call("/mcp", {
    body: rpc(1, "initialize", {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "test", version: "0" },
    }),
  });
  assert.equal(init.status, 200);
  assert.equal((await init.json()).result.serverInfo.name, "gsc-mcp");

  const list = await call("/mcp", { body: rpc(2, "tools/list") });
  const { tools } = (await list.json()).result;
  assert.equal(tools.length, 13);
  assert.equal(
    tools.find((t) => t.name === "sites_delete").annotations.destructiveHint,
    true,
  );
});

// ── service account JWT (WebCrypto) ──

test("service account assertion is a valid RS256 JWT", async () => {
  const { buildServiceAccountAssertion } = await import("../dist/auth.js");
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const pem = privateKey.export({ type: "pkcs8", format: "pem" });
  const jwt = await buildServiceAccountAssertion(
    { client_email: "sa@proj.iam.gserviceaccount.com", private_key: pem },
    ["scope-a", "scope-b"],
    1_700_000_000,
  );

  const [h, c, s] = jwt.split(".");
  const dec = (v) => JSON.parse(Buffer.from(v, "base64url").toString());
  assert.deepEqual(dec(h), { alg: "RS256", typ: "JWT" });
  assert.deepEqual(dec(c), {
    iss: "sa@proj.iam.gserviceaccount.com",
    scope: "scope-a scope-b",
    aud: "https://oauth2.googleapis.com/token",
    iat: 1_700_000_000,
    exp: 1_700_003_600,
  });

  const { verify } = await import("node:crypto");
  assert.ok(
    verify("RSA-SHA256", Buffer.from(`${h}.${c}`), publicKey, Buffer.from(s, "base64url")),
  );
});
