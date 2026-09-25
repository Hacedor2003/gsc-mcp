import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { buildServer } from "./server.js";
import {
  authorizationServerMetadata,
  getAccessTokenInfo,
  handleAuthorizeGet,
  handleAuthorizePost,
  handleRegister,
  handleRevoke,
  handleToken,
  protectedResourceMetadata,
  type KV,
} from "./oauth.js";
import { NON_READ_ONLY_TOOLS } from "./security.js";

interface Limiter {
  limit(opts: { key: string }): Promise<{ success: boolean }>;
}

export interface Env {
  OAUTH_KV?: KV;
  MCP_RATE_LIMITER?: Limiter;
  TOOL_RATE_LIMITER?: Limiter;
}

const MCP_PATH = "/mcp";
const MAX_BODY_BYTES = 1_048_576;
const MIN_TOKEN_LENGTH = 32;

function json(status: number, body: unknown, headers: HeadersInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

async function sha256(value: string): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
  );
}

/** Constant-time comparison of two secrets (compares fixed-length digests). */
async function secretsEqual(a: string, b: string): Promise<boolean> {
  const [da, db] = await Promise.all([sha256(a), sha256(b)]);
  let diff = 0;
  for (let i = 0; i < da.length; i++) diff |= da[i] ^ db[i];
  return diff === 0;
}

function allowedOrigins(): string[] {
  return (process.env.MCP_ALLOWED_ORIGINS || "")
    .split(/[\s,]+/)
    .filter(Boolean);
}

/** Read the request body, refusing anything above MAX_BODY_BYTES. */
async function readLimitedBody(request: Request): Promise<string | null> {
  const declared = Number(request.headers.get("content-length") || 0);
  if (declared > MAX_BODY_BYTES) return null;
  if (!request.body) return "";

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(merged);
}

/** Limiter bindings are optional (they need a paid plan): no binding = no limit. */
async function limited(limiter: Limiter | undefined, key: string): Promise<boolean> {
  return limiter ? !(await limiter.limit({ key })).success : false;
}

const tooMany = () => json(429, { error: "Too many requests" }, { "Retry-After": "60" });

/** Tool names in a JSON-RPC body (single message or batch) that are `tools/call`. */
function calledTools(body: unknown): string[] {
  const messages = Array.isArray(body) ? body : [body];
  return messages.flatMap((m) => {
    const msg = m as { method?: unknown; params?: { name?: unknown } } | null;
    return msg?.method === "tools/call" && typeof msg.params?.name === "string"
      ? [msg.params.name]
      : [];
  });
}

async function handle(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const kv = env.OAUTH_KV;

  if (path === "/health") {
    return json(200, { ok: true });
  }

  // Discovery metadata is public and cheap.
  if (kv && path === "/.well-known/oauth-authorization-server") {
    return json(200, authorizationServerMetadata(url.origin));
  }
  if (kv && path.startsWith("/.well-known/oauth-protected-resource")) {
    return json(200, protectedResourceMetadata(url.origin));
  }

  const isOAuthRoute = ["/register", "/authorize", "/token", "/revoke"].includes(path);
  if (!isOAuthRoute && path !== MCP_PATH) {
    return json(404, { error: "Not found" });
  }

  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  if (await limited(env.MCP_RATE_LIMITER, `${path === MCP_PATH ? "mcp" : "oauth"}:${ip}`)) {
    return tooMany();
  }

  // Fail closed: never serve tools without a configured, strong token.
  const expected = process.env.MCP_AUTH_TOKEN || "";
  if (expected.length < MIN_TOKEN_LENGTH) {
    return json(503, {
      error: `Server misconfigured: MCP_AUTH_TOKEN must be set (min ${MIN_TOKEN_LENGTH} chars)`,
    });
  }

  if (isOAuthRoute) {
    if (!kv) return json(503, { error: "OAuth not configured: OAUTH_KV binding missing" });
    if (path === "/authorize") {
      if (request.method === "GET") return handleAuthorizeGet(url, kv);
      if (request.method === "POST") return handleAuthorizePost(request, kv, expected);
      return json(405, { error: "Method not allowed" }, { Allow: "GET, POST" });
    }
    if (request.method !== "POST") {
      return json(405, { error: "Method not allowed" }, { Allow: "POST" });
    }
    if (path === "/register") return handleRegister(request, kv);
    if (path === "/token") return handleToken(request, kv);
    return handleRevoke(request, kv);
  }

  const authorization = request.headers.get("authorization") || "";
  const match = /^Bearer\s+(\S+)$/i.exec(authorization);
  let client = "static";
  let readOnly: boolean | undefined; // undefined = GSC_READ_ONLY default
  if (match && (await secretsEqual(match[1], expected))) {
    // static bearer: full access unless GSC_READ_ONLY
  } else {
    const info = match && kv ? await getAccessTokenInfo(kv, match[1]) : null;
    if (!info) {
      return json(
        401,
        { error: "Unauthorized" },
        {
          "WWW-Authenticate": kv
            ? `Bearer resource_metadata="${url.origin}/.well-known/oauth-protected-resource"`
            : "Bearer",
        },
      );
    }
    client = info.clientId;
    readOnly = info.scope === "gsc:read" ? true : undefined;
  }

  // DNS-rebinding / CSRF guard: browsers send Origin, MCP clients normally do not.
  const origin = request.headers.get("origin");
  if (origin !== null && !allowedOrigins().includes(origin)) {
    return json(403, { error: "Origin not allowed" });
  }

  // Stateless mode: no sessions, so only POST is meaningful.
  if (request.method !== "POST") {
    return json(405, { error: "Method not allowed" }, { Allow: "POST" });
  }

  const text = await readLimitedBody(request);
  if (text === null) return json(413, { error: "Request body too large" });

  let parsedBody: unknown;
  try {
    parsedBody = JSON.parse(text);
  } catch {
    return json(400, { error: "Invalid JSON body" });
  }

  const tools = calledTools(parsedBody);
  for (const tool of tools) {
    // Audit: who called what. Never log arguments (may hold URLs/queries).
    console.log(JSON.stringify({ event: "tools/call", tool, client, ip }));
  }
  if (
    tools.some((t) => NON_READ_ONLY_TOOLS.has(t)) &&
    (await limited(env.TOOL_RATE_LIMITER, `tool:${client}:${ip}`))
  ) {
    return tooMany();
  }

  const server = buildServer(false, readOnly);
  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });
  await server.connect(transport);
  return transport.handleRequest(request, { parsedBody });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await handle(request, env ?? {});
    } catch {
      // Never leak internals (or secrets) to the caller.
      return json(500, { error: "Internal error" });
    }
  },
};
