import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { buildServer } from "./server.js";

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

async function handle(request: Request): Promise<Response> {
  const url = new URL(request.url);

  if (url.pathname === "/health") {
    return json(200, { ok: true });
  }
  if (url.pathname !== MCP_PATH) {
    return json(404, { error: "Not found" });
  }

  // Fail closed: never serve tools without a configured, strong token.
  const expected = process.env.MCP_AUTH_TOKEN || "";
  if (expected.length < MIN_TOKEN_LENGTH) {
    return json(503, {
      error: `Server misconfigured: MCP_AUTH_TOKEN must be set (min ${MIN_TOKEN_LENGTH} chars)`,
    });
  }

  const authorization = request.headers.get("authorization") || "";
  const match = /^Bearer\s+(\S+)$/i.exec(authorization);
  if (!match || !(await secretsEqual(match[1], expected))) {
    return json(401, { error: "Unauthorized" }, { "WWW-Authenticate": "Bearer" });
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

  const server = buildServer(false);
  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });
  await server.connect(transport);
  return transport.handleRequest(request, { parsedBody });
}

export default {
  async fetch(request: Request): Promise<Response> {
    try {
      return await handle(request);
    } catch {
      // Never leak internals (or secrets) to the caller.
      return json(500, { error: "Internal error" });
    }
  },
};
