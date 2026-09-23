import { OAuthClientMetadataSchema } from "@modelcontextprotocol/sdk/shared/auth.js";

// Minimal OAuth 2.1 authorization server (RFC 6749 + PKCE + RFC 7591 dynamic
// client registration) so claude.ai's web connector (and other OAuth-only MCP
// clients) can connect. It fronts the same single account this server already
// represents: /authorize asks for the existing MCP_AUTH_TOKEN as the login
// credential, then issues per-client opaque tokens. Public clients only (no
// client_secret): PKCE (S256) is required instead, per OAuth 2.1 guidance for
// browser/native clients using dynamic registration.

const CODE_TTL_SECONDS = 300;
const ACCESS_TOKEN_TTL_SECONDS = 3600;
const REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 90;
const SCOPES = ["gsc:full", "gsc:read"] as const;
type Scope = (typeof SCOPES)[number];

export interface KV {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

interface StoredClient {
  client_id: string;
  redirect_uris: string[];
  client_name?: string;
  client_id_issued_at: number;
}

interface StoredCode {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scope: Scope;
  exp: number;
}

export interface StoredToken {
  clientId: string;
  scope: Scope;
}

function randomToken(bytes = 32): string {
  return [...crypto.getRandomValues(new Uint8Array(bytes))]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256Base64Url(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  let binary = "";
  for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function secretsEqual(a: string, b: string): Promise<boolean> {
  const enc = new TextEncoder();
  const [da, db] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  const [ba, bb] = [new Uint8Array(da), new Uint8Array(db)];
  let diff = 0;
  for (let i = 0; i < ba.length; i++) diff |= ba[i] ^ bb[i];
  return diff === 0;
}

function json(status: number, body: unknown, headers: HeadersInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

function oauthError(status: number, error: string, error_description?: string): Response {
  return json(status, { error, ...(error_description ? { error_description } : {}) });
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

function isValidScope(scope: string): scope is Scope {
  return (SCOPES as readonly string[]).includes(scope);
}

async function getClient(kv: KV, clientId: string): Promise<StoredClient | null> {
  const raw = await kv.get(`client:${clientId}`);
  return raw ? (JSON.parse(raw) as StoredClient) : null;
}

// ── Discovery metadata ──

export function authorizationServerMetadata(issuer: string) {
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    registration_endpoint: `${issuer}/register`,
    revocation_endpoint: `${issuer}/revoke`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: [...SCOPES],
  };
}

export function protectedResourceMetadata(issuer: string) {
  return {
    resource: `${issuer}/mcp`,
    authorization_servers: [issuer],
    scopes_supported: [...SCOPES],
    bearer_methods_supported: ["header"],
  };
}

// ── Dynamic client registration (RFC 7591) ──

export async function handleRegister(request: Request, kv: KV): Promise<Response> {
  let raw: unknown;
  try {
    raw = await request.json();
  } catch {
    return oauthError(400, "invalid_client_metadata", "Body must be JSON");
  }
  const parsed = OAuthClientMetadataSchema.safeParse(raw);
  if (!parsed.success) {
    return oauthError(400, "invalid_client_metadata", parsed.error.issues[0]?.message);
  }
  const metadata = parsed.data;
  if (metadata.redirect_uris.length === 0) {
    return oauthError(400, "invalid_redirect_uri", "At least one redirect_uri is required");
  }
  for (const uri of metadata.redirect_uris) {
    const isLoopback = /^https?:\/\/(127\.0\.0\.1|\[::1\]|localhost)(:\d+)?(\/|$)/.test(uri);
    if (!uri.startsWith("https://") && !isLoopback) {
      return oauthError(400, "invalid_redirect_uri", "redirect_uris must be https:// (loopback http is allowed)");
    }
  }

  const client_id = randomToken(16);
  const client_id_issued_at = Math.floor(Date.now() / 1000);
  const client: StoredClient = {
    client_id,
    redirect_uris: metadata.redirect_uris,
    client_name: metadata.client_name,
    client_id_issued_at,
  };
  await kv.put(`client:${client_id}`, JSON.stringify(client));

  return json(201, {
    ...metadata,
    client_id,
    client_id_issued_at,
    token_endpoint_auth_method: "none",
    grant_types: metadata.grant_types ?? ["authorization_code", "refresh_token"],
    response_types: metadata.response_types ?? ["code"],
  });
}

// ── Authorization endpoint ──

function redirectWithError(
  redirectUri: string,
  state: string | null,
  error: string,
  error_description?: string,
): Response {
  const url = new URL(redirectUri);
  url.searchParams.set("error", error);
  if (error_description) url.searchParams.set("error_description", error_description);
  if (state) url.searchParams.set("state", state);
  return Response.redirect(url.toString(), 302);
}

function renderConsentForm(opts: {
  clientId: string;
  clientName?: string;
  redirectUri: string;
  codeChallenge: string;
  state: string;
  scope: Scope;
  error?: string;
}): string {
  const name = opts.clientName ? escapeHtml(opts.clientName) : opts.clientId;
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>gsc-mcp authorization</title>
<style>body{font:16px system-ui;max-width:28rem;margin:3rem auto;padding:0 1rem}
input{width:100%;padding:.5rem;margin:.5rem 0;box-sizing:border-box}
button{padding:.5rem 1rem}.err{color:#b00}</style></head>
<body>
<h1>Authorize ${name}</h1>
<p>Grants scope <code>${escapeHtml(opts.scope)}</code> on this Search Console MCP server.</p>
${opts.error ? `<p class="err">${escapeHtml(opts.error)}</p>` : ""}
<form method="POST" action="/authorize">
<input type="hidden" name="client_id" value="${escapeHtml(opts.clientId)}">
<input type="hidden" name="redirect_uri" value="${escapeHtml(opts.redirectUri)}">
<input type="hidden" name="code_challenge" value="${escapeHtml(opts.codeChallenge)}">
<input type="hidden" name="state" value="${escapeHtml(opts.state)}">
<input type="hidden" name="scope" value="${escapeHtml(opts.scope)}">
<label>Server token (MCP_AUTH_TOKEN)<input type="password" name="token" autofocus required></label>
<button type="submit">Authorize</button>
</form>
</body></html>`;
}

export async function handleAuthorizeGet(url: URL, kv: KV): Promise<Response> {
  const clientId = url.searchParams.get("client_id") || "";
  const redirectUri = url.searchParams.get("redirect_uri") || "";
  const codeChallenge = url.searchParams.get("code_challenge") || "";
  const codeChallengeMethod = url.searchParams.get("code_challenge_method") || "";
  const state = url.searchParams.get("state") || "";
  const scope = url.searchParams.get("scope") || "gsc:full";
  const responseType = url.searchParams.get("response_type") || "";

  const client = await getClient(kv, clientId);
  if (!client) return oauthError(400, "invalid_request", "Unknown client_id");
  if (!client.redirect_uris.includes(redirectUri)) {
    return oauthError(400, "invalid_request", "redirect_uri not registered for this client");
  }
  if (responseType !== "code") {
    return redirectWithError(redirectUri, state, "unsupported_response_type");
  }
  if (codeChallengeMethod !== "S256" || !codeChallenge) {
    return redirectWithError(redirectUri, state, "invalid_request", "PKCE (S256) code_challenge is required");
  }
  if (!isValidScope(scope)) {
    return redirectWithError(redirectUri, state, "invalid_scope");
  }

  return new Response(
    renderConsentForm({ clientId, clientName: client.client_name, redirectUri, codeChallenge, state, scope }),
    { headers: { "Content-Type": "text/html; charset=utf-8" } },
  );
}

export async function handleAuthorizePost(
  request: Request,
  kv: KV,
  expectedToken: string,
): Promise<Response> {
  const form = await request.formData();
  const clientId = String(form.get("client_id") || "");
  const redirectUri = String(form.get("redirect_uri") || "");
  const codeChallenge = String(form.get("code_challenge") || "");
  const state = String(form.get("state") || "");
  const scope = String(form.get("scope") || "gsc:full");
  const token = String(form.get("token") || "");

  const client = await getClient(kv, clientId);
  if (!client || !client.redirect_uris.includes(redirectUri) || !isValidScope(scope)) {
    return oauthError(400, "invalid_request", "Malformed authorization request");
  }

  if (!expectedToken || !(await secretsEqual(token, expectedToken))) {
    return new Response(
      renderConsentForm({
        clientId,
        clientName: client.client_name,
        redirectUri,
        codeChallenge,
        state,
        scope,
        error: "Invalid token.",
      }),
      { status: 401, headers: { "Content-Type": "text/html; charset=utf-8" } },
    );
  }

  const code = randomToken(24);
  const stored: StoredCode = {
    clientId,
    redirectUri,
    codeChallenge,
    scope,
    exp: Date.now() + CODE_TTL_SECONDS * 1000,
  };
  await kv.put(`code:${code}`, JSON.stringify(stored), { expirationTtl: CODE_TTL_SECONDS });

  const dest = new URL(redirectUri);
  dest.searchParams.set("code", code);
  if (state) dest.searchParams.set("state", state);
  return Response.redirect(dest.toString(), 302);
}

// ── Token endpoint ──

async function issueTokens(kv: KV, clientId: string, scope: Scope) {
  const access_token = randomToken(32);
  const refresh_token = randomToken(32);
  const stored: StoredToken = { clientId, scope };
  await kv.put(`token:${access_token}`, JSON.stringify(stored), {
    expirationTtl: ACCESS_TOKEN_TTL_SECONDS,
  });
  await kv.put(`refresh:${refresh_token}`, JSON.stringify(stored), {
    expirationTtl: REFRESH_TOKEN_TTL_SECONDS,
  });
  return json(200, {
    access_token,
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_TTL_SECONDS,
    refresh_token,
    scope,
  });
}

export async function handleToken(request: Request, kv: KV): Promise<Response> {
  let form: FormData;
  try {
    form = await request.formData();
  } catch {
    return oauthError(400, "invalid_request", "Body must be application/x-www-form-urlencoded");
  }
  const grantType = String(form.get("grant_type") || "");

  if (grantType === "authorization_code") {
    const code = String(form.get("code") || "");
    const redirectUri = String(form.get("redirect_uri") || "");
    const clientId = String(form.get("client_id") || "");
    const codeVerifier = String(form.get("code_verifier") || "");

    const raw = await kv.get(`code:${code}`);
    if (!raw) return oauthError(400, "invalid_grant", "Unknown or expired code");
    await kv.delete(`code:${code}`); // one-time use

    const stored = JSON.parse(raw) as StoredCode;
    if (Date.now() > stored.exp) return oauthError(400, "invalid_grant", "Code expired");
    if (stored.clientId !== clientId || stored.redirectUri !== redirectUri) {
      return oauthError(400, "invalid_grant", "client_id/redirect_uri mismatch");
    }
    if (!codeVerifier || (await sha256Base64Url(codeVerifier)) !== stored.codeChallenge) {
      return oauthError(400, "invalid_grant", "PKCE verification failed");
    }

    return issueTokens(kv, stored.clientId, stored.scope);
  }

  if (grantType === "refresh_token") {
    const refreshToken = String(form.get("refresh_token") || "");
    const clientId = String(form.get("client_id") || "");

    const raw = await kv.get(`refresh:${refreshToken}`);
    if (!raw) return oauthError(400, "invalid_grant", "Unknown or expired refresh_token");
    const stored = JSON.parse(raw) as StoredToken;
    if (clientId && stored.clientId !== clientId) {
      return oauthError(400, "invalid_grant", "client_id mismatch");
    }
    await kv.delete(`refresh:${refreshToken}`); // rotate

    return issueTokens(kv, stored.clientId, stored.scope);
  }

  return oauthError(400, "unsupported_grant_type", grantType || "grant_type is required");
}

export async function handleRevoke(request: Request, kv: KV): Promise<Response> {
  const form = await request.formData();
  const token = String(form.get("token") || "");
  if (token) {
    await kv.delete(`token:${token}`);
    await kv.delete(`refresh:${token}`);
  }
  return new Response(null, { status: 200 });
}

/** Looks up a bearer token minted by /token. Returns null if absent/expired. */
export async function getAccessTokenInfo(kv: KV, token: string): Promise<StoredToken | null> {
  const raw = await kv.get(`token:${token}`);
  return raw ? (JSON.parse(raw) as StoredToken) : null;
}
