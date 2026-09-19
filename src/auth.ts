import { truncateError } from "./security.js";

export const HTTP_TIMEOUT_MS = 30_000;
const TOKEN_URL = "https://oauth2.googleapis.com/token";
const TOKEN_REFRESH_SKEW_MS = 60_000;

interface ServiceAccountKey {
  client_email: string;
  private_key: string;
}

let cached: { token: string; expiresAt: number } | null = null;

// ── Helpers ──

function base64url(input: string | Uint8Array): string {
  const bytes =
    typeof input === "string" ? new TextEncoder().encode(input) : input;
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function pemToDer(pem: string): ArrayBuffer {
  const body = pem
    .replace(/-----BEGIN [A-Z ]+-----/, "")
    .replace(/-----END [A-Z ]+-----/, "")
    .replace(/\s+/g, "");
  const binary = atob(body);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function parseServiceAccountKey(raw: string): ServiceAccountKey {
  let key: Partial<ServiceAccountKey>;
  try {
    key = JSON.parse(raw);
  } catch {
    throw new Error("Service account key is not valid JSON");
  }
  if (
    typeof key.client_email !== "string" ||
    typeof key.private_key !== "string"
  ) {
    throw new Error("Service account key needs client_email and private_key");
  }
  return { client_email: key.client_email, private_key: key.private_key };
}

/** Build the signed JWT (RS256) used in the service account token exchange. */
export async function buildServiceAccountAssertion(
  key: ServiceAccountKey,
  scopes: string[],
  nowSeconds = Math.floor(Date.now() / 1000),
): Promise<string> {
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claims = base64url(
    JSON.stringify({
      iss: key.client_email,
      scope: scopes.join(" "),
      aud: TOKEN_URL,
      iat: nowSeconds,
      exp: nowSeconds + 3600,
    }),
  );
  const signingInput = `${header}.${claims}`;
  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    pemToDer(key.private_key),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    cryptoKey,
    new TextEncoder().encode(signingInput),
  );
  return `${signingInput}.${base64url(new Uint8Array(signature))}`;
}

async function postToken(body: URLSearchParams, label: string) {
  const attempt = () =>
    fetch(TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
      signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
    });

  let res: Response;
  try {
    res = await attempt();
  } catch {
    // Retry once on transient network errors (e.g. keep-alive socket reuse).
    await new Promise((r) => setTimeout(r, 300));
    try {
      res = await attempt();
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      throw new Error(`${label} failed: ${truncateError(message)}`);
    }
  }

  if (!res.ok) {
    let detail = "";
    try {
      const err = JSON.parse(await res.text()) as { error?: string };
      detail = typeof err.error === "string" ? `: ${err.error}` : "";
    } catch {
      // ignore non-JSON error bodies
    }
    throw new Error(`${label} failed (${res.status})${detail}`);
  }

  const data = (await res.json()) as { access_token?: string; expires_in?: number };
  if (!data.access_token) throw new Error(`${label} returned no access token`);
  return {
    token: data.access_token,
    expiresAt: Date.now() + (data.expires_in ?? 3600) * 1000,
  };
}

async function loadServiceAccountKey(): Promise<ServiceAccountKey | null> {
  const json = process.env.GSC_SERVICE_ACCOUNT_JSON;
  if (json) return parseServiceAccountKey(json);

  const path = process.env.GSC_SERVICE_ACCOUNT_KEY_PATH;
  if (path) {
    // Node only: dynamic import keeps `fs` out of the Workers code path.
    const { readFile } = await import("node:fs/promises");
    return parseServiceAccountKey(await readFile(path, "utf8"));
  }
  return null;
}

// ── Public API ──

/**
 * Access token for the Google APIs. Sources, in order:
 * 1. GSC_SERVICE_ACCOUNT_JSON (service account key JSON, e.g. a Workers secret)
 * 2. GSC_SERVICE_ACCOUNT_KEY_PATH (service account key file, Node only)
 * 3. GSC_CLIENT_ID + GSC_CLIENT_SECRET + GSC_REFRESH_TOKEN (OAuth2)
 */
export async function getAccessToken(scopes: string[]): Promise<string> {
  if (cached && Date.now() < cached.expiresAt - TOKEN_REFRESH_SKEW_MS) {
    return cached.token;
  }

  const serviceAccount = await loadServiceAccountKey();
  if (serviceAccount) {
    const assertion = await buildServiceAccountAssertion(serviceAccount, scopes);
    cached = await postToken(
      new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion,
      }),
      "Service account token request",
    );
    return cached.token;
  }

  const clientId = process.env.GSC_CLIENT_ID;
  const clientSecret = process.env.GSC_CLIENT_SECRET;
  const refreshToken = process.env.GSC_REFRESH_TOKEN;
  if (!clientId || !clientSecret || !refreshToken) {
    throw new Error(
      "Missing credentials. Set GSC_SERVICE_ACCOUNT_KEY_PATH (or GSC_SERVICE_ACCOUNT_JSON) for service account auth, " +
        "or GSC_CLIENT_ID + GSC_CLIENT_SECRET + GSC_REFRESH_TOKEN for OAuth2.",
    );
  }

  cached = await postToken(
    new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      refresh_token: refreshToken,
      grant_type: "refresh_token",
    }),
    "Token refresh",
  );
  return cached.token;
}
