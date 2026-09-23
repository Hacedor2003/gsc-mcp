# Guía de despliegue en Cloudflare Workers

Esta guía publica gsc-mcp como servidor MCP remoto. Los clientes IA se conectan por HTTPS
(Streamable HTTP, modo stateless) en lugar de lanzar un proceso local por stdio.

## 1. Requisitos

- Cuenta de Cloudflare (el plan gratuito basta para empezar).
- Node.js 20 o superior y `npm install` ejecutado en el repo.
- Credenciales de Google con acceso a Search Console (paso 3).
- `openssl` para generar el token.

## 2. Cómo funciona

```
Cliente IA ──HTTPS + Bearer──▶ Worker (/mcp) ──OAuth/JWT──▶ APIs de Google
```

- `src/worker.ts` valida el token, el `Origin` y el tamaño del body, y crea un servidor MCP nuevo por petición.
- `src/auth.ts` obtiene el token de Google (service account con WebCrypto, o refresh token OAuth).
- `src/server.ts` define las 13 tools, igual que en modo stdio.
- `wrangler.jsonc` activa `nodejs_compat`, que expone variables y secrets en `process.env`.

## 3. Credenciales de Google

Elige una opción.

**Service account (recomendada para servidores)**

1. En Google Cloud Console crea un service account y descarga su clave JSON.
2. Activa las APIs *Search Console API* y *Web Search Indexing API* en el proyecto.
3. En Search Console, añade el `client_email` del service account como usuario de cada propiedad
   (permiso *Propietario* si necesitas el Indexing API o borrar sitios).

**OAuth refresh token**

Crea un cliente OAuth y obtén un refresh token con los scopes
`https://www.googleapis.com/auth/webmasters` y `https://www.googleapis.com/auth/indexing`
(ver la sección *Setup Guide* del README).

## 4. Desplegar

```bash
npm install
npx wrangler login

# Token de acceso para los clientes (mínimo 32 caracteres)
openssl rand -hex 32
npx wrangler secret put MCP_AUTH_TOKEN

# Credenciales de Google: una de las dos
npx wrangler secret put GSC_SERVICE_ACCOUNT_JSON     # pega el JSON completo de la clave
# o bien tres secrets:
npx wrangler secret put GSC_CLIENT_ID
npx wrangler secret put GSC_CLIENT_SECRET
npx wrangler secret put GSC_REFRESH_TOKEN

npm run worker:deploy
```

Wrangler imprime la URL. El endpoint MCP es:

```
https://gsc-mcp.<tu-subdominio>.workers.dev/mcp
```

Guarda el token en un gestor de contraseñas: Cloudflare no lo vuelve a mostrar.

## 5. Variables opcionales

Se definen en `wrangler.jsonc` (`vars`) o en el dashboard. No son secretos.

| Variable | Efecto |
| --- | --- |
| `GSC_ALLOWED_SITES` | Lista separada por comas de propiedades o prefijos de URL permitidos, por ejemplo `sc-domain:example.com,https://blog.example.com/posts/`. Todo lo demás se rechaza antes de llamar a Google. |
| `GSC_READ_ONLY` | `1` registra solo las 6 tools de lectura y pide solo el scope `webmasters.readonly`. |
| `MCP_ALLOWED_ORIGINS` | Orígenes de navegador permitidos. Vacío rechaza cualquier petición con `Origin`. |

Ejemplo:

```jsonc
"vars": { "GSC_ALLOWED_SITES": "sc-domain:example.com" }
```

## 6. Conectar clientes

**Claude Code**

```bash
claude mcp add --transport http gsc https://gsc-mcp.<tu-subdominio>.workers.dev/mcp \
  --header "Authorization: Bearer <MCP_AUTH_TOKEN>"
```

**Clientes sin soporte HTTP remoto** (por ejemplo algunos IDE): usa
[`mcp-remote`](https://www.npmjs.com/package/mcp-remote) con la misma URL y el mismo header.

**No soportado:** el conector web personalizado de claude.ai, porque exige OAuth 2.1 y este servidor usa un bearer estático.

## 7. Verificar

```bash
URL=https://gsc-mcp.<tu-subdominio>.workers.dev
TOKEN=<MCP_AUTH_TOKEN>
H='-H Content-Type:application/json -H Accept:application/json,text/event-stream'

curl -s $URL/health                                                   # {"ok":true}
curl -s -o /dev/null -w '%{http_code}\n' -X POST $URL/mcp $H -d '{}'  # 401 sin token
curl -s -X POST $URL/mcp $H -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'                 # lista de 13 tools
```

También puedes usar el MCP Inspector: `npx @modelcontextprotocol/inspector`.

## 8. Desarrollo local

```bash
cp .dev.vars.example .dev.vars    # rellena los valores; el archivo está en .gitignore
npm run worker:dev                # http://localhost:8787/mcp
npm run worker:check              # compila el bundle sin desplegar
npm test                          # 24 tests
```

## 9. Operación

**Rotar el token**

```bash
openssl rand -hex 32
npx wrangler secret put MCP_AUTH_TOKEN
```

Actualiza después el header en cada cliente. El token anterior deja de valer de inmediato.

**Ver logs:** `npx wrangler tail` (los logs no incluyen tokens ni cuerpos de petición).

**Revocar todo acceso:** `npx wrangler delete`, o borra el secret `MCP_AUTH_TOKEN`. Sin token el Worker responde 503 y no sirve nada.

## 10. Seguridad

- El Worker guarda credenciales de Google con **permisos de escritura**. Quien tenga el token puede borrar propiedades y sitemaps y enviar notificaciones de indexación.
- Mitigaciones incluidas: fail-closed sin token, comparación en tiempo constante, límite de body de 1 MB, control de `Origin`, validación de entradas, marcador de datos no confiables en las respuestas y annotations `destructiveHint`.
- Recomendado: define `GSC_ALLOWED_SITES`, y crea una regla de rate limiting de Cloudflare (WAF) sobre `/mcp` para frenar intentos de adivinar el token.
- Las respuestas de Search Console incluyen datos de terceros (queries, URLs). El cliente debe tratarlas como datos, no como instrucciones.
- Nunca subas `.dev.vars` ni pegues secrets en el repo o en `wrangler.jsonc`.

## 11. Problemas frecuentes

| Síntoma | Causa y solución |
| --- | --- |
| `503 Server misconfigured` | Falta `MCP_AUTH_TOKEN` o mide menos de 32 caracteres. Ejecuta `wrangler secret put MCP_AUTH_TOKEN`. |
| `401 Unauthorized` | Token incorrecto o header mal formado. Debe ser `Authorization: Bearer <token>`. |
| `403 Origin not allowed` | Petición desde navegador. Añade el origen a `MCP_ALLOWED_ORIGINS`. |
| `405 Method not allowed` | Solo se acepta POST. Usa transporte HTTP en el cliente, no SSE ni GET. |
| `413 Request body too large` | El body supera 1 MB. |
| `Error: Missing credentials…` en una tool | Falta el secret de Google. Define `GSC_SERVICE_ACCOUNT_JSON` o los tres secrets OAuth. |
| `Token refresh failed (400): invalid_grant` | Refresh token revocado o de otro cliente OAuth. Genera uno nuevo. |
| Google devuelve 403 en una propiedad | El service account no es usuario de esa propiedad en Search Console. |
| `Not in GSC_ALLOWED_SITES` | La propiedad o URL queda fuera de la lista permitida. |

## 12. CI

`.github/workflows/deploy.yml` corre en cada push a `main` (y manualmente con
`workflow_dispatch`): `npm ci`, build, tests, `worker:check` (dry-run) y solo si
todo pasa, `wrangler deploy`. Requiere el secret de repo `CLOUDFLARE_API_TOKEN`
(Workers → *Edit Cloudflare Workers* en el dashboard).

## 13. Límites conocidos

- Sin OAuth 2.1 (conectores web de claude.ai) y con un único token para todos los clientes.
- Modo stateless: sin notificaciones iniciadas por el servidor ni suscripciones a resources.

Estos puntos están en `todo.md`.
