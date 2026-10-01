const BASE_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-robots-tag": "noindex, nofollow",
};

const MAX_BODY_BYTES = 32 * 1024;
const MAX_MESSAGES = 24;
const MAX_MESSAGE_CHARS = 8000;
const MAX_TOTAL_CHARS = 24000;
const SESSION_TTL_SECONDS = 15 * 60;

const json = (data, status = 200, extraHeaders = {}) =>
  new Response(JSON.stringify(data), { status, headers: { ...BASE_HEADERS, ...extraHeaders } });

const b64url = {
  encode(bytes) {
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/g, "");
  },
  decode(value) {
    const base64 = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (value.length % 4)) % 4);
    const s = atob(base64);
    return Uint8Array.from(s, (c) => c.charCodeAt(0));
  },
};

function allowedOrigins(env) {
  return new Set((env.PUBLIC_ALLOWED_ORIGINS || "").split(",").map((v) => v.trim()).filter(Boolean));
}

function corsHeaders(request, env) {
  const origin = request.headers.get("origin");
  if (!origin || !allowedOrigins(env).has(origin)) return null;
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "POST, OPTIONS",
    "access-control-allow-headers": "authorization, content-type",
    "access-control-max-age": "600",
    vary: "Origin",
  };
}

function validateMessages(value) {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_MESSAGES) {
    return { error: `messages must contain 1-${MAX_MESSAGES} items` };
  }
  let totalChars = 0;
  const messages = [];
  for (const item of value) {
    if (!item || typeof item !== "object") return { error: "Invalid message" };
    if (!["system", "user", "assistant"].includes(item.role)) return { error: "Invalid message role" };
    if (typeof item.content !== "string" || item.content.length === 0 || item.content.length > MAX_MESSAGE_CHARS) {
      return { error: `Each message must contain 1-${MAX_MESSAGE_CHARS} characters` };
    }
    totalChars += item.content.length;
    if (totalChars > MAX_TOTAL_CHARS) return { error: "Conversation is too large" };
    messages.push({ role: item.role, content: item.content });
  }
  return { messages };
}

async function readJson(request) {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.toLowerCase().startsWith("application/json")) return { response: json({ error: "Content-Type must be application/json" }, 415) };
  const declaredLength = Number(request.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_BYTES) return { response: json({ error: "Request body is too large" }, 413) };
  let raw;
  try { raw = await request.text(); } catch { return { response: json({ error: "Unable to read request body" }, 400) }; }
  if (new TextEncoder().encode(raw).byteLength > MAX_BODY_BYTES) return { response: json({ error: "Request body is too large" }, 413) };
  try { return { body: JSON.parse(raw) }; } catch { return { response: json({ error: "Invalid JSON" }, 400) }; }
}

async function hmacKey(secret) {
  return crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

async function issueSession(secret) {
  const payload = {
    sid: crypto.randomUUID(),
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
  };
  const encoded = b64url.encode(new TextEncoder().encode(JSON.stringify(payload)));
  const signature = await crypto.subtle.sign("HMAC", await hmacKey(secret), new TextEncoder().encode(encoded));
  return `${encoded}.${b64url.encode(new Uint8Array(signature))}`;
}

async function verifySession(secret, token) {
  if (!secret || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  try {
    const valid = await crypto.subtle.verify("HMAC", await hmacKey(secret), b64url.decode(parts[1]), new TextEncoder().encode(parts[0]));
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(b64url.decode(parts[0])));
    if (!payload.sid || !payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

async function verifyTurnstile(env, token, request) {
  if (!env.TURNSTILE_SECRET_KEY || typeof token !== "string" || token.length === 0 || token.length > 2048) return false;
  const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      secret: env.TURNSTILE_SECRET_KEY,
      response: token,
      remoteip: request.headers.get("cf-connecting-ip") || undefined,
    }),
  });
  if (!response.ok) return false;
  const result = await response.json();
  if (!result.success) return false;
  if (env.PUBLIC_TURNSTILE_HOSTNAME && result.hostname !== env.PUBLIC_TURNSTILE_HOSTNAME) return false;
  return true;
}

async function callOpenRouter(env, messages) {
  if (!env.OPENROUTER_API_KEY) throw new Error("OPENROUTER_API_KEY is not configured");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);
  try {
    const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      signal: controller.signal,
      headers: { authorization: `Bearer ${env.OPENROUTER_API_KEY}`, "content-type": "application/json" },
      body: JSON.stringify({ model: env.OPENROUTER_MODEL || "openai/gpt-5", messages, max_tokens: 1200 }),
    });
    if (!response.ok) throw new Error(`OpenRouter request failed (${response.status})`);
    return response.json();
  } finally {
    clearTimeout(timeout);
  }
}

async function runAssistant(request, env, extraHeaders = {}) {
  const parsed = await readJson(request);
  if (parsed.response) return new Response(parsed.response.body, { status: parsed.response.status, headers: { ...Object.fromEntries(parsed.response.headers), ...extraHeaders } });
  const validated = validateMessages(parsed.body.messages);
  if (validated.error) return json({ error: validated.error }, 400, extraHeaders);
  try {
    const result = await callOpenRouter(env, validated.messages);
    return json({ provider: "openrouter", result }, 200, extraHeaders);
  } catch {
    return json({ error: "AI provider unavailable" }, 503, extraHeaders);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return json({ ok: true, service: "githua-sales-assistant" });
    }

    const isPublic = url.pathname.startsWith("/v1/public/");
    if (isPublic) {
      const cors = corsHeaders(request, env);
      if (!cors) return json({ error: "Origin not allowed" }, 403);
      if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

      if (request.method === "POST" && url.pathname === "/v1/public/session") {
        if (!env.PUBLIC_SESSION_SECRET || !env.TURNSTILE_SECRET_KEY) return json({ error: "Public access is not configured" }, 503, cors);
        const parsed = await readJson(request);
        if (parsed.response) return json({ error: "Invalid request" }, parsed.response.status, cors);
        const ok = await verifyTurnstile(env, parsed.body.turnstileToken, request);
        if (!ok) return json({ error: "Verification failed" }, 403, cors);
        return json({ token: await issueSession(env.PUBLIC_SESSION_SECRET), expiresIn: SESSION_TTL_SECONDS }, 200, cors);
      }

      if (request.method === "POST" && url.pathname === "/v1/public/assistant") {
        if (!env.PUBLIC_SESSION_SECRET || !env.PUBLIC_RATE_LIMITER) return json({ error: "Public access is not configured" }, 503, cors);
        const auth = request.headers.get("authorization") || "";
        const session = await verifySession(env.PUBLIC_SESSION_SECRET, auth.startsWith("Bearer ") ? auth.slice(7) : "");
        if (!session) return json({ error: "Unauthorized" }, 401, cors);
        const limited = await env.PUBLIC_RATE_LIMITER.limit({ key: session.sid });
        if (!limited.success) return json({ error: "Too many requests" }, 429, { ...cors, "retry-after": "60" });
        return runAssistant(request, env, cors);
      }

      return json({ error: "Not found" }, 404, cors);
    }

    if (request.method !== "POST" || url.pathname !== "/v1/assistant") return json({ error: "Not found" }, 404);
    if (!env.GATEWAY_API_KEY) return json({ error: "Gateway authentication is not configured" }, 503);
    if (request.headers.get("authorization") !== `Bearer ${env.GATEWAY_API_KEY}`) return json({ error: "Unauthorized" }, 401);
    return runAssistant(request, env);
  },
};
