const BASE_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
};

const MAX_BODY_BYTES = 32 * 1024;
const MAX_MESSAGES = 24;
const MAX_MESSAGE_CHARS = 8000;
const MAX_TOTAL_CHARS = 24000;
const SESSION_TTL_SECONDS = 8 * 60 * 60;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const json = (data, status = 200, extraHeaders = {}) =>
  new Response(JSON.stringify(data), { status, headers: { ...BASE_HEADERS, ...extraHeaders } });

const redirect = (location, headers = {}) =>
  new Response(null, { status: 302, headers: { location, "cache-control": "no-store", ...headers } });

const b64url = (bytes) => {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

const fromB64url = (value) => {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized + "=".repeat((4 - (normalized.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
};

async function hmac(secret, value) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(value)));
}

async function signedValue(secret, payload) {
  const encoded = b64url(encoder.encode(JSON.stringify(payload)));
  return `${encoded}.${b64url(await hmac(secret, encoded))}`;
}

async function readSignedValue(secret, value) {
  if (!secret || !value) return null;
  const [encoded, signature, extra] = value.split(".");
  if (!encoded || !signature || extra) return null;
  const expected = await hmac(secret, encoded);
  const actual = fromB64url(signature);
  if (expected.length !== actual.length) return null;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected[i] ^ actual[i];
  if (diff !== 0) return null;
  try {
    const payload = JSON.parse(decoder.decode(fromB64url(encoded)));
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

function cookie(request, name) {
  const header = request.headers.get("cookie") || "";
  for (const part of header.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return null;
}

function secureCookie(name, value, maxAge) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

function authConfig(env) {
  if (!env.AUTH0_DOMAIN || !env.AUTH0_CLIENT_ID || !env.AUTH0_CLIENT_SECRET || !env.SESSION_SECRET) {
    throw new Error("Authentication is not configured");
  }
}

async function startLogin(request, env) {
  authConfig(env);
  const origin = new URL(request.url).origin;
  const state = b64url(crypto.getRandomValues(new Uint8Array(24)));
  const stateCookie = await signedValue(env.SESSION_SECRET, {
    state,
    exp: Math.floor(Date.now() / 1000) + 600,
  });
  const authorize = new URL(`https://${env.AUTH0_DOMAIN}/authorize`);
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("client_id", env.AUTH0_CLIENT_ID);
  authorize.searchParams.set("redirect_uri", `${origin}/auth/callback`);
  authorize.searchParams.set("scope", "openid profile email");
  authorize.searchParams.set("state", state);
  return redirect(authorize.toString(), { "set-cookie": secureCookie("gsa_auth_state", stateCookie, 600) });
}

async function callback(request, env) {
  authConfig(env);
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const stored = await readSignedValue(env.SESSION_SECRET, cookie(request, "gsa_auth_state"));
  if (!code || !state || !stored || stored.state !== state) return json({ error: "Invalid authentication response" }, 400);

  const origin = url.origin;
  const tokenResponse = await fetch(`https://${env.AUTH0_DOMAIN}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      grant_type: "authorization_code",
      client_id: env.AUTH0_CLIENT_ID,
      client_secret: env.AUTH0_CLIENT_SECRET,
      code,
      redirect_uri: `${origin}/auth/callback`,
    }),
  });
  if (!tokenResponse.ok) return json({ error: "Authentication failed" }, 401);
  const tokens = await tokenResponse.json();

  const userResponse = await fetch(`https://${env.AUTH0_DOMAIN}/userinfo`, {
    headers: { authorization: `Bearer ${tokens.access_token}` },
  });
  if (!userResponse.ok) return json({ error: "Authentication failed" }, 401);
  const profile = await userResponse.json();
  if (!profile.sub) return json({ error: "Authentication failed" }, 401);

  const now = new Date().toISOString();
  const existing = await env.DB.prepare("SELECT id FROM users WHERE identity_subject = ?").bind(profile.sub).first();
  const userId = existing?.id || crypto.randomUUID();
  if (existing) {
    await env.DB.prepare("UPDATE users SET email = ?, display_name = ?, updated_at = ? WHERE id = ?")
      .bind(profile.email || null, profile.name || profile.nickname || null, now, userId).run();
  } else {
    await env.DB.prepare("INSERT INTO users (id, identity_subject, email, display_name, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)")
      .bind(userId, profile.sub, profile.email || null, profile.name || profile.nickname || null, now, now).run();
  }

  const session = await signedValue(env.SESSION_SECRET, {
    sub: profile.sub,
    uid: userId,
    email: profile.email || null,
    name: profile.name || profile.nickname || null,
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
  });
  const headers = new Headers({
    location: "/",
    "cache-control": "no-store",
  });
  // Keep both Set-Cookie header values. Converting Headers with Object.fromEntries
  // can collapse duplicate Set-Cookie values and discard the session cookie.
  headers.append("set-cookie", secureCookie("gsa_session", session, SESSION_TTL_SECONDS));
  headers.append("set-cookie", "gsa_auth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0");
  return new Response(null, { status: 302, headers });
}

async function logout(request, env) {
  authConfig(env);
  const origin = new URL(request.url).origin;
  const target = new URL(`https://${env.AUTH0_DOMAIN}/v2/logout`);
  target.searchParams.set("client_id", env.AUTH0_CLIENT_ID);
  target.searchParams.set("returnTo", origin);
  return redirect(target.toString(), {
    "set-cookie": "gsa_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
  });
}

async function sessionInfo(request, env) {
  authConfig(env);
  const session = await readSignedValue(env.SESSION_SECRET, cookie(request, "gsa_session"));
  if (!session) return json({ authenticated: false }, 401);
  return json({ authenticated: true, user: { id: session.uid, email: session.email, name: session.name } });
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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      if (request.method === "GET" && url.pathname === "/health") return json({ ok: true, service: "githua-sales-assistant" });
      if (request.method === "GET" && url.pathname === "/login") return await startLogin(request, env);
      if (request.method === "GET" && url.pathname === "/auth/callback") return await callback(request, env);
      if (request.method === "GET" && url.pathname === "/logout") return await logout(request, env);
      if (request.method === "GET" && url.pathname === "/v1/session") return await sessionInfo(request, env);
    } catch {
      return json({ error: "Authentication service unavailable" }, 503);
    }

    if (request.method !== "POST" || url.pathname !== "/v1/assistant") return json({ error: "Not found" }, 404);
    if (!env.GATEWAY_API_KEY) return json({ error: "Gateway authentication is not configured" }, 503);
    const supplied = request.headers.get("authorization");
    if (supplied !== `Bearer ${env.GATEWAY_API_KEY}`) return json({ error: "Unauthorized" }, 401);

    const contentType = request.headers.get("content-type") || "";
    if (!contentType.toLowerCase().startsWith("application/json")) return json({ error: "Content-Type must be application/json" }, 415);
    const declaredLength = Number(request.headers.get("content-length"));
    if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_BYTES) return json({ error: "Request body is too large" }, 413);

    let raw;
    try { raw = await request.text(); } catch { return json({ error: "Unable to read request body" }, 400); }
    if (new TextEncoder().encode(raw).byteLength > MAX_BODY_BYTES) return json({ error: "Request body is too large" }, 413);

    let body;
    try { body = JSON.parse(raw); } catch { return json({ error: "Invalid JSON" }, 400); }
    const validated = validateMessages(body.messages);
    if (validated.error) return json({ error: validated.error }, 400);

    try {
      const result = await callOpenRouter(env, validated.messages);
      return json({ provider: "openrouter", result });
    } catch {
      return json({ error: "AI provider unavailable" }, 503);
    }
  },
};
