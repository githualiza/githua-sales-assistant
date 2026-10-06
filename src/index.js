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

async function requireSession(request, env) {
  authConfig(env);
  return readSignedValue(env.SESSION_SECRET, cookie(request, "gsa_session"));
}

async function bootstrapWorkspace(request, env) {
  const session = await requireSession(request, env);
  if (!session?.uid) return json({ error: "Unauthorized" }, 401);

  const user = await env.DB.prepare("SELECT id FROM users WHERE id = ?").bind(session.uid).first();
  if (!user) return json({ error: "Authenticated user is not registered" }, 403);

  const existingMembership = await env.DB.prepare(
    "SELECT m.role, m.status, o.id AS organization_id, o.slug, o.name, o.status AS organization_status FROM memberships m JOIN organizations o ON o.id = m.organization_id WHERE m.user_id = ? AND m.status = 'active' ORDER BY m.created_at LIMIT 1"
  ).bind(session.uid).first();

  if (existingMembership) {
    return json({
      bootstrapped: false,
      organization: {
        id: existingMembership.organization_id,
        slug: existingMembership.slug,
        name: existingMembership.name,
        status: existingMembership.organization_status,
      },
      membership: { role: existingMembership.role, status: existingMembership.status },
    });
  }

  // Bootstrap is intentionally fail-closed: once any organization exists, new
  // authenticated users cannot make themselves owners through this endpoint.
  const organizationCount = await env.DB.prepare("SELECT COUNT(*) AS count FROM organizations").first();
  if (Number(organizationCount?.count || 0) !== 0) {
    return json({ error: "Workspace bootstrap is closed" }, 403);
  }

  const now = new Date().toISOString();
  const organizationId = crypto.randomUUID();
  const membershipId = crypto.randomUUID();

  await env.DB.batch([
    env.DB.prepare("INSERT INTO organizations (id, slug, name, status, created_at, updated_at) VALUES (?, ?, ?, 'active', ?, ?)")
      .bind(organizationId, "githua-ai-systems", "Githua AI Systems", now, now),
    env.DB.prepare("INSERT INTO memberships (id, organization_id, user_id, role, status, created_at, updated_at) VALUES (?, ?, ?, 'owner', 'active', ?, ?)")
      .bind(membershipId, organizationId, session.uid, now, now),
  ]);

  return json({
    bootstrapped: true,
    organization: { id: organizationId, slug: "githua-ai-systems", name: "Githua AI Systems", status: "active" },
    membership: { role: "owner", status: "active" },
  }, 201);
}

async function workspaceInfo(request, env) {
  const session = await requireSession(request, env);
  if (!session?.uid) return json({ error: "Unauthorized" }, 401);

  const membership = await env.DB.prepare(
    "SELECT m.role, m.status, o.id AS organization_id, o.slug, o.name, o.status AS organization_status FROM memberships m JOIN organizations o ON o.id = m.organization_id WHERE m.user_id = ? AND m.status = 'active' ORDER BY m.created_at LIMIT 1"
  ).bind(session.uid).first();

  if (!membership) return json({ error: "No active workspace membership" }, 403);
  return json({
    organization: {
      id: membership.organization_id,
      slug: membership.slug,
      name: membership.name,
      status: membership.organization_status,
    },
    membership: { role: membership.role, status: membership.status },
  });
}



const LEAD_READ_ROLES = new Set(["owner", "admin", "manager", "agent", "viewer"]);
const LEAD_WRITE_ROLES = new Set(["owner", "admin", "manager", "agent"]);
const LEAD_STATUSES = new Set(["new", "qualified", "contacted", "won", "lost"]);
const MAX_LEAD_FIELD = 500;
const MAX_LEAD_NOTES = 8000;

async function activeMembership(session, env) {
  if (!session?.uid) return null;
  return env.DB.prepare(
    "SELECT m.role, m.status, o.id AS organization_id, o.status AS organization_status FROM memberships m JOIN organizations o ON o.id = m.organization_id WHERE m.user_id = ? AND m.status = 'active' AND o.status = 'active' ORDER BY m.created_at LIMIT 1"
  ).bind(session.uid).first();
}

function cleanLeadText(value, max = MAX_LEAD_FIELD) {
  if (value == null) return null;
  if (typeof value !== "string") return undefined;
  const cleaned = value.trim();
  if (cleaned.length > max) return undefined;
  return cleaned || null;
}

async function listLeads(request, env) {
  const session = await requireSession(request, env);
  if (!session?.uid) return json({ error: "Unauthorized" }, 401);
  const membership = await activeMembership(session, env);
  if (!membership || !LEAD_READ_ROLES.has(membership.role)) return json({ error: "Forbidden" }, 403);

  const url = new URL(request.url);
  const requestedStatus = url.searchParams.get("status");
  if (requestedStatus && !LEAD_STATUSES.has(requestedStatus)) return json({ error: "Invalid lead status" }, 400);
  const limit = Math.min(Math.max(Number.parseInt(url.searchParams.get("limit") || "50", 10) || 50, 1), 100);

  const query = requestedStatus
    ? "SELECT id, owner_user_id, name, company, email, phone, status, source, notes, created_at, updated_at FROM leads WHERE organization_id = ? AND status = ? ORDER BY updated_at DESC LIMIT ?"
    : "SELECT id, owner_user_id, name, company, email, phone, status, source, notes, created_at, updated_at FROM leads WHERE organization_id = ? ORDER BY updated_at DESC LIMIT ?";
  const stmt = requestedStatus
    ? env.DB.prepare(query).bind(membership.organization_id, requestedStatus, limit)
    : env.DB.prepare(query).bind(membership.organization_id, limit);
  const result = await stmt.all();
  return json({ leads: result.results || [] });
}

async function createLead(request, env) {
  const session = await requireSession(request, env);
  if (!session?.uid) return json({ error: "Unauthorized" }, 401);
  const membership = await activeMembership(session, env);
  if (!membership || !LEAD_WRITE_ROLES.has(membership.role)) return json({ error: "Forbidden" }, 403);

  const contentType = request.headers.get("content-type") || "";
  if (!contentType.toLowerCase().startsWith("application/json")) return json({ error: "Content-Type must be application/json" }, 415);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return json({ error: "Invalid lead" }, 400);

  const name = cleanLeadText(body.name);
  if (!name || name === undefined) return json({ error: "Lead name is required and must be 500 characters or fewer" }, 400);
  const company = cleanLeadText(body.company);
  const email = cleanLeadText(body.email);
  const phone = cleanLeadText(body.phone);
  const source = cleanLeadText(body.source);
  const notes = cleanLeadText(body.notes, MAX_LEAD_NOTES);
  if ([company, email, phone, source, notes].some((value) => value === undefined)) return json({ error: "One or more lead fields are invalid" }, 400);
  const status = body.status == null ? "new" : body.status;
  if (typeof status !== "string" || !LEAD_STATUSES.has(status)) return json({ error: "Invalid lead status" }, 400);

  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  await env.DB.prepare(
    "INSERT INTO leads (id, organization_id, owner_user_id, name, company, email, phone, status, source, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
  ).bind(id, membership.organization_id, session.uid, name, company, email, phone, status, source, notes, now, now).run();
  return json({ lead: { id, name, company, email, phone, status, source, notes, owner_user_id: session.uid, created_at: now, updated_at: now } }, 201);
}

async function updateLead(request, env, leadId) {
  const session = await requireSession(request, env);
  if (!session?.uid) return json({ error: "Unauthorized" }, 401);
  const membership = await activeMembership(session, env);
  if (!membership || !LEAD_WRITE_ROLES.has(membership.role)) return json({ error: "Forbidden" }, 403);

  const existing = await env.DB.prepare(
    "SELECT id, name, company, email, phone, status, source, notes FROM leads WHERE id = ? AND organization_id = ?"
  ).bind(leadId, membership.organization_id).first();
  if (!existing) return json({ error: "Lead not found" }, 404);

  const contentType = request.headers.get("content-type") || "";
  if (!contentType.toLowerCase().startsWith("application/json")) return json({ error: "Content-Type must be application/json" }, 415);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return json({ error: "Invalid lead" }, 400);

  const next = { ...existing };
  for (const field of ["name", "company", "email", "phone", "source"]) {
    if (Object.prototype.hasOwnProperty.call(body, field)) {
      const value = cleanLeadText(body[field]);
      if (value === undefined || (field === "name" && !value)) return json({ error: "Invalid lead field" }, 400);
      next[field] = value;
    }
  }
  if (Object.prototype.hasOwnProperty.call(body, "notes")) {
    const value = cleanLeadText(body.notes, MAX_LEAD_NOTES);
    if (value === undefined) return json({ error: "Invalid lead notes" }, 400);
    next.notes = value;
  }
  if (Object.prototype.hasOwnProperty.call(body, "status")) {
    if (typeof body.status !== "string" || !LEAD_STATUSES.has(body.status)) return json({ error: "Invalid lead status" }, 400);
    next.status = body.status;
  }

  const now = new Date().toISOString();
  await env.DB.prepare(
    "UPDATE leads SET name = ?, company = ?, email = ?, phone = ?, status = ?, source = ?, notes = ?, updated_at = ? WHERE id = ? AND organization_id = ?"
  ).bind(next.name, next.company, next.email, next.phone, next.status, next.source, next.notes, now, leadId, membership.organization_id).run();
  return json({ lead: { ...next, id: leadId, updated_at: now } });
}


function escapeHtml(value = "") {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
}

function html(body, status = 200) {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    },
  });
}

async function dashboard(request, env) {
  const session = await requireSession(request, env);
  if (!session?.uid) return redirect("/login");

  const membership = await env.DB.prepare(
    "SELECT m.role, m.status, o.id AS organization_id, o.name, o.status AS organization_status FROM memberships m JOIN organizations o ON o.id = m.organization_id WHERE m.user_id = ? AND m.status = 'active' ORDER BY m.created_at LIMIT 1"
  ).bind(session.uid).first();
  if (!membership || membership.organization_status !== "active") {
    return html("<!doctype html><title>Access unavailable</title><p>No active workspace access.</p>", 403);
  }

  const orgId = membership.organization_id;
  const [leadCount, conversationCount, wonCount] = await env.DB.batch([
    env.DB.prepare("SELECT COUNT(*) AS count FROM leads WHERE organization_id = ?").bind(orgId),
    env.DB.prepare("SELECT COUNT(*) AS count FROM conversations WHERE organization_id = ? AND status = 'open'").bind(orgId),
    env.DB.prepare("SELECT COUNT(*) AS count FROM leads WHERE organization_id = ? AND status = 'won'").bind(orgId),
  ]);
  const counts = {
    leads: Number(leadCount.results?.[0]?.count || 0),
    conversations: Number(conversationCount.results?.[0]?.count || 0),
    won: Number(wonCount.results?.[0]?.count || 0),
  };

  const firstName = escapeHtml((session.name || "there").trim().split(/\s+/)[0]);
  const orgName = escapeHtml(membership.name);
  const role = escapeHtml(membership.role);
  return html(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Githua Sales Assistant</title>
<style>
:root{--ink:#07060a;--panel:rgba(18,15,24,.74);--line:rgba(232,205,174,.18);--muted:#b9b2c2;--pearl:#fff8f0;--champagne:#e8cdae;--champagne2:#f7dfc4;--violet:#a66cff;--violet2:#d2b6ff}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 82% 5%,rgba(166,108,255,.20),transparent 32%),radial-gradient(ellipse at 58% 25%,rgba(232,205,174,.13),transparent 26%),radial-gradient(ellipse at 8% 92%,rgba(166,108,255,.14),transparent 30%),var(--ink);color:var(--pearl);font:15px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;min-height:100vh}
.shell{display:grid;grid-template-columns:248px 1fr;min-height:100vh}.side{border-right:1px solid rgba(232,205,174,.16);padding:28px 18px;display:flex;flex-direction:column;background:linear-gradient(180deg,rgba(11,8,15,.94),rgba(15,9,21,.84));backdrop-filter:blur(22px);box-shadow:16px 0 60px rgba(90,45,145,.08)}
.brand{padding:0 10px 30px}.mark{width:42px;height:42px;border-radius:50% 42% 58% 38%;transform:rotate(18deg);background:linear-gradient(135deg,var(--champagne2),#fff1e1 28%,var(--violet2) 62%,#7c3dd4);box-shadow:0 0 30px rgba(166,108,255,.25),0 0 20px rgba(232,205,174,.15);margin-bottom:15px}.brand strong{display:block;letter-spacing:.01em}.brand span{font-size:12px;color:var(--muted)}
nav{display:grid;gap:5px}.nav{padding:11px 12px;border-radius:12px;color:#b8bbc3;text-decoration:none}.nav.active,.nav:hover{color:#fff;background:linear-gradient(90deg,rgba(166,108,255,.20),rgba(232,205,174,.08));box-shadow:inset 0 0 0 1px rgba(190,132,255,.32),0 8px 30px rgba(111,55,174,.10)}.dot{display:inline-block;width:6px;height:6px;border-radius:50%;background:currentColor;margin-right:10px;vertical-align:2px}
.account{margin-top:auto;padding:16px 10px 0;border-top:1px solid var(--line)}.account small{display:block;color:var(--muted);text-transform:capitalize}.logout{display:inline-block;color:#ddd;text-decoration:none;margin-top:10px;font-size:13px}
main{padding:44px clamp(24px,5vw,72px);position:relative;overflow:hidden}main:before{content:"";position:absolute;width:760px;height:240px;right:-120px;top:-70px;border-radius:50%;background:linear-gradient(110deg,transparent 5%,rgba(232,205,174,.10) 30%,rgba(166,108,255,.18) 55%,rgba(247,223,196,.11) 72%,transparent 90%);filter:blur(22px);transform:rotate(-8deg);pointer-events:none}.top{display:flex;justify-content:space-between;gap:20px;align-items:flex-start;margin-bottom:42px}.eyebrow{color:#bfc2c9;font-size:12px;letter-spacing:.13em;text-transform:uppercase}.top h1{font-size:clamp(30px,4vw,50px);font-weight:500;letter-spacing:-.045em;margin:8px 0 6px;background:linear-gradient(90deg,var(--pearl),var(--champagne2) 46%,var(--violet2));-webkit-background-clip:text;background-clip:text;color:transparent}.top p{margin:0;color:var(--muted);max-width:600px}.status{border:1px solid var(--line);border-radius:999px;padding:8px 12px;color:#cfd5d5;background:rgba(255,255,255,.035);white-space:nowrap;font-size:12px}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:14px}.card{border:1px solid var(--line);background:linear-gradient(145deg,rgba(73,46,91,.20),rgba(28,20,33,.72) 48%,rgba(232,205,174,.055));border-radius:20px;padding:22px;backdrop-filter:blur(18px);box-shadow:inset 0 1px rgba(255,255,255,.07),0 18px 50px rgba(0,0,0,.16)}.metric:nth-child(1){box-shadow:inset 0 1px rgba(255,255,255,.07),inset 0 -40px 70px rgba(132,69,224,.12)}.metric:nth-child(2){box-shadow:inset 0 1px rgba(255,255,255,.07),inset 0 -40px 70px rgba(232,205,174,.10)}.metric:nth-child(3){box-shadow:inset 0 1px rgba(255,255,255,.07),inset 0 -40px 70px rgba(166,108,255,.10)}.metric span{color:var(--muted);font-size:13px}.metric strong{display:block;font-size:34px;font-weight:450;letter-spacing:-.04em;margin-top:13px}
.hero{display:grid;grid-template-columns:1.35fr .65fr;gap:14px}.assistant{min-height:250px;position:relative;overflow:hidden}.assistant:after{content:"";position:absolute;width:260px;height:180px;border-radius:50%;right:-45px;bottom:-70px;background:radial-gradient(ellipse at 35% 30%,rgba(247,223,196,.36),rgba(166,108,255,.18) 42%,rgba(83,42,132,.08) 65%,transparent 72%);filter:blur(2px)}.assistant h2,.quick h2{font-size:20px;font-weight:500;margin:0 0 8px}.assistant p,.quick p{color:var(--muted);max-width:540px;margin:0}.soon{display:inline-block;margin-top:28px;border:1px solid var(--line);border-radius:12px;padding:10px 14px;color:#d9d9dc;font-size:13px}.quick{min-height:250px}.quicklinks{display:grid;gap:9px;margin-top:20px}.quicklinks div{padding:11px 12px;border-radius:12px;background:rgba(255,255,255,.045);color:#d9dadd;font-size:13px}
@media(max-width:850px){.shell{grid-template-columns:1fr}.side{position:static;border-right:0;border-bottom:1px solid var(--line);padding:18px}.brand{padding-bottom:14px}.brand .mark{display:none}nav{grid-template-columns:repeat(4,1fr);overflow:auto}.nav{white-space:nowrap}.account{display:none}main{padding:28px 18px}.top{margin-bottom:28px}.grid,.hero{grid-template-columns:1fr}.status{display:none}}
</style>
</head>
<body>
<div class="shell">
<aside class="side">
  <div class="brand"><div class="mark"></div><strong>Githua AI Systems</strong><span>Sales Assistant</span></div>
  <nav>
    <a class="nav active" href="/"><span class="dot"></span>Overview</a>
    <a class="nav" href="#"><span class="dot"></span>Leads</a>
    <a class="nav" href="#"><span class="dot"></span>Conversations</a>
    <a class="nav" href="#"><span class="dot"></span>Tasks</a>
    <a class="nav" href="#"><span class="dot"></span>Proposals & budgets</a>
    <a class="nav" href="#"><span class="dot"></span>Knowledge</a>
    <a class="nav" href="#"><span class="dot"></span>Settings</a>
  </nav>
  <div class="account"><strong>${orgName}</strong><small>${role}</small><a class="logout" href="/logout">Sign out</a></div>
</aside>
<main>
  <header class="top"><div><div class="eyebrow">Intelligence engineered around people</div><h1>Good to see you, ${firstName}.</h1><p>A calm view of your sales work, conversations and next moves.</p></div><div class="status">● Workspace active</div></header>
  <section class="grid">
    <div class="card metric"><span>Total leads</span><strong>${counts.leads}</strong></div>
    <div class="card metric"><span>Open conversations</span><strong>${counts.conversations}</strong></div>
    <div class="card metric"><span>Won leads</span><strong>${counts.won}</strong></div>
  </section>
  <section class="hero">
    <div class="card assistant"><div class="eyebrow">Githua Sales Assistant</div><h2>Your AI workspace is taking shape.</h2><p>The secure foundation is live. Next, the assistant will help qualify leads, prepare follow-ups, organise tasks and draft proposals without exposing your private gateway credentials.</p><span class="soon">AI actions · coming next</span></div>
    <div class="card quick"><div class="eyebrow">Workspace</div><h2>Simple by design.</h2><p>Only the tools your team needs, with access controlled by role.</p><div class="quicklinks"><div>Lead pipeline</div><div>Client conversations</div><div>Proposals & budgets</div></div></div>
  </section>
</main>
</div>
</body></html>`);
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
      if (request.method === "GET" && url.pathname === "/") return await dashboard(request, env);
      if (request.method === "GET" && url.pathname === "/health") return json({ ok: true, service: "githua-sales-assistant" });
      if (request.method === "GET" && url.pathname === "/login") return await startLogin(request, env);
      if (request.method === "GET" && url.pathname === "/auth/callback") return await callback(request, env);
      if (request.method === "GET" && url.pathname === "/logout") return await logout(request, env);
      if (request.method === "GET" && url.pathname === "/v1/session") return await sessionInfo(request, env);
      if (request.method === "POST" && url.pathname === "/v1/bootstrap") return await bootstrapWorkspace(request, env);
      if (request.method === "GET" && url.pathname === "/v1/workspace") return await workspaceInfo(request, env);
      if (request.method === "GET" && url.pathname === "/v1/leads") return await listLeads(request, env);
      if (request.method === "POST" && url.pathname === "/v1/leads") return await createLead(request, env);
      if (["PATCH", "PUT"].includes(request.method) && url.pathname.startsWith("/v1/leads/")) {
        const leadId = decodeURIComponent(url.pathname.slice("/v1/leads/".length));
        if (!leadId || leadId.includes("/")) return json({ error: "Not found" }, 404);
        return await updateLead(request, env, leadId);
      }
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
