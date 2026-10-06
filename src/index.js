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
  // Rotate the five approved Sales Assistant bird directions every 14 days.
  // Epoch: 2026-10-06 UTC = Elegant Ascent (bird 1).
  const BIRD_EPOCH = Date.UTC(2026, 9, 6);
  const BIRD_PERIOD_MS = 14 * 24 * 60 * 60 * 1000;
  const birdIndex = ((Math.floor((Date.now() - BIRD_EPOCH) / BIRD_PERIOD_MS) % 5) + 5) % 5;
  const birds = [
    { name: "Elegant Ascent", pose: "M28 79C43 54 49 22 83 12C70 31 68 45 73 57C87 47 99 50 106 58C88 58 79 69 73 88C61 74 48 71 28 79Z" },
    { name: "Focused Guide", pose: "M24 77C44 64 48 33 77 24C68 39 68 49 75 57C88 50 100 54 106 61C88 61 78 70 72 87C57 73 43 72 24 77Z" },
    { name: "Dynamic Wings", pose: "M18 77C38 51 47 18 82 10C69 31 68 44 75 54C91 42 105 47 112 57C91 55 79 68 72 92C57 72 39 68 18 77Z" },
    { name: "Minimal Emblem", pose: "M25 74C43 57 48 31 77 20C68 39 69 50 77 57C91 50 101 55 106 62C87 61 77 72 71 88C57 73 43 69 25 74Z" },
    { name: "Graceful Perch", pose: "M22 78C42 63 48 30 78 19C68 39 69 50 76 57C90 49 101 53 108 61C90 60 79 70 72 88C58 75 43 72 22 78Z" }
  ];
  const bird = birds[birdIndex];
  const birdSvg = `<svg viewBox="0 0 125 105" role="img" aria-label="${bird.name} Sales Assistant bird"><defs><linearGradient id="birdGradient" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#fff3dc"/><stop offset=".34" stop-color="#f0c28f"/><stop offset=".63" stop-color="#d2a3ff"/><stop offset="1" stop-color="#7130bb"/></linearGradient><filter id="birdGlow"><feGaussianBlur stdDeviation="2.4" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs><path d="${bird.pose}" fill="url(#birdGradient)" filter="url(#birdGlow)"/><path d="M72 58C83 48 95 49 105 57C92 56 82 61 75 72" fill="none" stroke="#fff0d8" stroke-width="2.2" stroke-linecap="round"/><circle cx="88" cy="54" r="1.6" fill="#130c18"/></svg>`;
  return html(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Githua Sales Assistant</title><style>
:root{--bg:#07070a;--line:#44394a;--muted:#b9b0c4;--cream:#ffe4c7;--purple:#9b55ef;--lav:#c897ff}*{box-sizing:border-box}body{margin:0;background:#07070a;color:#fff;font:14px/1.45 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}.app{min-height:100vh;display:grid;grid-template-columns:294px 1fr}.side{padding:28px 18px 22px;border-right:1px solid #332b39;background:radial-gradient(ellipse at 8% 100%,rgba(148,71,210,.24),transparent 32%),radial-gradient(ellipse at 55% 91%,rgba(255,215,180,.13),transparent 24%),#08080b;display:flex;flex-direction:column}.brand{display:flex;gap:13px;align-items:center;padding:0 10px 32px}.logo{width:64px;height:72px;position:relative}.logo:before,.logo:after{content:"";position:absolute;inset:4px 14px;border-radius:72% 20% 68% 28%;transform:rotate(30deg);background:linear-gradient(150deg,#fff4df,var(--cream) 32%,#b178f0 64%,#58228c);box-shadow:0 0 22px rgba(177,110,255,.22)}.logo:after{inset:27px 8px 1px 28px;transform:rotate(-18deg)}.brand strong{font-size:25px;line-height:1.02}.brand small{display:block;margin-top:8px;font-size:8px;letter-spacing:.18em;color:#eadbea;text-transform:uppercase}.nav{display:grid;gap:6px}.nav a{display:flex;align-items:center;gap:15px;color:#cbc5d5;text-decoration:none;padding:14px 16px;border-radius:12px;font-size:16px}.nav a.active{color:#fff;border:1px solid #9b5bdf;background:linear-gradient(90deg,rgba(132,67,206,.35),rgba(255,222,194,.08));box-shadow:0 0 22px rgba(156,85,247,.25)}.ico{width:25px;text-align:center;font-size:20px}.help{margin-top:auto;border:1px solid #76507c;border-radius:15px;padding:16px;background:linear-gradient(135deg,rgba(255,218,183,.10),rgba(130,57,187,.16));display:flex;gap:12px;align-items:center}.main{padding:20px 22px 28px 28px;position:relative;overflow:hidden;background:radial-gradient(ellipse at 80% 9%,rgba(112,51,158,.20),transparent 31%),#08080b}.main:before{content:"";position:absolute;right:-110px;top:70px;width:73%;height:185px;border-radius:50%;transform:rotate(-7deg);background:linear-gradient(160deg,transparent 3%,rgba(113,54,165,.15) 25%,rgba(250,211,178,.34) 46%,rgba(178,118,234,.31) 59%,rgba(255,229,204,.21) 70%,transparent 85%);filter:blur(18px)}.main>*{position:relative}.bar{display:flex;justify-content:space-between;align-items:center}.search{width:48%;border:1px solid #625b6b;border-radius:11px;padding:12px 15px;color:#bbb4c6;background:rgba(11,11,16,.78)}.profile{display:flex;align-items:center;gap:12px}.avatar{width:43px;height:43px;border-radius:50%;display:grid;place-items:center;background:linear-gradient(135deg,#f9dec6,#a870c0);border:1px solid #ffe7d0}.profile small{display:block;color:#b8afc2}.hero{padding:44px 6px 26px}.eyebrow{font-size:11px;letter-spacing:.34em;color:#c2b8c9;text-transform:uppercase}.hero h1{font-size:48px;font-weight:400;letter-spacing:-.04em;margin:13px 0 3px;background:linear-gradient(90deg,#fff5e8 0 45%,#c27aff 68%,#f1d5ff);background-clip:text;-webkit-background-clip:text;color:transparent}.hero p{font-size:19px;color:#bbb0c7;margin:0}.content{display:grid;grid-template-columns:minmax(0,1fr) 310px;gap:18px}.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.card{border:1px solid #5b5261;border-radius:15px;background:linear-gradient(145deg,rgba(37,30,43,.82),rgba(13,13,18,.91));box-shadow:inset 0 1px rgba(255,255,255,.05);overflow:hidden}.metric{height:158px;padding:21px;position:relative}.metric:after{content:"";position:absolute;width:130px;height:80px;right:-15px;bottom:-15px;border-radius:50%;background:radial-gradient(ellipse,rgba(153,76,242,.36),transparent 65%);filter:blur(8px)}.metric:nth-child(2):after{background:radial-gradient(ellipse,rgba(255,211,174,.30),transparent 65%)}.metric .row{display:flex;gap:14px;align-items:center}.circle{width:46px;height:46px;border-radius:50%;display:grid;place-items:center;border:1px solid #654f77;background:rgba(116,57,166,.22);font-size:21px}.metric strong{display:block;font-size:34px;font-weight:500;margin-top:4px}.metric a,.empty a{color:#b780ff;text-decoration:none}.quick{margin-top:18px;padding:18px 14px}.sectiontitle{font-size:17px;font-weight:600}.sub{color:#aaa2b4;font-size:12px}.actions{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:16px}.action{min-height:145px;padding:16px;border:1px solid #37313e;border-radius:12px;background:linear-gradient(145deg,#29252d,#16161d);text-decoration:none;color:#fff}.action b{display:block;margin:13px 0 3px}.action span{color:#b9b1c3;font-size:12px}.assistant{padding:20px;min-height:335px;background:linear-gradient(160deg,rgba(19,15,28,.96),rgba(11,10,16,.95));border-color:#765e82}.bird{height:100px;display:flex;justify-content:flex-end}.bird svg{height:100%;width:125px}.birdname{text-align:right;color:#aa9cb4;font-size:10px;letter-spacing:.08em}.assistant h2{font-size:20px;margin:0 0 5px}.assistant p{color:#bcb3c6}.open{display:block;text-align:center;margin:18px 0;padding:12px;border-radius:24px;background:linear-gradient(90deg,#ffe0c2,#c985f5);color:#171119;text-decoration:none;font-weight:600}.try{display:grid;gap:9px}.try div{border:1px solid #655b68;border-radius:20px;padding:9px 12px;font-size:11px}.bottom{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:18px}.empty{min-height:225px;padding:18px}.emptyhead{display:flex;justify-content:space-between}.emptybody{text-align:center;padding-top:28px;color:#bbb3c2}.pill{display:inline-block;margin-top:13px;padding:10px 22px;border-radius:24px;background:linear-gradient(90deg,#ffdcb9,#e9b889);color:#171217!important;text-decoration:none}.bottom .empty:nth-child(2) .pill,.bottom .empty:nth-child(3) .pill{background:linear-gradient(90deg,#a555f3,#7451b5);color:#fff!important}@media(max-width:1100px){.app{grid-template-columns:220px 1fr}.content{grid-template-columns:1fr}.actions{grid-template-columns:repeat(2,1fr)}}@media(max-width:760px){.app{display:block}.side{padding:16px}.brand{padding-bottom:14px}.nav{grid-template-columns:repeat(4,1fr);overflow:auto}.nav a{font-size:0;justify-content:center}.help{display:none}.main{padding:16px}.search{width:65%}.profile div:not(.avatar){display:none}.hero h1{font-size:36px}.metrics,.bottom{grid-template-columns:1fr}.actions{grid-template-columns:1fr 1fr}}
</style></head><body><div class="app"><aside class="side"><div class="brand"><div class="logo"></div><div><strong>Githua<br>AI Systems</strong><small>Intelligence engineered<br>around people.</small></div></div><nav class="nav"><a class="active" href="/"><span class="ico">⌂</span>Overview</a><a href="#"><span class="ico">♙</span>Leads</a><a href="#"><span class="ico">◌</span>Conversations</a><a href="#"><span class="ico">☑</span>Tasks</a><a href="#"><span class="ico">▤</span>Proposals & Budgets</a><a href="#"><span class="ico">▱</span>Knowledge</a><a href="#"><span class="ico">⚙</span>Settings</a></nav><div class="help"><span>✦</span><div><b>Need help?</b><br><span class="sub">Ask the Assistant</span></div></div></aside>
<main class="main"><div class="bar"><div class="search">⌕ &nbsp; Search leads, conversations, tasks...</div><div class="profile"><div class="avatar">\${firstName.slice(0,1).toUpperCase()}</div><div><b>\${firstName}</b><small>\${orgName}</small></div><span>⌄</span></div></div><section class="hero"><div class="eyebrow">Sales Assistant</div><h1>Good to see you, \${firstName}.</h1><p>A calm view of your sales work, conversations and next moves.</p></section>
<div class="content"><div><section class="metrics"><div class="card metric"><div class="row"><span class="circle">♟</span><div>Total leads<strong>\${counts.leads}</strong><a href="#">View leads →</a></div></div></div><div class="card metric"><div class="row"><span class="circle">●</span><div>Open conversations<strong>\${counts.conversations}</strong><a href="#">View conversations →</a></div></div></div><div class="card metric"><div class="row"><span class="circle">♜</span><div>Won leads<strong>\${counts.won}</strong><a href="#">View wins →</a></div></div></div></section><section class="card quick"><div class="sectiontitle">✦ Quick actions<div class="sub">Get things done faster.</div></div><div class="actions"><a class="action" href="#"><span class="circle">＋</span><b>Add a new lead</b><span>Capture and qualify new opportunities.</span></a><a class="action" href="#"><span class="circle">◌</span><b>Start a conversation</b><span>Continue a client conversation.</span></a><a class="action" href="#"><span class="circle">▤</span><b>Create proposal</b><span>Build a proposal or budget.</span></a><a class="action" href="#"><span class="circle">☑</span><b>Add a task</b><span>Keep your work on track.</span></a></div></section></div>
<aside class="card assistant"><div class="bird">\${birdSvg}</div><div class="birdname">\${bird.name} · rotates every 2 weeks</div><h2>Your AI Assistant</h2><p>Get help with leads, follow-ups, proposals, research and more.</p><a class="open" href="#">Open Assistant →</a><b>Try asking:</b><div class="try"><div>Summarize my open conversations →</div><div>Draft a follow-up email →</div><div>Create a proposal for a new lead →</div></div></aside></div>
<section class="bottom"><div class="card empty"><div class="emptyhead"><b>Recent leads</b><a href="#">View all →</a></div><div class="sub">Your latest leads and activity.</div><div class="emptybody"><b>No leads yet</b><br><span>When you add leads, they'll appear here.</span><br><a class="pill" href="#">Add your first lead →</a></div></div><div class="card empty"><div class="emptyhead"><b>Recent conversations</b><a href="#">View all →</a></div><div class="sub">Your latest conversations.</div><div class="emptybody"><b>No conversations yet</b><br><span>Your recent conversations will appear here.</span><br><a class="pill" href="#">Start a conversation →</a></div></div><div class="card empty"><div class="emptyhead"><b>Tasks</b><a href="#">View all →</a></div><div class="sub">Your upcoming tasks.</div><div class="emptybody"><b>No tasks yet</b><br><span>Add tasks to keep your work on track.</span><br><a class="pill" href="#">Add a task →</a></div></div></section></main></div></body></html>`);
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
