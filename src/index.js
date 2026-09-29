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

const json = (data, status = 200, extraHeaders = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { ...BASE_HEADERS, ...extraHeaders },
  });

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
      headers: {
        authorization: `Bearer ${env.OPENROUTER_API_KEY}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        model: env.OPENROUTER_MODEL || "openai/gpt-5",
        messages,
        max_tokens: 1200,
      }),
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

    if (request.method === "GET" && url.pathname === "/health") {
      return json({ ok: true, service: "githua-sales-assistant" });
    }

    if (request.method !== "POST" || url.pathname !== "/v1/assistant") {
      return json({ error: "Not found" }, 404);
    }

    if (!env.GATEWAY_API_KEY) {
      return json({ error: "Gateway authentication is not configured" }, 503);
    }

    const supplied = request.headers.get("authorization");
    if (supplied !== `Bearer ${env.GATEWAY_API_KEY}`) {
      return json({ error: "Unauthorized" }, 401);
    }

    const contentType = request.headers.get("content-type") || "";
    if (!contentType.toLowerCase().startsWith("application/json")) {
      return json({ error: "Content-Type must be application/json" }, 415);
    }

    const declaredLength = Number(request.headers.get("content-length"));
    if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_BYTES) {
      return json({ error: "Request body is too large" }, 413);
    }

    let raw;
    try {
      raw = await request.text();
    } catch {
      return json({ error: "Unable to read request body" }, 400);
    }

    if (new TextEncoder().encode(raw).byteLength > MAX_BODY_BYTES) {
      return json({ error: "Request body is too large" }, 413);
    }

    let body;
    try {
      body = JSON.parse(raw);
    } catch {
      return json({ error: "Invalid JSON" }, 400);
    }

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
