const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });

async function callOpenAI(env, messages) {
  if (!env.OPENAI_API_KEY) throw new Error("OPENAI_API_KEY is not configured");

  const response = await fetch("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: {
      authorization: `Bearer ${env.OPENAI_API_KEY}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      model: env.OPENAI_MODEL || "gpt-5",
      input: messages,
    }),
  });

  if (!response.ok) throw new Error(`OpenAI request failed (${response.status})`);
  return response.json();
}

async function callOpenRouter(env, messages) {
  if (!env.OPENROUTER_API_KEY) throw new Error("OPENROUTER_API_KEY is not configured");

  const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
    method: "POST",
    headers: {
      authorization: `Bearer ${env.OPENROUTER_API_KEY}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      model: env.OPENROUTER_MODEL || "openai/gpt-5",
      messages,
    }),
  });

  if (!response.ok) throw new Error(`OpenRouter request failed (${response.status})`);
  return response.json();
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

    if (env.GATEWAY_API_KEY) {
      const supplied = request.headers.get("authorization");
      if (supplied !== `Bearer ${env.GATEWAY_API_KEY}`) {
        return json({ error: "Unauthorized" }, 401);
      }
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: "Invalid JSON" }, 400);
    }

    const messages = Array.isArray(body.messages) ? body.messages : null;
    if (!messages || messages.length === 0) {
      return json({ error: "messages must be a non-empty array" }, 400);
    }

    try {
      const primary = await callOpenAI(env, messages);
      return json({ provider: "openai", result: primary });
    } catch (primaryError) {
      try {
        const fallback = await callOpenRouter(env, messages);
        return json({ provider: "openrouter", fallback: true, result: fallback });
      } catch {
        return json({ error: "AI providers unavailable" }, 503);
      }
    }
  },
};
