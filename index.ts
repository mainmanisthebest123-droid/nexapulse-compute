export interface Env {
  SUPABASE_URL: string;
  SUPABASE_SERVICE_ROLE_KEY: string;
  NP_CONTROL_TOKEN: string;
  NP_NODE_API_KEY: string;
}

type ComputeNode = {
  id: string;
  name: string;
  provider: string;
  endpoint_url: string;
  model_id: string;
  capabilities: string[];
  status: string;
  last_seen_at: string;
};

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
  });
}

function getBearerToken(request: Request): string | null {
  const header = request.headers.get("Authorization");
  if (!header) return null;

  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : null;
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

function requireControlAuth(request: Request, env: Env): boolean {
  const token = getBearerToken(request);
  return !!token && constantTimeEqual(token, env.NP_CONTROL_TOKEN);
}

function safeEndpoint(value: string): string {
  let url: URL;

  try {
    url = new URL(value);
  } catch {
    throw new Error("Invalid notebook endpoint URL.");
  }

  const allowedHosts = [
    "ngrok-free.app",
    "ngrok.app",
    "ngrok-free.dev",
    "ngrok.io",
  ];

  const allowedHost = allowedHosts.some(
    (host) =>
      url.hostname === host ||
      url.hostname.endsWith("." + host)
  );

  if (
    url.protocol !== "https:" ||
    !allowedHost ||
    url.username ||
    url.password ||
    url.port
  ) {
    throw new Error(
      "Endpoint must be an HTTPS ngrok URL on an approved ngrok domain."
    );
  }

  return url.origin;
}

function supabaseHeaders(env: Env): HeadersInit {
  return {
    "Content-Type": "application/json",
    apikey: env.SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
  };
}

function supabaseUrl(env: Env, path: string): string {
  return `${env.SUPABASE_URL.replace(/\/$/, "")}/rest/v1/${path}`;
}

async function supabaseRequest(
  env: Env,
  path: string,
  init: RequestInit = {}
): Promise<Response> {
  return fetch(supabaseUrl(env, path), {
    ...init,
    headers: {
      ...supabaseHeaders(env),
      ...(init.headers || {}),
    },
  });
}

async function handleRequest(
  request: Request,
  env: Env
): Promise<Response> {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: corsHeaders,
    });
  }

  const url = new URL(request.url);
  const path = url.pathname;

  // Health check
  if (request.method === "GET" && path === "/health") {
    return json({
      status: "ok",
      service: "nexapulse-compute-api",
      version: "0.2.0",
    });
  }

  // Protect all versioned API routes
  if (
    path.startsWith("/v1/") &&
    !requireControlAuth(request, env)
  ) {
    return json({ error: "Unauthorized" }, 401);
  }

  // Register a compute node
  if (
    request.method === "POST" &&
    path === "/v1/nodes/register"
  ) {
    let body: any;

    try {
      body = await request.json();
    } catch {
      return json({ error: "Invalid JSON body." }, 400);
    }

    if (
      !body?.name ||
      !body?.provider ||
      !body?.endpoint_url ||
      !body?.model_id
    ) {
      return json(
        { error: "Missing required node registration fields." },
        400
      );
    }

    let endpoint: string;

    try {
      endpoint = safeEndpoint(body.endpoint_url);
    } catch (error) {
      return json(
        {
          error:
            error instanceof Error
              ? error.message
              : "Invalid endpoint.",
        },
        400
      );
    }

    const node: ComputeNode = {
      id: crypto.randomUUID(),
      name: String(body.name).slice(0, 120),
      provider: String(body.provider).slice(0, 40),
      endpoint_url: endpoint,
      model_id: String(body.model_id).slice(0, 200),
      capabilities: Array.isArray(body.capabilities)
        ? body.capabilities
            .filter((item: unknown) => typeof item === "string")
            .slice(0, 30)
        : ["text", "chat-completions"],
      status: "online",
      last_seen_at: new Date().toISOString(),
    };

    const response = await supabaseRequest(
      env,
      "compute_nodes",
      {
        method: "POST",
        headers: {
          Prefer: "return=representation",
        },
        body: JSON.stringify(node),
      }
    );

    if (!response.ok) {
      const detail = await response.text();

      console.error(
        "Node registration failed:",
        response.status,
        detail
      );

      return json(
        { error: "Database registration failed." },
        502
      );
    }

    return json(
      {
        success: true,
        node,
      },
      201
    );
  }

  // Node heartbeat
  if (
    request.method === "POST" &&
    path === "/v1/nodes/heartbeat"
  ) {
    let body: any;

    try {
      body = await request.json();
    } catch {
      return json({ error: "Invalid JSON body." }, 400);
    }

    if (!body?.node_id) {
      return json(
        { error: "node_id is required." },
        400
      );
    }

    const nodeId = encodeURIComponent(
      String(body.node_id)
    );

    const response = await supabaseRequest(
      env,
      `compute_nodes?id=eq.${nodeId}`,
      {
        method: "PATCH",
        headers: {
          Prefer: "return=representation",
        },
        body: JSON.stringify({
          status: "online",
          last_seen_at: new Date().toISOString(),
        }),
      }
    );

    if (!response.ok) {
      console.error(
        "Heartbeat update failed:",
        response.status,
        await response.text()
      );

      return json(
        { error: "Heartbeat update failed." },
        502
      );
    }

    const updated =
      (await response.json()) as ComputeNode[];

    if (!updated.length) {
      return json({ error: "Node not found." }, 404);
    }

    return json({
      success: true,
      node_id: body.node_id,
      status: "online",
    });
  }

  // List registered nodes
  if (
    request.method === "GET" &&
    path === "/v1/nodes"
  ) {
    const response = await supabaseRequest(
      env,
      "compute_nodes?select=id,name,provider,endpoint_url,model_id,capabilities,status,last_seen_at&order=last_seen_at.desc"
    );

    if (!response.ok) {
      console.error(
        "Node listing failed:",
        response.status,
        await response.text()
      );

      return json(
        { error: "Could not retrieve nodes." },
        502
      );
    }

    const nodes =
      (await response.json()) as ComputeNode[];

    return json({
      nodes: nodes || [],
      count: nodes?.length || 0,
    });
  }

  // OpenAI-compatible chat completions proxy
  if (
    request.method === "POST" &&
    path === "/v1/chat/completions"
  ) {
    let body: any;

    try {
      body = await request.json();
    } catch {
      return json({ error: "Invalid JSON body." }, 400);
    }

    if (!Array.isArray(body?.messages)) {
      return json(
        { error: "A messages array is required." },
        400
      );
    }

    const modelId = body.model
      ? String(body.model)
      : null;

    const query = new URLSearchParams({
      select:
        "id,name,endpoint_url,model_id,last_seen_at",
      status: "eq.online",
      order: "last_seen_at.desc",
      limit: "10",
    });

    if (modelId) {
      query.set("model_id", `eq.${modelId}`);
    }

    const nodeResponse = await supabaseRequest(
      env,
      `compute_nodes?${query.toString()}`
    );

    if (!nodeResponse.ok) {
      console.error(
        "Node lookup failed:",
        nodeResponse.status,
        await nodeResponse.text()
      );

      return json(
        { error: "Could not locate a model runtime." },
        502
      );
    }

    const nodes =
      (await nodeResponse.json()) as ComputeNode[];

    const now = Date.now();

    const node = nodes.find((candidate) => {
      const lastSeen = Date.parse(
        candidate.last_seen_at
      );

      return (
        Number.isFinite(lastSeen) &&
        now - lastSeen <= 180_000
      );
    });

    if (!node) {
      return json(
        {
          error:
            "No active runtime is available for this model.",
          code: "model_unavailable",
        },
        503
      );
    }

    const targetUrl =
      `${node.endpoint_url.replace(/\/$/, "")}` +
      `/v1/chat/completions`;

    let upstream: Response;

    try {
      upstream = await fetch(targetUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${env.NP_NODE_API_KEY}`,
        },
        body: JSON.stringify({
          ...body,
          model: node.model_id,
        }),
        signal: AbortSignal.timeout(120_000),
      });
    } catch (error) {
      console.error(
        "Notebook runtime request failed:",
        error
      );

      return json(
        {
          error: "Could not reach the notebook runtime.",
          code: "runtime_unreachable",
        },
        502
      );
    }

    const responseBody = await upstream.text();

    return new Response(responseBody, {
      status: upstream.status,
      headers: {
        ...corsHeaders,
        "Content-Type":
          upstream.headers.get("Content-Type") ||
          "application/json",
        "Cache-Control": "no-store",
      },
    });
  }

  return json(
    { error: "Route not found." },
    404
  );
}

export default {
  async fetch(
    request: Request,
    env: Env
  ): Promise<Response> {
    try {
      if (
        !env.SUPABASE_URL ||
        !env.SUPABASE_SERVICE_ROLE_KEY ||
        !env.NP_CONTROL_TOKEN ||
        !env.NP_NODE_API_KEY
      ) {
        console.error(
          "A required Worker binding is missing."
        );

        return json(
          { error: "Worker configuration is incomplete." },
          500
        );
      }

      return await handleRequest(request, env);
    } catch (error) {
      console.error(
        "Unhandled Worker error:",
        error
      );

      return json(
        { error: "Internal server error." },
        500
      );
    }
  },
};
