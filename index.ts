export interface Env {
  SUPABASE_URL: string;
  SUPABASE_SERVICE_ROLE_KEY: string;
  SUPABASE_ANON_KEY: string;
  NP_OWNER_USER_IDS: string; // comma-separated Supabase Auth UUIDs
  NP_ENROLLMENT_TTL_SECONDS?: string;
  NP_NODE_LEASE_SECONDS?: string;
}

type Enrollment = {
  id: string;
  name: string;
  provider: string;
  endpoint_url: string;
  model_id: string;
  capabilities: string[];
  public_key: string;
  session_id: string;
  status: "pending" | "approved" | "rejected" | "expired";
  created_at: string;
  expires_at: string;
  approved_by?: string | null;
  approved_at?: string | null;
  last_seen_at?: string | null;
};

const cors: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
  "Access-Control-Max-Age": "86400",
};

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...cors },
  });
}

function uuid(value: unknown): value is string {
  return typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function supabaseHeaders(env: Env): HeadersInit {
  return {
    "Content-Type": "application/json",
    apikey: env.SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
  };
}

async function db(env: Env, path: string, init: RequestInit = {}): Promise<Response> {
  return fetch(`${env.SUPABASE_URL.replace(/\/$/, "")}/rest/v1/${path}`, {
    ...init,
    headers: { ...supabaseHeaders(env), ...(init.headers || {}) },
  });
}

async function currentUser(request: Request, env: Env): Promise<{ id: string } | null> {
  const token = request.headers.get("Authorization")?.replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const response = await fetch(`${env.SUPABASE_URL.replace(/\/$/, "")}/auth/v1/user`, {
    headers: { apikey: env.SUPABASE_ANON_KEY, Authorization: `Bearer ${token}` },
  });
  if (!response.ok) return null;
  const user = await response.json() as { id?: string };
  return uuid(user.id) ? { id: user.id } : null;
}

async function requireOwner(request: Request, env: Env): Promise<{ id: string } | null> {
  const user = await currentUser(request, env);
  if (!user) return null;
  const owners = (env.NP_OWNER_USER_IDS || "").split(",").map(x => x.trim()).filter(Boolean);
  return owners.includes(user.id) ? user : null;
}

function safeTunnel(input: unknown): string | null {
  if (typeof input !== "string" || input.length > 500) return null;
  try {
    const url = new URL(input);
    const hostOk = url.hostname === "trycloudflare.com" ||
      url.hostname.endsWith(".trycloudflare.com");
    if (url.protocol !== "https:" || !hostOk || url.username || url.password || url.port) return null;
    return url.origin;
  } catch { return null; }
}

async function readJson(request: Request): Promise<any | null> {
  try { return await request.json(); } catch { return null; }
}

async function verifyEd25519(publicKeyB64: string, message: string, signatureB64: string): Promise<boolean> {
  try {
    const decode = (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
    const key = await crypto.subtle.importKey(
      "raw", decode(publicKeyB64), { name: "Ed25519" }, false, ["verify"]
    );
    return await crypto.subtle.verify(
      "Ed25519", key, decode(signatureB64), new TextEncoder().encode(message)
    );
  } catch { return false; }
}

async function handle(request: Request, env: Env): Promise<Response> {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.method === "GET" && path === "/health") {
    return json({ status: "ok", service: "nexapulse-compute-api", version: "1.0.0" });
  }

  if (request.method === "POST" && path === "/v1/enrollments") {
    const body = await readJson(request);
    if (!body || !body.name || !body.provider || !body.model_id ||
        typeof body.session_id !== "string" || body.session_id.length < 12 ||
        typeof body.public_key !== "string") return json({ error: "Missing or invalid enrollment fields." }, 400);

    const endpoint = safeTunnel(body.endpoint_url);
    if (!endpoint) return json({ error: "Endpoint must be an HTTPS Cloudflare Quick Tunnel (*.trycloudflare.com)." }, 400);

    // Verify that the submitted tunnel currently serves this exact notebook session.
    let health: Response;
    try {
      health = await fetch(`${endpoint}/health`, { signal: AbortSignal.timeout(8000) });
    } catch { return json({ error: "Could not reach notebook health endpoint." }, 400); }
    if (!health.ok) return json({ error: "Notebook health endpoint returned an error." }, 400);
    const healthBody = await health.json().catch(() => ({})) as any;
    if (healthBody?.service !== "nexapulse-compute-node" ||
        healthBody?.session_id !== body.session_id) {
      return json({ error: "Notebook health check did not match the submitted session." }, 400);
    }

    const ttl = Math.min(3600, Math.max(300, Number(env.NP_ENROLLMENT_TTL_SECONDS || 900)));
    const row: Enrollment = {
      id: crypto.randomUUID(),
      name: String(body.name).slice(0, 100),
      provider: String(body.provider).slice(0, 40),
      endpoint_url: endpoint,
      model_id: String(body.model_id).slice(0, 200),
      capabilities: Array.isArray(body.capabilities)
        ? body.capabilities.filter((x: unknown) => typeof x === "string").slice(0, 20)
        : ["text"],
      public_key: body.public_key,
      session_id: body.session_id,
      status: "pending",
      created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + ttl * 1000).toISOString(),
    };
    const response = await db(env, "compute_enrollments", {
      method: "POST",
      headers: { Prefer: "return=representation" },
      body: JSON.stringify(row),
    });
    if (!response.ok) {
      console.error("Enrollment insert failed", response.status, await response.text());
      return json({ error: "Could not save enrollment." }, 502);
    }
    return json({ enrollment_id: row.id, status: "pending", expires_at: row.expires_at }, 201);
  }

  if (path.startsWith("/v1/")) {
    const owner = await requireOwner(request, env);
    if (!owner) return json({ error: "Unauthorized." }, 401);

    if (request.method === "GET" && path === "/v1/enrollments") {
      const response = await db(env, "compute_enrollments?select=id,name,provider,model_id,capabilities,status,created_at,expires_at,last_seen_at&order=created_at.desc&limit=100");
      if (!response.ok) return json({ error: "Could not load enrollments." }, 502);
      return new Response(await response.text(), { headers: { "Content-Type": "application/json", ...cors } });
    }

    const approveMatch = path.match(/^\/v1\/enrollments\/([0-9a-f-]+)\/approve$/i);
    if (request.method === "POST" && approveMatch) {
      const id = approveMatch[1];
      const now = new Date().toISOString();
      const response = await db(env, `compute_enrollments?id=eq.${id}&status=eq.pending`, {
        method: "PATCH",
        headers: { Prefer: "return=representation" },
        body: JSON.stringify({ status: "approved", approved_by: owner.id, approved_at: now }),
      });
      const rows = response.ok ? await response.json() as any[] : [];
      if (!response.ok) return json({ error: "Approval failed." }, 502);
      if (!rows.length) return json({ error: "Pending enrollment not found; it may have expired or already been handled." }, 404);
      return json({ id, status: "approved", approved_at: now });
    }

    const rejectMatch = path.match(/^\/v1\/enrollments\/([0-9a-f-]+)\/reject$/i);
    if (request.method === "POST" && rejectMatch) {
      const response = await db(env, `compute_enrollments?id=eq.${rejectMatch[1]}&status=eq.pending`, {
        method: "PATCH",
        headers: { Prefer: "return=representation" },
        body: JSON.stringify({ status: "rejected" }),
      });
      if (!response.ok) return json({ error: "Rejection failed." }, 502);
      const rows = await response.json() as any[];
      return rows.length ? json({ status: "rejected" }) : json({ error: "Pending enrollment not found." }, 404);
    }
  }

  if (request.method === "POST" && path === "/v1/nodes/heartbeat") {
    const body = await readJson(request);
    if (!body || !uuid(body.enrollment_id) || typeof body.timestamp !== "number" ||
        typeof body.signature !== "string") return json({ error: "Invalid heartbeat." }, 400);
    if (Math.abs(Date.now() - body.timestamp) > 60_000) return json({ error: "Heartbeat timestamp outside allowed window." }, 401);

    const lookup = await db(env, `compute_enrollments?id=eq.${body.enrollment_id}&select=id,public_key,status`);
    if (!lookup.ok) return json({ error: "Could not verify node." }, 502);
    const rows = await lookup.json() as any[];
    const node = rows[0];
    if (!node || node.status !== "approved") return json({ error: "Node is not approved." }, 403);
    const valid = await verifyEd25519(node.public_key, `${body.enrollment_id}:${body.timestamp}`, body.signature);
    if (!valid) return json({ error: "Invalid node signature." }, 401);

    const lease = Math.min(600, Math.max(60, Number(env.NP_NODE_LEASE_SECONDS || 180)));
    const now = new Date().toISOString();
    const expires = new Date(Date.now() + lease * 1000).toISOString();
    const update = await db(env, `compute_enrollments?id=eq.${body.enrollment_id}`, {
      method: "PATCH",
      body: JSON.stringify({ last_seen_at: now, expires_at: expires }),
    });
    if (!update.ok) return json({ error: "Heartbeat update failed." }, 502);
    return json({ status: "ok", lease_expires_at: expires });
  }

  return json({ error: "Not found." }, 404);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try { return await handle(request, env); }
    catch (error) {
      console.error("Unhandled Worker error", error);
      return json({ error: "Internal server error." }, 500);
    }
  },
};
