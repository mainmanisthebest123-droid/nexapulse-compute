export interface Env {
  SUPABASE_URL: string;
  SUPABASE_SERVICE_ROLE_KEY: string;
  SUPABASE_ANON_KEY: string;
  NP_OWNER_USER_IDS: string;
  NP_ALLOWED_ORIGINS?: string;
  NP_ENROLLMENT_TTL_SECONDS?: string;
  NP_NODE_LEASE_SECONDS?: string;
}

type Enrollment = {
  id: string; name: string; provider: string; endpoint_url: string; model_id: string;
  capabilities: string[]; public_key: string; session_id: string | null; inference_token?: string;
  status: "pending" | "approved" | "rejected" | "expired";
  created_at: string; expires_at: string; approved_by?: string | null;
  approved_at?: string | null; last_seen_at?: string | null; runtime_metadata?: Record<string, unknown>;
};

type Owner = { id: string };
const API_VERSION = "1.3.0";
const DEFAULT_ORIGINS = ["https://compute-85b.pages.dev"];

function allowedOrigins(env: Env): string[] {
  return (env.NP_ALLOWED_ORIGINS || DEFAULT_ORIGINS.join(","))
    .split(",").map(x => x.trim()).filter(Boolean);
}
function corsHeaders(request: Request, env: Env): Headers {
  const h = new Headers({
    "Vary": "Origin", "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Max-Age": "86400", "Cache-Control": "no-store",
  });
  const origin = request.headers.get("Origin");
  if (origin && allowedOrigins(env).includes(origin)) h.set("Access-Control-Allow-Origin", origin);
  return h;
}
function json(request: Request, env: Env, data: unknown, status = 200): Response {
  const headers = corsHeaders(request, env);
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(data), { status, headers });
}
function uuid(v: unknown): v is string {
  return typeof v === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(v);
}
function base64Bytes(value: string): Uint8Array | null {
  try {
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return null;
    return Uint8Array.from(atob(value), c => c.charCodeAt(0));
  } catch { return null; }
}
function safeTunnel(value: unknown): string | null {
  if (typeof value !== "string" || value.length > 500) return null;
  try {
    const u = new URL(value);
    const host = u.hostname.toLowerCase();
    if (u.protocol !== "https:" || !(host.endsWith(".trycloudflare.com")) ||
        u.username || u.password || u.port || u.search || u.hash) return null;
    return u.origin;
  } catch { return null; }
}
async function readJson(request: Request, maxBytes = 32_000): Promise<any | null> {
  const length = Number(request.headers.get("Content-Length") || 0);
  if (length > maxBytes) return null;
  try { return await request.json(); } catch { return null; }
}
function supabaseHeaders(env: Env): HeadersInit {
  return { "Content-Type": "application/json", apikey: env.SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}` };
}
async function db(env: Env, path: string, init: RequestInit = {}): Promise<Response> {
  return fetch(`${env.SUPABASE_URL.replace(/\/$/, "")}/rest/v1/${path}`, {
    ...init, headers: { ...supabaseHeaders(env), ...(init.headers || {}) },
  });
}
async function currentUser(request: Request, env: Env): Promise<Owner | null> {
  const auth = request.headers.get("Authorization") || "";
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  const r = await fetch(`${env.SUPABASE_URL.replace(/\/$/, "")}/auth/v1/user`, {
    headers: { apikey: env.SUPABASE_ANON_KEY, Authorization: `Bearer ${match[1]}` },
  });
  if (!r.ok) return null;
  const user = await r.json() as { id?: string };
  return uuid(user.id) ? { id: user.id } : null;
}
async function requireOwner(request: Request, env: Env): Promise<Owner | null> {
  const user = await currentUser(request, env);
  if (!user) return null;
  const ids = (env.NP_OWNER_USER_IDS || "").split(",").map(x => x.trim()).filter(Boolean);
  return ids.includes(user.id) ? user : null;
}
async function verifySignature(publicKey: string, message: string, signature: string): Promise<boolean> {
  const keyBytes = base64Bytes(publicKey), sigBytes = base64Bytes(signature);
  if (!keyBytes || keyBytes.length !== 32 || !sigBytes || sigBytes.length !== 64) return false;
  try {
    const key = await crypto.subtle.importKey("raw", keyBytes, { name: "Ed25519" }, false, ["verify"]);
    return crypto.subtle.verify("Ed25519", key, sigBytes, new TextEncoder().encode(message));
  } catch { return false; }
}
function safeRuntimeMetadata(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const input = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  const textFields = ["gpu_name", "runtime_version", "framework", "model_state"];
  for (const key of textFields) {
    const v = input[key];
    if (typeof v === "string") out[key] = v.slice(0, 120);
  }
  const numberFields = ["gpu_count", "cpu_count", "ram_gb", "vram_gb"];
  for (const key of numberFields) {
    const v = input[key];
    if (typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 4096) out[key] = v;
  }
  if (typeof input.model_loaded === "boolean") out.model_loaded = input.model_loaded;
  return out;
}
function secondsSetting(value: string | undefined, fallback: number, min: number, max: number): number {
  const n = Number(value ?? fallback);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, Math.floor(n))) : fallback;
}
async function expirePending(env: Env): Promise<void> {
  const now = encodeURIComponent(new Date().toISOString());
  await db(env, `compute_enrollments?status=eq.pending&expires_at=lt.${now}`, {
    method: "PATCH", body: JSON.stringify({ status: "expired" }),
  });
}
async function getEnrollments(env: Env): Promise<Enrollment[] | null> {
  await expirePending(env);
  const q = new URLSearchParams({
    select: "id,name,provider,endpoint_url,model_id,capabilities,status,created_at,expires_at,approved_by,approved_at,last_seen_at,runtime_metadata",
    order: "created_at.desc", limit: "100",
  });
  const r = await db(env, `compute_enrollments?${q}`);
  if (!r.ok) return null;
  return await r.json() as Enrollment[];
}
function isOnline(n: Enrollment, now = Date.now()): boolean {
  return n.status === "approved" && !!n.last_seen_at && Date.parse(n.expires_at) > now;
}
async function handle(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url), path = url.pathname;
  const origin = request.headers.get("Origin");
  if (origin && !allowedOrigins(env).includes(origin)) return json(request, env, { error: "Origin not allowed." }, 403);
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request, env) });

  if (request.method === "GET" && path === "/health") {
    return json(request, env, { status: "ok", service: "nexapulse-compute-api", version: API_VERSION });
  }

  // Notebook enrollment is public, but the tunnel must prove it is serving this session.
  if (request.method === "POST" && path === "/v1/enrollments") {
    const body = await readJson(request);
    if (!body || typeof body.name !== "string" || !body.name.trim() ||
        typeof body.provider !== "string" || typeof body.model_id !== "string" ||
        typeof body.session_id !== "string" || body.session_id.length < 12 || body.session_id.length > 128 ||
        typeof body.public_key !== "string" || !base64Bytes(body.public_key) || base64Bytes(body.public_key)!.length !== 32 ||
        typeof body.inference_token !== "string" || body.inference_token.length < 32 || body.inference_token.length > 256 ||
        (body.models !== undefined && (!Array.isArray(body.models) || body.models.length < 1 || body.models.length > 32))) {
      return json(request, env, { error: "Missing or invalid enrollment fields." }, 400);
    }
    const endpoint = safeTunnel(body.endpoint_url);
    if (!endpoint) return json(request, env, { error: "Endpoint must be an HTTPS Cloudflare Quick Tunnel hostname." }, 400);
    let health: Response;
    try {
      health = await fetch(`${endpoint}/health`, { redirect: "manual", signal: AbortSignal.timeout(8000) });
    } catch { return json(request, env, { error: "Could not reach notebook health endpoint." }, 400); }
    if (health.status >= 300 && health.status < 400) return json(request, env, { error: "Notebook health endpoint redirects are not accepted." }, 400);
    if (!health.ok) return json(request, env, { error: "Notebook health endpoint returned an error." }, 400);
    const hb = await health.json().catch(() => ({})) as any;
    if (hb?.service !== "nexapulse-compute-node" || hb?.session_id !== body.session_id) {
      return json(request, env, { error: "Notebook health check did not match this session." }, 400);
    }
    const now = new Date(), ttl = secondsSetting(env.NP_ENROLLMENT_TTL_SECONDS, 900, 300, 3600);
    const row: Enrollment = {
      id: crypto.randomUUID(), name: body.name.trim().slice(0, 100), provider: body.provider.slice(0, 40),
      endpoint_url: endpoint, model_id: body.model_id.slice(0, 200),
      capabilities: Array.isArray(body.capabilities) ? body.capabilities.filter((x: unknown) => typeof x === "string").slice(0, 20) : ["text"],
      public_key: body.public_key, session_id: body.session_id, inference_token: body.inference_token, status: "pending",
      created_at: now.toISOString(), expires_at: new Date(now.getTime() + ttl * 1000).toISOString(),
    };
    const r = await db(env, "compute_enrollments", { method: "POST", headers: { Prefer: "return=representation" }, body: JSON.stringify(row) });
    if (!r.ok) { console.error("Enrollment insert failed", r.status, await r.text()); return json(request, env, { error: "Could not save enrollment." }, 502); }
    const suppliedModels = Array.isArray(body.models) ? body.models : [{ model_id: body.model_id, display_name: body.model_id, capabilities: row.capabilities }];
    const cleanModels = suppliedModels.filter((m: any) => m && typeof m.model_id === "string" && m.model_id.trim()).map((m: any, i: number) => ({
      enrollment_id: row.id, model_id: m.model_id.trim().slice(0, 200),
      display_name: typeof m.display_name === "string" ? m.display_name.slice(0, 120) : m.model_id.trim().slice(0, 120),
      capabilities: Array.isArray(m.capabilities) ? m.capabilities.filter((x: unknown) => typeof x === "string").slice(0, 20) : ["text", "chat_completions"],
      is_default: m.model_id === row.model_id || i === 0, status: "available",
    }));
    if (!cleanModels.length) {
      await db(env, `compute_enrollments?id=eq.${row.id}`, { method: "DELETE" });
      return json(request, env, { error: "Enrollment did not include any valid model IDs." }, 400);
    }
    const modelInsert = await db(env, "compute_runtime_models", { method: "POST", body: JSON.stringify(cleanModels) });
    if (!modelInsert.ok) {
      console.error("Runtime model registration failed", modelInsert.status, await modelInsert.text());
      await db(env, `compute_enrollments?id=eq.${row.id}`, { method: "DELETE" });
      return json(request, env, { error: "Could not register the models for this runtime." }, 502);
    }
    return json(request, env, { enrollment_id: row.id, status: "pending", expires_at: row.expires_at, models: cleanModels.map(m => m.model_id) }, 201);
  }

  // Signed heartbeat must be handled before owner authentication.
  if (request.method === "POST" && path === "/v1/nodes/heartbeat") {
    const body = await readJson(request);
    if (!body || !uuid(body.enrollment_id) || typeof body.timestamp !== "number" || typeof body.signature !== "string") {
      return json(request, env, { error: "Invalid heartbeat." }, 400);
    }
    if (Math.abs(Date.now() - body.timestamp) > 60_000) return json(request, env, { error: "Heartbeat timestamp outside allowed window." }, 401);
    const q = new URLSearchParams({ id: `eq.${body.enrollment_id}`, select: "id,public_key,status,session_id" });
    const lookup = await db(env, `compute_enrollments?${q}`);
    if (!lookup.ok) return json(request, env, { error: "Could not verify node." }, 502);
    const node = (await lookup.json() as any[])[0];
    if (!node || node.status !== "approved") return json(request, env, { error: "Node is not approved." }, 403);
    if (body.session_id !== undefined && body.session_id !== node.session_id) return json(request, env, { error: "Session identity mismatch." }, 401);
    if (!await verifySignature(node.public_key, `${body.enrollment_id}:${body.timestamp}`, body.signature)) {
      return json(request, env, { error: "Invalid node signature." }, 401);
    }
    const now = new Date(), lease = secondsSetting(env.NP_NODE_LEASE_SECONDS, 180, 60, 600);
    const expires = new Date(now.getTime() + lease * 1000).toISOString();
    const update: Record<string, unknown> = { last_seen_at: now.toISOString(), expires_at: expires };
    if (body.runtime_metadata !== undefined) update.runtime_metadata = safeRuntimeMetadata(body.runtime_metadata);
    const patch = await db(env, `compute_enrollments?id=eq.${body.enrollment_id}&status=eq.approved`, {
      method: "PATCH", body: JSON.stringify(update),
    });
    if (!patch.ok) return json(request, env, { error: "Heartbeat update failed." }, 502);
    return json(request, env, { status: "ok", lease_expires_at: expires });
  }

  if (request.method === "DELETE" && path === "/v1/account") {
    const user = await currentUser(request, env);
    if (!user) return json(request, env, { error: "A valid signed-in session is required." }, 401);
    const deleted = await fetch(`${env.SUPABASE_URL.replace(/\/$/, "")}/auth/v1/admin/users/${user.id}`, {
      method: "DELETE", headers: supabaseHeaders(env),
    });
    if (!deleted.ok) {
      console.error("Self-service account deletion failed", deleted.status, await deleted.text());
      return json(request, env, { error: "Could not delete this account. Please contact support." }, 502);
    }
    return json(request, env, { status: "deleted" });
  }

  if (!path.startsWith("/v1/")) return json(request, env, { error: "Not found." }, 404);
  const owner = await requireOwner(request, env);
  if (!owner) return json(request, env, { error: "Owner authentication required." }, 401);

  if (request.method === "GET" && path === "/v1/enrollments") {
    const rows = await getEnrollments(env);
    return rows ? json(request, env, rows) : json(request, env, { error: "Could not load enrollments." }, 502);
  }

  if (request.method === "GET" && path === "/v1/nodes") {
    const rows = await getEnrollments(env);
    if (!rows) return json(request, env, { error: "Could not load nodes." }, 502);
    const nodes = rows.filter(n => n.status === "approved").map(n => ({
      id: n.id, name: n.name, provider: n.provider, model_id: n.model_id, capabilities: n.capabilities,
      status: isOnline(n) ? "online" : "offline", last_seen_at: n.last_seen_at || null,
      lease_expires_at: n.expires_at, created_at: n.created_at, runtime_metadata: n.runtime_metadata || {},
    }));
    return json(request, env, { nodes, count: nodes.length });
  }

  if (request.method === "GET" && path === "/v1/models") {
    const rows = await getEnrollments(env);
    if (!rows) return json(request, env, { error: "Could not load models." }, 502);
    const online = rows.filter(n => isOnline(n));
    const ids = online.map(n => n.id);
    let registry: any[] = [];
    if (ids.length) {
      const q = new URLSearchParams({ select: "id,enrollment_id,model_id,display_name,capabilities,status,is_default", enrollment_id: `in.(${ids.join(",")})`, status: "eq.available" });
      const rr = await db(env, `compute_runtime_models?${q}`);
      if (!rr.ok) return json(request, env, { error: "Could not load runtime model registry." }, 502);
      registry = await rr.json() as any[];
    }
    // Legacy approved runtimes are represented by their enrollment.model_id.
    const entries = registry.length ? registry : online.map(n => ({ enrollment_id: n.id, model_id: n.model_id, display_name: n.model_id, capabilities: n.capabilities, status: "available" }));
    const models = [...new Map(entries.map(m => [m.model_id, {
      id: m.model_id, name: m.display_name || m.model_id, status: "available",
      runtime_count: new Set(entries.filter(x => x.model_id === m.model_id).map(x => x.enrollment_id)).size,
      capabilities: [...new Set(entries.filter(x => x.model_id === m.model_id).flatMap(x => x.capabilities || []))],
    }])).values()];
    return json(request, env, { models, count: models.length });
  }

  if (request.method === "GET" && path === "/v1/dashboard/summary") {
    const rows = await getEnrollments(env);
    if (!rows) return json(request, env, { error: "Could not load dashboard summary." }, 502);
    const online = rows.filter(n => isOnline(n));
    const pending = rows.filter(n => n.status === "pending" && Date.parse(n.expires_at) > Date.now()).length;
    const models = new Set(online.map(n => n.model_id));
    return json(request, env, {
      generated_at: new Date().toISOString(),
      runtimes: { online: online.length, offline: rows.filter(n => n.status === "approved").length - online.length, pending },
      models: { available: models.size, configured: new Set(rows.filter(n => n.status === "approved").map(n => n.model_id)).size },
      projects: { count: null, status: "not_connected" },
      service: { status: "operational", version: API_VERSION },
    });
  }

  const action = path.match(/^\/v1\/enrollments\/([0-9a-f-]+)\/(approve|reject)$/i);
  if (request.method === "POST" && action && uuid(action[1])) {
    const id = action[1], verb = action[2].toLowerCase();
    const now = new Date().toISOString();
    const filter = `compute_enrollments?id=eq.${id}&status=eq.pending&expires_at=gt.${encodeURIComponent(now)}`;
    const patch = verb === "approve"
      ? { status: "approved", approved_by: owner.id, approved_at: now }
      : { status: "rejected" };
    const r = await db(env, filter, { method: "PATCH", headers: { Prefer: "return=representation" }, body: JSON.stringify(patch) });
    if (!r.ok) return json(request, env, { error: `Enrollment ${verb} failed.` }, 502);
    const changed = await r.json() as any[];
    if (!changed.length) return json(request, env, { error: "Active pending enrollment not found; it may have expired or already been handled." }, 404);
    return json(request, env, { id, status: verb === "approve" ? "approved" : "rejected", ...(verb === "approve" ? { approved_at: now } : {}) });
  }

  // Owner-authenticated browser inference. The Worker selects an approved,
  // unexpired runtime and forwards only through its enrolled HTTPS tunnel.
  if (request.method === "POST" && path === "/v1/chat/completions") {
    const body = await readJson(request, 64_000);
    if (!body || !Array.isArray(body.messages) || body.messages.length < 1 || body.messages.length > 80 ||
        body.messages.some((m: any) => !m || typeof m.role !== "string" || typeof m.content !== "string" || m.content.length > 24_000)) {
      return json(request, env, { error: "Invalid chat request. Provide 1–80 messages with string roles and content." }, 400);
    }
    const requestedModel = typeof body.model === "string" ? body.model.slice(0, 200) : "";
    if (!requestedModel) return json(request, env, { error: "Select a model ID for this chat request." }, 400);
    const modelQ = new URLSearchParams({ select: "enrollment_id,model_id", model_id: `eq.${requestedModel}`, status: "eq.available" });
    const modelLookup = await db(env, `compute_runtime_models?${modelQ}`);
    if (!modelLookup.ok) return json(request, env, { error: "Could not locate this model in the runtime registry." }, 502);
    const registered = await modelLookup.json() as any[];
    if (!registered.length) return json(request, env, { error: `Model ${requestedModel} is not registered on any runtime.`, code: "model_not_registered" }, 404);
    const runtimeIds = [...new Set(registered.map(x => x.enrollment_id).filter(uuid))];
    const now = encodeURIComponent(new Date().toISOString());
    const q = new URLSearchParams({
      select: "id,name,endpoint_url,model_id,inference_token,last_seen_at,expires_at,status",
      id: `in.(${runtimeIds.join(",")})`, status: "eq.approved", expires_at: `gt.${now}`,
      order: "last_seen_at.desc.nullslast", limit: "30",
    });
    const lookup = await db(env, `compute_enrollments?${q}`);
    if (!lookup.ok) return json(request, env, { error: "Could not locate an available model runtime." }, 502);
    const candidates = await lookup.json() as any[];
    const node = candidates.find(n => n.last_seen_at && Date.now() - Date.parse(n.last_seen_at) < 180_000 &&
      typeof n.inference_token === "string" && n.inference_token.length >= 32 && safeTunnel(n.endpoint_url));
    if (!node) return json(request, env, {
      error: requestedModel ? `No online approved runtime is available for model ${requestedModel}.` : "No online approved model runtime is available.",
      code: "model_runtime_unavailable",
    }, 503);
    const endpoint = safeTunnel(node.endpoint_url);
    if (!endpoint) return json(request, env, { error: "The selected runtime endpoint is invalid." }, 502);
    const forwardBody = {
      model: requestedModel,
      messages: body.messages,
      max_tokens: Math.max(1, Math.min(Number(body.max_tokens) || 512, 2048)),
      temperature: Math.max(0, Math.min(Number.isFinite(Number(body.temperature)) ? Number(body.temperature) : 0.7, 2)),
      top_p: Math.max(0.05, Math.min(Number.isFinite(Number(body.top_p)) ? Number(body.top_p) : 0.9, 1)),
    };
    try {
      const upstream = await fetch(`${endpoint}/v1/chat/completions`, {
        method: "POST", redirect: "manual", signal: AbortSignal.timeout(120_000),
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${node.inference_token}` },
        body: JSON.stringify(forwardBody),
      });
      if (upstream.status >= 300 && upstream.status < 400) return json(request, env, { error: "Runtime endpoint redirects are not accepted." }, 502);
      const result = await upstream.json().catch(() => null);
      if (!upstream.ok || !result || !Array.isArray(result.choices)) {
        console.error("Runtime inference failed", upstream.status);
        return json(request, env, { error: "The selected model runtime could not complete inference.", upstream_status: upstream.status }, 502);
      }
      return json(request, env, result, 200);
    } catch (error) {
      console.error("Runtime inference request failed", error);
      return json(request, env, { error: "The model runtime did not respond before the request timed out or the connection failed." }, 504);
    }
  }
  return json(request, env, { error: "Not found." }, 404);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY || !env.SUPABASE_ANON_KEY || !env.NP_OWNER_USER_IDS) {
        return json(request, env, { error: "Worker configuration is incomplete." }, 500);
      }
      return await handle(request, env);
    } catch (error) {
      console.error("Unhandled Worker error", error);
      return json(request, env, { error: "Internal server error." }, 500);
    }
  },
};
