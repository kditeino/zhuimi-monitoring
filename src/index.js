const TYPE_LABELS = {
  1: "充值",
  2: "消费",
  3: "管理",
  4: "系统",
  5: "错误",
  6: "退款",
};

const LOG_WINDOW_DAYS = 3;
const LOG_CAP = 300;
const PAGE_SIZE = 100;
const MAX_LOG_PAGES = 3;
const CACHE_TTL_MS = 45000;
const TZ = "Asia/Shanghai";

let cache = { ts: 0, status: null, logs: null };

function envOf(runtime, key, fallback) {
  const baked = (typeof globalThis !== "undefined" && globalThis.BAKED_ENV) || {};
  const fromBaked = baked[key];
  const fromRt = runtime && runtime[key];
  const fromProc =
    typeof process !== "undefined" && process.env ? process.env[key] : undefined;
  const raw = (fromBaked && String(fromBaked).trim()) || fromRt || fromProc || fallback || "";
  return String(raw).trim();
}

function json(status, obj) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

function unauthorized() {
  return new Response("Unauthorized", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Zhuimi Monitor"',
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

function safeEqual(a, b) {
  const enc = new TextEncoder();
  const ba = enc.encode(String(a));
  const bb = enc.encode(String(b));
  const n = Math.max(ba.length, bb.length, 1);
  let diff = ba.length === bb.length ? 0 : 1;
  for (let i = 0; i < n; i++) {
    diff |= (ba[i] || 0) ^ (bb[i] || 0);
  }
  return diff === 0;
}

function checkBasic(request, user, password) {
  const header = request.headers.get("Authorization") || "";
  if (!header.startsWith("Basic ")) return false;
  try {
    const raw = atob(header.slice(6).trim());
    const idx = raw.indexOf(":");
    if (idx < 0) return false;
    return safeEqual(raw.slice(0, idx), user) && safeEqual(raw.slice(idx + 1), password);
  } catch {
    return false;
  }
}

function shanghaiParts(date) {
  const fmt = new Intl.DateTimeFormat("en-GB", {
    timeZone: TZ,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
  const map = {};
  for (const part of fmt.formatToParts(date)) {
    if (part.type !== "literal") map[part.type] = part.value;
  }
  return map;
}

function formatFull(date) {
  const p = shanghaiParts(date);
  return p.year + "-" + p.month + "-" + p.day + " " + p.hour + ":" + p.minute + ":" + p.second;
}

function formatShort(date) {
  const p = shanghaiParts(date);
  return p.month + "-" + p.day + " " + p.hour + ":" + p.minute + ":" + p.second;
}

function roundN(n, digits) {
  const f = 10 ** digits;
  return Math.round(Number(n) * f) / f;
}

function moneyFromQuota(quota, quotaPerUnit, usdRate) {
  const q = Number(quota || 0);
  const usd = quotaPerUnit ? q / quotaPerUnit : 0;
  const cny = usd * usdRate;
  return { quota: q, usd: roundN(usd, 6), cny: roundN(cny, 4) };
}

function parseOther(raw) {
  if (raw && typeof raw === "object" && !Array.isArray(raw)) return raw;
  if (typeof raw === "string" && raw.trim()) {
    try {
      const val = JSON.parse(raw);
      return val && typeof val === "object" && !Array.isArray(val) ? val : {};
    } catch {
      return {};
    }
  }
  return {};
}

function extractStatusCode(content) {
  const text = content || "";
  if (!text.includes("status_code=")) return null;
  try {
    const part = text.split("status_code=")[1] || "";
    const n = parseInt(part.split(",")[0].trim().split(/\s+/)[0], 10);
    return Number.isFinite(n) ? n : null;
  } catch {
    return null;
  }
}

function typeLabel(typ) {
  return TYPE_LABELS[typ] || ("类型" + typ);
}

function dedupeById(items) {
  const seen = new Set();
  const out = [];
  for (const it of items) {
    const lid = it && it.id;
    if (lid === undefined || lid === null) {
      out.push(it);
      continue;
    }
    const key = Number(lid);
    if (!Number.isFinite(key)) {
      out.push(it);
      continue;
    }
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(it);
  }
  return out;
}

function formatLog(item, quotaPerUnit, usdRate) {
  const created = Number(item.created_at || 0);
  const dt = created ? new Date(created * 1000) : null;
  const content = item.content || "";
  const other = parseOther(item.other);
  const typ = item.type;
  const money = moneyFromQuota(item.quota, quotaPerUnit, usdRate);
  let short = String(content).replace(/\n/g, " ").trim();
  if (short.length > 120) short = short.slice(0, 117) + "...";
  return {
    id: item.id,
    created_at: created,
    time: dt ? formatShort(dt) : "",
    time_full: dt ? formatFull(dt) : "",
    type: typ,
    type_label: typeLabel(typ),
    username: item.username || "",
    model: item.model_name || "",
    group: item.group || "",
    token_name: item.token_name || "",
    channel_name: item.channel_name || "",
    duration: item.use_time || 0,
    quota: money.quota,
    cost_cny: money.cny,
    cost_usd: money.usd,
    content_short: short,
    content,
    request_id: item.request_id || "",
    status_code: extractStatusCode(content),
    prompt_tokens: item.prompt_tokens || 0,
    completion_tokens: item.completion_tokens || 0,
    ip: item.ip || "",
    other,
  };
}

async function apiGet(base, token, userId, path, params) {
  const root = base.endsWith("/") ? base : base + "/";
  const url = new URL(path, root);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
    }
  }
  const res = await fetch(url.toString(), {
    method: "GET",
    redirect: "manual",
    headers: {
      Authorization: "Bearer " + token,
      "New-Api-User": String(userId),
      Accept: "application/json",
      "Content-Type": "application/json",
    },
  });
  if (!res.ok || (res.status >= 300 && res.status < 400)) {
    const err = new Error("upstream HTTP " + res.status);
    err.status = 502;
    throw err;
  }
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    const err = new Error("upstream invalid JSON");
    err.status = 502;
    throw err;
  }
}

async function fetchStatus(base, token, userId) {
  const data = await apiGet(base, token, userId, "/api/status", null);
  return data.data || {};
}

async function fetchLogsWindow(base, token, userId, startTs, endTs) {
  const items = [];
  let total = null;
  for (let page = 1; page <= MAX_LOG_PAGES; page++) {
    const payload = await apiGet(base, token, userId, "/api/log/", {
      p: page,
      page_size: PAGE_SIZE,
      start_timestamp: startTs,
      end_timestamp: endTs,
    });
    if (!payload.success) {
      const err = new Error(payload.message || "log api failed");
      err.status = 502;
      throw err;
    }
    const data = payload.data || {};
    const batch = data.items || [];
    if (data.total !== undefined && data.total !== null) total = data.total;
    items.push.apply(items, batch);
    if (!batch.length) break;
    const uniqueN = new Set(items.filter((i) => i && i.id != null).map((i) => i.id)).size;
    if (total != null && uniqueN >= Number(total)) break;
  }
  return dedupeById(items);
}

function counter(values) {
  const map = new Map();
  for (const v of values) map.set(v, (map.get(v) || 0) + 1);
  return map;
}

function mostCommon(map, n) {
  return Array.from(map.entries())
    .sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])))
    .slice(0, n);
}

function buildOverview(status, rawLogs, cached) {
  const quotaPerUnit = Number(status.quota_per_unit || 500000);
  const usdRate = Number(status.usd_exchange_rate || status.price || 7.3);
  const flt = { site_wide: true, usernames: [], groups: [], model_substr: [] };
  const filtered = dedupeById(rawLogs || []);
  filtered.sort((a, b) => {
    const ca = Number(b.created_at || 0) - Number(a.created_at || 0);
    if (ca !== 0) return ca;
    return Number(b.id || 0) - Number(a.id || 0);
  });
  const consume = filtered.filter((i) => i.type === 2);
  const errors = filtered.filter((i) => i.type === 5);
  const totalQuota = consume.reduce((s, i) => s + Number(i.quota || 0), 0);
  const totalMoney = moneyFromQuota(totalQuota, quotaPerUnit, usdRate);
  const userTask = counter(consume.map((i) => i.username || "(unknown)"));
  const userErr = counter(errors.map((i) => i.username || "(unknown)"));
  const topTask = mostCommon(userTask, 1)[0] || ["—", 0];
  const topErr = mostCommon(userErr, 1)[0] || ["—", 0];
  const logs = filtered.slice(0, LOG_CAP).map((i) => formatLog(i, quotaPerUnit, usdRate));
  const typeCounts = {};
  for (const [t, n] of counter(filtered.map((i) => i.type))) {
    typeCounts[typeLabel(t)] = n;
  }
  const modelCounts = mostCommon(counter(filtered.map((i) => i.model_name || "(无)")), 10);
  const endDt = new Date();
  const startDt = new Date(endDt.getTime() - LOG_WINDOW_DAYS * 86400 * 1000);
  return {
    ok: true,
    site: "susciyuan.com",
    title: "追觅客户监控 · Susciyuan",
    window_days: LOG_WINDOW_DAYS,
    window: { start: formatFull(startDt), end: formatFull(endDt), tz: TZ },
    filter: flt,
    conversion: {
      quota_per_unit: quotaPerUnit,
      usd_exchange_rate: usdRate,
      quota_display_type: status.quota_display_type || "CNY",
      formula: "CNY = quota / quota_per_unit * usd_exchange_rate",
    },
    metrics: {
      usage_cny: totalMoney.cny,
      usage_usd: totalMoney.usd,
      usage_quota: totalQuota,
      total_requests: filtered.length,
      consume_count: consume.length,
      error_count: errors.length,
      top_task_user: topTask[0],
      top_task_count: topTask[1],
      top_error_user: topErr[0],
      top_error_count: topErr[1],
    },
    type_counts: typeCounts,
    top_models: modelCounts.map(([model, count]) => ({ model, count })),
    logs,
    log_total_in_window: filtered.length,
    log_returned: logs.length,
    generated_at: formatFull(endDt),
    cached,
  };
}

async function handleOverview(request, runtime) {
  const base = envOf(runtime, "SUSCIYUAN_BASE", "https://susciyuan.com").replace(/\/+$/, "");
  const token = envOf(runtime, "SUSCIYUAN_ACCESS_TOKEN", "");
  const userId = envOf(runtime, "SUSCIYUAN_USER_ID", "1") || "1";
  if (!token) {
    return json(500, { ok: false, error: "missing SUSCIYUAN_ACCESS_TOKEN" });
  }
  const url = new URL(request.url);
  const refreshRaw = (url.searchParams.get("refresh") || "0").toLowerCase();
  const refresh = refreshRaw === "1" || refreshRaw === "true" || refreshRaw === "yes";
  const now = Date.now();
  let status = cache.status;
  let rawLogs = cache.logs;
  let cached = false;
  if (!refresh && rawLogs != null && now - cache.ts < CACHE_TTL_MS) {
    cached = true;
  } else {
    const endTs = Math.floor(Date.now() / 1000);
    const startTs = endTs - LOG_WINDOW_DAYS * 86400;
    status = await fetchStatus(base, token, userId);
    rawLogs = await fetchLogsWindow(base, token, userId, startTs, endTs);
    cache = { ts: Date.now(), status, logs: rawLogs };
    cached = false;
  }
  return json(200, buildOverview(status, rawLogs, cached));
}

export default {
  async fetch(request, env) {
    const runtime = env || {};
    const password = envOf(runtime, "DASHBOARD_PASSWORD", "");
    if (password) {
      const user = envOf(runtime, "DASHBOARD_USER", "zhuimi") || "zhuimi";
      if (!checkBasic(request, user, password)) return unauthorized();
    }
    let url;
    try {
      url = new URL(request.url);
    } catch {
      return json(400, { ok: false, error: "bad url" });
    }
    const path = url.pathname;
    try {
      if (request.method !== "GET") {
        return json(405, { ok: false, error: "method not allowed" });
      }
      if (path === "/api/health") {
        return json(200, { ok: true });
      }
      if (path === "/api/overview") {
        return await handleOverview(request, runtime);
      }
      return json(404, { ok: false, error: "not found" });
    } catch (err) {
      const status = (err && err.status) || 500;
      const message = (err && err.message) || "internal error";
      const safe = String(message).replace(/Bearer\s+\S+/gi, "Bearer [redacted]");
      return json(status >= 400 ? status : 500, { ok: false, error: safe });
    }
  },
};
