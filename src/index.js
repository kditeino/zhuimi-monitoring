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
let balancesCache = { ts: 0, payload: null };
let aipddWalletPath = "";
let aipddFailedPaths = [];
let awcoinRateCache = { ts: 0, rmb: 0.0001, usd: 0.00001484 };

const AIPDD_DEFAULT_BASE = "https://api.aipdd.work";
const AIPDD_RATE_PATH = "/system/awcoin-rate";
const DEFAULT_AWCOIN_RMB = 0.0001;
// Probe order on official AIPDD (AWCoin). Unauthenticated GETs to all five
// return AIPDD-style 401 {code,message,data}, so they exist. Runtime caches
// the first path that yields a usable AWCoin balance. Do not call
// newapi.aipdd.work (ImpToken) or susciyuan /api/user/self here.
const AIPDD_WALLET_PATHS = ["/v1/user", "/v1/wallet", "/v1/account", "/v1/balance", "/api/user/self"];
const VOLC_BILLING_HOST = "billing.volcengineapi.com";
const VOLC_BILLING_SERVICE = "billing";
const VOLC_BILLING_REGION = "cn-north-1";
const VOLC_CONTENT_TYPE = "application/x-www-form-urlencoded";
const RATE_CACHE_TTL_MS = 60 * 60 * 1000;
const MAX_BALANCES_SUBREQ = 4;

function envOf(runtime, key, fallback) {
  const baked = (typeof globalThis !== "undefined" && globalThis.BAKED_ENV) || {};
  const fromBaked = baked[key];
  const fromRt = runtime && runtime[key];
  const fromProc =
    typeof process !== "undefined" && process.env ? process.env[key] : undefined;
  const raw = (fromBaked && String(fromBaked).trim()) || fromRt || fromProc || fallback || "";
  return String(raw).trim();
}

function json(status, obj, extraHeaders) {
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  };
  if (extraHeaders) {
    for (const [k, v] of Object.entries(extraHeaders)) headers[k] = v;
  }
  return new Response(JSON.stringify(obj), { status, headers });
}

const SESSION_COOKIE = "zm_sid";
const SESSION_DAYS = 7;
const SESSION_PEPPER = "zhuimi-monitor-session-v1";

function jsonUnauthorized() {
  return new Response(JSON.stringify({ ok: false, error: "unauthorized" }), {
    status: 401,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

function htmlPage(status, body, extraHeaders) {
  const headers = {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
  };
  if (extraHeaders) {
    for (const [k, v] of Object.entries(extraHeaders)) headers[k] = v;
  }
  return new Response(body, { status: status, headers: headers });
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

function cookieHeader(request, name) {
  const raw = request.headers.get("Cookie") || "";
  const parts = raw.split(";");
  for (let i = 0; i < parts.length; i++) {
    const piece = parts[i].trim();
    const eq = piece.indexOf("=");
    if (eq < 0) continue;
    if (piece.slice(0, eq) === name) return piece.slice(eq + 1);
  }
  return "";
}

function b64urlEncode(text) {
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlDecode(text) {
  const s = String(text || "").replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  return atob(s + pad);
}

async function sessionKeyBytes(password) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(password) + SESSION_PEPPER));
  return new Uint8Array(digest);
}

async function signSessionPayload(password, payload) {
  const sig = await hmacSha256Raw(await sessionKeyBytes(password), payload);
  return hexFromBuf(sig);
}

async function makeSessionToken(user, password, nowMs) {
  const exp = Math.floor(Number(nowMs || Date.now()) / 1000) + SESSION_DAYS * 86400;
  const payload = "v1|" + String(user) + "|" + exp;
  return b64urlEncode(payload) + "." + (await signSessionPayload(password, payload));
}

async function verifySessionToken(token, user, password, nowMs) {
  const parts = String(token || "").split(".");
  if (parts.length !== 2) return false;
  let payload = "";
  try {
    payload = b64urlDecode(parts[0]);
  } catch {
    return false;
  }
  const expected = await signSessionPayload(password, payload);
  if (!safeEqual(expected, parts[1])) return false;
  const bits = payload.split("|");
  if (bits.length !== 3 || bits[0] !== "v1" || !safeEqual(bits[1], user)) return false;
  const exp = Number(bits[2]);
  return Number.isFinite(exp) && exp > Math.floor(Number(nowMs || Date.now()) / 1000);
}

function sessionCookieValue(token, requestUrl, clear) {
  const secure = String(requestUrl || "").startsWith("https:") ? "; Secure" : "";
  if (clear) {
    return SESSION_COOKIE + "=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax" + secure;
  }
  const maxAge = SESSION_DAYS * 86400;
  return (
    SESSION_COOKIE +
    "=" +
    token +
    "; Path=/; Max-Age=" +
    maxAge +
    "; HttpOnly; SameSite=Lax" +
    secure
  );
}

function renderLoginPage(error) {
  const baked = typeof globalThis !== "undefined" ? globalThis.BAKED_LOGIN_HTML : "";
  const err = error
    ? '<div class="banner err" id="loginError">账号或密码不对</div>'
    : "";
  if (baked) return String(baked).replace("<!--ERROR-->", err);
  return (
    "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"UTF-8\" /><title>追觅客户监控</title></head>" +
    "<body><h1>追觅客户监控</h1>" +
    err +
    "<form id=\"loginForm\" method=\"post\" action=\"/api/login\">" +
    "<label for=\"username\">用户名</label>" +
    "<input type=\"text\" name=\"username\" id=\"username\" autocomplete=\"username\" required />" +
    "<label for=\"password\">密码</label>" +
    "<input type=\"password\" name=\"password\" id=\"password\" autocomplete=\"current-password\" required />" +
    "<button type=\"submit\">登录</button></form>" +
    "<script>(function(){var f=document.getElementById(\"loginForm\");if(!f)return;f.addEventListener(\"submit\",function(e){e.preventDefault();var u=document.getElementById(\"username\").value;var p=document.getElementById(\"password\").value;fetch(\"/api/login\",{method:\"POST\",credentials:\"same-origin\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify({username:u,password:p})}).then(function(r){if(r.ok)location.replace(\"/app.html\");});});})();</script>" +
    "</body></html>"
  );
}

function renderAppPage() {
  const baked = typeof globalThis !== "undefined" ? globalThis.BAKED_APP_HTML : "";
  return baked || "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"UTF-8\" /><title>追觅客户监控</title></head><body>追觅客户监控</body></html>";
}

async function readLoginForm(request) {
  const ctype = request.headers.get("Content-Type") || "";
  if (ctype.includes("application/json")) {
    try {
      const body = JSON.parse(await request.text());
      return {
        username: String((body && body.username) || ""),
        password: String((body && body.password) || ""),
      };
    } catch {
      return { username: "", password: "" };
    }
  }
  if (ctype.includes("multipart/form-data") && request.formData) {
    const fd = await request.formData();
    return {
      username: String(fd.get("username") || ""),
      password: String(fd.get("password") || ""),
    };
  }
  const text = await request.text();
  const params = new URLSearchParams(text);
  return {
    username: String(params.get("username") || ""),
    password: String(params.get("password") || ""),
  };
}

async function handleCredentialLogin(request, user, password, jsonMode) {
  if (!password) {
    if (jsonMode) return json(200, { ok: true });
    return new Response(null, { status: 302, headers: { Location: "/", "Cache-Control": "no-store" } });
  }
  const form = await readLoginForm(request);
  const ok = safeEqual(form.username, user) && safeEqual(form.password, password);
  if (!ok) {
    if (jsonMode) return json(401, { ok: false, error: "账号或密码不对" });
    return htmlPage(200, renderLoginPage(true));
  }
  const token = await makeSessionToken(user, password, Date.now());
  const cookie = sessionCookieValue(token, request.url, false);
  if (jsonMode) {
    return json(200, { ok: true }, { "Set-Cookie": cookie });
  }
  return new Response(null, {
    status: 302,
    headers: {
      Location: "/",
      "Set-Cookie": cookie,
      "Cache-Control": "no-store",
    },
  });
}

function handleLogoutResponse(request, jsonMode) {
  const cookie = sessionCookieValue("", request.url, true);
  if (jsonMode) {
    return json(200, { ok: true }, { "Set-Cookie": cookie });
  }
  return new Response(null, {
    status: 302,
    headers: {
      Location: "/",
      "Set-Cookie": cookie,
      "Cache-Control": "no-store",
    },
  });
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

function isRefresh(url) {
  const refreshRaw = (url.searchParams.get("refresh") || "0").toLowerCase();
  return refreshRaw === "1" || refreshRaw === "true" || refreshRaw === "yes";
}

function aipddBaseOf(runtime) {
  const raw =
    envOf(runtime, "AIPDD_BASE_URL", "") || envOf(runtime, "AIPDD_BASE", AIPDD_DEFAULT_BASE) || AIPDD_DEFAULT_BASE;
  const cleaned = String(raw).replace(/\/+$/, "");
  if (/newapi\.aipdd\.work/i.test(cleaned) || /susciyuan\.com/i.test(cleaned)) {
    return AIPDD_DEFAULT_BASE;
  }
  return cleaned || AIPDD_DEFAULT_BASE;
}

function asFiniteNumber(v) {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && v.trim() && !Number.isNaN(Number(v))) return Number(v);
  return null;
}

function looksLikeRatePayload(obj) {
  if (!obj || typeof obj !== "object") return false;
  const keys = Object.keys(obj);
  return keys.includes("rmb") && keys.includes("usd") && !keys.some((k) => /awcoin|balance|wallet|credit/i.test(k));
}

function looksLikeNewApiQuota(obj) {
  if (!obj || typeof obj !== "object") return false;
  const hasQuota = obj.quota != null && obj.used_quota != null;
  const hasAwcoin = obj.awcoin != null || obj.awCoin != null || obj.aw_coin != null;
  return hasQuota && !hasAwcoin;
}

function pickAwcoinFromObject(obj) {
  if (!obj || typeof obj !== "object") return null;
  if (looksLikeRatePayload(obj) || looksLikeNewApiQuota(obj)) return null;
  const preferred = [
    "awcoin",
    "awCoin",
    "AWCoin",
    "aw_coin",
    "awcoin_balance",
    "wallet_balance",
    "available_balance",
    "availableBalance",
    "remain_awcoin",
    "balance",
    "wallet",
    "credit",
    "available",
    "remain",
    "remaining",
    "amount",
  ];
  for (const key of preferred) {
    if (!Object.prototype.hasOwnProperty.call(obj, key)) continue;
    const n = asFiniteNumber(obj[key]);
    if (n != null) return n;
  }
  return null;
}

function extractAwcoin(payload) {
  if (payload == null) return null;
  const direct = asFiniteNumber(payload);
  if (direct != null) return direct;
  if (typeof payload !== "object") return null;
  if (payload.code != null && Number(payload.code) !== 0) return null;
  if (payload.success === false) return null;
  const data = payload.data;
  if (asFiniteNumber(data) != null) return asFiniteNumber(data);
  const fromData = pickAwcoinFromObject(data);
  if (fromData != null) return fromData;
  if (data && typeof data === "object") {
    const nestedWallet = pickAwcoinFromObject(data.wallet) || pickAwcoinFromObject(data.account) || pickAwcoinFromObject(data.user);
    if (nestedWallet != null) return nestedWallet;
  }
  return pickAwcoinFromObject(payload);
}

function extractAwcoinRate(payload) {
  const data = payload && payload.data && typeof payload.data === "object" ? payload.data : payload;
  const rmb = asFiniteNumber(data && data.rmb);
  const usd = asFiniteNumber(data && data.usd);
  return {
    rmb: rmb != null && rmb > 0 ? rmb : DEFAULT_AWCOIN_RMB,
    usd: usd != null && usd > 0 ? usd : null,
  };
}

function parseVolcBalance(payload) {
  if (!payload || typeof payload !== "object") return null;
  const meta = payload.ResponseMetadata;
  if (meta && meta.Error) return null;
  const result = payload.Result && typeof payload.Result === "object" ? payload.Result : payload;
  const raw = result.AvailableBalance != null ? result.AvailableBalance : result.CashBalance;
  return asFiniteNumber(raw);
}

function hexFromBuf(buf) {
  return Array.from(new Uint8Array(buf), function (b) {
    return b.toString(16).padStart(2, "0");
  }).join("");
}

function volcXDate(date) {
  const d = date || new Date();
  return d.toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
}

function uriEncodeRfc3986(s) {
  return encodeURIComponent(String(s)).replace(/[!'()*]/g, function (c) {
    return "%" + c.charCodeAt(0).toString(16).toUpperCase();
  });
}

function normQuery(params) {
  return Object.keys(params)
    .sort()
    .map(function (k) {
      return uriEncodeRfc3986(k) + "=" + uriEncodeRfc3986(params[k]);
    })
    .join("&");
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return hexFromBuf(digest);
}

async function hmacSha256Raw(keyBytes, text) {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(text));
  return new Uint8Array(sig);
}

async function signVolcengineV4(opts) {
  const method = (opts.method || "GET").toUpperCase();
  const path = opts.path || "/";
  const host = opts.host;
  const service = opts.service;
  const region = opts.region || VOLC_BILLING_REGION;
  const query = opts.query || {};
  const body = opts.body || "";
  const contentType = opts.contentType || VOLC_CONTENT_TYPE;
  const xDate = opts.xDate;
  const shortDate = xDate.slice(0, 8);
  const xContentSha256 = await sha256Hex(body);
  const signedHeaders = "content-type;host;x-content-sha256;x-date";
  const canonicalHeaders =
    "content-type:" +
    contentType +
    "\n" +
    "host:" +
    host +
    "\n" +
    "x-content-sha256:" +
    xContentSha256 +
    "\n" +
    "x-date:" +
    xDate +
    "\n";
  const canonicalRequest = [method, path, normQuery(query), canonicalHeaders, signedHeaders, xContentSha256].join("\n");
  const hashedCanon = await sha256Hex(canonicalRequest);
  const credentialScope = shortDate + "/" + region + "/" + service + "/request";
  const stringToSign = ["HMAC-SHA256", xDate, credentialScope, hashedCanon].join("\n");
  const enc = new TextEncoder();
  const kDate = await hmacSha256Raw(enc.encode(opts.sk), shortDate);
  const kRegion = await hmacSha256Raw(kDate, region);
  const kService = await hmacSha256Raw(kRegion, service);
  const kSigning = await hmacSha256Raw(kService, "request");
  const signature = hexFromBuf(await hmacSha256Raw(kSigning, stringToSign));
  return {
    authorization:
      "HMAC-SHA256 Credential=" +
      opts.ak +
      "/" +
      credentialScope +
      ", SignedHeaders=" +
      signedHeaders +
      ", Signature=" +
      signature,
    xDate: xDate,
    xContentSha256: xContentSha256,
    contentType: contentType,
    host: host,
    signature: signature,
    credentialScope: credentialScope,
    canonicalRequest: canonicalRequest,
  };
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
  const refresh = isRefresh(url);
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

function emptyAipdd(error) {
  return { configured: false, cny: null, usd: null, awcoin: null, error: error || null };
}

function emptyVolces(error) {
  return { configured: false, cny: null, usd: null, error: error || null };
}

function resetBalancesState() {
  balancesCache = { ts: 0, payload: null };
  aipddWalletPath = "";
  aipddFailedPaths = [];
  awcoinRateCache = { ts: 0, rmb: DEFAULT_AWCOIN_RMB, usd: 0.00001484 };
}

function assertAipddHost(url) {
  const host = String(url).toLowerCase();
  if (host.includes("newapi.aipdd.work") || host.includes("susciyuan.com") || host.includes("ark.cn-beijing.volces.com")) {
    const err = new Error("blocked host");
    err.status = 500;
    throw err;
  }
}

async function aipddGetJson(base, key, path) {
  const root = base.endsWith("/") ? base : base + "/";
  const url = new URL(path, root);
  assertAipddHost(url.hostname);
  const res = await fetch(url.toString(), {
    method: "GET",
    redirect: "manual",
    headers: {
      "X-API-Key": key,
      Authorization: "Bearer " + key,
      Accept: "application/json",
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

async function fetchAwcoinRate(base) {
  const now = Date.now();
  if (awcoinRateCache.ts && now - awcoinRateCache.ts < RATE_CACHE_TTL_MS) {
    return { rmb: awcoinRateCache.rmb, usd: awcoinRateCache.usd, cached: true };
  }
  const root = base.endsWith("/") ? base : base + "/";
  const url = new URL(AIPDD_RATE_PATH, root);
  assertAipddHost(url.hostname);
  const res = await fetch(url.toString(), {
    method: "GET",
    redirect: "manual",
    headers: { Accept: "application/json" },
  });
  if (!res.ok) {
    return { rmb: DEFAULT_AWCOIN_RMB, usd: awcoinRateCache.usd, cached: false };
  }
  const payload = JSON.parse(await res.text());
  const rate = extractAwcoinRate(payload);
  awcoinRateCache = { ts: Date.now(), rmb: rate.rmb, usd: rate.usd };
  return { rmb: rate.rmb, usd: rate.usd, cached: false };
}

async function probeAipddWallet(base, key, budget) {
  const tried = [];
  const paths = [];
  if (aipddWalletPath && aipddFailedPaths.indexOf(aipddWalletPath) < 0) paths.push(aipddWalletPath);
  for (let i = 0; i < AIPDD_WALLET_PATHS.length; i++) {
    const p = AIPDD_WALLET_PATHS[i];
    if (paths.indexOf(p) < 0 && aipddFailedPaths.indexOf(p) < 0) paths.push(p);
  }
  if (!paths.length) {
    aipddFailedPaths = [];
    paths.push.apply(paths, AIPDD_WALLET_PATHS);
  }
  const limit = Math.max(1, Math.min(budget, paths.length));
  for (let i = 0; i < limit; i++) {
    const path = paths[i];
    tried.push(path);
    try {
      const payload = await aipddGetJson(base, key, path);
      const awcoin = extractAwcoin(payload);
      if (awcoin != null) {
        aipddWalletPath = path;
        return { awcoin: awcoin, path: path, tried: tried };
      }
    } catch {
      // try next documented path; never surface upstream text
    }
    if (aipddFailedPaths.indexOf(path) < 0) aipddFailedPaths.push(path);
  }
  return { awcoin: null, path: "", tried: tried };
}

async function fetchVolcBalance(ak, sk, now) {
  const query = { Action: "QueryBalanceAcct", Version: "2022-01-01" };
  const signed = await signVolcengineV4({
    method: "GET",
    path: "/",
    host: VOLC_BILLING_HOST,
    service: VOLC_BILLING_SERVICE,
    region: VOLC_BILLING_REGION,
    query: query,
    body: "",
    contentType: VOLC_CONTENT_TYPE,
    ak: ak,
    sk: sk,
    xDate: volcXDate(now),
  });
  const url = "https://" + VOLC_BILLING_HOST + "/?" + normQuery(query);
  const res = await fetch(url, {
    method: "GET",
    redirect: "manual",
    headers: {
      Host: signed.host,
      "Content-Type": signed.contentType,
      "X-Date": signed.xDate,
      "X-Content-Sha256": signed.xContentSha256,
      Authorization: signed.authorization,
      Accept: "application/json",
    },
  });
  if (!res.ok || (res.status >= 300 && res.status < 400)) {
    const err = new Error("upstream HTTP " + res.status);
    err.status = 502;
    throw err;
  }
  const payload = JSON.parse(await res.text());
  const cny = parseVolcBalance(payload);
  if (cny == null) {
    const err = new Error("volc balance missing");
    err.status = 502;
    throw err;
  }
  return cny;
}

async function handleBalances(request, runtime) {
  const base = aipddBaseOf(runtime).replace(/\/+$/, "") || AIPDD_DEFAULT_BASE;
  const aipddKey = envOf(runtime, "AIPDD_API_KEY", "");
  const volcAk = envOf(runtime, "VOLC_ACCESS_KEY_ID", "");
  const volcSk = envOf(runtime, "VOLC_SECRET_ACCESS_KEY", "");
  const generatedAt = formatFull(new Date());

  const aipddReady = Boolean(aipddKey);
  const volcReady = Boolean(volcAk && volcSk);
  if (!aipddReady && !volcReady) {
    const volcMissing = [];
    if (!volcAk) volcMissing.push("VOLC_ACCESS_KEY_ID");
    if (!volcSk) volcMissing.push("VOLC_SECRET_ACCESS_KEY");
    return json(200, {
      ok: true,
      aipdd: emptyAipdd("未配置 AIPDD_API_KEY"),
      volces: emptyVolces("未配置 " + volcMissing.join(" / ")),
      generated_at: generatedAt,
      cached: false,
    });
  }

  const url = new URL(request.url);
  const refresh = isRefresh(url);
  const now = Date.now();
  if (!refresh && balancesCache.payload && now - balancesCache.ts < CACHE_TTL_MS) {
    return json(200, Object.assign({}, balancesCache.payload, { cached: true }));
  }

  let used = 0;
  let rateP = Promise.resolve({ rmb: DEFAULT_AWCOIN_RMB, usd: awcoinRateCache.usd, cached: true });
  let aipddP = Promise.resolve(null);
  let volcP = Promise.resolve(null);

  if (volcReady) {
    used += 1;
    volcP = fetchVolcBalance(volcAk, volcSk, new Date()).then(
      function (cny) {
        return { ok: true, cny: cny };
      },
      function () {
        return { ok: false };
      }
    );
  }

  if (aipddReady) {
    const rateFresh = awcoinRateCache.ts && now - awcoinRateCache.ts < RATE_CACHE_TTL_MS;
    if (!rateFresh && used < MAX_BALANCES_SUBREQ) {
      used += 1;
      rateP = fetchAwcoinRate(base).catch(function () {
        return { rmb: DEFAULT_AWCOIN_RMB, usd: awcoinRateCache.usd, cached: false };
      });
    }
    const walletBudget = Math.max(1, MAX_BALANCES_SUBREQ - used);
    aipddP = probeAipddWallet(base, aipddKey, walletBudget);
  }

  const settled = await Promise.all([rateP, aipddP, volcP]);
  const rate = settled[0] || { rmb: DEFAULT_AWCOIN_RMB, usd: null };
  const wallet = settled[1];
  const volcRes = settled[2];

  let aipdd;
  if (!aipddReady) {
    aipdd = emptyAipdd("未配置 AIPDD_API_KEY");
  } else if (!wallet || wallet.awcoin == null) {
    aipdd = { configured: true, cny: null, usd: null, awcoin: null, error: "AIPDD 余额查询失败" };
  } else {
    const rmb = rate.rmb > 0 ? rate.rmb : DEFAULT_AWCOIN_RMB;
    const cny = roundN(wallet.awcoin * rmb, 4);
    const usd = rate.usd != null ? roundN(wallet.awcoin * rate.usd, 6) : null;
    aipdd = { configured: true, cny: cny, usd: usd, awcoin: wallet.awcoin, error: null };
  }

  let volces;
  if (!volcAk || !volcSk) {
    const missing = [];
    if (!volcAk) missing.push("VOLC_ACCESS_KEY_ID");
    if (!volcSk) missing.push("VOLC_SECRET_ACCESS_KEY");
    volces = emptyVolces("未配置 " + missing.join(" / "));
  } else if (!volcRes || !volcRes.ok) {
    volces = { configured: true, cny: null, usd: null, error: "火山引擎余额查询失败" };
  } else {
    volces = { configured: true, cny: roundN(volcRes.cny, 4), usd: null, error: null, currency: "CNY" };
  }

  const payload = {
    ok: true,
    aipdd: aipdd,
    volces: volces,
    generated_at: formatFull(new Date()),
    cached: false,
  };
  balancesCache = { ts: Date.now(), payload: payload };
  return json(200, payload);
}

export {
  extractAwcoin,
  extractAwcoinRate,
  parseVolcBalance,
  signVolcengineV4,
  volcXDate,
  normQuery,
  resetBalancesState,
  makeSessionToken,
  verifySessionToken,
  renderLoginPage,
  SESSION_COOKIE,
};

export default {
  async fetch(request, env) {
    const runtime = env || {};
    const password = envOf(runtime, "DASHBOARD_PASSWORD", "");
    const user = envOf(runtime, "DASHBOARD_USER", "zhuimi") || "zhuimi";
    let url;
    try {
      url = new URL(request.url);
    } catch {
      return json(400, { ok: false, error: "bad url" });
    }
    const path = url.pathname;

    try {
      if ((path === "/api/login" || path === "/login") && request.method === "POST") {
        return handleCredentialLogin(request, user, password, path === "/api/login");
      }

      if (
        (path === "/api/logout" || path === "/api/logout/" || path === "/logout" || path === "/logout/") &&
        (request.method === "GET" || request.method === "POST")
      ) {
        return handleLogoutResponse(request, path.startsWith("/api/") && request.method === "POST");
      }

      if (path === "/login" && request.method === "GET") {
        return htmlPage(200, renderLoginPage(false));
      }

      const authed =
        !password || (await verifySessionToken(cookieHeader(request, SESSION_COOKIE), user, password, Date.now()));

      if (path === "/api/session") {
        if (!authed) return jsonUnauthorized();
        return json(200, { ok: true });
      }

      if (path === "/api/health") {
        return json(200, { ok: true });
      }

      if (password && !authed) {
        if (path.startsWith("/api/")) return jsonUnauthorized();
        if (request.method === "GET" && (path === "/" || path === "/index.html" || path === "/app.html")) {
          return htmlPage(200, renderLoginPage(false));
        }
      }

      if (request.method === "GET" && (path === "/" || path === "/index.html" || path === "/app.html")) {
        return htmlPage(200, renderAppPage());
      }

      if (request.method !== "GET") {
        return json(405, { ok: false, error: "method not allowed" });
      }
      if (path === "/api/overview") {
        return await handleOverview(request, runtime);
      }
      if (path === "/api/balances") {
        return await handleBalances(request, runtime);
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
