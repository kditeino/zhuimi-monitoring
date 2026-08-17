#!/usr/bin/env python3
"""Susciyuan (追觅) internal H5 monitoring dashboard — secrets stay server-side."""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import base64
import hashlib
import hmac


SESSION_COOKIE = "zm_sid"
SESSION_DAYS = 7
SESSION_PEPPER = "zhuimi-monitor-session-v1"


def _dashboard_creds(env: dict[str, str]) -> tuple[str, str] | None:
    user = (env.get("DASHBOARD_USER") or "").strip()
    pw = (env.get("DASHBOARD_PASSWORD") or "").strip()
    if not pw:
        return None
    return (user or "zhuimi", pw)


def _session_key(password: str) -> bytes:
    return hashlib.sha256((password + SESSION_PEPPER).encode("utf-8")).digest()


def _make_session_token(user: str, password: str) -> str:
    exp = int(time.time()) + SESSION_DAYS * 86400
    payload = f"v1|{user}|{exp}"
    raw = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")
    sig = hmac.new(_session_key(password), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{raw}.{sig}"


def _verify_session_token(token: str, user: str, password: str) -> bool:
    parts = (token or "").split(".")
    if len(parts) != 2:
        return False
    raw, got_sig = parts
    pad = "=" * (-len(raw) % 4)
    try:
        payload = base64.urlsafe_b64decode(raw + pad).decode("utf-8")
    except Exception:
        return False
    expect = hmac.new(_session_key(password), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect, got_sig):
        return False
    bits = payload.split("|")
    if len(bits) != 3 or bits[0] != "v1" or not hmac.compare_digest(bits[1], user):
        return False
    try:
        exp = int(bits[2])
    except ValueError:
        return False
    return exp > int(time.time())


def _cookie_from_headers(handler: "Handler", name: str) -> str:
    raw = handler.headers.get("Cookie") or ""
    for part in raw.split(";"):
        piece = part.strip()
        if "=" not in piece:
            continue
        k, v = piece.split("=", 1)
        if k == name:
            return v
    return ""


def _session_cookie(token: str, secure: bool, clear: bool = False) -> str:
    flags = "Path=/; HttpOnly; SameSite=Lax"
    if secure:
        flags += "; Secure"
    if clear:
        return f"{SESSION_COOKIE}=; {flags}; Max-Age=0"
    return f"{SESSION_COOKIE}={token}; {flags}; Max-Age={SESSION_DAYS * 86400}"


def _is_authed(handler: "Handler", env: dict[str, str]) -> bool:
    creds = _dashboard_creds(env)
    if creds is None:
        return True
    user, pw = creds
    return _verify_session_token(_cookie_from_headers(handler, SESSION_COOKIE), user, pw)


def _json_unauthorized(handler: "Handler") -> None:
    body = json.dumps({"ok": False, "error": "unauthorized"}, ensure_ascii=False).encode("utf-8")
    handler.send_response(401)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"


def _login_html(error: bool = False) -> bytes:
    html = (STATIC_DIR / "login.html").read_text(encoding="utf-8")
    err = '<div class="banner err" id="loginError">账号或密码不对</div>' if error else ""
    return html.replace("<!--ERROR-->", err).encode("utf-8")
FILTER_PATH = APP_DIR / "client_filter.json"
ENV_PATH = Path(
    os.environ.get(
        "SUSCIYUAN_ENV",
        str(Path(__file__).resolve().parent / ".env"),
    )
)
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8787"))

TZ_SH = timezone(timedelta(hours=8))
LOG_WINDOW_DAYS = 3
LOG_CAP = 300
CACHE_TTL_SEC = 45

# New API log type labels (confirmed on this deployment; others reserved)
TYPE_LABELS = {
    1: "充值",
    2: "消费",
    3: "管理",
    4: "系统",
    5: "错误",
    6: "退款",
}

_cache_lock = threading.Lock()
_cache: dict[str, Any] = {"ts": 0.0, "status": None, "logs": None}
_balances_cache: dict[str, Any] = {"ts": 0.0, "payload": None}


def load_env(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def load_filter() -> dict[str, Any]:
    if not FILTER_PATH.exists():
        return {"site_wide": True, "usernames": [], "groups": [], "model_substr": []}
    try:
        data = json.loads(FILTER_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"site_wide": True, "usernames": [], "groups": [], "model_substr": []}
    if data.get("site_wide"):
        return {
            "site_wide": True,
            "usernames": [],
            "groups": [],
            "model_substr": [],
            "notes": data.get("notes"),
        }
    return {
        "site_wide": False,
        "usernames": list(data.get("usernames") or []),
        "groups": list(data.get("groups") or []),
        "model_substr": list(data.get("model_substr") or []),
        "notes": data.get("notes"),
    }


def api_get(base: str, token: str, user_id: str, path: str, params: dict) -> dict:
    qs = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    url = f"{base.rstrip('/')}{path}"
    if qs:
        url = f"{url}?{qs}"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "New-Api-User": str(user_id),
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=45) as resp:
        return json.loads(resp.read().decode())


def fetch_status(env: dict[str, str]) -> dict[str, Any]:
    data = api_get(env["SUSCIYUAN_BASE"], env["SUSCIYUAN_ACCESS_TOKEN"], env.get("SUSCIYUAN_USER_ID", "1"), "/api/status", {})
    return data.get("data") or {}


def dedupe_by_id(items: list[dict]) -> list[dict]:
    """Keep one row per log id. New API p=0 and p=1 can return the same page."""
    seen: set[int] = set()
    out: list[dict] = []
    for it in items:
        lid = it.get("id")
        if lid is None:
            out.append(it)
            continue
        try:
            key = int(lid)
        except (TypeError, ValueError):
            out.append(it)
            continue
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out


def fetch_logs_window(env: dict[str, str], start_ts: int, end_ts: int) -> list[dict]:
    base = env["SUSCIYUAN_BASE"]
    token = env["SUSCIYUAN_ACCESS_TOKEN"]
    user_id = env.get("SUSCIYUAN_USER_ID", "1")
    items: list[dict] = []
    page = 1
    page_size = 100
    total = None
    while True:
        payload = api_get(
            base,
            token,
            user_id,
            "/api/log/",
            {
                "p": page,
                "page_size": page_size,
                "start_timestamp": start_ts,
                "end_timestamp": end_ts,
            },
        )
        if not payload.get("success"):
            raise RuntimeError(payload.get("message") or "log api failed")
        data = payload.get("data") or {}
        batch = data.get("items") or []
        total = data.get("total", total)
        items.extend(batch)
        if not batch:
            break
        unique_n = len({i.get("id") for i in items if i.get("id") is not None})
        if total is not None and unique_n >= int(total):
            break
        if unique_n >= 5000:
            break
        page += 1
        if page > 80:
            break
    return dedupe_by_id(items)


def parse_other(raw: Any) -> dict:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            val = json.loads(raw)
            return val if isinstance(val, dict) else {}
        except Exception:
            return {}
    return {}


def money_from_quota(quota: int | float | None, quota_per_unit: float, usd_rate: float) -> dict[str, float]:
    q = float(quota or 0)
    usd = q / quota_per_unit if quota_per_unit else 0.0
    cny = usd * usd_rate
    return {"quota": q, "usd": round(usd, 6), "cny": round(cny, 4)}


def extract_status_code(content: str) -> int | None:
    if "status_code=" not in (content or ""):
        return None
    try:
        part = content.split("status_code=", 1)[1]
        return int(part.split(",", 1)[0].strip().split()[0])
    except Exception:
        return None


def apply_filter(items: list[dict], flt: dict[str, Any]) -> list[dict]:
    if flt.get("site_wide"):
        return items
    users = {u.lower() for u in (flt.get("usernames") or []) if u}
    groups = {g.lower() for g in (flt.get("groups") or []) if g}
    substrs = [s.lower() for s in (flt.get("model_substr") or []) if s]
    if not users and not groups and not substrs:
        return items
    out = []
    for it in items:
        uname = (it.get("username") or "").lower()
        grp = (it.get("group") or "").lower()
        model = (it.get("model_name") or "").lower()
        ok = False
        if users and uname in users:
            ok = True
        if groups and grp in groups:
            ok = True
        if substrs and any(s in model for s in substrs):
            ok = True
        if ok:
            out.append(it)
    return out


def format_log(item: dict, quota_per_unit: float, usd_rate: float) -> dict[str, Any]:
    created = int(item.get("created_at") or 0)
    dt = datetime.fromtimestamp(created, TZ_SH) if created else None
    content = item.get("content") or ""
    other = parse_other(item.get("other"))
    typ = item.get("type")
    money = money_from_quota(item.get("quota"), quota_per_unit, usd_rate)
    short = content.replace("\n", " ").strip()
    if len(short) > 120:
        short = short[:117] + "..."
    return {
        "id": item.get("id"),
        "created_at": created,
        "time": dt.strftime("%m-%d %H:%M:%S") if dt else "",
        "time_full": dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "",
        "type": typ,
        "type_label": TYPE_LABELS.get(typ, f"类型{typ}"),
        "username": item.get("username") or "",
        "model": item.get("model_name") or "",
        "group": item.get("group") or "",
        "token_name": item.get("token_name") or "",
        "channel_name": item.get("channel_name") or "",
        "duration": item.get("use_time") or 0,
        "quota": money["quota"],
        "cost_cny": money["cny"],
        "cost_usd": money["usd"],
        "content_short": short,
        "content": content,
        "request_id": item.get("request_id") or "",
        "status_code": extract_status_code(content),
        "prompt_tokens": item.get("prompt_tokens") or 0,
        "completion_tokens": item.get("completion_tokens") or 0,
        "ip": item.get("ip") or "",
        "other": other,
    }


def build_overview(env: dict[str, str], force: bool = False) -> dict[str, Any]:
    now = time.time()
    with _cache_lock:
        if not force and _cache["logs"] is not None and now - float(_cache["ts"]) < CACHE_TTL_SEC:
            status = _cache["status"]
            raw_logs = _cache["logs"]
            cached = True
        else:
            status = None
            raw_logs = None
            cached = False

    if not cached:
        end_ts = int(time.time())
        start_ts = end_ts - LOG_WINDOW_DAYS * 86400
        status = fetch_status(env)
        raw_logs = fetch_logs_window(env, start_ts, end_ts)
        with _cache_lock:
            _cache["ts"] = time.time()
            _cache["status"] = status
            _cache["logs"] = raw_logs

    quota_per_unit = float(status.get("quota_per_unit") or 500000)
    usd_rate = float(status.get("usd_exchange_rate") or status.get("price") or 7.3)
    flt = load_filter()
    filtered = dedupe_by_id(apply_filter(list(raw_logs or []), flt))
    filtered.sort(key=lambda x: (x.get("created_at") or 0, x.get("id") or 0), reverse=True)

    consume = [i for i in filtered if i.get("type") == 2]
    errors = [i for i in filtered if i.get("type") == 5]
    total_quota = sum(float(i.get("quota") or 0) for i in consume)
    total_money = money_from_quota(total_quota, quota_per_unit, usd_rate)

    user_task = Counter(i.get("username") or "(unknown)" for i in consume)
    user_err = Counter(i.get("username") or "(unknown)" for i in errors)
    top_task_user, top_task_n = (user_task.most_common(1)[0] if user_task else ("—", 0))
    top_err_user, top_err_n = (user_err.most_common(1)[0] if user_err else ("—", 0))

    logs = [format_log(i, quota_per_unit, usd_rate) for i in filtered[:LOG_CAP]]

    type_counts = {TYPE_LABELS.get(t, f"类型{t}"): n for t, n in Counter(i.get("type") for i in filtered).items()}
    model_counts = Counter((i.get("model_name") or "(无)") for i in filtered).most_common(10)

    end_dt = datetime.now(TZ_SH)
    start_dt = end_dt - timedelta(days=LOG_WINDOW_DAYS)

    return {
        "ok": True,
        "site": "susciyuan.com",
        "title": "追觅客户监控 · Susciyuan",
        "window_days": LOG_WINDOW_DAYS,
        "window": {
            "start": start_dt.strftime("%Y-%m-%d %H:%M:%S"),
            "end": end_dt.strftime("%Y-%m-%d %H:%M:%S"),
            "tz": "Asia/Shanghai",
        },
        "filter": {
            "site_wide": bool(flt.get("site_wide")),
            "usernames": flt.get("usernames") or [],
            "groups": flt.get("groups") or [],
            "model_substr": flt.get("model_substr") or [],
        },
        "conversion": {
            "quota_per_unit": quota_per_unit,
            "usd_exchange_rate": usd_rate,
            "quota_display_type": status.get("quota_display_type") or "CNY",
            "formula": "CNY = quota / quota_per_unit * usd_exchange_rate",
        },
        "metrics": {
            "usage_cny": total_money["cny"],
            "usage_usd": total_money["usd"],
            "usage_quota": total_quota,
            "total_requests": len(filtered),
            "consume_count": len(consume),
            "error_count": len(errors),
            "top_task_user": top_task_user,
            "top_task_count": top_task_n,
            "top_error_user": top_err_user,
            "top_error_count": top_err_n,
        },
        "type_counts": type_counts,
        "top_models": [{"model": m, "count": c} for m, c in model_counts],
        "logs": logs,
        "log_total_in_window": len(filtered),
        "log_returned": len(logs),
        "generated_at": end_dt.strftime("%Y-%m-%d %H:%M:%S"),
        "cached": cached,
    }


def build_report(env: dict[str, str], hours: int | None = None, period: str | None = None) -> dict[str, Any]:
    overview = build_overview(env)
    now = datetime.now(TZ_SH)
    if period == "morning":
        # previous calendar day 00:00–12:00 CST
        day = (now - timedelta(days=1)).date()
        start = datetime(day.year, day.month, day.day, 0, 0, 0, tzinfo=TZ_SH)
        end = datetime(day.year, day.month, day.day, 12, 0, 0, tzinfo=TZ_SH)
        label = f"早报 {day.isoformat()} 00:00–12:00"
    elif period == "evening":
        day = (now - timedelta(days=1)).date() if now.hour < 12 else now.date()
        start = datetime(day.year, day.month, day.day, 12, 0, 0, tzinfo=TZ_SH)
        end = datetime(day.year, day.month, day.day, 23, 59, 59, tzinfo=TZ_SH)
        label = f"晚报 {day.isoformat()} 12:00–24:00"
    else:
        h = hours if hours and hours > 0 else 12
        end = now
        start = now - timedelta(hours=h)
        label = f"近{h}小时"

    start_ts = int(start.timestamp())
    end_ts = int(end.timestamp())
    qpu = overview["conversion"]["quota_per_unit"]
    rate = overview["conversion"]["usd_exchange_rate"]

    # Re-use cached raw logs then time-slice (covers last 3 days; enough for digests)
    with _cache_lock:
        raw = list(_cache["logs"] or [])
    flt = load_filter()
    items = dedupe_by_id(apply_filter(raw, flt))
    sliced = [i for i in items if start_ts <= int(i.get("created_at") or 0) <= end_ts]
    sliced.sort(key=lambda x: (x.get("created_at") or 0, x.get("id") or 0), reverse=True)

    consume = [i for i in sliced if i.get("type") == 2]
    errors = [i for i in sliced if i.get("type") == 5]
    total_quota = sum(float(i.get("quota") or 0) for i in consume)
    money = money_from_quota(total_quota, qpu, rate)
    user_task = Counter(i.get("username") or "(unknown)" for i in consume).most_common(8)
    user_err = Counter(i.get("username") or "(unknown)" for i in errors).most_common(8)
    models = Counter((i.get("model_name") or "(无)") for i in consume).most_common(8)

    error_rows = [format_log(i, qpu, rate) for i in errors[:40]]
    recent = [format_log(i, qpu, rate) for i in sliced[:80]]

    return {
        "ok": True,
        "title": "追觅客户监控 · 摘要",
        "period_label": label,
        "period": period or f"hours_{hours or 12}",
        "window": {
            "start": start.strftime("%Y-%m-%d %H:%M:%S"),
            "end": end.strftime("%Y-%m-%d %H:%M:%S"),
            "tz": "Asia/Shanghai",
        },
        "metrics": {
            "usage_cny": money["cny"],
            "usage_usd": money["usd"],
            "usage_quota": total_quota,
            "total_requests": len(sliced),
            "consume_count": len(consume),
            "error_count": len(errors),
        },
        "top_task_users": [{"username": u, "count": c} for u, c in user_task],
        "top_error_users": [{"username": u, "count": c} for u, c in user_err],
        "top_models": [{"model": m, "count": c} for m, c in models],
        "errors": error_rows,
        "recent_logs": recent,
        "conversion": overview["conversion"],
        "generated_at": now.strftime("%Y-%m-%d %H:%M:%S"),
        "site_wide": True,
    }


AIPDD_DEFAULT_BASE = "https://api.aipdd.work"
AIPDD_WALLET_PATHS = ["/v1/user", "/v1/wallet", "/v1/account", "/v1/balance", "/api/user/self"]
DEFAULT_AWCOIN_RMB = 0.0001
VOLC_BILLING_HOST = "billing.volcengineapi.com"
VOLC_BILLING_SERVICE = "billing"
VOLC_BILLING_REGION = "cn-north-1"
VOLC_CONTENT_TYPE = "application/x-www-form-urlencoded"


def _empty_aipdd(error: str | None) -> dict[str, Any]:
    return {"configured": False, "cny": None, "usd": None, "awcoin": None, "error": error}


def _empty_volces(error: str | None) -> dict[str, Any]:
    return {"configured": False, "cny": None, "usd": None, "error": error}


def _aipdd_base(env: dict[str, str]) -> str:
    raw = (env.get("AIPDD_BASE_URL") or env.get("AIPDD_BASE") or AIPDD_DEFAULT_BASE).strip().rstrip("/")
    if "newapi.aipdd.work" in raw.lower() or "susciyuan.com" in raw.lower():
        return AIPDD_DEFAULT_BASE
    return raw or AIPDD_DEFAULT_BASE


def _as_finite_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and value.strip():
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _looks_like_rate(obj: Any) -> bool:
    if not isinstance(obj, dict):
        return False
    keys = set(obj)
    return "rmb" in keys and "usd" in keys and not any(
        any(token in k.lower() for token in ("awcoin", "balance", "wallet", "credit")) for k in keys
    )


def _looks_like_newapi_quota(obj: Any) -> bool:
    if not isinstance(obj, dict):
        return False
    has_quota = obj.get("quota") is not None and obj.get("used_quota") is not None
    has_awcoin = obj.get("awcoin") is not None or obj.get("awCoin") is not None or obj.get("aw_coin") is not None
    return has_quota and not has_awcoin


def _pick_awcoin(obj: Any) -> float | None:
    if not isinstance(obj, dict) or _looks_like_rate(obj) or _looks_like_newapi_quota(obj):
        return None
    for key in (
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
    ):
        if key in obj:
            n = _as_finite_number(obj.get(key))
            if n is not None:
                return n
    return None


def _extract_awcoin(payload: Any) -> float | None:
    direct = _as_finite_number(payload)
    if direct is not None:
        return direct
    if not isinstance(payload, dict):
        return None
    if payload.get("code") is not None and int(payload.get("code") or 0) != 0:
        return None
    if payload.get("success") is False:
        return None
    data = payload.get("data")
    n = _as_finite_number(data)
    if n is not None:
        return n
    found = _pick_awcoin(data)
    if found is not None:
        return found
    if isinstance(data, dict):
        for nested in (data.get("wallet"), data.get("account"), data.get("user")):
            found = _pick_awcoin(nested)
            if found is not None:
                return found
    return _pick_awcoin(payload)


def _aipdd_get(base: str, key: str, path: str) -> dict[str, Any]:
    host = urllib.parse.urlparse(base).hostname or ""
    if "newapi.aipdd.work" in host or "susciyuan.com" in host:
        raise RuntimeError("blocked host")
    url = f"{base.rstrip('/')}{path}"
    req = urllib.request.Request(
        url,
        headers={
            "X-API-Key": key,
            "Authorization": f"Bearer {key}",
            "Accept": "application/json",
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=45) as resp:
        return json.loads(resp.read().decode())


def _volc_norm_query(params: dict[str, str]) -> str:
    parts = []
    for key in sorted(params):
        parts.append(
            f"{urllib.parse.quote(key, safe='-_.~')}={urllib.parse.quote(str(params[key]), safe='-_.~')}"
        )
    return "&".join(parts).replace("+", "%20")


def _volc_sign(ak: str, sk: str, x_date: str) -> dict[str, str]:
    query = {"Action": "QueryBalanceAcct", "Version": "2022-01-01"}
    body = ""
    x_content = hashlib.sha256(body.encode("utf-8")).hexdigest()
    signed_headers = "content-type;host;x-content-sha256;x-date"
    canonical = "\n".join(
        [
            "GET",
            "/",
            _volc_norm_query(query),
            "\n".join(
                [
                    f"content-type:{VOLC_CONTENT_TYPE}",
                    f"host:{VOLC_BILLING_HOST}",
                    f"x-content-sha256:{x_content}",
                    f"x-date:{x_date}",
                ]
            ),
            "",
            signed_headers,
            x_content,
        ]
    )
    hashed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    short = x_date[:8]
    scope = f"{short}/{VOLC_BILLING_REGION}/{VOLC_BILLING_SERVICE}/request"
    string_to_sign = "\n".join(["HMAC-SHA256", x_date, scope, hashed])
    k_date = hmac.new(sk.encode("utf-8"), short.encode("utf-8"), hashlib.sha256).digest()
    k_region = hmac.new(k_date, VOLC_BILLING_REGION.encode("utf-8"), hashlib.sha256).digest()
    k_service = hmac.new(k_region, VOLC_BILLING_SERVICE.encode("utf-8"), hashlib.sha256).digest()
    k_signing = hmac.new(k_service, b"request", hashlib.sha256).digest()
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "query": _volc_norm_query(query),
        "authorization": (
            f"HMAC-SHA256 Credential={ak}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
        ),
        "x_date": x_date,
        "x_content": x_content,
    }


def _fetch_volc_balance(ak: str, sk: str) -> float:
    now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    signed = _volc_sign(ak, sk, now)
    url = f"https://{VOLC_BILLING_HOST}/?{signed['query']}"
    req = urllib.request.Request(
        url,
        headers={
            "Host": VOLC_BILLING_HOST,
            "Content-Type": VOLC_CONTENT_TYPE,
            "X-Date": signed["x_date"],
            "X-Content-Sha256": signed["x_content"],
            "Authorization": signed["authorization"],
            "Accept": "application/json",
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=45) as resp:
        payload = json.loads(resp.read().decode())
    meta = payload.get("ResponseMetadata") or {}
    if meta.get("Error"):
        raise RuntimeError("volc error")
    result = payload.get("Result") if isinstance(payload.get("Result"), dict) else payload
    raw = result.get("AvailableBalance")
    if raw is None:
        raw = result.get("CashBalance")
    n = _as_finite_number(raw)
    if n is None:
        raise RuntimeError("volc balance missing")
    return n


def build_balances(env: dict[str, str], force: bool = False) -> dict[str, Any]:
    """Official AIPDD AWCoin + Volcengine billing balances. Missing keys stay unconfigured."""
    generated_at = datetime.now(TZ_SH).strftime("%Y-%m-%d %H:%M:%S")
    base = _aipdd_base(env)
    aipdd_key = (env.get("AIPDD_API_KEY") or "").strip()
    volc_ak = (env.get("VOLC_ACCESS_KEY_ID") or "").strip()
    volc_sk = (env.get("VOLC_SECRET_ACCESS_KEY") or "").strip()

    if not aipdd_key and not (volc_ak and volc_sk):
        missing = [k for k, v in (("VOLC_ACCESS_KEY_ID", volc_ak), ("VOLC_SECRET_ACCESS_KEY", volc_sk)) if not v]
        return {
            "ok": True,
            "aipdd": _empty_aipdd("未配置 AIPDD_API_KEY"),
            "volces": _empty_volces("未配置 " + " / ".join(missing)),
            "generated_at": generated_at,
            "cached": False,
        }

    with _cache_lock:
        cached_payload = _balances_cache.get("payload")
        cached_ts = float(_balances_cache.get("ts") or 0)
    if not force and cached_payload is not None and (time.time() - cached_ts) < CACHE_TTL_SEC:
        out = dict(cached_payload)
        out["cached"] = True
        return out

    rmb = DEFAULT_AWCOIN_RMB
    usd_rate = None
    if aipdd_key:
        try:
            rate_payload = _aipdd_get(base, aipdd_key, "/system/awcoin-rate")
            data = rate_payload.get("data") if isinstance(rate_payload.get("data"), dict) else {}
            rmb = _as_finite_number(data.get("rmb")) or DEFAULT_AWCOIN_RMB
            usd_rate = _as_finite_number(data.get("usd"))
        except Exception:
            rmb = DEFAULT_AWCOIN_RMB

    if aipdd_key:
        awcoin = None
        for path in AIPDD_WALLET_PATHS:
            try:
                payload = _aipdd_get(base, aipdd_key, path)
                awcoin = _extract_awcoin(payload)
                if awcoin is not None:
                    break
            except Exception:
                continue
        if awcoin is None:
            aipdd = {
                "configured": True,
                "cny": None,
                "usd": None,
                "awcoin": None,
                "error": "AIPDD 余额查询失败",
            }
        else:
            aipdd = {
                "configured": True,
                "cny": round(awcoin * rmb, 4),
                "usd": round(awcoin * usd_rate, 6) if usd_rate else None,
                "awcoin": awcoin,
                "error": None,
            }
    else:
        aipdd = _empty_aipdd("未配置 AIPDD_API_KEY")

    if not volc_ak or not volc_sk:
        missing = [k for k, v in (("VOLC_ACCESS_KEY_ID", volc_ak), ("VOLC_SECRET_ACCESS_KEY", volc_sk)) if not v]
        volces: dict[str, Any] = _empty_volces("未配置 " + " / ".join(missing))
    else:
        try:
            cny = _fetch_volc_balance(volc_ak, volc_sk)
            volces = {"configured": True, "cny": round(cny, 4), "usd": None, "error": None, "currency": "CNY"}
        except Exception:
            volces = {"configured": True, "cny": None, "usd": None, "error": "火山引擎余额查询失败"}

    payload = {
        "ok": True,
        "aipdd": aipdd,
        "volces": volces,
        "generated_at": datetime.now(TZ_SH).strftime("%Y-%m-%d %H:%M:%S"),
        "cached": False,
    }
    with _cache_lock:
        _balances_cache["ts"] = time.time()
        _balances_cache["payload"] = payload
    return payload


class Handler(BaseHTTPRequestHandler):
    env: dict[str, str] = {}

    def log_message(self, fmt: str, *args: Any) -> None:
        # keep access logs short; never log Authorization
        sys_stderr = __import__("sys").stderr
        sys_stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj: Any, cookie: str | None = None) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def _read_login_creds(self) -> tuple[str, str]:
        length = int(self.headers.get("Content-Length") or "0")
        raw = self.rfile.read(length) if length > 0 else b""
        ctype = (self.headers.get("Content-Type") or "").lower()
        if "application/json" in ctype:
            try:
                obj = json.loads(raw.decode("utf-8", errors="replace") or "{}")
            except json.JSONDecodeError:
                obj = {}
            if not isinstance(obj, dict):
                obj = {}
            return str(obj.get("username") or ""), str(obj.get("password") or "")
        form = parse_qs(raw.decode("utf-8", errors="replace"))
        return (form.get("username") or [""])[0], (form.get("password") or [""])[0]

    def _redirect(self, location: str, cookie: str | None = None) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _secure_cookie(self) -> bool:
        return (self.headers.get("X-Forwarded-Proto") or "").lower() == "https"

    def do_POST(self) -> None:  # noqa: N802
        env = load_env(ENV_PATH)
        parsed = urlparse(self.path)
        path = parsed.path
        if path in ("/logout", "/logout/", "/api/logout", "/api/logout/"):
            cookie = _session_cookie("", self._secure_cookie(), clear=True)
            if path.startswith("/api/"):
                self._json(200, {"ok": True}, cookie)
                return
            self._redirect("/", cookie)
            return
        if path not in ("/login", "/api/login"):
            self._json(405, {"ok": False, "error": "method not allowed"})
            return
        json_mode = path == "/api/login"
        creds = _dashboard_creds(env)
        if creds is None:
            if json_mode:
                self._json(200, {"ok": True})
            else:
                self._redirect("/")
            return
        user, pw = creds
        got_user, got_pw = self._read_login_creds()
        if (
            len(got_user) == len(user)
            and len(got_pw) == len(pw)
            and hmac.compare_digest(got_user, user)
            and hmac.compare_digest(got_pw, pw)
        ):
            token = _make_session_token(user, pw)
            cookie = _session_cookie(token, self._secure_cookie())
            if json_mode:
                self._json(200, {"ok": True}, cookie)
            else:
                self._redirect("/", cookie)
            return
        if json_mode:
            self._json(401, {"ok": False, "error": "账号或密码不对"})
            return
        self._send(200, _login_html(True), "text/html; charset=utf-8")

    def do_GET(self) -> None:  # noqa: N802
        env = load_env(ENV_PATH)
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path in ("/logout", "/logout/", "/api/logout", "/api/logout/"):
            self._redirect("/", _session_cookie("", self._secure_cookie(), clear=True))
            return
        if path == "/login":
            self._send(200, _login_html(False), "text/html; charset=utf-8")
            return
        if path == "/api/health":
            self._json(200, {"ok": True, "ts": int(time.time())})
            return
        if path == "/api/session":
            if not _is_authed(self, env):
                _json_unauthorized(self)
                return
            self._json(200, {"ok": True})
            return

        authed = _is_authed(self, env)
        if not authed:
            if path.startswith("/api/"):
                _json_unauthorized(self)
                return
            self._send(200, _login_html(False), "text/html; charset=utf-8")
            return

        try:
            if path == "/" or path == "/index.html" or path == "/app.html":
                html = (STATIC_DIR / "index.html").read_bytes()
                self._send(200, html, "text/html; charset=utf-8")
                return
            if path.startswith("/static/"):
                rel = path[len("/static/") :]
                if ".." in rel or rel.startswith("/"):
                    self._json(400, {"ok": False, "error": "bad path"})
                    return
                fp = STATIC_DIR / rel
                if not fp.is_file():
                    self._json(404, {"ok": False, "error": "not found"})
                    return
                ctype = "application/octet-stream"
                if fp.suffix == ".css":
                    ctype = "text/css; charset=utf-8"
                elif fp.suffix == ".js":
                    ctype = "application/javascript; charset=utf-8"
                elif fp.suffix == ".html":
                    ctype = "text/html; charset=utf-8"
                self._send(200, fp.read_bytes(), ctype)
                return
            if path == "/api/overview":
                force = qs.get("refresh", ["0"])[0] in ("1", "true", "yes")
                self._json(200, build_overview(self.env, force=force))
                return
            if path == "/api/balances":
                force = qs.get("refresh", ["0"])[0] in ("1", "true", "yes")
                self._json(200, build_balances(env, force=force))
                return
            if path == "/api/report":
                hours = None
                if "hours" in qs:
                    try:
                        hours = int(qs["hours"][0])
                    except Exception:
                        hours = 12
                period = qs.get("period", [None])[0]
                self._json(200, build_report(self.env, hours=hours, period=period))
                return
            if path == "/api/health":
                self._json(200, {"ok": True, "ts": int(time.time())})
                return
            self._json(404, {"ok": False, "error": "not found"})
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")[:300]
            self._json(502, {"ok": False, "error": f"upstream HTTP {e.code}", "detail": body})
        except Exception as e:
            self._json(500, {"ok": False, "error": str(e)})


def main() -> None:
    if not ENV_PATH.exists():
        raise SystemExit(f"env file missing: {ENV_PATH}")
    env = load_env(ENV_PATH)
    for key in ("SUSCIYUAN_BASE", "SUSCIYUAN_ACCESS_TOKEN"):
        if not env.get(key):
            raise SystemExit(f"missing {key} in env")
    Handler.env = env
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Susciyuan monitor listening on http://{HOST}:{PORT}/", flush=True)
    print(f"env={ENV_PATH} filter={FILTER_PATH}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("shutting down", flush=True)
        server.shutdown()


if __name__ == "__main__":
    main()
