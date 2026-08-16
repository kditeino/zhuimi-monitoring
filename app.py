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
import hmac


def _dashboard_creds(env: dict[str, str]) -> tuple[str, str] | None:
    user = (env.get("DASHBOARD_USER") or "").strip()
    pw = (env.get("DASHBOARD_PASSWORD") or "").strip()
    if not pw:
        return None
    return (user or "zhuimi", pw)


def _check_basic_auth(handler: "Handler", env: dict[str, str]) -> bool:
    creds = _dashboard_creds(env)
    if creds is None:
        return True
    user, pw = creds
    header = handler.headers.get("Authorization") or ""
    if not header.startswith("Basic "):
        return False
    try:
        raw = base64.b64decode(header.split(" ", 1)[1]).decode("utf-8")
        got_user, got_pw = raw.split(":", 1)
    except Exception:
        return False
    return hmac.compare_digest(got_user, user) and hmac.compare_digest(got_pw, pw)


def _require_auth(handler: "Handler", env: dict[str, str]) -> bool:
    if _check_basic_auth(handler, env):
        return True
    body = b"Unauthorized"
    handler.send_response(401)
    handler.send_header("WWW-Authenticate", 'Basic realm="Zhuimi Monitor"')
    handler.send_header("Content-Type", "text/plain; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)
    return False


APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
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

    def _json(self, code: int, obj: Any) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self._send(code, body, "application/json; charset=utf-8")

    def do_GET(self) -> None:  # noqa: N802
        env = load_env(ENV_PATH)
        if not _require_auth(self, env):
            return
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        try:
            if path == "/" or path == "/index.html":
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
