#!/usr/bin/env python3
"""Poll SusToken/New API error logs and emit a JSON report for alerting."""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

STATE_PATH = Path(os.environ.get(
    "SUSCIYUAN_STATE",
    str(Path(__file__).resolve().parent / "susciyuan-monitor-state.json"),
))
ENV_PATH = Path(os.environ.get(
    "SUSCIYUAN_ENV",
    str(Path(__file__).resolve().parent / ".env"),
))


def load_env(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip()
    return env


def load_state() -> dict:
    if STATE_PATH.exists():
        return json.loads(STATE_PATH.read_text())
    return {"last_seen_id": 0}


def save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n")
    os.chmod(STATE_PATH, 0o600)


def api_get(base: str, token: str, user_id: str, path: str, params: dict) -> dict:
    qs = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    url = f"{base.rstrip('/')}{path}?{qs}"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "New-Api-User": str(user_id),
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def summarize_error(item: dict) -> dict:
    content = item.get("content") or ""
    status = None
    if "status_code=" in content:
        try:
            status = int(content.split("status_code=", 1)[1].split(",", 1)[0].strip().split()[0])
        except Exception:
            status = None
    return {
        "id": item.get("id"),
        "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(item.get("created_at") or 0)),
        "created_at": item.get("created_at"),
        "username": item.get("username"),
        "model_name": item.get("model_name"),
        "token_name": item.get("token_name"),
        "channel_id": item.get("channel_id"),
        "group": item.get("group"),
        "status_code": status,
        "content": content,
    }


def main() -> int:
    init_only = "--init" in sys.argv
    env = load_env(ENV_PATH)
    base = env["SUSCIYUAN_BASE"]
    token = env["SUSCIYUAN_ACCESS_TOKEN"]
    user_id = env.get("SUSCIYUAN_USER_ID", "1")

    # type=5 is Error on this deployment (UI: 错误)
    data = api_get(
        base,
        token,
        user_id,
        "/api/log/",
        {"p": 1, "page_size": 50, "type": 5},
    )
    if not data.get("success"):
        print(json.dumps({"ok": False, "error": data.get("message") or "api failed"}, ensure_ascii=False))
        return 1

    payload = data.get("data") or {}
    items = payload.get("items") or []
    items_sorted = sorted(items, key=lambda x: x.get("id") or 0)
    state = load_state()
    last_seen = int(state.get("last_seen_id") or 0)

    if init_only:
        max_id = max((i.get("id") or 0) for i in items_sorted) if items_sorted else last_seen
        state["last_seen_id"] = max_id
        state["initialized_at"] = int(time.time())
        save_state(state)
        print(json.dumps({
            "ok": True,
            "init": True,
            "last_seen_id": max_id,
            "recent_error_count": len(items_sorted),
            "sample": [summarize_error(i) for i in items_sorted[-3:]],
        }, ensure_ascii=False, indent=2))
        return 0

    new_items = [i for i in items_sorted if (i.get("id") or 0) > last_seen]
    report = {
        "ok": True,
        "checked_at": int(time.time()),
        "last_seen_id": last_seen,
        "new_count": len(new_items),
        "errors": [summarize_error(i) for i in new_items],
    }
    if new_items:
        state["last_seen_id"] = max(i.get("id") or 0 for i in new_items)
        state["last_alert_at"] = int(time.time())
        save_state(state)
        report["last_seen_id"] = state["last_seen_id"]
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(json.dumps({"ok": False, "error": f"HTTP {e.code}", "body": body[:500]}, ensure_ascii=False))
        raise SystemExit(2)
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
        raise SystemExit(2)
