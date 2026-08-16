#!/usr/bin/env python3
"""Render an HTML email digest from the local dashboard /api/report."""
from __future__ import annotations

import json
import os
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

TZ = timezone(timedelta(hours=8))
BASE = os.environ.get("DASHBOARD_URL", "http://127.0.0.1:8787")
OUT = Path(os.environ.get(
    "REPORT_OUT",
    "/tmp/susciyuan-report.html",
))


def _opener():
    env_path = Path(os.environ.get(
        "SUSCIYUAN_ENV",
        str(Path(__file__).resolve().parent / ".env"),
    ))
    user, pw = "zhuimi", ""
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if line.startswith("DASHBOARD_USER="):
                user = line.split("=", 1)[1].strip() or user
            elif line.startswith("DASHBOARD_PASSWORD="):
                pw = line.split("=", 1)[1].strip()
    if not pw:
        return urllib.request.build_opener()
    mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    mgr.add_password(None, BASE, user, pw)
    return urllib.request.build_opener(urllib.request.HTTPBasicAuthHandler(mgr))


def fetch_report(period: str | None, hours: int | None) -> dict:
    if period:
        url = f"{BASE}/api/report?period={period}"
    else:
        url = f"{BASE}/api/report?hours={hours or 12}"
    with _opener().open(url, timeout=60) as resp:
        return json.loads(resp.read().decode())


def esc(s: object) -> str:
    return (
        str(s if s is not None else "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def render(data: dict, title: str) -> str:
    m = data.get("metrics") or data.get("summary") or {}
    # normalize keys from /api/report
    usage = m.get("usage_cny", m.get("cny", 0))
    reqs = m.get("total_requests", m.get("request_count", 0))
    errs = m.get("error_count", 0)
    top_task = m.get("top_task_user") or (data.get("top_task_users") or [{}])
    if isinstance(top_task, list):
        top_task_s = ", ".join(f"{x.get('username')}({x.get('count')})" for x in top_task[:3]) or "—"
    else:
        top_task_s = f"{top_task} ({m.get('top_task_count', '')})"
    top_err = data.get("top_error_users") or []
    if top_err:
        top_err_s = ", ".join(f"{x.get('username')}({x.get('count')})" for x in top_err[:3])
    else:
        top_err_s = f"{m.get('top_error_user', '—')} ({m.get('top_error_count', '')})"

    errors = data.get("errors") or data.get("recent_errors") or []
    consumes = data.get("consumes") or data.get("top_consumes") or []
    window = data.get("window") or {}

    err_rows = ""
    for e in errors[:15]:
        err_rows += (
            f"<tr><td>{esc(e.get('time') or e.get('created_at_str'))}</td>"
            f"<td>{esc(e.get('username'))}</td>"
            f"<td>{esc(e.get('model') or e.get('model_name'))}</td>"
            f"<td>{esc(e.get('status_code') or '')}</td>"
            f"<td style='word-break:break-all'>{esc((e.get('content') or '')[:280])}</td></tr>"
        )
    if not err_rows:
        err_rows = "<tr><td colspan='5'>该时段无错误日志</td></tr>"

    now = datetime.now(TZ).strftime("%Y-%m-%d %H:%M")
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{esc(title)}</title></head>
<body style="margin:0;padding:0;background:#0b1220;color:#e8eef9;font-family:-apple-system,BlinkMacSystemFont,'PingFang SC','Microsoft YaHei',sans-serif">
  <div style="max-width:720px;margin:0 auto;padding:24px 16px">
    <h1 style="margin:0 0 8px;font-size:22px">{esc(title)}</h1>
    <p style="color:#93a0b8;margin:0 0 18px;font-size:13px">生成时间 {esc(now)}（上海） · 站点 susciyuan.com · 追觅全站</p>
    <table style="width:100%;border-collapse:separate;border-spacing:8px 8px;margin:0 -8px 18px">
      <tr>
        <td style="background:#141e30;border-radius:12px;padding:14px;width:33%"><div style="color:#93a0b8;font-size:12px">用量金额</div><div style="font-size:22px;font-weight:700">¥{esc(usage)}</div></td>
        <td style="background:#141e30;border-radius:12px;padding:14px;width:33%"><div style="color:#93a0b8;font-size:12px">请求/任务数</div><div style="font-size:22px;font-weight:700">{esc(reqs)}</div></td>
        <td style="background:#141e30;border-radius:12px;padding:14px;width:33%"><div style="color:#93a0b8;font-size:12px">错误总数</div><div style="font-size:22px;font-weight:700;color:#ff6b7a">{esc(errs)}</div></td>
      </tr>
    </table>
    <div style="background:#141e30;border-radius:12px;padding:14px;margin-bottom:12px">
      <div style="color:#93a0b8;font-size:12px;margin-bottom:6px">活跃概况</div>
      <div>最多任务用户：{esc(top_task_s)}</div>
      <div>最多错误用户：{esc(top_err_s)}</div>
      <div style="color:#93a0b8;font-size:12px;margin-top:8px">窗口：{esc(window.get('start') or data.get('period') or '')} → {esc(window.get('end') or '')}</div>
    </div>
    <h2 style="font-size:16px;margin:18px 0 8px">错误明细（最多 15 条）</h2>
    <table style="width:100%;border-collapse:collapse;font-size:12px;background:#141e30;border-radius:12px;overflow:hidden">
      <thead><tr style="background:#1a2740;text-align:left">
        <th style="padding:8px">时间</th><th style="padding:8px">用户</th><th style="padding:8px">模型</th><th style="padding:8px">状态</th><th style="padding:8px">内容</th>
      </tr></thead>
      <tbody>{err_rows}</tbody>
    </table>
    <p style="color:#93a0b8;font-size:11px;margin-top:18px">由 Zhuimi 自动发送 · 内部报告请勿外传</p>
  </div>
</body></html>"""


def main() -> int:
    period = None
    hours = 12
    title = "追觅 Susciyuan 运营报告"
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--period":
            period = args[i + 1]; i += 2
        elif args[i] == "--hours":
            hours = int(args[i + 1]); i += 2
        elif args[i] == "--title":
            title = args[i + 1]; i += 2
        else:
            i += 1
    if period == "morning":
        title = title or "追觅 Susciyuan 早报"
        hours = hours or 15
    elif period == "evening":
        title = title or "追觅 Susciyuan 晚报"

    # Ensure dashboard is up
    try:
        data = fetch_report(period if period in ("morning", "evening") else None, hours)
    except Exception:
        # fallback: hours-only
        data = fetch_report(None, hours)

    if not data.get("ok", True) and data.get("ok") is False:
        print(json.dumps(data, ensure_ascii=False))
        return 1

    html = render(data, title)
    OUT.write_text(html, encoding="utf-8")
    meta = {
        "ok": True,
        "path": str(OUT),
        "title": title,
        "metrics": data.get("metrics") or data.get("summary"),
        "error_count": (data.get("metrics") or {}).get("error_count"),
    }
    print(json.dumps(meta, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
