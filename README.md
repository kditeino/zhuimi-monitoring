# 追觅 / Susciyuan 内部监控

面向 **susciyuan.com（追觅）** 的内部 H5 监控看板，以及错误日志轮询脚本。

看板用 Python 后端调用 New API（`/api/status`、`/api/log/`），在服务端读取密钥，前端不接触 token。

> **部署说明：** 阿里云 ESA 通常是静态/边缘托管，不适合直接跑本仓库。本应用带 Python 后端，需要能常驻进程、出站访问 New API 的主机（本机、容器或任意能跑 `python3` 的服务器）。

## 功能

- H5 看板：近 3 天用量、错误、用户/模型分布（默认全站 `site_wide`）
- 错误日志轮询：`monitor.py` 按上次看到的 log id 增量拉取 type=5 错误
- 摘要渲染：`render_report.py` 从本地看板 `/api/report` 生成 HTML 摘要

## 运行

需要 Python 3（仅标准库，无需 pip 依赖）。默认端口 **8787**。

```bash
cp .env.example .env
# 编辑 .env，填入下方环境变量
chmod +x start.sh
./start.sh
# 等价：python3 app.py
# 监听 http://0.0.0.0:8787/
```

错误轮询：

```bash
python3 monitor.py --init   # 首次记下当前最大错误 id
python3 monitor.py          # 之后增量输出新错误 JSON
```

摘要（需看板已启动）：

```bash
python3 render_report.py --hours 12
python3 render_report.py --period morning
python3 render_report.py --period evening
```

## 环境变量（仅键名）

在 `.env` 或进程环境中配置，**不要把真实值提交到 Git**。

| 键 | 用途 |
|----|------|
| `SUSCIYUAN_BASE` | New API 站点根 URL |
| `SUSCIYUAN_ACCESS_TOKEN` | New API 访问令牌（仅服务端） |
| `SUSCIYUAN_USER_ID` | New API 用户 id |
| `DASHBOARD_USER` | 看板 HTTP Basic 用户名（可选） |
| `DASHBOARD_PASSWORD` | 看板 HTTP Basic 密码（未设置则不启用鉴权） |
| `HOST` | 监听地址，默认 `0.0.0.0` |
| `PORT` | 监听端口，默认 `8787` |
| `SUSCIYUAN_ENV` | env 文件路径，默认仓库根目录 `.env` |
| `SUSCIYUAN_STATE` | 轮询状态文件路径 |
| `DASHBOARD_URL` | `render_report.py` 访问的看板地址 |

## 接口

| 路径 | 说明 |
|------|------|
| `GET /` | H5 看板 |
| `GET /api/overview` | 指标 + 近 3 天日志（`?refresh=1` 跳过缓存） |
| `GET /api/report?hours=12` | 结构化摘要 |
| `GET /api/report?period=morning / evening` | 半天窗口摘要 |
| `GET /api/health` | 存活检查 |

## 文件

- `app.py` — 看板服务（stdlib `ThreadingHTTPServer`）
- `static/index.html` — H5 界面
- `monitor.py` — 错误日志轮询
- `render_report.py` — HTML 摘要
- `client_filter.json` — 全站过滤开关（无密钥）
- `start.sh` — 启动脚本
- `.env.example` — 环境变量模板

## 安全

- 不要提交 `.env`、`*.env`、`susciyuan.env` 或状态 JSON
- 不要把 `SUSCIYUAN_ACCESS_TOKEN` 写进前端或 README
