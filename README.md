# 追觅 / Susciyuan 内部监控

面向 **susciyuan.com（追觅）** 的内部 H5 监控看板，以及错误日志轮询脚本。

看板通过服务端调用 New API（`/api/status`、`/api/log/`），密钥只留在运行时环境，前端不接触 token。

支持两种运行方式：

- **阿里云 ESA Pages**：静态资源 + 边缘函数（`src/index.js`）代理 `/api/*`
- **本机 / 服务器 Python**：`app.py` 常驻进程（标准库，无需 pip）

## 功能

- H5 看板：近 3 天用量、错误、用户/模型分布（默认全站 `site_wide`）
- 错误日志轮询：`monitor.py` 按上次看到的 log id 增量拉取 type=5 错误
- 摘要渲染：`render_report.py` 从本地看板 `/api/report` 生成 HTML 摘要

## ESA Pages 部署

仓库根目录的 `esa.jsonc` 是 ESA 的唯一构建配置（会覆盖控制台同名字段）：

- `name`: `zhuimi-monitoring`
- `entry`: `./dist-worker/index.js`（边缘函数，由构建从 `src/index.js` 生成）
- `installCommand` / `buildCommand`: 见 `esa.jsonc`（使用根目录 `package.json` 的 `build` 脚本）
- `assets.directory`: `./dist`
- `assets.notFoundStrategy`: `404Page`（不要用 `singlePageApplication`，否则浏览器对 `/api/*` 的 XHR 可能被回退成 `index.html`）

构建脚本把 `static/` 复制到 `dist/`，并把 `src/index.js` 生成到 `dist-worker/index.js`（没有 React / Vite）。

ESA 构建信息里的环境变量会在 `npm run build` 时打进边缘函数；改变量后要重新构建。不要把真实值写进仓库。

ESA 构建环境变量还要加上 `AIPDD_BASE`、`AIPDD_ACCESS_TOKEN`、`AIPDD_USER_ID`、`VOLCES_CHANNEL_ID`（只加名字，不要写真实值），加完后重新构建。

### 重建步骤

1. 把代码推送到 GitHub 仓库 `main` 分支。
2. ESA 控制台绑定该仓库后，推送会触发重建；也可在项目页手动重新部署。
3. 在 ESA 控制台的**构建信息**里配置环境变量（只填键名对应的值，不要写进仓库）。
4. 打开站点根路径查看看板；`GET /api/health`、`GET /api/overview` 由边缘函数处理。
5. 若构建报找不到 `package.json`，确认仓库根目录已包含本文件，且根目录不是只含 Python。

Node 版本：`package.json` 的 `engines.node` 要求 `>=18`。

## 本机 Python 运行

需要 Python 3（仅标准库）。默认端口 **8787**。

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
python3 monitor.py --init
python3 monitor.py
```

摘要（需看板已启动）：

```bash
python3 render_report.py --hours 12
python3 render_report.py --period morning
python3 render_report.py --period evening
```

## 环境变量（仅键名）

在 ESA 控制台、`.env` 或进程环境中配置，**不要把真实值提交到 Git**。

| 键 | 用途 |
|----|------|
| `SUSCIYUAN_BASE` | New API 站点根 URL（ESA 默认 `https://susciyuan.com`） |
| `SUSCIYUAN_ACCESS_TOKEN` | New API 访问令牌（仅服务端 / 边缘函数） |
| `SUSCIYUAN_USER_ID` | New API 用户 id（默认 `1`） |
| `DASHBOARD_USER` | 看板 HTTP Basic 用户名（默认 `zhuimi`） |
| `DASHBOARD_PASSWORD` | 看板 HTTP Basic 密码（未设置则不启用鉴权） |
| `AIPDD_BASE` | AIPDD New API 根 URL（默认 `https://api.aipdd.work`） |
| `AIPDD_ACCESS_TOKEN` | AIPDD 管理员令牌（仅服务端 / 边缘函数；未配置则余额卡显示「待配置」） |
| `AIPDD_USER_ID` | AIPDD 用户 id（默认 `1`） |
| `VOLCES_CHANNEL_ID` | AIPDD 上火山引擎渠道 id（未配置则该卡显示「待配置」） |
| `HOST` | Python 监听地址，默认 `0.0.0.0` |
| `PORT` | Python 监听端口，默认 `8787` |
| `SUSCIYUAN_ENV` | env 文件路径，默认仓库根目录 `.env` |
| `SUSCIYUAN_STATE` | 轮询状态文件路径 |
| `DASHBOARD_URL` | `render_report.py` 访问的看板地址 |

## 接口

| 路径 | 说明 |
|------|------|
| `GET /` | H5 看板（ESA 静态 `dist/index.html`，或 Python 读取 `static/index.html`） |
| `GET /api/overview` | 指标 + 近 3 天日志（`?refresh=1` 跳过缓存） |
| `GET /api/balances` | AIPDD / 火山引擎剩余金额（`?refresh=1` 跳过约 45s 缓存；不增加 overview 出站请求） |
| `GET /api/report?hours=12` | 结构化摘要（仅 Python） |
| `GET /api/report?period=morning / evening` | 半天窗口摘要（仅 Python） |
| `GET /api/health` | 存活检查 |

## 文件

- `esa.jsonc` — ESA Pages 构建与路由
- `package.json` — ESA 构建脚本（无运行时依赖）
- `scripts/build.mjs` — 将 `static/` 复制到 `dist/`，并生成 `dist-worker/index.js`
- `src/index.js` — ESA 边缘函数（`/api/health`、`/api/overview`、`/api/balances`）
- `static/index.html` — H5 界面（构建后进入 `dist/`）
- `static/404.html` — ESA `404Page` 回退页
- `app.py` — Python 看板服务
- `monitor.py` — 错误日志轮询
- `render_report.py` — HTML 摘要
- `client_filter.json` — 全站过滤开关（无密钥）
- `start.sh` — Python 启动脚本
- `.env.example` — 环境变量模板

## 安全

- 不要提交 `.env`、`*.env`、`susciyuan.env` 或状态 JSON
- 不要把 `SUSCIYUAN_ACCESS_TOKEN` 或 `AIPDD_ACCESS_TOKEN` 写进前端或 README
- 边缘函数失败时只返回 `{ok:false,error}`，不会回传 token
