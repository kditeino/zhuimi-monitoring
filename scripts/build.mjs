import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dist = join(root, "dist");
const distWorker = join(root, "dist-worker");
const staticDir = join(root, "static");
const srcWorker = join(root, "src", "index.js");

const BAKE_KEYS = [
  "SUSCIYUAN_BASE",
  "SUSCIYUAN_ACCESS_TOKEN",
  "SUSCIYUAN_USER_ID",
  "DASHBOARD_USER",
  "DASHBOARD_PASSWORD",
  "AIPDD_BASE_URL",
  "AIPDD_BASE",
  "AIPDD_API_KEY",
  "VOLC_ACCESS_KEY_ID",
  "VOLC_SECRET_ACCESS_KEY",
];

function bakedEnvLiteral() {
  const lines = BAKE_KEYS.map((key) => {
    const raw = process.env[key];
    const value = raw == null ? "" : String(raw);
    return "  " + key + ": " + JSON.stringify(value) + ",";
  });
  return "globalThis.BAKED_ENV = {\n" + lines.join("\n") + "\n};\n";
}

await rm(dist, { recursive: true, force: true });
await mkdir(dist, { recursive: true });
await cp(staticDir, dist, { recursive: true });
const loginHtml = await readFile(join(staticDir, "login.html"), "utf8");
const appHtml = await readFile(join(staticDir, "index.html"), "utf8");
await writeFile(join(dist, "index.html"), loginHtml, "utf8");
await writeFile(join(dist, "app.html"), appHtml, "utf8");
console.log("copied static/ -> dist/ (index.html is login, app.html is dashboard)");

const src = await readFile(srcWorker, "utf8");
await rm(distWorker, { recursive: true, force: true });
await mkdir(distWorker, { recursive: true });
const bakedHtml =
  "globalThis.BAKED_LOGIN_HTML = " +
  JSON.stringify(loginHtml) +
  ";\nglobalThis.BAKED_APP_HTML = " +
  JSON.stringify(appHtml) +
  ";\n";
await writeFile(join(distWorker, "index.js"), bakedEnvLiteral() + bakedHtml + src, "utf8");
console.log("wrote dist-worker/index.js (baked env keys and HTML; values not printed)");
