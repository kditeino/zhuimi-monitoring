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
console.log("copied static/ -> dist/");

const src = await readFile(srcWorker, "utf8");
await rm(distWorker, { recursive: true, force: true });
await mkdir(distWorker, { recursive: true });
await writeFile(join(distWorker, "index.js"), bakedEnvLiteral() + src, "utf8");
console.log("wrote dist-worker/index.js (baked env keys only; values not printed)");
