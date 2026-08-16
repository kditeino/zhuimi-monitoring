import { cp, mkdir, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dist = join(root, "dist");
const staticDir = join(root, "static");

await rm(dist, { recursive: true, force: true });
await mkdir(dist, { recursive: true });
await cp(staticDir, dist, { recursive: true });
console.log("copied static/ -> dist/");
