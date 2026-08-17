import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { afterEach, describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import worker, {
  SESSION_COOKIE,
  makeSessionToken,
  renderLoginPage,
  verifySessionToken,
} from "../src/index.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

describe("web form login", { concurrency: 1 }, () => {
  afterEach(() => {
    globalThis.BAKED_ENV = undefined;
    delete globalThis.fetch;
  });

  test("login page is a real form password managers can fill", () => {
    const html = readFileSync(join(root, "static", "login.html"), "utf8");
    assert.ok(html.includes("<form"));
    assert.ok(html.includes('name="username"'));
    assert.ok(html.includes('id="username"'));
    assert.ok(html.includes('autocomplete="username"'));
    assert.ok(html.includes('name="password"'));
    assert.ok(html.includes('id="password"'));
    assert.ok(html.includes('autocomplete="current-password"'));
    assert.ok(html.includes('type="password"'));
    assert.ok(html.includes("登录"));
    assert.ok(html.includes("追觅客户监控"));
    assert.ok(!html.includes("WWW-Authenticate"));
    assert.ok(html.includes('preventDefault'));
    assert.ok(html.includes('fetch("/api/login"'));
    assert.ok(html.includes('credentials:"same-origin"') || html.includes('credentials: "same-origin"'));
    assert.ok(html.includes("application/json"));
    assert.ok(html.includes("location.replace(\"/app.html\")"));
    assert.ok(html.includes("账号或密码不对"));
    assert.ok(!html.includes('action="/login"'));
    assert.ok(!html.includes('method="post" action="/login"'));
  });

  test("dashboard has a quiet logout link and keeps latest-log / balance cards", () => {
    const html = readFileSync(join(root, "static", "index.html"), "utf8");
    assert.ok(html.includes('href="/api/logout"'));
    assert.ok(html.includes('fetch("/api/logout"'));
    assert.ok(!html.includes('href="/logout"'));
    assert.ok(html.includes("退出"));
    assert.ok(html.includes("revealLatestLog"));
    assert.ok(html.includes("AIPDD剩余金额"));
    assert.ok(html.includes("火山引擎剩余金额"));
  });

  test("session token HMAC verifies and expires", async () => {
    const now = Date.parse("2026-08-17T06:00:00Z");
    const token = await makeSessionToken("zhuimi", "secret-pw", now);
    assert.equal(await verifySessionToken(token, "zhuimi", "secret-pw", now + 1000), true);
    assert.equal(await verifySessionToken(token, "zhuimi", "wrong-pw", now + 1000), false);
    assert.equal(await verifySessionToken(token, "other", "secret-pw", now + 1000), false);
    assert.equal(await verifySessionToken("tampered." + token.split(".")[1], "zhuimi", "secret-pw", now + 1000), false);
    const week = 7 * 86400 * 1000;
    assert.equal(await verifySessionToken(token, "zhuimi", "secret-pw", now + week + 2000), false);
  });

  test("GET / without cookie returns login HTML 200, not Basic 401", async () => {
    globalThis.BAKED_ENV = { DASHBOARD_PASSWORD: "pw", DASHBOARD_USER: "zhuimi" };
    const res = await worker.fetch(new Request("https://monitor.test/"), {});
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("WWW-Authenticate"), null);
    const body = await res.text();
    assert.ok(body.includes("追觅客户监控"));
    assert.ok(body.includes('action="/api/login"') || body.includes('fetch("/api/login"'));
    assert.ok(!body.includes('action="/login"'));
    assert.ok(body.includes('autocomplete="username"'));
    assert.ok(body.includes('autocomplete="current-password"'));
    assert.ok(!body.includes("pw"));
    assert.ok(!body.includes("<Error>"));
    assert.ok(!body.includes("MethodNotAllowed"));
  });

  test("POST /api/login sets HttpOnly Secure SameSite cookie and returns JSON", async () => {
    globalThis.BAKED_ENV = { DASHBOARD_PASSWORD: "s3cret", DASHBOARD_USER: "zhuimi" };
    const res = await worker.fetch(
      new Request("https://monitor.test/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "zhuimi", password: "s3cret" }),
        redirect: "manual",
      }),
      {}
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("WWW-Authenticate"), null);
    assert.equal((res.headers.get("Content-Type") || "").includes("application/json"), true);
    const cookie = res.headers.get("Set-Cookie") || "";
    assert.ok(cookie.startsWith(SESSION_COOKIE + "="));
    assert.ok(cookie.includes("HttpOnly"));
    assert.ok(cookie.includes("Secure"));
    assert.ok(cookie.includes("SameSite=Lax"));
    assert.ok(cookie.includes("Max-Age=604800"));
    assert.ok(!cookie.includes("s3cret"));
    const body = await res.json();
    assert.equal(body.ok, true);
    const text = JSON.stringify(body);
    assert.ok(!text.includes("<Error>"));
    assert.ok(!text.includes("MethodNotAllowed"));
  });

  test("POST /api/login with wrong password returns JSON error, not Basic or OSS XML", async () => {
    globalThis.BAKED_ENV = { DASHBOARD_PASSWORD: "s3cret", DASHBOARD_USER: "zhuimi" };
    const res = await worker.fetch(
      new Request("https://monitor.test/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "zhuimi", password: "wrong" }),
        redirect: "manual",
      }),
      {}
    );
    assert.equal(res.status, 401);
    assert.equal(res.headers.get("WWW-Authenticate"), null);
    assert.equal(res.headers.get("Set-Cookie"), null);
    const raw = await res.text();
    assert.ok(!raw.includes("<Error>"));
    assert.ok(!raw.includes("MethodNotAllowed"));
    const body = JSON.parse(raw);
    assert.equal(body.ok, false);
    assert.equal(body.error, "账号或密码不对");
    assert.ok(!raw.includes("wrong"));
    assert.ok(!raw.includes("s3cret"));
  });

  test("POST /login sets HttpOnly Secure SameSite cookie and 302s to /", async () => {
    globalThis.BAKED_ENV = { DASHBOARD_PASSWORD: "s3cret", DASHBOARD_USER: "zhuimi" };
    const res = await worker.fetch(
      new Request("https://monitor.test/login", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "username=zhuimi&password=s3cret",
        redirect: "manual",
      }),
      {}
    );
    assert.equal(res.status, 302);
    assert.equal(res.headers.get("Location"), "/");
    const cookie = res.headers.get("Set-Cookie") || "";
    assert.ok(cookie.startsWith(SESSION_COOKIE + "="));
    assert.ok(cookie.includes("HttpOnly"));
    assert.ok(cookie.includes("Secure"));
    assert.ok(cookie.includes("SameSite=Lax"));
    assert.ok(cookie.includes("Max-Age=604800"));
    assert.ok(!cookie.includes("s3cret"));
  });

  test("POST /login with wrong password returns login page, not 401 popup", async () => {
    globalThis.BAKED_ENV = { DASHBOARD_PASSWORD: "s3cret", DASHBOARD_USER: "zhuimi" };
    const res = await worker.fetch(
      new Request("https://monitor.test/login", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "username=zhuimi&password=wrong",
        redirect: "manual",
      }),
      {}
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("WWW-Authenticate"), null);
    assert.equal(res.headers.get("Set-Cookie"), null);
    const body = await res.text();
    assert.ok(body.includes("账号或密码不对"));
    assert.ok(!body.includes("wrong"));
    assert.ok(!body.includes("s3cret"));
  });

  test("cookie from POST /api/login can open /api/session", async () => {
    globalThis.BAKED_ENV = { DASHBOARD_PASSWORD: "s3cret", DASHBOARD_USER: "zhuimi" };
    const login = await worker.fetch(
      new Request("https://monitor.test/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "zhuimi", password: "s3cret" }),
      }),
      {}
    );
    const setCookie = login.headers.get("Set-Cookie") || "";
    const token = setCookie.split(";")[0];
    const session = await worker.fetch(
      new Request("https://monitor.test/api/session", { headers: { Cookie: token } }),
      {}
    );
    assert.equal(session.status, 200);
    assert.equal(session.headers.get("WWW-Authenticate"), null);
    const body = await session.json();
    assert.equal(body.ok, true);
  });

  test("valid cookie can open dashboard and APIs", async () => {
    globalThis.BAKED_ENV = {
      DASHBOARD_PASSWORD: "s3cret",
      DASHBOARD_USER: "zhuimi",
      SUSCIYUAN_ACCESS_TOKEN: "sus-token",
    };
    globalThis.fetch = async (url) => {
      if (String(url).includes("/api/status")) {
        return new Response(JSON.stringify({ success: true, data: { quota_per_unit: 500000, usd_exchange_rate: 7.3 } }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (String(url).includes("/api/log/")) {
        return new Response(JSON.stringify({ success: true, data: { total: 0, items: [] } }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      throw new Error("unexpected " + url);
    };
    const token = await makeSessionToken("zhuimi", "s3cret", Date.now());
    const headers = { Cookie: SESSION_COOKIE + "=" + token };
    const page = await worker.fetch(new Request("https://monitor.test/", { headers }), {});
    assert.equal(page.status, 200);
    const html = await page.text();
    assert.ok(html.includes("追觅客户监控"));
    assert.ok(!html.includes('action="/login"') || html.includes("立即刷新") || html.includes("追觅客户监控"));

    const api = await worker.fetch(new Request("https://monitor.test/api/overview?refresh=1", { headers }), {});
    assert.equal(api.status, 200);
    const body = await api.json();
    assert.equal(body.ok, true);
  });

  test("GET /logout clears cookie and does not use Basic", async () => {
    globalThis.BAKED_ENV = { DASHBOARD_PASSWORD: "s3cret", DASHBOARD_USER: "zhuimi" };
    const res = await worker.fetch(new Request("https://monitor.test/logout", { redirect: "manual" }), {});
    assert.equal(res.status, 302);
    assert.equal(res.headers.get("Location"), "/");
    const cookie = res.headers.get("Set-Cookie") || "";
    assert.ok(cookie.includes("Max-Age=0"));
    assert.equal(res.headers.get("WWW-Authenticate"), null);
  });

  test("GET /api/logout clears cookie and 302s without Basic", async () => {
    globalThis.BAKED_ENV = { DASHBOARD_PASSWORD: "s3cret", DASHBOARD_USER: "zhuimi" };
    const res = await worker.fetch(new Request("https://monitor.test/api/logout", { redirect: "manual" }), {});
    assert.equal(res.status, 302);
    assert.equal(res.headers.get("Location"), "/");
    const cookie = res.headers.get("Set-Cookie") || "";
    assert.ok(cookie.includes("Max-Age=0"));
    assert.equal(res.headers.get("WWW-Authenticate"), null);
  });

  test("POST /api/logout clears cookie and returns JSON", async () => {
    globalThis.BAKED_ENV = { DASHBOARD_PASSWORD: "s3cret", DASHBOARD_USER: "zhuimi" };
    const res = await worker.fetch(
      new Request("https://monitor.test/api/logout", { method: "POST", redirect: "manual" }),
      {}
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("WWW-Authenticate"), null);
    const cookie = res.headers.get("Set-Cookie") || "";
    assert.ok(cookie.includes("Max-Age=0"));
    const body = await res.json();
    assert.equal(body.ok, true);
  });

  test("no DASHBOARD_PASSWORD keeps the page open without login", async () => {
    globalThis.BAKED_ENV = { DASHBOARD_PASSWORD: "" };
    const res = await worker.fetch(new Request("https://monitor.test/api/session"), {});
    assert.equal(res.status, 200);
    const page = await worker.fetch(new Request("https://monitor.test/"), {});
    assert.equal(page.status, 200);
  });

  test("renderLoginPage fallback still has password-manager fields", () => {
    const html = renderLoginPage(false);
    assert.ok(html.includes('name="username"'));
    assert.ok(html.includes('autocomplete="current-password"'));
    assert.ok(html.includes("登录"));
    assert.ok(html.includes("/api/login"));
    assert.ok(!html.includes('action="/login"'));
  });
});
