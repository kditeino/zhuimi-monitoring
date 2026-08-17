import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { afterEach, describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import worker, {
  extractAwcoin,
  extractAwcoinRate,
  normQuery,
  parseVolcBalance,
  resetBalancesState,
  signVolcengineV4,
} from "../src/index.js";

describe("balances and latest-log UI", { concurrency: 1 }, () => {
  afterEach(() => {
    globalThis.BAKED_ENV = undefined;
    delete globalThis.fetch;
    resetBalancesState();
  });

  test("extractAwcoin reads AWCoin and ignores New API quota", () => {
    assert.equal(
      extractAwcoin({
        code: 0,
        data: { id: "u1", username: "demo", availableBalance: 123456, frozenBalance: 0 },
      }),
      123456
    );
    assert.equal(extractAwcoin({ code: 0, data: { awcoin: 123456 } }), 123456);
    assert.equal(extractAwcoin({ code: 0, data: { balance: "88.5" } }), 88.5);
    assert.equal(extractAwcoin({ code: 0, data: { wallet: { aw_coin: 10 } } }), 10);
    assert.equal(extractAwcoin({ success: true, data: { quota: 800000, used_quota: 200000 } }), null);
    assert.equal(extractAwcoin({ code: 401, message: "No valid access token or API Key was provided", data: null }), null);
    assert.equal(extractAwcoin({ code: 0, data: { rmb: 0.0001, usd: 0.00001484, updatedAt: "x" } }), null);
  });

  test("extractAwcoinRate uses public rmb default 0.0001", () => {
    assert.deepEqual(extractAwcoinRate({ code: 0, data: { rmb: 0.0001, usd: 0.00001484 } }), {
      rmb: 0.0001,
      usd: 0.00001484,
    });
    assert.equal(extractAwcoinRate(null).rmb, 0.0001);
  });

  test("parseVolcBalance prefers AvailableBalance then CashBalance", () => {
    assert.equal(
      parseVolcBalance({
        ResponseMetadata: { Action: "QueryBalanceAcct", Service: "billing" },
        Result: { AvailableBalance: "77.01", CashBalance: "83.01" },
      }),
      77.01
    );
    assert.equal(parseVolcBalance({ Result: { CashBalance: "12.3" } }), 12.3);
    assert.equal(parseVolcBalance({ ResponseMetadata: { Error: { Code: "X" } }, Result: { AvailableBalance: "1" } }), null);
  });

  test("signVolcengineV4 matches official HMAC-SHA256 vector", async () => {
    const signed = await signVolcengineV4({
      method: "GET",
      path: "/",
      host: "billing.volcengineapi.com",
      service: "billing",
      region: "cn-north-1",
      query: { Action: "QueryBalanceAcct", Version: "2022-01-01" },
      body: "",
      contentType: "application/x-www-form-urlencoded",
      ak: "AKTESTEXAMPLE",
      sk: "SKTESTEXAMPLESECRET",
      xDate: "20260817T034800Z",
    });
    assert.equal(signed.signature, "bc97a7b7d372b91d84087b659cdd94ae4a6100f9ccb81c203079c2e54bedbf1e");
    assert.equal(
      signed.authorization,
      "HMAC-SHA256 Credential=AKTESTEXAMPLE/20260817/cn-north-1/billing/request, SignedHeaders=content-type;host;x-content-sha256;x-date, Signature=bc97a7b7d372b91d84087b659cdd94ae4a6100f9ccb81c203079c2e54bedbf1e"
    );
    assert.equal(normQuery({ Action: "QueryBalanceAcct", Version: "2022-01-01" }), "Action=QueryBalanceAcct&Version=2022-01-01");
  });

  test("GET /api/balances is unconfigured without keys and does not call upstream", async () => {
    let calls = 0;
    globalThis.fetch = async () => {
      calls += 1;
      throw new Error("should not fetch");
    };
    const res = await worker.fetch(new Request("https://monitor.test/api/balances"), {});
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.equal(body.aipdd.configured, false);
    assert.equal(body.aipdd.error, "未配置 AIPDD_API_KEY");
    assert.equal(body.volces.configured, false);
    assert.match(body.volces.error, /VOLC_ACCESS_KEY_ID/);
    assert.equal(calls, 0);
  });

  test("GET /api/balances uses official AIPDD /user/info + Volc billing, not New API quota", async () => {
    const seen = [];
    globalThis.BAKED_ENV = {
      AIPDD_BASE_URL: "https://api.aipdd.work",
      AIPDD_API_KEY: "official-key",
      VOLC_ACCESS_KEY_ID: "AKTEST",
      VOLC_SECRET_ACCESS_KEY: "SKTEST",
      DASHBOARD_PASSWORD: "",
    };
    globalThis.fetch = async (url, init) => {
      const href = String(url);
      seen.push(href);
      const headers = (init && init.headers) || {};
      if (href.includes("api.aipdd.work") && href.includes("/user/info")) {
        assert.equal(headers["X-API-Key"], "official-key");
        assert.equal(headers.Authorization, "Bearer official-key");
        return new Response(
          JSON.stringify({
            code: 0,
            data: { id: "u1", username: "demo", availableBalance: 123456, frozenBalance: 10 },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      if (href.includes("billing.volcengineapi.com")) {
        assert.match(href, /Action=QueryBalanceAcct/);
        assert.match(href, /Version=2022-01-01/);
        assert.match(String(headers.Authorization || ""), /^HMAC-SHA256 /);
        return new Response(
          JSON.stringify({
            ResponseMetadata: { Action: "QueryBalanceAcct", Service: "billing" },
            Result: { AvailableBalance: "77.01", CashBalance: "83.01" },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      return new Response("no", { status: 404 });
    };

    const res = await worker.fetch(new Request("https://monitor.test/api/balances?refresh=1"), {});
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.equal(body.aipdd.configured, true);
    assert.equal(body.aipdd.awcoin, 123456);
    assert.equal(body.aipdd.cny, 12.3456);
    assert.equal(body.aipdd.frozenBalance, 10);
    assert.equal(body.aipdd.error, null);
    assert.equal(body.volces.configured, true);
    assert.equal(body.volces.cny, 77.01);
    assert.equal(body.volces.currency, "CNY");
    assert.ok(seen.length <= 4);
    assert.equal(seen.filter((u) => u.includes("api.aipdd.work")).length, 1);
    assert.ok(seen.some((u) => u.includes("/user/info")));
    assert.ok(seen.some((u) => u.includes("billing.volcengineapi.com")));
    assert.ok(!seen.some((u) => u.includes("/system/awcoin-rate")));
    assert.ok(!seen.some((u) => u.includes("/v1/")));
    assert.ok(!seen.some((u) => u.includes("/api/user/self")));
    assert.ok(!seen.some((u) => u.includes("susciyuan")));
    assert.ok(!seen.some((u) => u.includes("newapi.aipdd.work")));
    assert.ok(!seen.some((u) => u.includes("update_balance")));
    assert.ok(!seen.some((u) => u.includes("ark.cn-beijing")));
  });

  test("GET /api/balances does not treat New API quota as AIPDD remaining", async () => {
    globalThis.BAKED_ENV = { AIPDD_API_KEY: "official-key" };
    globalThis.fetch = async () => {
      return new Response(JSON.stringify({ success: true, data: { quota: 1000000, used_quota: 200000 } }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };
    const res = await worker.fetch(new Request("https://monitor.test/api/balances?refresh=1"), {});
    const body = await res.json();
    assert.equal(body.aipdd.configured, true);
    assert.equal(body.aipdd.cny, null);
    assert.equal(body.aipdd.error, "AIPDD 余额解析失败");
  });

  test("GET /api/balances reports invalid key on HTTP 401/403", async () => {
    globalThis.BAKED_ENV = { AIPDD_API_KEY: "official-key" };
    globalThis.fetch = async () => new Response(JSON.stringify({ code: 401, data: null }), { status: 401 });
    let res = await worker.fetch(new Request("https://monitor.test/api/balances?refresh=1"), {});
    let body = await res.json();
    assert.equal(body.aipdd.error, "AIPDD 钥匙无效");
    resetBalancesState();
    globalThis.fetch = async () => new Response(JSON.stringify({ code: 403, data: null }), { status: 403 });
    res = await worker.fetch(new Request("https://monitor.test/api/balances?refresh=1"), {});
    body = await res.json();
    assert.equal(body.aipdd.error, "AIPDD 钥匙无效");
  });

  test("GET /api/balances does not leak upstream text on failure", async () => {
    globalThis.BAKED_ENV = {
      AIPDD_API_KEY: "secret-key-value",
      VOLC_ACCESS_KEY_ID: "AKSECRET",
      VOLC_SECRET_ACCESS_KEY: "SKSECRET",
    };
    globalThis.fetch = async () => {
      return new Response(JSON.stringify({ message: "Bearer secret-key-value 尚未实现 raw dump" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    };
    const res = await worker.fetch(new Request("https://monitor.test/api/balances?refresh=1"), {});
    const body = await res.json();
    const dumped = JSON.stringify(body);
    assert.equal(body.ok, true);
    assert.equal(body.aipdd.error, "AIPDD 余额查询失败");
    assert.equal(body.volces.error, "火山引擎余额查询失败");
    assert.ok(!dumped.includes("secret-key-value"));
    assert.ok(!dumped.includes("尚未实现"));
    assert.ok(!dumped.includes("SKSECRET"));
  });

  test("GET /api/overview is unchanged when balance keys are missing", async () => {
    globalThis.BAKED_ENV = {
      SUSCIYUAN_BASE: "https://susciyuan.com",
      SUSCIYUAN_ACCESS_TOKEN: "sus-token",
      DASHBOARD_PASSWORD: "",
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
    const res = await worker.fetch(new Request("https://monitor.test/api/overview?refresh=1"), {});
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.equal(body.metrics.total_requests, 0);
  });

  test("page highlights latest log and shows new balance copy", () => {
    const html = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "static", "index.html"), "utf8");
    assert.ok(html.includes("revealLatestLog"));
    assert.ok(html.includes("scrollDetail"));
    assert.ok(html.includes("AIPDD剩余金额"));
    assert.ok(html.includes("火山引擎剩余金额"));
    assert.ok(html.includes("AIPDD_API_KEY"));
    assert.ok(html.includes("VOLC_ACCESS_KEY_ID"));
    assert.ok(html.includes("AWCoin"));
    assert.ok(!html.includes("AIPDD_ACCESS_TOKEN"));
    assert.ok(!html.includes("VOLCES_CHANNEL_ID"));
    assert.ok(!html.includes("findIndex(l => l.type === 5)"));
  });

  test("cookie auth wraps /api/balances without Basic popup", async () => {
    globalThis.BAKED_ENV = { DASHBOARD_PASSWORD: "pw", DASHBOARD_USER: "zhuimi" };
    const res = await worker.fetch(new Request("https://monitor.test/api/balances"), {});
    assert.equal(res.status, 401);
    assert.equal(res.headers.get("WWW-Authenticate"), null);
    const body = await res.json();
    assert.equal(body.error, "unauthorized");
  });

  test("build bake keys no longer include the old New API balance names", () => {
    const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "build.mjs"), "utf8");
    assert.ok(src.includes("AIPDD_API_KEY"));
    assert.ok(src.includes("AIPDD_BASE_URL"));
    assert.ok(src.includes("VOLC_ACCESS_KEY_ID"));
    assert.ok(src.includes("VOLC_SECRET_ACCESS_KEY"));
    assert.ok(!src.includes("AIPDD_ACCESS_TOKEN"));
    assert.ok(!src.includes("AIPDD_USER_ID"));
    assert.ok(!src.includes("VOLCES_CHANNEL_ID"));
  });

  test("worker uses only GET /user/info for AIPDD remaining", () => {
    const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "src", "index.js"), "utf8");
    assert.ok(src.includes("/user/info"));
    assert.ok(src.includes("availableBalance"));
    assert.ok(!src.includes("probeAipddWallet"));
    assert.ok(!src.includes("/v1/user"));
    assert.ok(!src.includes("/v1/wallet"));
    assert.ok(!src.includes("/v1/account"));
    assert.ok(!src.includes("/v1/balance"));
    assert.ok(!src.includes("/api/user/self"));
  });
});
