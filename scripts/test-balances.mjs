import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { afterEach, describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import worker, {
  channelMoney,
  conversionFromStatus,
  parseChannelBalance,
  remainQuotaFromUser,
} from "../src/index.js";

describe("balances and latest-log UI", { concurrency: 1 }, () => {

afterEach(() => {
  globalThis.BAKED_ENV = undefined;
  delete globalThis.fetch;
});

test("remainQuotaFromUser uses New API remaining quota, not quota - used", () => {
  assert.equal(remainQuotaFromUser({ quota: 800000, used_quota: 200000 }), 800000);
  assert.equal(remainQuotaFromUser({ quota: 0, used_quota: 10 }), 0);
  assert.equal(remainQuotaFromUser(null), 0);
});

test("conversionFromStatus falls back to 500000 and 7.3", () => {
  assert.deepEqual(conversionFromStatus(null), {
    quota_per_unit: 500000,
    usd_exchange_rate: 7.3,
  });
  assert.deepEqual(conversionFromStatus({ quota_per_unit: 250000, usd_exchange_rate: 7.1 }), {
    quota_per_unit: 250000,
    usd_exchange_rate: 7.1,
  });
});

test("parseChannelBalance reads New API balance field as USD by default", () => {
  assert.deepEqual(parseChannelBalance({ success: true, message: "", balance: 25.5 }), {
    value: 25.5,
    currency: null,
  });
  assert.deepEqual(parseChannelBalance({ success: true, data: 12 }), {
    value: 12,
    currency: null,
  });
  assert.deepEqual(parseChannelBalance({ data: { balance_cny: 88.2 } }), {
    value: 88.2,
    currency: "CNY",
  });
  assert.deepEqual(parseChannelBalance({ balance: 3, currency: "CNY" }), {
    value: 3,
    currency: "CNY",
  });
});

test("channelMoney converts USD to CNY and keeps explicit CNY", () => {
  assert.deepEqual(channelMoney(10, null, 7.3), { cny: 73, usd: 10, currency: "USD" });
  assert.deepEqual(channelMoney(73, "CNY", 7.3), { cny: 73, usd: 10, currency: "CNY" });
});

test("GET /api/balances is unconfigured without token and does not call upstream", async () => {
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
  assert.equal(body.aipdd.error, "未配置 AIPDD_ACCESS_TOKEN");
  assert.equal(body.volces.configured, false);
  assert.equal(body.volces.error, "未配置 VOLCES_CHANNEL_ID");
  assert.equal(calls, 0);
});

test("GET /api/balances uses AIPDD user/self and optional update_balance", async () => {
  const seen = [];
  globalThis.BAKED_ENV = {
    AIPDD_BASE: "https://api.aipdd.work",
    AIPDD_ACCESS_TOKEN: "test-token",
    AIPDD_USER_ID: "1",
    VOLCES_CHANNEL_ID: "9",
    DASHBOARD_PASSWORD: "",
  };
  globalThis.fetch = async (url, init) => {
    seen.push(String(url));
    const auth = init && init.headers && init.headers.Authorization;
    assert.equal(auth, "Bearer test-token");
    if (String(url).includes("/api/status")) {
      return new Response(JSON.stringify({ success: true, data: { quota_per_unit: 500000, usd_exchange_rate: 7.3 } }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (String(url).includes("/api/user/self")) {
      return new Response(JSON.stringify({ success: true, data: { quota: 1000000, used_quota: 200000 } }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (String(url).includes("/api/channel/update_balance/9")) {
      return new Response(JSON.stringify({ success: true, message: "", balance: 10 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response("no", { status: 404 });
  };

  const res = await worker.fetch(new Request("https://monitor.test/api/balances?refresh=1"), {});
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.ok, true);
  assert.equal(body.aipdd.configured, true);
  assert.equal(body.aipdd.quota_remain, 1000000);
  assert.equal(body.aipdd.cny, 14.6);
  assert.equal(body.volces.configured, true);
  assert.equal(body.volces.usd, 10);
  assert.equal(body.volces.cny, 73);
  assert.equal(body.volces.currency, "USD");
  assert.equal(seen.length, 3);
  assert.ok(seen.some((u) => u.includes("/api/status")));
  assert.ok(seen.some((u) => u.includes("/api/user/self")));
  assert.ok(seen.some((u) => u.includes("/api/channel/update_balance/9")));
  assert.ok(!seen.some((u) => u.includes("susciyuan")));
});

test("GET /api/balances does not leak upstream text on failure", async () => {
  globalThis.BAKED_ENV = {
    AIPDD_ACCESS_TOKEN: "secret-token-value",
    VOLCES_CHANNEL_ID: "9",
  };
  globalThis.fetch = async () => {
    return new Response(JSON.stringify({ success: false, message: "Bearer secret-token-value 尚未实现 raw dump" }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };
  const res = await worker.fetch(new Request("https://monitor.test/api/balances?refresh=1"), {});
  const body = await res.json();
  const dumped = JSON.stringify(body);
  assert.equal(body.ok, true);
  assert.equal(body.aipdd.configured, true);
  assert.equal(body.aipdd.error, "AIPDD 余额查询失败");
  assert.equal(body.volces.error, "火山引擎余额查询失败");
  assert.ok(!dumped.includes("secret-token-value"));
  assert.ok(!dumped.includes("尚未实现"));
});

test("GET /api/overview is unchanged when AIPDD keys are missing", async () => {
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
      return new Response(
        JSON.stringify({
          success: true,
          data: { total: 0, items: [] },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }
    throw new Error("unexpected " + url);
  };
  const res = await worker.fetch(new Request("https://monitor.test/api/overview?refresh=1"), {});
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.ok, true);
  assert.equal(body.metrics.total_requests, 0);
});

test("page highlights latest log and does not auto-open an error detail", () => {
  const html = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "static", "index.html"), "utf8");
  assert.ok(html.includes("revealLatestLog"));
  assert.ok(html.includes("scrollDetail"));
  assert.ok(html.includes("AIPDD剩余金额"));
  assert.ok(html.includes("火山引擎剩余金额"));
  assert.ok(html.includes("/api/balances"));
  assert.ok(!html.includes("findIndex(l => l.type === 5)"));
});

test("Basic Auth still wraps /api/balances", async () => {
  globalThis.BAKED_ENV = { DASHBOARD_PASSWORD: "pw", DASHBOARD_USER: "zhuimi" };
  const res = await worker.fetch(new Request("https://monitor.test/api/balances"), {});
  assert.equal(res.status, 401);
});
});
