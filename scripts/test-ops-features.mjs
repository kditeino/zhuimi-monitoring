import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { afterEach, describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import worker, {
  CREATE_CREDIT_CNY,
  SESSION_COOKIE,
  TAG_ASSET,
  TAG_FACE,
  extraTagsForLog,
  generatePassword,
  isDuplicateUsernameError,
  makeSessionToken,
  nextDailyUsername,
  quotaUnitsForCny,
  resetOverviewCache,
  shanghaiMMDD,
} from "../src/index.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const html = readFileSync(join(root, "static", "index.html"), "utf8");
const workerSrc = readFileSync(join(root, "src", "index.js"), "utf8");

describe("log extra tags and clickable chips", { concurrency: 1 }, () => {
  afterEach(() => {
    globalThis.BAKED_ENV = undefined;
    delete globalThis.fetch;
    resetOverviewCache();
  });

  test("真人脸 matches Volcengine real-person intercept text", () => {
    assert.deepEqual(
      extraTagsForLog({ content: "The input image may contain real person, rejected" }),
      [TAG_FACE]
    );
    assert.deepEqual(extraTagsForLog({ content: "内容审核：疑似真人" }), [TAG_FACE]);
    assert.ok(!extraTagsForLog({ content: "ordinary consume log" }).includes(TAG_FACE));
  });

  test("素材库 matches reference / image_url / resource-download fields, not a new type", () => {
    assert.ok(extraTagsForLog({ content: "uploaded 参考图" }).includes(TAG_ASSET));
    assert.ok(extraTagsForLog({ content: "参考视频 ready" }).includes(TAG_ASSET));
    assert.ok(extraTagsForLog({ content: "resource-download ok" }).includes(TAG_ASSET));
    assert.ok(extraTagsForLog({ other: { image_url: "https://x/a.png" } }).includes(TAG_ASSET));
    assert.ok(extraTagsForLog({ other: { video_url: "https://x/a.mp4" } }).includes(TAG_ASSET));
    assert.ok(extraTagsForLog({ other: { has_reference_video: true } }).includes(TAG_ASSET));
    assert.ok(extraTagsForLog({ other: { pricing_variant: "reference_video" } }).includes(TAG_ASSET));
    assert.ok(extraTagsForLog({ content: "reference-image attached" }).includes(TAG_ASSET));
    assert.ok(!extraTagsForLog({ content: "plain text only", type: 2 }).includes(TAG_ASSET));
    assert.ok(!workerSrc.includes("/api/asset"));
    assert.ok(!html.includes("/api/asset"));
  });

  test("overview attaches tags and always reports 真人脸 / 素材库 counts", async () => {
    globalThis.BAKED_ENV = {
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
            data: {
              total: 3,
              items: [
                { id: 1, type: 5, content: "may contain real person", model_name: "seedance", created_at: 1700000001 },
                { id: 2, type: 2, content: "ok", other: { has_reference_video: true }, model_name: "seedance", created_at: 1700000002 },
                { id: 3, type: 2, content: "hello", model_name: "gpt", created_at: 1700000003 },
              ],
            },
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
    assert.equal(body.tag_counts[TAG_FACE], 1);
    assert.equal(body.tag_counts[TAG_ASSET], 1);
    const face = body.logs.find((l) => l.id === 1);
    const asset = body.logs.find((l) => l.id === 2);
    const plain = body.logs.find((l) => l.id === 3);
    assert.deepEqual(face.tags, [TAG_FACE]);
    assert.deepEqual(asset.tags, [TAG_ASSET]);
    assert.deepEqual(plain.tags, []);
    assert.equal(body.type_counts["错误"], 1);
    assert.equal(body.type_counts["消费"], 2);
    assert.ok(!Object.keys(body.type_counts).includes(TAG_FACE));
    assert.ok(!Object.keys(body.type_counts).includes(TAG_ASSET));
  });

  test("dashboard chips are clickable and keep existing type names", () => {
    assert.ok(html.includes('id="createUserBtn"'));
    assert.ok(html.includes("新增用户"));
    assert.ok(html.includes('id="refreshBtn"'));
    assert.ok(html.indexOf('id="refreshBtn"') < html.indexOf('id="createUserBtn"'));
    assert.ok(html.includes("全部"));
    assert.ok(html.includes(TAG_FACE));
    assert.ok(html.includes(TAG_ASSET));
    assert.ok(html.includes("setFilter"));
    assert.ok(html.includes("chip.selected"));
    assert.ok(html.includes("cursor: pointer"));
    assert.ok(html.includes('data-kind="type"'));
    assert.ok(html.includes("模型平台地址：https://susciyuan.com"));
    assert.ok(html.includes("登录地址后可以自行创建多个KEY（API秘钥)"));
    assert.ok(html.includes("Seedance接口使用方法参见：https://aiworkin.feishu.cn/wiki/RZXkwDbzqi2auAkuF3EcJGWknVh"));
    assert.ok(html.includes("navigator.clipboard"));
    assert.ok(!html.includes("SUSCIYUAN_ACCESS_TOKEN"));
    assert.ok(!html.includes("quota:100"));
    assert.ok(!html.includes("quota: 100"));
    for (const name of ["充值", "消费", "管理", "系统", "错误", "退款"]) {
      assert.ok(html.includes('"' + name + '"') || html.includes("t-" + name));
    }
  });
});

describe("create user", { concurrency: 1 }, () => {
  afterEach(() => {
    globalThis.BAKED_ENV = undefined;
    delete globalThis.fetch;
    resetOverviewCache();
  });

  test("¥100 uses site conversion, not quota:100", () => {
    assert.equal(CREATE_CREDIT_CNY, 100);
    assert.equal(quotaUnitsForCny(100, 500000, 7.3), 6849315);
    assert.ok(!workerSrc.includes("quota: 100"));
    assert.ok(!workerSrc.includes("quota:100"));
  });

  test("User_MMDDnn takes max suffix and pads to 2 digits", () => {
    assert.equal(nextDailyUsername([], "0831"), "User_083101");
    assert.equal(nextDailyUsername(["User_083101", "user_083102"], "0831"), "User_083103");
    assert.equal(nextDailyUsername(["User_090101"], "0831"), "User_083101");
    assert.equal(nextDailyUsername(["User_083199"], "0831"), "User_0831100");
    assert.match("User_083101", /^User_0831(\d+)$/i);
    assert.match("user_083102", /^User_0831(\d+)$/i);
  });

  test("password is 10 chars with upper lower digit symbol and no quotes", () => {
    for (let i = 0; i < 40; i++) {
      const pw = generatePassword();
      assert.equal(pw.length, 10);
      assert.match(pw, /[A-Z]/);
      assert.match(pw, /[a-z]/);
      assert.match(pw, /\d/);
      assert.match(pw, /[!@#$%^&*()\-_=+[\]{};:,.<>/?~]/);
      assert.ok(!/[\s'"`]/.test(pw));
    }
  });

  test("POST /api/create-user requires session and sits before the GET-only guard", async () => {
    globalThis.BAKED_ENV = { DASHBOARD_PASSWORD: "pw", DASHBOARD_USER: "zhuimi" };
    const denied = await worker.fetch(new Request("https://monitor.test/api/create-user", { method: "POST" }), {});
    assert.equal(denied.status, 401);
    const body = await denied.json();
    assert.equal(body.error, "unauthorized");

    const other = await worker.fetch(
      new Request("https://monitor.test/api/overview", { method: "POST" }),
      {}
    );
    assert.equal(other.status, 401);
  });

  test("POST /api/create-user creates User_MMDDnn, adds ¥100 quota, never exposes token", async () => {
    const mmdd = shanghaiMMDD(new Date());
    const expectedName = "User_" + mmdd + "02";
    const seen = [];
    globalThis.BAKED_ENV = {
      DASHBOARD_PASSWORD: "pw",
      DASHBOARD_USER: "zhuimi",
      SUSCIYUAN_ACCESS_TOKEN: "sus-token-secret",
      SUSCIYUAN_USER_ID: "1",
      SUSCIYUAN_BASE: "https://susciyuan.com",
    };
    globalThis.fetch = async (url, init) => {
      const href = String(url);
      const method = (init && init.method) || "GET";
      seen.push(method + " " + href);
      const headers = (init && init.headers) || {};
      assert.equal(headers.Authorization, "Bearer sus-token-secret");
      assert.equal(headers["New-Api-User"], "1");
      if (href.includes("/api/status")) {
        return jsonRes({ success: true, data: { quota_per_unit: 500000, usd_exchange_rate: 7.3, quota_display_type: "CNY" } });
      }
      if (href.includes("/api/user/search")) {
        return jsonRes({
          success: true,
          data: { items: [{ id: 9, username: "User_" + mmdd + "01" }], total: 1 },
        });
      }
      if (method === "POST" && /\/api\/user\/$/.test(href)) {
        const body = JSON.parse(init.body);
        assert.equal(body.username, expectedName);
        assert.equal(body.group, "default");
        assert.equal(body.role, 1);
        assert.ok(!Object.prototype.hasOwnProperty.call(body, "quota") || body.quota == null);
        assert.equal(body.password.length, 10);
        return jsonRes({ success: true, message: "", data: { id: 44, username: expectedName, password: "" } });
      }
      if (method === "POST" && href.includes("/api/user/manage")) {
        const body = JSON.parse(init.body);
        assert.equal(body.id, 44);
        assert.equal(body.action, "add_quota");
        assert.equal(body.mode, "add");
        assert.equal(body.value, 6849315);
        assert.notEqual(body.value, 100);
        return jsonRes({ success: true, message: "" });
      }
      throw new Error("unexpected " + method + " " + href);
    };

    const token = await makeSessionToken("zhuimi", "pw", Date.now());
    const res = await worker.fetch(
      new Request("https://monitor.test/api/create-user", {
        method: "POST",
        headers: { Cookie: SESSION_COOKIE + "=" + token, "Content-Type": "application/json" },
        body: "{}",
      }),
      {}
    );
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.equal(body.username, expectedName);
    assert.equal(body.credit_cny, 100);
    assert.equal(body.quota, 6849315);
    assert.equal(body.password.length, 10);
    const dumped = JSON.stringify(body);
    assert.ok(!dumped.includes("sus-token-secret"));
    assert.ok(seen.some((s) => s.startsWith("POST ") && s.includes("/api/user/")));
    assert.ok(seen.some((s) => s.includes("/api/user/manage")));
  });

  test("duplicate username bumps nn; quota-add failure keeps username", async () => {
    const mmdd = shanghaiMMDD(new Date());
    let creates = 0;
    globalThis.BAKED_ENV = {
      DASHBOARD_PASSWORD: "",
      SUSCIYUAN_ACCESS_TOKEN: "sus-token",
    };
    globalThis.fetch = async (url, init) => {
      const href = String(url);
      const method = (init && init.method) || "GET";
      if (href.includes("/api/status")) {
        return jsonRes({ success: true, data: { quota_per_unit: 500000, usd_exchange_rate: 7.3 } });
      }
      if (href.includes("/api/user/search")) {
        return jsonRes({ success: true, data: { items: [], total: 0 } });
      }
      if (method === "POST" && /\/api\/user\/$/.test(href)) {
        creates += 1;
        const body = JSON.parse(init.body);
        if (creates === 1) {
          assert.equal(body.username, "User_" + mmdd + "01");
          return jsonRes({ success: false, message: "username already exists" });
        }
        assert.equal(body.username, "User_" + mmdd + "02");
        return jsonRes({ success: true, data: { id: 77, username: body.username } });
      }
      if (method === "POST" && href.includes("/api/user/manage")) {
        return jsonRes({ success: false, message: "quota engine down" });
      }
      throw new Error("unexpected " + href);
    };
    const res = await worker.fetch(new Request("https://monitor.test/api/create-user", { method: "POST" }), {});
    assert.equal(res.status, 502);
    const body = await res.json();
    assert.equal(body.ok, false);
    assert.equal(body.created, true);
    assert.equal(body.username, "User_" + mmdd + "02");
    assert.match(body.error, /User_/);
    assert.match(body.error, /额度/);
    assert.ok(body.password);
    assert.equal(isDuplicateUsernameError("username already exists"), true);
  });
});

function jsonRes(obj) {
  return new Response(JSON.stringify(obj), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}
