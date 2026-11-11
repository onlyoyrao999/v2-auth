// End-to-end test for v2-auth (assumes `wrangler pages dev` on :8788
// with .dev.vars ADMIN_PASSWORD=liantong-test-pw).
import { parseKeyDescription, readTlv } from "../functions/lib/attest.js";
import { expiredSubscription, expiredFallbackSubscription } from "../functions/lib/poison.js";
import { filterBlockedKeywords } from "../functions/lib/filter.js";
import vm from "node:vm";

const BASE = "http://127.0.0.1:8788";
let pass = 0, fail = 0;
const check = (name, cond, extra = "") => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${extra ? "  (" + extra + ")" : ""}`);
  cond ? pass++ : fail++;
};

// ---------- 1. attestation DER parser unit test ----------
function derLen(n) {
  if (n < 128) return [n];
  const b = [];
  while (n > 0) { b.unshift(n & 0xff); n >>= 8; }
  return [0x80 | b.length, ...b];
}
const T = (tagBytes, content) => new Uint8Array([...tagBytes, ...derLen(content.length), ...content]);
const SEQ = (...kids) => T([0x30], kids.flatMap((k) => [...k]));
const INT = (v) => T([0x02], [v]);
const ENUM = (v) => T([0x0a], [v]);
const OCT = (bytes) => T([0x04], [...bytes]);
const BOOL = (v) => T([0x01], [v ? 0xff : 0x00]);
const CTX709 = (content) => T([0xbf, 0x85, 0x45], content);
const CTX704 = (content) => T([0xbf, 0x85, 0x40], content);

{
  const challenge = new Uint8Array(32).fill(0xab);
  const digest = new Uint8Array(32).fill(0x22);
  const pkgInfo = SEQ(OCT(new TextEncoder().encode("com.v2ray.ang.fdroid")), INT(107));
  const appId = SEQ(T([0x31], [...pkgInfo]), T([0x31], [...OCT(digest)]));
  const root = SEQ(OCT(new Uint8Array(32).fill(7)), BOOL(true), ENUM(0), OCT(new Uint8Array(32).fill(9)));
  const kd = SEQ(
    INT(3), ENUM(1), INT(3), ENUM(1), OCT(challenge), OCT(new Uint8Array(0)),
    SEQ(CTX709([...appId])), SEQ(CTX704([...root]))
  );
  const parsed = parseKeyDescription(kd, readTlv(kd, 0));
  check("attest: challenge", Buffer.from(parsed.challenge).equals(Buffer.from(challenge)));
  check("attest: level TEE", parsed.securityLevel === 1);
  check("attest: package", parsed.software.appId.packages[0] === "com.v2ray.ang.fdroid");
  check("attest: digest", parsed.software.appId.digests[0] === "22".repeat(32));
  check("attest: boot locked+verified", parsed.tee.rootOfTrust.deviceLocked === true && parsed.tee.rootOfTrust.verifiedBootState === 0);
}

// ---------- 2. HTTP flow ----------
const j = async (path, body, headers = {}) => {
  const r = await fetch(BASE + path, {
    method: "POST", headers: { "content-type": "application/json", ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, data: await r.json().catch(() => null), headers: r.headers };
};
const b64u = (bytes) => Buffer.from(bytes).toString("base64url");
async function newDeviceKey() {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const spki = await crypto.subtle.exportKey("spki", kp.publicKey);
  return { kp, pubkey: Buffer.from(spki).toString("base64") };
}
async function signedCall(path, machine, kp) {
  const ts = Math.floor(Date.now() / 1000);
  const nonce = b64u(crypto.getRandomValues(new Uint8Array(12)));
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, kp.privateKey,
    new TextEncoder().encode(`${machine}|${ts}|${nonce}|${path}`)
  );
  const r = await fetch(BASE + path, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ machineCode: machine, ts, nonce, sig: b64u(new Uint8Array(sig)) }),
  });
  return { status: r.status, text: await r.text() };
}

const login = await fetch(BASE + "/api/admin/login", {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ password: "liantong-test-pw" }),
});
const cookie = (login.headers.get("set-cookie") || "").split(";")[0];
check("admin login", login.status === 200 && cookie.startsWith("sess="));
const badLogin = await j("/api/admin/login", { password: "wrong" });
check("admin bad password rejected", badLogin.status === 401);

const M1 = "TEST-MACH-0000-0001", M2 = "TEST-MACH-0000-0002", M3 = "TEST-MACH-0000-0003";
const issue1 = await j("/api/admin/issue", { machineCode: M1, days: 30, note: "测试客户甲", mode: "code" }, { cookie });
check("issue code", issue1.status === 200 && /^V2O-/.test(issue1.data.code || ""), issue1.data.code);
const issue2 = await j("/api/admin/issue", { machineCode: M2, days: 365, note: "", mode: "code" }, { cookie });

// The production mix-up: an activation code pasted into the machine
// field must be refused in both modes — never parked as a fake
// machine that no device can claim.
const codeAsMachine1 = await j("/api/admin/issue", { machineCode: issue1.data.code, days: 30, mode: "code" }, { cookie });
check("activation code as machine rejected (code mode)", codeAsMachine1.status === 400 && codeAsMachine1.data.reason === "bad_machine");
const codeAsMachine2 = await j("/api/admin/issue", { machineCode: issue1.data.code, days: 30, mode: "open" }, { cookie });
check("activation code as machine rejected (open mode)", codeAsMachine2.status === 400 && codeAsMachine2.data.reason === "bad_machine");
const garbageMachine = await j("/api/admin/issue", { machineCode: "HELLO-WORLD", days: 30, mode: "open" }, { cookie });
check("garbage machine rejected", garbageMachine.status === 400 && garbageMachine.data.reason === "bad_machine");
// lowercase / ungrouped input is normalized to the canonical code,
// and the direct-open -> claim chain still works end to end.
const lowerOpen = await j("/api/admin/issue", { machineCode: "testmach00000009", days: 30, mode: "open" }, { cookie });
const devLow = await newDeviceKey();
const claimLow = await j("/api/claim", { machineCode: "TEST-MACH-0000-0009", pubkey: devLow.pubkey });
check("normalized machine open + claim works", lowerOpen.status === 200 && claimLow.status === 200 && !!claimLow.data.token);

const dev1 = await newDeviceKey();
const badActivate = await j("/api/activate", { machineCode: M1, code: "V2O-XXXXX-XXXXX-XXXXX-XXXXX", pubkey: dev1.pubkey });
check("activate wrong code rejected", badActivate.status === 403 && badActivate.data.reason === "not_found");
const crossActivate = await j("/api/activate", { machineCode: M1, code: issue2.data.code, pubkey: dev1.pubkey });
check("code bound to other machine rejected", crossActivate.status === 403 && crossActivate.data.reason === "bound_other");

// issued-but-unused codes are listed for the seller, and can be killed
const listWithIssued = await (await fetch(BASE + "/api/admin/devices", { headers: { cookie } })).json();
const issuedM2 = (listWithIssued.issued || []).find((i) => i.machine === M2);
check("issued code listed before activation", !!issuedM2 && issuedM2.status === "issued");
check("issued code re-copyable via vault", issuedM2.code === issue2.data.code, issuedM2.code);
const killCode = await j("/api/admin/action", { licKey: issuedM2.licKey, action: "revoke" }, { cookie });
const dev2x = await newDeviceKey();
const deadActivate = await j("/api/activate", { machineCode: M2, code: issue2.data.code, pubkey: dev2x.pubkey });
check("killed unused code is hard-deleted and cannot activate", killCode.status === 200 && deadActivate.status === 403 && deadActivate.data.reason === "not_found");
const act1 = await j("/api/activate", { machineCode: M1, code: issue1.data.code, pubkey: dev1.pubkey, platform: "android-test" });
check("activate ok + token", act1.status === 200 && !!act1.data.token && !!act1.data.expires_at);

const val1 = await signedCall("/api/validate", M1, dev1.kp);
check("signed validate ok", val1.status === 200 && JSON.parse(val1.text).ok === true, val1.text.slice(0, 80));
const valTok = await j("/api/validate", { machineCode: M1, token: act1.data.token });
check("token validate ok", valTok.status === 200 && valTok.data.ok === true);
const valBadTok = await j("/api/validate", { machineCode: M1, token: "bogus" });
check("bad token rejected", valBadTok.status === 403);

const ts = Math.floor(Date.now() / 1000);
const wrongSig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, dev1.kp.privateKey,
  new TextEncoder().encode("something else"));
const valBadSig = await j("/api/validate", { machineCode: M1, ts, nonce: "n1", sig: b64u(new Uint8Array(wrongSig)) });
check("bad signature rejected", valBadSig.status === 403 && valBadSig.data.reason === "bad_sig");

const sub1 = await signedCall("/api/subscription", M1, dev1.kp);
const subHash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(sub1.text));
check("subscription delivered", sub1.status === 200 && sub1.text.length > 500,
  `len=${sub1.text.length} sha256=${Buffer.from(subHash).toString("hex").slice(0, 16)}…`);
const subDeny = await j("/api/subscription", { machineCode: M1, token: "bogus" });
check("subscription denied without auth", subDeny.status === 403);

// distributor channel: separate subscription URL (SUB_URL_DIST)
const M4 = "TEST-MACH-0000-0004";
const issueD = await j("/api/admin/issue", { machineCode: M4, days: 30, note: "分销客户", mode: "code", channel: "dist" }, { cookie });
const dev4 = await newDeviceKey();
const act4 = await j("/api/activate", { machineCode: M4, code: issueD.data.code, pubkey: dev4.pubkey });
const subDist = await signedCall("/api/subscription", M4, dev4.kp);
const expectedDist = await (await fetch("http://127.0.0.1:8899/sub_dist.txt")).text();
check("dist channel gets dist subscription",
  act4.status === 200 && subDist.status === 200 && subDist.text === expectedDist,
  `len=${subDist.text.length}`);

// claim flow (direct-open)
const open3 = await j("/api/admin/issue", { machineCode: M3, days: 90, note: "直开户", mode: "open" }, { cookie });
const dev3 = await newDeviceKey();
const claim3 = await j("/api/claim", { machineCode: M3, pubkey: dev3.pubkey, platform: "android-test" });
check("claim direct-open ok", open3.status === 200 && claim3.status === 200 && !!claim3.data.token);
const claimAgain = await j("/api/claim", { machineCode: M3, pubkey: dev3.pubkey });
check("second claim is a reinstall re-claim (new contract)", claimAgain.status === 200 && !!claimAgain.data.token && claimAgain.data.token !== claim3.data.token);

// revoke / restore / expire
const revoke = await j("/api/admin/action", { machineCode: M1, action: "revoke" }, { cookie });
const valRevoked = await signedCall("/api/validate", M1, dev1.kp);
check("revoked device locked out", revoke.status === 200 && valRevoked.status === 403 && JSON.parse(valRevoked.text).reason === "revoked");
const restore = await j("/api/admin/action", { machineCode: M1, action: "restore" }, { cookie });
const valRestored = await signedCall("/api/validate", M1, dev1.kp);
check("restore works", restore.status === 200 && valRestored.status === 200);
const ext = await j("/api/admin/action", { machineCode: M1, action: "extend", days: -10000 }, { cookie });
const valExpired = await signedCall("/api/validate", M1, dev1.kp);
check("expired license locked out", ext.status === 200 && valExpired.status === 403 && JSON.parse(valExpired.text).reason === "expired");

// manual expiry edit （修改时间）: absolute moment, past moment, permanent
const nowS = Math.floor(Date.now() / 1000);
const setFuture = await j("/api/admin/action", { machineCode: M1, action: "set_expiry", expires_at: nowS + 3600 }, { cookie });
const valEdited = await signedCall("/api/validate", M1, dev1.kp);
check("set_expiry to future revives device", setFuture.status === 200 && setFuture.data.expires_at === nowS + 3600 && valEdited.status === 200);
const setPast = await j("/api/admin/action", { machineCode: M1, action: "set_expiry", expires_at: nowS - 10 }, { cookie });
const valPast = await signedCall("/api/validate", M1, dev1.kp);
check("set_expiry to past expires device", setPast.status === 200 && valPast.status === 403 && JSON.parse(valPast.text).reason === "expired");
const setBad = await j("/api/admin/action", { machineCode: M1, action: "set_expiry", expires_at: "abc" }, { cookie });
check("set_expiry rejects garbage", setBad.status === 400);
const setPerm = await j("/api/admin/action", { machineCode: M1, action: "set_expiry", expires_at: null }, { cookie });
const valPerm = await signedCall("/api/validate", M1, dev1.kp);
check("set_expiry null makes permanent", setPerm.status === 200 && setPerm.data.expires_at === null && valPerm.status === 200);

// device subscription expiry notice (owner, 2026-11-06): an expired
// device pulling its subscription gets NO subscription content at
// all — a plain-text notice instead, on any day, no window. Nothing
// fabricated is ever served as subscription content.
await j("/api/admin/action", { machineCode: M1, action: "set_expiry", expires_at: nowS - 120 }, { cookie });
const subExp1 = await signedCall("/api/subscription", M1, dev1.kp);
check("device expired: pull returns plain-text expiry notice (403)",
  subExp1.status === 403 && subExp1.text.includes("已到期，请联系卖家"));
await j("/api/admin/action", { machineCode: M1, action: "set_expiry", expires_at: nowS - 90000 }, { cookie });
const subExp2 = await signedCall("/api/subscription", M1, dev1.kp);
check("device expired long ago: same plain-text notice (no window)",
  subExp2.status === 403 && subExp2.text.includes("已到期，请联系卖家"));
await j("/api/admin/action", { machineCode: M1, action: "set_expiry", expires_at: null }, { cookie });
const subAlive = await signedCall("/api/subscription", M1, dev1.kp);
check("device permanent again: real subscription served", subAlive.status === 200 && subAlive.text.length > 500);

const devList = await fetch(BASE + "/api/admin/devices", { headers: { cookie } }).then((r) => r.json());
check("device table lists devices", devList.ok && devList.devices.length >= 2, `${devList.devices?.length} devices`);
const noAuthList = await fetch(BASE + "/api/admin/devices").then((r) => r.status);
check("device table requires login", noAuthList === 401);

// session token via header (localStorage path): refresh must not
// demand the password again while the token is valid.
const login2 = await j("/api/admin/login", { password: "liantong-test-pw" });
const sessToken = login2.data.session;
check("login returns session token", login2.status === 200 && typeof sessToken === "string" && sessToken.includes("."));
const headerAuth = await fetch(BASE + "/api/admin/devices", { headers: { "x-session": sessToken } });
check("x-session header authenticates", headerAuth.status === 200);
const badHeaderAuth = await fetch(BASE + "/api/admin/devices", { headers: { "x-session": "bogus.token" } });
check("bogus x-session rejected", badHeaderAuth.status === 401);

// ---------- 3. distributor portal (/mmm) ----------
const createDist = await j("/api/admin/dist", { action: "create", slug: "mmm", name: "分销老王", password: "dist-pw-1", quota: 2 }, { cookie });
check("admin creates distributor", createDist.status === 200 && createDist.data.ok === true);
const portal = await fetch(BASE + "/mmm");
const portalHtml = await portal.text();
check("portal /mmm serves distributor console", portal.status === 200 && portalHtml.includes("分销商后台"));
check("unknown slug 404s", (await fetch(BASE + "/nosuchslug")).status === 404);
const distBadLogin = await j("/api/dist/login", { slug: "mmm", password: "nope" });
check("dist bad password rejected", distBadLogin.status === 401);
const renameDist = await j("/api/admin/dist", { slug: "mmm", action: "rename", name: "老王本王" }, { cookie });
const distList2 = await (await fetch(BASE + "/api/admin/dist", { headers: { cookie } })).json();
check("distributor renamed", renameDist.status === 200 && (distList2.distributors || []).some((d) => d.slug === "mmm" && d.name === "老王本王"));
const distLoginRes = await fetch(BASE + "/api/dist/login", {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ slug: "mmm", password: "dist-pw-1" }),
});
const dcookie = (distLoginRes.headers.get("set-cookie") || "").split(";")[0];
check("dist login ok", distLoginRes.status === 200 && dcookie.startsWith("dsess="));
const dme = await fetch(BASE + "/api/dist/me", { headers: { cookie: dcookie } }).then((r) => r.json());
check("dist me + quota", dme.ok === true && dme.remaining === 2);
const M5 = "TEST-MACH-0000-0005", M6 = "TEST-MACH-0000-0006", M7 = "TEST-MACH-0000-0007";
const dIssue1 = await j("/api/dist/issue", { machineCode: M5, days: 30, note: "王客户", mode: "code" }, { cookie: dcookie });
check("dist issues code", dIssue1.status === 200 && /^V2O-/.test(dIssue1.data.code || ""));
const dBadMachine = await j("/api/dist/issue", { machineCode: dIssue1.data.code, days: 30, mode: "code" }, { cookie: dcookie });
check("dist: activation code as machine rejected", dBadMachine.status === 400 && dBadMachine.data.reason === "bad_machine");
const dPerm = await j("/api/dist/issue", { machineCode: M6, days: 0, note: "" }, { cookie: dcookie });
check("dist permanent rejected (max 1y rule)", dPerm.status === 400);
const dev5 = await newDeviceKey();
const act5 = await j("/api/activate", { machineCode: M5, code: dIssue1.data.code, pubkey: dev5.pubkey });
const sub5 = await signedCall("/api/subscription", M5, dev5.kp);
check("dist customer pulls DIST subscription", act5.status === 200 && sub5.status === 200 && sub5.text === expectedDist);
const dIssue2 = await j("/api/dist/issue", { machineCode: M6, days: 30, note: "", mode: "code" }, { cookie: dcookie });
const dIssue3 = await j("/api/dist/issue", { machineCode: M7, days: 30, note: "", mode: "code" }, { cookie: dcookie });
check("quota exhausted at limit", dIssue2.status === 200 && dIssue3.status === 403 && dIssue3.data.reason === "quota_exhausted");
// Duration-weighted quota (owner, 2026-11-04): a 90-day card costs
// 3 units — a quota-2 distributor cannot afford one at all.
await j("/api/admin/dist", { action: "create", slug: "qq2", name: "权重测试", password: "dist-pw-1", quota: 2 }, { cookie });
const qq2LoginRes = await fetch(BASE + "/api/dist/login", {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ slug: "qq2", password: "dist-pw-1" }),
});
const qq2Cookie = (qq2LoginRes.headers.get("set-cookie") || "").split(";")[0];
const dWeighted = await j("/api/dist/issue", { machineCode: "QQ22-MACH-0000-0001", days: 90, mode: "code" }, { cookie: qq2Cookie });
check("90-day card costs 3 quota units", dWeighted.status === 403 && dWeighted.data.cost === 3 && dWeighted.data.remaining === 2);
const dDevices = await fetch(BASE + "/api/dist/devices", { headers: { cookie: dcookie } }).then((r) => r.json());
check("dist sees only own customers (incl. sold-unactivated)", dDevices.ok === true
  && JSON.stringify(dDevices.devices.map((d) => d.machine).sort()) === JSON.stringify([M5, M6].sort())
  && dDevices.devices.find((d) => d.machine === M5 && !d.pending)
  && dDevices.devices.find((d) => d.machine === M6 && d.pending === true));
const disableDist = await j("/api/admin/dist", { slug: "mmm", action: "disable" }, { cookie });
const distLoginDisabled = await j("/api/dist/login", { slug: "mmm", password: "dist-pw-1" });
check("disabled distributor cannot log in", disableDist.status === 200 && distLoginDisabled.status === 401);

// distributor self-setup: admin creates WITHOUT a password; the
// distributor sets his own on first visit (saved hashed in KV).
const createDist2 = await j("/api/admin/dist", { action: "create", slug: "abc", name: "自设密码分销", quota: 5 }, { cookie });
const state1 = await (await fetch(BASE + "/api/dist/state?slug=abc")).json();
check("create without password -> needs_setup", createDist2.status === 200 && state1.ok === true && state1.needs_setup === true);
const loginBeforeSetup = await j("/api/dist/login", { slug: "abc", password: "whatever1" });
check("login blocked before setup", loginBeforeSetup.status === 401 && loginBeforeSetup.data.reason === "needs_setup");
const setupRes = await fetch(BASE + "/api/dist/setup", {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ slug: "abc", password: "self-set-1" }),
});
const sCookie = (setupRes.headers.get("set-cookie") || "").split(";")[0];
check("distributor sets own password + auto-login", setupRes.status === 200 && sCookie.startsWith("dsess="));
const setupAgain = await j("/api/dist/setup", { slug: "abc", password: "another-1" });
check("second setup rejected", setupAgain.status === 409);
const resetPw = await j("/api/admin/dist", { slug: "abc", action: "resetpw" }, { cookie });
const state2 = await (await fetch(BASE + "/api/dist/state?slug=abc")).json();
check("admin reset -> needs_setup again", resetPw.status === 200 && state2.needs_setup === true);

// delete: only a disabled account can be removed, then the slug is gone
const delActive = await j("/api/admin/dist", { slug: "abc", action: "delete" }, { cookie });
check("delete of active account refused", delActive.status === 400);
await j("/api/admin/dist", { slug: "abc", action: "disable" }, { cookie });
const delOk = await j("/api/admin/dist", { slug: "abc", action: "delete" }, { cookie });
const state3 = await fetch(BASE + "/api/dist/state?slug=abc");
check("disabled account deleted, slug gone", delOk.status === 200 && state3.status === 404);

// device hard delete: row + license gone, token useless afterwards
const delDev = await j("/api/admin/action", { machineCode: M1, action: "delete" }, { cookie });
const afterDel = await (await fetch(BASE + "/api/admin/devices", { headers: { cookie } })).json();
check("device deleted from table", delDev.status === 200 && !(afterDel.devices || []).some((d) => d.machine === M1));
const valAfterDel = await j("/api/validate", { machineCode: M1, token: act1.data.token });
check("validate denied after device delete", valAfterDel.status === 403);

// ---- console page scripts must parse (a broken inline script
// kills every button on the page, login included) ----
{
  const consoleHtml = await (await fetch(BASE + "/")).text();
  const blocks = [...consoleHtml.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
  let parseOk = blocks.length > 0;
  for (const b of blocks) { try { new vm.Script(b); } catch { parseOk = false; } }
  check("console page inline scripts parse", parseOk && !consoleHtml.includes("<redacted>"));
}

// ---- guest customers (admin-managed; /g/<id> page + sealed link) ----
const expectedSub = readFileSync(new URL("./fixtures/sub_main.txt", import.meta.url), "utf8");
const gNoAuth = await j("/api/admin/guest", { action: "create", username: "x", password: "guest-pw-1", days: 30 });
check("guest admin api requires login", gNoAuth.status === 401);
const gCreate = await j("/api/admin/guest", { action: "create", username: "小火箭阿强", password: "guest-pw-1", days: 30, note: "游客甲" }, { cookie });
check("admin creates guest", gCreate.status === 200 && !!gCreate.data.id && gCreate.data.path === "/g/" + gCreate.data.id, JSON.stringify(gCreate.data).slice(0, 90));
const GID = gCreate.data.id;
const gDup = await j("/api/admin/guest", { action: "create", username: "小火箭阿强", password: "guest-pw-2", days: 30 }, { cookie });
check("duplicate guest username rejected", gDup.status === 409);
const gWeak = await j("/api/admin/guest", { action: "create", username: "弱口令游客", password: "123", days: 30 }, { cookie });
check("weak guest password rejected", gWeak.status === 400);
const gList = await (await fetch(BASE + "/api/admin/guest", { headers: { cookie } })).json();
check("guest listed for admin", gList.ok === true && (gList.guests || []).some((g) => g.id === GID && g.username === "小火箭阿强" && !("pw_hash" in g)));
const gPage = await fetch(BASE + "/g/" + GID);
const gPageHtml = await gPage.text();
check("guest page pre-login shows password box only", gPage.status === 200 && gPageHtml.includes('id="pw"') && !gPageHtml.includes("/s/"));
check("unknown guest page 404s", (await fetch(BASE + "/g/zzzzzzzzzzzz")).status === 404);
const gOldEndpoint = await j("/api/guest/link", { code: "whatever" });
check("old code-exchange endpoint gone", gOldEndpoint.status === 404 || gOldEndpoint.status === 405);
const gMeAnon = await fetch(BASE + "/api/guest/me");
check("guest me requires login", gMeAnon.status === 401);
const gBadPw = await j("/api/guest/login", { id: GID, password: "nope-nope" });
check("guest bad password rejected", gBadPw.status === 401 && gBadPw.data.reason === "bad_password");
const gLoginRes = await fetch(BASE + "/api/guest/login", {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ id: GID, password: "guest-pw-1" }),
});
const gcookie = (gLoginRes.headers.get("set-cookie") || "").split(";")[0];
check("guest login ok", gLoginRes.status === 200 && gcookie.startsWith("gsess="));
const gMe = await (await fetch(BASE + "/api/guest/me", { headers: { cookie: gcookie } })).json();
check("guest me: remaining time + sealed link only, no real address",
  gMe.ok === true && gMe.username === "小火箭阿强" && gMe.days_left >= 29 && gMe.days_left <= 30 &&
  typeof gMe.link === "string" && gMe.link.includes("/s/") && !JSON.stringify(gMe).includes("8899"),
  JSON.stringify(gMe).slice(0, 110));
const gFetch = await fetch(gMe.link);
check("guest link serves subscription content", gFetch.status === 200 && (await gFetch.text()) === expectedSub);
check("guest page has logout button", gPageHtml.includes('id="logoutBtn"'));
const gOut = await fetch(BASE + "/api/guest/logout", { method: "POST" });
const gOutCookie = gOut.headers.get("set-cookie") || "";
check("guest logout expires session cookie", gOut.status === 200 && gOutCookie.startsWith("gsess=;") && gOutCookie.includes("Max-Age=0"));
check("tampered guest link rejected", (await fetch(BASE + "/s/AAAAbbbbCCCCdddd")).status === 404);
await j("/api/admin/guest", { id: GID, action: "disable" }, { cookie });
check("guest link dead after disable", (await fetch(gMe.link)).status === 403);
const gLoginOff = await j("/api/guest/login", { id: GID, password: "guest-pw-1" });
check("disabled guest cannot log in", gLoginOff.status === 403 && gLoginOff.data.reason === "disabled");
const gMeOff = await fetch(BASE + "/api/guest/me", { headers: { cookie: gcookie } });
check("disabled guest session rejected", gMeOff.status === 401);
await j("/api/admin/guest", { id: GID, action: "enable" }, { cookie });
check("guest link back after enable", (await fetch(gMe.link)).status === 200);
await j("/api/admin/guest", { id: GID, action: "extend", days: -10000 }, { cookie });
// Long expired: no hard cut any more — the link stays open and only
// ever serves the fully obfuscated subscription, same as a member.
const gLongFetch = await fetch(gMe.link);
const gLongBody = await gLongFetch.text();
let gLongText = "";
try {
  gLongText = Buffer.from(gLongBody.replace(/\s+/g, ""), "base64").toString("utf8");
} catch { /* not base64: stays empty and the checks below fail loudly */ }
const gLongStray = (gLongText.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).filter((x) => x !== "114.115.116.117");
check("long-expired guest link still serves only obfuscated (200, no hard cut)",
  gLongFetch.status === 200 && gLongText.includes("114.115.116.117") && gLongStray.length === 0 &&
  gLongText.includes("xxx") && !gLongText.includes("example.com") && !gLongText.includes("trojanpass123"),
  `stray=${gLongStray.length}`);
// Expired TODAY (moments ago): the same obfuscated subscription.
await j("/api/admin/guest", { id: GID, action: "set_expiry", expires_at: Math.floor(Date.now() / 1000) - 120 }, { cookie });
const gExpiredFetch = await fetch(gMe.link);
const gExpiredBody = await gExpiredFetch.text();
let gPoisonText = "";
try {
  gPoisonText = Buffer.from(gExpiredBody.replace(/\s+/g, ""), "base64").toString("utf8");
} catch { /* not base64: stays empty and the checks below fail loudly */ }
const gStrayIps = (gPoisonText.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).filter((x) => x !== "114.115.116.117");
check("guest expired today gets obfuscated subscription (200, names 已到期请联系卖家, UUIDs xxx, addresses dead IP)",
  gExpiredFetch.status === 200 && gPoisonText.includes("114.115.116.117") && gStrayIps.length === 0 &&
  gPoisonText.includes("xxx") && gPoisonText.includes(encodeURIComponent("已到期请联系卖家")) &&
  !gPoisonText.includes("example.com") && !gPoisonText.includes("trojanpass123"),
  `stray=${gStrayIps.length}`);
// Expired since a previous day: still only the obfuscated version.
await j("/api/admin/guest", { id: GID, action: "set_expiry", expires_at: Math.floor(Date.now() / 1000) - 90000 }, { cookie });
const gOldFetch = await fetch(gMe.link);
check("guest expired before today: link still serves only obfuscated (200, no hard cut)", gOldFetch.status === 200);
await j("/api/admin/guest", { id: GID, action: "extend", days: 10001 }, { cookie });
const gRevived = await fetch(gMe.link);
check("extended guest link alive again with real content",
  gRevived.status === 200 && (await gRevived.text()) === expectedSub);
await j("/api/admin/guest", { id: GID, action: "password", password: "guest-pw-9" }, { cookie });
check("old guest password dead after change", (await j("/api/guest/login", { id: GID, password: "guest-pw-1" })).status === 401);
check("new guest password works", (await j("/api/guest/login", { id: GID, password: "guest-pw-9" })).status === 200);
const gDelActive = await j("/api/admin/guest", { id: GID, action: "delete" }, { cookie });
check("delete of active guest refused", gDelActive.status === 400);
await j("/api/admin/guest", { id: GID, action: "disable" }, { cookie });
const gDel = await j("/api/admin/guest", { id: GID, action: "delete" }, { cookie });
check("guest deleted, link + page gone", gDel.status === 200 && (await fetch(gMe.link)).status === 404 && (await fetch(BASE + "/g/" + GID)).status === 404);

// ---- formal members （小火箭正式会员： /m/<id> page + main-channel link) ----
const mbCreate = await j("/api/admin/member", { action: "create", username: "苹果正式会员", password: "member-pw-1", days: 30, note: "会员甲" }, { cookie });
check("admin creates member", mbCreate.status === 200 && !!mbCreate.data.id && mbCreate.data.path === "/m/" + mbCreate.data.id, JSON.stringify(mbCreate.data).slice(0, 90));
const MID = mbCreate.data.id;
const mbDup = await j("/api/admin/member", { action: "create", username: "苹果正式会员", password: "member-pw-2", days: 30 }, { cookie });
check("duplicate member username rejected", mbDup.status === 409);
const mbList = await (await fetch(BASE + "/api/admin/member", { headers: { cookie } })).json();
check("member listed for admin", mbList.ok === true && (mbList.members || []).some((m) => m.id === MID && m.username === "苹果正式会员" && !("pw_hash" in m)));
const mbPage = await fetch(BASE + "/m/" + MID);
const mbPageHtml = await mbPage.text();
check("member page pre-login shows password box + logout button", mbPage.status === 200 && mbPageHtml.includes('id="pw"') && mbPageHtml.includes('id="logoutBtn"') && !mbPageHtml.includes("/s/"));
check("unknown member page 404s", (await fetch(BASE + "/m/zzzzzzzzzzzz")).status === 404);
check("member me requires login", (await fetch(BASE + "/api/member/me")).status === 401);
const mbLoginRes = await fetch(BASE + "/api/member/login", {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ id: MID, password: "member-pw-1" }),
});
const mbcookie = (mbLoginRes.headers.get("set-cookie") || "").split(";")[0];
check("member login ok", mbLoginRes.status === 200 && mbcookie.startsWith("msess="));
const mbMe = await (await fetch(BASE + "/api/member/me", { headers: { cookie: mbcookie } })).json();
check("member me: remaining time + sealed link only, no real address",
  mbMe.ok === true && mbMe.username === "苹果正式会员" && mbMe.days_left >= 29 && mbMe.days_left <= 30 &&
  typeof mbMe.link === "string" && mbMe.link.includes("/s/") && !JSON.stringify(mbMe).includes("8899"),
  JSON.stringify(mbMe).slice(0, 110));
const mbFetch = await fetch(mbMe.link);
check("member link serves the main subscription", mbFetch.status === 200 && (await mbFetch.text()) === expectedSub);
const mbOut = await fetch(BASE + "/api/member/logout", { method: "POST" });
const mbOutCookie = mbOut.headers.get("set-cookie") || "";
check("member logout expires session cookie", mbOut.status === 200 && mbOutCookie.startsWith("msess=;") && mbOutCookie.includes("Max-Age=0"));
await j("/api/admin/member", { id: MID, action: "disable" }, { cookie });
check("member link dead after disable", (await fetch(mbMe.link)).status === 403);
await j("/api/admin/member", { id: MID, action: "enable" }, { cookie });
check("member link back after enable", (await fetch(mbMe.link)).status === 200);
await j("/api/admin/member", { id: MID, action: "set_expiry", expires_at: Math.floor(Date.now() / 1000) - 90000 }, { cookie });
const mbExpFetch = await fetch(mbMe.link);
const mbExpBody = await mbExpFetch.text();
let mbExpText = mbExpBody;
try { const d = Buffer.from(mbExpBody.replace(/\s+/g, ""), "base64").toString("utf8"); if (d.includes("://")) mbExpText = d; } catch {}
let mbOrigText = expectedSub;
try { const d = Buffer.from(expectedSub.replace(/\s+/g, ""), "base64").toString("utf8"); if (d.includes("://")) mbOrigText = d; } catch {}
const mbExpLines = mbExpText.split(/\r?\n/).filter(Boolean);
const mbOrigLines = mbOrigText.split(/\r?\n/).filter(Boolean);
const mbNodeName = (line) => {
  const vm = line.match(/^vmess:\/\/(.+)$/);
  if (vm) { try { return JSON.parse(Buffer.from(vm[1], "base64").toString("utf8")).ps; } catch { return null; } }
  const h = line.indexOf("#");
  return h === -1 ? null : decodeURIComponent(line.slice(h + 1));
};
const mbOrigUuids = mbOrigText.match(/\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g) || [];
check("expired member link serves obfuscated subscription (200, all names 已到期请联系卖家, all UUIDs xxx, all addresses dead IP)",
  mbExpFetch.status === 200 && mbExpLines.length === mbOrigLines.length &&
  mbExpLines.every((l) => mbNodeName(l) === "已到期请联系卖家") &&
  mbExpText.includes("xxx") && mbExpText.includes("114.115.116.117") &&
  !/\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/.test(mbExpText) &&
  mbOrigUuids.every((u) => !mbExpText.includes(u)),
  `lines=${mbExpLines.length}`);
const mbFbText = Buffer.from(expiredFallbackSubscription().replace(/\s+/g, ""), "base64").toString("utf8");
check("expired fallback is one dead node, always open (name 已到期请联系卖家, xxx, dead IP)",
  mbFbText === "vless://xxx@114.115.116.117:443#%E5%B7%B2%E5%88%B0%E6%9C%9F%E8%AF%B7%E8%81%94%E7%B3%BB%E5%8D%96%E5%AE%B6",
  mbFbText);
const sniSample = Buffer.from([
  "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@real.example.com:443?security=tls&sni=sni.real.example.com&host=host.real.example.com&path=%2F%3Fed%3D2048&type=ws#TestNode",
  "vmess://" + Buffer.from(JSON.stringify({ v: "2", ps: "TestVmess", add: "1.2.3.4", port: "443", id: "11111111-2222-3333-4444-555555555555", host: "host.real.example.com", sni: "sni.real.example.com", path: "/?ed=2048" })).toString("base64"),
].join("\n")).toString("base64");
const sniOut = Buffer.from(expiredSubscription(sniSample).replace(/\s+/g, ""), "base64").toString("utf8");
check("expired obfuscation blanks SNI/host/path too (sni=xxx, host=xxx, path=xxx, no real domain)",
  sniOut.includes("sni=xxx") && sniOut.includes("host=xxx") && sniOut.includes("path=xxx") &&
  !sniOut.includes("real.example.com") && !sniOut.includes("sni.real.example.com") && !sniOut.includes("ed=2048") &&
  JSON.parse(Buffer.from(sniOut.split("\n")[1].slice(8), "base64").toString("utf8")).host === "xxx" &&
  JSON.parse(Buffer.from(sniOut.split("\n")[1].slice(8), "base64").toString("utf8")).path === "xxx",
  sniOut);
// Keyword filter: info nodes and blocked labels are dropped on serve.
const kwLines = [
  `vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@1.2.3.4:443?encryption=none#${encodeURIComponent("剩余流量：805.55 GB")}`,
  `vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@1.2.3.4:443?encryption=none#${encodeURIComponent("距离下次重置剩余：8 天")}`,
  `vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@1.2.3.4:443?encryption=none#${encodeURIComponent("套餐到期：2029-07-18")}`,
  `vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@try.cloudflare.182682.example.com:443?encryption=none&security=tls&type=ws#${encodeURIComponent("–若无法使用请更新节点–")}`,
  `hysteria2://pass@216.227.169.1:50075?insecure=1#${encodeURIComponent("白嫖节点")}`,
  `trojan://trojanpass123@5.6.7.8:443#${encodeURIComponent("客户端专用")}`,
  `vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@1.2.3.4:443?encryption=none#${encodeURIComponent("官方入口")}`,
  `vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@1.2.3.4:443?encryption=none#${encodeURIComponent("EDT导航优选域名")}`,
  `vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@1.2.3.4:443?encryption=none#${encodeURIComponent("分享免费")}`,
  `vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@1.2.3.4:443?encryption=none#${encodeURIComponent("BestCF优选")}`,
  `vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@1.2.3.4:443?encryption=none#${encodeURIComponent("bestcf节点")}`,
  `vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@1.2.3.4:443?encryption=none#${encodeURIComponent("onezun节点")}`,
  "vmess://" + Buffer.from(JSON.stringify({ v: "2", ps: "剩余流量", add: "1.2.3.4", port: "443", id: "11111111-2222-3333-4444-555555555555" })).toString("base64"),
  "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@1.2.3.4:443?encryption=none#%E7%BE%8E%E5%9B%BD%E8%8A%82%E7%82%B901",
  "trojan://trojanpass123@5.6.7.8:443#%E6%97%A5%E6%9C%AC%E8%8A%82%E7%82%B903",
];
const kwB64 = Buffer.from(kwLines.join("\n")).toString("base64");
const kwOut = Buffer.from(filterBlockedKeywords(kwB64).replace(/\s+/g, ""), "base64").toString("utf8");
const kwOutLines = kwOut.split("\n").filter(Boolean);
check("keyword filter drops info/blocked nodes, keeps real nodes (b64 in, b64 out)",
  kwOutLines.length === 2 && kwOut.includes("%E7%BE%8E%E5%9B%BD%E8%8A%82%E7%82%B901") && kwOut.includes("%E6%97%A5%E6%9C%AC%E8%8A%82%E7%82%B903") &&
  !kwOut.includes("剩余流量") && !kwOut.includes("重置") && !kwOut.includes("套餐到期") &&
  !kwOut.includes("白嫖") && !kwOut.includes("客户端") && !kwOut.includes("更新节点") && !kwOut.includes("805.55") && !kwOut.includes("2029-07-18") &&
  !kwOut.includes("官方入口") && !kwOut.includes("EDT导航优选域名") && !kwOut.includes("分享免费") &&
  !kwOut.toLowerCase().includes("bestcf") && !kwOut.toLowerCase().includes("onezun"),
  kwOut);
const kwPlainOut = filterBlockedKeywords(kwLines.join("\n"));
check("keyword filter works on plain text too",
  kwPlainOut.split("\n").filter(Boolean).length === 2 && !kwPlainOut.includes("剩余流量") && kwPlainOut.includes("%E7%BE%8E%E5%9B%BD%E8%8A%82%E7%82%B901"),
  kwPlainOut);
check("keyword filter leaves an all-blocked subscription untouched (never serves empty)",
  filterBlockedKeywords(kwLines.slice(0, 13).join("\n")) === kwLines.slice(0, 13).join("\n"));
const kwCleanB64 = Buffer.from(kwLines.slice(13).join("\n")).toString("base64");
check("keyword filter leaves a clean subscription byte-identical",
  filterBlockedKeywords(kwCleanB64) === kwCleanB64);
await j("/api/admin/member", { id: MID, action: "extend", days: 10001 }, { cookie });
const mbRevived = await fetch(mbMe.link);
check("extended member link alive again with real content", mbRevived.status === 200 && (await mbRevived.text()) === expectedSub);
const mbDelActive = await j("/api/admin/member", { id: MID, action: "delete" }, { cookie });
check("delete of active member refused", mbDelActive.status === 400);
await j("/api/admin/member", { id: MID, action: "disable" }, { cookie });
const mbDel = await j("/api/admin/member", { id: MID, action: "delete" }, { cookie });
check("member deleted, link + page gone", mbDel.status === 200 && (await fetch(mbMe.link)).status === 404 && (await fetch(BASE + "/m/" + MID)).status === 404);

// ---- minute-level durations (admin licenses + guests) ----
const MM1 = "TEST-MACH-0000-0101", MM2 = "TEST-MACH-0000-0102", MM3 = "TEST-MACH-0000-0103";
const minIssue = await j("/api/admin/issue", { machineCode: MM1, durationValue: 5, durationUnit: "minute", note: "五分钟客户", mode: "code" }, { cookie });
check("issue 5-minute code", minIssue.status === 200 && /^V2O-/.test(minIssue.data.code || ""));
const devM1 = await newDeviceKey();
const actM1 = await j("/api/activate", { machineCode: MM1, code: minIssue.data.code, pubkey: devM1.pubkey });
const listM = await (await fetch(BASE + "/api/admin/devices", { headers: { cookie } })).json();
const rowM1 = (listM.devices || []).find((d) => d.machine === MM1);
check("5-minute expiry exact (expires_at - activated_at == 300)",
  actM1.status === 200 && !!rowM1 && rowM1.lic.expires_at - rowM1.lic.activated_at === 300,
  rowM1 ? `diff=${rowM1.lic.expires_at - rowM1.lic.activated_at}` : "row missing");
const valM1 = await j("/api/validate", { machineCode: MM1, token: actM1.data.token });
check("5-minute validate remain_sec in range", valM1.status === 200 && valM1.data.remain_sec > 0 && valM1.data.remain_sec <= 300, `remain=${valM1.data.remain_sec}`);
const oneIssue = await j("/api/admin/issue", { machineCode: MM2, durationValue: 1, durationUnit: "minute", note: "一分钟客户", mode: "code" }, { cookie });
const devM2 = await newDeviceKey();
await j("/api/activate", { machineCode: MM2, code: oneIssue.data.code, pubkey: devM2.pubkey });
const listM2 = await (await fetch(BASE + "/api/admin/devices", { headers: { cookie } })).json();
const rowM2 = (listM2.devices || []).find((d) => d.machine === MM2);
check("1-minute expiry exact (diff == 60)", !!rowM2 && rowM2.lic.expires_at - rowM2.lic.activated_at === 60,
  rowM2 ? `diff=${rowM2.lic.expires_at - rowM2.lic.activated_at}` : "row missing");
const minIssued = await j("/api/admin/issue", { machineCode: MM3, durationValue: 5, durationUnit: "minute", note: "未激活五分钟", mode: "code" }, { cookie });
const listM3 = await (await fetch(BASE + "/api/admin/devices", { headers: { cookie } })).json();
const issuedM3 = (listM3.issued || []).find((i) => i.machine === MM3);
check("issued list shows 5分钟, not 0 天", minIssued.status === 200 && !!issuedM3 && issuedM3.duration_text === "5分钟", issuedM3 ? issuedM3.duration_text : "missing");
const badDur = await j("/api/admin/issue", { machineCode: MM3, durationValue: 0, durationUnit: "minute", mode: "code" }, { cookie });
check("zero-minute duration rejected", badDur.status === 400);
const badUnit = await j("/api/admin/issue", { machineCode: MM3, durationValue: 5, durationUnit: "week", mode: "code" }, { cookie });
check("bogus duration unit rejected", badUnit.status === 400);
// guest with a 1-minute account: login, minute-level remaining, expiry
const gmCreate = await j("/api/admin/guest", { action: "create", username: "一分钟游客", password: "guest-pw-1", durationValue: 1, durationUnit: "minute" }, { cookie });
check("admin creates 1-minute guest", gmCreate.status === 200 && !!gmCreate.data.id, JSON.stringify(gmCreate.data).slice(0, 80));
const GMID = gmCreate.data.id;
const gmLogin = await j("/api/guest/login", { id: GMID, password: "guest-pw-1" });
check("1-minute guest logs in", gmLogin.status === 200 && typeof gmLogin.data.session === "string");
const gmMe = await (await fetch(BASE + "/api/guest/me", { headers: { "x-gsess": gmLogin.data.session } })).json();
check("1-minute guest sees minute-level remaining", gmMe.ok === true && gmMe.remain_sec > 0 && gmMe.remain_sec <= 60 && gmMe.minutes_left === 1, `remain_sec=${gmMe.remain_sec}`);
check("1-minute guest link serves before expiry", (await fetch(gmMe.link)).status === 200);
await j("/api/admin/guest", { id: GMID, action: "extend", days: -1 }, { cookie });
check("guest link past expiry still serves only obfuscated (200, no hard cut)", (await fetch(gmMe.link)).status === 200);
const gmLoginExpired = await j("/api/guest/login", { id: GMID, password: "guest-pw-1" });
check("expired guest cannot log in", gmLoginExpired.status === 403 && gmLoginExpired.data.reason === "expired");
await j("/api/admin/guest", { id: GMID, action: "extend", days: 2 }, { cookie });
check("guest link alive again after extend", (await fetch(gmMe.link)).status === 200);
// guest manual expiry edit （修改时间， precise to the second)
const gSetPastDay = await j("/api/admin/guest", { id: GMID, action: "set_expiry", expires_at: nowS - 90000 }, { cookie });
check("guest set_expiry to a past day still serves only obfuscated (200)", gSetPastDay.status === 200 && (await fetch(gmMe.link)).status === 200);
const gSetPast = await j("/api/admin/guest", { id: GMID, action: "set_expiry", expires_at: nowS - 5 }, { cookie });
check("guest set_expiry to moments ago serves obfuscated (200)",
  gSetPast.status === 200 && (await fetch(gmMe.link)).status === 200);
const gSetFuture = await j("/api/admin/guest", { id: GMID, action: "set_expiry", expires_at: nowS + 3600 }, { cookie });
check("guest set_expiry to future revives link", gSetFuture.status === 200 && gSetFuture.data.expires_at === nowS + 3600 && (await fetch(gmMe.link)).status === 200);
const gSetBad = await j("/api/admin/guest", { id: GMID, action: "set_expiry", expires_at: "xyz" }, { cookie });
check("guest set_expiry rejects garbage", gSetBad.status === 400);
await j("/api/admin/guest", { id: GMID, action: "disable" }, { cookie });
await j("/api/admin/guest", { id: GMID, action: "delete" }, { cookie });

// ---- legacy offline-code conversion (fixture key; skipped if absent) ----
import { readFileSync } from "node:fs";
let legacyFx = null;
try { legacyFx = JSON.parse(readFileSync(new URL("./fixtures/legacy_test_key.json", import.meta.url), "utf8")); } catch {}
if (legacyFx) {
  const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const b32enc = (bytes) => {
    let s = "", buf = 0, bits = 0;
    for (const b of bytes) { buf = (buf << 8) | b; bits += 8; while (bits >= 5) { bits -= 5; s += B32[(buf >> bits) & 31]; } }
    if (bits > 0) s += B32[(buf << (5 - bits)) & 31];
    return s;
  };
  const group = (s) => s.match(/.{1,4}/g).join("-");
  const priv = await crypto.subtle.importKey("jwk", legacyFx.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const devL = await newDeviceKey();
  async function makeLegacyCode(machineHash, expiryMinutes) {
    const payload = new Uint8Array(63);
    payload[0] = 0x03;
    payload[1] = (expiryMinutes >>> 24) & 0xff; payload[2] = (expiryMinutes >>> 16) & 0xff;
    payload[3] = (expiryMinutes >>> 8) & 0xff; payload[4] = expiryMinutes & 0xff;
    payload.set(machineHash, 5);
    crypto.getRandomValues(payload.subarray(15));
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, priv, payload));
    const blob = new Uint8Array(127); blob.set(payload); blob.set(sig, 63);
    return group(b32enc(blob));
  }
  const hashL = new Uint8Array(10); crypto.getRandomValues(hashL);
  const machineL = group(b32enc(hashL));
  const futureMin = Math.floor(Date.now() / 60000) + 60 * 24 * 30;
  const legacyCode = await makeLegacyCode(hashL, futureMin);
  const conv = await j("/api/legacy", { machineCode: machineL, code: legacyCode, pubkey: devL.pubkey, platform: "android-test" });
  check("legacy code converts + token issued", conv.status === 200 && !!conv.data.token, JSON.stringify(conv.data).slice(0, 80));
  const valL = await j("/api/validate", { machineCode: machineL, token: conv.data.token });
  check("converted device validates", valL.status === 200 && valL.data.ok === true);
  const convWrongMachine = await j("/api/legacy", { machineCode: M2, code: legacyCode, pubkey: devL.pubkey });
  check("legacy code bound to its machine", convWrongMachine.status === 403 && convWrongMachine.data.reason === "bound_other");
  const expiredCode = await makeLegacyCode(hashL, Math.floor(Date.now() / 60000) - 60);
  const convExpired = await j("/api/legacy", { machineCode: machineL, code: expiredCode, pubkey: devL.pubkey });
  check("expired legacy code refused", convExpired.status === 403 && convExpired.data.reason === "expired");
  const tampered = legacyCode.slice(0, -2) + (legacyCode.endsWith("A") ? "B" : "A") + legacyCode.slice(-1);
  const convBad = await j("/api/legacy", { machineCode: machineL, code: tampered, pubkey: devL.pubkey });
  check("tampered legacy code refused", convBad.status === 403);
}

// ---- distributor-managed guests ----
const createDistG = await j("/api/admin/dist", { action: "create", slug: "ggg", name: "游客分销", password: "dist-guest-pw", quota: 3 }, { cookie });
const dgLoginRes = await fetch(BASE + "/api/dist/login", {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ slug: "ggg", password: "dist-guest-pw" }),
});
const dgCookie = (dgLoginRes.headers.get("set-cookie") || "").split(";")[0];
check("dist guest: distributor ready", createDistG.status === 200 && dgCookie.startsWith("dsess="));
const dgCreate = await j("/api/dist/guest", { action: "create", username: "分销游客甲", password: "guest-pw-9", durationValue: 30, durationUnit: "day" }, { cookie: dgCookie });
check("dist creates guest", dgCreate.status === 200 && !!dgCreate.data.id, JSON.stringify(dgCreate.data).slice(0, 80));
const DGID = dgCreate.data.id;
const dgMe0 = await fetch(BASE + "/api/dist/me", { headers: { cookie: dgCookie } }).then((r) => r.json());
check("dist guest consumes one quota", dgMe0.ok === true && dgMe0.used === 1 && dgMe0.remaining === 2, JSON.stringify(dgMe0).slice(0, 80));
const dgLogin = await j("/api/guest/login", { id: DGID, password: "guest-pw-9" });
const dgMe = await (await fetch(BASE + "/api/guest/me", { headers: { "x-gsess": dgLogin.data.session } })).json();
const dgFetch = await fetch(dgMe.link);
check("dist guest link serves DIST subscription", dgFetch.status === 200 && (await dgFetch.text()) === expectedDist);
const dgPerm = await j("/api/dist/guest", { action: "create", username: "分销游客乙", password: "guest-pw-9", days: 0 }, { cookie: dgCookie });
check("dist guest permanent rejected", dgPerm.status === 400);
const dgYear = await j("/api/dist/guest", { action: "create", username: "分销游客乙", password: "guest-pw-9", durationValue: 366, durationUnit: "day" }, { cookie: dgCookie });
check("dist guest over 365 days rejected", dgYear.status === 400);
const dgPermExp = await j("/api/dist/guest", { id: DGID, action: "set_expiry", expires_at: null }, { cookie: dgCookie });
check("dist guest set_expiry permanent rejected", dgPermExp.status === 400);
const dgAdminTouch = await j("/api/dist/guest", { id: GID, action: "disable" }, { cookie: dgCookie });
check("dist cannot touch admin guest", dgAdminTouch.status === 404);
await j("/api/dist/guest", { id: DGID, action: "disable" }, { cookie: dgCookie });
check("dist guest link dies on disable", (await fetch(dgMe.link)).status === 403);
await j("/api/dist/guest", { id: DGID, action: "enable" }, { cookie: dgCookie });
check("dist guest link revives on enable", (await fetch(dgMe.link)).status === 200);
const dgList = await fetch(BASE + "/api/admin/guest", { headers: { cookie } }).then((r) => r.json());
check("admin sees dist guest with owner", (dgList.guests || []).some((g) => g.id === DGID && g.dist === "ggg"));
// the distributor's own guest list (x-dsess header auth, as the page
// uses): the added guest is there, and a second one appends BELOW it
const dgToken = dgCookie.slice("dsess=".length);
const dgOwn1 = await fetch(BASE + "/api/dist/guest", { headers: { "x-dsess": dgToken } }).then((r) => r.json());
check("dist guest list shows his guest", dgOwn1.ok === true && dgOwn1.guests.length === 1 && dgOwn1.guests[0].id === DGID);
const dgCreate2 = await j("/api/dist/guest", { action: "create", username: "分销游客丙", password: "guest-pw-9", durationValue: 10, durationUnit: "day" }, { cookie: dgCookie });
const dgOwn2 = await fetch(BASE + "/api/dist/guest", { headers: { "x-dsess": dgToken } }).then((r) => r.json());
check("new guest appends at the bottom", dgCreate2.status === 200 && dgOwn2.guests.length === 2 && dgOwn2.guests[0].id === DGID && dgOwn2.guests[1].id === dgCreate2.data.id);

console.log(`\n==== ${pass} passed, ${fail} failed ====`);
process.exit(fail ? 1 : 0);
