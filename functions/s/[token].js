import { getGuest, guestProblem, getMember, memberProblem, vaultOpen, logEvent, noteGuestFetch } from "../lib/core.js";
import { serveSubscription, guestChannel } from "../api/subscription.js";
import { expiredSubscription, expiredFallbackSubscription } from "../lib/poison.js";

// GET /s/<sealed-token>
// A guest's personal subscription link, pasted into Shadowrocket or
// any other third-party client as a subscription URL. The token is an
// opaque AES-GCM sealed guest reference, minted when the admin
// created the guest; the real subscription URL never leaves the
// server. Every fetch re-reads the guest record, so the moment the
// admin disables or deletes the guest, this link stops serving
// subscription data; re-enabling revives it. Expiry is different:
// an expired record (guest or formal member) keeps an always-open
// link that only ever serves the fully obfuscated subscription,
// and renewing revives the real content on the next fetch.
export async function onRequestGet({ request, env, params }) {
  const deny = (reason, status = 403) =>
    new Response(JSON.stringify({ ok: false, reason }), {
      status,
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    });

  let payload = null;
  try {
    payload = JSON.parse((await vaultOpen(env, params.token)) || "null");
  } catch {
    payload = null;
  }
  if (payload && payload.m) {
    // Formal member （小火箭正式会员）: his link serves the main
    // channel — the same subscription the authorized client pulls —
    // while the record is usable. Expired: still serve the
    // subscription, but fully obfuscated (owner, 2026-11-09) — every
    // node renamed “已到期请联系卖家”, every UUID/password “xxx”
    // and every address the dead IP, so updating in Shadowrocket
    // overwrites his nodes with dead ones. Nothing else is ever
    // served, and renewing revives the real content on the next
    // fetch. If the live subscription cannot be fetched, serve the
    // static fallback instead of a 403, so the link always stays
    // open and always serves only obfuscated nodes.
    const mrec = await getMember(env, payload.m);
    if (!mrec) return deny("not_found", 404);
    const mproblem = memberProblem(mrec);
    if (mproblem === "expired") {
      await logEvent(env, "member_sub_expired", mrec.username || "", "expired");
      const mcontent = await serveSubscription(env, "main");
      return new Response(mcontent ? expiredSubscription(mcontent) : expiredFallbackSubscription(), {
        status: 200,
        headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
      });
    }
    if (mproblem) {
      await logEvent(env, "member_sub_deny", mrec.username || "", mproblem);
      return deny(mproblem);
    }
    const mcontent = await serveSubscription(env, "main");
    if (!mcontent) return deny("sub_unavailable", 502);
    return new Response(mcontent, {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
    });
  }
  if (!payload || !payload.g) return deny("bad_link", 404);

  const rec = await getGuest(env, payload.g);
  if (!rec) return deny("not_found", 404);
  const problem = guestProblem(rec);
  if (problem === "expired") {
    // Owner rule (2026-11-09): an expired guest, like an expired
    // formal member, keeps an always-open link that only ever
    // serves the fully obfuscated subscription — every node renamed
    // “已到期请联系卖家”, every UUID/password “xxx”, every address
    // the dead IP, SNI/ws host/ws path “xxx” — so updating in the
    // client overwrites his nodes with dead ones. No hard cut any
    // more, on any day. Renewing revives the real content on the
    // next fetch. If the live subscription cannot be fetched, serve
    // the static fallback instead of a 403, so the link always
    // stays open.
    const content = await serveSubscription(env, guestChannel(env, rec));
    await logEvent(env, "guest_sub_expired", rec.username || "", "expired");
    return new Response(content ? expiredSubscription(content) : expiredFallbackSubscription(), {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
    });
  }
  if (problem) {
    await logEvent(env, "guest_sub_deny", rec.username || "", problem);
    return deny(problem);
  }

  // Fetch watching: note where this fetch came from (Cloudflare IP
  // geolocation). More than 5 distinct provinces in 7 days means
  // the link is being shared — the guest is disabled on the spot
  // and this fetch is denied too. TEST_REGION_HEADER exists only
  // in local dev vars (never set in production) so the region rule
  // can be exercised end-to-end with an x-test-region header.
  const cf = request.cf || {};
  let region = "";
  if (env.TEST_REGION_HEADER) region = request.headers.get("x-test-region") || "";
  if (!region) region = cf.region || "";
  if (!region && cf.country) region = cf.country;
  const verdict = await noteGuestFetch(env, payload.g, rec, {
    ip: request.headers.get("cf-connecting-ip") || "",
    ua: (request.headers.get("user-agent") || "").slice(0, 120),
    region,
  });
  if (verdict.dailyBlocked) return deny("daily_limit", 429);
  if (verdict.disabled) return deny("disabled");

  const content = await serveSubscription(env, guestChannel(env, rec));
  if (!content) return deny("sub_unavailable", 502);
  return new Response(content, {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}
