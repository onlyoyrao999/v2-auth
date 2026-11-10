import { readJson, nowSec, gate, putDev, logEvent } from "../lib/core.js";
import { filterBlockedKeywords } from "../lib/filter.js";

// Channel config: each license carries channel "main" | "dist".
// main -> env.SUB_URL (KV sub:*), dist -> env.SUB_URL_DIST (KV subd:*).
// Distributors share the main subscription unless a SEPARATE, VALID
// dist URL is configured: a value that is not an http(s) URL at all
// (the dashboard once held the literal text "mm") counts as "not
// configured" and falls back to main, instead of breaking every
// distributor pull.
function usableUrl(v) {
  if (!v) return null;
  try {
    const u = new URL(v);
    return u.protocol === "http:" || u.protocol === "https:" ? v : null;
  } catch {
    return null;
  }
}
function channelCfg(env, channel) {
  if (channel === "guest") {
    const g = usableUrl(env.SUB_URL_GUEST);
    if (g) return { url: g, prefix: "subg" };
  }
  if (channel === "dist") {
    const dist = usableUrl(env.SUB_URL_DIST);
    if (dist) return { url: dist, prefix: "subd" };
  }
  return { url: usableUrl(env.SUB_URL), prefix: "sub" };
}

// Guests normally ride their record's channel (main/dist). Setting
// env.SUB_URL_GUEST pins EVERY guest to that one subscription address
// instead — unset, or not a valid http(s) URL, guest dispatch follows
// the record's channel exactly as before.
export function guestChannel(env, rec) {
  if (usableUrl(env.SUB_URL_GUEST)) return "guest";
  return rec && rec.channel === "dist" ? "dist" : "main";
}

export async function serveSubscription(env, channel) {
  const { url } = channelCfg(env, channel);
  // REAL-TIME ONLY, no cache is ever served (owner, 2026-11-05):
  // the node addresses inside the subscription rotate constantly,
  // so a stored copy is a list of dead addresses — serving it
  // "as a fallback" hands the customer junk that looks like a
  // working config. Every serve fetches the subscription address
  // fresh and returns exactly that, minus any line whose display
  // name carries a blocked keyword (see lib/filter.js); when the
  // live fetch fails the serve fails with it (callers answer
  // sub_unavailable / hard deny) and the client retries later.
  // Nothing is stored.
  if (!url) return null;
  try {
    const up = await fetch(url, {
      headers: { "user-agent": "okhttp/4.9.0" },
      // 20s, not 8s: the main subscription source measured 2026-11-07
      // answers in ~5s from a browser and slower through the worker —
      // at 8s every member pull timed out into sub_unavailable while
      // the address itself was perfectly healthy.
      signal: AbortSignal.timeout(20000),
    });
    if (!up.ok) return null;
    const text = await up.text();
    if (!text || text.length <= 50) return null;
    return filterBlockedKeywords(text);
  } catch {
    return null;
  }
}

// POST {machineCode, sig, ts, nonce} or {machineCode, token}
// Validates first; only then serves the subscription for the device's
// channel, pulled from the channel's URL in real time on every call.
export async function onRequestPost({ request, env }) {
  const body = await readJson(request);
  const g = await gate(env, body.machineCode, body, "/api/subscription");
  if (!g.ok) {
    // Expired devices (owner, 2026-11-06, final form): stop serving
    // real content and say so in the open — the pull returns a
    // plain-text notice, on any day, no window. No fabricated or
    // altered content is ever served as a subscription.
    if (g.reason === "expired") {
      await logEvent(env, "sub_expired_notice", body.machineCode || "", "expired");
      return new Response("已到期，请联系卖家", {
        status: 403,
        headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
      });
    }
    await logEvent(env, "sub_deny", body.machineCode || "", g.reason);
    return new Response(JSON.stringify({ ok: false, reason: g.reason }), {
      status: g.status || 403,
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    });
  }

  const channel = g.lic.channel === "dist" ? "dist" : "main";
  const content = await serveSubscription(env, channel);
  if (!content) {
    return new Response(JSON.stringify({ ok: false, reason: "sub_unavailable" }), {
      status: 502, headers: { "content-type": "application/json", "cache-control": "no-store" },
    });
  }
  const dev = { ...g.dev, last_seen: nowSec(), pulls: (g.dev.pulls || 0) + 1 };
  await putDev(env, body.machineCode, dev);
  return new Response(content, {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}
