// ---------- keyword filter for served subscriptions ----------
// Owner rule (2026-11-10): when a subscription is served, drop any
// node whose display name contains one of these keywords. The
// upstream source embeds "info nodes" whose names leak the upstream
// account — remaining traffic, days to the next reset, the plan's
// expiry date — and other labels the owner does not want served.
// Dropping the whole line removes the entry from the client
// entirely; merely blanking the keyword would still leave the
// value behind (e.g. ": 805.55 GB").
//
// The list is the owner's words, in order. Extend it here when he
// names more keywords — the match is a plain substring on the
// decoded display name, so "距离下次重置剩余" also matches through
// "剩余", and "白嫖" matches "白嫖节点" etc.
export const BLOCKED_KEYWORDS = [
  "剩余流量",
  "距离下次重置剩余",
  "套餐到期",
  "白嫖",
  "客户端",
];

function b64DecodeText(s) {
  const bin = atob(s.replace(/\s+/g, ""));
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}
function b64EncodeText(s) {
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function decodeFragment(frag) {
  try {
    return decodeURIComponent(frag);
  } catch {
    return frag;
  }
}

// The display name of one subscription line, or "" when it has none:
// vmess carries it in the base64 JSON "ps" field, every other URI
// carries it in the "#" fragment, and a bare line is its own name.
export function lineDisplayName(line) {
  const vm = line.match(/^vmess:\/\/(.+)$/);
  if (vm) {
    try {
      const obj = JSON.parse(b64DecodeText(vm[1]));
      return typeof obj.ps === "string" ? obj.ps : "";
    } catch {
      return "";
    }
  }
  const hash = line.indexOf("#");
  if (hash !== -1) return decodeFragment(line.slice(hash + 1));
  return line;
}

function isBlocked(line) {
  const name = lineDisplayName(line);
  if (BLOCKED_KEYWORDS.some((k) => name.includes(k))) return true;
  // A keyword outside the name (e.g. in a query param) still counts.
  if (BLOCKED_KEYWORDS.some((k) => line.includes(k))) return true;
  return false;
}

// Drop every blocked line from a subscription, preserving the
// envelope (base64 in, base64 out; plain in, plain out). If the
// filter would leave nothing at all, return the input unchanged
// rather than serving an empty subscription.
export function filterBlockedKeywords(content) {
  let text = content;
  let wasB64 = false;
  try {
    const decoded = b64DecodeText(content.trim());
    if (decoded.includes("://")) {
      text = decoded;
      wasB64 = true;
    }
  } catch {
    // Not base64: filter the content as-is.
  }
  const kept = text.split(/\r?\n/).filter((line) => {
    if (!line.trim()) return true;
    return !isBlocked(line);
  });
  const droppedAny = kept.length !== text.split(/\r?\n/).length;
  if (!droppedAny) return content;
  const hasNode = kept.some((line) => line.includes("://"));
  if (!hasNode) return content;
  const out = kept.join("\n");
  return wasB64 ? b64EncodeText(out) : out;
}
