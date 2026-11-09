// ---------- poisoned subscription for expired licenses ----------
// Every server address in the subscription becomes one dead IP:
// raw IPv4s anywhere in the text, the authority host of every
// share URI (domains included — an IP-only pass would leave
// domain-addressed nodes alive), and the "add" field inside
// vmess payloads. Every UUID is replaced too: a poisoned file that
// kept the real UUID would leak it — anyone could pair it with a
// live address by hand and keep connecting. Ports and names stay
// untouched so the file stays structurally valid and clients
// accept the update.
//
// Shared by the guest link (/s/<token>) and the device pull
// (/api/subscription): both serve this on the Beijing expiry day
// of an expired license, and hard-deny from the next day on.
const FAKE_IP = "114.115.116.117";
const FAKE_UUID = "00000000-0000-4000-8000-000000000000";
const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const UUID_RE = /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g;

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

export function poisonSubscription(content) {
  let text = content;
  let wasB64 = false;
  try {
    const decoded = b64DecodeText(content.trim());
    if (decoded.includes("://")) {
      text = decoded;
      wasB64 = true;
    }
  } catch {
    // Not base64: transform the content as-is.
  }
  const lines = text.split(/\r?\n/).map((line) => {
    const vm = line.match(/^vmess:\/\/(.+)$/);
    if (vm) {
      try {
        let inner = b64DecodeText(vm[1]);
        inner = inner.replace(/"add"\s*:\s*"[^"]*"/, `"add": "${FAKE_IP}"`);
        inner = inner.replace(/"id"\s*:\s*"[^"]*"/, `"id": "${FAKE_UUID}"`);
        inner = inner.replace(UUID_RE, FAKE_UUID);
        inner = inner.replace(IPV4_RE, FAKE_IP);
        return "vmess://" + b64EncodeText(inner);
      } catch {
        return line.replace(UUID_RE, FAKE_UUID).replace(IPV4_RE, FAKE_IP);
      }
    }
    return line
      .replace(/^([a-z0-9+.-]+:\/\/[^/@]*@)([^/:?#]+)/i, `$1${FAKE_IP}`)
      .replace(UUID_RE, FAKE_UUID)
      .replace(IPV4_RE, FAKE_IP);
  });
  const out = lines.join("\n");
  return wasB64 ? b64EncodeText(out) : out;
}

// ---------- expired formal-member subscription ----------
// Owner rule (2026-11-09): when a formal member （小火箭正式会员）
// expires, his /s/ link still serves the subscription — but only
// as a reminder, not as working nodes. Every node name becomes
// “已到期，请续费” so the user sees it the first time he opens
// Shadowrocket and knows to contact the seller to renew, and every
// UUID / password becomes “xxx” so no node can actually connect.
// Nothing else changes: addresses, ports and the rest of the
// payload are left untouched, and the base64 envelope is preserved
// (base64 in, base64 out; plain in, plain out).
const EXPIRED_NAME = "已到期，请续费";
const EXPIRED_ID = "xxx";

function renameUriLine(line) {
  const hash = line.indexOf("#");
  const base = hash === -1 ? line : line.slice(0, hash);
  let out = base.replace(UUID_RE, EXPIRED_ID);
  // vless://<uuid>@host / trojan://<password>@host / ss://<user>@host:
  // the credential is the userinfo before the first "@".
  const at = out.match(/^([a-z0-9+.-]+:\/\/)([^/@?#]+)@/i);
  if (at) out = out.slice(0, at[1].length) + EXPIRED_ID + out.slice(at[1].length + at[2].length);
  // ss://<base64(method:password@host:port)> — no "@" outside the
  // payload, so decode it, blank the password, re-encode it.
  if (!at && /^ss:\/\//i.test(out)) {
    const m = out.match(/^ss:\/\/([^/?#]+)(\?.*)?$/i);
    if (m) {
      try {
        const inner = b64DecodeText(m[1]);
        const innerAt = inner.lastIndexOf("@");
        const innerColon = inner.indexOf(":");
        if (innerAt > innerColon && innerColon !== -1) {
          out = "ss://" + b64EncodeText(inner.slice(0, innerColon + 1) + EXPIRED_ID + inner.slice(innerAt)) + (m[2] || "");
        }
      } catch {
        // Not a decodable ss payload: leave the line as-is.
      }
    }
  }
  return out + "#" + encodeURIComponent(EXPIRED_NAME);
}

export function expiredSubscription(content) {
  let text = content;
  let wasB64 = false;
  try {
    const decoded = b64DecodeText(content.trim());
    if (decoded.includes("://")) {
      text = decoded;
      wasB64 = true;
    }
  } catch {
    // Not base64: transform the content as-is.
  }
  const lines = text.split(/\r?\n/).map((line) => {
    if (!line.trim()) return line;
    const vm = line.match(/^vmess:\/\/(.+)$/);
    if (vm) {
      try {
        const obj = JSON.parse(b64DecodeText(vm[1]));
        obj.ps = EXPIRED_NAME;
        obj.id = EXPIRED_ID;
        let inner = JSON.stringify(obj).replace(UUID_RE, EXPIRED_ID);
        return "vmess://" + b64EncodeText(inner);
      } catch {
        return renameUriLine(line.replace(UUID_RE, EXPIRED_ID));
      }
    }
    if (line.includes("://")) return renameUriLine(line);
    return line.replace(UUID_RE, EXPIRED_ID);
  });
  const out = lines.join("\n");
  return wasB64 ? b64EncodeText(out) : out;
}
