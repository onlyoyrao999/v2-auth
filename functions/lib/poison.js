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
// Owner rule (2026-11-09, final form): when a formal member
// （小火箭正式会员） expires, his /s/ link still serves the
// subscription — but fully obfuscated, so updating in Shadowrocket
// overwrites his nodes with dead ones. Every node name becomes
// “已到期请联系卖家”, every UUID / password becomes “xxx”, and
// every server address becomes the dead IP 114.115.116.117 (the
// same dead IP the guest poison uses). SNI and Host values in the
// URI query and in vmess payloads are blanked to “xxx” too, so no
// real domain leaks through them either. Ports and the base64
// envelope are preserved (base64 in, base64 out; plain in, plain
// out), and renewing revives the real content on the next fetch.
const EXPIRED_NAME = "已到期请联系卖家";
const EXPIRED_ID = "xxx";

function obfuscateUriLine(line) {
  const hash = line.indexOf("#");
  const base = hash === -1 ? line : line.slice(0, hash);
  let out = base.replace(UUID_RE, EXPIRED_ID);
  // vless://<uuid>@host / trojan://<password>@host / ss://<user>@host:
  // the credential is the userinfo before the first "@", the
  // address is the authority host after it.
  const at = out.match(/^([a-z0-9+.-]+:\/\/)([^/@?#]+)@/i);
  if (at) {
    out = out.slice(0, at[1].length) + EXPIRED_ID + out.slice(at[1].length + at[2].length);
    out = out.replace(/^([a-z0-9+.-]+:\/\/[^/@]*@)([^/:?#]+)/i, `$1${FAKE_IP}`);
  }
  // Query params that name the real server — SNI, ws Host, ws Path
  // and friends — blank them to xxx too, or the real domain would
  // still leak through them.
  out = out.replace(/([?&])(sni|host|path|serverName|server_name|peer)=[^&#]*/gi, `$1$2=${EXPIRED_ID}`);
  // ss://<base64(method:password@host:port)> — no "@" outside the
  // payload, so decode it, blank the password and the host,
  // re-encode it.
  if (!at && /^ss:\/\//i.test(out)) {
    const m = out.match(/^ss:\/\/([^/?#]+)(\?.*)?$/i);
    if (m) {
      try {
        const inner = b64DecodeText(m[1]);
        const innerAt = inner.lastIndexOf("@");
        const innerColon = inner.indexOf(":");
        if (innerAt > innerColon && innerColon !== -1) {
          const hostPort = inner.slice(innerAt + 1);
          const colon = hostPort.indexOf(":");
          const port = colon === -1 ? "" : hostPort.slice(colon);
          out = "ss://" + b64EncodeText(inner.slice(0, innerColon + 1) + EXPIRED_ID + "@" + FAKE_IP + port) + (m[2] || "");
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
        obj.add = FAKE_IP;
        let inner = JSON.stringify(obj)
          .replace(/"sni"\s*:\s*"[^"]*"/g, `"sni": "${EXPIRED_ID}"`)
          .replace(/"host"\s*:\s*"[^"]*"/g, `"host": "${EXPIRED_ID}"`)
          .replace(/"path"\s*:\s*"[^"]*"/g, `"path": "${EXPIRED_ID}"`)
          .replace(UUID_RE, EXPIRED_ID).replace(IPV4_RE, FAKE_IP);
        return "vmess://" + b64EncodeText(inner);
      } catch {
        return obfuscateUriLine(line.replace(UUID_RE, EXPIRED_ID));
      }
    }
    if (line.includes("://")) return obfuscateUriLine(line);
    return line.replace(UUID_RE, EXPIRED_ID).replace(IPV4_RE, FAKE_IP);
  });
  const out = lines.join("\n");
  return wasB64 ? b64EncodeText(out) : out;
}

// Fallback for an expired member when the live subscription cannot
// be fetched at all: a single dead node, in the same base64
// envelope, so the link still answers 200 and the client still
// overwrites its nodes instead of keeping the real ones on a 403.
export function expiredFallbackSubscription() {
  return b64EncodeText(
    `vless://${EXPIRED_ID}@${FAKE_IP}:443#${encodeURIComponent(EXPIRED_NAME)}`,
  );
}
