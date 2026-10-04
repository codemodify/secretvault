// Passkeys: the parts of WebAuthn the extension decides itself, before
// secretvault is asked (svext/webauthn.go checks the same again):
//
//   - which rpId a page's origin may use (rpIdFits): the origin's host, or
//     a registrable domain suffix of it by the Public Suffix List, on a
//     secure page only (https, or http on localhost);
//   - clientDataJSON (clientData), built from the origin the browser gave
//     for the frame, never from anything the page says;
//   - reading what a page passed to navigator.credentials.create or get
//     (createRequest, getRequest) into the protocol's members, or saying
//     why secretvault should not take it, so the browser handles it.
//
// A classic script, like the other lib/ modules: it adds SVWebAuthn to
// the global object, and needs SVPSL and SVOrigin.
(function (root) {
  "use strict";

  const LIMITS = Object.freeze({
    rpId: 253,
    rpName: 256,
    userName: 256,
    userHandle: 64,
    credentialId: 1023,
    credentialIds: 64,
    credentialIdsBytes: 16 * 1024,
    algorithms: 16,
    challengeMin: 16,
    challengeMax: 4096,
    clientData: 8192,
  });

  const ES256 = -7;
  const EDDSA = -8;

  // ---------------------------------------------------------- base64url

  const ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

  function b64(bytes) {
    const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let out = "";
    let i = 0;
    for (; i + 2 < b.length; i += 3) {
      const n = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2];
      out += ALPHA[n >> 18] + ALPHA[(n >> 12) & 63] + ALPHA[(n >> 6) & 63] + ALPHA[n & 63];
    }
    if (i < b.length) {
      const n = (b[i] << 16) | ((i + 1 < b.length ? b[i + 1] : 0) << 8);
      out += ALPHA[n >> 18] + ALPHA[(n >> 12) & 63];
      if (i + 1 < b.length) out += ALPHA[(n >> 6) & 63];
    }
    return out;
  }

  // unb64 reads base64url (no padding); null for anything else.
  function unb64(s) {
    if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return null;
    const out = new Uint8Array(Math.floor((s.length * 3) / 4));
    let bits = 0;
    let acc = 0;
    let j = 0;
    for (const c of s) {
      acc = (acc << 6) | ALPHA.indexOf(c);
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        out[j++] = (acc >> bits) & 0xff;
      }
    }
    if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) return null; // non-zero padding bits
    return out.subarray(0, j);
  }

  // bytes reads a BufferSource a page passed (an ArrayBuffer, or a view
  // of one), or plain's {$bytes} for one, into a copy; null for anything
  // else.
  function bytes(v) {
    if (v && typeof v === "object" && Object.keys(v).length === 1 && typeof v.$bytes === "string") return unb64(v.$bytes);
    if (v instanceof ArrayBuffer) return new Uint8Array(v.slice(0));
    if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer.slice(v.byteOffset, v.byteOffset + v.byteLength));
    // Across realms (a page's buffers seen from an extension's world).
    const tag = Object.prototype.toString.call(v);
    if (tag === "[object ArrayBuffer]") return new Uint8Array(v).slice();
    if (/^\[object (Uint8|Int8|Uint8Clamped|Uint16|Int16|Uint32|Int32|Float32|Float64|BigInt64|BigUint64)Array\]$/.test(tag) || tag === "[object DataView]") {
      return new Uint8Array(v.buffer, v.byteOffset, v.byteLength).slice();
    }
    return null;
  }

  // plain copies what a page passed as publicKey options into what can be
  // sent as a runtime message (JSON): buffers become {$bytes: base64url},
  // functions and other objects are dropped, and it is bounded (depth,
  // members, lengths, all in all), so a page cannot make it large.
  // null when it is over the bounds.
  function plain(v) {
    let budget = 256 * 1024;
    const walk = (x, depth) => {
      if (budget <= 0 || depth > 6) throw new Refusal("the options are too large");
      if (x === null || typeof x === "boolean") return x;
      if (typeof x === "number") return Number.isFinite(x) ? x : null;
      if (typeof x === "string") {
        budget -= x.length;
        return x.length <= 16384 ? x : x.slice(0, 16384);
      }
      if (typeof x !== "object") return undefined;
      const b = bytes(x);
      if (b) {
        budget -= b.length * 2;
        if (b.length > 16384) throw new Refusal("a buffer is too large");
        return { $bytes: b64(b) };
      }
      if (Array.isArray(x)) {
        if (x.length > 256) throw new Refusal("a list is too long");
        return x.map((e) => walk(e, depth + 1));
      }
      const out = {};
      let n = 0;
      for (const k of Object.keys(x)) {
        if (++n > 64) throw new Refusal("too many members");
        const w = walk(x[k], depth + 1);
        if (w !== undefined && k !== "__proto__") out[k] = w;
      }
      return out;
    };
    try {
      const out = walk(v, 0);
      return budget > 0 ? out : null;
    } catch {
      return null;
    }
  }

  // ---------------------------------------------------------- the rpId

  function isIP(host) {
    return /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(":") || host.startsWith("[");
  }

  // secureOrigin: https, or http on localhost or a .localhost name, with a
  // domain for its host.
  function secureOrigin(origin) {
    const p = root.SVOrigin.parseOrigin(origin);
    if (!p || isIP(p.host)) return false;
    if (p.scheme === "https:") return true;
    return p.scheme === "http:" && (p.host === "localhost" || p.host.endsWith(".localhost"));
  }

  // normalRPID is an rpId as browsers write hosts (the URL parser's
  // lower-case ASCII form), or null when it is not a host name.
  function normalRPID(rpId) {
    if (typeof rpId !== "string" || rpId === "" || rpId.length > LIMITS.rpId || /[/:?#@\s\\[\]%]/.test(rpId)) return null;
    let host;
    try {
      host = new URL("https://" + rpId + "/").hostname;
    } catch {
      return null;
    }
    if (!host || isIP(host) || host.endsWith(".") || !/^[a-z0-9.-]+$/.test(host)) return null;
    return host;
  }

  // rpIdFits: may a page at origin use rpId (as normalRPID writes it)?
  function rpIdFits(list, rpId, origin) {
    if (!secureOrigin(origin)) return false;
    if (typeof rpId !== "string" || rpId === "" || normalRPID(rpId) !== rpId) return false;
    const host = root.SVOrigin.parseOrigin(origin).host;
    if (rpId === host) return true;
    if (!host.endsWith("." + rpId)) return false;
    const ps = root.SVPSL.publicSuffix(list, host);
    return !(rpId === root.SVPSL.publicSuffix(list, rpId) || ps === rpId || ps.endsWith("." + rpId));
  }

  // ------------------------------------------------------ clientDataJSON

  // clientData is clientDataJSON (WebAuthn §5.8.1.1, in its order): the
  // type, the challenge, the frame's origin, whether the frame is
  // cross-origin, and then its top page's origin.
  function clientData(type, challenge, origin, topOrigin) {
    const cross = typeof topOrigin === "string" && topOrigin !== "";
    let s = '{"type":' + JSON.stringify(type) + ',"challenge":' + JSON.stringify(b64(challenge)) + ',"origin":' + JSON.stringify(origin) +
      ',"crossOrigin":' + (cross ? "true" : "false");
    if (cross) s += ',"topOrigin":' + JSON.stringify(topOrigin);
    return s + "}";
  }

  // ------------------------------------------------- what the page asked

  // Refusal: why secretvault leaves a request to the browser.
  class Refusal extends Error {}

  function no(why) {
    throw new Refusal(why);
  }

  function text(v, max, what) {
    if (v === undefined || v === null) return "";
    if (typeof v !== "string") no(what + " is not text");
    // Truncated as an authenticator may (WebAuthn §6.4.1), at a character.
    let s = v.slice(0, 2 * max);
    s = (typeof s.toWellFormed === "function" ? s.toWellFormed() : s).replace(/[\u0000-\u001f\u007f�]/g, " ");
    let cps = Array.from(s).slice(0, max);
    const enc = new TextEncoder();
    while (enc.encode(cps.join("")).length > max) cps = cps.slice(0, -1);
    return cps.join("");
  }

  function challengeOf(pk) {
    const c = bytes(pk.challenge);
    if (!c || c.length < LIMITS.challengeMin || c.length > LIMITS.challengeMax) no("the challenge is missing or of a size secretvault does not take");
    return c;
  }

  function credentialIds(list, what) {
    if (list === undefined || list === null) return [];
    if (!Array.isArray(list)) no(what + " is not a list");
    if (list.length > LIMITS.credentialIds) no(what + " is too long");
    const out = [];
    let size = 0;
    for (const d of list) {
      if (!d || typeof d !== "object" || d.type !== "public-key") continue; // unknown types are skipped, as browsers do
      const id = bytes(d.id);
      if (!id || id.length === 0 || id.length > LIMITS.credentialId) no(what + " holds a bad credential ID");
      // All of them must fit in one request to secretvault (64 KiB).
      if ((size += id.length) > LIMITS.credentialIdsBytes) no(what + " is too large");
      out.push(b64(id));
    }
    return out;
  }

  function uvOf(v) {
    if (v === undefined || v === null || v === "") return "preferred";
    if (v === "required" || v === "preferred" || v === "discouraged") return v;
    return "preferred"; // unknown values are taken as the default
  }

  function rpIdOf(list, given, origin) {
    const host = root.SVOrigin.parseOrigin(origin);
    if (!host) no("not a page secretvault serves");
    const rpId = given === undefined || given === null ? host.host : normalRPID(given);
    if (!rpId || !rpIdFits(list, rpId, origin)) no("the rpId does not fit the page");
    return rpId;
  }

  // createRequest reads publicKey options of navigator.credentials.create
  // into the members of passkey-create (all but clientData), with the
  // challenge, or throws a Refusal.
  function createRequest(list, pk, origin) {
    if (!pk || typeof pk !== "object") no("no publicKey options");
    const rp = pk.rp && typeof pk.rp === "object" ? pk.rp : no("no rp");
    const user = pk.user && typeof pk.user === "object" ? pk.user : no("no user");
    const rpId = rpIdOf(list, rp.id, origin);
    const handle = bytes(user.id);
    if (!handle || handle.length < 1 || handle.length > LIMITS.userHandle) no("the user handle is missing or too long");
    const params = Array.isArray(pk.pubKeyCredParams) ? pk.pubKeyCredParams : no("no pubKeyCredParams");
    const algorithms = [];
    for (const p of params) {
      if (p && p.type === "public-key" && Number.isInteger(p.alg) && algorithms.length < LIMITS.algorithms) algorithms.push(p.alg);
    }
    if (params.length > 0 && !algorithms.some((a) => a === ES256 || a === EDDSA)) no("the site takes no key secretvault makes");
    const sel = pk.authenticatorSelection && typeof pk.authenticatorSelection === "object" ? pk.authenticatorSelection : {};
    if (sel.authenticatorAttachment === "cross-platform") no("the site asks for a security key or a phone");
    const req = {
      rpId,
      rpName: text(rp.name, LIMITS.rpName, "rp.name") || undefined,
      user: b64(handle),
      userName: text(user.name, LIMITS.userName, "user.name"),
      userDisplayName: text(user.displayName, LIMITS.userName, "user.displayName") || undefined,
      algorithms: algorithms.length > 0 ? algorithms : undefined,
      exclude: credentialIds(pk.excludeCredentials, "excludeCredentials"),
      uv: uvOf(sel.userVerification),
    };
    if (req.exclude.length === 0) req.exclude = undefined;
    const ext = pk.extensions && typeof pk.extensions === "object" ? pk.extensions : {};
    return { req, rpId, challenge: challengeOf(pk), credProps: ext.credProps === true, timeout: timeoutOf(pk.timeout) };
  }

  // getRequest reads publicKey options of navigator.credentials.get into
  // the members of passkeys and passkey-get, with the challenge.
  function getRequest(list, pk, origin) {
    if (!pk || typeof pk !== "object") no("no publicKey options");
    const rpId = rpIdOf(list, pk.rpId, origin);
    const allow = credentialIds(pk.allowCredentials, "allowCredentials");
    return { rpId, allow: allow.length > 0 ? allow : undefined, uv: uvOf(pk.userVerification), challenge: challengeOf(pk), timeout: timeoutOf(pk.timeout) };
  }

  // timeoutOf is how long to wait, in ms: the page's hint, between 30
  // seconds and 10 minutes, five minutes when it gives none.
  function timeoutOf(t) {
    if (typeof t !== "number" || !Number.isFinite(t) || t <= 0) return 5 * 60 * 1000;
    return Math.min(Math.max(t, 30 * 1000), 10 * 60 * 1000);
  }

  root.SVWebAuthn = Object.freeze({
    LIMITS, ES256, EDDSA, b64, unb64, bytes, plain, secureOrigin, normalRPID, rpIdFits, clientData, createRequest, getRequest, Refusal,
  });
})(globalThis);
