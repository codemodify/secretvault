// The protocol with secretvault's native-messaging host, version 1
// (docs/browser.md; svext/protocol.go is the other side). Requests are
// built here, and checked as the host will check them, so a request that
// would be refused is not sent; answers and events are checked before
// anything reads them.
//
//   request  {v: 1, id: "r7", op: "logins", vault: "", origin: "https://github.com"}
//   answer   {v: 1, id: "r7", ok: true, logins: [...]}
//   refusal  {v: 1, id: "r7", ok: false, error: "locked", message: "..."}
//   event    {v: 1, event: "vault", vault: "personal", locked: true}
(function (root) {
  "use strict";

  const VERSION = 1;
  const HOST = "io.github.codemodify.secretvault";

  const LIMITS = Object.freeze({
    request: 64 * 1024,
    id: 64,
    origin: 1024,
    vault: 256,
    username: 1024,
    password: 4096, // bytes, as UTF-8
    title: 256,
    extension: 64,
    generateMin: 8,
    generateMax: 128,
  });

  // The members each operation takes (true: required).
  const OPS = Object.freeze({
    hello: { extension: false },
    state: {},
    unlock: { vault: false },
    lock: { vault: false },
    logins: { vault: false, origin: true },
    fill: { vault: false, origin: true, login: true, confirm: false },
    totp: { vault: false, origin: true, login: true, confirm: false },
    check: { vault: false, origin: true, username: false, password: true },
    save: { vault: false, origin: true, username: false, password: true, login: false, title: false },
    generate: { length: false, symbols: false },
  });

  const encoder = new TextEncoder();

  function bytes(s) {
    return encoder.encode(s).length;
  }

  // text: a string people read, of at most max bytes, with no control
  // characters.
  function text(v, max) {
    return typeof v === "string" && bytes(v) <= max && !/[\u0000-\u001f\u007f�]/.test(v);
  }

  const CHECKS = {
    extension: (v) => text(v, LIMITS.extension),
    vault: (v) => text(v, LIMITS.vault),
    origin: (v) => root.SVOrigin.parseOrigin(v) !== null,
    login: (v) => typeof v === "string" && /^[0-9a-f]{32}$/.test(v),
    username: (v) => text(v, LIMITS.username),
    // Lone surrogates would not survive UTF-8, and U+FFFD is what they
    // would become: the host refuses both.
    password: (v) => typeof v === "string" && v.length > 0 && v.isWellFormed() && !v.includes("�") && bytes(v) <= LIMITS.password,
    title: (v) => text(v, LIMITS.title),
    length: (v) => Number.isInteger(v) && v >= LIMITS.generateMin && v <= LIMITS.generateMax,
    symbols: (v) => typeof v === "boolean",
    confirm: (v) => typeof v === "boolean",
  };

  class ProtocolError extends Error {
    constructor(code, message) {
      super(message);
      this.code = code;
    }
  }

  // request builds a request, or throws a ProtocolError("bad-request")
  // saying what is wrong with it. Members that are undefined are left out.
  function request(id, op, params) {
    const allowed = OPS[op];
    if (!allowed) throw new ProtocolError("unknown-op", "no operation " + op);
    if (typeof id !== "string" || !/^[A-Za-z0-9._-]{1,64}$/.test(id)) throw new ProtocolError("bad-request", "a bad id");
    const msg = { v: VERSION, id, op };
    for (const [k, v] of Object.entries(params || {})) {
      if (v === undefined) continue;
      if (!(k in allowed)) throw new ProtocolError("bad-request", op + " takes no " + k);
      if (!CHECKS[k](v)) throw new ProtocolError("bad-request", op + ": a bad " + k);
      msg[k] = v;
    }
    for (const [k, required] of Object.entries(allowed)) {
      if (required && !(k in msg)) throw new ProtocolError("bad-request", op + " needs " + k);
    }
    if (bytes(JSON.stringify(msg)) > LIMITS.request) throw new ProtocolError("too-large", "the request is too large");
    return msg;
  }

  // reply checks a message from the host: an answer {kind: "answer", id,
  // ok, ...}, an event {kind: "event", ...}, or null for anything else.
  function reply(m) {
    if (m === null || typeof m !== "object" || Array.isArray(m) || m.v !== VERSION) return null;
    if (typeof m.event === "string") {
      if (m.event === "vault" && typeof m.vault === "string" && typeof m.locked === "boolean") {
        return { kind: "event", event: "vault", vault: m.vault, locked: m.locked };
      }
      if (m.event === "down") {
        return { kind: "event", event: "down", error: String(m.error || "not-running"), message: String(m.message || "") };
      }
      return null;
    }
    if (typeof m.id !== "string" || typeof m.ok !== "boolean") return null;
    if (!m.ok) {
      return { kind: "answer", id: m.id, ok: false, error: String(m.error || "failed"), message: String(m.message || "") };
    }
    return Object.assign({}, m, { kind: "answer" });
  }

  // logins checks the logins of an answer, keeping only well-formed ones.
  function logins(list) {
    if (!Array.isArray(list)) return [];
    return list
      .filter(
        (l) =>
          l &&
          typeof l === "object" &&
          CHECKS.login(l.id) &&
          typeof l.title === "string" &&
          typeof l.username === "string" &&
          typeof l.url === "string" &&
          (l.match === "host" || l.match === "site"),
      )
      .map((l) => ({ id: l.id, title: l.title, username: l.username, url: l.url, match: l.match, totp: l.totp === true }));
  }

  // vaults checks the vaults of an answer.
  function vaults(list) {
    if (!Array.isArray(list)) return [];
    return list
      .filter((v) => v && typeof v.name === "string" && typeof v.locked === "boolean")
      .map((v) => ({ name: v.name, locked: v.locked, default: v.default === true }));
  }

  root.SVProtocol = Object.freeze({ VERSION, HOST, LIMITS, OPS, ProtocolError, request, reply, logins, vaults });
})(globalThis);
