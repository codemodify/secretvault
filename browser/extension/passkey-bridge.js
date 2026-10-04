// The extension's side of passkeys in a page, in the content script's own
// world, which the page cannot reach. passkey-page.js, in the page's own
// world, wraps navigator.credentials.create and get, and hands what the
// page asked over a MessageChannel the two set up before any script of
// the page's runs (below). This passes it to the background, with what
// only this world can tell truly:
//
//   - whether the person is acting on the page now (user activation, which
//     a page script cannot fake), without which secretvault does not step
//     in: the browser handles the request;
//   - whether the frame's permissions policy allows WebAuthn (Chromium's
//     document.featurePolicy, seen from this world, which the page cannot
//     redefine), and whether the frame is same-origin with all its
//     ancestors.
//
// The page's origin is the browser's: the background takes it from the
// sender's URL, and refuses a document whose own origin (seen from this
// world: opaque in a sandboxed document) or secure context say otherwise.
// Nothing secret passes here: the answers are
// a public key credential the page gets anyway.
(function () {
  "use strict";

  const ext = globalThis.browser ?? globalThis.chrome;
  const W = globalThis.SVWebAuthn;
  if (!ext || !ext.runtime || !W) return;

  // This document's id, which the extension's content scripts in this
  // frame share (content.js says it with frame:hello), and the page
  // cannot see: so the background tells this page's requests from an
  // older page's.
  if (typeof globalThis.SVDocument !== "string") {
    const b = new Uint8Array(16);
    crypto.getRandomValues(b);
    globalThis.SVDocument = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  }
  const DOC = globalThis.SVDocument;

  const PORT = "secretvault-passkey-port";
  const ASK = "secretvault-passkey-ask";

  let port = null;
  const live = new Map(); // the page's request id -> true while it waits

  function policy(feature) {
    try {
      const p = document.permissionsPolicy || document.featurePolicy;
      if (p && typeof p.allowsFeature === "function") return p.allowsFeature(feature) === true;
    } catch {
      // Not to be known.
    }
    return null; // Firefox: not known, so a frame of another origin is left to the browser
  }

  // sameOriginWithAncestors: every frame up to the top is this frame's
  // origin (WebAuthn §5.1.3: otherwise clientData says crossOrigin).
  function sameOriginWithAncestors() {
    try {
      for (let w = window; w !== w.parent; w = w.parent) {
        if (w.parent.location.origin !== location.origin) return false;
      }
      return true;
    } catch {
      return false; // a frame of another origin above this one
    }
  }

  function post(m) {
    try {
      port.postMessage(m);
    } catch {
      // The page went away.
    }
  }

  function answer(id, r) {
    if (!port || !live.has(id)) return;
    live.delete(id);
    post(Object.assign({ id }, r));
  }

  async function ask(m) {
    const id = m.id;
    const get = m.op === "get";
    const conditional = get && m.mediation === "conditional";
    const options = W.plain(m.publicKey);
    if (!options) return answer(id, { kind: "fallback" });
    const msg = {
      type: get ? "passkey:get" : "passkey:create",
      id,
      doc: DOC,
      publicKey: options,
      conditional,
      activation: !!(navigator.userActivation && navigator.userActivation.isActive),
      policy: policy(get ? "publickey-credentials-get" : "publickey-credentials-create"),
      sameOrigin: sameOriginWithAncestors(),
      // This document's own origin and secure context, as the browser has
      // them: a sandboxed document's origin is opaque ("null") whatever
      // its URL says.
      origin: typeof self.origin === "string" ? self.origin : "",
      secure: self.isSecureContext === true,
    };
    // A conditional request waits for the person to choose in the panel,
    // which may be long; if the background was stopped meanwhile, it is
    // offered again.
    for (let tries = 0; tries < (conditional ? 20 : 1); tries++) {
      let r;
      try {
        r = await ext.runtime.sendMessage(msg);
      } catch {
        r = null;
      }
      if (!live.has(id)) return;
      if (r && r.ok && r.result && typeof r.result.kind === "string") return answer(id, r.result);
      if (!conditional) break;
      await new Promise((res) => setTimeout(res, 1000));
    }
    answer(id, { kind: "fallback" });
  }

  function onMessage(e) {
    const m = e.data;
    if (!m || typeof m !== "object" || typeof m.id !== "string" || !/^[0-9a-z]{1,40}$/.test(m.id)) return;
    if (m.op === "abort") {
      if (live.delete(m.id)) ext.runtime.sendMessage({ type: "passkey:abort", id: m.id }).catch(() => {});
      return;
    }
    if (m.op === "ping") {
      post(live.has(m.id) ? { id: m.id, ack: true } : { id: m.id, kind: "fallback" });
      return;
    }
    if (m.op !== "create" && m.op !== "get") return;
    if (live.has(m.id) || live.size >= 4) {
      post({ id: m.id, kind: "fallback" }); // too many at once: the browser's
      return;
    }
    // Heard: the page's world waits for the answer, and asks now and then
    // whether this still has it (below).
    live.set(m.id, true);
    post({ id: m.id, ack: true });
    ask(m);
  }

  // The handshake: the page's world makes the channel and hands one end
  // over in a synchronous event, while no script of the page's has run
  // (both scripts run at document_start). Whichever of the two runs first,
  // the other completes it: the page's world hands its end over when it
  // runs, and again when this asks; this takes one end once, and says so
  // over it. Until it has heard that, the page's world leaves every
  // request to the browser.
  function take(e) {
    if (port || !e.ports || e.ports.length !== 1) return;
    port = e.ports[0];
    removeEventListener(PORT, take, true);
    port.onmessage = onMessage;
    post({ id: "", op: "ready" });
  }
  addEventListener(PORT, take, true);
  dispatchEvent(new Event(ASK));
})();
