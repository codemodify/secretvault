// secretvault's passkeys, in the page's own world (a content script of
// world MAIN, at document_start, before any script of the page's). It
// wraps navigator.credentials.create and get: a request for a public key
// credential goes to the extension (passkey-bridge.js, over a
// MessageChannel), which offers secretvault's passkeys in a window of its
// own, or offers to save a new one there, or leaves the request to the
// browser: then the browser's own create or get is called, with the
// page's own arguments, and the person may use the computer's own
// authenticator, a security key or a phone, as without secretvault.
//
// This script is in the page's world, so it holds nothing the page could
// not have: what it sends is what the page asked; what it gets back is a
// credential for the page. It decides nothing. The origin, the rpId's
// check, clientDataJSON, the person's choice and the signature are all
// made where the page cannot reach (the background, secretvault's window,
// and secretvault itself). It keeps the functions it relies on as they
// were before the page could change them, and talks to nothing but its
// channel.
(function () {
  "use strict";

  const W = globalThis;
  const CC = W.CredentialsContainer;
  if (typeof CC !== "function" || !CC.prototype || typeof CC.prototype.get !== "function" || !W.MessageChannel) return;

  // What this script uses, as it is before the page runs.
  const fcall = Function.prototype.call;
  const uncurry = (f) => fcall.bind(f);
  const nativeCreate = uncurry(CC.prototype.create);
  const nativeGet = uncurry(CC.prototype.get);
  const defineProperty = Object.defineProperty;
  const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  const objectCreate = Object.create;
  const freeze = Object.freeze;
  const assign = Object.assign;
  const Promise_ = W.Promise;
  const rejected = Promise_.reject.bind(Promise_);
  const then = uncurry(Promise_.prototype.then);
  const addListener = uncurry(W.EventTarget.prototype.addEventListener);
  const removeListener = uncurry(W.EventTarget.prototype.removeEventListener);
  const dispatch = uncurry(W.EventTarget.prototype.dispatchEvent);
  const postMessage = uncurry(W.MessagePort.prototype.postMessage);
  const startPort = uncurry(W.MessagePort.prototype.start);
  const MessageEvent_ = W.MessageEvent;
  const Event_ = W.Event;
  const DOMException_ = W.DOMException;
  const Uint8Array_ = W.Uint8Array;
  const ArrayBuffer_ = W.ArrayBuffer;
  const AbortController_ = W.AbortController;
  const abort = uncurry(W.AbortController.prototype.abort);
  const signalOf = uncurry(getOwnPropertyDescriptor(W.AbortController.prototype, "signal").get);
  const aborted = uncurry(getOwnPropertyDescriptor(W.AbortSignal.prototype, "aborted").get);
  const reasonDesc = getOwnPropertyDescriptor(W.AbortSignal.prototype, "reason");
  const reasonOf = reasonDesc ? uncurry(reasonDesc.get) : () => undefined;
  const hasFocus = uncurry(W.Document.prototype.hasFocus);
  const doc = W.document;
  const setTimeout_ = W.setTimeout;
  const random = W.Math.random;
  const toString36 = uncurry(W.Number.prototype.toString);
  const PKC = W.PublicKeyCredential;
  const AttResp = W.AuthenticatorAttestationResponse;
  const AssResp = W.AuthenticatorAssertionResponse;
  const ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const indexOf = uncurry(String.prototype.indexOf);
  const charAt = uncurry(String.prototype.charAt);

  const PORT = "secretvault-passkey-port";
  const ASK = "secretvault-passkey-ask";

  // ------------------------------------------------- the channel

  const ch = new W.MessageChannel();
  const port = ch.port1;
  const waiting = new W.Map(); // id -> {done, heard}
  const mapGet = uncurry(W.Map.prototype.get);
  const mapSet = uncurry(W.Map.prototype.set);
  const mapDelete = uncurry(W.Map.prototype.delete);
  let ready = false; // the extension's world has the other end, and said so

  addListener(port, "message", (e) => {
    const m = e.data;
    if (!m || typeof m !== "object" || typeof m.id !== "string") return;
    if (m.op === "ready" && m.id === "") {
      ready = true;
      removeListener(W, ASK, give, true);
      return;
    }
    const w = mapGet(waiting, m.id);
    if (!w) return;
    if (m.ack === true) {
      w.heard++;
      w.fresh = true;
      return;
    }
    mapDelete(waiting, m.id);
    w.done(m);
  });
  startPort(port);

  // give hands the other end over, to the extension's world if it is
  // listening (it takes it once); until it says it has, it may ask again.
  // (The event does not transfer the port: a page script that asked before
  // the extension's world said so could take it too, and then only answer
  // its own requests, which it could make of the browser anyway.)
  function give() {
    if (ready) return;
    dispatch(W, new MessageEvent_(PORT, { ports: [ch.port2] }));
  }
  addListener(W, ASK, give, true);
  give();

  let seq = 0;

  // ask sends a request to the extension and waits for its answer:
  // {kind: "fallback"}, {kind: "error", name, message} or {kind: "credential", ...}.
  function ask(op, options, signal) {
    const id = toString36(++seq, 36) + toString36((random() * 1e9) | 0, 36);
    return new Promise_((resolve) => {
      if (!ready) return resolve({ kind: "fallback" }); // the extension is not here: the browser's
      const w = { done: resolve, heard: 0 };
      mapSet(waiting, id, w);
      // Is the extension's world still there? It says it has the request
      // at once, and again whenever asked, which this does every fifteen
      // seconds. A request not heard of within a second of being sent, or
      // by the next look after being asked about (the extension went away,
      // say), is the browser's. Messages are not slowed in a tab in the
      // background, as timers are, so an answer always comes before the
      // timer that looks for it.
      const watch = (ms) => {
        setTimeout_(() => {
          if (mapGet(waiting, id) !== w) return;
          if (w.fresh) {
            w.fresh = false;
            try {
              postMessage(port, { id, op: "ping" });
            } catch {
              // Gone: found so below.
            }
            return watch(w.heard > 0 ? 15000 : 1000);
          }
          mapDelete(waiting, id);
          resolve({ kind: "fallback" });
        }, ms);
      };
      watch(1000);
      try {
        postMessage(port, { id, op, publicKey: options.publicKey, mediation: options.mediation });
      } catch {
        // Not something the channel can carry: the browser's to handle.
        mapDelete(waiting, id);
        resolve({ kind: "fallback" });
        return;
      }
      if (signal) {
        addListener(signal, "abort", () => {
          if (mapGet(waiting, id)) {
            mapDelete(waiting, id);
            try {
              postMessage(port, { id, op: "abort" });
            } catch {
              // Gone.
            }
            resolve({ kind: "aborted" });
          }
        });
      }
    });
  }

  // ------------------------------------------------- answers as objects

  function buffer(s) {
    if (typeof s !== "string") return new ArrayBuffer_(0);
    const out = new Uint8Array_(((s.length * 3) / 4) | 0);
    let bits = 0;
    let acc = 0;
    let j = 0;
    for (let i = 0; i < s.length; i++) {
      acc = (acc << 6) | indexOf(ALPHA, charAt(s, i));
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        out[j++] = (acc >> bits) & 0xff;
      }
    }
    return out.buffer.slice(0, j);
  }

  function value(o, k, v) {
    defineProperty(o, k, { value: v, enumerable: true, configurable: false, writable: false });
  }

  function method(o, k, f) {
    defineProperty(o, k, { value: f, enumerable: false, configurable: false, writable: false });
  }

  // credential makes the PublicKeyCredential the page gets: an object of
  // the browser's own prototypes, with its values as own properties.
  function credential(r) {
    const create_ = r.type === "create";
    const resp = objectCreate(create_ ? (AttResp ? AttResp.prototype : null) : (AssResp ? AssResp.prototype : null));
    value(resp, "clientDataJSON", buffer(r.clientDataJSON));
    const json = { clientDataJSON: r.clientDataJSON };
    if (create_) {
      value(resp, "attestationObject", buffer(r.attestationObject));
      method(resp, "getTransports", () => ["internal"]);
      method(resp, "getAuthenticatorData", () => buffer(r.authenticatorData));
      method(resp, "getPublicKey", () => buffer(r.publicKey));
      method(resp, "getPublicKeyAlgorithm", () => r.algorithm);
      assign(json, { attestationObject: r.attestationObject, authenticatorData: r.authenticatorData, transports: ["internal"],
        publicKey: r.publicKey, publicKeyAlgorithm: r.algorithm });
    } else {
      value(resp, "authenticatorData", buffer(r.authenticatorData));
      value(resp, "signature", buffer(r.signature));
      value(resp, "userHandle", r.userHandle ? buffer(r.userHandle) : null);
      assign(json, { authenticatorData: r.authenticatorData, signature: r.signature, userHandle: r.userHandle || undefined });
    }
    freeze(json);
    const c = objectCreate(PKC ? PKC.prototype : null);
    const ext = r.credProps ? { credProps: { rk: true } } : {};
    value(c, "id", r.credentialId);
    value(c, "rawId", buffer(r.credentialId));
    value(c, "type", "public-key");
    value(c, "authenticatorAttachment", "platform");
    value(c, "response", resp);
    method(c, "getClientExtensionResults", () => assign({}, ext));
    method(c, "toJSON", () => ({ id: r.credentialId, rawId: r.credentialId, type: "public-key", authenticatorAttachment: "platform",
      clientExtensionResults: assign({}, ext), response: assign({}, json) }));
    return c;
  }

  function failure(r) {
    const names = ["NotAllowedError", "InvalidStateError", "SecurityError", "AbortError", "NotSupportedError"];
    let name = "NotAllowedError";
    for (let i = 0; i < names.length; i++) if (names[i] === r.name) name = r.name;
    return new DOMException_(typeof r.message === "string" ? r.message : "The operation was not allowed.", name);
  }

  // focused waits, a little, for the page to have the focus again (after
  // secretvault's window closed): browsers refuse WebAuthn to a page
  // without it.
  function focused() {
    return new Promise_((resolve) => {
      if (hasFocus(doc)) return resolve();
      const done = () => {
        removeListener(W, "focus", done, true);
        resolve();
      };
      addListener(W, "focus", done, true);
      setTimeout_(done, 3000);
    });
  }

  function abortError(signal) {
    const reason = reasonOf(signal);
    return reason !== undefined ? reason : new DOMException_("The operation was aborted.", "AbortError");
  }

  // ------------------------------------------------- the wrappers

  async function run(op, self, options, native) {
    const signal = options.signal || null;
    if (signal && aborted(signal)) throw abortError(signal);
    const r = await ask(op, options, signal);
    switch (r.kind) {
      case "credential":
        return credential(r);
      case "error":
        throw failure(r);
      case "aborted":
        throw abortError(signal);
    }
    await focused();
    return native(self, options);
  }

  // conditional is get with mediation "conditional" (autofill): the
  // browser's own offer and secretvault's (in its panel, when the person
  // opens it) wait together; the first the person takes wins, and the
  // other is called off.
  function conditional(self, options) {
    const signal = options.signal || null;
    if (signal && aborted(signal)) return rejected(abortError(signal));
    const ac = new AbortController_();
    const mine = signalOf(ac);
    if (signal) addListener(signal, "abort", () => abort(ac, reasonOf(signal)));
    const own = assign({}, options);
    own.signal = mine;
    return new Promise_((resolve, reject) => {
      let settled = false;
      let ours = true;
      let nativeFailed = null;
      const sv = ask("get", options, mine);
      then(nativeGet(self, own), (v) => {
        if (settled) return;
        settled = true;
        abort(ac); // calls ours off
        resolve(v);
      }, (e) => {
        if (settled) return;
        if (signal && aborted(signal)) {
          settled = true;
          return reject(abortError(signal));
        }
        if (!ours) {
          settled = true;
          return reject(e);
        }
        nativeFailed = e;
      });
      then(sv, (r) => {
        if (settled) return;
        if (r.kind === "credential") {
          settled = true;
          abort(ac); // calls the browser's off
          return resolve(credential(r));
        }
        if (r.kind === "error") {
          settled = true;
          abort(ac);
          return reject(failure(r));
        }
        ours = false;
        if (nativeFailed) {
          settled = true;
          reject(nativeFailed);
        }
      });
    });
  }

  function wrap(name, fn) {
    // The wrapper keeps the name and length of the browser's function.
    defineProperty(fn, "name", { value: name });
    defineProperty(fn, "length", { value: 0 });
    defineProperty(CC.prototype, name, { value: fn, writable: true, enumerable: true, configurable: true });
  }

  wrap("create", function create(options) {
    if (!options || typeof options !== "object" || !options.publicKey) return nativeCreate(this, options);
    return run("create", this, options, nativeCreate);
  });

  wrap("get", function get(options) {
    if (!options || typeof options !== "object" || !options.publicKey) return nativeGet(this, options);
    if (options.mediation === "conditional") return conditional(this, options);
    return run("get", this, options, nativeGet);
  });
})();
