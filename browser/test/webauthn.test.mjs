import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { SVWebAuthn as W, SVProtocol as P, list, manifest } from "./load.mjs";

const vectors = JSON.parse(readFileSync(fileURLToPath(new URL("webauthn-vectors.json", import.meta.url)), "utf8"));

function hex(s) {
  return Uint8Array.from(s.match(/../g).map((h) => parseInt(h, 16)));
}

test("an rpId fits an origin by WebAuthn's rules, as secretvault's (the same cases)", () => {
  for (const c of vectors.rpId) {
    assert.equal(W.rpIdFits(list, c.rpId, c.origin), c.ok, `${c.origin} with ${JSON.stringify(c.rpId)} (${c.why || ""})`);
  }
});

test("clientDataJSON is built from the browser's origin, byte for byte as secretvault reads it", () => {
  for (const c of vectors.clientData) {
    assert.equal(W.clientData(c.type, hex(c.challenge), c.origin, c.topOrigin), c.json);
  }
});

test("base64url goes both ways, and refuses what is not", () => {
  for (let n = 0; n < 70; n++) {
    const b = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 0xff);
    assert.deepEqual(W.unb64(W.b64(b)), b, "length " + n);
    assert.equal(W.b64(b), Buffer.from(b).toString("base64url"));
  }
  for (const bad of ["a", "ab=", "a+b", "a/b", "AB==", 7, null]) assert.equal(W.unb64(bad), null, String(bad));
  assert.equal(W.unb64("AB"), null, "non-zero padding bits");
});

test("an rpId is read as browsers write hosts", () => {
  assert.equal(W.normalRPID("Example.COM"), "example.com");
  assert.equal(W.normalRPID("bücher.example"), "xn--bcher-kva.example");
  for (const bad of ["", "a b", "example.com/x", "example.com:443", "1.2.3.4", "[::1]", "example.com.", null, 5]) {
    assert.equal(W.normalRPID(bad), null, String(bad));
  }
  assert.equal(W.secureOrigin("http://localhost:8080"), true);
  assert.equal(W.secureOrigin("http://example.com"), false);
  assert.equal(W.secureOrigin("https://127.0.0.1"), false);
});

const challenge = new Uint8Array(32).fill(7);

function createOptions(extra) {
  return Object.assign({
    challenge,
    rp: { id: "example.com", name: "Example" },
    user: { id: new TextEncoder().encode("user-1"), name: "ada@example.com", displayName: "Ada" },
    pubKeyCredParams: [{ type: "public-key", alg: -257 }, { type: "public-key", alg: -7 }],
    excludeCredentials: [{ type: "public-key", id: new Uint8Array([1, 2, 3]) }],
    authenticatorSelection: { userVerification: "required", residentKey: "required" },
    extensions: { credProps: true },
  }, extra);
}

test("create's options are read into passkey-create's members", () => {
  const { req, challenge: c, credProps } = W.createRequest(list, W.plain(createOptions()), "https://login.example.com");
  assert.deepEqual(req, {
    rpId: "example.com", rpName: "Example", user: W.b64(new TextEncoder().encode("user-1")), userName: "ada@example.com",
    userDisplayName: "Ada", algorithms: [-257, -7], exclude: ["AQID"], uv: "required",
  });
  assert.deepEqual(c, challenge);
  assert.equal(credProps, true);
  // As the protocol builds it.
  const m = P.request("r1", "passkey-create", Object.assign({}, req, { origin: "https://login.example.com", clientData: W.b64(new Uint8Array(40)) }));
  assert.equal(m.op, "passkey-create");
  // No rpId: the origin's host.
  assert.equal(W.createRequest(list, W.plain(createOptions({ rp: { name: "x" } })), "https://login.example.com").req.rpId, "login.example.com");
});

test("what secretvault does not take is left to the browser", () => {
  const origin = "https://login.example.com";
  const refused = [
    createOptions({ rp: { id: "evil.com" } }),
    createOptions({ rp: { id: "com" } }),
    createOptions({ challenge: new Uint8Array(8) }),
    createOptions({ user: { id: new Uint8Array(65), name: "x" } }),
    createOptions({ user: { name: "x" } }),
    createOptions({ pubKeyCredParams: [{ type: "public-key", alg: -257 }] }),
    createOptions({ authenticatorSelection: { authenticatorAttachment: "cross-platform" } }),
    createOptions({ excludeCredentials: "nope" }),
    null,
  ];
  for (const o of refused) assert.throws(() => W.createRequest(list, W.plain(o), origin), W.Refusal, JSON.stringify(W.plain(o)));
  assert.throws(() => W.createRequest(list, W.plain(createOptions()), "http://login.example.com"), W.Refusal, "not secure");
  assert.throws(() => W.getRequest(list, W.plain({ challenge, rpId: "example.com" }), "https://example.org"), W.Refusal);
  // More credential IDs than fit in one request to secretvault: the browser's.
  const many = Array.from({ length: 20 }, () => ({ type: "public-key", id: new Uint8Array(1023) }));
  assert.throws(() => W.getRequest(list, { challenge: { $bytes: W.b64(challenge) }, rpId: "example.com",
    allowCredentials: many.map((d) => ({ type: d.type, id: { $bytes: W.b64(d.id) } })) }, origin), W.Refusal);
});

test("get's options are read into passkeys' and passkey-get's members", () => {
  const g = W.getRequest(list, W.plain({ challenge, rpId: "example.com", allowCredentials: [{ type: "public-key", id: new Uint8Array([9]) }, { type: "other", id: 1 }] }),
    "https://www.example.com");
  assert.equal(g.rpId, "example.com");
  assert.deepEqual(g.allow, ["CQ"]);
  assert.equal(g.uv, "preferred");
  assert.ok(P.request("r2", "passkeys", { origin: "https://www.example.com", rpId: g.rpId, allow: g.allow }));
  assert.throws(() => P.request("r3", "passkey-get", { origin: "https://www.example.com", rpId: "Example.com", login: "0".repeat(32), clientData: "AA" }), P.ProtocolError);
});

test("what a page passes is copied into a bounded, plain form", () => {
  const p = W.plain({ a: new Uint8Array([1, 2]), b: [1, "x", null, () => 1], c: { d: new DataView(new ArrayBuffer(2)) }, f: () => 1 });
  assert.deepEqual(p, { a: { $bytes: "AQI" }, b: [1, "x", null, undefined], c: { d: { $bytes: "AAA" } } });
  assert.deepEqual(W.bytes(p.a), new Uint8Array([1, 2]));
  assert.equal(W.plain({ big: new Uint8Array(20000) }), null);
  let deep = {};
  for (let i = 0; i < 10; i++) deep = { deep };
  assert.equal(W.plain(deep), null);
  assert.equal(W.plain(Array(300).fill(1)), null);
  // Names are cut to the protocol's lengths, at a character, and cleaned.
  const long = W.createRequest(list, W.plain(createOptions({ user: { id: new Uint8Array([1]), name: "é".repeat(300) + "\n", displayName: "a\u0000b" } })), "https://example.com");
  assert.equal(new TextEncoder().encode(long.req.userName).length, 256);
  assert.equal(long.req.userDisplayName, "a b");
});

test("the manifest runs the passkey scripts at document_start, the page's part in its own world", () => {
  const m = manifest();
  const bridge = m.content_scripts.find((c) => c.js.includes("passkey-bridge.js"));
  const page = m.content_scripts.find((c) => c.js.includes("passkey-page.js"));
  assert.equal(bridge.run_at, "document_start");
  assert.equal(bridge.world, undefined, "the bridge is in the extension's isolated world");
  assert.deepEqual(page.js, ["passkey-page.js"], "nothing of the extension's but that script in the page's world");
  assert.equal(page.world, "MAIN");
  assert.equal(page.run_at, "document_start");
  assert.ok(!m.web_accessible_resources[0].resources.includes("passkey.html"), "the passkey window is not for pages to load");
});
