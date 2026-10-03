import { test } from "node:test";
import assert from "node:assert/strict";
import { SVProtocol as P, manifest } from "./load.mjs";

const origin = "https://github.com";
const login = "0123456789abcdef0123456789abcdef";

test("requests are built as the host checks them", () => {
  assert.deepEqual(P.request("r1", "logins", { vault: "", origin }), { v: 1, id: "r1", op: "logins", vault: "", origin });
  assert.deepEqual(P.request("r2", "fill", { origin, login, vault: undefined }), { v: 1, id: "r2", op: "fill", origin, login });
  assert.deepEqual(P.request("r3", "save", { origin, username: "ada", password: "pä$$ 😀", title: "GitHub" }).password, "pä$$ 😀");
  assert.deepEqual(P.request("r4", "generate", { length: 24, symbols: true }), { v: 1, id: "r4", op: "generate", length: 24, symbols: true });
  assert.deepEqual(P.request("r5", "state"), { v: 1, id: "r5", op: "state" });
});

test("requests the host would refuse are not sent", () => {
  const bad = [
    ["r", "dump", {}, "unknown-op"],
    ["a b", "state", {}, "bad-request"],
    ["r", "state", { origin }, "bad-request"],
    ["r", "logins", {}, "bad-request"],
    ["r", "logins", { origin: "https://github.com/login" }, "bad-request"],
    ["r", "logins", { origin: "file:///" }, "bad-request"],
    ["r", "fill", { origin, login: "../x" }, "bad-request"],
    ["r", "fill", { origin, login: login.toUpperCase() }, "bad-request"],
    ["r", "save", { origin }, "bad-request"],
    ["r", "save", { origin, password: "" }, "bad-request"],
    ["r", "save", { origin, password: "x".repeat(4097) }, "bad-request"],
    ["r", "save", { origin, password: "é".repeat(2049) }, "bad-request"],
    ["r", "save", { origin, password: "\ud800" }, "bad-request"],
    ["r", "save", { origin, password: "x", username: "a\u0000b" }, "bad-request"],
    ["r", "save", { origin, password: "x", username: "u".repeat(1025) }, "bad-request"],
    ["r", "save", { origin, password: "x", title: "a\nb" }, "bad-request"],
    ["r", "generate", { length: 4 }, "bad-request"],
    ["r", "generate", { length: 24.5 }, "bad-request"],
    ["r", "generate", { symbols: "yes" }, "bad-request"],
  ];
  for (const [id, op, params, code] of bad) {
    assert.throws(() => P.request(id, op, params), (e) => e instanceof P.ProtocolError && e.code === code, op + " " + JSON.stringify(params));
  }
});

test("answers and events are checked before they are read", () => {
  assert.equal(P.reply(null), null);
  assert.equal(P.reply([1]), null);
  assert.equal(P.reply({ id: "r1", ok: true }), null, "no version");
  assert.equal(P.reply({ v: 2, id: "r1", ok: true }), null, "another version");
  assert.equal(P.reply({ v: 1, id: 7, ok: true }), null);
  assert.equal(P.reply({ v: 1, event: "surprise" }), null);
  assert.deepEqual(P.reply({ v: 1, event: "vault", vault: "personal", locked: true }), { kind: "event", event: "vault", vault: "personal", locked: true });
  assert.equal(P.reply({ v: 1, event: "down", error: "not-running", message: "gone" }).event, "down");
  const refused = P.reply({ v: 1, id: "r1", ok: false, error: "denied", message: "no" });
  assert.equal(refused.ok, false);
  assert.equal(refused.error, "denied");
  assert.equal(P.reply({ v: 1, id: "r1", ok: true, logins: [] }).kind, "answer");
});

test("only well-formed logins and vaults are kept", () => {
  const good = { id: login, title: "GitHub", username: "ada", url: "https://github.com", match: "host", totp: true };
  const got = P.logins([good, { ...good, id: "x" }, { ...good, match: "anything" }, null, "x", { ...good, password: "leak" }]);
  assert.equal(got.length, 2);
  assert.ok(!("password" in got[1]), "a member the protocol does not have is dropped");
  assert.deepEqual(P.logins("nope"), []);
  assert.deepEqual(P.vaults([{ name: "a", locked: false, default: true }, { name: 1 }]), [{ name: "a", locked: false, default: true }]);
});

test("the manifest names the host and asks for little", () => {
  const m = manifest();
  assert.equal(m.manifest_version, 3);
  assert.equal(P.HOST, "io.github.codemodify.secretvault");
  assert.deepEqual(m.permissions.sort(), ["nativeMessaging", "storage"]);
  assert.match(m.content_security_policy.extension_pages, /script-src 'self';/);
  assert.doesNotMatch(m.content_security_policy.extension_pages, /unsafe|https?:|\*/);
  assert.deepEqual(m.web_accessible_resources[0].resources, ["panel.html"]);
  for (const cs of m.content_scripts) assert.deepEqual(cs.matches, ["http://*/*", "https://*/*"]);
});
