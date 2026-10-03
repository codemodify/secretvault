import { test } from "node:test";
import assert from "node:assert/strict";
import { SVPSL, SVOrigin, list } from "./load.mjs";

test("the bundled Public Suffix List is read", () => {
  assert.ok(SVPSL.size(list) > 5000, "rules: " + SVPSL.size(list));
});

test("registrable domains are the list's", () => {
  // The list's own test vectors, and its private section, as svext's Go
  // tests check them.
  const cases = {
    com: "",
    "example.com": "example.com",
    "b.example.com": "example.com",
    "uk.com": "",
    "example.uk.com": "example.uk.com",
    "test.ac": "test.ac",
    jp: "",
    "www.test.jp": "test.jp",
    "ac.jp": "",
    "test.ac.jp": "test.ac.jp",
    "kyoto.jp": "",
    "ide.kyoto.jp": "",
    "b.ide.kyoto.jp": "b.ide.kyoto.jp",
    "c.kobe.jp": "",
    "b.c.kobe.jp": "b.c.kobe.jp",
    "city.kobe.jp": "city.kobe.jp",
    "www.city.kobe.jp": "city.kobe.jp",
    ck: "",
    "test.ck": "",
    "b.test.ck": "b.test.ck",
    "www.ck": "www.ck",
    "www.www.ck": "www.ck",
    "k12.ak.us": "",
    "test.k12.ak.us": "test.k12.ak.us",
    "xn--85x722f.com.cn": "xn--85x722f.com.cn",
    "xn--55qx5d.cn": "",
    "www.xn--85x722f.xn--55qx5d.cn": "xn--85x722f.xn--55qx5d.cn",
    "co.uk": "",
    "www.example.co.uk": "example.co.uk",
    "github.io": "",
    "alice.github.io": "alice.github.io",
    "www.alice.github.io": "alice.github.io",
    localhost: "",
    "127.0.0.1": "",
    "[::1]": "",
  };
  for (const [host, want] of Object.entries(cases)) {
    assert.equal(SVPSL.registrableDomain(list, host), want, host);
  }
});

test("a page's origin is the browser's idea of it", () => {
  assert.equal(SVOrigin.originOf("https://github.com/login?x=1#y"), "https://github.com");
  assert.equal(SVOrigin.originOf("https://GitHub.com:443/"), "https://github.com");
  assert.equal(SVOrigin.originOf("http://localhost:8080/a"), "http://localhost:8080");
  assert.equal(SVOrigin.originOf("https://bücher.example/"), "https://xn--bcher-kva.example");
  assert.equal(SVOrigin.originOf("http://[::1]:3000/"), "http://[::1]:3000");
  for (const no of ["about:blank", "file:///etc/passwd", "data:text/html,x", "javascript:alert(1)", "moz-extension://abc/panel.html", "chrome-extension://abc/", "ftp://x.example/", "not a url", undefined, null, 7]) {
    assert.equal(SVOrigin.originOf(no), null, String(no));
  }
});

test("origins have one spelling", () => {
  for (const ok of ["https://github.com", "http://localhost:8080", "https://xn--bcher-kva.example", "http://[::1]:3000"]) {
    assert.ok(SVOrigin.parseOrigin(ok), ok);
  }
  for (const bad of ["https://github.com/", "https://github.com/login", "https://GitHub.com", "https://github.com:443", "https://user@github.com", "https://bücher.example", "github.com", "", "x".repeat(2000)]) {
    assert.equal(SVOrigin.parseOrigin(bad), null, bad);
  }
});

test("logins match by origin, as the daemon matches them", () => {
  const cases = [
    ["https://github.com", "https://github.com", "host"],
    ["github.com", "https://github.com", "host"],
    ["https://github.com/login", "https://github.com", "host"],
    ["https://github.com", "https://gist.github.com", "site"],
    ["https://login.example.co.uk", "https://www.example.co.uk", "site"],
    ["https://co.uk", "https://example.co.uk", null],
    ["https://alice.github.io", "https://bob.github.io", null],
    ["https://github.com", "https://evilgithub.com", null],
    ["https://github.com", "https://github.com.evil.example", null],
    ["https://github.com", "http://github.com", null],
    ["http://github.com", "https://github.com", "host"],
    ["https://github.com:8443", "https://github.com", null],
    ["https://github.com", "https://github.com:8443", null],
    ["http://localhost:3000", "http://localhost:3000", "host"],
    ["http://intranet", "http://wiki.intranet", null],
    ["https://10.0.0.2", "https://10.0.0.1", null],
    ["https://bücher.example/", "https://xn--bcher-kva.example", "host"],
    ["*.github.com", "https://github.com", null],
    ["", "https://github.com", null],
    ["https://github.com", "https://github.com/", null],
  ];
  for (const [stored, page, want] of cases) {
    assert.equal(SVOrigin.match(list, stored, page), want, stored + " on " + page);
  }
});
