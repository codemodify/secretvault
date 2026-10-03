// Which logins a page may be offered, by its origin. secretvaultd decides
// (svext/origin.go); the extension checks again with the same rules
// before it fills, so a mistake on one side is not enough.
//
//   - The scheme: an https login is never offered to http; an http one is
//     offered to https on the same host and default port (an upgrade).
//     A stored URL without a scheme is https. Only http and https count.
//   - The port: a stored port must be the page's; none means the
//     scheme's default.
//   - The host: the page's own ("host"), or one with the same registrable
//     domain by the Public Suffix List ("site"). Addresses and one-label
//     names (localhost) fit only themselves.
(function (root) {
  "use strict";

  const MAX_ORIGIN = 1024;

  function defaultPort(scheme) {
    return scheme === "http:" ? "80" : "443";
  }

  // parts is a URL's origin, taken apart, or null when it has none of
  // ours: {scheme: "https:", host: "github.com", port: "443"}.
  function parts(u) {
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    if (!u.hostname) return null;
    let host = u.hostname.toLowerCase().replace(/\.$/, "");
    if (!/^(\[[0-9a-f:.]+\]|[a-z0-9_.-]+)$/.test(host)) return null;
    return { scheme: u.protocol, host, port: u.port || defaultPort(u.protocol) };
  }

  function format(p) {
    const port = p.port === defaultPort(p.scheme) ? "" : ":" + p.port;
    return p.scheme + "//" + p.host + port;
  }

  // originOf is a page URL's origin, "https://github.com", or null for a
  // page that has none of ours (about:, file:, data:, the extension's own).
  function originOf(url) {
    if (typeof url !== "string" || url.length > 8192) return null;
    let u;
    try {
      u = new URL(url);
    } catch {
      return null;
    }
    const p = parts(u);
    return p ? format(p) : null;
  }

  // parseOrigin reads an origin exactly as originOf writes it, else null.
  function parseOrigin(s) {
    if (typeof s !== "string" || s === "" || s.length > MAX_ORIGIN) return null;
    let u;
    try {
      u = new URL(s);
    } catch {
      return null;
    }
    const p = parts(u);
    if (!p || format(p) !== s) return null;
    return p;
  }

  // storedOrigin reads a URL as items keep it ("github.com",
  // "https://github.com/login"), or null.
  function storedOrigin(stored) {
    if (typeof stored !== "string") return null;
    let s = stored.trim();
    if (s === "" || s.length > 4096 || /[<>^`{|}*"\s\\]/.test(s)) return null;
    if (!s.includes("://")) s = "https://" + s;
    try {
      return parts(new URL(s));
    } catch {
      return null;
    }
  }

  // match says how a stored URL fits a page's origin: "host", "site" or
  // null. list is a parsed Public Suffix List (SVPSL.parse).
  function match(list, stored, pageOrigin) {
    const s = storedOrigin(stored);
    const p = parseOrigin(pageOrigin);
    if (!s || !p) return null;
    const same = s.scheme === p.scheme && s.port === p.port;
    const upgrade = s.scheme === "http:" && p.scheme === "https:" && s.port === "80" && p.port === "443";
    if (!same && !upgrade) return null;
    if (s.host === p.host) return "host";
    const rd = root.SVPSL.registrableDomain(list, p.host);
    if (rd !== "" && rd === root.SVPSL.registrableDomain(list, s.host)) return "site";
    return null;
  }

  // hostOf is an origin's host, for people to read.
  function hostOf(origin) {
    const p = parseOrigin(origin);
    return p ? p.host : "";
  }

  root.SVOrigin = Object.freeze({ originOf, parseOrigin, storedOrigin, match, hostOf, MAX_ORIGIN });
})(globalThis);
