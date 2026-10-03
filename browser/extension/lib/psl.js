// The Public Suffix List: where a name stops being a registry's and
// starts being someone's. "co.uk" and "github.io" are public suffixes, so
// "example.co.uk" and "alice.github.io" each have one owner, and
// "bob.github.io" is someone else. Both of the list's sections are read.
//
// The same algorithm as secretvaultd's (svext/psl.go), on the same file
// (data/public_suffix_list.dat): the longest rule that fits wins, an
// exception ("!www.ck") over the wildcard it excepts ("*.ck"), and a name
// no rule fits has its last label as its suffix.
//
// A classic script: it adds SVPSL to the global object, for the
// background script, the extension's pages and node's tests alike.
(function (root) {
  "use strict";

  // toASCII is a name in the form browsers send it (xn--...), by the
  // URL parser, which does IDNA; null when it is no host name.
  function toASCII(name) {
    if (/^[\x21-\x7e]*$/.test(name)) return name.toLowerCase();
    try {
      return new URL("http://" + name + "/").hostname;
    } catch {
      return null;
    }
  }

  // parse reads the list's text into its three kinds of rule.
  function parse(text) {
    const list = { rules: new Set(), wildcards: new Set(), exceptions: new Set() };
    for (let line of String(text).split("\n")) {
      line = line.trim();
      if (line === "" || line.startsWith("//")) continue;
      line = line.split(/\s/)[0];
      let set = list.rules;
      if (line.startsWith("!")) {
        set = list.exceptions;
        line = line.slice(1);
      } else if (line.startsWith("*.")) {
        set = list.wildcards;
        line = line.slice(2);
      }
      const ascii = toASCII(line);
      if (ascii) set.add(ascii);
    }
    return list;
  }

  function size(list) {
    return list.rules.size + list.wildcards.size + list.exceptions.size;
  }

  // publicSuffix of an ASCII host name: "co.uk" for "www.example.co.uk".
  function publicSuffix(list, host) {
    const labels = host.split(".");
    for (let i = 0; i < labels.length; i++) {
      const s = labels.slice(i).join(".");
      if (list.exceptions.has(s)) return labels.slice(i + 1).join(".");
      if (list.rules.has(s)) return s;
      if (i + 1 < labels.length && list.wildcards.has(labels.slice(i + 1).join("."))) return s;
    }
    return labels[labels.length - 1];
  }

  function isIP(host) {
    return /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(":") || host.startsWith("[");
  }

  // registrableDomain is the public suffix and the label before it, or
  // "" for a public suffix itself, an address, or a one-label name.
  function registrableDomain(list, host) {
    if (!host || isIP(host) || !host.includes(".")) return "";
    const ps = publicSuffix(list, host);
    if (ps === host) return "";
    const rest = host.slice(0, host.length - ps.length - 1);
    return rest.slice(rest.lastIndexOf(".") + 1) + "." + ps;
  }

  root.SVPSL = Object.freeze({ parse, size, publicSuffix, registrableDomain, toASCII });
})(globalThis);
