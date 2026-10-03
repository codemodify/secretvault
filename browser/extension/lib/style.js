// What computed CSS values say about whether a thing can be seen: the
// content script asks before it marks or fills a field, and before it
// takes a click on its own marks. Pure functions of the values, so they
// are tested without a browser.
(function (root) {
  "use strict";

  // alpha is a computed colour's opacity, in any of the forms browsers
  // write them: transparent, rgb(r, g, b, a), rgba(), and the functions
  // with a "/ alpha" (oklch(), lab(), color(), rgb() in its newer form).
  function alpha(color) {
    const c = String(color || "").trim();
    if (c === "transparent") return 0;
    const m = /^[a-z-]+\((.*)\)$/i.exec(c);
    if (!m) return 1;
    let a;
    if (m[1].includes("/")) {
      a = m[1].split("/").pop().trim();
    } else {
      const parts = m[1].split(",");
      if (parts.length < 4) return 1;
      a = parts[3].trim();
    }
    const v = parseFloat(a);
    if (!Number.isFinite(v)) return 1;
    return a.endsWith("%") ? v / 100 : v;
  }

  // hides reports whether a computed filter all but hides what it is on:
  // a low opacity(), brightness() or contrast(), more than a little
  // blur(), or an SVG filter (url()), which could do anything.
  function hides(filter) {
    if (!filter || filter === "none") return false;
    if (/url\(/i.test(filter)) return true;
    for (const m of String(filter).matchAll(/(opacity|brightness|contrast)\(\s*([\d.]+)(%?)\s*\)/g)) {
      const v = parseFloat(m[2]) / (m[3] ? 100 : 1);
      if ((m[1] === "opacity" && v < 0.5) || (m[1] !== "opacity" && v < 0.3)) return true;
    }
    const blur = /blur\(\s*([\d.]+)px\s*\)/.exec(filter);
    return !!(blur && parseFloat(blur[1]) > 2);
  }

  root.SVStyle = Object.freeze({ alpha, hides });
})(globalThis);
