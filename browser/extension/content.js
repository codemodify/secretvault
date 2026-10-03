// The part of the extension in each page: it marks login fields, opens
// the extension's panel when the person clicks a mark, fills what the
// person chose there, and reports forms the person sent, for saving.
//
// It runs in the content script's own world: the page cannot read its
// variables, and its marks and panel live in closed shadow roots the page
// cannot reach into. It never holds the list of logins (that is the
// panel's, an extension page in an iframe the page cannot read), and it
// gets a login only to fill it, once, after the person chose it.
//
// What it will not do: fill when the page loads (only when the person
// asks), fill a frame of another origin than its tab's page (background.js
// does not serve one), or fill a field that cannot be seen. Nor will it
// show anything in the page that depends on what secretvault holds: a
// login to save is offered on the toolbar button only.
//
// A page can still restyle, cover or move what is its own (the elements
// that hold the marks and the panel are in its DOM), to trick a click.
// So they are put in the top layer, above the page's content; one the
// page touches is taken away; a click counts only on a mark that has
// stood still, uncovered and unaltered, for a moment; and the panel
// closes when the field it was opened for moves.
(function () {
  "use strict";

  const ext = globalThis.browser ?? globalThis.chrome;
  const F = globalThis.SVForms;
  const S = globalThis.SVStyle;
  if (!ext || !ext.runtime || !F || !S) return;
  const { alpha, hides } = S;

  const MARK = 20;
  const PANEL_W = 320;
  const PANEL_H = 360;
  const SETTLE_MS = 400; // a mark must have stood still this long to be clicked

  let active = false;
  let nextHandle = 1;
  const fields = new Map(); // handle -> input
  const handles = new WeakMap(); // input -> handle
  const marks = new Map(); // handle -> {host, el, at, movedAt}
  const spoiled = new WeakMap(); // field -> how often the page touched its mark; at 3 it is not marked again
  let panel = null; // {host, handle, rect}
  let reported = "";

  // ---------------------------------------------------- our elements

  const popovers = typeof HTMLElement.prototype.showPopover === "function";
  const ours = new WeakSet(); // the elements that hold the marks and the panel
  const leaving = new WeakSet(); // those this script takes away itself
  const wanted = new WeakMap(); // host -> {props, css}: its style, as set here
  let raising = false; // this script is putting a host in the top layer again

  // A host whose attributes change, but for its style as set here, is
  // the page's doing.
  const guard = new MutationObserver((records) => {
    for (const r of records) {
      const host = r.target;
      const w = wanted.get(host);
      if (!w || !host.isConnected) continue;
      if (r.attributeName !== "style" || host.getAttribute("style") !== w.css) tampered(host);
    }
  });
  // So is one taken out of <html> (to be put somewhere see-through, say).
  const roots = new MutationObserver((records) => {
    for (const r of records) {
      for (const n of r.removedNodes) if (ours.has(n) && !leaving.has(n)) tampered(n);
    }
  });

  function cssOf(props) {
    return Object.entries(props)
      .map(([k, v]) => k + ":" + v + " !important")
      .join(";");
  }

  // restyle sets a host's whole style attribute: what the page added to
  // it goes, and a change that is not this is the page's.
  function restyle(host, changes) {
    const w = wanted.get(host);
    Object.assign(w.props, changes);
    w.css = cssOf(w.props);
    host.setAttribute("style", w.css);
    w.css = host.getAttribute("style");
  }

  // shadowHost is an element of ours in the page, its insides in a
  // closed shadow root, in the top layer where the browser has one. It is
  // shown only once it is there.
  function shadowHost(props) {
    const host = document.createElement("span");
    ours.add(host);
    wanted.set(host, { props: { all: "initial", position: "fixed", "z-index": "2147483647", display: "none", margin: "0", padding: "0", border: "0", overflow: "visible", ...props }, css: "" });
    restyle(host, {});
    const root = host.attachShadow({ mode: "closed" });
    if (popovers) {
      host.setAttribute("popover", "manual");
      // Out of the top layer is the page's doing, unless it is ours.
      host.addEventListener("beforetoggle", (e) => {
        if (e.newState === "closed" && !raising && !leaving.has(host)) setTimeout(() => tampered(host), 0);
      });
    }
    document.documentElement.append(host);
    raise(host);
    guard.observe(host, { attributes: true });
    return { host, root };
  }

  // raise puts host in the top layer (again: above the page's own).
  function raise(host) {
    if (!popovers) return;
    raising = true;
    try {
      if (host.matches(":popover-open")) host.hidePopover();
      host.showPopover();
    } catch {
      // It stays shut, and so not shown.
    } finally {
      raising = false;
    }
  }

  // up reports whether host is where it was put: a child of <html>, in
  // the top layer (where there is one).
  function up(host) {
    return host.isConnected && host.parentNode === document.documentElement && (!popovers || host.matches(":popover-open"));
  }

  function drop(host) {
    leaving.add(host);
    host.remove();
  }

  function tampered(host) {
    for (const [h, m] of marks) {
      if (m.host === host) {
        spoiled.set(m.el, (spoiled.get(m.el) || 0) + 1);
        marks.delete(h);
      }
    }
    if (panel && panel.host === host) panel = null;
    drop(host);
  }

  // ---------------------------------------------------------- the fields

  function labelText(el) {
    const l = el.labels && el.labels[0];
    return l ? String(l.textContent || "").trim().slice(0, 100) : "";
  }

  function describe(el) {
    return {
      type: el.type,
      name: el.name,
      id: el.id,
      autocomplete: el.getAttribute("autocomplete") || "",
      placeholder: el.getAttribute("placeholder") || "",
      label: labelText(el),
      ariaLabel: el.getAttribute("aria-label") || "",
      inputmode: el.getAttribute("inputmode") || "",
      maxLength: el.maxLength > 0 ? el.maxLength : undefined,
    };
  }

  // visible: the field is there to be seen: in the page, not hidden by
  // CSS, not see-through, not clipped or masked away, its text not
  // transparent, not shrunk to nothing.
  function visible(el) {
    if (!el.isConnected || el.disabled || el.type === "hidden") return false;
    const r = el.getBoundingClientRect();
    if (r.width < 8 || r.height < 8) return false;
    if (typeof el.checkVisibility === "function" &&
        !el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true, opacityProperty: true, visibilityProperty: true })) {
      return false;
    }
    const own = getComputedStyle(el);
    if (own.clipPath !== "none" || (own.maskImage && own.maskImage !== "none")) return false;
    if (alpha(own.color) < 0.2 || alpha(own.getPropertyValue("-webkit-text-fill-color") || own.color) < 0.2) return false;
    let opacity = 1;
    for (let e = el; e && e.nodeType === 1; e = e.parentElement) {
      const s = getComputedStyle(e);
      if (s.display === "none" || s.visibility === "hidden" || s.visibility === "collapse") return false;
      if (hides(s.filter)) return false;
      const o = parseFloat(s.opacity);
      opacity *= Number.isFinite(o) ? o : 1;
      if (opacity < 0.2) return false;
    }
    return true;
  }

  // hits reports whether a point of the field is the field (or its label).
  function hits(el, x, y) {
    if (x < 0 || y < 0 || x > innerWidth || y > innerHeight) return false;
    const hit = document.elementFromPoint(x, y);
    if (!hit) return false;
    if (hit === el || el.contains(hit)) return true;
    const label = hit.closest && hit.closest("label");
    return !!(label && label.control === el);
  }

  // onScreen: the field is in view and nothing covers its middle, nor
  // both its sides. It is scrolled to first, as a field the toolbar's list
  // fills may be below.
  function onScreen(el) {
    let r = el.getBoundingClientRect();
    if (r.bottom < 0 || r.right < 0 || r.top > innerHeight || r.left > innerWidth) {
      el.scrollIntoView({ block: "center", inline: "nearest" });
      r = el.getBoundingClientRect();
    }
    const y = r.top + r.height / 2;
    return hits(el, r.left + r.width / 2, y) && (hits(el, r.left + r.width / 4, y) || hits(el, r.left + (3 * r.width) / 4, y));
  }

  function usable(el) {
    return el instanceof HTMLInputElement && visible(el) && !el.readOnly && onScreen(el);
  }

  function handleOf(el) {
    let h = handles.get(el);
    if (!h) {
      h = nextHandle++;
      handles.set(el, h);
      fields.set(h, el);
    }
    return h;
  }

  function hintOf(form) {
    if (!form) return "";
    const button = form.querySelector("button[type=submit], input[type=submit], button:not([type])");
    const said = button ? button.textContent || button.value || "" : "";
    return [form.id, form.getAttribute("name"), form.getAttribute("action"), form.className, said].join(" ").slice(0, 500);
  }

  // groups are the inputs by form; inputs in no form are one group.
  function groups() {
    const out = new Map();
    for (const el of document.querySelectorAll("input")) {
      const key = el.form || document;
      if (!out.has(key)) out.set(key, []);
      out.get(key).push(el);
    }
    return out;
  }

  function analyzed(key, inputs) {
    const vis = inputs.filter(visible);
    return { vis, a: F.analyze(vis.map(describe), hintOf(key === document ? null : key)) };
  }

  // groupOf is the analysed group a field is in.
  function groupOf(el) {
    const key = el.form || document;
    const inputs = key === document ? Array.from(document.querySelectorAll("input")).filter((i) => !i.form) : Array.from(key.querySelectorAll("input"));
    return analyzed(key, inputs);
  }

  // ------------------------------------------------------------- marking

  function icon() {
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 16 16");
    svg.setAttribute("width", "14");
    svg.setAttribute("height", "14");
    svg.setAttribute("aria-hidden", "true");
    const path = document.createElementNS(ns, "path");
    // A keyhole in a shield.
    path.setAttribute("d", "M8 1 2.5 3v4.2C2.5 10.6 4.9 13.6 8 15c3.1-1.4 5.5-4.4 5.5-7.8V3L8 1zm0 4a1.6 1.6 0 0 1 .8 3l.5 3H6.7l.5-3A1.6 1.6 0 0 1 8 5z");
    path.setAttribute("fill", "#ffffff");
    svg.append(path);
    return svg;
  }

  // covered reports whether the page has something of its own in the top
  // layer (a popover, a modal dialog, a full-screen element): wherever it
  // is, its ::backdrop may lie over the whole window, ours included.
  function covered() {
    for (const sel of [":popover-open", "dialog:modal", ":fullscreen"]) {
      let list = [];
      try {
        list = document.querySelectorAll(sel);
      } catch {
        continue;
      }
      for (const el of list) if (!ours.has(el)) return true;
    }
    return false;
  }

  // intact reports whether one of our hosts is as it was put: in <html>,
  // in the top layer, styled as set, shown as it is, nothing over it.
  function intact(host) {
    const w = wanted.get(host);
    return !!w && up(host) && host.getAttribute("style") === w.css && plain(host) && plain(document.documentElement) && !covered();
  }

  // plain reports whether an element's style shows what is in it as it is.
  function plain(el) {
    const s = getComputedStyle(el);
    return parseFloat(s.opacity) >= 0.99 && s.visibility === "visible" && !hides(s.filter) && s.clipPath === "none" &&
      (!s.maskImage || s.maskImage === "none") && (el !== document.documentElement ? s.transform === "none" : true);
  }

  // trusted reports whether a click on a mark is the person's, on a mark
  // they could see: a real click, on a mark that has stood still, that
  // nothing covers and nothing has restyled.
  function trusted(m, e) {
    if (!e.isTrusted || performance.now() - m.movedAt < SETTLE_MS) return false;
    if (covered()) {
      raise(m.host); // above the page's again; a later click may count
      m.movedAt = performance.now();
      return false;
    }
    if (!intact(m.host)) return false;
    // A click with the pointer must land on the mark itself; one from the
    // keyboard (detail 0) comes from the person tabbing to it, which the
    // page cannot do for them.
    return e.detail === 0 || document.elementFromPoint(e.clientX, e.clientY) === m.host;
  }

  function addMark(el, handle) {
    const { host, root } = shadowHost({ width: MARK + "px", height: MARK + "px" });
    const b = document.createElement("button");
    b.type = "button";
    b.title = "secretvault";
    b.setAttribute("aria-label", "Fill from secretvault");
    for (const [k, v] of Object.entries({
      all: "initial", display: "flex", "align-items": "center", "justify-content": "center", width: MARK + "px", height: MARK + "px",
      "border-radius": "4px", background: "#2f6f4f", cursor: "pointer", "box-sizing": "border-box",
    })) {
      b.style.setProperty(k, v, "important");
    }
    b.append(icon());
    const m = { host, el, at: "", movedAt: performance.now() };
    // The field keeps the focus.
    b.addEventListener("mousedown", (e) => e.isTrusted && e.preventDefault());
    b.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (trusted(m, e)) openPanel(handle); // a page cannot click it for the person
    });
    root.append(b);
    marks.set(handle, m);
  }

  function placeMark(m) {
    const r = m.el.getBoundingClientRect();
    const shown = r.width >= 8 && r.bottom > 0 && r.top < innerHeight && r.right > 0 && r.left < innerWidth;
    const at = shown ? Math.round(r.right - MARK - 4) + "," + Math.round(r.top + (r.height - MARK) / 2) : "none";
    if (at === m.at) return;
    m.at = at;
    m.movedAt = performance.now();
    if (!shown) {
      restyle(m.host, { display: "none" });
      return;
    }
    const [left, top] = at.split(",");
    restyle(m.host, { display: up(m.host) ? "block" : "none", left: left + "px", top: top + "px" });
  }

  // placePanel puts the panel under its field (or above, if there is no
  // room below), once: a field that moves after closes it.
  function placePanel(p) {
    const el = fields.get(p.handle);
    if (!el || !el.isConnected) return closePanel();
    const r = el.getBoundingClientRect();
    if (p.rect) {
      if (Math.abs(r.left - p.rect.left) > 2 || Math.abs(r.top - p.rect.top) > 2) closePanel();
      return;
    }
    p.rect = { left: r.left, top: r.top };
    let top = r.bottom + 4;
    if (top + PANEL_H > innerHeight && r.top - PANEL_H - 4 >= 0) top = r.top - PANEL_H - 4;
    const left = Math.max(4, Math.min(r.left, innerWidth - PANEL_W - 4));
    restyle(p.host, { left: Math.round(left) + "px", top: Math.round(Math.max(4, top)) + "px" });
  }

  let placing = false;
  function place() {
    if (placing) return;
    placing = true;
    requestAnimationFrame(() => {
      placing = false;
      for (const m of marks.values()) placeMark(m);
      if (panel) placePanel(panel);
    });
  }

  // scan marks the fields of every login form, and forgets the rest.
  function scan() {
    if (!active) return;
    const keep = new Set();
    const forms = new Set();
    for (const [key, inputs] of groups()) {
      const { vis, a } = analyzed(key, inputs);
      if (!a.kind) continue;
      forms.add(a.kind);
      for (const i of [a.username, a.password, ...a.newPasswords, a.otp]) {
        if (i < 0 || (spoiled.get(vis[i]) || 0) >= 3) continue;
        const h = handleOf(vis[i]);
        keep.add(h);
        if (!marks.has(h)) addMark(vis[i], h);
      }
    }
    for (const [h, m] of marks) {
      if (!keep.has(h)) {
        drop(m.host);
        marks.delete(h);
      }
    }
    for (const [h, el] of fields) if (!el.isConnected && !marks.has(h)) fields.delete(h);
    place();
    const now = [...forms].sort().join(",");
    if (now !== reported) {
      reported = now;
      ext.runtime.sendMessage({ type: "frame:fields", forms: [...forms] }).catch(() => {});
    }
  }

  let scanning = 0;
  function later() {
    if (scanning) return;
    scanning = setTimeout(() => {
      scanning = 0;
      scan();
    }, 300);
  }

  // --------------------------------------------------------------- panel

  function isPanelURL(url) {
    return typeof url === "string" && url.startsWith(ext.runtime.getURL("panel.html#"));
  }

  async function openPanel(handle) {
    closePanel();
    let r;
    try {
      r = await ext.runtime.sendMessage({ type: "panel:open", handle });
    } catch {
      return;
    }
    if (!r || !r.ok || !isPanelURL(r.url)) return;
    const { host, root } = shadowHost({ width: PANEL_W + "px", height: PANEL_H + "px", left: "-10000px", top: "0" });
    const f = document.createElement("iframe");
    for (const [k, v] of Object.entries({
      all: "initial", display: "block", width: "100%", height: "100%", border: "0", "border-radius": "8px",
      "box-shadow": "0 4px 18px rgba(0,0,0,.28)", background: "Canvas", "color-scheme": "light dark",
    })) {
      f.style.setProperty(k, v, "important");
    }
    f.setAttribute("referrerpolicy", "no-referrer");
    f.src = r.url;
    root.append(f);
    panel = { host, handle, rect: null };
    placePanel(panel);
    if (panel) restyle(host, { display: up(host) ? "block" : "none" });
  }

  function closePanel() {
    if (panel) {
      drop(panel.host);
      panel = null;
    }
  }

  // ------------------------------------------------------------- filling

  const setValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;

  function put(el, value) {
    el.focus({ preventScroll: true });
    setValue.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  // pick is the group to fill when the toolbar's list asks (no mark was
  // clicked): the focused field's, else the first that has what is filled.
  function pick(what) {
    const want = what === "totp" ? ["otp"] : what === "new" ? ["signup", "change"] : ["login", "change", "username"];
    const fits = (g) => want.includes(g.a.kind) || (what === "totp" && g.a.otp >= 0);
    const focused = document.activeElement;
    if (focused instanceof HTMLInputElement && handles.has(focused)) {
      const g = groupOf(focused);
      if (fits(g)) return { g, el: focused };
    }
    for (const [key, inputs] of groups()) {
      const g = analyzed(key, inputs);
      if (fits(g)) return { g, el: null };
    }
    return null;
  }

  // fill puts what the person chose into the fields it is for: all of
  // them, or none if one cannot be seen.
  function fill(msg) {
    if (!active || location.origin !== msg.origin) return { ok: false, why: "this page is not the one the login was chosen for" };
    closePanel();
    let found;
    if (Number.isInteger(msg.handle)) {
      const el = fields.get(msg.handle);
      if (!el || !el.isConnected) return { ok: false, why: "the field is gone" };
      found = { g: groupOf(el), el };
    } else {
      found = pick(msg.what);
    }
    if (!found) return { ok: false, why: "no field to fill here" };
    const { vis, a } = found.g;
    const plan = [];
    if (msg.what === "login") {
      if (a.username >= 0 && msg.username) plan.push([vis[a.username], msg.username]);
      if (a.password >= 0) plan.push([vis[a.password], msg.password]);
      if (a.otp >= 0 && msg.code) plan.push([vis[a.otp], msg.code]);
    } else if (msg.what === "totp") {
      const el = found.el && F.kind(describe(found.el)) === "otp" ? found.el : a.otp >= 0 ? vis[a.otp] : null;
      if (el) plan.push([el, msg.code]);
    } else if (msg.what === "new") {
      for (const i of a.newPasswords) plan.push([vis[i], msg.password]);
    }
    if (plan.length === 0) return { ok: false, why: "no field for it here" };
    for (const [el] of plan) {
      if (!usable(el)) return { ok: false, why: "a field to fill cannot be seen" };
    }
    for (const [el, value] of plan) put(el, value);
    return { ok: true, filled: plan.length };
  }

  // ---------------------------------------------------- what is sent

  let lastSent = 0;

  // report sends a form's user name and password to the background, to
  // offer saving them on the toolbar button: only for what the person did
  // (a trusted event, with the page holding the person's activation), at
  // most once a second. Nothing comes back to the page.
  function report(g) {
    if (!active || (navigator.userActivation && !navigator.userActivation.isActive)) return;
    const now = Date.now();
    if (now - lastSent < 1000) return;
    const { vis, a } = g;
    let password = "";
    if (a.kind === "login") password = vis[a.password].value;
    else if (a.kind === "signup" || a.kind === "change") {
      const values = a.newPasswords.map((i) => vis[i].value);
      if (values.some((v) => v !== values[0])) return; // the confirmation does not match
      password = values[0] || "";
    } else return;
    if (!password) return;
    lastSent = now;
    const username = a.username >= 0 ? vis[a.username].value.trim() : "";
    ext.runtime.sendMessage({ type: "submitted", username, password }).catch(() => {});
  }

  function nearGroup(el) {
    if (el.form) return groupOf(el.form.querySelector("input") || el);
    for (let e = el, n = 0; e && n < 6; e = e.parentElement, n++) {
      const pw = e.querySelector && e.querySelector("input[type=password]");
      if (pw) return groupOf(pw);
    }
    return null;
  }

  function listen() {
    document.addEventListener("submit", (e) => {
      if (e.isTrusted && e.target instanceof HTMLFormElement) {
        const first = e.target.querySelector("input[type=password]");
        if (first) report(groupOf(first));
      }
    }, true);
    document.addEventListener("keydown", (e) => {
      if (!e.isTrusted) return;
      if (e.key === "Escape" && panel) {
        closePanel();
        return;
      }
      if (e.key === "Enter" && e.target instanceof HTMLInputElement && e.target.type === "password") report(groupOf(e.target));
    }, true);
    document.addEventListener("click", (e) => {
      if (!e.isTrusted || !(e.target instanceof Element)) return;
      const b = e.target.closest("button, input[type=submit], input[type=button], [role=button]");
      if (b) {
        const g = nearGroup(b);
        if (g && g.a.kind) report(g);
      }
    }, true);
    document.addEventListener("mousedown", (e) => {
      // A click outside the panel closes it (a click in it is the
      // iframe's, which the page does not see).
      if (e.isTrusted && panel && e.target !== panel.host) closePanel();
    }, true);
    addEventListener("scroll", place, { capture: true, passive: true });
    addEventListener("resize", place, { passive: true });
    new MutationObserver(() => {
      later();
      place();
    }).observe(document.documentElement, {
      childList: true, subtree: true, attributes: true, attributeFilter: ["type", "hidden", "style", "class", "disabled"],
    });
    document.addEventListener("focusin", later, true);
    roots.observe(document.documentElement, { childList: true });
  }

  ext.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (!sender || sender.id !== ext.runtime.id || !msg) return false;
    switch (msg.type) {
      case "fill":
        sendResponse(fill(msg));
        // What was filled is the page's now; the message is let go.
        msg.password = msg.username = msg.code = null;
        return false;
      case "panel:close":
        closePanel();
        return false;
      case "panel:verify":
        // Asked before a choice made in the panel is acted on: was the
        // panel the page showed as it was put, when the person chose?
        sendResponse({ ok: !!panel && intact(panel.host) });
        return false;
    }
    return false;
  });

  ext.runtime.sendMessage({ type: "frame:hello" }).then((r) => {
    if (!r || !r.ok || !r.active) return;
    active = true;
    listen();
    scan();
  }, () => {});
})();
