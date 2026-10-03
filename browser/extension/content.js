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
// does not serve one), or fill a field that cannot be seen.
(function () {
  "use strict";

  const ext = globalThis.browser ?? globalThis.chrome;
  const F = globalThis.SVForms;
  if (!ext || !ext.runtime || !F) return;

  const MARK = 20;
  const PANEL_W = 320;
  const PANEL_H = 360;
  const OFFER_H = 230;

  let active = false;
  let nextHandle = 1;
  const fields = new Map(); // handle -> input
  const handles = new WeakMap(); // input -> handle
  const marks = new Map(); // handle -> {host, el}
  let panel = null; // {host, handle}
  let offer = null; // {host}
  let reported = "";

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
  // CSS, not see-through, not shrunk to nothing.
  function visible(el) {
    if (!el.isConnected || el.disabled || el.type === "hidden") return false;
    const r = el.getBoundingClientRect();
    if (r.width < 8 || r.height < 8) return false;
    if (typeof el.checkVisibility === "function" &&
        !el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true, opacityProperty: true, visibilityProperty: true })) {
      return false;
    }
    let opacity = 1;
    for (let e = el; e && e.nodeType === 1; e = e.parentElement) {
      const s = getComputedStyle(e);
      if (s.display === "none" || s.visibility === "hidden" || s.visibility === "collapse") return false;
      const o = parseFloat(s.opacity);
      opacity *= Number.isFinite(o) ? o : 1;
      if (opacity < 0.2) return false;
    }
    return true;
  }

  // onScreen: the field is in view and nothing covers its middle. It is
  // scrolled to first, as a field the toolbar's list fills may be below.
  function onScreen(el) {
    let r = el.getBoundingClientRect();
    if (r.bottom < 0 || r.right < 0 || r.top > innerHeight || r.left > innerWidth) {
      el.scrollIntoView({ block: "center", inline: "nearest" });
      r = el.getBoundingClientRect();
    }
    const x = r.left + r.width / 2;
    const y = r.top + r.height / 2;
    if (x < 0 || y < 0 || x > innerWidth || y > innerHeight) return false;
    const hit = document.elementFromPoint(x, y);
    if (!hit) return false;
    if (hit === el || el.contains(hit)) return true;
    const label = hit.closest && hit.closest("label");
    return !!(label && label.control === el);
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

  function style(el, props) {
    for (const [k, v] of Object.entries(props)) el.style.setProperty(k, v, "important");
  }

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

  // shadowHost is an element of ours in the page, its insides in a
  // closed shadow root.
  function shadowHost() {
    const host = document.createElement("span");
    style(host, { all: "initial", position: "fixed", "z-index": "2147483646", display: "block", margin: "0", padding: "0", border: "0" });
    const root = host.attachShadow({ mode: "closed" });
    document.documentElement.append(host);
    return { host, root };
  }

  function addMark(el, handle) {
    const { host, root } = shadowHost();
    style(host, { width: MARK + "px", height: MARK + "px" });
    const b = document.createElement("button");
    b.type = "button";
    b.title = "secretvault";
    b.setAttribute("aria-label", "Fill from secretvault");
    style(b, {
      all: "initial", display: "flex", "align-items": "center", "justify-content": "center", width: MARK + "px", height: MARK + "px",
      "border-radius": "4px", background: "#2f6f4f", cursor: "pointer", "box-sizing": "border-box", opacity: "0.9",
    });
    b.append(icon());
    // The field keeps the focus.
    b.addEventListener("mousedown", (e) => e.isTrusted && e.preventDefault());
    b.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (e.isTrusted) openPanel(handle); // a page cannot click it for the person
    });
    root.append(b);
    marks.set(handle, { host, el });
  }

  function placeMark(m) {
    const r = m.el.getBoundingClientRect();
    const shown = r.width >= 8 && r.bottom > 0 && r.top < innerHeight && r.right > 0 && r.left < innerWidth;
    style(m.host, {
      display: shown ? "block" : "none",
      left: Math.round(r.right - MARK - 4) + "px",
      top: Math.round(r.top + (r.height - MARK) / 2) + "px",
    });
  }

  function placePanel(p, h) {
    const el = fields.get(p.handle);
    if (!el || !el.isConnected) return closePanel();
    const r = el.getBoundingClientRect();
    let top = r.bottom + 4;
    if (top + h > innerHeight && r.top - h - 4 >= 0) top = r.top - h - 4;
    const left = Math.max(4, Math.min(r.left, innerWidth - PANEL_W - 4));
    style(p.host, { left: Math.round(left) + "px", top: Math.round(Math.max(4, top)) + "px" });
  }

  let placing = false;
  function place() {
    if (placing) return;
    placing = true;
    requestAnimationFrame(() => {
      placing = false;
      for (const m of marks.values()) placeMark(m);
      if (panel) placePanel(panel, PANEL_H);
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
        if (i < 0) continue;
        const h = handleOf(vis[i]);
        keep.add(h);
        if (!marks.has(h)) addMark(vis[i], h);
      }
    }
    for (const [h, m] of marks) {
      if (!keep.has(h)) {
        m.host.remove();
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

  function frame(url, w, h) {
    const { host, root } = shadowHost();
    style(host, { width: w + "px", height: h + "px", "z-index": "2147483647" });
    const f = document.createElement("iframe");
    style(f, {
      all: "initial", display: "block", width: "100%", height: "100%", border: "0", "border-radius": "8px",
      "box-shadow": "0 4px 18px rgba(0,0,0,.28)", background: "Canvas", "color-scheme": "light dark",
    });
    f.setAttribute("referrerpolicy", "no-referrer");
    f.src = url;
    root.append(f);
    return host;
  }

  function ours(url) {
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
    if (!r || !r.ok || !ours(r.url)) return;
    panel = { host: frame(r.url, PANEL_W, PANEL_H), handle };
    placePanel(panel, PANEL_H);
  }

  function closePanel() {
    if (panel) {
      panel.host.remove();
      panel = null;
    }
  }

  function showOffer(url) {
    if (window !== window.top || !ours(url)) return;
    if (offer) offer.host.remove();
    const host = frame(url, PANEL_W, OFFER_H);
    style(host, { top: "12px", right: "12px", left: "auto" });
    offer = { host };
  }

  function closeOffer() {
    if (offer) {
      offer.host.remove();
      offer = null;
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
    const focused = document.activeElement;
    if (focused instanceof HTMLInputElement && handles.has(focused)) {
      const g = groupOf(focused);
      if (want.includes(g.a.kind) || (what === "totp" && g.a.otp >= 0)) return { g, el: focused };
    }
    for (const [key, inputs] of groups()) {
      const g = analyzed(key, inputs);
      if (want.includes(g.a.kind) || (what === "totp" && g.a.otp >= 0)) return { g, el: null };
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
  // offer saving them: only for what the person did (a trusted event,
  // with the page holding the person's activation), at most once a second.
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
      if (e.key === "Escape" && (panel || offer)) {
        closePanel();
        closeOffer();
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
    new MutationObserver(later).observe(document.documentElement, {
      childList: true, subtree: true, attributes: true, attributeFilter: ["type", "hidden", "style", "class", "disabled"],
    });
    document.addEventListener("focusin", later, true);
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
        closeOffer();
        return false;
      case "offer:show":
        showOffer(msg.url);
        return false;
    }
    return false;
  });

  ext.runtime.sendMessage({ type: "frame:hello" }).then((r) => {
    if (!r || !r.ok || !r.active) return;
    active = true;
    listen();
    scan();
    if (r.offer) showOffer(r.offer);
  }, () => {});
})();
