// The extension's panel: the toolbar popup, and the panel a mark opens in
// the page (in an iframe of the extension's own, which the page cannot
// read). It shows secretvault's state, the logins for the page, and a
// login waiting to be saved, and says which login to fill. It never holds
// a password: filling goes from the background straight to the page.
"use strict";

const ext = globalThis.browser ?? globalThis.chrome;
const token = location.hash.length > 1 ? location.hash.slice(1) : undefined;
const inPage = token !== undefined;

const $ = (id) => document.getElementById(id);

let view = { origin: null, state: null, offer: null, mode: "popup", forms: [] };
let busy = false;

// A panel in a page sits among the page's own elements, which can be
// moved under the pointer just before a click, or laid over the panel.
// So it takes no click until it has been in view for a moment, and,
// where the browser can tell (IntersectionObserver v2, in Chromium), none
// while anything covers it. Nothing in it takes the focus by itself. The
// toolbar popup is the browser's own window, and needs none of this.
const ARM_MS = 500;
let armedAt = performance.now() + ARM_MS;
let unobscured = true;

function rearm() {
  armedAt = performance.now() + ARM_MS;
}

function armed() {
  return !inPage || (performance.now() >= armedAt && unobscured && document.visibilityState === "visible");
}

if (inPage) {
  document.addEventListener("visibilitychange", rearm);
  if ("IntersectionObserver" in globalThis && "isVisible" in IntersectionObserverEntry.prototype) {
    unobscured = false;
    new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isVisible && !unobscured) rearm();
          unobscured = e.isVisible;
        }
      },
      { threshold: [1.0], trackVisibility: true, delay: 100 },
    ).observe(document.body);
  }
}

// act is a handler that runs only on a panel that is armed.
function act(fn) {
  return (...args) => {
    if (armed()) return fn(...args);
  };
}

// ask asks the background, and throws what it refused with.
async function ask(type, extra) {
  const r = await ext.runtime.sendMessage({ type, token, ...extra });
  if (!r || !r.ok) {
    const e = new Error((r && r.message) || "something went wrong");
    e.code = (r && r.error) || "failed";
    throw e;
  }
  return r;
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function status(...parts) {
  const s = $("status");
  s.replaceChildren(...parts.map((p) => (typeof p === "string" ? el("p", null, p) : p)));
}

function warn(text) {
  status(el("p", "warn", text));
}

function close() {
  if (inPage) ask("panel:close").catch(() => {});
  else window.close();
}

function vault() {
  return view.state && view.state.vault ? view.state.vault : "";
}

function chosen() {
  const vs = (view.state && view.state.vaults) || [];
  return vs.find((v) => v.name === vault()) || null;
}

// words says what went wrong, for people.
function words(e) {
  switch (e.code) {
    case "denied":
      return "secretvault said no.";
    case "locked":
      return "The vault is locked.";
    case "not-found":
      return e.message || "That login is not there any more.";
    case "navigated":
      return "The page changed. Open the list again.";
    case "timeout":
      return "secretvault did not answer in time.";
    case "not-installed":
    case "not-running":
      return "secretvault is not running.";
  }
  return e.message || "Something went wrong.";
}

// --------------------------------------------------------------- render

function renderDown(s) {
  $("vaults").hidden = true;
  $("list").hidden = true;
  $("actions").hidden = true;
  const retry = el("button", null, "Try again");
  retry.type = "button";
  retry.addEventListener("click", () => start());
  if (s.error === "not-installed") {
    const cmd = el("code", null, "secretvault browser install");
    const p = el("p", null, "secretvault's host is not set up for this browser. Run ");
    p.append(cmd, ", then restart the browser.");
    status(p, retry);
  } else {
    status(el("p", "warn", "secretvault is not running."), el("p", null, s.message || ""), retry);
  }
}

function renderVaults() {
  const vs = view.state.vaults;
  $("vaults").hidden = vs.length < 2;
  const sel = $("vault");
  sel.replaceChildren(
    ...vs.map((v) => {
      const o = el("option", null, v.name + (v.default ? " (default)" : "") + (v.locked ? " — locked" : ""));
      o.value = v.name;
      o.selected = v.name === vault();
      return o;
    }),
  );
}

function renderLocked(v) {
  $("list").hidden = true;
  $("actions").hidden = true;
  const unlock = el("button", "primary", "Unlock");
  unlock.type = "button";
  unlock.addEventListener("click", act(async () => {
    unlock.disabled = true;
    status("secretvault is asking for the passphrase of vault " + v.name + ", in a window of its own.");
    try {
      view.state = await ask("panel:unlock", { vault: v.name });
      await render();
    } catch (e) {
      warn(words(e));
      unlock.disabled = false;
      $("status").append(unlock);
    }
  }));
  status(el("p", null, "Vault " + v.name + " is locked."), unlock);
}

function renderOffer() {
  const o = view.offer;
  $("offer").hidden = !o;
  if (!o) return;
  const host = globalThis.SVOrigin.hostOf(o.origin) || o.origin;
  $("offer-title").textContent = o.status === "changed" ? "Update the saved password?" : "Save this login?";
  $("offer-what").textContent = (o.username ? o.username + " on " : "On ") + host + ", in vault " + (o.vault || vault() || "(default)") + ".";
  $("offer-name").value = host;
  $("offer-name").parentElement.querySelector("label[for=offer-name]").hidden = o.status === "changed";
  $("offer-name").hidden = o.status === "changed";
  $("offer-save").textContent = o.status === "changed" ? "Update" : "Save";
}

async function renderList() {
  $("list").hidden = false;
  $("actions").hidden = false;
  $("generate").hidden = !(inPage || view.forms.includes("signup") || view.forms.includes("change"));
  const ul = $("logins");
  ul.replaceChildren();
  if (!view.origin) {
    status("secretvault fills logins on http and https pages.");
    $("generate").hidden = true;
    return;
  }
  status("Asking secretvault…");
  let r;
  try {
    r = await ask("panel:logins", { vault: vault() });
  } catch (e) {
    if (e.code === "locked") return start();
    warn(words(e));
    return;
  }
  const host = globalThis.SVOrigin.hostOf(r.origin);
  if (r.logins.length === 0) {
    status("No logins for " + host + " in vault " + vault() + ".");
    return;
  }
  status();
  for (const l of r.logins) {
    const li = el("li");
    const b = el("button", "login");
    b.type = "button";
    b.append(el("span", "title", l.title || l.url));
    b.append(el("span", "user", l.username || "(no user name)"));
    if (l.match === "site") b.append(el("span", "note", "saved for " + (globalThis.SVOrigin.storedOrigin(l.url) || { host: l.url }).host));
    b.addEventListener("click", act(() => fill(l, "login")));
    li.append(b);
    if (l.totp) {
      const c = el("button", "code", "Code");
      c.type = "button";
      c.title = "Fill the one-time code";
      c.addEventListener("click", act(() => fill(l, "totp")));
      li.append(c);
    }
    ul.append(li);
  }
}

async function render() {
  const s = view.state;
  $("site").textContent = view.origin ? globalThis.SVOrigin.hostOf(view.origin) : "";
  if (!s.running) return renderDown(s);
  renderVaults();
  renderOffer();
  const v = chosen();
  if (!v) {
    $("list").hidden = true;
    $("actions").hidden = true;
    status("There is no vault yet. Make one with secretvault first.");
    return;
  }
  if (v.locked) return renderLocked(v);
  await renderList();
}

// --------------------------------------------------------------- actions

async function fill(l, what) {
  if (busy) return;
  busy = true;
  status("Asking secretvault for " + (l.title || "the login") + "…");
  try {
    const r = await ask("panel:fill", { vault: vault(), login: l.id, what });
    if (r.filled > 0) return close();
    warn(r.why ? "Not filled: " + r.why + "." : "Not filled.");
  } catch (e) {
    warn(words(e));
  } finally {
    busy = false;
  }
}

async function generate() {
  if (busy) return;
  busy = true;
  try {
    const r = await ask("panel:generate", {});
    if (r.filled > 0) return close();
    warn(r.why ? "Not filled: " + r.why + "." : "There is no new-password field here.");
  } catch (e) {
    warn(words(e));
  } finally {
    busy = false;
  }
}

async function decide(decision) {
  try {
    const r = await ask("panel:save", { decision, title: $("offer-name").value });
    view.offer = null;
    renderOffer();
    if (r.saved) status(r.created ? "Saved." : "Updated.");
  } catch (e) {
    warn(words(e));
  }
}

async function start() {
  status("Asking secretvault…");
  try {
    view = await ask("panel:init");
  } catch (e) {
    warn(words(e));
    return;
  }
  await render();
}

$("close").hidden = !inPage;
$("close").addEventListener("click", close);
$("generate").addEventListener("click", act(generate));
$("lock").addEventListener("click", act(async () => {
  try {
    view.state = await ask("panel:lock", { vault: vault() });
    await render();
  } catch (e) {
    warn(words(e));
  }
}));
$("vault").addEventListener("change", async () => {
  const name = $("vault").value;
  await ask("panel:vault", { vault: name }).catch(() => {});
  view.state.vault = name;
  await render();
});
$("offer-save").addEventListener("click", () => decide("save"));
$("offer-skip").addEventListener("click", () => decide("dismiss"));
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") close();
});
ext.runtime.onMessage.addListener((msg) => {
  // secretvault's state changed (a vault locked or unlocked, the host
  // stopped): look again.
  if (msg && msg.type === "state" && !busy) {
    ask("panel:state")
      .then((s) => {
        view.state = s;
        return render();
      })
      .catch(() => {});
  }
  return false;
});

start();
