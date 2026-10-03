// The extension's background: the only part that talks to secretvault.
//
// It holds the connection to the native-messaging host, and decides, from
// what the browser says of each sender (never from what a page says),
// which frame may be served and for which origin:
//
//   - Content scripts (content.js) report login fields, ask for the
//     panel when the person clicks a mark, and report forms sent. They
//     never see the list of logins, and get a login only to fill, after
//     the person chose it in the extension's own UI.
//   - The extension's own pages (panel.html: the toolbar popup, or the
//     panel a mark opens in the page, in an iframe of the extension's
//     origin the page cannot read) show the logins and say which to fill.
//     A panel in a page holds a token, made for that tab, frame and
//     origin when its mark was clicked.
//
// Secrets: a login read for a fill goes to the frame it was chosen for,
// and is dropped. A password a page sent, offered for saving, is kept in
// memory for two minutes at most, then dropped; nothing secret is stored.
//
// Saving is offered on the toolbar button (its badge, then the popup),
// never in the page: whether secretvault already holds what a page sent
// must not be something the page can see.
"use strict";

if (typeof importScripts === "function") {
  // Chromium's service worker; Firefox lists these in the manifest.
  importScripts("lib/psl.js", "lib/origin.js", "lib/protocol.js");
}

const ext = globalThis.browser ?? globalThis.chrome;
const O = globalThis.SVOrigin;
const P = globalThis.SVProtocol;

const QUICK = 15 * 1000; // hello, state, generate
const PATIENT = 5 * 60 * 1000; // anything the daemon may ask the person about
const OFFER_LIFE = 2 * 60 * 1000;
const PANEL_IDLE = 60 * 1000; // a panel in a page unused this long is let go
const PANEL_LIFE = 10 * 60 * 1000; // and any after this long

// ---------------------------------------------------------------- the host

const host = {
  port: null,
  seq: 0,
  waiting: new Map(), // id -> {resolve, reject, timer}
  down: null, // {error, message}: why the host is not there
  hello: null, // {browser, secretvault}
};

function fail(code, message) {
  return new P.ProtocolError(code, message);
}

function connect() {
  if (host.port) return host.port;
  let port;
  try {
    port = ext.runtime.connectNative(P.HOST);
  } catch (e) {
    host.down = { error: "not-installed", message: String(e && e.message) };
    throw fail("not-installed", host.down.message);
  }
  host.port = port;
  host.down = null;
  port.onMessage.addListener(onHostMessage);
  port.onDisconnect.addListener((p) => {
    const why = (p && p.error && p.error.message) || (ext.runtime.lastError && ext.runtime.lastError.message) || "";
    if (host.port === port) host.port = null;
    host.hello = null;
    if (!host.down) {
      host.down = /no such native application|not found|specified native messaging host/i.test(why)
        ? { error: "not-installed", message: why }
        : { error: "not-running", message: why || "secretvault's host stopped" };
    }
    for (const [, w] of host.waiting) {
      clearTimeout(w.timer);
      w.reject(fail(host.down.error, host.down.message));
    }
    host.waiting.clear();
    broadcast();
  });
  return port;
}

function onHostMessage(m) {
  const r = P.reply(m);
  if (!r) return;
  if (r.kind === "event") {
    if (r.event === "down") host.down = { error: r.error, message: r.message };
    broadcast();
    return;
  }
  const w = host.waiting.get(r.id);
  if (!w) return;
  host.waiting.delete(r.id);
  clearTimeout(w.timer);
  if (r.ok) w.resolve(r);
  else w.reject(fail(r.error, r.message));
}

// call sends a request and waits for its answer.
async function call(op, params, timeout = PATIENT) {
  const id = "r" + ++host.seq;
  const msg = P.request(id, op, params);
  const port = connect();
  if (!host.hello && op !== "hello") {
    const h = await call("hello", { extension: ext.runtime.getManifest().version }, QUICK);
    host.hello = { browser: h.browser, secretvault: h.secretvault };
  }
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      host.waiting.delete(id);
      reject(fail("timeout", "secretvault did not answer"));
    }, timeout);
    host.waiting.set(id, { resolve, reject, timer });
    try {
      port.postMessage(msg);
    } catch (e) {
      host.waiting.delete(id);
      clearTimeout(timer);
      reject(fail("not-running", String(e && e.message)));
    }
  });
}

// broadcast tells the extension's open pages to look again.
function broadcast() {
  try {
    ext.runtime.sendMessage({ type: "state" }).catch(() => {});
  } catch {
    // No page is open.
  }
}

// ------------------------------------------------------------- what we know

let suffixList = null;
async function suffixes() {
  if (!suffixList) {
    const r = await fetch(ext.runtime.getURL("data/public_suffix_list.dat"));
    suffixList = globalThis.SVPSL.parse(await r.text());
  }
  return suffixList;
}

const tabs = new Map(); // tabId -> {origin, frames: Map<frameId, {origin, forms: Set}>}
const panels = new Map(); // token -> {tabId, frameId, origin, handle, until, ends, panelFrame, panelDoc}
const offers = new Map(); // tabId -> {origin, vault, username, password, login, status, expires, timer}
const listed = new Map(); // tabId -> {origin, logins: Map<id, login>}: what a panel was shown
const sent = new Map(); // tabId -> [times]: forms reported sent, to limit them

function senderOrigins(sender) {
  const tab = sender.tab;
  if (!tab || typeof tab.id !== "number" || tab.id < 0) return null;
  const frameOrigin = O.originOf(sender.url);
  const topOrigin = O.originOf(tab.url);
  if (!frameOrigin || !topOrigin) return null;
  return { tabId: tab.id, frameId: sender.frameId || 0, frameOrigin, topOrigin, incognito: tab.incognito === true };
}

// served is a content script's frame if it may be served: an http or
// https frame of the same origin as its tab's page. A frame of another
// origin (an advertisement, a widget, a page framing a login it does not
// own) gets no marks and no fills.
function served(sender) {
  const s = senderOrigins(sender);
  if (!s || s.frameOrigin !== s.topOrigin) return null;
  return s;
}

function tabState(tabId) {
  let t = tabs.get(tabId);
  if (!t) {
    t = { origin: null, frames: new Map() };
    tabs.set(tabId, t);
  }
  return t;
}

function forgetTab(tabId) {
  tabs.delete(tabId);
  listed.delete(tabId);
  sent.delete(tabId);
  dropOffer(tabId);
  for (const [token, p] of panels) if (p.tabId === tabId) panels.delete(token);
}

function newToken() {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function panelURL(token) {
  return ext.runtime.getURL("panel.html") + "#" + token;
}

// ------------------------------------------------------------------- offers

function dropOffer(tabId) {
  const o = offers.get(tabId);
  if (!o) return;
  clearTimeout(o.timer);
  o.password = null;
  offers.delete(tabId);
  ext.action.setBadgeText({ tabId, text: "" }).catch(() => {});
  ext.action.setTitle({ tabId, title: "secretvault" }).catch(() => {});
}

function offerView(o) {
  return o ? { origin: o.origin, vault: o.vault, username: o.username, status: o.status, login: o.login || "" } : null;
}

async function chosenVault() {
  try {
    const got = await ext.storage.local.get("vault");
    return typeof got.vault === "string" ? got.vault : "";
  } catch {
    return "";
  }
}

// --------------------------------------------------- content scripts' asks

const fromContent = {
  // A frame starts: may it be served, and is a save waiting to be offered?
  async "frame:hello"(msg, sender) {
    const s = senderOrigins(sender);
    if (!s) return { active: false };
    const t = tabState(s.tabId);
    if (s.frameId === 0) {
      // A new page in the tab: what was shown for the last one is gone.
      t.origin = s.topOrigin;
      t.frames.clear();
      listed.delete(s.tabId);
      for (const [token, p] of panels) if (p.tabId === s.tabId) panels.delete(token);
    }
    if (s.frameOrigin !== s.topOrigin) return { active: false };
    t.frames.set(s.frameId, { origin: s.frameOrigin, forms: new Set() });
    return { active: true };
  },

  // A frame found login fields (or lost them).
  async "frame:fields"(msg, sender) {
    const s = served(sender);
    if (!s) return {};
    const f = tabState(s.tabId).frames.get(s.frameId);
    if (f && Array.isArray(msg.forms)) {
      f.forms = new Set(msg.forms.filter((k) => ["login", "signup", "change", "otp", "username"].includes(k)));
    }
    return {};
  },

  // The person clicked a mark: the panel, for that field.
  async "panel:open"(msg, sender) {
    const s = served(sender);
    if (!s) throw fail("denied", "this frame is not served");
    if (!Number.isInteger(msg.handle) || msg.handle < 0) throw fail("bad-request", "no field");
    return { url: panelFor(s, msg.handle) };
  },

  // A form with a password was sent, by the person.
  async submitted(msg, sender) {
    const s = served(sender);
    if (!s || s.incognito) return {};
    const now = Date.now();
    const times = (sent.get(s.tabId) || []).filter((x) => now - x < 10000);
    if (times.length >= 3) return {}; // a page sending forms in a loop is not asked about
    times.push(now);
    sent.set(s.tabId, times);
    const username = typeof msg.username === "string" ? msg.username : "";
    const password = typeof msg.password === "string" ? msg.password : "";
    let checked;
    const vault = await chosenVault();
    try {
      checked = await call("check", { vault, origin: s.topOrigin, username: username || undefined, password });
    } catch {
      return {}; // invalid, locked, refused, not running: nothing to offer
    }
    if (checked.status !== "new" && checked.status !== "changed") return {};
    dropOffer(s.tabId);
    const o = { origin: s.topOrigin, vault, username, password, login: checked.status === "changed" ? checked.login : "", status: checked.status };
    o.timer = setTimeout(() => dropOffer(s.tabId), OFFER_LIFE);
    offers.set(s.tabId, o);
    ext.action.setBadgeBackgroundColor({ tabId: s.tabId, color: "#2f6f4f" }).catch(() => {});
    ext.action.setBadgeText({ tabId: s.tabId, text: "1" }).catch(() => {});
    ext.action.setTitle({ tabId: s.tabId, title: "secretvault: save the login you just used?" }).catch(() => {});
    return {};
  },
};

// panelFor makes the token a panel in the page is opened with, for the
// field handle of the frame s. The panel's own frame is bound to it when
// the panel first uses it; any other frame is refused.
function panelFor(s, handle) {
  for (const [token, p] of panels) if (p.tabId === s.tabId) panels.delete(token);
  const token = newToken();
  const now = Date.now();
  panels.set(token, { tabId: s.tabId, frameId: s.frameId, origin: s.topOrigin, handle, until: now + PANEL_IDLE, ends: now + PANEL_LIFE, panelFrame: null, panelDoc: null });
  return panelURL(token);
}

// ----------------------------------------------------- the extension's pages

// where is what a page of ours acts on: a panel in a page, by its token,
// or the toolbar popup, on the active tab.
async function where(msg, sender) {
  if (sender.tab) {
    const p = typeof msg.token === "string" ? panels.get(msg.token) : null;
    const now = Date.now();
    if (!p || p.tabId !== sender.tab.id || p.until < now || p.ends < now) throw fail("denied", "this panel has expired: click the mark again");
    // The first frame to use the token is the panel's; no other may.
    const doc = typeof sender.documentId === "string" ? sender.documentId : null;
    if (p.panelFrame === null) {
      p.panelFrame = sender.frameId;
      p.panelDoc = doc;
    } else if (p.panelFrame !== sender.frameId || p.panelDoc !== doc) {
      throw fail("denied", "this panel is another's");
    }
    p.until = now + PANEL_IDLE;
    return { tabId: p.tabId, frameId: p.frameId, origin: p.origin, handle: p.handle, mode: "fill", token: msg.token };
  }
  const [tab] = await ext.tabs.query({ active: true, currentWindow: true });
  if (!tab || typeof tab.id !== "number") throw fail("no-page", "no page");
  return { tabId: tab.id, frameId: null, origin: O.originOf(tab.url), handle: null, mode: "popup", incognito: tab.incognito === true };
}

// stillThere checks the tab still shows the origin a panel was for.
async function stillThere(w) {
  const tab = await ext.tabs.get(w.tabId);
  if (!w.origin || O.originOf(tab.url) !== w.origin) throw fail("navigated", "the page changed: open the list again");
}

// frameFor picks the frame to fill: the panel's own, else the top frame
// if it has fields, else a frame of the same origin that has.
function frameFor(w, want) {
  if (w.frameId !== null) return w.frameId;
  const t = tabs.get(w.tabId);
  if (!t) return 0;
  const has = (f) => f.origin === w.origin && [...f.forms].some((k) => want.includes(k));
  const top = t.frames.get(0);
  if (top && has(top)) return 0;
  for (const [id, f] of t.frames) if (has(f)) return id;
  return 0;
}

async function state() {
  const vault = await chosenVault();
  try {
    const st = await call("state", {}, QUICK);
    const vaults = P.vaults(st.vaults);
    const chosen = vaults.find((v) => v.name === vault) || vaults[0] || null;
    return { running: true, browser: host.hello ? host.hello.browser : "", vaults, vault: chosen ? chosen.name : "" };
  } catch (e) {
    return { running: false, error: e.code || "not-running", message: e.message || "" };
  }
}

const fromPages = {
  async "panel:init"(msg, sender) {
    const w = await where(msg, sender);
    return {
      mode: w.mode,
      origin: w.origin,
      state: await state(),
      // The offer is the toolbar popup's alone.
      offer: w.mode === "popup" ? offerView(offers.get(w.tabId)) : null,
      forms: w.frameId === null ? formsOf(w) : [],
    };
  },

  async "panel:state"(msg, sender) {
    await where(msg, sender);
    return state();
  },

  async "panel:vault"(msg, sender) {
    await where(msg, sender);
    if (typeof msg.vault !== "string" || msg.vault.length > P.LIMITS.vault) throw fail("bad-request", "a bad vault");
    await ext.storage.local.set({ vault: msg.vault });
    return {};
  },

  async "panel:unlock"(msg, sender) {
    await where(msg, sender);
    await call("unlock", { vault: msg.vault || undefined });
    return state();
  },

  async "panel:lock"(msg, sender) {
    await where(msg, sender);
    await call("lock", { vault: msg.vault || undefined });
    return state();
  },

  async "panel:logins"(msg, sender) {
    const w = await where(msg, sender);
    if (!w.origin) throw fail("no-page", "secretvault fills logins on http and https pages");
    const r = await call("logins", { vault: msg.vault || undefined, origin: w.origin });
    // The daemon matched them; they are checked again here.
    const list = await suffixes();
    const logins = P.logins(r.logins).filter((l) => r.origin === w.origin && O.match(list, l.url, w.origin) !== null);
    listed.set(w.tabId, { origin: w.origin, vault: msg.vault || "", logins: new Map(logins.map((l) => [l.id, l])) });
    return { origin: w.origin, logins };
  },

  async "panel:fill"(msg, sender) {
    const w = await where(msg, sender);
    const l = shown(w, msg.login);
    const totp = msg.what === "totp";
    if (totp && !l.totp) throw fail("not-found", "that login has no one-time code");
    await stillThere(w);
    const frameId = frameFor(w, totp ? ["otp", "login"] : ["login", "username", "change"]);
    let creds = totp
      ? await call("totp", { vault: msg.vault || undefined, origin: w.origin, login: l.id })
      : await call("fill", { vault: msg.vault || undefined, origin: w.origin, login: l.id });
    try {
      await stillThere(w);
      const fill = totp
        ? { type: "fill", what: "totp", origin: w.origin, handle: w.handle, code: String(creds.code || "") }
        : { type: "fill", what: "login", origin: w.origin, handle: w.handle, username: String(creds.username || ""), password: String(creds.password || ""), code: typeof creds.totp === "string" ? creds.totp : "" };
      creds = null;
      const r = await ext.tabs.sendMessage(w.tabId, fill, { frameId });
      return { filled: r && r.ok ? r.filled : 0, why: r && !r.ok ? r.why : "" };
    } finally {
      creds = null;
    }
  },

  async "panel:generate"(msg, sender) {
    const w = await where(msg, sender);
    if (!w.origin) throw fail("no-page", "no page");
    await stillThere(w);
    let g = await call("generate", { length: 24, symbols: true }, QUICK);
    const fill = { type: "fill", what: "new", origin: w.origin, handle: w.handle, password: String(g.password || "") };
    g = null;
    const r = await ext.tabs.sendMessage(w.tabId, fill, { frameId: frameFor(w, ["signup", "change"]) });
    return { filled: r && r.ok ? r.filled : 0, why: r && !r.ok ? r.why : "" };
  },

  async "panel:save"(msg, sender) {
    const w = await where(msg, sender);
    if (w.mode !== "popup") throw fail("denied", "a login is saved from the toolbar button");
    const o = offers.get(w.tabId);
    if (!o) throw fail("not-found", "nothing waits to be saved");
    if (msg.decision !== "save") {
      dropOffer(w.tabId);
      return { saved: false };
    }
    const title = typeof msg.title === "string" && msg.title.trim() !== "" ? msg.title.trim() : undefined;
    const r = await call("save", { vault: o.vault || undefined, origin: o.origin, username: o.username || undefined, password: o.password, login: o.login || undefined, title });
    dropOffer(w.tabId);
    return { saved: true, created: r.created === true };
  },

  async "panel:close"(msg, sender) {
    const w = await where(msg, sender);
    if (w.token) {
      panels.delete(w.token);
      ext.tabs.sendMessage(w.tabId, { type: "panel:close" }, { frameId: w.frameId }).catch(() => {});
    }
    return {};
  },
};

// shown is a login the panel was shown for this tab and origin.
function shown(w, id) {
  const l = listed.get(w.tabId);
  const login = l && l.origin === w.origin && typeof id === "string" ? l.logins.get(id) : null;
  if (!login) throw fail("not-found", "that login was not offered for this page");
  return login;
}

function formsOf(w) {
  const t = tabs.get(w.tabId);
  if (!t) return [];
  const out = new Set();
  for (const f of t.frames.values()) if (f.origin === w.origin) for (const k of f.forms) out.add(k);
  return [...out];
}

function isOurPage(sender) {
  return typeof sender.url === "string" && sender.url.startsWith(ext.runtime.getURL(""));
}

ext.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== ext.runtime.id || !msg || typeof msg.type !== "string") return false;
  const table = isOurPage(sender) ? fromPages : fromContent;
  if (!Object.hasOwn(table, msg.type)) return false;
  table[msg.type](msg, sender).then(
    (r) => sendResponse({ ok: true, ...r }),
    (e) => sendResponse({ ok: false, error: (e && e.code) || "failed", message: (e && e.message) || "" }),
  );
  return true;
});

ext.tabs.onRemoved.addListener((tabId) => forgetTab(tabId));
