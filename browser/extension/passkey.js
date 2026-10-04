// secretvault's passkey window: where the person chooses one of
// secretvault's passkeys to sign in with, or saves a new one, or leaves it
// to the browser (another device, a security key, the computer's own).
// It is an extension page in a window of the browser's, which no page can
// draw over, script or click in; it holds no secret. A click or a key
// meant for the page must not land on it: its buttons take no click for a
// moment after it shows, gets the focus, or changes; nothing in it takes
// the focus by itself; and a button pressed from the keyboard counts only
// once it has held the focus a moment (the person tabbed to it, and saw
// it), not when typing ran on into the window.
"use strict";

const ext = globalThis.browser ?? globalThis.chrome;
const token = location.hash.length > 1 ? location.hash.slice(1) : "";
const $ = (id) => document.getElementById(id);

const ARM_MS = 600;
const KEY_MS = 800;
let armedAt = performance.now() + ARM_MS;
let view = null;
let busy = false;
let focusedAt = 0; // when the element with the focus got it

function rearm() {
  armedAt = performance.now() + ARM_MS;
}

document.addEventListener("visibilitychange", rearm);
window.addEventListener("focus", rearm);
document.addEventListener("focusin", () => {
  focusedAt = performance.now();
});

function armed() {
  return performance.now() >= armedAt && document.visibilityState === "visible" && document.hasFocus() && !busy;
}

function act(fn) {
  return (e) => {
    if (!e || e.isTrusted !== true || !armed()) return;
    if (e.detail === 0) {
      // From the keyboard: on the button that has had the focus a moment.
      if (document.activeElement !== e.currentTarget || performance.now() - focusedAt < KEY_MS) return;
    }
    fn();
  };
}

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
  $("status").replaceChildren(...parts.map((p) => (typeof p === "string" ? el("p", null, p) : p)));
}

function warn(text) {
  status(el("p", "warn", text));
}

function words(e) {
  switch (e.code) {
    case "denied":
      return "secretvault said no. You can choose again, or use another device.";
    case "locked":
      return "The vault is locked.";
    case "not-found":
      return "That passkey is not there any more.";
    case "busy":
      return "secretvault is already on it.";
    case "timeout":
      return "secretvault did not answer in time.";
    case "not-installed":
    case "not-running":
      return "secretvault is not running.";
  }
  return e.message || "Something went wrong.";
}

function chosenVault() {
  const s = view && view.state;
  return s && s.vaults ? s.vaults.find((v) => v.name === s.vault) || null : null;
}

function renderVaults() {
  const s = view.state;
  const vs = (s && s.vaults) || [];
  $("vaults").hidden = vs.length < 2;
  $("vault").replaceChildren(
    ...vs.map((v) => {
      const o = el("option", null, v.name + (v.default ? " (default)" : "") + (v.locked ? " — locked" : ""));
      o.value = v.name;
      o.selected = v.name === s.vault;
      return o;
    }),
  );
}

function render() {
  rearm(); // what was just drawn takes no click yet
  const v = chosenVault();
  const site = view.rpId;
  const where = view.top ? " The sign-in is in a frame of " + view.site + ", on " + view.top + "." : "";
  $("verify").hidden = !view.verify;
  renderVaults();
  if (view.kind === "create") {
    $("title").textContent = "Save a passkey for " + site + "?";
    const who = view.userName || view.userDisplayName;
    $("about").textContent = "A passkey signs you in to " + site + (who ? " as " + who : "") + " without a password. secretvault keeps it in vault " +
      (v ? v.name : "") + ", and uses it only when you choose it." + where;
    $("choose").hidden = true;
    if (!$("name").value) $("name").value = view.rpName || site;
  } else {
    $("title").textContent = "Sign in to " + site;
    $("about").textContent = "Choose a passkey secretvault keeps for " + site + "." + where;
    $("save").hidden = true;
  }
  if (!view.state || !view.state.running) {
    $("choose").hidden = true;
    $("save").hidden = true;
    status(el("p", "warn", "secretvault is not running."));
    return;
  }
  if (v && v.locked) {
    $("choose").hidden = true;
    $("save").hidden = true;
    const unlock = el("button", "primary", "Unlock vault " + v.name);
    unlock.type = "button";
    unlock.addEventListener("click", act(async () => {
      busy = true;
      status("secretvault is asking for the passphrase of vault " + v.name + ", in a window of its own.");
      try {
        view = await ask("passkey:unlock", { vault: v.name });
        busy = false;
        status();
        render();
      } catch (e) {
        busy = false;
        warn(words(e));
      }
    }));
    status(el("p", null, "Vault " + v.name + " is locked."), unlock);
    return;
  }
  status();
  if (view.kind === "create") {
    $("save").hidden = false;
    return;
  }
  $("choose").hidden = false;
  const ul = $("passkeys");
  ul.replaceChildren();
  if (view.passkeys.length === 0) {
    status("No passkey for " + site + " in vault " + (v ? v.name : "") + ".");
    return;
  }
  for (const k of view.passkeys) {
    const li = el("li");
    const b = el("button", "login");
    b.type = "button";
    b.append(el("span", "title", k.userName || k.userDisplayName || k.title));
    b.append(el("span", "user", k.title + (k.userDisplayName && k.userName ? " · " + k.userDisplayName : "")));
    b.addEventListener("click", act(() => use(k)));
    li.append(b);
    ul.append(li);
  }
}

async function use(k) {
  busy = true;
  status("Asking secretvault to sign in with " + (k.userName || k.title) + "…");
  try {
    await ask("passkey:use", { login: k.id });
    // The window closes: the page has its answer.
  } catch (e) {
    busy = false;
    warn(words(e));
  }
}

async function save() {
  busy = true;
  status("Asking secretvault to save the passkey…");
  try {
    await ask("passkey:save", { title: $("name").value });
  } catch (e) {
    busy = false;
    warn(words(e));
  }
}

async function start() {
  try {
    view = await ask("passkey:init");
  } catch (e) {
    warn(words(e));
    return;
  }
  render();
}

$("save-button").addEventListener("click", act(save));
$("other").addEventListener("click", act(() => ask("passkey:other").catch(() => window.close())));
$("cancel").addEventListener("click", () => ask("passkey:cancel").catch(() => window.close())); // Cancel is always safe
$("vault").addEventListener("change", async () => {
  try {
    view = await ask("passkey:vault", { vault: $("vault").value });
    render();
  } catch (e) {
    warn(words(e));
  }
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") ask("passkey:cancel").catch(() => window.close());
});
// While the person decides, the background is kept running.
setInterval(() => ask("passkey:alive").catch(() => {}), 20 * 1000);

start();
