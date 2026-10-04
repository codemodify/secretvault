// Loads the extension's classic scripts (each adds its namespace to the
// global object, as in the browser) and the bundled Public Suffix List.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const ext = new URL("../extension/", import.meta.url);

await import(new URL("lib/psl.js", ext));
await import(new URL("lib/origin.js", ext));
await import(new URL("lib/webauthn.js", ext));
await import(new URL("lib/protocol.js", ext));
await import(new URL("lib/forms.js", ext));
await import(new URL("lib/style.js", ext));

export const { SVPSL, SVOrigin, SVWebAuthn, SVProtocol, SVForms, SVStyle } = globalThis;

export const list = SVPSL.parse(readFileSync(fileURLToPath(new URL("data/public_suffix_list.dat", ext)), "utf8"));

export function manifest() {
  return JSON.parse(readFileSync(fileURLToPath(new URL("manifest.json", ext)), "utf8"));
}

// form reads fixture HTML into the descriptions content.js makes of a
// form's fields: {fields, hint} per <form> (fields outside any form are
// one more group). Only what the tests need: <form>, <input>, <label for>.
export function forms(html) {
  const attrs = (tag) => {
    const out = {};
    for (const m of tag.matchAll(/([a-zA-Z-]+)(?:\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+)))?/g)) {
      out[m[1].toLowerCase()] = m[3] ?? m[4] ?? m[5] ?? "";
    }
    return out;
  };
  const labels = {};
  for (const m of html.matchAll(/<label\s+for="([^"]+)"[^>]*>([^<]*)<\/label>/g)) labels[m[1]] = m[2].trim();
  const describe = (tag) => {
    const a = attrs(tag.replace(/^<input/i, "").replace(/\/?>$/, ""));
    return {
      type: a.type || "text",
      name: a.name || "",
      id: a.id || "",
      autocomplete: a.autocomplete || "",
      placeholder: a.placeholder || "",
      label: labels[a.id] || "",
      ariaLabel: a["aria-label"] || "",
      inputmode: a.inputmode || "",
      maxLength: a.maxlength ? Number(a.maxlength) : undefined,
    };
  };
  const groups = [];
  const rest = html.replace(/<form([^>]*)>([\s\S]*?)<\/form>/gi, (_, head, body) => {
    const a = attrs(head);
    const button = (body.match(/<button[^>]*>([^<]*)<\/button>/i) || [])[1] || "";
    groups.push({ hint: [a.id, a.name, a.action, a.class, button].filter(Boolean).join(" "), fields: [...body.matchAll(/<input\b[^>]*>/gi)].map((m) => describe(m[0])) });
    return "";
  });
  const loose = [...rest.matchAll(/<input\b[^>]*>/gi)].map((m) => describe(m[0]));
  if (loose.length > 0) groups.push({ hint: "", fields: loose });
  return groups;
}
