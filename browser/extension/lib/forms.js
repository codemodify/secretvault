// What the fields of a form are for: a login (a user name and its
// password), a sign-up (new passwords), a change of password (the current
// one and new ones), a one-time code, or a user name alone (sites that
// ask for the password on the next page).
//
// It works on plain descriptions of the fields, not on the page, so it
// can be tested without a browser: content.js describes each visible
// field ({type, name, id, autocomplete, placeholder, label, inputmode,
// maxLength}) in page order and acts on what this says.
(function (root) {
  "use strict";

  const USER = /user|login|e-?mail|account|identifier|uname|nick|benutzer|usuario|utilisateur/i;
  const OTP = /one.?time|otp|totp|2fa|mfa|two.?factor|verification.?code|verify.?code|auth.?code|security.?code|passcode|token|sms.?code/i;
  const OTP_STRONG = /one.?time.?code|\botp\b|totp|2fa|mfa|two.?factor/i;
  const NEW = /new|confirm|repeat|retype|again|re-?enter|verif|create|register|sign.?up|choose/i;
  const CURRENT = /current|old|existing/i;
  const SIGNUP = /sign.?up|register|registration|create.?(an.?)?account|join|enrol/i;
  const IGNORED = new Set(["hidden", "checkbox", "radio", "submit", "button", "reset", "file", "image", "color", "date", "datetime-local", "month", "week", "time", "range", "search"]);
  const TEXTUAL = new Set(["text", "email", "tel", "number", "url", ""]);

  function tokens(autocomplete) {
    return String(autocomplete || "")
      .toLowerCase()
      .split(/\s+/)
      .filter(Boolean);
  }

  function words(d) {
    return [d.name, d.id, d.placeholder, d.label, d.ariaLabel].filter(Boolean).join(" ");
  }

  // kind says what one field is: "password", "otp", "username", "email",
  // "text" (it might hold a user name) or null (nothing of ours).
  function kind(d) {
    const type = String(d.type || "text").toLowerCase();
    const ac = tokens(d.autocomplete);
    if (type === "password") return ac.includes("one-time-code") ? "otp" : "password";
    if (IGNORED.has(type) || !TEXTUAL.has(type)) return null;
    if (ac.includes("one-time-code")) return "otp";
    const w = words(d);
    const short = Number.isInteger(d.maxLength) && d.maxLength >= 4 && d.maxLength <= 10;
    const numeric = d.inputmode === "numeric" || type === "number" || type === "tel";
    if (OTP_STRONG.test(w) || (OTP.test(w) && (short || numeric))) return "otp";
    if (ac.includes("username")) return "username";
    if (ac.includes("email") || type === "email") return "email";
    if (USER.test(w)) return "username";
    if (type === "number" || type === "tel" || type === "url") return null;
    return "text";
  }

  // role says what a password field is for, when it says so itself:
  // "current", "new", or null.
  function role(d) {
    const ac = tokens(d.autocomplete);
    if (ac.includes("new-password")) return "new";
    if (ac.includes("current-password")) return "current";
    const w = words(d);
    if (CURRENT.test(w)) return "current";
    if (NEW.test(w)) return "new";
    return null;
  }

  // analyze says what a form's fields are for. fields are the form's
  // visible fields, in page order; hint is what the form says of itself
  // (its name, id, action, the text of its button), which tells a sign-up
  // with one password from a login. Indexes are into fields; -1 for none.
  function analyze(fields, hint) {
    const kinds = fields.map(kind);
    const pw = [];
    kinds.forEach((k, i) => k === "password" && pw.push(i));
    const roles = pw.map((i) => role(fields[i]));

    // Passwords that do not say what they are for, by their company.
    const firstNew = roles.indexOf("new");
    pw.forEach((fi, j) => {
      if (roles[j] !== null) return;
      if (roles.includes("current") && !roles.includes("new")) roles[j] = "new";
      else if (firstNew >= 0) roles[j] = j < firstNew ? "current" : "new";
      else if (pw.length >= 3) roles[j] = j === 0 ? "current" : "new";
      else if (pw.length === 2) roles[j] = "new"; // a password and its confirmation
      else roles[j] = SIGNUP.test(hint || "") ? "new" : "current";
    });

    const current = pw.filter((_, j) => roles[j] === "current");
    const fresh = pw.filter((_, j) => roles[j] === "new");
    const otp = kinds.indexOf("otp");

    // The user name: the nearest field before the first password that is
    // one (by its type or words), else the nearest plain text field.
    const before = pw.length > 0 ? pw[0] : fields.length;
    let username = -1;
    for (let i = before - 1; i >= 0; i--) {
      if (kinds[i] === "username" || kinds[i] === "email") {
        username = i;
        break;
      }
    }
    if (username < 0 && pw.length > 0) {
      for (let i = before - 1; i >= 0; i--) {
        if (kinds[i] === "text") {
          username = i;
          break;
        }
        if (kinds[i] !== null) break;
      }
    }

    let what = null;
    if (current.length > 0 && fresh.length > 0) what = "change";
    else if (fresh.length > 0) what = "signup";
    else if (current.length > 0) what = "login";
    else if (otp >= 0) what = "otp";
    else if (username >= 0 && (kinds[username] === "username" || tokens(fields[username].autocomplete).includes("email"))) what = "username";
    if (what === null || what === "otp") username = -1;

    return { kind: what, username, password: current.length > 0 ? current[0] : -1, newPasswords: fresh, otp };
  }

  root.SVForms = Object.freeze({ kind, role, analyze });
})(globalThis);
