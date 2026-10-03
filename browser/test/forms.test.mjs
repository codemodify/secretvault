import { test } from "node:test";
import assert from "node:assert/strict";
import { SVForms as F, forms } from "./load.mjs";

function one(html) {
  const [g] = forms(html);
  return { ...F.analyze(g.fields, g.hint), fields: g.fields };
}

test("a login form: a user name and its password", () => {
  const a = one(`<form action="/session">
    <input type="hidden" name="authenticity_token" value="x">
    <label for="login_field">Username or email address</label>
    <input type="text" name="login" id="login_field" autocomplete="username">
    <input type="password" name="password" id="password" autocomplete="current-password">
    <input type="submit" value="Sign in">
  </form>`);
  assert.equal(a.kind, "login");
  assert.equal(a.fields[a.username].name, "login");
  assert.equal(a.fields[a.password].name, "password");
  assert.deepEqual(a.newPasswords, []);
});

test("a login form that says nothing of itself", () => {
  const a = one(`<form><input name="q1"><input type="password" name="p"></form>`);
  assert.equal(a.kind, "login");
  assert.equal(a.username, 0);
  assert.equal(a.password, 1);
});

test("an e-mail address is a user name", () => {
  const a = one(`<form><input type="email" name="email"><input type="checkbox" name="remember"><input type="password" name="pass"></form>`);
  assert.equal(a.kind, "login");
  assert.equal(a.fields[a.username].name, "email");
});

test("a sign-up: new passwords, to generate", () => {
  const a = one(`<form id="register">
    <input type="email" name="email" autocomplete="email">
    <input type="password" name="password" autocomplete="new-password">
    <input type="password" name="password_confirmation">
  </form>`);
  assert.equal(a.kind, "signup");
  assert.deepEqual(a.newPasswords, [1, 2]);
  assert.equal(a.password, -1);
});

test("a sign-up with one password says so by its form", () => {
  const a = one(`<form id="signup-form"><input name="username"><input type="password" name="password"><button>Create account</button></form>`);
  assert.equal(a.kind, "signup");
  assert.deepEqual(a.newPasswords, [1]);
});

test("a change of password: the current one and new ones", () => {
  const a = one(`<form>
    <label for="o">Old password</label><input type="password" id="o" name="old">
    <label for="n">New password</label><input type="password" id="n" name="new">
    <label for="c">Confirm new password</label><input type="password" id="c" name="confirm">
  </form>`);
  assert.equal(a.kind, "change");
  assert.equal(a.password, 0);
  assert.deepEqual(a.newPasswords, [1, 2]);
});

test("three passwords that say nothing are a change", () => {
  const a = one(`<form><input type="password"><input type="password"><input type="password"></form>`);
  assert.equal(a.kind, "change");
  assert.equal(a.password, 0);
  assert.deepEqual(a.newPasswords, [1, 2]);
});

test("a one-time code", () => {
  for (const html of [
    `<form><input name="code" autocomplete="one-time-code" inputmode="numeric"></form>`,
    `<form><input name="otp" maxlength="6"></form>`,
    `<form><input name="verification_code" inputmode="numeric"></form>`,
    `<form><input type="tel" name="totp"></form>`,
  ]) {
    const a = one(html);
    assert.equal(a.kind, "otp", html);
    assert.equal(a.otp, 0, html);
    assert.equal(a.username, -1, html);
  }
});

test("a user name alone, before the password's page", () => {
  const a = one(`<form><input type="email" name="identifier" autocomplete="username"><button>Next</button></form>`);
  assert.equal(a.kind, "username");
  assert.equal(a.username, 0);
});

test("what is no login is left alone", () => {
  for (const html of [
    `<form role="search"><input type="search" name="q"></form>`,
    `<form><input type="email" name="newsletter"><button>Subscribe</button></form>`,
    `<form><input name="first_name"><input name="last_name"></form>`,
    `<form><input type="text" name="token"><input type="hidden" name="x"></form>`,
    `<form><input type="number" name="quantity"></form>`,
  ]) {
    const a = one(html);
    assert.equal(a.kind, null, html);
    assert.equal(a.username, -1, html);
  }
});

test("fields outside forms are one group", () => {
  const groups = forms(`<div><input name="user"><input type="password" name="pw"></div><form role="search"><input type="search"></form>`);
  assert.equal(groups.length, 2);
  const loose = groups[1];
  assert.equal(F.analyze(loose.fields, loose.hint).kind, "login");
});

test("kinds of single fields", () => {
  assert.equal(F.kind({ type: "password" }), "password");
  assert.equal(F.kind({ type: "password", autocomplete: "one-time-code" }), "otp");
  assert.equal(F.kind({ type: "hidden", name: "username" }), null);
  assert.equal(F.kind({ type: "submit" }), null);
  assert.equal(F.kind({ type: "email" }), "email");
  assert.equal(F.kind({ type: "text", name: "user_login" }), "username");
  assert.equal(F.kind({ type: "text", name: "city" }), "text");
  assert.equal(F.role({ type: "password", autocomplete: "new-password" }), "new");
  assert.equal(F.role({ type: "password", name: "current_password" }), "current");
  assert.equal(F.role({ type: "password", name: "pw" }), null);
});
