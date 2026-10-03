import { test } from "node:test";
import assert from "node:assert/strict";
import { SVStyle as S } from "./load.mjs";

test("a colour's opacity, however the browser writes it", () => {
  const cases = {
    "rgb(0, 0, 0)": 1,
    "rgba(0, 0, 0, 0)": 0,
    "rgba(10, 20, 30, 0.5)": 0.5,
    "rgb(0 0 0 / 0)": 0,
    "rgb(0 0 0 / 15%)": 0.15,
    "oklch(0 0 0 / 0)": 0,
    "oklch(0.5 0.1 120)": 1,
    "lab(50 20 30 / 0.1)": 0.1,
    "color(srgb 1 0 0 / 0)": 0,
    "color(display-p3 1 0 0)": 1,
    transparent: 0,
    "": 1,
    currentcolor: 1,
  };
  for (const [c, want] of Object.entries(cases)) {
    assert.ok(Math.abs(S.alpha(c) - want) < 1e-9, c + ": " + S.alpha(c));
  }
});

test("filters that all but hide what they are on", () => {
  for (const f of ["opacity(0)", "opacity(0.2)", "opacity(10%)", "brightness(0)", "contrast(0.1)", "blur(8px)", "drop-shadow(0 0 2px red) opacity(0.01)", "url(\"#hide\")", "url(data:image/svg+xml,x) invert(1)"]) {
    assert.equal(S.hides(f), true, f);
  }
  for (const f of ["none", "", undefined, "opacity(0.9)", "brightness(1.2)", "drop-shadow(0 1px 2px rgb(0 0 0 / 0.2))", "blur(1px)", "invert(1)", "grayscale(1)"]) {
    assert.equal(S.hides(f), false, String(f));
  }
});
