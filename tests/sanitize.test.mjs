/**
 * Sanitiser tests. Run: node --test tests/
 *
 * Every case in the "attacks" block is a payload that got past an earlier
 * version of a real guard. They are regression tests, not hypotheticals.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { JSDOM } from "jsdom";

// Provide DOMParser/Node to the module under test.
const dom = new JSDOM("");
globalThis.DOMParser = dom.window.DOMParser;
globalThis.Node = dom.window.Node;

const { sanitize, esc } = await import("../app/js/sanitize.js");

test("keeps allowlisted formatting", () => {
  const out = sanitize("<p>Hello <strong>there</strong></p>");
  assert.equal(out, "<p>Hello <strong>there</strong></p>");
});

test("keeps tables, which real content depends on", () => {
  const out = sanitize("<table><tr><td colspan=\"2\">A</td></tr></table>");
  assert.match(out, /<td colspan="2">A<\/td>/);
});

test("unwraps unknown tags instead of deleting their content", () => {
  // Deleting would silently eat the paragraph. That is data loss, and the
  // author does not notice until much later.
  const out = sanitize("<section><p>keep me</p></section>");
  assert.equal(out, "<p>keep me</p>");
});

test("removes script entirely rather than unwrapping it", () => {
  // Unwrapping would paste the source into the page as visible text.
  const out = sanitize("<script>alert(1)</script><p>ok</p>");
  assert.equal(out, "<p>ok</p>");
});

test("drops comments", () => {
  assert.equal(sanitize("<!--[if IE]><script>x</script><![endif]--><p>a</p>"), "<p>a</p>");
});

test("preserves plain text", () => {
  assert.equal(sanitize("just words"), "just words");
});

test("empty input is safe", () => {
  assert.equal(sanitize(""), "");
  assert.equal(sanitize(null), "");
  assert.equal(sanitize(undefined), "");
});

// ---------------------------------------------------------------
// Attacks that defeated an earlier denylist version of this guard
// ---------------------------------------------------------------

test("attack: slash separator with no whitespace", () => {
  // <img/src=x/onerror=...> contains no whitespace at all, so any guard
  // matching /\son[a-z]+=/ misses it completely.
  const out = sanitize('<img/src=x/onerror=alert(1)>');
  assert.ok(!out.includes("onerror"), out);
  assert.ok(!out.includes("<img"), out);
});

test("attack: event handler on an allowlisted tag", () => {
  const out = sanitize('<p onclick="steal()">text</p>');
  assert.equal(out, "<p>text</p>");
});

test("attack: javascript: url", () => {
  const out = sanitize('<a href="javascript:alert(1)">click</a>');
  assert.ok(!out.includes("javascript"), out);
  assert.ok(!out.includes("href"), out);
});

test("attack: javascript: url split by a control character", () => {
  // A plain string match for "javascript:" does not see this. Browsers do.
  const out = sanitize('<a href="java\tscript:alert(1)">click</a>');
  assert.ok(!/href/.test(out), out);
});

test("attack: data: url", () => {
  const out = sanitize('<a href="data:text/html;base64,PHNjcmlwdD4=">x</a>');
  assert.ok(!out.includes("href"), out);
});

test("attack: svg payload", () => {
  const out = sanitize('<svg><animate onbegin=alert(1)></svg>');
  assert.ok(!out.includes("onbegin"), out);
  assert.ok(!out.includes("svg"), out);
});

test("attack: style attribute is stripped", () => {
  const out = sanitize('<p style="background:url(javascript:alert(1))">x</p>');
  assert.equal(out, "<p>x</p>");
});

test("attack: nested payload survives unwrapping of its parent", () => {
  const out = sanitize('<section><img src=x onerror=alert(1)><p>keep</p></section>');
  assert.ok(!out.includes("onerror"), out);
  assert.ok(out.includes("keep"), out);
});

// ---------------------------------------------------------------
// False positives: real content that a denylist wrongly refused
// ---------------------------------------------------------------

test("prose containing 'on... =' is not an attack", () => {
  // A guard matching /\son[a-z]+\s*=/ unanchored refuses this ordinary line.
  const text = "<p>Plan only = referral required</p>";
  assert.equal(sanitize(text), text);
});

test("comparison operators in prose survive", () => {
  const out = sanitize("<p>Use when count &gt; 5 and age &lt; 18</p>");
  assert.match(out, /count &gt; 5/);
});

// ---------------------------------------------------------------
// Link hardening
// ---------------------------------------------------------------

test("safe links keep href and gain rel", () => {
  const out = sanitize('<a href="https://example.com">x</a>');
  assert.match(out, /href="https:\/\/example\.com"/);
  assert.match(out, /rel="noopener noreferrer"/);
});

test("relative and anchor links are allowed", () => {
  assert.match(sanitize('<a href="/page">x</a>'), /href="\/page"/);
  assert.match(sanitize('<a href="#section">x</a>'), /href="#section"/);
});

test("mailto and tel are allowed", () => {
  assert.match(sanitize('<a href="mailto:a@b.com">x</a>'), /mailto:/);
  assert.match(sanitize('<a href="tel:+123">x</a>'), /tel:/);
});

// ---------------------------------------------------------------

test("esc escapes every dangerous character", () => {
  assert.equal(esc(`<&">'`), "&lt;&amp;&quot;&gt;&#39;");
  assert.equal(esc("<script>"), "&lt;script&gt;");
  assert.equal(esc(null), "");
  assert.equal(esc(undefined), "");
});
