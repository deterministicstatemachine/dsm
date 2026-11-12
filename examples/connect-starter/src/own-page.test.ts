// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The starter answers its own page and no other caller on the machine.

import assert from "node:assert/strict";
import { test } from "node:test";
import { fromOwnPage, type Caller } from "./own-page.js";

const PORT = 3000;
const page: Caller = { method: "POST", host: "127.0.0.1:3000", origin: "http://127.0.0.1:3000", contentType: "application/json" };

test("the starter's own page is answered, by either name of the address", () => {
  assert.equal(fromOwnPage(page, PORT), true);
  assert.equal(fromOwnPage({ ...page, host: "localhost:3000", origin: "http://localhost:3000" }, PORT), true);
  assert.equal(fromOwnPage({ ...page, contentType: "application/json; charset=utf-8" }, PORT), true);
});

test("a caller that sends no Origin (a script, curl) is answered", () => {
  assert.equal(fromOwnPage({ method: "GET", host: "127.0.0.1:3000", origin: undefined, contentType: undefined }, PORT), true);
  assert.equal(fromOwnPage({ ...page, origin: undefined }, PORT), true);
});

test("another site's page is refused", () => {
  assert.equal(fromOwnPage({ ...page, origin: "https://elsewhere.example" }, PORT), false);
  assert.equal(fromOwnPage({ ...page, origin: "http://127.0.0.1:8080" }, PORT), false);
  assert.equal(fromOwnPage({ ...page, origin: "null" }, PORT), false);
});

test("a name pointed at this machine is refused", () => {
  assert.equal(fromOwnPage({ ...page, host: "rebound.example:3000", origin: undefined }, PORT), false);
  assert.equal(fromOwnPage({ ...page, host: undefined }, PORT), false);
  assert.equal(fromOwnPage({ ...page, host: "127.0.0.1:3001" }, PORT), false);
});

test("a POST a page could send without asking first is refused", () => {
  assert.equal(fromOwnPage({ ...page, origin: undefined, contentType: "text/plain" }, PORT), false);
  assert.equal(fromOwnPage({ ...page, origin: undefined, contentType: undefined }, PORT), false);
  assert.equal(fromOwnPage({ ...page, origin: undefined, contentType: "application/x-www-form-urlencoded" }, PORT), false);
});
