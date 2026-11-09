#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The tester's hand on the starter's page, for scripts/first_run_check.sh: a
// real browser (headless Chromium, through Playwright) presses the buttons a
// newcomer presses on http://127.0.0.1:3000 and reads back what the page
// shows. Playwright lives in the clean machine's image under FIRST_RUN_HAND,
// off PATH, apart from anything the newcomer types; this script is the only
// thing that uses it.
//
//   first_run_page.mjs offer            press "Show the connect code"; print the code the page shows
//   first_run_page.mjs send <amount>    on the ask form, pick the connected wallet, ask it to send
//                                       <amount> ERA, press Ask; wait until the page's table shows
//                                       THAT request (its connection and seq) with the fact
//                                       "received"; print the row
//
// Anything the page would alert (a refused request) fails the step with the
// page's own words. STARTER_URL overrides the page's address.

import { createRequire } from "node:module";
import path from "node:path";

const hand = process.env.FIRST_RUN_HAND;
if (!hand) {
  console.error("FIRST_RUN_HAND is not set: the directory Playwright is installed in");
  process.exit(2);
}
const { chromium } = createRequire(path.join(hand, "package.json"))("playwright");
const STARTER = process.env.STARTER_URL ?? "http://127.0.0.1:3000";
const [command, argument] = process.argv.slice(2);

function note(line) {
  console.error(`[page] ${line}`);
}

async function main() {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const alerts = [];
  page.on("dialog", async (dialog) => {
    alerts.push(dialog.message());
    await dialog.dismiss();
  });
  page.on("pageerror", (e) => note(`page error: ${e}`));
  await page.goto(STARTER);
  // The page has read its account.
  await page.waitForFunction(() => document.getElementById("account").textContent.startsWith("account "), null, { timeout: 60_000 });
  const title = await page.title();
  note(`opened ${STARTER}: "${title}"`);

  switch (command) {
    case "offer": {
      await page.click("#offer");
      await page.waitForFunction(
        () => !document.getElementById("offered").hidden && document.getElementById("code").textContent.startsWith("dsm:connect/v1:"),
        null,
        { timeout: 30_000 },
      );
      const code = (await page.textContent("#code")).trim();
      const qr = (await page.$("#qr svg")) !== null;
      note(`the page shows the connect code (${code.length} characters)${qr ? " and its QR" : ""}`);
      if (!qr) throw new Error("the page shows no QR for the code");
      console.log(code);
      break;
    }
    case "send": {
      const amount = argument;
      if (!amount) throw new Error("usage: first_run_page.mjs send <amount>");
      // The page lists the connected wallet once its next poll sees it.
      await page.waitForFunction(() => document.getElementById("ask-connection").value !== "", null, { timeout: 60_000 });
      const connection = await page.inputValue("#ask-connection");
      await page.selectOption("#ask-kind", "send");
      await page.fill("#ask-amount", amount);
      note(`asking wallet ${connection} to send ${amount} ${await page.inputValue("#ask-object")}`);
      const [response] = await Promise.all([
        page.waitForResponse((r) => r.request().method() === "POST" && new URL(r.url()).pathname === "/api/ask"),
        page.click("#ask-run"),
      ]);
      const answer = await response.json();
      if (!response.ok()) throw new Error(`the page's ask was refused: ${answer.error}`);
      const seq = String(answer.seq);
      note(`the ask is request ${seq}; watching its row in the page's table`);
      const row = `#requests tr[data-connection="${connection}"][data-seq="${seq}"]`;
      try {
        await page.waitForFunction(
          (selector) => {
            const tr = document.querySelector(selector);
            return tr !== null && tr.querySelector(".fact")?.textContent === "received";
          },
          row,
          { timeout: 240_000 },
        );
      } catch (e) {
        const shown = await page.$eval(row, (tr) => tr.innerText.replace(/\s+/g, " ")).catch(() => "(no row for this request)");
        throw new Error(`the page never showed request ${seq} received; it shows: ${shown}${alerts.length ? `; alerts: ${alerts.join(" | ")}` : ""}`);
      }
      const outcome = await page.$eval(`${row} td.outcome`, (td) => td.innerText.replace(/\s+/g, " ").trim());
      console.log(`the page shows request ${seq} on ${connection}: outcome ${outcome}, fact received`);
      break;
    }
    default:
      throw new Error(`usage: first_run_page.mjs offer | send <amount>`);
  }
  if (alerts.length > 0) throw new Error(`the page alerted: ${alerts.join(" | ")}`);
  await browser.close();
}

main().catch((e) => {
  console.error(`[page] ${e instanceof Error ? e.message : e}`);
  process.exit(1);
});
