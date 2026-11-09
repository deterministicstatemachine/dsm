#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0

// dsm-dev-wallet: a player's wallet in the terminal, for trying an application
// without a phone. It is a second dsm-app-host (`make dev-wallet`) on the same
// SDK path a phone runs; this only names its routes.
//
//   dsm-dev-wallet id                     this wallet's identity
//   dsm-dev-wallet fund                   ERA from the development set's faucet, unless it holds some
//   dsm-dev-wallet owned                  what it owns
//   dsm-dev-wallet connect <code>         read a dsm:connect/v1: code and approve it
//   dsm-dev-wallet connections            every application it is connected to
//   dsm-dev-wallet sync                   fetch and carry out what applications asked
//   dsm-dev-wallet pending                requests waiting for approval
//   dsm-dev-wallet approve <connection> <seq>
//   dsm-dev-wallet decline <connection> <seq>
//   dsm-dev-wallet log <connection>       what an application asked, and what came of it
//   dsm-dev-wallet disconnect <connection>
//
// DSM_WALLET_NAME picks the wallet (`wallet`, the default, or `wallet2`).

import { pb } from "./index.js";
import { localAccount } from "./local.js";
import type { Connection } from "./results.js";

function usage(): never {
  console.error(
    "usage: dsm-dev-wallet id | fund | owned | connect <code> | connections | sync | pending |\n" +
      "       approve <connection> <seq> | decline <connection> <seq> | log <connection> | disconnect <connection>",
  );
  process.exit(2);
}

function arg(args: string[], index: number): string {
  const value = args[index];
  if (value === undefined || value.length === 0) usage();
  return value;
}

function show(c: Connection): void {
  console.log(`connection ${c.id}  ${c.name}  ${c.connected ? "CONNECTED" : "DISCONNECTED"}`);
  for (const line of c.grants) console.log(`  grants: ${line}`);
  for (const s of c.spent) console.log(`  used:   ${s.spent} of ${s.total} ${s.symbol}`);
  if (c.lastError.length > 0) console.log(`  last sync: ${c.lastError}`);
}

async function main(args: string[]): Promise<void> {
  const name = process.env.DSM_WALLET_NAME === "wallet2" ? "wallet2" : "wallet";
  const wallet = await localAccount(name);
  switch (args[0]) {
    case "id":
      console.log(await wallet.id());
      return;
    case "fund": {
      const era = await wallet.owns("ERA").catch(() => undefined);
      if (era !== undefined && era.amount > 0n) {
        console.log(`already holds ${era.display} ERA`);
        return;
      }
      for (let attempt = 1; attempt <= 120; attempt++) {
        const claim = await wallet.fund();
        if (claim.funded) {
          console.log(`funded: ${claim.message}`);
          return;
        }
        if (attempt === 1) console.log(`waiting for the faucet: ${claim.message}`);
        await new Promise((r) => setTimeout(r, 500));
      }
      throw new Error("the faucet did not fund this wallet within a minute");
    }
    case "owned":
      for (const o of await wallet.owned()) {
        console.log(`${o.object.symbol.padEnd(8)} ${o.display.padStart(16)}   ${o.object.kind.padEnd(8)} ${o.object.id}`);
      }
      return;
    case "connect": {
      const preview = await wallet.preview(arg(args, 1));
      console.log(`${preview.name} (account ${preview.app}) asks to:`);
      for (const line of preview.asks) console.log(`  - ${line}`);
      console.log("approved:");
      show(await wallet.approve(preview));
      return;
    }
    case "connections":
      for (const c of await wallet.connections()) show(c);
      return;
    case "sync":
      for (const c of await wallet.sync()) show(c);
      return;
    case "pending": {
      const waiting = await wallet.pending();
      if (waiting.length === 0) console.log("nothing waiting");
      for (const p of waiting) {
        console.log(`${p.connection} ${p.seq}  ${p.from}: ${p.summary}`);
        console.log(`  why it waits: ${p.reason}${p.approved ? " (approved; goes through on the next sync)" : ""}`);
      }
      return;
    }
    case "approve":
    case "decline": {
      const decided = await wallet.respond(arg(args, 1), BigInt(arg(args, 2)), args[0]);
      console.log(`${pb.ConnectOutcome[decided.outcome]}: ${decided.line}`);
      return;
    }
    case "log": {
      const log = await wallet.log(arg(args, 1));
      for (const e of log.entries) {
        console.log(`${e.seq}  ${e.summary}  ${pb.ConnectOutcome[e.outcome]}  ${e.detail}`);
      }
      return;
    }
    case "disconnect":
      show(await wallet.disconnect(arg(args, 1)));
      return;
    default:
      usage();
  }
}

main(process.argv.slice(2)).catch((e: unknown) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
