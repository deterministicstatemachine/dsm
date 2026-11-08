#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0

// dsm-dev-wallet: a player's wallet in the terminal, for testing a Connect
// application without a phone. It is a second dsm-app-host (`make dev-wallet`)
// on the same SDK path a phone runs; this only names its routes.
//
//   dsm-dev-wallet id                     this wallet's device id
//   dsm-dev-wallet fund                   claim the faucet, unless it already holds ERA
//   dsm-dev-wallet balances               what it holds
//   dsm-dev-wallet connect <code>         preview a dsm:connect/v1: code and approve it
//   dsm-dev-wallet sessions               every connected application
//   dsm-dev-wallet sync                   fetch and carry out what applications asked
//   dsm-dev-wallet pending                requests waiting for approval
//   dsm-dev-wallet approve <session> <seq>
//   dsm-dev-wallet decline <session> <seq>
//   dsm-dev-wallet log <session>          what an application asked, and what came of it
//   dsm-dev-wallet disconnect <session>

import { decodeId, encodeB32 } from "./b32.js";
import { pb } from "./index.js";
import { localAccount } from "./local.js";

function usage(): never {
  console.error(
    "usage: dsm-dev-wallet id | fund | balances | connect <code> | sessions | sync | pending |\n" +
      "       approve <session> <seq> | decline <session> <seq> | log <session> | disconnect <session>",
  );
  process.exit(2);
}

function arg(args: string[], index: number): string {
  const value = args[index];
  if (value === undefined || value.length === 0) usage();
  return value;
}

function showSession(s: pb.ConnectSessionV1): void {
  console.log(`session ${encodeB32(s.sessionId)}  ${s.displayName}  ${pb.ConnectSessionStatus[s.status]}`);
  for (const line of s.scopeLines) console.log(`  grants: ${line}`);
  for (const spent of s.spent) console.log(`  spent:  ${spent.spentDisplay} of ${spent.totalDisplay} ${spent.symbol}`);
  if (s.lastError.length > 0) console.log(`  last sync: ${s.lastError}`);
}

async function main(args: string[]): Promise<void> {
  const wallet = await localAccount("wallet");
  switch (args[0]) {
    case "id":
      console.log(await wallet.id());
      return;
    case "fund": {
      const held = (await wallet.balances()).find((b) => b.symbol === "ERA" && b.available > 0n);
      if (held !== undefined) {
        console.log(`already holds ${held.displayAmount} ERA`);
        return;
      }
      for (let attempt = 1; attempt <= 120; attempt++) {
        const claim = await wallet.claimFaucet();
        if (claim.success) {
          console.log(`claimed ${claim.tokensReceived} base units: ${claim.message}`);
          return;
        }
        if (attempt === 1) console.log(`waiting for the faucet: ${claim.message}`);
        await new Promise((r) => setTimeout(r, 500));
      }
      throw new Error("the faucet did not pay within a minute");
    }
    case "balances":
      for (const b of await wallet.balances()) {
        console.log(`${b.symbol.padEnd(8)} ${b.displayAmount.padStart(16)}   policy ${b.policyAnchorB32}`);
      }
      return;
    case "connect": {
      const code = arg(args, 1);
      const preview = await wallet.preview(code);
      console.log(`${preview.displayName} (account ${encodeB32(preview.appDeviceId)}) asks for:`);
      for (const line of preview.scopeLines) console.log(`  - ${line}`);
      const session = await wallet.approve(preview.offerDigest);
      console.log("approved:");
      showSession(session);
      return;
    }
    case "sessions":
      for (const s of await wallet.sessions()) showSession(s);
      return;
    case "sync":
      for (const s of await wallet.sync()) showSession(s);
      return;
    case "pending": {
      const waiting = await wallet.pending();
      if (waiting.length === 0) console.log("nothing waiting");
      for (const p of waiting) {
        console.log(`${encodeB32(p.sessionId)} ${p.seq}  ${p.displayName}: ${p.summary}`);
        console.log(`  why it waits: ${p.reason}${p.approved ? " (approved; settles on the next sync)" : ""}`);
      }
      return;
    }
    case "approve":
    case "decline": {
      const decided = await wallet.respond(
        decodeId(arg(args, 1), "the session id"),
        BigInt(arg(args, 2)),
        args[0],
      );
      console.log(`${pb.ConnectOutcome[decided.outcome]}: ${decided.line}`);
      return;
    }
    case "log": {
      const log = await wallet.log(decodeId(arg(args, 1), "the session id"));
      console.log(log.toJsonString({ prettySpaces: 2 }));
      return;
    }
    case "disconnect":
      showSession(await wallet.disconnect(decodeId(arg(args, 1), "the session id")));
      return;
    default:
      usage();
  }
}

main(process.argv.slice(2)).catch((e: unknown) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
