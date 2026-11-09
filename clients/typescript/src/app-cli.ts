#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0

// dsm-app: your application's account from the terminal, through the same
// client your code uses. `make app-dev` runs the account.
//
//   dsm-app id                               this account's device id
//   dsm-app fund                             claim the faucet, unless it already holds ERA
//   dsm-app balances                         what it holds
//   dsm-app offer <name> <ticker> <per-request> <total>
//                                            a connect code asking to be paid in <ticker>
//   dsm-app sessions                         every connected wallet
//   dsm-app pay <session> <ticker> <amount>  ask a wallet to pay this account
//   dsm-app holdings <session> <ticker>      ask a wallet to prove what it holds
//   dsm-app status <session> <seq>           what became of a request
//   dsm-app activity [after]                 what calls and wallets did to this account

import { decodeId, encodeB32 } from "./b32.js";
import { intent, scope } from "./account.js";
import { pb } from "./index.js";
import { localAccount } from "./local.js";

function usage(): never {
  console.error(
    "usage: dsm-app id | fund | balances | offer <name> <ticker> <per-request> <total> | sessions |\n" +
      "       pay <session> <ticker> <amount> | holdings <session> <ticker> | status <session> <seq> |\n" +
      "       activity [after]",
  );
  process.exit(2);
}

function arg(args: string[], index: number): string {
  const value = args[index];
  if (value === undefined || value.length === 0) usage();
  return value;
}

async function main(args: string[]): Promise<void> {
  const app = await localAccount("app");
  switch (args[0]) {
    case "id":
      console.log(await app.id());
      return;
    case "fund": {
      const held = (await app.balances()).find((b) => b.symbol === "ERA" && b.available > 0n);
      if (held !== undefined) {
        console.log(`already holds ${held.displayAmount} ERA`);
        return;
      }
      for (let attempt = 1; attempt <= 120; attempt++) {
        const claim = await app.claimFaucet();
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
      for (const b of await app.balances()) {
        console.log(`${b.symbol.padEnd(8)} ${b.displayAmount.padStart(16)}   policy ${b.policyAnchorB32}`);
      }
      return;
    case "offer": {
      const token = await app.policyCommitOf(arg(args, 2));
      const offer = await app.offer({
        displayName: arg(args, 1),
        scopes: [scope.pay(token, BigInt(arg(args, 3)), BigInt(arg(args, 4))), scope.holdings([token])],
        freeRequests: 64,
      });
      console.log(offer.code);
      return;
    }
    case "sessions":
      for (const s of await app.sessions()) {
        console.log(
          `session ${encodeB32(s.sessionId)}  wallet ${encodeB32(s.peerDeviceId)}  ${pb.ConnectSessionStatus[s.status]}`,
        );
      }
      return;
    case "pay": {
      const token = await app.policyCommitOf(arg(args, 2));
      const ref = await app.request(
        decodeId(arg(args, 1), "the session id"),
        intent.pay(token, BigInt(arg(args, 3)), "dsm-app pay"),
      );
      console.log(`request ${ref.seq}`);
      return;
    }
    case "holdings": {
      const token = await app.policyCommitOf(arg(args, 2));
      const ref = await app.request(decodeId(arg(args, 1), "the session id"), intent.holdings([token]));
      console.log(`request ${ref.seq}`);
      return;
    }
    case "status": {
      const s = await app.status({ sessionId: decodeId(arg(args, 1), "the session id"), seq: BigInt(arg(args, 2)) });
      console.log(`answered: ${s.answered ? "yes" : "no"}  outcome: ${pb.ConnectOutcome[s.outcome]}  ${s.reason}`);
      console.log(`fact: ${pb.ConnectFact[s.fact]}  ${s.factDetail}`);
      for (const h of s.holdings) console.log(`  holds ${h.amount} of ${encodeB32(h.policyCommit)}`);
      return;
    }
    case "activity": {
      const after = args[1] === undefined ? 0n : BigInt(args[1]);
      const activity = await app.ingress.activity(after);
      for (const e of activity.entries) {
        const outcome = e.error.length > 0 ? `refused: ${e.error}` : e.result;
        console.log(`${e.seq}  ${pb.AppHostActivityKind[e.kind]}  ${e.name}  ${e.summary}  -> ${outcome}`);
      }
      return;
    }
    default:
      usage();
  }
}

main(process.argv.slice(2)).catch((e: unknown) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
