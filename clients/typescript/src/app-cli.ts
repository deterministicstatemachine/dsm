#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0

// dsm-app: your application's account from the terminal, through the same
// client your code uses. `make app-dev` runs the account.
//
//   dsm-app id                                   this account's identity
//   dsm-app fund                                 ERA from the development set's faucet, unless it holds some
//   dsm-app owned                                what it owns
//   dsm-app issue <SYMBOL> <name> <supply> [decimals]
//                                                issue a new object; this account holds the supply
//   dsm-app give <wallet> <object> <amount>      give a connected wallet some of an object
//   dsm-app offer <name> <object> <per-request> <total>
//                                                a connect code: be sent <object> within those caps,
//                                                be shown what the wallet owns, sign in
//   dsm-app connections                          every connected wallet
//   dsm-app send <connection> <object> <amount>  ask a wallet to send this account some of an object
//   dsm-app owns <connection> <object>           ask a wallet to prove what it owns of an object
//   dsm-app accept <connection> <object>         ask a wallet to accept an object this account issued
//   dsm-app login <connection>                   ask a wallet to sign in (the player approves on the device)
//   dsm-app result <connection> <seq>            what became of a request
//   dsm-app activity [after]                     what calls and wallets did to this account
//
// Amounts are in the object's own units: 0.10 ERA, 1 sword.

import { encodeB32 } from "./b32.js";
import { pb } from "./index.js";
import { localAccount } from "./local.js";
import { ask, grant } from "./requests.js";
import type { Result } from "./results.js";

function usage(): never {
  console.error(
    "usage: dsm-app id | fund | owned | issue <SYMBOL> <name> <supply> [decimals] | give <wallet> <object> <amount> |\n" +
      "       offer <name> <object> <per-request> <total> | connections | send <connection> <object> <amount> |\n" +
      "       owns <connection> <object> | accept <connection> <object> | login <connection> |\n" +
      "       result <connection> <seq> | activity [after]",
  );
  process.exit(2);
}

function arg(args: string[], index: number): string {
  const value = args[index];
  if (value === undefined || value.length === 0) usage();
  return value;
}

function show(r: Result): void {
  console.log(`answered: ${r.answered ? "yes" : "no"}  outcome: ${r.outcome}  ${r.reason}`);
  console.log(`fact: ${r.fact}  ${r.detail}`);
  for (const o of r.owns ?? []) console.log(`  owns ${o.amount} of ${o.object}`);
  if (r.signed !== undefined) console.log(`  signed: ${r.signed.statement}`);
}

async function main(args: string[]): Promise<void> {
  const app = await localAccount("app");
  switch (args[0]) {
    case "id":
      console.log(await app.id());
      return;
    case "fund": {
      const era = await app.owns("ERA").catch(() => undefined);
      if (era !== undefined && era.amount > 0n) {
        console.log(`already holds ${era.display} ERA`);
        return;
      }
      for (let attempt = 1; attempt <= 120; attempt++) {
        const claim = await app.fund();
        if (claim.funded) {
          console.log(`funded: ${claim.message}`);
          return;
        }
        if (attempt === 1) console.log(`waiting for the faucet: ${claim.message}`);
        await new Promise((r) => setTimeout(r, 500));
      }
      throw new Error("the faucet did not fund this account within a minute");
    }
    case "owned":
      for (const o of await app.owned()) {
        console.log(`${o.object.symbol.padEnd(8)} ${o.display.padStart(16)}   ${o.object.kind.padEnd(8)} ${o.object.id}`);
      }
      return;
    case "issue": {
      const issued = await app.issue({
        symbol: arg(args, 1),
        name: arg(args, 2),
        supply: arg(args, 3),
        decimals: args[4] === undefined ? 0 : Number(args[4]),
      });
      console.log(`issued ${issued.symbol} (${issued.kind}, supply ${issued.supply}): ${issued.id}`);
      return;
    }
    case "give":
      await app.give(arg(args, 1), arg(args, 2), arg(args, 3), "dsm-app give");
      console.log("sent");
      return;
    case "offer": {
      const object = arg(args, 2);
      const offer = await app.offer({
        name: arg(args, 1),
        grants: [grant.send(object, arg(args, 3), arg(args, 4)), grant.owns([object]), grant.accept()],
      });
      console.log(offer.code);
      return;
    }
    case "connections":
      for (const c of await app.connections()) {
        console.log(`connection ${c.id}  wallet ${c.peer}  ${c.connected ? "CONNECTED" : "DISCONNECTED"}`);
      }
      return;
    case "send": {
      const ref = await app.request(arg(args, 1), ask.send(arg(args, 2), arg(args, 3), "dsm-app send"));
      console.log(`request ${ref.seq}`);
      return;
    }
    case "owns": {
      const ref = await app.request(arg(args, 1), ask.owns([arg(args, 2)]));
      console.log(`request ${ref.seq}`);
      return;
    }
    case "accept": {
      const ref = await app.request(arg(args, 1), ask.accept(arg(args, 2)));
      console.log(`request ${ref.seq}`);
      return;
    }
    case "login": {
      const ref = await app.request(arg(args, 1), ask.login("dsm-app"));
      console.log(`request ${ref.seq}: waits for the player to approve it on the device`);
      return;
    }
    case "result":
      show(await app.result({ connection: (await app.connection(arg(args, 1))).id, seq: BigInt(arg(args, 2)) }));
      return;
    case "activity": {
      const after = args[1] === undefined ? 0n : BigInt(args[1]);
      const activity = await app.ingress.activity(after);
      console.log(`account ${encodeB32(activity.deviceId)}`);
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
