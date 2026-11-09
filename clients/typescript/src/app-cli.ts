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
//   dsm-app offer <name> <object> <per-request> <total> [coin]
//                                                a connect code: be sent <object> within those caps, be
//                                                shown what the wallet owns, hand it objects this account
//                                                issues, read its contacts, referee matches it stakes
//                                                <object> in (1.00 a match, 2.00 in all); with [coin],
//                                                sell it <coin> for <object> through this account's vault
//                                                (1.00 a trade, 5.00 in all)
//   dsm-app connections                          every connected wallet
//   dsm-app send <connection> <object> <amount>  ask a wallet to send this account some of an object
//   dsm-app owns <connection> <object>           ask a wallet to prove what it owns of an object
//   dsm-app accept <connection> <object>         ask a wallet to accept an object this account issued
//   dsm-app login <connection>                   ask a wallet to sign in (the player approves on the device)
//   dsm-app contacts <connection>                ask a wallet who its contacts are
//   dsm-app vault <a> <reserve-a> <b> <reserve-b>
//                                                open a vault that trades between two objects, funded from
//                                                what this account owns (the fee is 0.30%)
//   dsm-app vaults                               this account's vaults and their reserves
//   dsm-app price <connection> <from> <to> <amount>
//                                                ask what <amount> of <from> would get in <to> through
//                                                this account's vaults (information, never a fact)
//   dsm-app trade <connection> <from> <to> <amount> [percent]
//                                                the wallet accepts <to>, this account prices the trade,
//                                                then asks for it at no less than [percent] (95) of the price
//   dsm-app stake <connection> <opponent> <match> <object> <amount> <A|B> [against]
//                                                ask a wallet to stake on a match this account referees
//                                                against the wallet of <opponent> (its connection); side B
//                                                passes side A's stake id as [against]
//   dsm-app decide <stake> <A|B|void>            decide a match: who the stakes pay
//   dsm-app collect <connection> <stake>...      ask the winner's wallet to collect the stakes
//   dsm-app result <connection> <seq>            what became of a request
//   dsm-app activity [after]                     what calls and wallets did to this account
//   dsm-app help                                 this list
//
// Amounts are in the object's own units: 0.10 ERA, 1 sword. Stake ids are hex,
// as `result` prints them.

import { encodeB32 } from "./b32.js";
import { pb } from "./index.js";
import { localAccount } from "./local.js";
import { ask, grant } from "./requests.js";
import type { Decision } from "./account.js";
import type { Result } from "./results.js";

const USAGE =
    "usage: dsm-app id | fund | owned | issue <SYMBOL> <name> <supply> [decimals] | give <wallet> <object> <amount> |\n" +
      "       offer <name> <object> <per-request> <total> [coin] | connections | send <connection> <object> <amount> |\n" +
      "       owns <connection> <object> | accept <connection> <object> | login <connection> | contacts <connection> |\n" +
      "       vault <a> <reserve-a> <b> <reserve-b> | vaults | price <connection> <from> <to> <amount> |\n" +
      "       trade <connection> <from> <to> <amount> [percent] | stake <connection> <opponent> <match> <object> <amount> <A|B> [against] |\n" +
      "       decide <stake> <A|B|void> | collect <connection> <stake>... | result <connection> <seq> | activity [after] | help";

function usage(): never {
  console.error(USAGE);
  process.exit(2);
}

function arg(args: string[], index: number): string {
  const value = args[index];
  if (value === undefined || value.length === 0) usage();
  return value;
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function stakeId(text: string): Uint8Array {
  if (!/^([0-9a-f]{2})+$/i.test(text)) usage();
  return Uint8Array.from(Buffer.from(text, "hex"));
}

function show(r: Result): void {
  console.log(`answered: ${r.answered ? "yes" : "no"}  outcome: ${r.outcome}  ${r.reason}`);
  console.log(`fact: ${r.fact}  ${r.detail}`);
  for (const o of r.owns ?? []) console.log(`  owns ${o.amount} of ${o.object}`);
  if (r.signed !== undefined) console.log(`  signed: ${r.signed.statement}`);
  if (r.price !== undefined) console.log(`  price: ${r.price.amountIn} in, ${r.price.amountOut} out (smallest units, ${r.price.hops} hop${r.price.hops === 1 ? "" : "s"})`);
  if (r.match !== undefined) {
    for (const s of r.match.stakes) console.log(`  stake ${hex(s)}`);
    console.log(`  verdict cell ${hex(r.match.cell)}  amount ${r.match.amount}`);
  }
}

function decision(text: string): Decision {
  if (text !== "A" && text !== "B" && text !== "void") usage();
  return text;
}

async function main(args: string[]): Promise<void> {
  const app = await localAccount("app");
  switch (args[0]) {
    case "help":
      console.log(USAGE);
      return;
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
      const grants = [
        grant.send(object, arg(args, 3), arg(args, 4)),
        grant.owns([object]),
        grant.accept(),
        grant.contacts(),
        grant.match([{ object, perRequest: "1.00", total: "2.00" }]),
      ];
      const coin = args[5];
      if (coin !== undefined && coin.length > 0) grants.push(grant.trade(object, coin, [{ object, perRequest: "1.00", total: "5.00" }]));
      const offer = await app.offer({ name: arg(args, 1), grants });
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
    case "contacts": {
      const ref = await app.request(arg(args, 1), ask.contacts());
      console.log(`request ${ref.seq}`);
      return;
    }
    case "vault": {
      const vault = await app.openVault({ a: arg(args, 1), reserveA: arg(args, 2), b: arg(args, 3), reserveB: arg(args, 4) });
      console.log(`vault ${hex(vault.id)}: ${vault.a.display} ${vault.a.symbol}, ${vault.b.display} ${vault.b.symbol}`);
      return;
    }
    case "vaults":
      for (const v of await app.vaults()) {
        console.log(`vault ${hex(v.id)}  ${v.a.symbol}/${v.b.symbol}  ${v.a.display} ${v.a.symbol}, ${v.b.display} ${v.b.symbol}  ${v.active ? "active" : "closed"}`);
      }
      return;
    case "price": {
      const ref = await app.request(arg(args, 1), ask.price(arg(args, 2), arg(args, 3), arg(args, 4)));
      console.log(`request ${ref.seq}`);
      return;
    }
    case "trade": {
      const connection = await app.connection(arg(args, 1));
      const from = arg(args, 2);
      const to = arg(args, 3);
      const amount = arg(args, 4);
      const percent = args[5] === undefined ? 95n : BigInt(args[5]);
      // A wallet receives only what it has taken up itself: it accepts the object first.
      const accepted = await app.wait(await app.request(connection, ask.accept(to)), { until: "answered" });
      if (accepted.outcome !== "carried_out") throw new Error(`the wallet did not accept ${to}: ${accepted.reason}`);
      const priced = await app.wait(await app.request(connection, ask.price(from, to, amount)));
      if (priced.price === undefined) throw new Error(`no price: ${priced.reason}`);
      const atLeast = (priced.price.amountOut * percent) / 100n;
      console.log(`priced: ${amount} ${from} gets ${priced.price.amountOut} of ${to} (smallest units); asking for at least ${atLeast}`);
      const ref = await app.request(connection, ask.trade(from, to, amount, atLeast));
      console.log(`request ${ref.seq}`);
      return;
    }
    case "stake": {
      const connection = await app.connection(arg(args, 1));
      const other = await app.connection(arg(args, 2));
      if (!other.connected) throw new Error(`the opponent's connection ${other.id} is disconnected`);
      const side = arg(args, 6);
      if (side !== "A" && side !== "B") usage();
      const against = args[7];
      const ref = await app.request(
        connection,
        ask.match.stake({
          match: arg(args, 3),
          object: arg(args, 4),
          amount: arg(args, 5),
          side,
          opponent: other.opponent,
          against: against === undefined ? undefined : stakeId(against),
        }),
      );
      console.log(`request ${ref.seq}`);
      return;
    }
    case "decide": {
      const verdict = await app.decide(stakeId(arg(args, 1)), decision(arg(args, 2)));
      console.log(`decided: ${Buffer.from(verdict.outcome).toString()}  state ${verdict.state}`);
      return;
    }
    case "collect": {
      const stakes = args.slice(2).map(stakeId);
      if (stakes.length === 0) usage();
      const ref = await app.request(arg(args, 1), ask.match.collect(stakes));
      console.log(`request ${ref.seq}`);
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
