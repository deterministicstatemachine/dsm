// SPDX-License-Identifier: MIT OR Apache-2.0
//
// My Game, plugged into DSM, in one file: a connect code, a wallet that
// connects to it, a payment, gems handed over, and a sign-in. It talks to the
// account `make app-dev` runs.
//
//   npm install
//   node my-game.mjs

import { ask, grant, localAccount } from "dsm-app-client";

const app = await localAccount("app");

// The wallets connected before this run, so the one that connects now stands out.
const before = new Set((await app.connections()).map((c) => c.id));

// 1. The offer: what My Game may do without asking the player again.
const offer = await app.offer({
  name: "My Game",
  grants: [grant.send("ERA", "0.10", "1.00"), grant.owns(["ERA"]), grant.accept()],
});
console.log(`connect code: ${offer.code}`);
console.log("waiting for a wallet to connect to it...");

// 2. A wallet connects: scanned on a phone, or `make dev-wallet-connect CODE=...`.
let player;
for (;;) {
  player = (await app.connections()).find((c) => c.connected && !before.has(c.id));
  if (player !== undefined) break;
  await new Promise((resolve) => setTimeout(resolve, 1000));
}
console.log(`wallet ${player.peer} connected`);

// 3. 0.05 ERA, inside the grant, so the player is not asked again.
const paid = await app.wait(await app.request(player, ask.send("ERA", "0.05", "100 gems")));
console.log(`payment: outcome ${paid.outcome}, fact ${paid.fact}`);
if (paid.fact !== "received") process.exit(1);

// 4. Your own coin. Issuing it again with the same terms answers with the
//    same coin, so this runs again and again. The wallet accepts it, then
//    your account gives.
const gems = await app.issue({ symbol: "GEMS", name: "Gems", supply: "1000000" });
await app.wait(await app.request(player, ask.accept(gems)), { until: "answered" });
await app.give(player, gems, "100");
console.log(`gave 100 ${gems.symbol}`);

// 5. A sign-in. It always waits for the player to approve it on the device.
console.log("sign-in asked: approve it on the device");
const login = await app.wait(await app.request(player, ask.login("My Game")));
console.log(`sign-in: outcome ${login.outcome}, fact ${login.fact}`);
if (login.fact === "signed") console.log(`signed: ${login.signed.statement}`);
