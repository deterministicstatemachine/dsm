# Apps plugged into DSM

These apps are plugged into DSM today. Each kept its own server and its own logic, added a DSM account of its own, and lets its users connect their DSM wallets to it. Their code is public, in [Irrefutable Labs' repositories](https://github.com/orgs/Irrefutable-Labs/repositories).

| App | What it is | What DSM does in it |
|---|---|---|
| [Wildstate](#wildstate) | A creature-collecting game for Android | The coin and every creature are objects in the player's own wallet; the shop, the market and staked matches run through it |
| [OpenBoxes for DSM](#openboxes-for-dsm) | The open-source warehouse and inventory system | Custody: a stock change stands only when DSM recorded it; staff sign in with their wallet; a carrier takes custody on a phone |
| [CBFpy for DSM](#cbfpy-for-dsm) | A prototype AI with a body | Every step it takes is a DSM transition, decided by rules, and anyone can audit the chain from public keys |

## Wildstate

Wildstate is a creature-collecting game for Android: walk the camp, catch creatures in the tall grass, battle trainers, buy capsules, trade at the market, and fight other players in the arena. Walking, encounters, battles and dialogue run on the game's own server and never touch DSM. What a player owns lives in their DSM wallet:

- **WILD, the game's coin**, is an object the game's account issued, with a fixed supply. The game pays players in it: a starting amount when they connect, and a bounty for each trainer beaten.
- **Every creature** is an object of which exactly one exists, issued by the game's account at the capture. It names the game as its issuer, its species and its capture number; its HP, XP and charges are game data kept against it.
- **The shop** is paid through the wallet. A capsule is granted only when the wallet's 3 WILD has arrived on the game's own account; a message saying "paid" grants nothing.
- **Coins and the roster** come from proofs of what the wallet owns, which the game's account checks itself.
- **The market** is a WILD/ERA vault the game's account funds, and players trade with it from inside the game.
- **The arena's staked matches** are decided by a pinned program, not by a referee. Each wallet locks its own stake, and the winner takes both. The program is [`wildstate-duel`](https://github.com/deterministicstatemachine/dsm/tree/main/crates/wildstate-duel), in this repository.
- Pressing **DSM** in the game shows one timeline: what ran on the game server, and every call the game's account made on DSM.

The game connects the way [Make an offer, connect a wallet](connect.md) does: it shows a code, and the player opens it in their wallet and approves what the game asks for. Its integration is described in [docs/dsm-integration.md](https://github.com/Irrefutable-Labs/wildstate-dsm/blob/master/docs/dsm-integration.md); the game is [Irrefutable-Labs/wildstate-dsm](https://github.com/Irrefutable-Labs/wildstate-dsm).

## OpenBoxes for DSM

[OpenBoxes](https://openboxes.com) is an open-source warehouse and inventory system, first written to track emergency medical supplies in Haiti after the 2010 earthquake and now run by healthcare facilities around the world. OpenBoxes for DSM keeps OpenBoxes' books, and gives DSM the authority over custody at a DSM warehouse:

- **Each warehouse is a DSM account.** A stock change there (a receipt, a transfer, a shipment) stands only when DSM has recorded the matching transition. Otherwise the write fails.
- **The books follow DSM.** A reconciliation reads DSM's state, finds any gap, and corrects it with a new entry, never by editing history.
- **Sign-in is the wallet's.** A person signs in by approving a request in their wallet. Once a wallet is bound, passwords stop.
- **Seats** are held in vaults, assigned and returned on DSM, and a revoked seat stays revoked.
- **The carrier leg.** Handing a shipment to a carrier sends the organization's custody units to the carrier's wallet. At the destination's door the carrier hands them over on a phone screen, the destination takes them in, and receiving is admitted only up to what DSM moved.

It is in review as [pull request #1](https://github.com/Irrefutable-Labs/openboxes-dsm/pull/1) on [Irrefutable-Labs/openboxes-dsm](https://github.com/Irrefutable-Labs/openboxes-dsm). The pull request records the whole demo walked on the beta fleet with two phones: 500 boxes released, 120 shipped and handed to a carrier, handed over and taken in at the door, a seat revoked and returned, and a 40-box gap found, signed and corrected.

## CBFpy for DSM

[CBFpy](https://github.com/StanfordASL/cbfpy) is Stanford's library for control barrier functions: the mathematics that keeps a robot's controls inside a safe set. Irrefutable Labs' fork adds a prototype on DSM: an AI with a body proposes what to do next, and deterministic rules decide which proposal may become a real step on a DSM chain. No AI judges anything.

<figure class="term"><a href="images/apps/cbfpy-console.webp"><img src="images/apps/cbfpy-console.webp" alt="The Ethical Autonomy Console after a run: what the AI knows, the audit, the chain, and every candidate it put forward with the reason each was refused"></a><figcaption>The console after a run: what the AI knows, the audit, the chain, and every candidate it put forward, each refused one with its reason.</figcaption></figure>

How DSM carries it:

- **Every proposal is committed.** Each candidate the AI puts forward is committed with its outcome under one fork root, refused ones included, so the chain holds everything it proposed, not only what it did.
- **A step is a DSM transition.** The enforcer, the only program holding the device key, checks a candidate from what the step before it already knew, commits the chosen one, stores it, and only then carries out the act and signs a receipt for it.
- **What the senses report is committed too.** A look's report is its own signed link and must answer exactly the look its parent asked for. Anything the AI could reach that it has not seen recently counts as occupied.
- **Anyone can audit it.** `ethical-audit` checks the stored chain link by link, each from its parent alone, replays it through DSM, checks every act's receipt, and checks that the world holds exactly what committed acts wrote. It needs public keys only.

The rules it enforces are set out in [its README](https://github.com/Irrefutable-Labs/cbfpy-dsm/blob/main/dsm/README.md): it never aims at harm to any animal bigger than a baby mouse as an adult, or to any honeybee; it never knowingly causes harm; what it has not seen counts as present; it drives no faster than it could stop on road it has seen; a conflict ends in a no, with the reason; and if its senses fail their check, every motor act stops.

<div class="shots">
<figure style="flex-basis:380px;max-width:380px"><a href="images/apps/cbfpy-knows.webp"><img src="images/apps/cbfpy-knows.webp" alt="What it knows: the AI's body beside a wall, cells it has seen, cells it never saw, and a dotted circle behind the wall"></a><figcaption>What it knows: its body beside a wall, and the cells behind it it never saw, which count as occupied. With <b>show what was really there</b> on, the dotted circle is who the simulated world put behind the wall. It never broke through.</figcaption></figure>
<figure style="flex-basis:380px;max-width:380px"><a href="images/apps/cbfpy-audit.webp"><img src="images/apps/cbfpy-audit.webp" alt="The audit: charter, chain, receipts, considered forks and world, each checked"></a><figcaption>The audit, from public material alone: the charter, the chain, every receipt, every replaced fork, and the world.</figcaption></figure>
</div>

<figure class="term"><a href="images/apps/cbfpy-refused.webp"><img src="images/apps/cbfpy-refused.webp" alt="Candidates the AI put forward and the rules refused, each with its purpose, its claims and the reason it was refused"></a><figcaption>Candidates it put forward that the rules refused, each with what it declared and the reason.</figcaption></figure>

These come from a run of the prototype as its README describes it, on its `main` branch on 2026-11-11: the recorded run of the real model, replayed on the wall world, then the audit. The replay ended:

```text
sequence 20
committed steps: 12
every committed step verified from its parent
```

and the audit printed:

```text
10 superseded forks verified from their parents, holding 30 more candidates, 30 of them refused or unmeasured
every step's act has a receipt signed by the device
the world holds exactly the 12 files committed actions wrote, and nothing else
charter in force: version 1
```

It enforces the rules and the facts it is given, in a simulated world. It does not understand ethics, and an act that passes is not made good by passing. Its [report](https://github.com/Irrefutable-Labs/cbfpy-dsm/blob/main/dsm/REPORT.md) says what is and is not shown; the code is in [Irrefutable-Labs/cbfpy-dsm](https://github.com/Irrefutable-Labs/cbfpy-dsm/tree/main/dsm).
