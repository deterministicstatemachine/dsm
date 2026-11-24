# Changelog

All notable changes to DSM Protocol will be documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)  
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [Unreleased]

## [0.1.1-beta.5] — 2026-11-24

### Added

- **Every trade leaves its vault's state and a proof; a reader checks one
  proof (SoFi Amendment S36; owner, 2026-11-22).** After each swap the
  trader's phone proves the vault step with leanVM (BLAKE3 proven by Flock)
  and publishes one record: the vault's whole tree and a proof of every step
  from the vault's genesis. A wallet reading a vault starts at the newest
  record that verifies, checks that its trade consumed its parent from the
  trade's own objects, and reads none of the vault's history. On a Galaxy A16
  a proof takes about 2–3 s after the trade and is checked in about 95 ms.
  The owner baselines, the vault histories and the vault witnesses in Connect
  quotes and swaps are gone; a wallet backup taken before this release still
  restores.

- **A connected app sends the player to the wallet to approve, and the wallet
  goes back to it (DSM Amendment A11; owner, 2026-11-19).** A `dsm:connect/v1:`
  link that carries the code of an application the wallet is already connected
  to no longer asks to connect again: the Apps screen opens that application's
  waiting requests, and once the player has approved or declined them the
  wallet steps back to the app that opened it, as after a connect. It is the
  same for every application. The wallet finds the connection in its own record
  (`connect.connectedBy`, a new query) and fetches nothing the link names.

- **The wallet backs up after every transaction, or by hand (owner,
  2026-11-24).** Settings, in both skins, has the choice: every transaction,
  the default, or by hand, which puts a small Back up button on the Send
  screen that says what came of it (`wallet.backupNow`). Rust keeps the
  setting and acts on it. A backup after a transaction is taken once the
  transaction's rows have landed, 1.5 s later, where it waited for 20 s of
  quiet; a transaction landing while a backup is written cancels that write,
  as the database itself reports, and the next backup follows it. On the rig
  (2026-11-24) a backup by hand took 4.0–4.4 s, and a send's automatic backup
  was written 5.3 s after its delivery.

- **The Modern wallet has the inbox.** The received transfers not yet looked
  at, as Rust counts them, and what is waiting on the storage nodes were drawn
  only by the DGen wallet screen. The Modern wallet shows the same inbox on
  every view, with its count as a badge.

- **The new ERA symbol, the hexagonal E, in both skins.**

### Fixed

- **A wallet that holds nothing of a vault can check a payer's trade through
  it (SoFi Amendment S36).** Checking a two-hop trade needs each leg's vault
  state at its parent root, and only the vault being walked had its parent's
  proof record read: on the rig (2026-11-24) a receiver held a payment for
  "its route evidence: VaultLeaf". A vault's state at a root not established
  on the device is now read from the proof record whose root it is, verified
  back to the accepted genesis, before the published-state read.

- **A send whose relationship moved while it was prepared is refused, and
  nothing is marked.** The background poller can apply the relationship's own
  checkpoint between the send reading its tip and the check of that tip. The
  check read the move as a consumed parent and marked the contact for online
  reconciliation, which no sync clears, so every later send to that contact
  was refused ("Relationship state diverged and needs repair"). Nothing is
  changed or sent before that check, so the send is refused with "nothing was
  sent: send again" and the contact is left as it is.

- **A vault's head is read without waiting on this device's own proof
  records, and a chain asked for at a vault's genesis root is its genesis.**
  The wait made one side of an escrow find no head of the other side's vault.

- **A quote or a trade reads each final cell fresh once, and another trader's
  unresolved position once.** Every verifier an operation built read the same
  cells again. On a Galaxy A16 a one-hop quote went from 13.4 s to 6.6 s, and a
  trade's route reads from 52 to 28. A route search that cannot establish a
  vault's head now names the vault and the reason, where it said only that
  some liquidity could not be reached.

- **Each device keeps one wallet backup on the nodes, written over each time
  (DSM Amendment A40; owner, 2026-11-23).** A backup used to go to new cells
  every time, and the nodes kept every one, including attempts the wallet's
  next payment cut short. Now each device has one backup slot on every node,
  apart from the cells, and only its cell lock starts a write of it. A node
  holds one whole backup per slot and at most one being written: the next
  backup writes over the one being written and replaces the whole one once
  every part has arrived. The network's record of every payment is unchanged
  and stays the full history. Nodes at schema 4 add the slot tables in place
  on start, with nothing else touched, and no longer take writes to the old
  backup cells; phones drop their records of writing them.

- **A wallet backup no longer copies every payment the wallet ever made, and
  the phone no longer keeps a copy of every backup it wrote (DSM Amendment
  A40).** On the beta nodes, backups were 4.23 GB of the 4.44 GB each node held:
  each one carried the full record of every past payment (about 57 MB on the
  busiest phone), and a new one is written after every payment, so storage grew
  with the square of a wallet's payments. A backup now carries the steps in
  flight and each contact's latest step, so its size follows the wallet's
  contacts. Every other table, the offline account's among them, is carried
  whole as before. The phone no longer keeps a record of writing backup
  parts (2.16 GB on one phone). What a restore
  installs and how a receiver accepts a step are unchanged.

- **A payment after a quiet spell no longer waits on its payer's earlier
  steps.** A receiver checks each of a payer's steps since the state it kept of
  the payer (the owner's ruling of 2026-11-15); until now it did so only when
  the payment arrived, and on the rig a wallet's first payment after idle took
  63–95 s to show. The background poller now walks each contact forward after
  its cycles (one pass at a time, at most every 30 s), so the payment finds the
  earlier steps already checked. Same check, run earlier.

- Two-hop trades in a row over one pair of vaults no longer stop both vaults (rig, 2026-11-22). After the third such trade, no wallet could establish the vaults' newest generation: the trader's next trade was refused by its own verifier (`CoreDoesNotFold`, the entries' paths are not of one tree), and another trader's trade on the same vault was held for good (`AttemptLiveness`). A vault's walk took the other vault's chain once, as it stood when first asked for, and never asked again after its own chain moved on; and the check of an attempt behind a two-hop trade never fetched the other vault's chain at all. Both now fetch it again when the chain in hand does not name the parent they need, once. New test: two-hop trades five rounds in a row, then trades by the trader and by another wallet, on five storage nodes. The attempt check behind a two-hop trade is shown by the rig (a trade held since 17:23 resolved Void, nothing moved), not yet by a local test.

- An escrow step says what it came to as soon as Rust answers it, and a lookup walks its vaults at once. The Escrow tab read its vault lists again before it said anything, and each list walked its vaults to their heads one after another: on the rig (2026-11-22) a release Rust finished in under 20 s showed nothing for 151 s on a wallet with 27 vaults of its own and a 12-vault cell looked up, a lock and a decide for 166 s and 106 s, and a lookup of that cell took 59 s. The tab now shows a lock's, a decide's and a release's answer when it arrives (3 s, 3 s and 18 s on that wallet) and reads the lists again afterwards; a re-read that fails is named as the re-read's failure, where it used to be reported as "Release failed" over a stake already released, and the balances are refreshed either way. `escrow.locked` and `escrow.vaults` accept their vaults' geneses at once and walk the vaults to their heads at once, sixteen at a time, through the same verifier and the same checks, in the order they were named: the 12-vault lookup takes 29 to 31 s on that wallet and 19 s on another. What is left of a lookup is each vault's walk checking again the same traders' positions another vault's walk checked; that is not changed here.
- A payment no longer waits on the owner's baseline duty (SoFi Amendment S24). The syncs `wallet.send` runs on its own path leave it to the next sync, and while the background poller runs, a sync starts the pass beside it, one at a time, instead of awaiting it. The pass walks every vault the device created from its genesis; on the rig phones (2026-11-21) it added ~22 s to every send and ~15 s to every receipt. Sends went from 33–37 s to 10 s at the sender, and from 40–48 s to 23 s at the receiver.
- The wallet's page reads its balances and history again when a connected application's request is carried out. A payment or a commitment under the application's grant moves what the wallet holds with nobody at the wallet's screen, and nothing told the page: on the rig (2026-11-22) a wallet that committed 150 STEEL to a Sennite structure went on showing 300 until the app was restarted. `connect_routes::finish`, the one place a processed request is recorded, now posts `dsm-wallet-refresh` for an outcome of carried out.
- The wallet home no longer lists dBTC for a wallet that holds none (owner, 2026-11-22). Rust lists every token the protocol defines whether or not the wallet has ever held it; the home of either skin ("Your Balances", "Your Tokens") now leaves out a protocol-defined token, other than the wallet's main currency, of which the wallet holds nothing: no balance, nothing Rust reports locked in flight (`BalanceGetResponse.locked`, which the page's balance view now carries), and no offline allocation with something in it. An allocation the appliance has not stated yet lists nothing by itself, since the row would show the token at zero. ERA is listed at zero, and so is a token the wallet created or added: adding it is what lets the wallet receive it. Which tokens the protocol defines is Rust's word, not a ticker's. The Tokens screen and Rust's `balance.list` are unchanged.
- The Send screen offers only what there is something of to send (owner, 2026-11-22). A token held at zero is no longer in its token list: an online send lists the tokens with a balance, and an offline send those with an offline allocation, or one the appliance has not stated yet (unknown, not zero). The Modern send page, which already listed only holdings with something in them, now also offers a chosen recipient only the tokens that contact has added, as the classic Send screen does; a token asked for that the recipient has not added is not replaced by another: the page says so and offers what can be sent.
- A token is sent only to a contact that has added it (owner, 2026-11-21). A device credits a token only once it has added it, so a send of one it had not added debited the sender, was refused by the recipient on every sync, and held the whole relationship until the recipient added the token. Each wallet now states the tokens it has added in a list its AK signs and keeps in its own directory cell on the storage nodes, beside its entry (`DeviceTokenListV1`); the list is written when a token is created or added, and by the next sync for a wallet updated to this build. A wallet reads its contacts' lists from the nodes each time it opens and keeps what they state. The Send screen offers a chosen recipient only those tokens and the protocol's own assets (`ContactAddResponse.sendable_token_ids`), and `wallet.send` refuses any other before anything is debited; nothing is read from the network on a send's path, except that a token missing from what is kept has that contact's lists read once more before the send is refused. When a read keeps a token it did not keep before, Rust says so (`contact.tokens`) and the page reads its contacts again, so the Send screen shows it without leaving the screen. Adding a token is permanent, so every list that verifies still holds and what a contact has added is their union. A contact on an older build states no list and can be sent the protocol's own assets only. No node changes, and the directory entry is unchanged.
- A send that can never complete says so on its history row. Since the Send screen is answered before a send's economic admission is finished, a send whose admission cannot land (its position was spent first by a copy of the wallet) marks its history row `failed`, with the reason, and the page reads its history again; nothing of it is delivered. While a send finishes its admission beside the answer it keeps its hold on the device's pending admission, so a sync leaves the admission to it, as it did while the send awaited it.
- A recipient reads a payer's evidence back from the members before putting it there again, each object at once: the payer has already published it, so it is read once and put only when it is short of `Stored`. And a sync on a payment's path leaves the two backlog sweeps (frozen artifacts still owed the set, route writes short of their route's end) to the next sync, as it leaves the owner's baselines: they are the device's standing debts, not the payment's. On the rig phones (2026-11-21) the recipient's work on a transfer went from ~2.6 s to ~2.2 s, a pre-send sync that had waited 1.1 s on a wallet backup's route write took 0.2–0.5 s, and four sends were answered 1.3–1.9 s after CONFIRM and shown on the recipient's screen 7.1–8.4 s after it.
- The Send screen is answered once an online send's debit is committed; its economic admission (publish, validate, register the root claim along its route, read it back final) and then its delivery run beside it, in that order (owner, 2026-11-21: "Admission after answering"). Nothing is delivered before the debit is admitted, as before. An admission that can never land, because a copy of the wallet spent from the position first, now fails after the screen said sent; the page's balance and history are read again when the background work ends, whatever it came to. Payments an application asks for still wait for the admission and the delivery. On the rig phones the sender's screen was answered ~2.1 s after CONFIRM (4.3 s when the pre-send sync was slow), where it was ~6 s.
- An online send is answered sooner on both phones. The Send screen is answered once the debit and its economic admission are committed, and the delivery to the storage nodes runs beside it; a delivery that does not finish is the reconciliation sweep's, as before (§16.6). Payments an application asks for still wait for their delivery, which is what carries them out. A recipient's screen refreshes as soon as a transfer is accepted and applied, not after the device's own admission and release that follow. And a directory entry this wallet has proven is remembered by the digest of its bytes: a send still reads the recipient's entry every time, but the same bytes are not proven again, where they were proven twice per send. On the rig phones (2026-11-21) the time from CONFIRM to the sender's answer went from ~11 s to ~6 s, and from the tap to the recipient's screen from 23.0 s to 15.3–15.9 s.
- An offline payment's frames cross Bluetooth about ten times faster. The receiver wrote each chunk to its database in its own synced transaction (~50–70 ms a chunk) before it acknowledged; it now writes a frame's first chunk at once and the rest 32 at a time, one transaction each, and a process that dies mid-frame takes again only what was not written. The GATT server sends 32 notifications between acknowledgements instead of 10. On the rig phones (2026-11-21) the 255- and 297-chunk frames went from ~21 s to 2.2–2.5 s and a 1 ERA offline payment from 147.7 s to 114.3 s; the board commits (~30 s a side) and the confirm, the one frame sent as notifications (~45 ms a chunk), are most of what is left.

### Security

- `url` is 2.5.9 in the three lockfiles that carry it (the workspace's, the SDK's, the Android anchor's), with `form_urlencoded` 1.2.3: RUSTSEC-2026-0592 (2026-11-20), a stack overflow in `Url::origin()` on nested `blob:` URLs, is fixed there. The security audit refused 2.5.8.
- **A board pays or is paid offline only under the owner's stamp (DSM
  Amendment A38).** Every board is set up by the owner before it ships, and he
  signs its public identity (anchor id, `pk_host`, `pk_chip`) with his stamp
  key, a BLAKE3-SPHINCS+ SPX128f key kept under his passphrase
  (`crates/dsm-board-stamp`). The board keeps the stamp only when it verifies
  under the stamp keys its signed firmware carries, and reports it with a new
  identity read. A receiver checks the payer's stamp on every payment, a payer
  checks the receiver's board, the receiving board checks the payer's in its
  own payment check, and a wallet installs and drives only a stamped board.
  An unstamped board is refused by name, never as a changed one. A trial
  install, whose keys change at every boot, pays and is paid nothing offline.
- **The board makes its own secret (DSM Amendment A38).** The signed image
  seals it from the board's TRNG, in OTP page 49, its lock row written before
  any row; no phone or computer draws or sees it. It seals only when the seal
  command is sent (`OP_SEAL_SECRET`, `used-chip-bench --seal-secret`): starting
  a board writes nothing to its OTP, and until then the board answers every
  request with what it found, its chip included. The
  phone's procedure and `provision-otp.sh` no longer write a secret, and refuse
  a page 49 someone else wrote.
- **An offline payment is final without its payer (DSM Amendment A39).**
  Every step an offline account's board signs has an origin cell, keyed by the
  account root it starts from, which holds the first step written there: one
  history per account, whoever writes it. A receiver keeps the payer's steps it
  was carried and settles from the payer's cells alone; the payer never has to
  come back online. Every load, unload and unload of received money is now
  signed by the board at its next counter, as a payment is, so a payer cannot
  unload money it already paid offline, published or not. A load or unload
  holds its cells, or every checker refuses it. With a broken board, a payment
  and a conflicting step from one root never both count. The board's firmware
  is unchanged: it signs every action but a receive alike.
- **Restore a wallet from its 24 words (DSM Amendment A40).** Under Create /
  INITIALIZE, a new option restores a wallet that exists on the network: the
  same identity (genesis, device id, keys), checked against the wallet's own
  directory entry before anything is installed, back at its last online
  balance. The balance comes from the wallet's own register, re-verified from
  its start to its head with the check any device runs for a peer, its leaves
  rebuilt from each step's witness. SoFi trades and escrow releases that
  realized come back too: the restore works out what each one paid exactly as
  the lost phone did, from SoFi's public objects, and keeps it only when it
  matches the root the network holds. A position still open holds the restore
  until it resolves. Words of no wallet on the network restore
  nothing. Contacts come back from the wallet's own backup on the nodes:
  sealed under a key only the 24 words give, taken once the wallet has been
  still about 20 seconds (any new step cancels it), and installed only when it
  is the wallet as the register's head shows it. A board's offline account
  comes back from the network: the wallet puts its own offline steps at their
  origin cells once online, and a restore advances the backed-up account
  through them, using it only when it matches the board's counter exactly.
  Connect sessions, local history and anything since the last backup do not
  come back.

---

## [0.1.1-beta.4] — 2026-11-15

A replacement for 0.1.0-beta.4, cut the same way: nothing is migrated.
Uninstall any earlier beta, create a new wallet, and expect the storage nodes
to be reprovisioned (node schema 4, client database 49). The network id is
still `dsm-testnet`.

### Security

- **A receiver keeps each payer's last proven state (DSM Amendment A36).** A
  payment is checked from the state the receiver last proved for that payer,
  through every step the payer made since, each from its own parent; a
  credit's source is checked the same way. Four second-spend runs on real
  nodes (an old state, an unseen own step, a state no step installed, a
  balance no step paid) are refused. A contact's history is walked when it is
  added. This is the receiver-side check of the original paper (§10.4).
- **A relationship's first inbox is bound to its writer's published key
  (DSM Amendment A37).** Each directory entry carries a first-inbox lock; a
  third party who computes the first inbox from two devices' ids can no
  longer write there first and keep them from becoming contacts. Nodes keep
  no key per inbox address.
- **A storage cell can no longer be jammed past a reader's budget.** A reader
  keeps the leader's first recognized value and copies of it only, so junk
  written at an application cell, an escrow verdict cell, the device
  directory or the ERA reserve head no longer makes it unreadable.
- **Look-alike tickers are refused.** A ticker that reads as `ERA` or `dBTC`
  to a person (Cyrillic, Greek, full-width or mathematical letters, or any
  invisible character) is refused at creation.

### Changed

- **The storage nodes distribute an object among themselves** (storage spec
  §5 rule 7). A writer uploads an object once; the member that takes it
  copies it to its set-mates, and the writer checks every member holds it
  and fills any gap itself.
- **A board that cannot reach its chip says what the chip answered.** When
  bring-up fails, the board's refusal now carries the TROPIC01's status byte
  at each start-up warm-up transfer (its ready, alarm and start-up bits, and
  nothing else the chip sent), so a silent line, a chip in alarm, and a chip
  still starting can be told apart from the phone without opening the board.

### Noted for after beta

- Storage-node misbehaviour evidence, stake burning, the operator registry
  and seat reassignment (storage spec §24 item 16). Not built.

---

## [0.1.0-beta.4] — 2026-11-13

Beta.4 is a clean cut from beta.3. Nothing is migrated: uninstall any earlier
beta before installing this one, and create a new wallet. The network id is
still `dsm-testnet`, and the faucet funds each new account. This release is
for developer onboarding and feedback; it is not for holding value.

### Breaking

- **No state from beta.3 is read.** The device state, the client database, the
  wire formats and the storage fleet all changed, and no migration is
  provided, deliberately: beta carries no production user state, so the remedy
  is a wipe.
- **Identity is rooted in the recovery phrase.** A wallet's genesis is derived
  from its BIP39 phrase, self-attested and published to the fleet (#514). The
  hardware-binding scheme of earlier betas (C-DBRW) and the MPC genesis are
  removed (#514, #992, #1148).
- **A new storage fleet.** Five nodes with a quorum of three, pinned in the
  client. A node stores and serves bytes and keeps write-once registers; it
  validates no protocol rule (#932).
- **SoFi's routes are replaced.** The `dlv.*` and `route.*` routes are gone.
  A vault is created, traded against, resolved and closed through `sofi.*`,
  and every decision is Core's.
- **A token's supply is fixed when it is created.** There is no mint after
  creation.
- **ERA has two decimals** (#1095).
- **Online messages are removed** (#1050).
- **dBTC is being replaced and does not function in this release.** Its code
  stays in the tree and nothing runs it; see the README's dBTC section.

### Added

- **Plug your app into DSM (DSM Connect, DSM Amendment A11).** An app keeps
  its own server and language, gets a DSM account of its own, and its users
  connect their wallets to it under a grant they approve. The app asks a
  wallet for a payment, a proof of what it owns, a sign-in, an item given or
  accepted, a trade or a match (#1112, #1118, #1121). Shipped with it:
  - `dsm-app-host`, prebuilt for Linux (x86-64, ARM64) and macOS (arm64,
    x86-64), installed by `install.sh`, which checks every download against
    `SHA256SUMS`;
  - the TypeScript and Python clients, the Connect starter, and terminal
    wallets for development;
  - the guide, published as pages, and `BUILDING_APPS.md`;
  - an app's account on the beta network by default (`make app-dev`), or on a
    local storage set (`make app-dev-local`);
  - application cells, contributions and a state scope, as generic facilities
    for applications.
- **Offline payments with the appliance.** A phone with the DSM board (RP2350
  with the TROPIC01 secure element) pays another phone with a board over
  Bluetooth with no network. Each offline release carries three signatures
  over the same step: the wallet's, the chip's and the board firmware's. The
  receiver's board takes part too: it checks the payment and commits the
  receive, so a payment is received once. Money is loaded into and unloaded
  from an offline account, money received offline is kept apart until it is
  moved to the balance, and a phone that received offline goes on paying
  offline from what it loaded (#1148, #1226). Installing a board is never
  automatic and is tried first (DSM Amendment A32).
- **SoFi on the device.** A vault is a constant-product market over two
  adopted tokens with a fee in basis points, created from its owner's own
  balances (`sofi.createVault`). A trader finds and prices a route
  (`sofi.findRoute`) and trades through one or two vaults (`sofi.trade`,
  `sofi.route`); a trade interrupted before it finished is completed from what
  storage holds (`sofi.resolve`, `sofi.relay`); the owner closes the vault and
  takes both reserves back (`sofi.close`).
- **Escrow vaults (SoFi Amendment S21).** An amount is locked under named
  outcomes, each naming who decides it and whom it pays, and is released by
  the verdict (#1114). A computed escrow is decided by a pinned program over a
  signed transcript instead of by signers (#1118).
- **Tokens.** Create a token under a policy for a fee in ERA, with coin
  artwork; share it by QR code or anchor; adopt it; burn it. Adoption precedes
  receipt: a device is never credited a token it has not adopted (#871,
  #1110).
- **The faucet.** A new account claims 100 ERA, and the claim is listed in the
  wallet's history (#1018).
- **Wallet.**
  - The recovery phrase is shown when a wallet is created and checked before
    the wallet exists (#1088).
  - Every screen is on the StateBoy frame, with gold, zebra and leopard skins
    (#1028, #1036); the Modern and DGen looks and Simple mode (DSM Amendment
    A17).
  - Contact cards and email receipts (DSM Amendment A17).
  - A hands-on guided tour in practice mode (#973).
  - A debug report through the share sheet (#1107), and a count on the app
    icon of money received and not yet looked at (#1151).
- **iOS app.** The same Rust SDK and the same screens in a Swift container,
  for the Simulator and for a device. It has no board link, so it makes no
  offline payments.
- **Storage nodes.** Long-poll for waiting clients (#1108), arrival records
  and byte commitments (#974), each operator's own certificate authority, and
  one-line setup for a public node.
- **Formal models, checked in CI.** Lean 4 and TLA+ models of the core, SoFi
  and the offline protocol; a formal proof for SPHINCS+ over BLAKE3 (#1120);
  and a Lean proof that no counterfeit value is accepted, online or offline
  (#1149).
- **Build gates.** The build refuses placeholders, fabricated results and
  hidden errors (#1045); every tracked `Cargo.lock` is audited (#889); a
  tagged release runs the full tests and a newcomer's first run on a clean
  machine before it publishes.

### Changed

- **Acceptance is one hop (DSM Amendment A14).** A receiver validates a peer's
  step from that step's own parent and reads nothing behind it.
  `ci/acceptance_lock.py` enforces this in CI.
- **One device state.** The per-device state and its sparse Merkle tree
  replace the hash chain and the state number, which are deleted.
- **Online payments.** The signed operation is the only authority, with one
  ingestion boundary (#1048); a send is kept in a durable outbox and finalized
  atomically; a payment settles in seconds (#1107).
- **Bluetooth and USB carry offline payments only.** The radio, its addresses
  and pairing belong to the native layer; the frontend renders what Rust
  reports (#1021, #1023, #1030).
- **The frontend renders only.** The wallet's decisions (app lock, pair order,
  token fields) moved into Rust.
- **One pinned Rust toolchain,** enforced in CI.

### Removed

- C-DBRW hardware binding, and its fields on the wire (#514, #1148).
- The MPC genesis (#992).
- The hash chain, the state number and the legacy state machine API.
- The earlier secure-element relay design for offline payments, replaced by
  the appliance.
- SoFi's pre-signed fallback and slippage floors, and the earlier `dlv.*` and
  `route.*` settlement paths.
- The PaidK gate (#965).
- Online messages (#1050).
- Code that reported success without doing the work (#964, #966, #992).

### Security

- **Security audits of 2026-10-15, 2026-10-18 and 2026-11-12,** with their
  fixes (#1139, #1142, #1152).
- **A transfer's memo, ticker and nonce are in no public object** (#1102).
- **The ML-KEM key delivered over Bluetooth is authenticated** against the
  pinned identity key before it is cached.
- **Storage node:** every `/admin` endpoint is behind the admin token, and the
  admin and gossip tokens fail closed when unset (#421, #422).
- **Hostile input is bounded:** over-long proofs, trailing bytes in decoders
  and oversized Bluetooth reassembly are refused (#428, #429, #430, #431,
  #450).
- **Builtin ERA cannot be issued** at the accepting transition.
- **Dependency advisories fixed:** rustls (#887), quinn-proto and quinn-udp
  (#889, #1227), ctutils (#1155), crypto-bigint (#1148).

### Not in this release

- dBTC (being replaced).
- Offline payments on iOS (no board link).
- Token emissions beyond the faucet: the schedule is in Core only.
- The Android APK is not built by the release workflow; the maintainer signs
  and uploads it.

---

## [0.1.0-beta.3] — 2026-04-22

Major architectural release. **215 commits, 525 files, +66.7k/-43.1k lines** since beta.2. Reshapes the state model around `DeviceState`, unifies the native ingress boundary across platforms (iOS scaffolding added), purges ~10,000+ lines of legacy code, and hardens APK signing to v2+v3+v4.

### Architectural changes

- **`DeviceState` is now the canonical state model** — `State` is a derived view computed from `DeviceState`. `StateMachine` stripped to bare minimum (`DeviceState` + `relationship_manager`). The old dispatch surface (`execute_transition`, `execute_dsm_operation`, `apply_operation`) is gone. All operations — bilateral transfers, mint, burn, fee transfers, DLV unlock, smart commitments — now route through a single uniform `CoreSdk::execute_on_relationship` API. The `advance` path split into `prepare / commit / restore` semantics for cleaner recovery and settlement.
- **Unified ingress boundary across platforms** — the legacy `appRouter` dispatch is gone. All protocol traffic now flows through `dsm_sdk::ingress` (~1,460 LOC) with platform-specific ABI shims on top. Android JNI (`unified_protobuf_bridge`) routes envelope / router / hardware-facts calls through the shared ingress.
- **iOS scaffolding** — C FFI surface exported via `dsm_process_envelope_protobuf` / `dsm_free_envelope_bytes`. Platform scaffolding under `dsm_sdk/src/platform/ios/{bluetooth,transport}.rs`. iOS integration documented in `docs/book/11-integration-guide.md`. (iOS app itself is not yet shipped.)
- **Two new Android bridges** — `NativeBoundaryBridge` for DSM native ingress/startup and `NativeHostBridge` for host-capability requests (QR, BLE, NFC, permissions, biometric).
- **§4.3 spec compliance: `state_number` purged from canonical hash paths** — removed from the `State` struct and every canonical hash input across `dsm` and `dsm_sdk`. Identity logic switched to hash-based IDs. Multiple §4.3-violating call sites deleted (including the broken `get_state_by_number` helper, with 5 callers migrated).

### Added

- **NFC recovery pipeline** — capsule v4 format, persisted recovery key, SMT-root capsule reuse, full identity restore flow. NFC handling inlined in the bridge; standalone NFC activities removed.
- **`bitcoinTap` vault summaries** — storage path switched to BitcoinTap-style vault summaries.
- **Recovery tombstone codec migrated to protobuf** (previously bincode) — aligns with the repo's "protobuf-only in protocol paths" invariant.
- **GATT identity read flow** — `observeGattIdentityRead` JNI/Kotlin path; BLE event relay now allows callers to mark transient events droppable when the bridge is unavailable.
- **Expanded BLE hardening** — peer identity hydration from persisted contacts for stale BLE addresses; multi-peer fallback address resolution with coordinator tests; session-lifecycle locking (`TEST_DB_LIFECYCLE_LOCK`); BLE session recovery routed through canonical SMT; BLE foreground service wakes on stitched-receipt cache hit.
- **Contact export** — `export_contacts` overlays persisted `chain_tip` + `ble_address` instead of dropping them behind stale in-memory state.
- **APK signing schemes v3 and v4** — release APKs now carry v2, v3, and v4 signatures (v1/JAR disabled; minSdk 24 doesn't require it). v4 emits an `.idsig` file alongside the APK for incremental install on Android 11+.
- **Interactive APK signing flow** — `make android-release` now prompts for keystore path, key alias, keystore password, and key password on an interactive TTY; env-var and gradle-property overrides supported.
- **Expanded test coverage** — unit coverage added for storage-node API & replication, SDK storage & bilateral, core crypto, frontend wallet/hooks/services/utils, Android bridge/BLE/security (JVM).
- **Formal verification expansion** — vertical-validation property tests extended; SPHINCS+/BLAKE3 deterministic-signing and cross-domain-digest retarget-rejection property tests added; all 10 previously-ignored security/verification tests fixed and passing; TLA+ runs (`DSM_tiny`, `DSM_small`, `DSM_system`, `Tripwire`) pass on the release commit.
- **`caveman-compress`** plugin + tool for docs/prose compression.

### Changed

- **Release keystore format** — signing keystore default switched from JKS to PKCS12 (`.p12`), aligning with the Java 9+ default and keytool recommendations.
- **Android beta version alignment** — release APK reports `versionCode = 3` and `versionName = 0.1.0-beta.3`.
- **Wallet UI polish** — transaction cards show aliases + amount on own line, expanded views keep full hashes, faucet/history cards no longer balloon on small screens.
- **Bridge readiness sequencing** — frontend identity loading now waits for `dsm-identity-ready` instead of `dsm-bridge-ready`.
- **Rust toolchain switched to stable** — no more nightly dependency.
- **CI guardrails rewritten for fork architecture** — `enforce-guardrails` and flow assertions updated for unified ingress.

### Fixed

- **Online send false "SMT proofs are invalid"** — `wallet.send` uses `smt_proofs.pre_root` when constructing first-advance receipt commitments.
- **Pixel 9 faucet brick** — §4.3-violating monotonic `state_number` check removed from faucet path.
- **Faucet phantom token row** — credits no longer render a stale ERA = 0 row.
- **SendTab error surface** — offline transfer failures now show the real reason instead of a generic "Offline transfer failed."
- **Settlement stale-tip cleanup** — successful bilateral settlement clears stale observed-remote-tip claims so converged relationships don't block behind old live-peer mismatches.
- **Sender-session persistence fail-closed** — BLE sender session registration aborts on persist errors instead of continuing in-memory-only.
- **Frontend startup regressions** — stale frontend tests repaired after the ingress migration; identity readiness now reflects the active startup flow.

### Security

- **DLV settlement anchoring enforced** — token operations now require anchored DLV settlement.
- **Real signature checks in verification** — replaces prior placeholder paths.
- **Malformed token-id rejection** — balance-key derivation hard-fails on malformed token IDs instead of admitting ambiguous keys; duplicate hardening in balance checks.
- **Canonical identity binding** — identity store and invalidation are bound to canonical genesis IDs; prevents cross-identity contamination.
- **`ThermalStateProto` removed** — obsolete residue from an old transport schema; kept the live protocol surface singular.
- **Dependency surface reduction** — `dsm` core crate no longer pulls certificate-generation, host/network-discovery, async utility, or wall-clock crates for normal builds.
- **Dependabot alerts closed** — upgraded handlebars to 4.7.9, closing 7 advisories.

### Legacy code purge (~10,000+ LOC deleted)

Made possible by the `DeviceState` migration:

| Area | LOC deleted |
|---|---:|
| `HashChain` infrastructure | ~3,200 |
| `BCR` heuristic detection | ~1,200 |
| `hierarchical_device_management` module | ~1,180 |
| `protocol_metrics.rs` | ~1,362 |
| `chain_tip_sync_sdk` module | ~787 |
| `BilateralStateManager` dead session/chain-tip surface | ~280 |
| `StateMachine` verification helpers | ~210 |
| Dead `State` / `RelationshipManager` / `RelationshipStatePair` methods | ~600+ |

Also removed: `DualModeVerifier`, `state_to_wire`, `random_walk` state helpers, `verify_trustless_identity`, `resume_relationship`, `create_token_state_transition`, `ContactManager::update_contact_from_transition`, `State` struct fields (`external_data`, `hashchain_head`, `matches_parameters`, `state_type`, `value`, `commitment`), plus 10+ zero-caller `State` methods.

### Dependencies

tokio `1.50 → 1.51`, hyper `0.14 → 1.8`, axum `0.8.8 → 0.8.9`, axum-server `0.7.3 → 0.8.0`, rustls-native-certs `0.7.3 → 0.8.3`, tokio-postgres `0.7.16 → 0.7.17`, tokio-postgres-rustls `0.12.0 → 0.13.0`, hmac `0.12.1 → 0.13.0`, uuid `1.22 → 1.23`, mockall `0.12.1 → 0.14.0`, toml_edit `0.22.27 → 0.25.8`, handlebars `→ 4.7.9`. Frontend: react-dom, `@types/node`, `@typescript-eslint/parser`, copy-webpack-plugin, webpack-cli, mini-css-extract-plugin. CI: codecov-action v6, upload-artifact v7.

---

## [0.1.0-beta.2] — 2026-04-06

Targeted hardening release focused on bilateral BLE reliability. 121 files changed, +5.6k/-3.6k lines.

### Fixed

- **Bilateral BLE confirm flow** — BLE confirm delivery is now revised and persisted across app restarts. Pending confirms are cleared after a successful `BilateralCommitResponse` in `handle_commit_response`, preventing duplicate delivery on reconnect.
- **Frontend session-status polling** — switched `pollSessionStatus` from `setInterval` to a self-scheduling `setTimeout`, eliminating overlapping async polls and the race conditions they caused.
- **SQLite modal recovery** — SQLite modal recovery now runs before rejecting operations, reducing false-negative rejections when the DB was mid-recovery.

### Changed

- **BLE bilateral handler refactor** (PR #140) — `bilateral_ble_handler.rs` and `bilateral_full_offline_flow.rs` reworked around the revised confirm lifecycle; BLE relationship-status handling and toolchain checks tightened.
- **TLA+ replay tools** — `deviceBalance` added to TLA specs and replay tools to make balance-sensitive invariants checkable in replay.

### Added

- **PII scan in preflight** — developer preflight now scans for PII before tooling runs.

### Removed

- **SoFi examples** — legacy SoFi example code dropped from the tree.
- **`fix_bridge.patch`** — stale patch file removed.

---

## [0.1.0-beta.1] — 2026-02-19

### Added
- **Bilateral BLE offline transfer** — two-device token transfers over Bluetooth LE with no internet connection required; full state-machine handshake with cryptographic verification on both ends
- **Deterministic state machine core** — hash-chained transaction history with no server-side state; each state transition is irreversible and cryptographically bound to the previous
- **DSM SDK (Rust)** — JNI-exposed library for Android providing wallet management, token operations, BLE transport, and storage-node communication
- **Local storage nodes** — five-node SQLite-backed storage layer with deterministic hashing-based assignment and configurable replication
- **Android client** — React Native/WebView hybrid app with hardware-backed key storage, BLE pairing flow, and integrated diagnostics overlay
- **Local Bitcoin test tooling** — deterministic test-faucet utilities enabled only in early test/debug builds
- **16 KB page-size support** — native libs built with `-Wl,-z,max-page-size=16384` for Android 15+ high-RAM device compatibility
- **`make` build system** — single Makefile entrypoint for all developer tasks (`make help` for full list)

### Changed
- All storage-node endpoints default to `127.0.0.1` (loopback via `adb reverse`) instead of a LAN IP
- Version bumped from `0.1.0` to `0.1.0-beta.1` across all crates, Android app, and frontend

### Security
- Removed hardcoded RSA public key from `storage_node_config.toml`; replaced with placeholder
- `.cargo/config.toml` (machine-local NDK paths) is now gitignored; use `make setup` to generate from template
- `.so` build artifacts are gitignored and must be built locally via `make android-libs`

---

[Unreleased]: https://github.com/deterministicstatemachine/dsm/compare/v0.1.0-beta.3...HEAD
[0.1.0-beta.3]: https://github.com/deterministicstatemachine/dsm/compare/v0.1.0-beta.2...v0.1.0-beta.3
[0.1.0-beta.2]: https://github.com/deterministicstatemachine/dsm/compare/v0.1.0-beta.1...v0.1.0-beta.2
[0.1.0-beta.1]: https://github.com/deterministicstatemachine/dsm/releases/tag/v0.1.0-beta.1
