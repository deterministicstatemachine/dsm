# Make an offer, connect a wallet

Your app shows a code, and a wallet connects to it. By the end of this page a wallet is connected to your account, and your app knows exactly what the wallet has let it do.

## What an offer is

An offer is what your app asks for, before a wallet agrees to anything. It carries your app's name and a list of **grants**: things the wallet will let your app do without asking the player again, each with a cap. Send, up to so much per request and so much in all. Owns, to prove what it holds. Accept, to take objects your app issues. The wallet shows all of it to the player before they approve. Nothing in a grant is hidden, and nothing outside it runs without the player.

In code, an offer is one call:

```ts
const offer = await app.offer({
  name: "My Game",
  grants: [grant.send("ERA", "0.10", "1.00"), grant.owns(["ERA"]), grant.accept()],
});
console.log(offer.code);
```

Amounts are in the object's own units: `"0.10"` is a tenth of an ERA. This page makes offers two ways: on the starter's page, and from the command line.

## 1. The starter: your app as a page

The starter is a web app plugged into DSM, and the place to build your app from pieces. It runs in the foreground, so give it a terminal of its own, in your app's folder:

```bash
dsm-connect-starter
```

Open [http://127.0.0.1:3000](http://127.0.0.1:3000).

<figure class="term"><a href="images/starter-top.webp"><img src="images/starter-top.webp" alt="The Connect Starter page: its account's identity, what the page is, and a switch between TypeScript and Python"></a><figcaption>The top of the page: your account's identity, and the switch that shows every piece's code in TypeScript or in Python.</figcaption></figure>

The page is a builder, with three kinds of pieces, in the order an app uses them:

1. **Objects your app issues**: a coin, points, an item (supply 1 is a one-of-a-kind), a ticket; and a shop, a vault that sells one object for another.
2. **What the wallet lets your app do**: the offer. Tick the grants (send, owns, accept, contacts, match, trade), set each cap, and press **Show the connect code**.
3. **Ask a connected wallet**: send, prove what it owns, sign in, sign a statement, accept or receive an object, price or make a trade through your shop, stake on a match, decide it, collect.

Under every piece is the exact code it is, with a **Copy** button. The page never makes that code up: it asks the starter's server, which runs one mapping from piece to client call both to show the code and to make the call. Set the pieces up the way your app needs them, press the button to see it happen, then paste the code into your own app.

<div class="shots">
<figure style="flex-basis:330px;max-width:330px"><a href="images/starter-offer.webp"><img src="images/starter-offer.webp" alt="The offer piece: the app's name, the grants with their caps, the Show the connect code button, and the offer's code under it"></a><figcaption>The offer: tick the grants, set the caps. The code under it changes with them.</figcaption></figure>
<figure style="flex-basis:300px;max-width:300px"><a href="images/starter-connect-code.webp"><img src="images/starter-connect-code.webp" alt="The connect code as a QR code, a link to open it in the wallet on the same device, and the code as text"></a><figcaption><b>Show the connect code</b>: a QR for a phone, a link for a wallet on the same device, and the code as text.</figcaption></figure>
</div>

To connect the terminal wallet below to the page's code instead of the command line's, copy the code under the QR and run `dsm-dev-wallet connect ` followed by it.

## 2. A wallet in the terminal

To test without a phone, start a player's wallet in the terminal:

```bash
dsm-dev-wallet up
```

It is a second account, made the same way `dsm-app up` made yours, on the same network, and funded from the faucet:

```text
[dsm-dev-wallet] wallet account running
  storage set:    the beta network (carried in dsm-app-host)
  ingress:        http://127.0.0.1:8788   (your server calls this)
  ingress secret: …/.dsm-dev/wallet/ingress/ingress-token
  relay:          https://127.0.0.1:8444   (wallets reach this)
  recovery:       …/.dsm-dev/wallet/data/RECOVERY_MNEMONIC
  log:            …/.dsm-dev/wallet/host.log
funded: claimed 100.00 ERA (economic position 1)
```

`dsm-dev-wallet down` stops it.

## 3. Make the offer from the command line

```bash
CODE=$(dsm-app offer 'My Game' ERA 0.10 1.00)
```

The words after `offer` are your app's name, the object a wallet may send it, the cap per request and the cap in all. The command line's offer asks for more than sends: to be shown what the wallet owns, to hand it objects your account issues, to see its contacts, and to referee matches it stakes ERA in (1.00 a match, 2.00 in all).

The code is now in `$CODE`:

```bash
echo $CODE
```

```text
dsm:connect/v1:18B6GX3ME1SKMBSF64S3EBHG5RR2WC9T70T38CRJ41QXQJEH1V239MWMG2Q6RPQ5SJ4RD3XP78QK4KMD5G86Z5SCMB2MY6H0TPTDHBBYF15C78D78Z8ACYG4C5HQ0A6TAVSEY614C1D27CXRNWGG
```

It is long because it carries the relay's address and its certificate pin: the wallet fetches the offer itself, over TLS pinned to that certificate.

## 4. Connect the terminal wallet

```bash
dsm-dev-wallet connect "$CODE"
```

The wallet fetches the offer, checks it, and prints what My Game asks for. The terminal wallet is your test wallet, so it approves on its own, and prints the connection: its id, the app, `CONNECTED`, and the grants it now holds.

```text
My Game (account 0RHS9YDRSPR9PG9WESBX7PMGAVMEJSSVSC11QSD4NG4JPKY3XQ80) asks to:
  - Send this app: up to 0.10 ERA a time, 1.00 ERA in all
  - Prove what you own of ERA and of objects this app issued
  - Receive objects this app issues
  - See which of your contacts are here: their DSM IDs, not their names
  - Lock stakes for matches: up to 1.00 ERA a time, 2.00 ERA in all
  - Up to 64 requests that spend nothing; after them, each waits for you
approved:
connection RKBQ40RXFBYWZCJ150X3XG32V7EQYPN1SDGV96VGGTCAQCJMCSTG  My Game  CONNECTED
  grants: Send this app: up to 0.10 ERA a time, 1.00 ERA in all
  grants: Prove what you own of ERA and of objects this app issued
  grants: Receive objects this app issues
  grants: See which of your contacts are here: their DSM IDs, not their names
  grants: Lock stakes for matches: up to 1.00 ERA a time, 2.00 ERA in all
  grants: 0 of 64 requests that spend nothing used
```

A player on a phone reads the same list and decides.

## 5. See it from your app's side

```bash
dsm-app connections
```

```text
connection RKBQ40RXFBYWZCJ150X3XG32V7EQYPN1SDGV96VGGTCAQCJMCSTG  wallet HA62NJZ06ZY8C79HKM39AGTC3CMX9348RJH30GZTHA00BCSP0KV0  CONNECTED
```

One line per wallet: the connection's id, the wallet's identity, and whether it is connected. The connection's id is what every request on the next page names. The starter lists the same, with what each connection may do:

<figure class="term"><a href="images/starter-connected.webp"><img src="images/starter-connected.webp" alt="The starter's Connected wallets: each connection, the wallet's identity, its grants, and whether it is connected"></a><figcaption>Connected wallets on the starter, after the next pages' steps too, so it lists several: the ones a wallet disconnected stay listed, with what they allowed.</figcaption></figure>

## 6. On a phone

On Android, the wallet's **Apps** screen has **Connect an app**. Scan the starter's QR with **Scan code**, or open the code as a link on the same phone and press **Read**. The wallet shows the same list the terminal printed: who asks, what for, and the caps. The player approves.

<div class="shots">
<figure><img src="images/android-connect-code.webp" width="210" alt="Android: the Apps screen with a connect code and the Read button"><figcaption>A code, handed over as a link.</figcaption></figure>
<figure><img src="images/android-connect-preview.webp" width="210" alt="Android: My Game asks to connect, with the list of grants and their caps"><figcaption>Who asks, and what for.</figcaption></figure>
<figure><img src="images/android-connect-approve.webp" width="210" alt="Android: the end of the list, with Cancel and Approve"><figcaption>The player approves, or cancels.</figcaption></figure>
</div>

The iOS Simulator has no camera, so there the code opens as a link. From the repo ([building from source](setup.md#building-from-source-instead)), this opens a code in the wallet on every phone on your machine at once, the adb devices and the booted iOS Simulators (debug builds of the wallet):

```bash
make phones-connect CODE="$CODE"
```

<div class="shots">
<figure><img src="images/ios-connect-code.webp" width="210" alt="iOS: the Apps screen with a connect code and the Read button"><figcaption>The code, opened as a link.</figcaption></figure>
<figure><img src="images/ios-connect-preview.webp" width="210" alt="iOS: My Game asks to connect, with the list of grants"><figcaption>The same list on iOS.</figcaption></figure>
<figure><img src="images/ios-connect-approve.webp" width="210" alt="iOS: Cancel and Approve"><figcaption>Approve.</figcaption></figure>
<figure><img src="images/ios-connected.webp" width="210" alt="iOS: Connected to My Game, with a Disconnect button"><figcaption>Connected. The player can disconnect at any time.</figcaption></figure>
</div>

The red box says the code came from outside the wallet. Any app or web page on a phone can open such a link, so the wallet asks the player to approve only an offer they opened themselves, from the app they mean to connect.

These phones were recorded before the command line's `offer` asked to see contacts, so their lists are one line shorter than the one above.

## What each side holds now

- The wallet holds a grant it can read and end at any time.
- Your account holds a connection to the wallet.
- No keys moved, and nothing was taken on the relay's word.

A wallet connects to an app once. To connect it again, it disconnects first (the [next page](requests.md) ends with that), or a second wallet connects: `DSM_WALLET_NAME=wallet2 dsm-dev-wallet up`, then `DSM_WALLET_NAME=wallet2 dsm-dev-wallet connect $CODE`.

## The whole page, as one script

With `dsm-app up` running, this makes the terminal wallet, the offer and the connection:

```bash
dsm-dev-wallet up
CODE=$(dsm-app offer 'My Game' ERA 0.10 1.00)
echo $CODE
dsm-dev-wallet connect "$CODE"
dsm-app connections
```

Next: [Ask the wallet for things](requests.md).
