// SPDX-License-Identifier: Apache-2.0
//
// The guided tour, step by step. Each step names the real screen it runs on,
// the real element it points at, and, for hands-on steps, what the user has to
// do before the tour moves on. Everything the user does runs in practice mode.

import type { ScreenType } from '../../types/app';
import type { PracticeEvent } from './practiceMode';

export type TourWait =
  /** Move on once this screen is open. */
  | { kind: 'screen'; screen: ScreenType }
  /** Move on once this element is on screen. */
  | { kind: 'selector'; selector: string }
  /** Move on once nothing on screen matches this selector any more. */
  | { kind: 'gone'; selector: string }
  /** Move on once this field holds a value (a positive number when `positive`). */
  | { kind: 'value'; selector: string; positive?: boolean }
  /** Move on once practice mode reports this action. */
  | { kind: 'event'; event: PracticeEvent };

export type TourStep = {
  id: string;
  /** The screen this step runs on. The tour opens it if it is not already open. */
  screen: ScreenType;
  /** CSS selector of the element the step points at. No target: the guide just talks. */
  target?: string;
  title: string;
  body: string;
  /** Hands-on steps: what the user must do. The tour moves on by itself. */
  wait?: TourWait;
  /** Short instruction shown in place of NEXT on hands-on steps. */
  prompt?: string;
  /** A home menu brick to highlight, so pressing A opens it. */
  menuItem?: string;
  /** Clicking an element matching this selector means the user backed out: go back one step. */
  backOn?: string;
};

export const TOUR_STEPS: ReadonlyArray<TourStep> = [
  {
    id: 'welcome',
    screen: 'home',
    title: 'Welcome to StateBoy',
    body: "I'm your guide. I'll take you through every screen and point at each thing as we go. You'll try things for real, in practice mode: nothing you do in this tour touches your wallet.",
  },
  {
    id: 'button-a',
    screen: 'home',
    target: '#button-a',
    title: 'This is A',
    body: 'A picks whatever is highlighted. Press it now to keep going.',
  },
  {
    id: 'button-b',
    screen: 'home',
    target: '#button-b',
    title: 'This is B',
    body: 'B steps back: out of a screen, or back one step in this tour. Tap NEXT to carry on.',
  },
  {
    id: 'dpad',
    screen: 'home',
    target: '.new-dpad, #dpad-up',
    title: 'The D-pad',
    body: 'The D-pad moves the highlight through a menu. You can always tap the screen instead.',
  },
  {
    id: 'start-select',
    screen: 'home',
    target: '#button-start',
    title: 'START and SELECT',
    body: 'START turns sound on and off. SELECT, right beside it, changes the color theme. Long-press SELECT to change the shell itself: gold, zebra, leopard and more.',
  },
  {
    id: 'menu',
    screen: 'home',
    target: '.dsm-menu[aria-label="Main Menu"]',
    title: 'The main menu',
    body: 'Every part of the wallet starts from here.',
  },
  {
    id: 'go-wallet',
    screen: 'home',
    target: '.dsm-menu-item[data-label="WALLET"]',
    menuItem: 'WALLET',
    title: 'Your turn',
    body: "Tap WALLET to open your wallet. Pressing A works too, because it's highlighted.",
    wait: { kind: 'screen', screen: 'wallet' },
    prompt: 'Tap WALLET',
  },
  {
    id: 'balances',
    screen: 'wallet',
    target: '[aria-label="Your balances"]',
    title: 'Your balances',
    body: 'Every token you hold shows here. These are practice numbers: 1000 ERA and 50 PLAY to play with.',
  },
  {
    id: 'wallet-tabs',
    screen: 'wallet',
    target: '.sb-tabs[aria-label="Wallet sections"]',
    title: 'Wallet tabs',
    body: 'These tabs switch the wallet between Overview, Send, History and Bitcoin. Swapping lives on the TRADE screen.',
  },
  {
    id: 'go-send',
    screen: 'wallet',
    target: '.overview-tab .sb-actions .sb-btn--primary',
    title: "Let's send something",
    body: "Tap Send. We'll pay some practice tokens to alice, a practice contact.",
    wait: { kind: 'selector', selector: '.send-tab' },
    prompt: 'Tap Send',
  },
  {
    id: 'ticker',
    screen: 'wallet',
    target: '.send-tab > .sb-card',
    title: 'Your token ticker',
    body: "Do you see this? That short name is the token's ticker, the quickest way to know which token you're dealing with. The number beside it is how much of it you hold.",
  },
  {
    id: 'mode',
    screen: 'wallet',
    target: '.send-tab [aria-label="Transaction mode"]',
    title: 'Online or offline',
    body: "Online goes through the storage nodes and waits in their inbox, even if they're asleep. Offline goes phone to phone over Bluetooth when you're side by side. Let's look at Offline for a moment.",
  },
  {
    id: 'go-offline',
    screen: 'wallet',
    target: '.send-tab [aria-label="Transaction mode"] button:nth-of-type(2)',
    title: 'Try Offline',
    body: 'Tap Offline. An offline send needs two more things besides Bluetooth, and they appear here.',
    wait: { kind: 'selector', selector: '[data-tour="offline-funding"]' },
    prompt: 'Tap Offline',
  },
  {
    id: 'offline-funding',
    screen: 'wallet',
    target: '[data-tour="offline-funding"]',
    title: 'Offline funding',
    body: 'Offline sends spend from a separate pot: your offline allocation, which the anchor appliance guards. Offline Funding moves tokens from your online account into that pot, and back again. The i beside it explains the two balances.',
  },
  {
    id: 'appliance',
    screen: 'wallet',
    target: '[data-tour="appliance-setup"]',
    title: 'The appliance',
    body: "The DSM Anchor appliance plugs into this phone's USB port. Appliance shows whether it is connected and walks you through the first plug-in. Android asks for permission once; after that it connects on its own whenever you choose Offline.",
  },
  {
    id: 'go-online',
    screen: 'wallet',
    target: '.send-tab [aria-label="Transaction mode"] button:nth-of-type(1)',
    title: 'Back to Online',
    body: "We'll send online in this tour. Tap Online.",
    wait: { kind: 'gone', selector: '[data-tour="offline-funding"]' },
    prompt: 'Tap Online',
  },
  {
    id: 'info',
    screen: 'wallet',
    target: '.send-tab [aria-label="About sending modes"]',
    title: 'Stuck? Look for i',
    body: 'Tap an i on any screen for a plain explanation of what is there.',
  },
  {
    id: 'recipient',
    screen: 'wallet',
    target: '#recipient',
    title: 'Who gets it',
    body: "Pick who you're paying. Choose alice from the list.",
    wait: { kind: 'value', selector: '#recipient' },
    prompt: 'Pick alice',
  },
  {
    id: 'recipient-check',
    screen: 'wallet',
    target: '[data-testid="send-recipient-confirm"]',
    title: 'Check who',
    body: "Did you notice that line? It spells out the device you're paying. A name can be anything; this is who it really goes to.",
  },
  {
    id: 'amount',
    screen: 'wallet',
    target: '#amount',
    title: 'How much',
    body: 'Now go ahead and enter an amount. Try 25.',
    wait: { kind: 'value', selector: '#amount', positive: true },
    prompt: 'Type an amount',
  },
  {
    id: 'token',
    screen: 'wallet',
    target: '.send-tab .sb-tokensel--inline',
    title: 'Which token',
    body: "This is the token it'll be paid in. When you hold more than one, make sure this ticker is the one you mean.",
  },
  {
    id: 'double-check',
    screen: 'wallet',
    target: '.send-tab .sb-input-row',
    title: 'Stop and look',
    body: "Before you hit Send, check the amount and the token together. You'll be asked to confirm, but pay attention now: once it's sent, there is no undo.",
  },
  {
    id: 'press-send',
    screen: 'wallet',
    target: '.send-tab button[type="submit"]',
    title: 'Send it',
    body: 'Happy with it? Tap Send.',
    wait: { kind: 'selector', selector: '.bilateral-transfer-dialog' },
    prompt: 'Tap Send',
  },
  {
    id: 'confirm',
    screen: 'wallet',
    target: '.bilateral-transfer-dialog',
    title: 'Last look',
    body: 'This is your last chance to back out. Read it once more: the amount, the token, and who. Then tap Confirm.',
    wait: { kind: 'event', event: 'sent' },
    prompt: 'Tap Confirm',
    backOn: '.bilateral-btn-reject',
  },
  {
    id: 'sent',
    screen: 'wallet',
    target: '[aria-label="Your balances"]',
    title: 'Sent',
    body: "Done. Your practice balance went down by exactly what you sent. For real, it would now be waiting in alice's inbox, even if her phone is off.",
  },
  {
    id: 'go-tokens',
    screen: 'home',
    target: '.dsm-menu-item[data-label="TOKENS"]',
    menuItem: 'TOKENS',
    title: 'Tokens',
    body: "Let's look at your tokens. Tap TOKENS.",
    wait: { kind: 'screen', screen: 'accounts' },
    prompt: 'Tap TOKENS',
  },
  {
    id: 'token-tabs',
    screen: 'accounts',
    target: '[data-tour="tokens-tabs"]',
    title: 'Balances and Faucet',
    body: 'Balances lists every token on this wallet. Faucet hands out free ERA so you can try things.',
  },
  {
    id: 'create-token',
    screen: 'accounts',
    target: '[data-tour="create-token"]',
    title: 'Your own token',
    body: 'Create Token makes a token of your own, under rules you set when you make it.',
  },
  {
    id: 'go-faucet',
    screen: 'accounts',
    target: '[data-tour="tokens-tabs"] button:nth-of-type(2)',
    title: 'Free tokens',
    body: 'Open the Faucet tab.',
    wait: { kind: 'selector', selector: '[data-tour="faucet-claim"]' },
    prompt: 'Tap Faucet',
  },
  {
    id: 'claim',
    screen: 'accounts',
    target: '[data-tour="faucet-claim"]',
    title: 'Claim some',
    body: "Tap Claim Faucet. In practice you'll get 100 ERA straight away.",
    wait: { kind: 'event', event: 'claimed' },
    prompt: 'Tap Claim Faucet',
  },
  {
    id: 'claimed',
    screen: 'accounts',
    target: '[data-tour="tokens-tabs"]',
    title: 'There they are',
    body: 'Your practice ERA just went up by 100. Balances shows every token you hold, any time.',
  },
  {
    id: 'go-balances',
    screen: 'accounts',
    target: '[data-tour="tokens-tabs"] button:nth-of-type(1)',
    title: 'Back to Balances',
    body: 'Open Balances again.',
    wait: { kind: 'selector', selector: '.tokens-tab' },
    prompt: 'Tap Balances',
  },
  {
    id: 'token-row',
    screen: 'accounts',
    target: '.tokens-tab .token-card',
    title: 'Open a token',
    body: 'Each token is a card. Tap one to open it.',
    wait: { kind: 'selector', selector: '.token-card.is-open' },
    prompt: 'Tap a token',
  },
  {
    id: 'token-detail',
    screen: 'accounts',
    target: '.token-card.is-open .sb-card--dark',
    title: 'What a token is',
    body: "Its supply, its decimals and who defined it: the rules it was made with, and nobody can change them. A token you adopted also offers Burn, which destroys some of what you hold, and Forget, which hides it.",
  },
  {
    id: 'go-trade',
    screen: 'home',
    target: '.dsm-menu-item[data-label="TRADE"]',
    menuItem: 'TRADE',
    title: 'Trade',
    body: 'Now the market. Tap TRADE.',
    wait: { kind: 'screen', screen: 'sofi' },
    prompt: 'Tap TRADE',
  },
  {
    id: 'trade-tabs',
    screen: 'sofi',
    target: '.sb-tabs[aria-label="SoFi sections"]',
    title: 'Sovereign liquidity',
    body: 'This is SoFi: sovereign finance. Swap trades one token for another. Liquidity is where that comes from: vaults that people like you put up. No exchange sits in the middle; it settles between devices.',
  },
  {
    id: 'trade-quote',
    screen: 'sofi',
    target: '.swap-tab .sb-btn--primary.sb-btn--block',
    title: 'Quote, then trade',
    body: "Pick what you pay and what you want, then Quote. You see the exact amount you'd get before anything moves. Trade lands at a position, or is void if someone else's trade won the race, and then nothing moved. We won't trade in the tour.",
  },
  {
    id: 'go-liquidity',
    screen: 'sofi',
    target: '.sb-tabs[aria-label="SoFi sections"] button:nth-of-type(2)',
    title: 'Liquidity',
    body: 'Open the Liquidity tab.',
    wait: { kind: 'selector', selector: '.liquidity-tab' },
    prompt: 'Tap Liquidity',
  },
  {
    id: 'liquidity-vault',
    screen: 'sofi',
    target: '.liquidity-tab .sb-btn--primary.sb-btn--block',
    title: 'Your own liquidity vault',
    body: 'Create Liquidity Vault puts two of your tokens into a vault of your own, at the price their amounts set. Every trade against it pays you the fee you choose. Close it any time and the reserves come back to you.',
  },
  {
    id: 'resolve',
    screen: 'sofi',
    target: '.sofi-screen .sb-screen__actions .sb-btn',
    title: 'Resolve',
    body: 'If a trade was cut short, Resolve finishes what this phone still has pending. You will rarely need it.',
  },
  {
    id: 'go-contacts',
    screen: 'home',
    target: '.dsm-menu-item[data-label="CONTACTS"]',
    menuItem: 'CONTACTS',
    title: 'Contacts',
    body: 'Next, the people you deal with. Tap CONTACTS.',
    wait: { kind: 'screen', screen: 'contacts' },
    prompt: 'Tap CONTACTS',
  },
  {
    id: 'contact-tabs',
    screen: 'contacts',
    target: '[data-tour="contacts-tabs"]',
    title: 'Your contacts',
    body: "My Contacts lists everyone you've added. Add Contact scans someone's code to add them. My QR shows your own code, so others can add you.",
  },
  {
    id: 'add-contact',
    screen: 'contacts',
    target: '[data-tour="contacts-tabs"] button:nth-of-type(2)',
    title: 'Adding someone',
    body: "Add Contact scans the code on their phone, or takes it pasted. What you add is their device, not a name: the name is only the label you give it.",
  },
  {
    id: 'go-my-qr',
    screen: 'contacts',
    target: '[data-tour="contacts-tabs"] button:nth-of-type(3)',
    title: 'Your code',
    body: 'Open My QR.',
    wait: { kind: 'selector', selector: '.my-contact' },
    prompt: 'Tap My QR',
  },
  {
    id: 'my-qr',
    screen: 'contacts',
    target: '.my-contact .sb-card--hero',
    title: 'This is you',
    body: "Someone scans this once and you're in their contacts. Every payment they send you after that goes to this device, whatever they call you.",
  },
  {
    id: 'contact-code',
    screen: 'contacts',
    target: '[aria-label="Copy contact code"]',
    title: "Can't scan?",
    body: 'Copy the code and send it any way you like. It says the same thing as the picture.',
  },
  {
    id: 'go-storage',
    screen: 'home',
    target: '.dsm-menu-item[data-label="STORAGE"]',
    menuItem: 'STORAGE',
    title: 'Storage',
    body: 'Tap STORAGE.',
    wait: { kind: 'screen', screen: 'storage' },
    prompt: 'Tap STORAGE',
  },
  {
    id: 'storage',
    screen: 'storage',
    target: '.sb-tabs[aria-label="Storage sections"]',
    title: 'Storage nodes',
    body: "Storage nodes keep copies of what you publish, so people can reach you while you're offline. They hold bytes and decide nothing. These tabs show your set and each node in it.",
  },
  {
    id: 'storage-set',
    screen: 'storage',
    target: '[aria-label="Storage set status"]',
    title: 'Your set',
    body: 'Answered is how many of your nodes replied just now. Syncs counts the times this phone caught up with them. Local DB is what this phone keeps of its own.',
  },
  {
    id: 'go-members',
    screen: 'storage',
    target: '.sb-tabs[aria-label="Storage sections"] button:nth-of-type(2)',
    title: 'The nodes',
    body: 'Open Members.',
    wait: { kind: 'selector', selector: '[aria-label="Storage members"]' },
    prompt: 'Tap Members',
  },
  {
    id: 'members',
    screen: 'storage',
    target: '[aria-label="Storage members"]',
    title: 'Each node',
    body: 'One row per node, with a dot for whether it answered. Tap a row for what it holds of yours. A quiet node is only quiet: nodes keep bytes and decide nothing.',
  },
  {
    id: 'go-settings',
    screen: 'home',
    target: '.dsm-menu-item[data-label="SETTINGS"]',
    menuItem: 'SETTINGS',
    title: 'Settings',
    body: 'Last stop. Tap SETTINGS.',
    wait: { kind: 'screen', screen: 'settings' },
    prompt: 'Tap SETTINGS',
  },
  {
    id: 'version',
    screen: 'settings',
    target: '.settings-screen button.sb-card',
    title: 'Developer options',
    body: 'Tap the version seven times and Developer Options appears: policy tools, for tokens you build yourself.',
  },
  {
    id: 'security',
    screen: 'settings',
    target: '[aria-labelledby="security-section-title"]',
    title: 'Lock it',
    body: 'Lock the wallet with a PIN, a button combo or your fingerprint, so nobody else can open it.',
  },
  {
    id: 'ring',
    screen: 'settings',
    target: '[aria-labelledby="nfc-section-title"]',
    title: 'Ring backup',
    body: 'An NFC ring can carry your backup. If you lose this phone, the ring brings your wallet back on a new one.',
  },
  {
    id: 'replay',
    screen: 'settings',
    target: '[data-tour="tutorial-button"]',
    title: 'Come back any time',
    body: 'You can replay this tour from here whenever you like.',
  },
  {
    id: 'done',
    screen: 'home',
    target: '.dsm-menu-item[data-label="WALLET"]',
    title: "You're ready",
    body: 'That is everything. Your real wallet is back, exactly as you left it. Press B to back out of any screen, and look for i whenever you want an explanation.',
  },
];
