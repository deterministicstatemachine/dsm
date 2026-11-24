// SPDX-License-Identifier: Apache-2.0
// The home screen's chameleon hands the user to the b0x inbox: tapping the
// envelope on his tongue asks for it, and the wallet screen's inbox opens
// when it comes up. One tap, one opening.

export type InboxAsk = 'open' | 'none';

let ask: InboxAsk = 'none';

/** The user tapped the envelope: the inbox opens when the wallet screen comes up. */
export function askForInbox(): void {
  ask = 'open';
}

/** What was asked since the last look, and the ask is spent. */
export function takeInboxAsk(): InboxAsk {
  const asked = ask;
  ask = 'none';
  return asked;
}
