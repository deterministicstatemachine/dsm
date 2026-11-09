// SPDX-License-Identifier: Apache-2.0
// What the last read of the anchor appliance said, as both skins show it. Rust reads the
// appliance (`anchor.status`); this names the three ways that read can stand and the words for
// each, so the DGen pop-up and the Modern send page say the same thing about the same read.
import type { AnchorStatus } from '../dsm/anchor';

/** What the last read of the appliance said, or that none has happened. */
export type ApplianceRead =
  | { kind: 'unread' }
  | { kind: 'read'; status: AnchorStatus }
  | { kind: 'error'; message: string };

/** The appliance answered its status and is attached. */
export function applianceConnected(read: ApplianceRead): boolean {
  return read.kind === 'read' && read.status.connected;
}

/** The one line that says where the appliance stands, Rust's own words when it gave them. */
export function applianceStateText(read: ApplianceRead): string {
  switch (read.kind) {
    case 'unread':
      return 'Not checked yet';
    case 'read':
      return read.status.statusText || (read.status.connected ? 'Connected' : 'Not connected');
    case 'error':
      return 'Not connected';
  }
}
