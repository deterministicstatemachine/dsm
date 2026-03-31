/* eslint-disable @typescript-eslint/no-explicit-any */
// Interactive BLE transfer test harness.
// Each step is invoked manually via UI buttons in BleTestScreen.
// Not automated — requires two physical devices.

import {
  startBleScanViaRouter,
  stopBleScanViaRouter,
  startBleAdvertisingViaRouter,
  requestBlePermissions,
  setBleIdentityForAdvertising,
  startPairingAll,
  appRouterInvokeBin,
  appRouterQueryBin,
  getDeviceIdBinBridgeAsync,
} from '../dsm/WebViewBridge';
import { decodeFramedEnvelopeV3 } from '../dsm/decoding';
import { offlineSend } from '../dsm/transactions';
import { decodeBase32Crockford, encodeBase32Crockford } from '../utils/textId';
import { bridgeEvents } from '../bridge/bridgeEvents';
import * as pb from '../proto/dsm_app_pb';

export type BleStepResult = {
  status: string;
  success: boolean;
};

export type BleRole = 'sender' | 'receiver';

export type BleStep = 'permissions' | 'discover' | 'pair' | 'send' | 'verify'
  | 'advertise' | 'accept' | 'receive';

export const SENDER_STEPS: BleStep[] = ['permissions', 'discover', 'pair', 'send', 'verify'];
export const RECEIVER_STEPS: BleStep[] = ['permissions', 'advertise', 'accept', 'receive', 'verify'];

export function getSteps(role: BleRole): BleStep[] {
  return role === 'sender' ? SENDER_STEPS : RECEIVER_STEPS;
}

// Module-level state: discovered peer from GATT identity read
let discoveredPeer: { address: string; deviceId: Uint8Array; genesisHash: Uint8Array } | null = null;

// eslint-disable-next-line @typescript-eslint/no-unused-vars
async function invokeAndDecode(method: string, body: Uint8Array): Promise<pb.Envelope> {
  const argPack = new pb.ArgPack({
    codec: pb.Codec.PROTO as any,
    body: body as any,
  });
  const resBytes = await appRouterInvokeBin(method, argPack.toBinary());
  if (!resBytes || resBytes.length === 0) {
    throw new Error(`${method}: empty response`);
  }
  return decodeFramedEnvelopeV3(resBytes);
}

async function queryAndDecode(path: string): Promise<pb.Envelope> {
  const resBytes = await appRouterQueryBin(path);
  if (!resBytes || resBytes.length === 0) {
    throw new Error(`${path}: empty response`);
  }
  return decodeFramedEnvelopeV3(resBytes);
}

function getEraBalance(balResp: pb.BalancesListResponse): number {
  const era = balResp.balances.find((b: any) => b.tokenId === 'ERA');
  return era ? Number(era.available) : 0;
}

export async function runBleInteractiveStep(
  role: BleRole,
  step: BleStep,
): Promise<BleStepResult> {
  try {
    switch (step) {
      case 'permissions': {
        await requestBlePermissions();
        return { status: 'BLE permissions granted', success: true };
      }

      // --- SENDER steps ---
      case 'discover': {
        if (role !== 'sender') {
          return { status: 'discover is a sender step', success: false };
        }
        discoveredPeer = null;
        // Listen for peer identity via protobuf binary path (contact.bleMapped from EventBridge)
        let resolved = false;
        const identityPromise = new Promise<void>(resolve => {
          const unsub = bridgeEvents.on('contact.bleMapped', (detail) => {
            if (resolved) return;
            try {
              const addr = detail?.address;
              const deviceIdB32 = detail?.deviceId;
              const genesisB32 = detail?.genesisHash;
              if (addr && deviceIdB32) {
                const deviceIdBytes = decodeBase32Crockford(deviceIdB32);
                const genesisBytes = genesisB32 ? decodeBase32Crockford(genesisB32) : new Uint8Array(32);
                if (deviceIdBytes.length === 32) {
                  discoveredPeer = {
                    address: addr,
                    genesisHash: genesisBytes,
                    deviceId: deviceIdBytes,
                  };
                  console.log(`[BLE Test] Peer identity received: addr=${addr} deviceId=${deviceIdB32.slice(0, 12)}...`);
                }
              }
            } catch (e) {
              console.warn('[BLE Test] Failed to parse peer identity event', e);
            }
            resolved = true;
            unsub();
            resolve();
          });
          // Also resolve when scan stops (no peer found within scan window)
          const unsubStop = bridgeEvents.on('ble.scanStopped', () => {
            if (!resolved) {
              resolved = true;
              unsub();
              unsubStop();
              resolve();
            }
          });
        });
        await startBleScanViaRouter();
        // Wait for peer identity or scan stop
        await identityPromise;
        await stopBleScanViaRouter();
        if (discoveredPeer) {
          const peer = discoveredPeer as { address: string; deviceId: Uint8Array; genesisHash: Uint8Array };
          return { status: `Peer discovered: ${peer.address} (identity: ${peer.deviceId.length}B)`, success: true };
        }
        return { status: 'BLE scan complete (12s). No peer identity received.', success: false };
      }

      case 'pair': {
        if (role !== 'sender') {
          return { status: 'pair is a sender step', success: false };
        }
        if (!discoveredPeer) {
          return { status: 'No peer discovered. Run DISCOVER first.', success: false };
        }
        console.log(`[BLE Test] Starting Rust pairing orchestrator for all unpaired contacts`);
        await startPairingAll();
        return {
          status: `Rust pairing orchestrator started. BLE pairing will proceed automatically.`,
          success: true,
        };
      }

      case 'send': {
        if (role !== 'sender') {
          return { status: 'send is a sender step', success: false };
        }
        if (!discoveredPeer) {
          return { status: 'No peer discovered. Run DISCOVER first.', success: false };
        }
        // Re-start advertising + scanning before the send so the receiver can
        // re-establish a GATT connection. The pairing phase stopped both, and
        // the BLE link may have dropped by the time the user presses SEND.
        const devIdSend = await getDeviceIdBinBridgeAsync();
        if (devIdSend && devIdSend.length === 32) {
          await setBleIdentityForAdvertising(new Uint8Array(32), devIdSend);
          await startBleAdvertisingViaRouter();
        }
        await startBleScanViaRouter();
        // Brief pause to let BLE stack settle and peer discover us
        await new Promise(r => setTimeout(r, 2000));

        // Get current balance before send
        const preBalEnv = await queryAndDecode('balance.list');
        let preBal = 0;
        if (preBalEnv.payload.case === 'balancesListResponse') {
          preBal = getEraBalance(preBalEnv.payload.value as pb.BalancesListResponse);
        }
        if (preBal < 1) {
          return { status: `Insufficient balance: ${preBal} ERA`, success: false };
        }
        const peerDeviceIdB32 = encodeBase32Crockford(discoveredPeer.deviceId);
        console.log(`[BLE Test] Sending 1 ERA to ${discoveredPeer.address} (${peerDeviceIdB32.slice(0, 12)}...)`);
        const txResult = await offlineSend({
          tokenId: 'ERA',
          to: peerDeviceIdB32,
          amount: 1,
          memo: 'BLE test transfer',
          bleAddress: discoveredPeer.address,
        });
        if (txResult.accepted) {
          return {
            status: `Sent 1 ERA to ${discoveredPeer.address}. Pre-balance: ${preBal}. ${txResult.result ?? ''}`,
            success: true,
          };
        }
        return {
          status: `Send failed: ${txResult.result ?? txResult.failureReason ?? 'unknown'}`,
          success: false,
        };
      }

      case 'verify': {
        // Check current ERA balance
        const balEnv = await queryAndDecode('balance.list');
        if (balEnv.payload.case !== 'balancesListResponse') {
          return { status: `balance.list: unexpected payload ${balEnv.payload.case}`, success: false };
        }
        const bal = getEraBalance(balEnv.payload.value as pb.BalancesListResponse);
        return {
          status: `Current ERA balance: ${bal}`,
          success: true,
        };
      }

      // --- RECEIVER steps ---
      case 'advertise': {
        if (role !== 'receiver') {
          return { status: 'advertise is a receiver step', success: false };
        }
        // Inject identity into BLE layer for advertising
        const devId = await getDeviceIdBinBridgeAsync();
        if (!devId || devId.length !== 32) {
          return { status: 'No device ID for BLE advertising', success: false };
        }
        // Get genesis hash from AppState via bridge
        const ghEnv = await queryAndDecode('identity.pairing_qr');
        const genesisBytes = new Uint8Array(32);
        if (ghEnv.payload.case === 'contactQrResponse') {
          // Decode genesis hash from the QR response
          console.log('[BLE Test] Got pairing QR for advertising identity');
        }

        await setBleIdentityForAdvertising(genesisBytes, devId);
        const advResult = await startBleAdvertisingViaRouter();
        if (!advResult.success) {
          return { status: `BLE advertising failed: ${advResult.error?.message}`, success: false };
        }
        return { status: 'BLE advertising started. Waiting for sender to discover...', success: true };
      }

      case 'accept': {
        if (role !== 'receiver') {
          return { status: 'accept is a receiver step', success: false };
        }
        // Re-start advertising after pairing so the sender can re-establish
        // a GATT connection for the bilateral transfer. Pairing stops advertising,
        // but the sender needs the receiver to be discoverable when it sends.
        const devIdAccept = await getDeviceIdBinBridgeAsync();
        if (devIdAccept && devIdAccept.length === 32) {
          await setBleIdentityForAdvertising(new Uint8Array(32), devIdAccept);
          await startBleAdvertisingViaRouter();
        }
        // Also start scanning so we can connect back to the sender if needed
        await startBleScanViaRouter();
        return {
          status: 'Re-advertising + scanning for bilateral transfer. Ready to receive.',
          success: true,
        };
      }

      case 'receive': {
        if (role !== 'receiver') {
          return { status: 'receive is a receiver step', success: false };
        }
        // BLE transfers are fully offline — data arrives via GATT and is applied
        // to local SQLite by the native layer. No remote storage sync needed.
        // Just check the local balance to confirm the transfer landed.
        const recvBalEnv = await queryAndDecode('balance.list');
        if (recvBalEnv.payload.case !== 'balancesListResponse') {
          return { status: `balance.list: unexpected payload ${recvBalEnv.payload.case}`, success: false };
        }
        const recvBal = getEraBalance(recvBalEnv.payload.value as pb.BalancesListResponse);
        return { status: `Local balance after BLE receive: ${recvBal} ERA. Use VERIFY to confirm.`, success: true };
      }

      default:
        return { status: `Unknown step: ${step}`, success: false };
    }
  } catch (e: any) {
    return { status: `Error: ${e?.message ?? String(e)}`, success: false };
  }
}
