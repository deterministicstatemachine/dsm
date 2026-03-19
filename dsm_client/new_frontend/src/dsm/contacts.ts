/* eslint-disable @typescript-eslint/no-explicit-any */
import * as pb from '../proto/dsm_app_pb';
import {
  getContactsStrictBridge,
  normalizeToBytes,
  appRouterInvokeBin,
  requestBlePermissions as bridgeRequestBlePermissions,
} from './WebViewBridge';
import { ContactsList, AddContactArgs, AddContactResult, BilateralRelationshipDTO, ChainTipDTO } from './types';

function mapContactToDTO(c: any): BilateralRelationshipDTO {
  // ═══════════════════════════════════════════════════════════════════════
  // INVARIANT: Proto data uses camelCase field names from @bufbuild/protobuf.
  // DO NOT add snake_case fallbacks (e.g. c.device_id ?? c.deviceId).
  // If you see snake_case data, the bridge is returning raw objects — fix
  // the bridge, not the mapper. ESLint enforces this via no-restricted-syntax.
  // ═══════════════════════════════════════════════════════════════════════
  const deviceId = c.deviceId instanceof Uint8Array ? c.deviceId : new Uint8Array();
  const alias = c.alias || '';
  const verifyCounter = typeof c.verifyCounter === 'bigint' ? c.verifyCounter : BigInt(c.verifyCounter || 0);
  const signingPublicKey = c.signingPublicKey instanceof Uint8Array ? c.signingPublicKey : new Uint8Array();

  const genesisHash = (c.genesisHash instanceof Uint8Array)
      ? c.genesisHash
      : (c.genesisHash?.v instanceof Uint8Array ? c.genesisHash.v : undefined);

  const tipHash = c.chainTip?.v instanceof Uint8Array ? c.chainTip.v : undefined;

  let tip: ChainTipDTO | undefined = undefined;
  if (tipHash) {
      tip = { tipHash };
  }

  const bleAddr = c.bleAddress || '';

  return {
    deviceId,
    publicKey: signingPublicKey,
    alias,
    genesisHash,
    lastSeenTick: verifyCounter,
    chainTip: tip,
    bleAddress: typeof bleAddr === 'string' && bleAddr.length > 0 ? bleAddr : undefined,
    genesisVerifiedOnline: c.genesisVerifiedOnline === true,
    addedCounter: typeof c.addedCounter === 'bigint' ? c.addedCounter : BigInt(c.addedCounter || 0),
  };
}

import { decodeFramedEnvelopeV3 } from './decoding';

export async function getContacts(): Promise<ContactsList> {
  try {
    const responseBytes = await getContactsStrictBridge();

    if (!responseBytes || responseBytes.length === 0) {
      throw new Error('getContacts: empty response from bridge');
    }

    const env = decodeFramedEnvelopeV3(responseBytes);

    // Check for top-level error
    if (env.payload.case === 'error') {
      const err = env.payload.value;
      throw new Error(`DSM native error (contacts): code=${err.code} msg=${err.message}`);
    }

    // Extract contacts from envelope
    if (env.payload.case !== 'contactsListResponse') {
      console.error('[getContacts] Unexpected payload.case:', env.payload.case);
      throw new Error(`Unexpected payload case for contacts: ${env.payload.case}`);
    }

    const contactsResponse = env.payload.value;
    if (!contactsResponse) {
      throw new Error('contactsListResponse payload is null');
    }

    const contacts = contactsResponse.contacts.map(mapContactToDTO);
    return { contacts, total: contacts.length };

  } catch (e) {
    console.error('[getContacts] Failed to decode response:', e);
    throw e;
  }
}

export async function addContact(args: AddContactArgs): Promise<AddContactResult> {
  if (!args.alias) {
    throw new Error('alias required');
  }
  const deviceId = normalizeToBytes(args.deviceId);
  const genesisHash = normalizeToBytes(args.genesisHash);
  const signingPublicKey = normalizeToBytes(args.signingPublicKey);
  
  if (genesisHash.length !== 32) {
    throw new Error('genesisHash must be 32 bytes');
  }
  if (signingPublicKey.length !== 64) {
    throw new Error('signingPublicKey must be 64 bytes');
  }
  try {
    const req = new pb.ContactManualAddRequest({
      alias: args.alias,
      deviceId: deviceId as any,
      genesisHash: genesisHash as any,
      signingPublicKey: signingPublicKey as any,
    });

    const argPack = new pb.ArgPack({
      schemaHash: { v: new Uint8Array(32) },
      codec: pb.Codec.PROTO,
      body: new Uint8Array(req.toBinary()) as any,
    });

    const responseBytes = await appRouterInvokeBin(
      'contacts.addManual',
      argPack.toBinary()
    );

    // Canonical Envelope v3 decode
    const env = decodeFramedEnvelopeV3(responseBytes);
    if (env.payload.case === 'error') {
      const errMsg = env.payload.value.message || `Error code ${env.payload.value.code}`;
      throw new Error(`addContact failed: ${errMsg}`);
    }
    if (env.payload.case !== 'contactAddResponse') {
      throw new Error(`Expected contactAddResponse, got ${env.payload.case}`);
    }
    const resp = env.payload.value;
    const success = !!resp.alias; // Check if we got back an alias
    
    return {
      accepted: success,
      contactId: undefined, // Could map resp.deviceId to B32 if utility available
      error: success ? undefined : 'Empty response or failure'
    };
  } catch (e) {
    console.error('[addContact] Bridge call failed:', e);
    return {
      accepted: false,
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

export async function requestBlePermissions(): Promise<void> {
    return bridgeRequestBlePermissions();
}
