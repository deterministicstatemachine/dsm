// SPDX-License-Identifier: MIT OR Apache-2.0

/* eslint-disable @typescript-eslint/no-explicit-any */
import * as pb from '../proto/dsm_app_pb';
import {
  getContactsStrictBridge,
  normalizeToBytes,
  routerInvokeBin,
  requestBlePermissions as bridgeRequestBlePermissions,
} from './WebViewBridge';
import { ContactsList, AddContactArgs, AddContactResult, BilateralRelationshipDTO } from './types';

/** A contact as contacts.list states it; a contact missing what Rust always writes is refused. */
function mapContactToDTO(c: pb.ContactAddResponse): BilateralRelationshipDTO {
  const genesisHash = c.genesisHash?.v;
  const chainTip = c.chainTip?.v;
  if (c.deviceId.length !== 32) {
    throw new Error(`STRICT: contacts.list answered a contact with a ${c.deviceId.length}-byte device id`);
  }
  if (!genesisHash || genesisHash.length !== 32) {
    throw new Error('STRICT: contacts.list answered a contact without its 32-byte genesis');
  }
  if (c.signingPublicKey.length !== 64) {
    throw new Error(`STRICT: contacts.list answered a contact with a ${c.signingPublicKey.length}-byte signing key`);
  }
  if (!c.alias) {
    throw new Error('STRICT: contacts.list answered a contact without its alias');
  }
  if (chainTip !== undefined && chainTip.length !== 32) {
    throw new Error(`STRICT: contacts.list answered a contact with a ${chainTip.length}-byte tip`);
  }
  return {
    deviceId: c.deviceId,
    publicKey: c.signingPublicKey,
    alias: c.alias,
    genesisHash,
    chainTip,
    // The wire's empty string is "no address".
    bleAddress: c.bleAddress || undefined,
    genesisVerifiedOnline: c.genesisVerifiedOnline,
    sendStatus: c.sendStatus,
  };
}

import { decodeFramedEnvelopeV3 } from './decoding';
import { encodeBase32Crockford } from '../utils/textId';

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
  
  if (deviceId.length !== 32) {
    throw new Error('deviceId must be 32 bytes');
  }
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
      codec: pb.Codec.PROTO,
      body: new Uint8Array(req.toBinary()) as any,
    });

    const responseBytes = await routerInvokeBin(
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
    // Rust answers an added contact with the contact itself; a refusal is an error.
    return { accepted: true, contactId: encodeBase32Crockford(env.payload.value.deviceId) };
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
