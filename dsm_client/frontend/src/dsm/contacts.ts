// SPDX-License-Identifier: MIT OR Apache-2.0

/* eslint-disable @typescript-eslint/no-explicit-any */
import * as pb from '../proto/dsm_app_pb';
import {
  getContactsStrictBridge,
  routerInvokeBin,
  routerQueryBin,
  requestBlePermissions as bridgeRequestBlePermissions,
} from './WebViewBridge';
import { ContactsList, AddContactArgs, AddContactResult, BilateralRelationshipDTO, ContactCard } from './types';

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

/** Rust's refusal, worded as Rust worded it. */
function refusal(route: string, e: pb.Error): Error {
  return new Error(e.message || `${route} failed with code ${e.code}`);
}

/** This device's contact code: the text its QR encodes, as Rust renders it. */
export async function getContactCode(): Promise<string> {
  const env = decodeFramedEnvelopeV3(await routerQueryBin('identity.contact_code'));
  if (env.payload.case === 'error') throw refusal('identity.contact_code', env.payload.value);
  if (env.payload.case !== 'appStateResponse' || env.payload.value.key !== 'contact_code' || !env.payload.value.value) {
    throw new Error(`STRICT: identity.contact_code answered ${env.payload.case} without the code`);
  }
  return env.payload.value.value;
}

/**
 * The card a scanned or pasted contact code carries. Rust reads the code and
 * refuses one that is not whole or names another network than this device's.
 */
export async function readContactCode(text: string): Promise<ContactCard> {
  const scanned = new pb.QrScanResultPayload({ textUtf8: text });
  const pack = new pb.ArgPack({ codec: pb.Codec.PROTO, body: scanned.toBinary() as any });
  const env = decodeFramedEnvelopeV3(await routerQueryBin('contacts.readContactCode', pack.toBinary()));
  if (env.payload.case === 'error') throw refusal('contacts.readContactCode', env.payload.value);
  if (env.payload.case !== 'contactQrResponse') {
    throw new Error(`STRICT: contacts.readContactCode answered ${env.payload.case}`);
  }
  const card = env.payload.value;
  if (card.deviceId.length !== 32 || card.genesisHash.length !== 32 || card.signingPublicKey.length !== 64 || !card.network) {
    throw new Error('STRICT: contacts.readContactCode answered a card without its identity');
  }
  return {
    deviceId: card.deviceId,
    genesisHash: card.genesisHash,
    signingPublicKey: card.signingPublicKey,
    network: card.network,
    preferredAlias: card.preferredAlias || undefined,
  };
}

/**
 * Adds the contact a card names. Rust resolves the device's directory entry on
 * the pinned set first and answers the contact it added, or its refusal.
 */
export async function addContact(args: AddContactArgs): Promise<AddContactResult> {
  try {
    const req = new pb.ContactManualAddRequest({
      alias: args.alias,
      deviceId: args.deviceId as any,
      genesisHash: args.genesisHash as any,
      signingPublicKey: args.signingPublicKey as any,
    });
    const argPack = new pb.ArgPack({
      codec: pb.Codec.PROTO,
      body: new Uint8Array(req.toBinary()) as any,
    });
    const env = decodeFramedEnvelopeV3(await routerInvokeBin('contacts.addManual', argPack.toBinary()));
    if (env.payload.case === 'error') throw refusal('contacts.addManual', env.payload.value);
    if (env.payload.case !== 'contactAddResponse') {
      throw new Error(`STRICT: contacts.addManual answered ${env.payload.case}`);
    }
    const added = env.payload.value;
    return { accepted: true, contactId: encodeBase32Crockford(added.deviceId), alias: added.alias };
  } catch (e) {
    return {
      accepted: false,
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

export async function requestBlePermissions(): Promise<void> {
    return bridgeRequestBlePermissions();
}
