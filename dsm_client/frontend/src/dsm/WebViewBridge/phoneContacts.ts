// SPDX-License-Identifier: Apache-2.0
// The phone's contacts, as far as the wallet reads them (DSM Amendment A17):
// the one contact the user picks to link to a DSM contact, and that contact's
// photo for display. Nothing else of the phonebook is read.

import { ContactProfileV1 } from "../../proto/dsm_app_pb";
import { once } from "../EventBridge";
import { callBin } from "./transportCore";
import type { PersonProfile } from "../../domain/types";

export const PHONE_CONTACT_PICKED = "phone_contact_picked";

/**
 * Opens the phone's contact picker and answers the contact picked, or `null`
 * when the user picked none or did not allow the read.
 */
export async function pickPhoneContact(): Promise<PersonProfile | null> {
  const picked = new Promise<Uint8Array>((resolve) => {
    once(PHONE_CONTACT_PICKED, resolve);
  });
  await callBin("pickPhoneContact", new Uint8Array(0));
  const bytes = await picked;
  if (bytes.length === 0) return null;
  const p = ContactProfileV1.fromBinary(bytes);
  return { name: p.displayName, email: p.email, phone: p.phone, phoneLookupKey: p.phoneLookupKey };
}

/** A linked phone contact's photo as a data URL, or `null` when there is none to show. */
export async function phoneContactPhoto(lookupKey: string): Promise<string | null> {
  if (lookupKey.length === 0) return null;
  const bytes = await callBin("phoneContactPhoto", new TextEncoder().encode(lookupKey));
  if (bytes.length === 0) return null;
  const type = bytes[0] === 0x89 ? "image/png" : "image/jpeg";
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return `data:${type};base64,${btoa(binary)}`;
}

/** Opens the phone's share sheet with `text`, for the user to send where they choose. */
export async function shareText(text: string): Promise<void> {
  await callBin("shareText", new TextEncoder().encode(text));
}
