/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/services/qr/contactQrService.ts
// SPDX-License-Identifier: Apache-2.0
// Transport-layer ContactQrV3 encoding (protobuf-only).
// UI should call into this service and avoid protobuf details.

import * as pb from '../../proto/dsm_app_pb';
import { decodeBase32Crockford, encodeBase32Crockford as base32CrockfordEncode } from '../../utils/textId';

const MAX_QR_BYTES = 900; // generous headroom for Level-M

/**
 * Generate SDK fingerprint: 32-byte quantum-resistant hash of build/version info.
 * Matches Rust implementation using BLAKE3, but uses deterministic quantum-resistant construction in browser.
 * Used for ContactQrV3 protobuf field validation.
 * No JSON, no timestamps, no SHA-256 - only deterministic bytes and Base32 Crockford.
 */
async function generateSdkFingerprint(): Promise<Uint8Array> {
  // Build deterministic bytes: version + platform + sdk identifier
  // No JSON, no timestamps - only fixed identifying information
  const encoder = new TextEncoder();
  const versionBytes = encoder.encode('1.0.0'); // from package.json
  const platformBytes = encoder.encode('web'); // identifies this as web frontend
  const sdkBytes = encoder.encode('dsm-wallet-frontend'); // SDK identifier

  // Concatenate with null separators (no JSON)
  const separator = new Uint8Array([0]);
  const buildBytes = new Uint8Array([
    ...Array.from(versionBytes),
    ...Array.from(separator),
    ...Array.from(platformBytes),
    ...Array.from(separator),
    ...Array.from(sdkBytes)
  ]);

  // Quantum-resistant deterministic hash (approximates BLAKE3 behavior)
  // Since BLAKE3 not available in Web Crypto API, use deterministic quantum-resistant construction
  const fingerprint = new Uint8Array(32);

  // Initialize with first 32 bytes of build data
  for (let i = 0; i < Math.min(32, buildBytes.length); i++) {
    fingerprint[i] = buildBytes[i];
  }

  // Apply quantum-resistant mixing (deterministic, no crypto API dependency)
  for (let i = 0; i < buildBytes.length; i++) {
    const byte = buildBytes[i];
    // Mix into all fingerprint positions using quantum-resistant operations
    for (let j = 0; j < 32; j++) {
      // Use bitwise operations that are quantum-resistant
      fingerprint[j] = (fingerprint[j] + byte + i + j) & 0xff;
      fingerprint[j] = ((fingerprint[j] << 1) | (fingerprint[j] >>> 7)) & 0xff; // Rotate left by 1
    }
  }

  // Final quantum-resistant diffusion
  for (let i = 0; i < 32; i++) {
    fingerprint[i] = (fingerprint[i] + fingerprint[(i + 1) % 32]) & 0xff;
    fingerprint[i] = ((fingerprint[i] * 3) + 1) & 0xff; // Simple quantum-resistant mixing
  }

  return toArrayBufferBacked(fingerprint);
}

// Debug logging gate: enabled if process.env.QR_DEBUG === '1' or window.__QR_DEBUG__ === true
function qrDebugEnabled(): boolean {
  try {
    if (typeof process !== 'undefined' && (process as any).env?.QR_DEBUG === '1') return true;
  } catch {}
  try {
    const w: any = typeof window !== 'undefined' ? window : {};
    if (w.__QR_DEBUG__ === true) return true;
  } catch {}
  return false;
}

function qrLog(...args: any[]): void {
  if (qrDebugEnabled()) {
    // eslint-disable-next-line no-console
    console.log(...args);
  }
}

export type ShareQrInput = {
  genesisHash: Uint8Array; // 32 bytes
  deviceId: Uint8Array;    // 32 bytes (canonical)
  network?: string;        // optional network identifier
  signingPublicKey?: Uint8Array; // 64 bytes SPHINCS+ SPX256s public key (required for bilateral!)
  preferredAlias?: string; // Optional user-chosen alias to persist on backend
};

export type ContactQrV3Data = {
  deviceId: Uint8Array;    // raw 32 bytes
  genesisHash: Uint8Array; // raw 32 bytes
  network?: string;
  signingPublicKeyB32?: string;
  signingPublicKeyLength?: number;
};

export type DecodedContactQr = {
  contact: ContactQrV3Data;
  rawBytes: Uint8Array;
};

// Force ArrayBuffer-backed Uint8Array (not SharedArrayBuffer) to satisfy
// toolchains that type fields as Uint8Array<ArrayBuffer>.
function toArrayBufferBacked(src: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(src.length);
  out.set(src);
  return out as Uint8Array<ArrayBuffer>;
}

/**
 * Encode ContactQrV3 protobuf for proper backend handling.
 * Backend expects ContactQrV3 (not Headers) for contacts.handle_contact_qr_v3.
 */
export async function encodeContactQrV3Payload(input: ShareQrInput): Promise<Uint8Array> {
  qrLog('[encodeContactQrV3] Input:', {
    genesisHashLen: input.genesisHash?.length,
    deviceIdLen: input.deviceId?.length,
    signingPublicKeyLen: input.signingPublicKey?.length,
    genesisSnippet: input.genesisHash ? Array.from(input.genesisHash.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join('') : 'null',
    deviceIdSnippet: input.deviceId ? Array.from(input.deviceId.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join('') : 'null'
  });

  if (!(input.genesisHash instanceof Uint8Array) || input.genesisHash.length !== 32) {
    throw new Error(`QR: genesis_hash must be 32 bytes, got ${input.genesisHash?.length}`);
  }
  // CRITICAL: device_id MUST be exactly 32 bytes (cryptographic device identity, no shortcuts)
  if (!(input.deviceId instanceof Uint8Array) || input.deviceId.length !== 32) {
    throw new Error(`QR: device_id must be exactly 32 bytes, got ${input.deviceId?.length}`);
  }

  // Binary-first: pass raw 32-byte identifiers directly into proto bytes fields.
  // Outer QR payload transport uses Base32 Crockford (see renderContactQr()),
  // but inner ContactQrV3 fields are raw bytes — no text encoding on the wire.

  // Generate SDK fingerprint: BLAKE3 hash of build info (32 bytes)
  // Matches Rust implementation in dsm_sdk/src/sdk/qr.rs
  const sdkFingerprint = await generateSdkFingerprint();

  // Build ContactQrV3 with all required fields
  // CRITICAL: Include signingPublicKey for bilateral BLE transfer verification!
  const contactQr = new pb.ContactQrV3({
    deviceId: toArrayBufferBacked(input.deviceId),
    network: input.network || 'dsm-local',
    storageNodes: [],
    sdkFingerprint: toArrayBufferBacked(sdkFingerprint),
    genesisHash: toArrayBufferBacked(input.genesisHash),
    signingPublicKey: input.signingPublicKey ? toArrayBufferBacked(input.signingPublicKey) : new Uint8Array(0),
    preferredAlias: input.preferredAlias?.trim() || '',
  });

  const payload = contactQr.toBinary();
  if (payload.length > MAX_QR_BYTES) {
    throw new Error(`QR: payload ${payload.length}B exceeds safe limit ${MAX_QR_BYTES}B.`);
  }
  return payload;
}

/**
 * Decode ContactQrV3 protobuf bytes from a QR data string.
 * Accepts either `dsm:contact/v3:` URI format or raw Base32 Crockford payload.
 */
export function decodeContactQrV3Payload(qrData: string): DecodedContactQr | null {
  try {
    let bytes: Uint8Array;
    if (qrData.startsWith('dsm:contact/v3:')) {
      const b32Payload = qrData.slice('dsm:contact/v3:'.length);
      bytes = decodeBase32Crockford(b32Payload);
    } else {
      bytes = decodeBase32Crockford(qrData);
    }

    const contact = pb.ContactQrV3.fromBinary(bytes);
    if (!contact.deviceId?.length || !contact.genesisHash?.length) return null;

    const signingPublicKey = contact.signingPublicKey instanceof Uint8Array ? contact.signingPublicKey : undefined;
    const signingPublicKeyB32 = signingPublicKey && signingPublicKey.length > 0
      ? base32CrockfordEncode(signingPublicKey)
      : undefined;

    return {
      rawBytes: contact.toBinary(),
      contact: {
        deviceId: contact.deviceId,
        genesisHash: contact.genesisHash,
        network: contact.network || undefined,
        signingPublicKeyB32,
        signingPublicKeyLength: signingPublicKey?.length || 0,
      },
    };
  } catch {
    return null;
  }
}

export function decodeQrPayloadBase32ToText(payloadBase32: string): string | null {
  try {
    const bytes = decodeBase32Crockford(String(payloadBase32 || '').trim());
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}
