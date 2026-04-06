// SPDX-License-Identifier: Apache-2.0
import { encodeBase32Crockford } from '../../utils/textId';

jest.mock('../WebViewBridge', () => ({
  appRouterInvokeBin: jest.fn(),
}));
jest.mock('../decoding', () => ({
  decodeFramedEnvelopeV3: jest.fn(),
}));

import { parseDeTFiHeader } from '../detfi';

function makeBlob(bytes: number[]): string {
  return encodeBase32Crockford(new Uint8Array(bytes));
}

describe('parseDeTFiHeader', () => {
  it('parses a valid vault/local header (version=1, mode=0, type=0)', () => {
    const blob = makeBlob([1, 0, 0, 0xff, 0xff]);
    const result = parseDeTFiHeader(blob);
    expect(result.success).toBe(true);
    expect(result.header).toEqual({
      version: 1,
      mode: 'local',
      type: 'vault',
      sizeBytes: 5,
    });
  });

  it('parses a valid policy/posted header (version=1, mode=1, type=1)', () => {
    const blob = makeBlob([1, 1, 1, 0xaa]);
    const result = parseDeTFiHeader(blob);
    expect(result.success).toBe(true);
    expect(result.header).toEqual({
      version: 1,
      mode: 'posted',
      type: 'policy',
      sizeBytes: 4,
    });
  });

  it('parses vault/posted (version=1, mode=1, type=0)', () => {
    const blob = makeBlob([1, 1, 0]);
    const result = parseDeTFiHeader(blob);
    expect(result.success).toBe(true);
    expect(result.header).toEqual({
      version: 1,
      mode: 'posted',
      type: 'vault',
      sizeBytes: 3,
    });
  });

  it('parses policy/local (version=1, mode=0, type=1)', () => {
    const blob = makeBlob([1, 0, 1]);
    const result = parseDeTFiHeader(blob);
    expect(result.success).toBe(true);
    expect(result.header).toEqual({
      version: 1,
      mode: 'local',
      type: 'policy',
      sizeBytes: 3,
    });
  });

  it('returns error for empty string', () => {
    const result = parseDeTFiHeader('');
    expect(result.success).toBe(false);
    expect(result.error).toBe('blob is empty');
  });

  it('returns error for whitespace-only string', () => {
    const result = parseDeTFiHeader('   \t\n  ');
    expect(result.success).toBe(false);
    expect(result.error).toBe('blob is empty');
  });

  it('returns error for blob shorter than 3 header bytes', () => {
    const blob = makeBlob([1, 0]);
    const result = parseDeTFiHeader(blob);
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/too short/);
  });

  it('returns error for unsupported version', () => {
    const blob = makeBlob([2, 0, 0]);
    const result = parseDeTFiHeader(blob);
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/unsupported version: 2/);
  });

  it('returns error for version 0', () => {
    const blob = makeBlob([0, 0, 0]);
    const result = parseDeTFiHeader(blob);
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/unsupported version: 0/);
  });

  it('returns error for invalid mode (2)', () => {
    const blob = makeBlob([1, 2, 0]);
    const result = parseDeTFiHeader(blob);
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/invalid mode: 2/);
  });

  it('returns error for invalid type (2)', () => {
    const blob = makeBlob([1, 0, 2]);
    const result = parseDeTFiHeader(blob);
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/invalid type: 2/);
  });

  it('handles non-string input gracefully', () => {
    const result = parseDeTFiHeader(undefined as unknown as string);
    expect(result.success).toBe(false);
    expect(result.error).toBe('blob is empty');
  });

  it('handles null input gracefully', () => {
    const result = parseDeTFiHeader(null as unknown as string);
    expect(result.success).toBe(false);
    expect(result.error).toBe('blob is empty');
  });

  it('trims leading/trailing whitespace before decoding', () => {
    const blob = makeBlob([1, 0, 0, 0x42]);
    const result = parseDeTFiHeader(`  ${blob}  `);
    expect(result.success).toBe(true);
    expect(result.header?.version).toBe(1);
    expect(result.header?.mode).toBe('local');
    expect(result.header?.type).toBe('vault');
  });

  it('reports sizeBytes matching the full decoded length', () => {
    const payload = new Array(100).fill(0xab);
    const blob = makeBlob([1, 1, 0, ...payload]);
    const result = parseDeTFiHeader(blob);
    expect(result.success).toBe(true);
    expect(result.header!.sizeBytes).toBe(103);
  });

  it('returns error for invalid base32 characters', () => {
    const result = parseDeTFiHeader('!!!INVALID!!!');
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });
});
