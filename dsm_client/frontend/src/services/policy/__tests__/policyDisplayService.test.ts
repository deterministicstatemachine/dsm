// SPDX-License-Identifier: Apache-2.0
import { mapPoliciesToDisplayEntries, PolicyRecord } from '../policyDisplayService';
import { shortId, prettyAnchor } from '../../../utils/anchorDisplay';

function make32(seed: number): Uint8Array {
  const b = new Uint8Array(32);
  for (let i = 0; i < 32; i++) b[i] = (seed + i) & 0xff;
  return b;
}

describe('mapPoliciesToDisplayEntries', () => {
  it('maps a single policy with all metadata', () => {
    const hash = make32(0x10);
    const policies: PolicyRecord[] = [
      {
        alias: 'My Token',
        ticker: 'MTK',
        policy_hash: hash,
        metadata: { ticker: 'MTK', alias: 'My Token', decimals: 8, maxSupply: '21000000' },
      },
    ];
    const entries = mapPoliciesToDisplayEntries(policies);
    expect(entries).toHaveLength(1);
    expect(entries[0].label).toBe('MTK');
    expect(entries[0].shortId).toBe(shortId(hash));
    expect(entries[0].prettyAnchor).toBe(prettyAnchor(hash));
    expect(entries[0].ticker).toBe('MTK');
    expect(entries[0].alias).toBe('My Token');
    expect(entries[0].decimals).toBe(8);
    expect(entries[0].maxSupply).toBe('21000000');
  });

  it('falls back to alias/name for label when no metadata ticker', () => {
    const hash = make32(0x20);
    const policies: PolicyRecord[] = [
      { alias: 'FallbackAlias', policy_hash: hash },
    ];
    const entries = mapPoliciesToDisplayEntries(policies);
    expect(entries).toHaveLength(1);
    expect(entries[0].label).toBe('FallbackAlias');
  });

  it('uses shortId as label when no identifier fields at all', () => {
    const hash = make32(0x30);
    const policies: PolicyRecord[] = [{ policy_hash: hash }];
    const entries = mapPoliciesToDisplayEntries(policies);
    expect(entries).toHaveLength(1);
    expect(entries[0].label).toBe(shortId(hash));
  });

  it('skips policies without any 32-byte anchor', () => {
    const policies: PolicyRecord[] = [
      { alias: 'NoBytesPolicy', policy_hash: null },
      { alias: 'ShortBytes', policy_hash: new Uint8Array(16) },
    ];
    const entries = mapPoliciesToDisplayEntries(policies);
    expect(entries).toHaveLength(0);
  });

  it('extracts from policy_hash with nested .v field', () => {
    const hash = make32(0x40);
    const policies: PolicyRecord[] = [
      { alias: 'Nested', policy_hash: { v: hash } },
    ];
    const entries = mapPoliciesToDisplayEntries(policies);
    expect(entries).toHaveLength(1);
    expect(entries[0].shortId).toBe(shortId(hash));
  });

  it('extracts from policy_hash with nested .value field', () => {
    const hash = make32(0x50);
    const policies: PolicyRecord[] = [
      { alias: 'NestedVal', policy_hash: { value: hash } },
    ];
    const entries = mapPoliciesToDisplayEntries(policies);
    expect(entries).toHaveLength(1);
    expect(entries[0].shortId).toBe(shortId(hash));
  });

  it('falls back to policyHash when policy_hash is absent', () => {
    const hash = make32(0x60);
    const policies: PolicyRecord[] = [
      { alias: 'AltHash', policyHash: hash },
    ];
    const entries = mapPoliciesToDisplayEntries(policies);
    expect(entries).toHaveLength(1);
    expect(entries[0].shortId).toBe(shortId(hash));
  });

  it('falls back to policy_commit when hashes are absent', () => {
    const commit = make32(0x70);
    const policies: PolicyRecord[] = [
      { alias: 'Commit', policy_commit: commit },
    ];
    const entries = mapPoliciesToDisplayEntries(policies);
    expect(entries).toHaveLength(1);
    expect(entries[0].shortId).toBe(shortId(commit));
  });

  it('falls back to policyCommit when all others are absent', () => {
    const commit = make32(0x80);
    const policies: PolicyRecord[] = [
      { alias: 'PCom', policyCommit: commit },
    ];
    const entries = mapPoliciesToDisplayEntries(policies);
    expect(entries).toHaveLength(1);
    expect(entries[0].shortId).toBe(shortId(commit));
  });

  it('handles an empty array', () => {
    expect(mapPoliciesToDisplayEntries([])).toEqual([]);
  });

  it('handles null/undefined input', () => {
    expect(mapPoliciesToDisplayEntries(null)).toEqual([]);
    expect(mapPoliciesToDisplayEntries(undefined)).toEqual([]);
  });

  it('coerces { policies: [...] } wrapper objects', () => {
    const hash = make32(0x90);
    const wrapper = {
      policies: [{ alias: 'Wrapped', policy_hash: hash }],
    };
    const entries = mapPoliciesToDisplayEntries(wrapper);
    expect(entries).toHaveLength(1);
    expect(entries[0].label).toBe('Wrapped');
  });

  it('maps multiple policies preserving order', () => {
    const h1 = make32(0xa0);
    const h2 = make32(0xb0);
    const policies: PolicyRecord[] = [
      { alias: 'First', policy_hash: h1 },
      { alias: 'Second', policy_hash: h2 },
    ];
    const entries = mapPoliciesToDisplayEntries(policies);
    expect(entries).toHaveLength(2);
    expect(entries[0].label).toBe('First');
    expect(entries[1].label).toBe('Second');
  });

  it('prefers metadata.ticker over alias for label', () => {
    const hash = make32(0xc0);
    const policies: PolicyRecord[] = [
      {
        alias: 'AliasName',
        policy_hash: hash,
        metadata: { ticker: 'TKR' },
      },
    ];
    const entries = mapPoliciesToDisplayEntries(policies);
    expect(entries[0].label).toBe('TKR');
  });

  it('uses policyId as id fallback in label chain', () => {
    const hash = make32(0xd0);
    const policies: PolicyRecord[] = [
      { policyId: 'pol-123', policy_hash: hash },
    ];
    const entries = mapPoliciesToDisplayEntries(policies);
    expect(entries[0].label).toBe('pol-123');
  });
});
