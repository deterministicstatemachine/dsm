// SPDX-License-Identifier: Apache-2.0
// Audit 2026-10-15, item 5: a name another person chose cannot render as a
// different one, a device is named by the same fingerprint everywhere, and two
// contacts that go by one name are found to.

import { contactsNamed, deviceFingerprint, sameName, visibleText } from '../displayName';

const RLO = '\u202E';
const PDF = '\u202C';
const ZWJ = '\u200D';
const ZWSP = '\u200B';
const LRI = '\u2066';
const PDI = '\u2069';

function contact(alias: string, deviceId: string, name?: string) {
  return {
    alias,
    deviceId,
    profile: name === undefined ? undefined : { name, email: '', phone: '', phoneLookupKey: '' },
  };
}

describe('visibleText', () => {
  it('takes out bidi controls, zero-width characters and other controls', () => {
    expect(visibleText(`Alice${RLO}ecilA${PDF}`)).toBe('AliceecilA');
    expect(visibleText(`${LRI}Bob${PDI}`)).toBe('Bob');
    expect(visibleText(`Ca${ZWSP}rol${ZWJ}`)).toBe('Carol');
    expect(visibleText('Dave\u0000\u0007\u001B')).toBe('Dave');
    expect(visibleText('\uFEFFErin')).toBe('Erin');
  });

  it('keeps one space between words and trims the ends', () => {
    expect(visibleText('  Frank \t\n  Ocean  ')).toBe('Frank Ocean');
    expect(visibleText(`${RLO}${PDF}`)).toBe('');
  });

  it('leaves letters of every script alone', () => {
    expect(visibleText('Zoë 山田 Ойген')).toBe('Zoë 山田 Ойген');
  });
});

describe('deviceFingerprint', () => {
  it('is the first twelve Base32 characters in groups of four, from text or bytes', () => {
    expect(deviceFingerprint('7Q2MK4XDP9RAWXYZ0123')).toBe('7Q2M-K4XD-P9RA');
    expect(deviceFingerprint(new Uint8Array(32))).toBe('0000-0000-0000');
  });

  it('refuses an id too short to have one', () => {
    expect(() => deviceFingerprint('ABCDEFGHJKM')).toThrow(/no fingerprint/);
  });
});

describe('sameName and contactsNamed', () => {
  it('reads two names as one when only case, compatibility forms or hidden characters differ', () => {
    const names = ['alice', `Al${ZWSP}ice`, 'Ａｌｉｃｅ', ` Alice${RLO}`, 'Alicia', 'Alic', 'Bob'];
    expect(names.filter((n) => sameName('Alice', n))).toEqual(['alice', `Al${ZWSP}ice`, 'Ａｌｉｃｅ', ` Alice${RLO}`]);
  });

  it('never reads a name with nothing visible in it as the same name', () => {
    expect(['', ' ', `${RLO}${PDF}`].filter((n) => sameName(n, n))).toEqual([]);
  });

  it('finds the other contacts that go by a name, by alias or by their details', () => {
    const contacts = [
      contact('alice', 'AAAAAAAAAAAAAAAA'),
      contact('al', 'BBBBBBBBBBBBBBBB', 'Alice'),
      contact('bob', 'CCCCCCCCCCCCCCCC'),
    ];
    expect(contactsNamed(contacts, 'Alice', 'AAAAAAAAAAAAAAAA').map((c) => c.deviceId)).toEqual(['BBBBBBBBBBBBBBBB']);
    expect(contactsNamed(contacts, `Al${RLO}ice`, 'ZZZZZZZZZZZZZZZZ').map((c) => c.deviceId)).toEqual([
      'AAAAAAAAAAAAAAAA',
      'BBBBBBBBBBBBBBBB',
    ]);
    expect(contactsNamed(contacts, 'bob', 'CCCCCCCCCCCCCCCC')).toEqual([]);
  });
});
