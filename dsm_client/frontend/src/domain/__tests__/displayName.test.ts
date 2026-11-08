// SPDX-License-Identifier: Apache-2.0
// Audit 2026-10-15, item 5: a name another person chose cannot render as a
// different one, a device is named by the same fingerprint everywhere, and two
// contacts that go by one name are found to. Audit 2026-10-18, SA-159: neither
// holds while a name can hide in a letter that draws as blank space or in a
// letter of another script that looks the same.

import { contactsNamed, deviceFingerprint, sameName, visibleText } from '../displayName';

const RLO = '\u202E';
const PDF = '\u202C';
const ZWJ = '\u200D';
const ZWSP = '\u200B';
const LRI = '\u2066';
const PDI = '\u2069';
/** The Hangul fillers: letters (Lo) that draw as blank space. */
const HANGUL_CHOSEONG_FILLER = '\u115F';
const HANGUL_JUNGSEONG_FILLER = '\u1160';
const HANGUL_FILLER = '\u3164';
const HALFWIDTH_HANGUL_FILLER = '\uFFA0';
const CGJ = '\u034F';
const VS16 = '\uFE0F';
const TAG_A = '\u{E0061}';
const BRAILLE_BLANK = '\u2800';
const NULL_NOTEHEAD = '\u{1D159}';
/** Cyrillic and Greek letters drawn as Latin ones. */
const CYRILLIC_A = '\u0410';
const CYRILLIC_SMALL_A = '\u0430';
const CYRILLIC_SMALL_IE = '\u0435';
const CYRILLIC_SMALL_O = '\u043E';
const GREEK_ALPHA = '\u0391';

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

  it('takes out the Hangul fillers, every other default-ignorable character and the blank symbols (SA-159)', () => {
    expect(visibleText(`Alice${HANGUL_FILLER}`)).toBe('Alice');
    expect(visibleText(`${HANGUL_CHOSEONG_FILLER}${HANGUL_JUNGSEONG_FILLER}Bob`)).toBe('Bob');
    expect(visibleText(`Ca${HALFWIDTH_HANGUL_FILLER}rol`)).toBe('Carol');
    expect(visibleText(`Da${CGJ}ve${VS16}${TAG_A}`)).toBe('Dave');
    expect(visibleText(`E${BRAILLE_BLANK}rin${NULL_NOTEHEAD}`)).toBe('Erin');
    expect(visibleText(`${HANGUL_FILLER}${HALFWIDTH_HANGUL_FILLER} ${BRAILLE_BLANK}`)).toBe('');
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
    expect(['', ' ', `${RLO}${PDF}`, HANGUL_FILLER, BRAILLE_BLANK].filter((n) => sameName(n, n))).toEqual([]);
  });

  it('reads a name padded with a Hangul filler as the name it pads (SA-159)', () => {
    const padded = [`Alice${HANGUL_FILLER}`, `Al${HALFWIDTH_HANGUL_FILLER}ice`, `${HANGUL_CHOSEONG_FILLER}Alice`, `Ali${BRAILLE_BLANK}ce`];
    expect(padded.filter((n) => sameName('Alice', n))).toEqual(padded);
  });

  it('reads a name spelled in look-alike letters of another script as the name it looks like (SA-159)', () => {
    const lookalikes = [
      `${CYRILLIC_A}lice`,
      `${CYRILLIC_SMALL_A}lice`,
      `Alic${CYRILLIC_SMALL_IE}`,
      `${GREEK_ALPHA}lice`,
      // An upper-case I drawn as the l it replaces.
      'AIice',
      // Another case as well as another script.
      `${CYRILLIC_SMALL_A}LICE`,
    ];
    expect(lookalikes.filter((n) => sameName('Alice', n))).toEqual(lookalikes);
    expect(sameName('Bob', `B${CYRILLIC_SMALL_O}b`)).toBe(sameName('Bob', 'bob'));
    // Letters that only look alike in part are not one name, and nor are names in another script.
    expect(['Alicia', 'Alic', 'Ойген', 'Eugen'].filter((n) => sameName('Alice', n))).toEqual([]);
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

  it('finds the contact a filler-padded or look-alike namesake imitates (SA-159)', () => {
    const contacts = [contact('Alice', 'AAAAAAAAAAAAAAAA'), contact('Bob', 'CCCCCCCCCCCCCCCC')];
    expect(contactsNamed(contacts, `Alice${HANGUL_FILLER}`, 'ZZZZZZZZZZZZZZZZ').map((c) => c.deviceId)).toEqual(['AAAAAAAAAAAAAAAA']);
    expect(contactsNamed(contacts, `${CYRILLIC_A}lice`, 'ZZZZZZZZZZZZZZZZ').map((c) => c.deviceId)).toEqual(['AAAAAAAAAAAAAAAA']);
    expect(contactsNamed(contacts, `B${CYRILLIC_SMALL_O}b`, 'ZZZZZZZZZZZZZZZZ').map((c) => c.deviceId)).toEqual(['CCCCCCCCCCCCCCCC']);
  });
});
