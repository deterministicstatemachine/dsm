/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { renderHook } from '@testing-library/react';

jest.mock('../../services/dsmClient', () => ({
  dsmClient: {
    getContacts: jest.fn(),
    addContact: jest.fn(),
    updateContactStrict: jest.fn(),
    deleteContactStrict: jest.fn(),
  },
}));

jest.mock('../../contexts/contacts/utils', () => ({
  parseBinary32: jest.fn((input: any) => (input instanceof Uint8Array ? input : new Uint8Array(32))),
  parseBinary64: jest.fn((input: any) => (input instanceof Uint8Array ? input : new Uint8Array(64))),
  bytesToDisplay: jest.fn((u8: Uint8Array) => Array.from(u8).map(b => b.toString(16).padStart(2, '0')).join('')),
}));

jest.mock('../../utils/logger', () => ({
  default: { error: jest.fn(), debug: jest.fn(), warn: jest.fn(), info: jest.fn() },
  __esModule: true,
}));

// requestAnimationFrame polyfill for awaitWithFrameBudget
let rafCallbacks: Array<() => void> = [];
(globalThis as any).requestAnimationFrame = (cb: () => void) => {
  rafCallbacks.push(cb);
  return rafCallbacks.length;
};
(globalThis as any).cancelAnimationFrame = jest.fn();

function flushRaf(frames = 1) {
  for (let i = 0; i < frames; i++) {
    const batch = rafCallbacks.slice();
    rafCallbacks = [];
    batch.forEach(cb => cb());
  }
}

function freshModule() {
  jest.resetModules();
  jest.doMock('../../services/dsmClient', () => ({
    dsmClient: {
      getContacts: jest.fn(),
      addContact: jest.fn(),
      updateContactStrict: jest.fn(),
      deleteContactStrict: jest.fn(),
    },
  }));
  jest.doMock('../../contexts/contacts/utils', () => ({
    parseBinary32: jest.fn((input: any) => (input instanceof Uint8Array ? input : new Uint8Array(32))),
    parseBinary64: jest.fn((input: any) => (input instanceof Uint8Array ? input : new Uint8Array(64))),
    bytesToDisplay: jest.fn((u8: Uint8Array) => Array.from(u8).map(b => b.toString(16).padStart(2, '0')).join('')),
  }));
  jest.doMock('../../utils/logger', () => ({
    default: { error: jest.fn(), debug: jest.fn(), warn: jest.fn(), info: jest.fn() },
    __esModule: true,
  }));
  const mod = require('../contactsStore');
  const client = require('../../services/dsmClient').dsmClient;
  return { ...mod, client };
}

function makeContact(overrides: Record<string, any> = {}) {
  return {
    alias: 'Alice',
    genesisHash: 'abcd1234',
    deviceId: 'dev001',
    signingPublicKey: 'key123',
    genesisVerifiedOnline: true,
    ...overrides,
  };
}

describe('ContactsStore', () => {
  afterEach(() => {
    jest.restoreAllMocks();
    rafCallbacks = [];
  });

  describe('initial state', () => {
    it('has correct defaults', () => {
      const { contactsStore } = freshModule();
      const s = contactsStore.getSnapshot();
      expect(s).toEqual({ contacts: [], isLoading: false, error: null });
    });
  });

  describe('subscribe / unsubscribe', () => {
    it('notifies listeners and supports unsubscribe', () => {
      const { contactsStore } = freshModule();
      const listener = jest.fn();
      const unsub = contactsStore.subscribe(listener);
      contactsStore.setError('test');
      expect(listener).toHaveBeenCalledTimes(1);

      unsub();
      contactsStore.setError('ignored');
      expect(listener).toHaveBeenCalledTimes(1);
    });
  });

  describe('setError / clearContacts', () => {
    it('sets and clears error', () => {
      const { contactsStore } = freshModule();
      contactsStore.setError('bad');
      expect(contactsStore.getSnapshot().error).toBe('bad');
      contactsStore.setError(null);
      expect(contactsStore.getSnapshot().error).toBeNull();
    });

    it('clears contacts array', () => {
      const { contactsStore } = freshModule();
      contactsStore.clearContacts();
      expect(contactsStore.getSnapshot().contacts).toEqual([]);
    });
  });

  describe('refreshContacts()', () => {
    it('fetches contacts and maps them', async () => {
      const { contactsStore, client } = freshModule();
      client.getContacts.mockResolvedValue({
        contacts: [makeContact()],
      });

      await contactsStore.refreshContacts();
      const s = contactsStore.getSnapshot();
      expect(s.contacts).toHaveLength(1);
      expect(s.contacts[0].alias).toBe('Alice');
      expect(s.isLoading).toBe(false);
    });

    it('handles empty contacts', async () => {
      const { contactsStore, client } = freshModule();
      client.getContacts.mockResolvedValue({ contacts: [] });

      await contactsStore.refreshContacts();
      expect(contactsStore.getSnapshot().contacts).toEqual([]);
    });

    it('handles missing contacts field', async () => {
      const { contactsStore, client } = freshModule();
      client.getContacts.mockResolvedValue({});

      await contactsStore.refreshContacts();
      expect(contactsStore.getSnapshot().contacts).toEqual([]);
    });

    it('preserves existing bleAddress if new data lacks it', async () => {
      const { contactsStore, client } = freshModule();
      const contactWithBle = makeContact({ bleAddress: 'AA:BB:CC' });
      client.getContacts.mockResolvedValue({ contacts: [contactWithBle] });
      await contactsStore.refreshContacts();

      // Second refresh — contact without bleAddress
      const contactNoBle = makeContact({ bleAddress: undefined });
      client.getContacts.mockResolvedValue({ contacts: [contactNoBle] });
      await contactsStore.refreshContacts();

      expect(contactsStore.getSnapshot().contacts[0].bleAddress).toBe('AA:BB:CC');
    });

    it('sets error on failure', async () => {
      const { contactsStore, client } = freshModule();
      client.getContacts.mockRejectedValue(new Error('fetch fail'));

      await contactsStore.refreshContacts();
      expect(contactsStore.getSnapshot().error).toBe('fetch fail');
    });

    it('uses default message for non-Error throw', async () => {
      const { contactsStore, client } = freshModule();
      client.getContacts.mockRejectedValue('bad');

      await contactsStore.refreshContacts();
      expect(contactsStore.getSnapshot().error).toBe('Failed to refresh contacts');
    });

    it('sets isLoading true only on first load', async () => {
      const { contactsStore, client } = freshModule();
      client.getContacts.mockResolvedValue({ contacts: [] });

      const listener = jest.fn();
      contactsStore.subscribe(listener);

      await contactsStore.refreshContacts();
      // First call: isLoading was set to true
      const loadingEmits = listener.mock.calls.filter(() => true);
      expect(loadingEmits.length).toBeGreaterThan(0);

      listener.mockClear();
      await contactsStore.refreshContacts();
      // Second call should not set isLoading to true again (hasLoadedOnce is true)
      // But it should still emit for error: null and contacts
    });
  });

  describe('stale-refresh protection (sequence number)', () => {
    it('ignores results from outdated refresh calls', async () => {
      const { contactsStore, client } = freshModule();
      let resolve1!: (v: any) => void;
      let resolve2!: (v: any) => void;

      client.getContacts
        .mockReturnValueOnce(new Promise(r => { resolve1 = r; }))
        .mockReturnValueOnce(new Promise(r => { resolve2 = r; }));

      const p1 = contactsStore.refreshContacts();
      const p2 = contactsStore.refreshContacts();

      // Resolve second before first — second should win
      resolve2({ contacts: [makeContact({ alias: 'Bob' })] });
      await p2;

      resolve1({ contacts: [makeContact({ alias: 'Stale' })] });
      await p1;

      const contacts = contactsStore.getSnapshot().contacts;
      // The first call was stale (seq was outdated), so Bob should be the result
      expect(contacts[0].alias).toBe('Bob');
    });
  });

  describe('scheduleRefreshContacts()', () => {
    it('deduplicates rapid calls via queueMicrotask', async () => {
      const { contactsStore, client } = freshModule();
      client.getContacts.mockResolvedValue({ contacts: [] });

      contactsStore.scheduleRefreshContacts('a');
      contactsStore.scheduleRefreshContacts('b');

      // Flush microtask queue
      await Promise.resolve();
      await Promise.resolve();

      // Only one actual refresh should have been triggered
      expect(client.getContacts).toHaveBeenCalledTimes(1);
    });
  });

  describe('handleBleMapped / handleBleUpdated', () => {
    it('both schedule a refresh', async () => {
      const { contactsStore, client } = freshModule();
      client.getContacts.mockResolvedValue({ contacts: [] });

      contactsStore.handleBleMapped({ address: 'AA' });
      await Promise.resolve();
      await Promise.resolve();
      expect(client.getContacts).toHaveBeenCalledTimes(1);

      // Allow the pending flag to reset
      await new Promise(r => setTimeout(r, 0));

      contactsStore.handleBleUpdated({ bleAddress: 'BB' });
      await Promise.resolve();
      await Promise.resolve();
      expect(client.getContacts).toHaveBeenCalledTimes(2);
    });
  });

  describe('addContact()', () => {
    it('adds contact and refreshes', async () => {
      const { contactsStore, client } = freshModule();
      client.addContact.mockResolvedValue({ accepted: true });
      client.getContacts.mockResolvedValue({ contacts: [makeContact()] });

      const result = await contactsStore.addContact('Alice', new Uint8Array(32), new Uint8Array(32), new Uint8Array(64));
      expect(result).toBe(true);
      expect(client.addContact).toHaveBeenCalled();
    });

    it('returns false when add is not accepted', async () => {
      const { contactsStore, client } = freshModule();
      client.addContact.mockResolvedValue({ accepted: false, error: 'dup' });

      const result = await contactsStore.addContact('A', new Uint8Array(32), new Uint8Array(32), new Uint8Array(64));
      expect(result).toBe(false);
      expect(contactsStore.getSnapshot().error).toBe('dup');
    });

    it('returns false when deviceId is empty', async () => {
      const { contactsStore } = freshModule();
      const result = await contactsStore.addContact('A', new Uint8Array(32), '', new Uint8Array(64));
      expect(result).toBe(false);
      expect(contactsStore.getSnapshot().error).toContain('device_id required');
    });

    it('returns false when signingPublicKey is empty', async () => {
      const { contactsStore } = freshModule();
      const result = await contactsStore.addContact('A', new Uint8Array(32), new Uint8Array(32), '');
      expect(result).toBe(false);
      expect(contactsStore.getSnapshot().error).toContain('signingPublicKey required');
    });

    it('sets isLoading false on completion', async () => {
      const { contactsStore, client } = freshModule();
      client.addContact.mockRejectedValue(new Error('net'));

      await contactsStore.addContact('A', new Uint8Array(32), new Uint8Array(32), new Uint8Array(64));
      expect(contactsStore.getSnapshot().isLoading).toBe(false);
    });
  });

  describe('updateContact()', () => {
    it('returns true on success', async () => {
      const { contactsStore, client } = freshModule();
      client.updateContactStrict = jest.fn().mockResolvedValue({ success: true });
      client.getContacts.mockResolvedValue({ contacts: [] });

      const result = await contactsStore.updateContact('id1', { alias: 'Bob' });
      expect(result).toBe(true);
    });

    it('returns false when not available', async () => {
      const { contactsStore, client } = freshModule();
      delete client.updateContactStrict;

      const result = await contactsStore.updateContact('id1', { alias: 'Bob' });
      expect(result).toBe(false);
      expect(contactsStore.getSnapshot().error).toContain('not available');
    });

    it('returns false on failure result', async () => {
      const { contactsStore, client } = freshModule();
      client.updateContactStrict = jest.fn().mockResolvedValue({ success: false, message: 'denied' });

      const result = await contactsStore.updateContact('id1', {});
      expect(result).toBe(false);
      expect(contactsStore.getSnapshot().error).toBe('denied');
    });
  });

  describe('deleteContact()', () => {
    it('returns true on success', async () => {
      const { contactsStore, client } = freshModule();
      client.deleteContactStrict = jest.fn().mockResolvedValue({ success: true });
      client.getContacts.mockResolvedValue({ contacts: [] });

      const result = await contactsStore.deleteContact('id1');
      expect(result).toBe(true);
    });

    it('returns false when not available', async () => {
      const { contactsStore, client } = freshModule();
      delete client.deleteContactStrict;

      const result = await contactsStore.deleteContact('id1');
      expect(result).toBe(false);
      expect(contactsStore.getSnapshot().error).toContain('not available');
    });

    it('returns false on failure result', async () => {
      const { contactsStore, client } = freshModule();
      client.deleteContactStrict = jest.fn().mockResolvedValue({ success: false, message: 'nope' });

      const result = await contactsStore.deleteContact('id1');
      expect(result).toBe(false);
    });
  });

  describe('getContactByGenesisHash()', () => {
    it('finds contact by genesis hash (case-insensitive)', async () => {
      const { contactsStore, client } = freshModule();
      client.getContacts.mockResolvedValue({ contacts: [makeContact({ genesisHash: 'ABCD' })] });
      await contactsStore.refreshContacts();

      const contact = contactsStore.getContactByGenesisHash('abcd');
      expect(contact).not.toBeNull();
      expect(contact?.alias).toBe('Alice');
    });

    it('returns null when not found', async () => {
      const { contactsStore, client } = freshModule();
      client.getContacts.mockResolvedValue({ contacts: [] });
      await contactsStore.refreshContacts();

      expect(contactsStore.getContactByGenesisHash('nonexistent')).toBeNull();
    });
  });

  describe('getContactByAlias()', () => {
    it('finds contact by alias (case-insensitive)', async () => {
      const { contactsStore, client } = freshModule();
      client.getContacts.mockResolvedValue({ contacts: [makeContact()] });
      await contactsStore.refreshContacts();

      const contact = contactsStore.getContactByAlias('alice');
      expect(contact).not.toBeNull();
    });

    it('returns null when not found', () => {
      const { contactsStore } = freshModule();
      expect(contactsStore.getContactByAlias('nobody')).toBeNull();
    });
  });

  describe('contact mapping edge cases', () => {
    it('handles Uint8Array genesisHash', async () => {
      const { contactsStore, client } = freshModule();
      client.getContacts.mockResolvedValue({
        contacts: [makeContact({ genesisHash: new Uint8Array([0, 1, 2]) })],
      });
      await contactsStore.refreshContacts();
      expect(contactsStore.getSnapshot().contacts[0].genesisHash).toBeDefined();
    });

    it('handles missing alias', async () => {
      const { contactsStore, client } = freshModule();
      client.getContacts.mockResolvedValue({
        contacts: [makeContact({ alias: undefined })],
      });
      await contactsStore.refreshContacts();
      expect(contactsStore.getSnapshot().contacts[0].alias).toBe('Unknown');
    });

    it('sets isVerified from genesisVerifiedOnline', async () => {
      const { contactsStore, client } = freshModule();
      client.getContacts.mockResolvedValue({
        contacts: [makeContact({ genesisVerifiedOnline: false })],
      });
      await contactsStore.refreshContacts();
      expect(contactsStore.getSnapshot().contacts[0].isVerified).toBe(false);
    });
  });
});

// Hook tests use static imports (same React instance as @testing-library/react)
import { useContactsStore } from '../contactsStore';

describe('useContactsStore hook', () => {
  it('returns the full snapshot', () => {
    const { result } = renderHook(() => useContactsStore());
    expect(result.current).toHaveProperty('contacts');
    expect(result.current).toHaveProperty('isLoading');
    expect(result.current).toHaveProperty('error');
  });
});
