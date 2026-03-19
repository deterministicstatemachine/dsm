import React from 'react';
import { act, render, waitFor } from '@testing-library/react';
import { ContactsProvider, useContacts } from '../ContactsContext';
import { hasIdentity } from '../../utils/identity';

jest.mock('../../utils/identity', () => ({
  hasIdentity: jest.fn(),
}));

jest.mock('../../hooks/useBridgeEvents', () => ({
  useBridgeEvent: () => undefined,
}));

describe('ContactsContext strict mutations', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (hasIdentity as jest.MockedFunction<typeof hasIdentity>).mockResolvedValue(false);
  });

  it('fails closed when updateContactStrict is unavailable', async () => {
    let latest: ReturnType<typeof useContacts> | null = null;

    function Harness() {
      latest = useContacts();
      return <div>{latest.error}</div>;
    }

    render(
      <ContactsProvider>
        <Harness />
      </ContactsProvider>
    );

    await waitFor(() => expect(latest).not.toBeNull());

    let ok = true;
    await act(async () => {
      ok = await latest!.updateContact('contact-1', { alias: 'renamed' });
    });

    expect(ok).toBe(false);
    await waitFor(() => expect(latest!.error).toMatch(/updateContactStrict is not available/));
  });

  it('fails closed when deleteContactStrict is unavailable', async () => {
    let latest: ReturnType<typeof useContacts> | null = null;

    function Harness() {
      latest = useContacts();
      return <div>{latest.error}</div>;
    }

    render(
      <ContactsProvider>
        <Harness />
      </ContactsProvider>
    );

    await waitFor(() => expect(latest).not.toBeNull());

    let ok = true;
    await act(async () => {
      ok = await latest!.deleteContact('contact-1');
    });

    expect(ok).toBe(false);
    await waitFor(() => expect(latest!.error).toMatch(/deleteContactStrict is not available/));
  });
});
