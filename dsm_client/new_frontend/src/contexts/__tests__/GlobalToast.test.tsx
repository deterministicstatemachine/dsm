import React from 'react';
import { act, render, screen, waitFor } from '@testing-library/react';
import { UXProvider, useUX } from '../UXContext';
import GlobalToast from '../../components/GlobalToast';
import { bridgeEvents } from '../../bridge/bridgeEvents';

describe('GlobalToast', () => {
  test('shows transfer accepted toast when notifyToast called', async () => {
    // Render a small harness to call notifyToast via useUX
    const TestHarness = () => {
      const { notifyToast } = useUX();
      React.useEffect(() => {
        notifyToast('transfer_accepted');
      }, [notifyToast]);
      return null;
    };

    render(
      <UXProvider>
        <TestHarness />
        <GlobalToast />
      </UXProvider>
    );

    await waitFor(() => expect(screen.getByText(/Transfer accepted/)).toBeInTheDocument());
  });

  test('shows inbox toast when new inbox items arrive', async () => {
    render(
      <UXProvider>
        <GlobalToast />
      </UXProvider>
    );

    act(() => {
      bridgeEvents.emit('inbox.updated', { unreadCount: 1, newItems: 1, source: 'poll' });
    });

    await waitFor(() => expect(screen.getByText(/New inbox item received/)).toBeInTheDocument());
  });
});
