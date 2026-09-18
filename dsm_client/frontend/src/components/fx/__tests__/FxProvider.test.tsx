// SPDX-License-Identifier: Apache-2.0
import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { FxLayer, FxProvider, useFx } from '../FxProvider';
import { bridgeEvents } from '../../../bridge/bridgeEvents';
import { LOCK_SETUP_COMPLETE_EVENT } from '../../../services/lock/lockService';

function Harness({ appState, soundEnabled }: { appState?: 'securing_device' | 'wallet_ready' | 'locked'; soundEnabled?: boolean }) {
  return (
    <FxProvider appState={appState} soundEnabled={soundEnabled}>
      <Trigger />
      <FxLayer />
    </FxProvider>
  );
}

function Trigger() {
  const fx = useFx();
  return (
    <button type="button" onClick={() => fx.play({ anim: 'vault', title: 'Pool created', key: 'pool' })}>
      trigger
    </button>
  );
}

describe('FxProvider', () => {
  it('renders nothing until a scene is asked for', () => {
    render(<Harness />);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('plays a scene a screen asks for, and collapses repeats sharing a key', () => {
    render(<Harness />);
    fireEvent.click(screen.getByText('trigger'));
    fireEvent.click(screen.getByText('trigger'));
    expect(screen.getByRole('dialog', { name: 'Pool created' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'OK' }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('shows queued scenes one at a time', () => {
    render(<Harness />);
    fireEvent.click(screen.getByText('trigger'));
    act(() => { bridgeEvents.emit('bilateral.transferComplete', undefined as never); });

    expect(screen.getByRole('dialog', { name: 'Pool created' })).toBeInTheDocument();
    expect(screen.queryByRole('dialog', { name: 'Transfer sealed' })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'OK' }));
    expect(screen.getByRole('dialog', { name: 'Transfer sealed' })).toBeInTheDocument();
  });

  it('cues a deposit landing, an exit, a refused clone and a pairing from bridge events', () => {
    const { unmount } = render(<Harness />);
    act(() => { bridgeEvents.emit('deposit.completed', { depositId: 'd1', amount: '0.001' }); });
    expect(screen.getByRole('dialog', { name: 'Deposit complete' })).toBeInTheDocument();
    expect(document.querySelector('fx-canvas')?.getAttribute('amount')).toBe('+0.001 BTC');
    unmount();

    render(<Harness />);
    act(() => { bridgeEvents.emit('wallet.exitCompleted', { source: 'test' }); });
    expect(screen.getByRole('dialog', { name: 'Bitcoin sent' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'OK' }));

    act(() => { bridgeEvents.emit('dsm.deterministicSafety', { classification: 'clone', message: 'state already spent' }); });
    const refused = screen.getByRole('dialog', { name: 'Link refused' });
    expect(refused).toBeInTheDocument();
    expect(refused.querySelector('fx-canvas')?.getAttribute('anim')).toBe('tamper');
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));

    act(() => { bridgeEvents.emit('ble.pairingStatus', { deviceId: 'dev1', status: 'paired', message: 'Link quality OK' }); });
    expect(screen.getByRole('dialog', { name: 'Paired' })).toBeInTheDocument();
  });

  it('ignores pairing progress that is not a completed pairing', () => {
    render(<Harness />);
    act(() => { bridgeEvents.emit('ble.pairingStatus', { deviceId: 'dev1', status: 'scanning', message: '' }); });
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('celebrates the device being anchored once securing finishes', () => {
    const { rerender } = render(<Harness appState="securing_device" />);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    rerender(<Harness appState="wallet_ready" />);
    expect(screen.getByRole('dialog', { name: 'Device ready' })).toBeInTheDocument();
  });

  it('plays the lock scene only when the lock was just set up', () => {
    const first = render(<Harness appState="wallet_ready" />);
    first.rerender(<Harness appState="locked" />);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    first.unmount();

    const second = render(<Harness appState="wallet_ready" />);
    act(() => { window.dispatchEvent(new CustomEvent(LOCK_SETUP_COMPLETE_EVENT)); });
    second.rerender(<Harness appState="locked" />);
    expect(screen.getByRole('dialog', { name: 'Lock enabled' })).toBeInTheDocument();
  });

  it('says nothing about money over a locked wallet', () => {
    const { rerender } = render(<Harness appState="wallet_ready" />);
    fireEvent.click(screen.getByText('trigger'));
    expect(screen.getByRole('dialog', { name: 'Pool created' })).toBeInTheDocument();

    rerender(<Harness appState="locked" />);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();

    act(() => { bridgeEvents.emit('deposit.completed', { depositId: 'd9', amount: '0.5' }); });
    act(() => { bridgeEvents.emit('wallet.creditReceived', { source: 'test', tokenId: 'ERA' }); });
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('mirrors the sound setting into the engine mute flag', () => {
    const { rerender } = render(<Harness soundEnabled={false} />);
    expect(window.STATEBOY_MUTED).toBe(true);
    rerender(<Harness soundEnabled />);
    expect(window.STATEBOY_MUTED).toBe(false);
  });
});
