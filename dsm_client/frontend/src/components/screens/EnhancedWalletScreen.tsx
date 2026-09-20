// SPDX-License-Identifier: Apache-2.0
// EnhancedWalletScreen — thin orchestrator delegating to tab components and hooks.
import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import { useWalletScreenData } from './wallet/hooks/useWalletScreenData';
import OverviewTab from './wallet/OverviewTab';
import SendTab from './wallet/SendTab';
import SwapTab from './wallet/SwapTab';
import HistoryTab from './wallet/HistoryTab';
import InboxOverlay from './wallet/InboxOverlay';
import BitcoinTapTab from './bitcoin/BitcoinTapTab';
import { ensureBleAdvertisingIfContacts } from '../../contexts/ContactsContext';
import { stopBleAdvertisingViaRouter } from '../../dsm/WebViewBridge';
import { bridgeEvents } from '../../bridge/bridgeEvents';
import { Notice, ScreenFrame, ScreenTabs } from '../common/ScreenFrame';
import '../../styles/EnhancedWallet.css';

type WalletTab = 'overview' | 'send' | 'swap' | 'history' | 'bitcoin';

const TABS: ReadonlyArray<{ id: WalletTab; label: string }> = [
  { id: 'overview', label: 'Overview' },
  { id: 'send', label: 'Send' },
  { id: 'swap', label: 'Swap' },
  { id: 'history', label: 'History' },
  { id: 'bitcoin', label: 'Bitcoin' },
];

interface EnhancedWalletScreenProps {
  btcLogoSrc?: string;
  initialTab?: WalletTab;
}

const EnhancedWalletScreen: React.FC<EnhancedWalletScreenProps> = ({ btcLogoSrc, initialTab }) => {
  // Layout
  const headerRef = useRef<HTMLDivElement | null>(null);
  const bodyRef = useRef<HTMLDivElement | null>(null);
  const [headerHeight, setHeaderHeight] = useState<number>(40);

  useEffect(() => {
    const measure = () => {
      if (!headerRef.current) return;
      const h = headerRef.current.getBoundingClientRect().height;
      if (Number.isFinite(h) && h > 0) {
        setHeaderHeight(Math.round(h));
      }
    };
    measure();
    window.addEventListener('resize', measure);
    return () => window.removeEventListener('resize', measure);
  }, []);

  // ── BLE lifecycle: wallet screen visible = BLE advertising active ──
  // Both parties must be on the wallet screen for bilateral transfers.
  // On mount: start GATT server + advertising via protobuf bridge.
  // On unmount or app backgrounded: stop advertising.
  // On app foregrounded: re-ensure advertising.
  useEffect(() => {
    void ensureBleAdvertisingIfContacts();

    const handleVisibility = (ev: { state: DocumentVisibilityState }) => {
      if (ev.state === 'visible') {
        void ensureBleAdvertisingIfContacts();
      } else {
        void stopBleAdvertisingViaRouter();
      }
    };
    const off = bridgeEvents.on('visibility.change', handleVisibility);

    return () => {
      off();
      void stopBleAdvertisingViaRouter();
    };
  }, []);

  const [activeTab, setActiveTab] = useState<WalletTab>(initialTab || 'overview');

  // A tab is a new page: it opens at the top, not wherever the last one was scrolled to.
  useEffect(() => {
    if (bodyRef.current) bodyRef.current.scrollTop = 0;
  }, [activeTab]);

  const btcGif = btcLogoSrc || 'images/logos/btc-logo.gif';

  const data = useWalletScreenData(activeTab);

  const toast = useMemo(() => {
    if (!data.touchFeedback) return null;
    switch (data.touchFeedback) {
      case 'refreshed': return 'Refreshed';
      case 'copied': return 'Copied';
      case 'transaction_sent': return 'Transaction sent';
      case 'b0x_checked': return 'Inbox checked';
      default: return null;
    }
  }, [data.touchFeedback]);

  const handleSendComplete = useCallback(() => {
    data.setTouchFeedback('transaction_sent');
    setActiveTab('overview');
  }, [data]);

  const handleSwapComplete = useCallback(() => {
    data.setTouchFeedback('transaction_sent');
    setActiveTab('overview');
  }, [data]);

  const switchToSend = useCallback(() => setActiveTab('send'), []);
  const switchToHistory = useCallback(() => setActiveTab('history'), []);
  const switchToOverview = useCallback(() => setActiveTab('overview'), []);

  const headerActions = (
    <>
      <InboxOverlay headerHeight={headerHeight} loadWalletData={data.loadWalletData} />
      <button
        type="button"
        onClick={() => void data.handleRefresh()}
        className={`sb-icon-btn${data.refreshing ? ' spinning' : ''}`}
        disabled={data.refreshing}
        title="Refresh"
        aria-label="Refresh"
      >
        <img src="images/icons/icon_refresh.svg" alt="" />
      </button>
    </>
  );

  if (data.loading) {
    // No "DSM Wallet" title until the wallet has loaded: the title is the
    // signal, to people and to tests, that the screen is ready to use.
    return (
      <ScreenFrame title="Loading" className="enhanced-wallet-screen loading">
        <div className="sb-empty">Loading wallet{'…'}</div>
      </ScreenFrame>
    );
  }

  if (data.error && !data.identity) {
    return (
      <ScreenFrame title="DSM Wallet" className="enhanced-wallet-screen">
        <Notice kind="error">{data.error}</Notice>
        <div className="sb-actions">
          <button type="button" onClick={() => void data.loadWalletData()} className="sb-btn sb-btn--primary">Try Again</button>
          <button type="button" onClick={() => data.setError(null)} className="sb-btn" aria-label="Dismiss error">Dismiss</button>
        </div>
      </ScreenFrame>
    );
  }

  return (
    <ScreenFrame
      title="DSM Wallet"
      className={`enhanced-wallet-screen ${data.refreshing ? 'refreshing' : ''} ${data.touchFeedback ? `feedback-${data.touchFeedback}` : ''}`}
      headRef={headerRef}
      bodyRef={bodyRef}
      bodyClassName="tab-content"
      actions={headerActions}
      tabs={<ScreenTabs tabs={TABS} active={activeTab} onChange={setActiveTab} ariaLabel="Wallet sections" />}
      banner={
        <>
          {data.error && (
            <Notice kind="error" banner onClose={() => data.setError(null)}>{data.error}</Notice>
          )}
          {data.warning && (
            <Notice banner onClose={() => data.setWarning(null)}>{data.warning}</Notice>
          )}
        </>
      }
    >
      {activeTab === 'overview' && (
        <OverviewTab
          balances={data.balances}
          transactions={data.transactions}
          aliasLookup={data.aliasLookup}
          genesisB32={data.genesisB32}
          deviceB32={data.deviceB32}
          onSwitchToSend={switchToSend}
          onSwitchToHistory={switchToHistory}
        />
      )}

      {activeTab === 'send' && (
        <SendTab
          contacts={data.contacts}
          balances={data.balances}
          onCancel={switchToOverview}
          onSendComplete={handleSendComplete}
          loadWalletData={data.loadWalletData}
          setError={data.setError}
        />
      )}

      {activeTab === 'swap' && (
        <SwapTab
          balances={data.balances}
          deviceB32={data.deviceB32}
          onCancel={switchToOverview}
          onSwapComplete={handleSwapComplete}
          loadWalletData={data.loadWalletData}
          setError={data.setError}
        />
      )}

      {activeTab === 'bitcoin' && (
        <BitcoinTapTab btcLogoSrc={btcGif} />
      )}

      {activeTab === 'history' && (
        <HistoryTab
          transactions={data.transactions}
          aliasLookup={data.aliasLookup}
        />
      )}

      {/* Toast */}
      {toast && (
        <div
          role="status"
          aria-live="polite"
          className="sb-notice sb-notice--success"
          style={{
            position: 'absolute',
            top: headerHeight + 8,
            left: 12,
            right: 12,
            zIndex: 10010,
            margin: 0,
          }}
        >
          <span>{toast}</span>
          <button
            type="button"
            onClick={() => data.setTouchFeedback(null)}
            aria-label="Dismiss"
            className="sb-notice__close"
          >
            {'×'}
          </button>
        </div>
      )}
    </ScreenFrame>
  );
};

export default EnhancedWalletScreen;
