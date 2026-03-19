// SPDX-License-Identifier: Apache-2.0
// EnhancedWalletScreen — thin orchestrator delegating to tab components and hooks.
import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import { useWalletScreenData } from './wallet/hooks/useWalletScreenData';
import OverviewTab from './wallet/OverviewTab';
import SendTab from './wallet/SendTab';
import HistoryTab from './wallet/HistoryTab';
import InboxOverlay from './wallet/InboxOverlay';
import BitcoinTapTab from './BitcoinTapTab';
import '../../styles/EnhancedWallet.css';

interface EnhancedWalletScreenProps {
  eraTokenSrc?: string;
  btcLogoSrc?: string;
  initialTab?: 'overview' | 'send' | 'history' | 'bitcoin';
}

const EnhancedWalletScreen: React.FC<EnhancedWalletScreenProps> = ({ eraTokenSrc, btcLogoSrc, initialTab }) => {
  // Layout
  const headerRef = useRef<HTMLDivElement | null>(null);
  const [headerHeight, setHeaderHeight] = useState<number>(56);

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

  const [activeTab, setActiveTab] = useState<'overview' | 'send' | 'history' | 'bitcoin'>(initialTab || 'overview');

  const eraGif = eraTokenSrc || 'images/logos/era_token_gb.gif';
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

  const switchToSend = useCallback(() => setActiveTab('send'), []);
  const switchToHistory = useCallback(() => setActiveTab('history'), []);
  const switchToOverview = useCallback(() => setActiveTab('overview'), []);

  if (data.loading) {
    return (
      <div className="enhanced-wallet-screen loading">
        <div className="loading-spinner"><div className="spinner"/></div>
        <p>Loading wallet{'\u2026'}</p>
      </div>
    );
  }
  if (data.error && !data.identity) {
    return (
      <div className="enhanced-wallet-screen error">
        <div className="error-container">
          <h3>Error</h3>
          <p>{data.error}</p>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => void data.loadWalletData()} className="retry-button">Try Again</button>
            <button onClick={() => data.setError(null)} className="retry-button" aria-label="Dismiss error">Dismiss</button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={`enhanced-wallet-screen ${data.refreshing ? 'refreshing' : ''} ${data.touchFeedback ? `feedback-${data.touchFeedback}` : ''}`} style={{ position: 'relative' }}>
      {/* Header */}
      <div className="wallet-header" ref={headerRef}>
        <h2>DSM Wallet</h2>
        <div className="header-buttons" style={{ display: 'flex', gap: 8 }}>
          <InboxOverlay headerHeight={headerHeight} loadWalletData={data.loadWalletData} />
          <button
            onClick={() => void data.handleRefresh()}
            className={`refresh-icon ${data.refreshing ? 'spinning' : ''}`}
            disabled={data.refreshing}
            title="Refresh"
            aria-label="Refresh"
            style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', padding: 6, border: '1px solid var(--border)', borderRadius: 4, background: 'transparent' }}
          >
            <img src="images/icons/icon_refresh.svg" alt="Refresh" style={{ width: 16, height: 16, imageRendering: 'pixelated' }} />
          </button>
        </div>
      </div>

      {/* Error banner */}
      {data.error && (
        <div className="error-banner" style={{ padding: '8px 12px', marginBottom: 8, background: 'rgba(var(--text-rgb), 0.12)', border: '2px dashed var(--border)', fontSize: 12, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span>{data.error}</span>
          <button onClick={() => data.setError(null)} style={{ background: 'transparent', border: 'none', color: 'inherit', cursor: 'pointer', fontSize: 14 }}>{'\u00D7'}</button>
        </div>
      )}

      {data.warning && (
        <div className="warning-banner" style={{ padding: '8px 12px', marginBottom: 8, background: 'rgba(var(--text-rgb), 0.08)', border: '1px solid var(--border)', fontSize: 12, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span>{data.warning}</span>
          <button onClick={() => data.setWarning(null)} style={{ background: 'transparent', border: 'none', color: 'inherit', cursor: 'pointer', fontSize: 14 }}>{'\u00D7'}</button>
        </div>
      )}

      {/* Tabs */}
      <div className="tab-navigation">
        {(['overview', 'send', 'history', 'bitcoin'] as const).map((tab) => (
          <button key={tab} onClick={() => setActiveTab(tab)} className={`tab-button ${activeTab === tab ? 'active' : ''}`}>
            {tab === 'bitcoin' ? 'BTC Tap' : tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="tab-content">
        {activeTab === 'overview' && (
          <OverviewTab
            balances={data.balances}
            transactions={data.transactions}
            aliasLookup={data.aliasLookup}
            eraGif={eraGif}
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
            eraGif={eraGif}
            btcGif={btcGif}
            onCancel={switchToOverview}
            onSendComplete={handleSendComplete}
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
      </div>

      {/* Toast */}
      {toast && (
        <div
          role="status"
          aria-live="polite"
          style={{
            position: 'absolute',
            top: headerHeight + 8,
            left: '50%',
            transform: 'translateX(-50%)',
            zIndex: 10010,
            maxWidth: 'calc(100% - 24px)',
            padding: '6px 10px',
            background: 'rgba(var(--text-rgb),0.92)',
            border: '2px solid var(--border)',
            borderRadius: 8,
            color: 'var(--bg)',
            fontSize: 11,
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}
        >
          <span
            style={{
              fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
              color: 'inherit',
              opacity: 1,
            }}
          >
            {toast}
          </span>
          <button
            type="button"
            onClick={() => data.setTouchFeedback(null)}
            aria-label="Dismiss"
            className="button-brick"
            style={{
              padding: '2px 6px',
              borderRadius: 8,
              border: '1px solid var(--border)',
              background: 'transparent',
              color: 'inherit',
              fontSize: 11,
              lineHeight: 1,
            }}
          >
            {'\u00D7'}
          </button>
        </div>
      )}
    </div>
  );
};

export default EnhancedWalletScreen;
