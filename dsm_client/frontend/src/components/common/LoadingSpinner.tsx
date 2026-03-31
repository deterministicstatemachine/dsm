/* eslint-disable @typescript-eslint/no-explicit-any */
import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { bridgeEvents } from '../../bridge/bridgeEvents';

interface LoadingSpinnerProps {
  message?: string;
  size?: 'small' | 'medium' | 'large';
  /**
   * Optional deterministic external tick. Increment it from event-driven code
   * (e.g., after a bridge RX/TX or BLE event) to advance the dots without clocks.
   */
  tick?: number;
  eraTokenSrc?: string;
}

/**
 * Deterministic, clockless loading indicator.
 * Dots advance ONLY on event-driven signals:
 * - CustomEvent('DSM_PORT_TX'|'DSM_PORT_RX'|'DSM_UI_TICK')
 * - CustomEvent('DSM_BLE_EVENT')
 * - prop `tick` change
 *
 * No timers, no rAF, no randomness.
 */
const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({
  message = 'Loading',
  size = 'medium',
  tick,
  eraTokenSrc = 'images/logos/era_token_gb.gif',
}) => {
  const [dots, setDots] = useState<1 | 2 | 3>(1);

  // Advance dots deterministically: 1 -> 2 -> 3 -> 1
  const bump = useCallback(() => {
    setDots(prev => (prev === 3 ? 1 : ((prev + 1) as 1 | 2 | 3)));
  }, []);

  // Advance on external tick prop (purely event-driven from caller)
  useEffect(() => {
    if (typeof tick === 'number') bump();
  }, [tick, bump]);

  // Advance on DSM activity events (transport, BLE, or explicit UI tick)
    // Advance on DSM activity events (transport or explicit UI tick)
  useEffect(() => {
    const offTx = bridgeEvents.on('port.tx', () => bump());
    const offRx = bridgeEvents.on('port.rx', () => bump());
    const offUi = bridgeEvents.on('ui.tick', () => bump());

    return () => {
      offTx();
      offRx();
      offUi();
    };
  }, [bump]);

  const sizeMap = useMemo(
    () =>
      ({
        small: { coin: '40px', text: '8px' },
        medium: { coin: '60px', text: '10px' },
        large: { coin: '80px', text: '12px' },
      }) as const,
    []
  );
  const currentSize = sizeMap[size];

  const renderDots = () => {
    return Array.from({ length: 3 }, (_, i) => (
      <span
        key={i}
        style={{
          opacity: i < dots ? 1 : 0.3,
          transition: 'opacity 120ms linear',
          display: 'inline-block',
          width: '4px',
        }}
      >
        .
      </span>
    ));
  };

  return (
    <div
      className="dsm-loading-container"
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        textAlign: 'center',
        padding: '20px',
      }}
      aria-live="polite"
      aria-busy="true"
    >
      <img
        src={eraTokenSrc}
        alt="Loading…"
        style={{
          width: currentSize.coin,
          height: currentSize.coin,
          objectFit: 'contain',
          marginBottom: '16px',
        }}
      />
      <div
        style={{
          color: 'var(--text-dark)',
          fontSize: currentSize.text,
          fontFamily: 'Martian Mono, monospace',
          textTransform: 'uppercase',
          letterSpacing: '1px',
        }}
      >
        {message.toUpperCase()}
        <span style={{ minWidth: '12px', display: 'inline-block', textAlign: 'left' }}>
          {renderDots()}
        </span>
      </div>
    </div>
  );
};

export default LoadingSpinner;