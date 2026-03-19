/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// path: src/components/screens/EraFaucetScreen.tsx
// ERA Token Faucet Screen - DJTE-based emission claims (no geo-location)
// Uses the ERA token policy for testnet token distribution

import React, { useEffect, useState, useCallback } from 'react';
import { dsmClient } from '../../dsm/index';
import { useWallet } from '../../contexts/WalletContext';
import logger from '../../utils/logger';

// ERA Token Policy identifier (DJTE-enabled)
const ERA_TOKEN_POLICY = 'era-token-v1';

interface FaucetClaimResult {
  success: boolean;
  message?: string;
  tokensReceived?: string | number;
  nextAvailable?: string | number;
  _debug?: {
    resultBytesLen?: number;
    resultPackCodec?: number;
    resultPackBodyLen?: number;
    resultPackSchemaHashLen?: number;
    decodeNote?: string;
  };
}

export default function EraFaucetScreen(): JSX.Element {
  const { refreshBalances } = useWallet();
  const [claiming, setClaiming] = useState<boolean>(false);
  const [lastResult, setLastResult] = useState<FaucetClaimResult | null>(null);
  const [identityReady, setIdentityReady] = useState<boolean>(false);

  // Check if identity is ready on mount
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const ready = await dsmClient.isReady();
        if (!cancelled) setIdentityReady(ready);
      } catch {
        if (!cancelled) setIdentityReady(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  // Claim ERA tokens via DJTE emission
  const handleClaim = useCallback(async () => {
    logger.info('[EraFaucetScreen] handleClaim invoked');
    if (claiming) {
      logger.debug('[EraFaucetScreen] handleClaim: already claiming, ignoring');
      return;
    }
    
    logger.info('[EraFaucetScreen] handleClaim: starting claim flow');
    setClaiming(true);
    setLastResult(null);
    
    try {
      logger.debug('[EraFaucetScreen] handleClaim: calling dsmClient.claimTestnetFaucet()');
      // Call the testnet faucet (native protocol)
      // Note: ERA_TOKEN_POLICY is implied by the testnet faucet handler
      const result: any = await dsmClient.claimTestnetFaucet();
      logger.debug('[EraFaucetScreen] handleClaim: dsmClient.claimTestnetFaucet() returned', result);

      // Trigger balance refresh if successful
      if (result?.success) {
        // Refresh silently in background so UI updates when ready
        void refreshBalances();
      }

      const tokensReceivedRaw = result?.tokensReceived;
      const nextAvailableRaw = result?.nextAvailable ?? result?.nextAvailableIndex;

      setLastResult({
        success: Boolean(result?.success),
        message: (result?.message as string) || (result?.success ? 'Claim successful!' : 'Claim failed'),
        tokensReceived: tokensReceivedRaw !== undefined ? String(tokensReceivedRaw) : undefined,
        nextAvailable: nextAvailableRaw !== undefined ? String(nextAvailableRaw) : undefined,
        _debug: result?._debug,
      });
    } catch (e: any) {
      setLastResult({
        success: false,
        message: e?.message || 'Faucet claim failed',
      });
    } finally {
      setClaiming(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [claiming]);

  return (
    <div 
      className="dsm-content" 
      style={{ 
        maxWidth: 400, 
        padding: 16,
        fontFamily: "'Martian Mono', monospace",
      }}
    >
      {/* Header */}
      <div 
        style={{ 
          marginBottom: 16, 
          fontSize: 12, 
          letterSpacing: '1px', 
          fontWeight: 'bold',
          textTransform: 'uppercase',
          color: 'var(--text-dark)',
        }}
      >
        ERA TOKEN FAUCET
      </div>

      {/* Description */}
      <div 
        style={{ 
          marginBottom: 16, 
          fontSize: 11, 
          lineHeight: 1.5,
          opacity: 0.9,
          padding: 12,
          background: 'linear-gradient(0deg, rgba(var(--text-rgb),0.08), rgba(var(--bg-rgb),0.06))',
          border: '1px solid var(--border)',
          borderRadius: 6,
        }}
      >
        <div style={{ marginBottom: 8 }}>
          <strong>DJTE Emission Faucet</strong>
        </div>
        <div style={{ fontSize: 10, opacity: 0.85 }}>
          Claim testnet ERA tokens via Deterministic Join-Triggered Emissions.
          No geo-location required. Tokens are distributed based on your device&apos;s
          spend-gate unlock and Join Activation Proof (JAP).
        </div>
      </div>

      {/* Identity Status */}
      <div 
        style={{ 
          marginBottom: 16, 
          padding: 10,
          background: identityReady
            ? 'rgba(var(--text-rgb), 0.10)'
            : 'rgba(var(--text-rgb), 0.05)',
          border: `1px solid var(--border)`,
          borderRadius: 6,
          fontSize: 10,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ 
            width: 8, 
            height: 8, 
            borderRadius: '50%', 
            background: identityReady ? 'var(--text)' : 'var(--border)',
            opacity: identityReady ? 1 : 0.5,
          }} />
          <span>
            Identity: <strong>{identityReady ? 'READY' : 'NOT INITIALIZED'}</strong>
          </span>
        </div>
      </div>

      {/* Claim Button */}
      <button
        className="wallet-style-button"
        onClick={() => void handleClaim()}
        disabled={claiming || !identityReady}
        style={{
          width: '100%',
          padding: 14,
          fontFamily: "'Martian Mono', monospace",
          fontSize: 11,
          textTransform: 'uppercase',
          letterSpacing: '1px',
          background: claiming || !identityReady
            ? 'rgba(100, 100, 100, 0.3)'
            : 'linear-gradient(0deg, rgba(var(--text-rgb),0.12), rgba(var(--bg-rgb),0.06)), repeating-linear-gradient(45deg, rgba(var(--text-rgb),0.14) 0px, rgba(var(--text-rgb),0.14) 2px, transparent 2px, transparent 4px)',
          color: claiming || !identityReady ? 'rgba(var(--text-rgb),0.5)' : 'var(--text)',
          border: '2px solid var(--border)',
          borderRadius: 8,
          cursor: claiming || !identityReady ? 'not-allowed' : 'pointer',
          boxShadow: 'inset 0 -2px 0 rgba(var(--text-rgb),0.18), inset 0 2px 0 rgba(var(--bg-rgb),0.08)',
        }}
        aria-label="Claim ERA tokens from faucet"
      >
        {claiming ? 'CLAIMING...' : 'CLAIM ERA TOKENS'}
      </button>

      {/* Result Display */}
      {lastResult && (
        <div 
          style={{ 
            marginTop: 16, 
            padding: 12,
            background: lastResult.success 
              ? 'rgba(15, 100, 15, 0.1)' 
              : 'rgba(100, 15, 15, 0.1)',
            border: `1px solid ${lastResult.success ? 'rgba(15, 100, 15, 0.3)' : 'rgba(100, 15, 15, 0.3)'}`,
            borderRadius: 6,
            fontSize: 11,
          }}
        >
          <div style={{ fontWeight: 'bold', marginBottom: 6 }}>
            {lastResult.success ? '✓ SUCCESS' : '✗ FAILED'}
          </div>
          <div style={{ opacity: 0.9 }}>
            {lastResult.message}
          </div>
          {lastResult.tokensReceived !== undefined && (
            <div style={{ marginTop: 8, fontSize: 10, opacity: 0.8 }}>
              Tokens received: <strong>{lastResult.tokensReceived}</strong>
            </div>
          )}
          {lastResult.nextAvailable && (
            <div style={{ marginTop: 4, fontSize: 10, opacity: 0.8 }}>
              Next available index: <strong>{lastResult.nextAvailable}</strong>
            </div>
          )}

          {lastResult._debug && (
            <div
              style={{
                marginTop: 10,
                paddingTop: 10,
                borderTop: '1px dashed rgba(var(--text-rgb),0.25)',
                fontSize: 9,
                lineHeight: 1.35,
                opacity: 0.85,
              }}
            >
              <div style={{ fontWeight: 'bold', marginBottom: 4 }}>
                Decode debug
              </div>
              <div>
                Result bytes: <strong>{String(lastResult._debug.resultBytesLen ?? '-') }</strong>
              </div>
              <div>
                ResultPack.codec: <strong>{String(lastResult._debug.resultPackCodec ?? '-') }</strong>
              </div>
              <div>
                ResultPack.body.length:{' '}
                <strong>{String(lastResult._debug.resultPackBodyLen ?? '-') }</strong>
              </div>
              <div>
                ResultPack.schema_hash.length:{' '}
                <strong>{String(lastResult._debug.resultPackSchemaHashLen ?? '-') }</strong>
              </div>
              <div>
                Note: <strong>{String(lastResult._debug.decodeNote ?? '-') }</strong>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ERA Policy Info */}
      <div 
        style={{ 
          marginTop: 16, 
          padding: 10,
          background: 'rgba(var(--text-rgb), 0.06)',
          border: '1px solid var(--border)',
          borderRadius: 6,
          fontSize: 9,
          opacity: 0.8,
        }}
      >
        <div><strong>Policy:</strong> {ERA_TOKEN_POLICY}</div>
        <div><strong>Emission:</strong> DJTE (Deterministic Join-Triggered)</div>
        <div><strong>Network:</strong> Testnet</div>
      </div>

      {/* Navigation hint */}
      <div 
        className="navigation-hint" 
        style={{ 
          marginTop: 16, 
          fontSize: 10, 
          opacity: 0.6,
          textAlign: 'center',
        }}
      >
        Press B to go back
      </div>
    </div>
  );
}
