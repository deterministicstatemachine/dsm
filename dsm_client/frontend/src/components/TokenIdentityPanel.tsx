// SPDX-License-Identifier: Apache-2.0
// TokenIdentityPanel — what a creator hands to a peer so they can adopt a token.
//
// The adoption confirmation card has always shown the token id and CPTA anchor.
// The device that CREATED the token showed neither, anywhere, so getting the
// anchor to a peer meant reading it out of the database and encoding it by
// hand — and a hand-rolled Base32 pads the trailing group differently from the
// canonical encoder, producing a plausible 52-character string that resolves to
// nothing. The resulting POLICY_NOT_FOUND is indistinguishable from a token
// whose policy was never published.
//
// Everything shown here is rendered by Rust and carried on the wire. This
// component derives nothing: not the anchor, not the fingerprint, not the URI.

import React, { useEffect, useState } from 'react';
import QRCode from 'qrcode';

import { tokenAdoptionQr } from '../dsm/policies';
import { copyText } from '../utils/anchorDisplay';
import { logger } from '../utils/logger';

const LABEL: React.CSSProperties = {
  flex: '0 0 auto',
  opacity: 0.6,
  textTransform: 'uppercase',
  letterSpacing: 0.4,
  fontSize: 6,
  fontWeight: 700,
  paddingTop: 1,
};

const VALUE: React.CSSProperties = {
  flex: '1 1 auto',
  textAlign: 'right',
  wordBreak: 'break-all',
  overflowWrap: 'anywhere',
  fontSize: 7,
  fontFamily: "'Martian Mono', monospace",
};

const ROW: React.CSSProperties = {
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'flex-start',
  gap: 8,
  padding: '5px 10px',
  borderBottom: '1px solid rgba(var(--bg-rgb),0.14)',
  fontSize: 8,
};

export interface TokenIdentityPanelProps {
  /** Ticker-keyed id used to address routes. */
  tokenId: string;
  /** The token's canonical id. `tokenId` is the ticker, which is not an identity. */
  canonicalTokenId?: string;
  symbol: string;
  policyAnchorB32?: string;
  anchorFingerprint?: string;
  /** Protocol assets (ERA, dBTC) exist on every device — nothing to hand over. */
  isProtocolToken: boolean;
}

const TokenIdentityPanel: React.FC<TokenIdentityPanelProps> = ({
  tokenId,
  canonicalTokenId,
  symbol,
  policyAnchorB32,
  anchorFingerprint,
  isProtocolToken,
}) => {
  const [copied, setCopied] = useState<string | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [qrError, setQrError] = useState<string | null>(null);

  // Rust assembles the adoption URI; this only renders it. Protocol assets are
  // not adoptable, so they get no code.
  useEffect(() => {
    if (isProtocolToken || !tokenId) return;
    let cancelled = false;
    (async () => {
      try {
        const { uri } = await tokenAdoptionQr(tokenId);
        const url = await QRCode.toDataURL(uri, {
          errorCorrectionLevel: 'M',
          margin: 2,
          color: { dark: '#000000', light: '#FFFFFF' },
          width: 176,
        });
        if (!cancelled) setQrDataUrl(url);
      } catch (e) {
        if (!cancelled) {
          const msg = e instanceof Error ? e.message : 'could not build the code';
          logger.warn('[TokenIdentityPanel] adoption QR failed:', msg);
          setQrError(msg);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [tokenId, isProtocolToken]);

  const onCopy = async (label: string, value: string) => {
    const ok = await copyText(value);
    setCopied(ok ? label : null);
  };

  const rows: Array<[string, string]> = [['Ticker', symbol || tokenId]];
  // Only claim to show a token id when the real one is present. Labelling the
  // ticker "Token ID" tells the user something false — two different tokens can
  // share a ticker, which is exactly the collision adoption refuses.
  if (canonicalTokenId) rows.push(['Token ID', canonicalTokenId]);
  if (policyAnchorB32) {
    rows.push(['Policy Anchor (CPTA)', policyAnchorB32]);
    if (anchorFingerprint) rows.push(['Fingerprint', anchorFingerprint]);
  }

  return (
    <div
      data-testid="token-identity"
      style={{ borderTop: '1px solid rgba(var(--bg-rgb),0.14)' }}
    >
      <div
        style={{
          padding: '6px 10px 4px',
          fontSize: 6,
          fontWeight: 700,
          letterSpacing: 0.8,
          textTransform: 'uppercase',
          color: 'rgba(var(--bg-rgb),0.55)',
        }}
      >
        Identity
      </div>

      {rows.map(([label, value]) => (
        <div key={label} style={ROW}>
          <span style={LABEL}>{label}</span>
          <span style={VALUE}>{value}</span>
        </div>
      ))}

      {policyAnchorB32 && !isProtocolToken && (
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            gap: 8,
            padding: '8px 10px 10px',
          }}
          onClick={(e) => e.stopPropagation()}
        >
          <button
            type="button"
            onClick={() => void onCopy('anchor', policyAnchorB32)}
            style={{
              width: '100%',
              padding: '8px 10px',
              fontSize: 9,
              fontFamily: "'Martian Mono', monospace",
              textTransform: 'uppercase',
              letterSpacing: 0.6,
              fontWeight: 700,
              background: 'var(--bg)',
              color: 'var(--text)',
              border: '2px solid var(--border)',
              borderRadius: 0,
              cursor: 'pointer',
            }}
          >
            {copied === 'anchor' ? 'Copied' : 'Copy Anchor'}
          </button>

          {qrDataUrl && (
            <>
              <img
                src={qrDataUrl}
                alt={`Adoption code for ${symbol || tokenId}`}
                style={{ width: 176, height: 176, imageRendering: 'pixelated' }}
              />
              <div style={{ fontSize: 6, opacity: 0.6, textAlign: 'center', letterSpacing: 0.4 }}>
                Scan to add {symbol || tokenId}
              </div>
            </>
          )}
          {qrError && (
            <div style={{ fontSize: 6, opacity: 0.7, textAlign: 'center' }}>
              Code unavailable — the anchor above still works.
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default React.memo(TokenIdentityPanel);
