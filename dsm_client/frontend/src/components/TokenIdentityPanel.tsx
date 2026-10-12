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
    <div data-testid="token-identity" className="token-identity">
      <h3 className="sb-section-title">Identity</h3>

      {rows.map(([label, value]) => (
        <div key={label} className="sb-kv">
          <span className="sb-kv__k">{label}</span>
          <span className="sb-kv__v sb-kv__v--mono">{value}</span>
        </div>
      ))}

      {policyAnchorB32 && !isProtocolToken && (
        <div
          style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8, paddingTop: 8 }}
          onClick={(e) => e.stopPropagation()}
        >
          <button
            type="button"
            className="sb-btn sb-btn--small sb-btn--block"
            onClick={() => void onCopy('anchor', policyAnchorB32)}
          >
            {copied === 'anchor' ? 'Copied' : 'Copy Anchor'}
          </button>

          {qrDataUrl && (
            <>
              <span className="sb-qr">
                <img
                  src={qrDataUrl}
                  alt={`Adoption code for ${symbol || tokenId}`}
                  width={152}
                  height={152}
                />
              </span>
              <div className="sb-hint sb-hint--tight" style={{ textAlign: 'center' }}>
                Scan to add {symbol || tokenId}
              </div>
            </>
          )}
          {qrError && (
            <div className="sb-hint sb-hint--tight" style={{ textAlign: 'center' }}>
              Code unavailable — the anchor above still works.
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default React.memo(TokenIdentityPanel);
