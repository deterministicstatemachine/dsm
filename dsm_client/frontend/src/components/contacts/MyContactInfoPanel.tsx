// SPDX-License-Identifier: Apache-2.0
// path: src/components/contacts/MyContactInfoPanel.tsx
// MyContactInfoPanel — this device's contact code, as Rust renders it, and its QR.

import React, { useEffect, useState, useCallback } from 'react';
import QRCode from 'qrcode';

import { AudioManager } from '../../utils/audio';
import logger from '../../utils/logger';
import { getContactCode } from '../../dsm/contacts';
import { copyText } from '../../utils/anchorDisplay';
import { Notice } from '../common/ScreenFrame';

function qrSideFor(innerWidth: number): number {
  return Math.min(220, Math.max(160, Math.floor(innerWidth - 110)));
}

export default function MyContactInfoPanel(): React.JSX.Element {
  const [contactCode, setContactCode] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [copied, setCopied] = useState<boolean | null>(null);
  const [qrSize, setQrSize] = useState<number>(() =>
    qrSideFor(typeof window !== 'undefined' ? window.innerWidth : 320),
  );

  // Fetch the code once (or on retry)
  useEffect(() => {
    let cancelled = false;
    if (contactCode) return; // Already have it

    (async () => {
      try {
        setLoading(true);
        setError(null);
        logger.info('[MyContactInfoPanel] Requesting the contact code from Rust...');
        const code = await getContactCode();
        logger.debug('[MyContactInfoPanel] contact code len:', code.length);
        if (!cancelled) {
          setContactCode(code);
          setLoading(false);
        }
      } catch (err) {
        if (!cancelled) {
          logger.error('[MyContactInfoPanel] Fetch failed:', err);
          setError(err instanceof Error ? err.message : 'Failed to load');
          setLoading(false);
        }
      }
    })();
    return () => { cancelled = true; };
  }, [contactCode]); // Retry if contactCode is reset to empty

  // Render the QR when the code or size changes
  useEffect(() => {
    if (!contactCode || !qrSize) return;

    let cancelled = false;
    (async () => {
      try {
        const url = await QRCode.toDataURL(contactCode, {
          errorCorrectionLevel: 'M',
          margin: 2,
          color: { dark: '#000000', light: '#FFFFFF' },
          width: qrSize,
          type: 'image/png',
        });
        if (!cancelled) {
          setQrDataUrl(url);
        }
      } catch (qrErr) {
        if (!cancelled) logger.warn('[MyContactInfoPanel] Render failed:', qrErr);
      }
    })();
    return () => { cancelled = true; };
  }, [contactCode, qrSize]);

  useEffect(() => {
    const onResize = () => {
      if (typeof window === 'undefined') return;
      setQrSize(qrSideFor(window.innerWidth));
    };
    window.addEventListener('resize', onResize, { passive: true });
    return () => window.removeEventListener('resize', onResize);
  }, []);

  const onCopy = useCallback(async () => {
    const ok = await copyText(contactCode);
    if (ok) {
      try { AudioManager.play('confirm'); } catch {}
    }
    setCopied(ok);
  }, [contactCode]);

  if (loading) return <div className="sb-empty">Loading your contact code{'…'}</div>;
  if (error) {
    return (
      <>
        <Notice kind="error">{error}</Notice>
        <div className="sb-actions">
          <button type="button" className="sb-btn sb-btn--primary" onClick={() => { setError(null); setContactCode(''); }}>
            Try Again
          </button>
        </div>
      </>
    );
  }

  return (
    <div className="my-contact">
      <section className="sb-card sb-card--dark sb-card--hero">
        <div className="qr-code-container qr-code-above-scanlines" style={{ display: 'flex', justifyContent: 'center' }}>
          <span className="sb-qr">
            {qrDataUrl ? (
              <img src={qrDataUrl} alt="DSM Contact QR" width={qrSize} height={qrSize} />
            ) : (
              <span style={{ display: 'block', width: qrSize, height: qrSize }} aria-hidden="true" />
            )}
          </span>
        </div>
        <div className="sb-hero__label" style={{ marginTop: 8 }}>Scan this code to add me as a contact</div>
        <div className="sb-hero__sub">Encoding: dsm:contact/v3</div>
      </section>

      {copied === true && <Notice kind="success" role="status" onClose={() => setCopied(null)}>Copied contact code</Notice>}
      {copied === false && <Notice kind="error" onClose={() => setCopied(null)}>Could not copy. Select the code and copy it by hand.</Notice>}

      <section className="sb-card">
        <div className="sb-field" style={{ marginBottom: 8 }}>
          <label htmlFor="my-contact-code">Contact code</label>
          <textarea
            id="my-contact-code"
            className="sb-input sb-input--mono"
            readOnly
            value={contactCode}
            rows={4}
            onClick={(e) => e.currentTarget.select()}
            spellCheck={false}
          />
        </div>
        <button
          type="button"
          className="sb-btn sb-btn--primary sb-btn--block"
          onClick={() => void onCopy()}
          aria-label="Copy contact code"
        >
          Copy
        </button>
      </section>
    </div>
  );
}
