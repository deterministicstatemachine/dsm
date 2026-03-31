/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// path: src/components/contacts/MyContactInfoPanel.tsx
// MyContactInfoPanel — deterministic QR of minimal contact payload (genesis+device), protobuf-only, no clocks.

import React, { useEffect, useRef, useState, useCallback } from 'react';
import QRCode from 'qrcode';

import { AudioManager } from '../../utils/audio';
import logger from '../../utils/logger';
import { fetchPairingContactUri } from '../../services/qr/pairingQrService';

export default function MyContactInfoPanel(): JSX.Element {
  const [contactUri, setContactUri] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [qrSize, setQrSize] = useState<number>(() => {
    const w = typeof window !== 'undefined' ? window.innerWidth : 320;
    return Math.min(280, Math.max(200, Math.floor(w - 80)));
  });
  const qrRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const style = document.createElement('style');
    style.setAttribute('data-qr-visibility-fix', '1');
    style.textContent = `
      .qr-code-container {
        position: relative !important;
        z-index: 9999 !important;
        isolation: isolate !important;
        background: transparent !important;
      }
      img[alt="DSM Contact QR"], canvas[width] {
        mix-blend-mode: normal !important;
        filter: none !important;
        opacity: 1 !important;
        image-rendering: pixelated !important;
        background: #ffffff !important;
        display: block !important;
      }
    `;
    document.head.appendChild(style);
    return () => { try { document.head.removeChild(style); } catch {} };
  }, []);

  // Separate effect: Fetch URI only once (or on retry)
  useEffect(() => {
    let cancelled = false;
    if (contactUri) return; // Already have it

    (async () => {
      try {
        setLoading(true);
        setError(null);
        logger.info('[MyContactInfoPanel] Requesting pairing QR from router...');
        const uri = await fetchPairingContactUri();
        logger.debug('[MyContactInfoPanel] contact uri len:', uri.length);
        if (!cancelled) {
            setContactUri(uri);
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
  }, [contactUri]); // Retry if contactUri is reset to empty

  // Separate effect: Render QR when URI or size changes
  useEffect(() => {
    if (!contactUri || !qrSize) return;
    
    let cancelled = false;
    (async () => {
        try {
          const url = await QRCode.toDataURL(contactUri, {
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
  }, [contactUri, qrSize]);

  useEffect(() => {
    const onResize = () => {
      if (typeof window === 'undefined') return;
      const next = Math.min(280, Math.max(200, Math.floor(window.innerWidth - 80)));
      setQrSize(next);
    };
    window.addEventListener('resize', onResize, { passive: true });
    return () => window.removeEventListener('resize', onResize);
  }, []);

  const copyToClipboard = useCallback((text: string, label: string) => {
    const onCopied = () => {
      try { AudioManager.play('confirm'); } catch {}
      alert(`Copied ${label}`);
    };

    const navAny = (navigator as any);
    if (navAny?.clipboard?.writeText) {
      navAny.clipboard.writeText(text).then(onCopied).catch(() => {
        try {
          const ta = document.createElement('textarea');
          ta.value = text;
          ta.setAttribute('readonly', 'true');
          ta.style.position = 'absolute';
          ta.style.left = '-9999px';
          document.body.appendChild(ta);
          ta.select();
          document.execCommand('copy');
          document.body.removeChild(ta);
        } catch {}
        onCopied();
      });
    } else {
      try {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', 'true');
        ta.style.position = 'absolute';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      } catch {}
      onCopied();
    }
  }, []);

  if (loading) return <div style={{ padding: 16 }}>Loading...</div>;
  if (error) return <div style={{ padding: 16, color: 'var(--text-dark)' }}>Error: {error}</div>;

  const qrNode = (
    <div
      className="qr-code-container qr-code-above-scanlines"
      style={{
        background: 'transparent',
      }}
    >
      {qrDataUrl ? (
        <img
          src={qrDataUrl}
          alt="DSM Contact QR"
          width={qrSize}
          height={qrSize}
          style={{
            imageRendering: 'pixelated',
            display: 'block',
            background: '#ffffff',
          }}
        />
      ) : (
        <canvas
          ref={qrRef}
          width={qrSize}
          height={qrSize}
          style={{
            imageRendering: 'pixelated',
            width: qrSize,
            height: qrSize,
            display: 'block',
            background: '#ffffff',
          }}
        />
      )}
    </div>
  );

  return (
    <div style={{ padding: 16, fontFamily: 'monospace', color: 'var(--text-dark)', background: 'var(--bg)' }}>
      <h2 style={{ fontSize: 18, marginBottom: 12, textAlign: 'center' }}>MY CONTACT INFO</h2>

      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12, marginBottom: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'center' }}>
          {qrNode}
        </div>

        <div style={{ fontSize: 12, lineHeight: 1.4, textAlign: 'center', maxWidth: 480 }}>
          <div>Scan this code to add me as a contact.</div>
          <div style={{ opacity: 0.8 }}>Encoding: dsm:contact/v3</div>
        </div>
      </div>

      <div style={{ marginTop: 8 }}>
        <div style={{ fontSize: 14, fontWeight: 'bold', marginBottom: 6 }}>CONTACT URI</div>
        <textarea
          readOnly
          value={contactUri}
          onClick={(e) => e.currentTarget.select()}
          style={{
            width: '100%',
            minHeight: 72,
            fontFamily: 'monospace',
            fontSize: 12,
            padding: 8,
            border: '2px solid var(--border)',
            background: 'var(--bg)',
            color: 'var(--text-dark)',
          }}
        />
        <button
          onClick={() => copyToClipboard(contactUri, 'Contact URI')}
          className="wallet-style-button"
          style={{
            width: '100%',
            marginTop: 8,
            padding: 12,
            fontFamily: '\'Martian Mono\', monospace',
            textTransform: 'uppercase',
            background: 'linear-gradient(0deg, rgba(var(--text-rgb),0.12), rgba(var(--bg-rgb),0.06)), repeating-linear-gradient(45deg, rgba(var(--text-rgb),0.14) 0px, rgba(var(--text-rgb),0.14) 2px, transparent 2px, transparent 4px)',
            color: 'var(--text)',
            border: '2px solid var(--border)',
            borderRadius: 8,
            cursor: 'pointer',
            boxShadow: 'inset 0 -2px 0 rgba(var(--text-rgb),0.18), inset 0 2px 0 rgba(var(--bg-rgb),0.08)',
            fontSize: 10,
          }}
          aria-label="Copy Contact URI"
        >
          COPY
        </button>
      </div>
    </div>
  );
}
