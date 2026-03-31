/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// path: src/components/qr/GenesisQrPanel.tsx
// Genesis QR Code Display - Show genesis hash as QR for secondary devices to scan

import React, { useEffect, useMemo, useState } from 'react';
import { encodeGenesisQrDataFromBase32 } from '../../services/qr/genesisQrService';
import QRCode from 'qrcode';

interface GenesisQRCodeScreenProps {
  genesisHashBase32: string;
  onClose?: () => void;
}

export default function GenesisQrPanel({ genesisHashBase32, onClose }: GenesisQRCodeScreenProps) {
  const [qrPngUrl, setQrPngUrl] = useState<string>('');
  const [qrError, setQrError] = useState<boolean>(false);

  const encodedQr = useMemo(() => {
    try {
      return {
        data: encodeGenesisQrDataFromBase32(genesisHashBase32),
        hasError: false,
      };
    } catch (e) {
      console.error('Failed to encode genesis hash for QR:', e);
      return {
        data: '',
        hasError: true,
      };
    }
  }, [genesisHashBase32]);

  useEffect(() => {
    if (encodedQr.hasError || !encodedQr.data) {
      setQrPngUrl('');
      setQrError(true);
      return;
    }

    let cancelled = false;

    // PNG-only rendering — SVG path removed to eliminate XSS surface
    void QRCode.toDataURL(encodedQr.data, {
      errorCorrectionLevel: 'M',
      margin: 2,
      width: 300,
      type: 'image/png',
      color: { dark: '#000000', light: '#FFFFFF' },
    }).then((url) => {
      if (!cancelled && typeof url === 'string' && url.length > 0) {
        setQrPngUrl(url);
        setQrError(false);
      }
    }).catch((err) => {
      if (!cancelled) {
        console.error('QR PNG generation failed:', err);
        setQrPngUrl('');
        setQrError(true);
      }
    });

    return () => {
      cancelled = true;
    };
  }, [encodedQr]);

  return (
    <div className="genesis-qr-screen">
      <div className="header">
        <h2>Share Your Genesis</h2>
        <p>Scan this QR code with your secondary device</p>
      </div>

      <div className="qr-code-container">
        {qrPngUrl ? (
          <div className="qr-code qr-code-above-scanlines">
            <img alt="DSM Genesis QR" src={qrPngUrl} style={{ width: 300, height: 300 }} />
          </div>
        ) : qrError ? (
          <div className="loading">QR generation failed</div>
        ) : (
          <div className="loading">Generating QR code...</div>
        )}
      </div>

      <div className="info">
        <h3>Genesis Hash:</h3>
        <code className="genesis-hash">{encodedQr.data || 'binary[32]'}</code>
        <button
          onClick={() => {
            const text = encodedQr.data;
            const navAny = (navigator as any);
            if (navAny?.clipboard?.writeText) {
              navAny.clipboard.writeText(text).catch(() => {});
            } else {
              try {
                const ta = document.createElement('textarea');
                ta.value = text;
                ta.style.position = 'absolute';
                ta.style.left = '-9999px';
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                document.body.removeChild(ta);
              } catch {}
            }
          }}
          style={{
            marginTop: 10,
            padding: '8px 20px',
            background: 'rgba(var(--text-rgb),0.12)',
            color: 'var(--text-dark)',
            border: '1px solid var(--border)',
            borderRadius: 4,
            cursor: 'pointer',
            fontFamily: 'monospace',
            fontSize: 12,
          }}
        >
          Copy Hash
        </button>
      </div>

      {onClose && (
        <button className="close-button" onClick={onClose}>
          Close
        </button>
      )}

      <style>{`
        .genesis-qr-screen {
          padding: 20px;
          max-width: 600px;
          margin: 0 auto;
        }
        .header {
          text-align: center;
          margin-bottom: 30px;
        }
        .qr-code-container {
          display: flex;
          justify-content: center;
          margin: 30px 0;
        }
        .qr-code {
          width: 300px;
          height: 300px;
          display: flex;
          align-items: center;
          justify-content: center;
          background: white;
          border: 2px solid #ccc;
          border-radius: 8px;
          padding: 10px;
        }
        .qr-code-above-scanlines {
          position: relative !important;
          z-index: 9999 !important;
          isolation: isolate !important;
        }
        .qr-code-above-scanlines::before {
          content: '' !important;
          position: absolute !important;
          top: -8px !important;
          left: -8px !important;
          right: -8px !important;
          bottom: -8px !important;
          background: #ffffff !important;
          z-index: -1 !important;
        }
        .qr-code svg {
          width: 100%;
          height: 100%;
        }
        img[alt="DSM Genesis QR"] {
          mix-blend-mode: normal !important;
          filter: none !important;
          opacity: 1 !important;
          background: #ffffff !important;
          image-rendering: pixelated !important;
        }
        .info {
          margin-top: 30px;
          text-align: center;
        }
        .genesis-hash {
          display: block;
          padding: 10px;
          background: rgba(var(--text-rgb),0.08);
          border-radius: 4px;
          word-break: break-all;
          font-size: 12px;
          margin-top: 10px;
        }
        .close-button {
          display: block;
          margin: 20px auto;
          padding: 10px 20px;
          background: rgba(var(--text-rgb),0.18);
          color: var(--text-dark);
          border: 1px solid var(--border);
          border-radius: 4px;
          cursor: pointer;
        }
        .close-button:hover {
          background: rgba(var(--text-rgb),0.25);
        }
        .loading {
          width: 300px;
          height: 300px;
          border: 2px solid var(--border);
          display: flex;
          align-items: center;
          justify-content: center;
          background: var(--bg);
          padding: 20px;
          text-align: center;
        }
      `}</style>
    </div>
  );
}
