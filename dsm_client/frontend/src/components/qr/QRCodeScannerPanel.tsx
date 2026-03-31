/* eslint-disable @typescript-eslint/no-explicit-any */
import React, { useEffect, useRef, useState, useCallback } from 'react';
import { dsmClient as servicesDsmClient } from '../../services/dsmClient';
import { useContacts } from '../../contexts/ContactsContext';
import { decodeContactQrV3Payload, decodeQrPayloadBase32ToText, type ContactQrV3Data } from '../../services/qr/contactQrService';
import { parseBinary64, bytesToDisplay } from '../../contexts/contacts/utils';
import { decodeFramedEnvelopeV3 } from '../../dsm/decoding';
import logger from '../../utils/logger';

function suggestAliasFromDeviceId(deviceId: Uint8Array | undefined): string {
  if (!deviceId || deviceId.length === 0) return 'contact';
  return bytesToDisplay(deviceId).slice(0, 8).toLowerCase();
}

function decodeContactQrV3(qrData: string): { contact: ContactQrV3Data; rawBytes: Uint8Array } | null {
  logger.debug('[QR] Raw data preview', {
    length: qrData.length,
    preview: qrData.substring(0, 100),
  });
  const decoded = decodeContactQrV3Payload(qrData);
  if (!decoded) {
    logger.warn('[QR] Failed to decode ContactQrV3 payload');
    return null;
  }
  try {
    const dev = decoded.contact.deviceId;
    const gen = decoded.contact.genesisHash;
    logger.debug('[QR] Parsed ContactQrV3 fields', {
      deviceId_len: dev?.length ?? 0,
      genesisHash_len: gen?.length ?? 0,
      network: decoded.contact.network || '(none)',
    });
  } catch {}
  return decoded;
}

type ScanPhase =
  | { status: 'idle' }
  | { status: 'scanning' }
  | { status: 'prompt'; alias: string; contact: ContactQrV3Data }
  | { status: 'adding'; alias: string }
  | { status: 'success'; alias: string }
  | { status: 'error'; message: string };

type QRCodeScannerProps = {
  onCancel?: () => void;
  onScan?: (scannedData: string) => void | Promise<void>;
  eraTokenSrc?: string;
};

export default function QRCodeScannerPanel(props: QRCodeScannerProps = {}): React.JSX.Element {
  const { eraTokenSrc = 'images/logos/era_token_gb.gif' } = props;
  const { addContact } = useContacts();
  const [phase, setPhase] = useState<ScanPhase>({ status: 'idle' });
  const [initializing, setInitializing] = useState(false);
  const [aliasInput, setAliasInput] = useState<string>('');
  const [pasteInput, setPasteInput] = useState('');
  const nativeScanPendingRef = useRef<boolean>(false);
  const addingContactRef = useRef<boolean>(false);

  const containerId = 'qr-reader';

  const nextFrame = () => new Promise<void>(resolve => requestAnimationFrame(() => resolve()));

  const startNativeScan = useCallback(async () => {
    if (nativeScanPendingRef.current) return;
    try {
      const { startNativeQrScannerViaRouter } = await import('../../dsm/WebViewBridge');
      logger.info('[QRScanner] Starting native ML Kit scanner...');
      nativeScanPendingRef.current = true;
      setInitializing(true);
      setPhase({ status: 'scanning' });
      await startNativeQrScannerViaRouter();
      setInitializing(false);
    } catch (err) {
      logger.warn('[QRScanner] Failed to start native scanner:', err);
      nativeScanPendingRef.current = false;
      setPhase({ status: 'error', message: 'Native QR scanner not available.' });
      setInitializing(false);
    }
  }, []);

  // Inject scanner-local styles only; camera launch is explicit.
  useEffect(() => {
    const style = document.createElement('style');
    style.setAttribute('data-qrcode-scanner-style', '1');
    style.textContent = `
        #${containerId}, #${containerId} * { box-sizing: border-box; }
        #${containerId} { display: flex; flex-direction: column; align-items: center; padding: 4px 8px 8px; width: 100%; overflow: hidden; }
        #${containerId} .center-state { width: 100%; max-width: 420px; border: 2px solid var(--border); border-radius: 8px; padding: 10px; background: var(--bg); box-shadow: inset 0 -2px 0 rgba(var(--text-rgb),0.18), inset 0 2px 0 rgba(var(--bg-rgb),0.08); margin-bottom: 8px; text-align: center; }
        #${containerId} .center-state h3 { margin: 0 0 6px; font-size: 10px; font-family: 'Press Start 2P', monospace; letter-spacing: 1px; color: var(--text-dark); text-transform: uppercase; }
        #${containerId} .center-state .body { font-family: 'Martian Mono', monospace; font-size: 11px; line-height: 1.35; color: var(--text); opacity: 0.95; }
        #${containerId} .controls { width: 100%; max-width: 420px; display: flex; flex-direction: column; gap: 6px; margin-top: 2px; align-items: stretch; }
        #${containerId} .controls .left { flex: 1; display: flex; flex-direction: column; gap: 6px; }
        #${containerId} .controls .right { display: flex; gap: 6px; flex-wrap: wrap; justify-content: flex-end; }
        #${containerId} select, #${containerId} button { font-family: 'Martian Mono', monospace; text-transform: uppercase; font-size: 10px; }
        #${containerId} button.wallet-style-button, #${containerId} .wallet-style-button { padding: 8px 12px; min-height: 36px; }
        #${containerId} .hint { font-size: 9px; opacity: .9; color: var(--text-dark); margin-top: 2px; text-align: center; font-family: 'Press Start 2P', monospace; letter-spacing: 1px; }
        #${containerId} .alias-card { width: 100%; max-width: 420px; background: var(--bg); border: 2px solid var(--border); border-radius: 8px; padding: 10px 12px; margin-top: 8px; font-size: 11px; font-family: 'Martian Mono', monospace; line-height: 1.35; box-shadow: inset 0 -2px 0 rgba(var(--text-rgb),0.18), inset 0 2px 0 rgba(var(--bg-rgb),0.08); }
        #${containerId} .alias-card h3 { margin: 0 0 6px; font-size: 10px; font-family: 'Press Start 2P', monospace; letter-spacing: 1px; color: var(--text-dark); text-transform: uppercase; }
        #${containerId} .alias-card .row { display: flex; gap: 8px; align-items: stretch; flex-wrap: nowrap; }
        #${containerId} .alias-card .row input { flex: 1 1 auto; min-width: 0; background: var(--bg); border: 2px solid var(--border); border-radius: 4px; padding: 6px 8px; font-family: 'Martian Mono', monospace; font-size: 11px; color: var(--text); }
        #${containerId} .alias-card .row input:focus { outline: none; border-color: var(--stateboy-screen); background: var(--bg-secondary); }
        #${containerId} .alias-card .row button { flex: 0 0 auto; }
        #${containerId} .alias-meta { font-size: 9px; opacity: 0.85; margin-top: 8px; font-family: 'Martian Mono', monospace; word-break: break-all; }
        #${containerId} .alias-meta code { font-size: 9px; }
        #${containerId} .alias-card.success { border-color: var(--border); background: var(--bg-secondary); color: var(--text-dark); }
        #${containerId} .alias-card.error { border-color: var(--border); background: var(--bg-secondary); color: var(--text-dark); }
        #${containerId} textarea::placeholder { color: var(--text-dark); opacity: 0.55; }
        #${containerId} input::placeholder { color: var(--text-dark); opacity: 0.55; }
        @keyframes contact-fade-in { from { opacity: 0; } to { opacity: 1; } }
        @keyframes contact-slide-up { from { transform: translateY(20px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
        #${containerId} .contact-found-overlay { position: absolute; top: 0; left: 0; right: 0; bottom: 0; z-index: 100; display: flex; align-items: center; justify-content: center; background: rgba(var(--text-rgb), 0.86); border-radius: 8px 8px 0 0; overflow: hidden; animation: contact-fade-in 0.2s ease-in; }
        #${containerId} .contact-found-overlay .overlay-card { -webkit-appearance: none; appearance: none; width: 92%; max-width: 92%; background: var(--bg, #9bbc0f); background-image: linear-gradient(0deg, rgba(var(--text-rgb),0.12), rgba(var(--text-rgb),0.04)), repeating-linear-gradient(45deg, rgba(var(--text-rgb),0.14) 0px, rgba(var(--text-rgb),0.14) 2px, transparent 2px, transparent 4px); border: 4px solid var(--border, #306230); border-radius: 8px; max-height: 85%; overflow-y: auto; box-shadow: inset 0 -3px 0 rgba(var(--text-rgb),0.25), inset 0 3px 0 rgba(var(--text-dark-rgb),0.1), 0 8px 24px rgba(var(--text-rgb),0.4); animation: contact-slide-up 0.3s ease-out; image-rendering: pixelated; }
        #${containerId} .contact-found-overlay .overlay-header { padding: 14px 12px; border-bottom: 3px solid var(--border, #306230); text-align: center; }
        #${containerId} .contact-found-overlay .overlay-body { padding: 12px; }
        #${containerId} .contact-found-overlay .overlay-info-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; padding: 10px 12px; background: var(--bg, #9bbc0f); border: 2px solid var(--border, #306230); border-radius: 6px; }
        #${containerId} .contact-found-overlay .overlay-actions { padding: 12px; border-top: 2px solid var(--border, #306230); display: flex; gap: 8px; }
        #${containerId} .wallet-style-button { position: relative; background: linear-gradient(0deg, rgba(var(--text-rgb),0.12), rgba(var(--bg-rgb),0.06)), repeating-linear-gradient(45deg, rgba(var(--text-rgb),0.14) 0px, rgba(var(--text-rgb),0.14) 2px, transparent 2px, transparent 4px); image-rendering: pixelated; border: 2px solid var(--border); border-radius: 8px; color: var(--text-dark); cursor: pointer; transition: all 0.2s ease; box-shadow: inset 0 -2px 0 rgba(var(--text-rgb),0.18), inset 0 2px 0 rgba(var(--bg-rgb),0.08); display: inline-flex; align-items: center; justify-content: center; gap: 6px; font-family: 'Martian Mono', monospace; }
        #${containerId} .wallet-style-button:hover { transform: scale(1.02); }
        #${containerId} .wallet-style-button:active { transform: scale(0.98); }
        @media (min-width: 480px) { #${containerId} .controls { flex-direction: row; align-items: center; justify-content: space-between; } #${containerId} .controls .left { flex-direction: row; align-items: center; } }
        @media (max-width: 380px) { #${containerId} .alias-card .row { flex-wrap: wrap; } #${containerId} .alias-card .row button { width: 100%; } }
      `;
    document.head.appendChild(style);

    return () => { document.head.removeChild(style); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Handle result dispatched back from the native QrScannerActivity.
  useEffect(() => {
    const handleNativeScanResult = (e: Event) => {
      const ce = e as CustomEvent<{ topic: string; payloadText?: string; payloadLatin1?: string; payloadBase32?: string; payloadBytes?: Uint8Array }>;
      if (ce.detail?.topic !== 'qr_scan_result') return;

      nativeScanPendingRef.current = false;

      // Future: direct Envelope bytes path (not yet sent by native side).
      let qrData = '';
      if (ce.detail.payloadBytes) {
        try {
          const env = decodeFramedEnvelopeV3(ce.detail.payloadBytes);
          if (env.payload.case === 'error') {
            const err = env.payload.value;
            logger.info('[QRScanner] Native scan error envelope:', err.message);
            if (err.code === 1) { props.onCancel?.(); return; }
            setPhase({ status: 'error', message: err.message || 'Scan failed' });
            setInitializing(false);
            return;
          }
          logger.warn('[QRScanner] payloadBytes not yet implemented, using text path');
        } catch (err) {
          logger.error('[QRScanner] Failed to decode envelope from payloadBytes:', err);
          setPhase({ status: 'error', message: 'Invalid QR format' });
          setInitializing(false);
          return;
        }
      }

      if (ce.detail.payloadText) {
        qrData = ce.detail.payloadText;
      } else if (ce.detail.payloadBase32) {
        const decoded = decodeQrPayloadBase32ToText(ce.detail.payloadBase32);
        if (decoded) { qrData = decoded; }
        else { logger.error('[QRScanner] Failed to decode Base32 payload'); }
      } else {
        qrData = ce.detail.payloadLatin1 || '';
      }

      logger.info('[QRScanner] Native scan result received, length:', qrData.length);

      if (!qrData) {
        logger.info('[QRScanner] Native scan cancelled/failed');
        setInitializing(false);
        setPhase({ status: 'idle' });
        return;
      }

      const decoded = decodeContactQrV3(qrData);
      if (!decoded) {
        if (props.onScan) {
          try {
            const p = props.onScan(qrData);
            if (p && typeof (p as Promise<void>).catch === 'function') {
              (p as Promise<void>).catch((err: unknown) => logger.warn('[QR] onScan handler error:', err));
            }
          } catch (err: unknown) { logger.warn('[QR] onScan handler error:', err); }
          return;
        }
        setPhase({ status: 'error', message: 'Invalid contact QR code' });
        return;
      }

      const alias = suggestAliasFromDeviceId(decoded.contact.deviceId);
      logger.info('[QRScanner] Native scan decoded contact:', alias);

      if (props.onScan) {
        try {
          const p = props.onScan(qrData);
          if (p && typeof (p as Promise<void>).catch === 'function') {
            (p as Promise<void>).catch((err: unknown) => logger.warn('[QR] onScan handler error:', err));
          }
        } catch (err: unknown) { logger.warn('[QR] onScan handler error:', err); }
        return;
      }

      setAliasInput(alias);
      setPhase({ status: 'prompt', alias, contact: decoded.contact });
      setInitializing(false);
    };

    window.addEventListener('dsm-event', handleNativeScanResult);
    return () => window.removeEventListener('dsm-event', handleNativeScanResult);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.onScan]);

  const onConfirmAdd = useCallback(async () => {
    logger.info('[QRScanner] onConfirmAdd called, phase:', phase.status);
    if (phase.status !== 'prompt') return;

    if (addingContactRef.current) {
      logger.warn('[QRScanner] Already adding contact, ignoring tap');
      return;
    }

    const alias = aliasInput.trim();
    logger.info('[QRScanner] Adding contact with alias:', alias);
    if (!alias) {
      setPhase({ status: 'error', message: 'Enter a contact alias' });
      return;
    }

    const contact = phase.contact;
    addingContactRef.current = true;
    setPhase({ status: 'adding', alias });

    try {
      let ready = true;
      try { ready = await servicesDsmClient.isReady(); } catch { ready = false; }
      if (!ready) {
        addingContactRef.current = false;
        setPhase({ status: 'error', message: 'Wallet identity not initialized: create your wallet identity first to add contacts.' });
        return;
      }

      logger.debug('[QRScanner] Contact from QR', {
        deviceId: contact.deviceId,
        genesisHash: contact.genesisHash,
        signingPublicKeyLen: contact.signingPublicKeyLength || 0,
      });

      if (!(contact.deviceId instanceof Uint8Array) || contact.deviceId.length !== 32) {
        logger.error('[QRScanner] Invalid deviceId: expected 32 bytes, got', contact.deviceId?.length);
        addingContactRef.current = false;
        setPhase({ status: 'error', message: 'Invalid device ID in QR code' });
        return;
      }
      if (!(contact.genesisHash instanceof Uint8Array) || contact.genesisHash.length !== 32) {
        logger.error('[QRScanner] Invalid genesisHash: expected 32 bytes, got', contact.genesisHash?.length);
        addingContactRef.current = false;
        setPhase({ status: 'error', message: 'Invalid genesis hash in QR code' });
        return;
      }

      if (!contact.signingPublicKeyB32) {
        logger.error('[QRScanner] Missing signingPublicKeyB32 in QR payload');
        addingContactRef.current = false;
        setPhase({ status: 'error', message: 'Missing signing public key in QR code' });
        return;
      }
      try {
        parseBinary64(contact.signingPublicKeyB32, 'signingPublicKey');
      } catch (e: any) {
        logger.error('[QRScanner] Invalid signing public key:', e?.message || e);
        addingContactRef.current = false;
        setPhase({ status: 'error', message: 'Invalid signing public key in QR code' });
        return;
      }

      logger.info('[QRScanner] Calling ContactsContext.addContact with alias:', alias);
      const success = await addContact(
        alias,
        contact.genesisHash,
        contact.deviceId,
        contact.signingPublicKeyB32
      );

      if (success) {
        logger.info('[QRScanner] Contact added successfully with alias:', alias);
        addingContactRef.current = false;
        setPhase({ status: 'success', alias });

        await nextFrame();
        await nextFrame();

        try {
          const bridge = (window as { DsmBridge?: Record<string, unknown> }).DsmBridge;
          if (bridge) {
            logger.info('[QRScanner] Contact added; Rust pairing orchestrator will handle BLE pairing automatically.');
          }
        } catch (bleErr) {
          logger.warn('[QRScanner] BLE pairing initiation failed (non-fatal):', bleErr);
        }
      } else {
        logger.error('[QRScanner] Contact add failed');
        addingContactRef.current = false;
        setPhase({ status: 'error', message: 'Failed to add contact' });
      }
    } catch (e) {
      logger.error('[QRScanner] Exception in onConfirmAdd:', e);
      logger.error('[QRScanner] Error stack:', (e as Error)?.stack);
      addingContactRef.current = false;
      const msg = e instanceof Error ? e.message : 'Failed to add contact';
      if (/identity not initializ|identity not ready|identity not initialized|DSM bridge identity not ready|Identity not initialized/i.test(msg)) {
        const bridge = (window as any)?.DsmBridge;
        const hasIdent = bridge?.hasIdentityDirect?.() ?? false;
        if (hasIdent) {
          setPhase({ status: 'error', message: 'Wallet still initializing. Please wait a moment and try again.' });
        } else {
          setPhase({ status: 'error', message: 'Failed to add contact: Wallet identity not initialized. Create your wallet identity first before adding contacts.' });
        }
      } else {
        setPhase({ status: 'error', message: msg });
      }
    }
  }, [phase, aliasInput, addContact]);

  const onCancel = useCallback(() => {
    props.onCancel?.();
  }, [props]);

  const handleManualInput = useCallback(() => {
    const raw = pasteInput.trim();
    if (!raw) return;

    // Route through same pipeline as native scan result
    if (props.onScan) {
      try {
        const p = props.onScan(raw);
        if (p && typeof (p as Promise<void>).catch === 'function') {
          (p as Promise<void>).catch((err: unknown) => logger.warn('[QR] onScan handler error:', err));
        }
      } catch (err: unknown) { logger.warn('[QR] onScan handler error:', err); }
      setPasteInput('');
      return;
    }

    const decoded = decodeContactQrV3(raw);
    if (!decoded) {
      setPhase({ status: 'error', message: 'Invalid contact code — expected the full dsm:contact/v3 code or its Base32 payload.' });
      return;
    }

    const alias = suggestAliasFromDeviceId(decoded.contact.deviceId);
    setAliasInput(alias);
    setPhase({ status: 'prompt', alias, contact: decoded.contact });
    setPasteInput('');
  }, [pasteInput, props]);

  return (
    <div id={containerId}>
      {/* Contact found overlay renders at the bottom of the component as a full-screen modal */}
      {phase.status === 'adding' && (
        <div className="center-state" style={{ padding: 24 }}>
          <img
            src={eraTokenSrc}
            alt="Adding contact..."
            style={{ width: 48, height: 48, marginBottom: 12, imageRendering: 'pixelated' }}
          />
          <h3>Adding Contact</h3>
          <div className="body">Saving &quot;{phase.alias}&quot; to your contacts...</div>
        </div>
      )}
      {(phase.status === 'idle' || phase.status === 'scanning') && (
        <div className="center-state">
          <h3>{phase.status === 'scanning' ? 'Camera Open' : 'Add Contact'}</h3>
          <div className="body">
            {phase.status === 'scanning'
              ? 'Scan the QR code with the native camera, or back out and enter the contact code manually below.'
              : 'Open the camera to scan a contact QR code, or enter the contact code manually below.'}
          </div>
        </div>
      )}
      <div className="controls">
        <div className="left">
          <button
            className="wallet-style-button"
            onClick={() => {
              setPasteInput('');
              setPhase({ status: 'idle' });
              setAliasInput('');
              nativeScanPendingRef.current = false;
              void startNativeScan();
            }}
            disabled={initializing || phase.status === 'scanning'}
          >
            {phase.status === 'scanning' ? 'Camera Active' : 'Open Camera'}
          </button>
        </div>
        <div className="right">
          <button className="wallet-style-button" onClick={onCancel}>Cancel</button>
        </div>
      </div>
      <div className="hint">
        {initializing
          ? 'Opening native camera…'
          : phase.status === 'scanning'
            ? 'Camera launched. If scanning fails, go back and enter the contact code here.'
            : 'Enter the contact code shown under the QR, or use the camera.'}
      </div>
      <div className="alias-card" style={{ marginTop: 8 }}>
        <h3 style={{ margin: '0 0 8px' }}>Enter Contact Code</h3>
        <textarea
          placeholder="dsm:contact/v3:... or the Base32 code shown under the QR"
          value={pasteInput}
          onChange={e => setPasteInput(e.target.value)}
          rows={4}
          style={{
            width: '100%',
            fontFamily: '\'Martian Mono\', monospace',
            fontSize: 11,
            padding: '6px 8px',
            background: 'var(--bg)',
            border: '2px solid var(--border)',
            borderRadius: 4,
            color: 'var(--text)',
            resize: 'vertical',
            boxSizing: 'border-box',
          }}
        />
        <button
          className="wallet-style-button"
          onClick={handleManualInput}
          disabled={!pasteInput.trim()}
          style={{ marginTop: 6, width: '100%' }}
        >
          Use Contact Code
        </button>
      </div>
      {phase.status === 'prompt' && (
        <div className="contact-found-overlay" onClick={(e) => { if (e.target === e.currentTarget) { setPhase({ status: 'idle' }); setAliasInput(''); } }}>
          <div className="overlay-card">
            <div className="overlay-header">
              <h3 style={{ margin: 0, fontSize: 10, fontFamily: "'Press Start 2P', monospace", letterSpacing: 1, color: 'var(--text-dark)', textTransform: 'uppercase', fontWeight: 700, textShadow: '1px 1px 0 rgba(var(--bg-rgb),0.5)' }}>Contact Found</h3>
            </div>
            <div className="overlay-body">
              <div className="overlay-info-row">
                <span style={{ fontSize: 9, fontFamily: "'Press Start 2P', monospace", color: 'var(--text)', textTransform: 'uppercase' }}>Device</span>
                <span style={{ fontSize: 9, fontFamily: "'Martian Mono', monospace", color: 'var(--text-dark)', wordBreak: 'break-all', maxWidth: '60%', textAlign: 'right' }}>{bytesToDisplay(phase.contact.deviceId).slice(0, 16)}…</span>
              </div>
              <div className="overlay-info-row">
                <span style={{ fontSize: 9, fontFamily: "'Press Start 2P', monospace", color: 'var(--text)', textTransform: 'uppercase' }}>Genesis</span>
                <span style={{ fontSize: 9, fontFamily: "'Martian Mono', monospace", color: 'var(--text-dark)', wordBreak: 'break-all', maxWidth: '60%', textAlign: 'right' }}>{bytesToDisplay(phase.contact.genesisHash).slice(0, 16)}…</span>
              </div>
              <div style={{ marginTop: 12, fontSize: 9, fontFamily: "'Press Start 2P', monospace", color: 'var(--text-dark)', textTransform: 'uppercase', marginBottom: 6 }}>Alias</div>
              <input
                type="text"
                placeholder="Choose an alias"
                value={aliasInput}
                onChange={e => setAliasInput(e.target.value)}
                style={{
                  width: '100%',
                  boxSizing: 'border-box',
                  background: 'var(--bg)',
                  border: '2px solid var(--border)',
                  borderRadius: 4,
                  padding: '8px 10px',
                  fontFamily: "'Martian Mono', monospace",
                  fontSize: 11,
                  color: 'var(--text)',
                }}
              />
            </div>
            <div className="overlay-actions">
              <button
                className="wallet-style-button"
                onClick={() => { setPhase({ status: 'idle' }); setAliasInput(''); }}
                style={{ flex: 1 }}
              >
                Cancel
              </button>
              <button
                className="wallet-style-button"
                onClick={onConfirmAdd}
                style={{ flex: 1, fontWeight: 700 }}
              >
                Add
              </button>
            </div>
          </div>
        </div>
      )}
      {phase.status === 'success' && (
        <div className="alias-card success">✓ Contact &quot;{phase.alias}&quot; added.</div>
      )}
      {phase.status === 'error' && (
        <div className="alias-card error">✗ Error: {phase.message}</div>
      )}
    </div>
  );
}
