// SPDX-License-Identifier: MIT OR Apache-2.0
// Add Contact: the native camera or a pasted contact code. The code goes to
// Rust as it was scanned or pasted; the card shown is the card Rust read, and
// a refusal is shown as Rust worded it. The person can be picked from the
// phone's contacts, and their details are kept with the contact (A17).

import React, { useEffect, useRef, useState, useCallback, useId } from 'react';
import { useContacts } from '../../contexts/ContactsContext';
import { readContactCode } from '../../dsm/contacts';
import { pickPhoneContact } from '../../dsm/WebViewBridge/phoneContacts';
import type { ContactCard } from '../../dsm/types';
import type { PersonProfile } from '../../domain/types';
import { profileFromCard, withPhoneContact } from '../../domain/personProfile';
import { bytesToDisplay } from '../../contexts/contacts/utils';
import { useBackButton, useConfirmButton } from '../../hooks/useBackButton';
import { Notice } from '../common/ScreenFrame';
import logger from '../../utils/logger';

type ScanPhase =
  | { status: 'idle' }
  | { status: 'scanning' }
  | { status: 'reading' }
  | { status: 'prompt'; card: ContactCard; profile: PersonProfile }
  | { status: 'adding'; alias: string }
  | { status: 'success'; alias: string }
  | { status: 'error'; message: string };

type QRCodeScannerProps = {
  onCancel?: () => void;
  eraTokenSrc?: string;
};

function messageOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export default function QRCodeScannerPanel(props: QRCodeScannerProps = {}): React.JSX.Element {
  const { eraTokenSrc = 'images/logos/era_token_gb.gif' } = props;
  const { addContact } = useContacts();
  const [phase, setPhase] = useState<ScanPhase>({ status: 'idle' });
  const [initializing, setInitializing] = useState(false);
  const [aliasInput, setAliasInput] = useState<string>('');
  const [pasteInput, setPasteInput] = useState('');
  const nativeScanPendingRef = useRef<boolean>(false);
  const addingContactRef = useRef<boolean>(false);
  const promptTitleId = `${useId()}-title`;
  const aliasId = `${useId()}-alias`;

  const showCard = useCallback(async (text: string) => {
    setPhase({ status: 'reading' });
    try {
      const card = await readContactCode(text);
      setAliasInput(card.preferredAlias ?? '');
      setPhase({ status: 'prompt', card, profile: profileFromCard(card) });
    } catch (e) {
      logger.warn('[QRScanner] Rust refused the contact code:', messageOf(e));
      setPhase({ status: 'error', message: messageOf(e) });
    }
  }, []);

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

  // Handle result dispatched back from the native QrScannerActivity.
  useEffect(() => {
    const handleNativeScanResult = (e: Event) => {
      const ce = e as CustomEvent<{ topic: string; payloadText?: string }>;
      if (ce.detail?.topic !== 'qr_scan_result') return;

      nativeScanPendingRef.current = false;
      setInitializing(false);
      const text = ce.detail.payloadText ?? '';
      logger.info('[QRScanner] Native scan result received, length:', text.length);
      if (!text) {
        // Cancelled, or the camera read nothing.
        setPhase({ status: 'idle' });
        return;
      }
      void showCard(text);
    };

    window.addEventListener('dsm-event', handleNativeScanResult);
    return () => window.removeEventListener('dsm-event', handleNativeScanResult);
  }, [showCard]);

  const onConfirmAdd = useCallback(async () => {
    if (phase.status !== 'prompt') return;
    if (addingContactRef.current) {
      logger.warn('[QRScanner] Already adding contact, ignoring tap');
      return;
    }
    addingContactRef.current = true;
    const alias = aliasInput.trim();
    setPhase({ status: 'adding', alias });
    try {
      const result = await addContact(alias, phase.card, { ...phase.profile, name: alias });
      setPhase(result.accepted
        ? { status: 'success', alias: result.alias }
        : { status: 'error', message: result.error });
    } catch (e) {
      logger.error('[QRScanner] addContact failed:', messageOf(e));
      setPhase({ status: 'error', message: messageOf(e) });
    } finally {
      addingContactRef.current = false;
    }
  }, [phase, aliasInput, addContact]);

  // Picks the person from the phone's contacts: their name becomes the alias.
  const fromPhone = useCallback(() => {
    if (phase.status !== 'prompt') return;
    const { card, profile } = phase;
    pickPhoneContact().then(
      (picked) => {
        if (picked === null) return;
        const merged = withPhoneContact(profile, picked);
        setAliasInput(merged.name);
        setPhase({ status: 'prompt', card, profile: merged });
      },
      (e: unknown) => setPhase({ status: 'error', message: `Your contacts did not open: ${messageOf(e)}` }),
    );
  }, [phase]);

  const dismissPrompt = useCallback(() => {
    setPhase({ status: 'idle' });
    setAliasInput('');
  }, []);

  // While the found-contact card is up, B puts it away and A adds.
  const promptOpen = phase.status === 'prompt';
  useBackButton(promptOpen, dismissPrompt);
  useConfirmButton(promptOpen, () => { void onConfirmAdd(); });

  const onCancel = useCallback(() => {
    props.onCancel?.();
  }, [props]);

  const handleManualInput = useCallback(() => {
    const raw = pasteInput.trim();
    if (!raw) return;
    setPasteInput('');
    void showCard(raw);
  }, [pasteInput, showCard]);

  const openCamera = () => {
    setPasteInput('');
    setPhase({ status: 'idle' });
    setAliasInput('');
    nativeScanPendingRef.current = false;
    void startNativeScan();
  };

  return (
    <div className="qr-scanner">
      {phase.status === 'adding' && (
        <section className="sb-card sb-card--dark sb-card--hero" aria-live="polite">
          {/* The coin on its light, bordered tile, as the faucet shows it: bare
              on the dark card its artwork has no edge. */}
          <span className="sb-coin-tile">
            <img
              src={eraTokenSrc}
              alt="Adding contact..."
              style={{ width: 48, height: 48, imageRendering: 'pixelated' }}
            />
          </span>
          <div className="sb-hero__label" style={{ marginTop: 6 }}>Adding Contact</div>
          <div className="sb-hero__sub">
            {phase.alias ? <>Saving &quot;{phase.alias}&quot; to your contacts...</> : 'Saving the contact...'}
          </div>
        </section>
      )}

      {phase.status === 'reading' && (
        <section className="sb-card sb-card--dark" aria-live="polite">
          <div className="sb-card__title">Reading Code</div>
          <p className="sb-hint sb-hint--tight">Reading the contact code...</p>
        </section>
      )}

      {(phase.status === 'idle' || phase.status === 'scanning') && (
        <section className="sb-card sb-card--dark">
          <div className="sb-card__title">{phase.status === 'scanning' ? 'Camera Open' : 'Add Contact'}</div>
          <p className="sb-hint">
            {phase.status === 'scanning'
              ? 'Scan the QR code with the camera, or back out and enter the contact code below.'
              : 'Open the camera to scan a contact QR code, or enter the contact code below.'}
          </p>
          <div className="sb-actions" style={{ margin: 0 }}>
            <button type="button" className="sb-btn" onClick={onCancel}>Cancel</button>
            <button
              type="button"
              className="sb-btn sb-btn--primary"
              onClick={openCamera}
              disabled={initializing || phase.status === 'scanning'}
            >
              {phase.status === 'scanning' ? 'Camera Active' : 'Open Camera'}
            </button>
          </div>
        </section>
      )}

      {(phase.status === 'success' || phase.status === 'error') && (
        <div className="sb-actions" style={{ marginTop: 0 }}>
          <button type="button" className="sb-btn" onClick={onCancel}>Back to contacts</button>
          <button type="button" className="sb-btn sb-btn--primary" onClick={openCamera} disabled={initializing}>
            Open Camera
          </button>
        </div>
      )}

      <p className="sb-hint" aria-live="polite">
        {initializing
          ? 'Opening the camera…'
          : phase.status === 'scanning'
            ? 'Camera launched. If scanning fails, come back and enter the contact code here.'
            : 'Enter the contact code shown with the QR, or use the camera.'}
      </p>

      <section className="sb-card" data-tour="contact-code">
        <div className="sb-card__title">Enter Contact Code</div>
        <div className="sb-field">
          <textarea
            className="sb-input sb-input--mono"
            aria-label="Contact code"
            placeholder="dsm:contact/v3:..."
            value={pasteInput}
            onChange={e => setPasteInput(e.target.value)}
            rows={4}
            spellCheck={false}
          />
        </div>
        <button
          type="button"
          className="sb-btn sb-btn--primary sb-btn--block"
          onClick={handleManualInput}
          disabled={!pasteInput.trim()}
        >
          Use Contact Code
        </button>
      </section>

      {phase.status === 'success' && (
        <Notice kind="success" role="status">Contact &quot;{phase.alias}&quot; added.</Notice>
      )}
      {phase.status === 'error' && (
        <Notice kind="error">{phase.message}</Notice>
      )}

      {phase.status === 'prompt' && (
        <div className="sb-popover-backdrop" onClick={(e) => { if (e.target === e.currentTarget) dismissPrompt(); }}>
          <div
            className="sb-popover sb-card--dark"
            role="dialog"
            aria-modal="true"
            aria-labelledby={promptTitleId}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="sb-popover__head">
              <h3 id={promptTitleId} className="sb-popover__title">Contact Found</h3>
              <button type="button" className="sb-popover__close" onClick={dismissPrompt} aria-label="Close">{'×'}</button>
            </div>
            <div className="sb-popover__body">
              <div className="sb-kv">
                <span className="sb-kv__k">Device</span>
                <span className="sb-kv__v sb-kv__v--mono">{bytesToDisplay(phase.card.deviceId).slice(0, 16)}…</span>
              </div>
              <div className="sb-kv">
                <span className="sb-kv__k">Genesis</span>
                <span className="sb-kv__v sb-kv__v--mono">{bytesToDisplay(phase.card.genesisHash).slice(0, 16)}…</span>
              </div>
              <div className="sb-field" style={{ marginTop: 10, marginBottom: 0 }}>
                <label htmlFor={aliasId}>Alias</label>
                <input
                  id={aliasId}
                  type="text"
                  className="sb-input"
                  placeholder="Blank: named by its device"
                  value={aliasInput}
                  onChange={e => setAliasInput(e.target.value)}
                />
              </div>
              {phase.profile.email.length > 0 ? (
                <div className="sb-kv"><span className="sb-kv__k">Email</span><span className="sb-kv__v">{phase.profile.email}</span></div>
              ) : null}
              {phase.profile.phone.length > 0 ? (
                <div className="sb-kv"><span className="sb-kv__k">Phone</span><span className="sb-kv__v">{phase.profile.phone}</span></div>
              ) : null}
              <button type="button" className="sb-btn sb-btn--block" style={{ marginTop: 10 }} onClick={fromPhone}>From phone contacts</button>
            </div>
            <div className="sb-actions" style={{ margin: 0 }}>
              <button type="button" className="sb-btn" onClick={dismissPrompt}>Cancel</button>
              <button type="button" className="sb-btn sb-btn--primary" onClick={() => void onConfirmAdd()}>Add</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
