// SPDX-License-Identifier: Apache-2.0
//
// Additional Device enrollment screen (NEW-device side). Pure rendering: it captures the
// existing genesis device's QR (paste or scan), shows which identity it will join, and asks Rust
// to run the admission. All crypto/BLE/decisions happen in Rust (device.requestAdmission); the
// existing authorized device must approve+sign the admission with its device signing key.

import React, { useCallback, useMemo, useState } from 'react';
import {
  readGenesisFromQr,
  requestAdditionalDeviceAdmission,
} from '../../services/device/additionalDeviceService';

type Props = {
  onNavigate?: (screen: string) => void;
};

type Step = 'input' | 'confirm' | 'requesting' | 'done' | 'error';

const AdditionalDeviceScreen: React.FC<Props> = ({ onNavigate }) => {
  const [qrText, setQrText] = useState('');
  const [step, setStep] = useState<Step>('input');
  const [message, setMessage] = useState<string>('');

  const parsed = useMemo(() => (qrText.trim() ? readGenesisFromQr(qrText.trim()) : null), [qrText]);

  const onConfirm = useCallback(() => {
    if (!parsed) {
      setMessage('That is not a valid genesis device QR. Paste the QR data from the existing device.');
      setStep('error');
      return;
    }
    setStep('confirm');
    setMessage('');
  }, [parsed]);

  const onRequest = useCallback(async () => {
    setStep('requesting');
    setMessage('');
    try {
      const res = await requestAdditionalDeviceAdmission(qrText.trim());
      if (res.ok) {
        setStep('done');
        setMessage(res.message ?? 'Device admitted.');
      } else {
        setStep('error');
        setMessage(res.message ?? 'Admission request failed.');
      }
    } catch (e) {
      setStep('error');
      setMessage(e instanceof Error ? e.message : String(e));
    }
  }, [qrText]);

  return (
    <div className="dsm-content dsm-content--home">
      <div style={{ marginTop: '24px', fontSize: '12px', letterSpacing: '1px' }}>ADDITIONAL DEVICE</div>
      <div style={{ margin: '8px 0 16px', fontSize: '10px', color: 'var(--text-dark)' }}>
        Add this device to an existing identity&apos;s device tree. Scan or paste the QR shown by an
        already-authorized device on that identity. That device must approve the admission.
      </div>

      {(step === 'input' || step === 'error') && (
        <>
          <textarea
            aria-label="Genesis device QR"
            value={qrText}
            onChange={(e) => setQrText(e.target.value)}
            placeholder="Paste the existing device's QR data here"
            rows={4}
            style={{ width: '100%', fontFamily: 'monospace', fontSize: '11px' }}
          />
          {parsed && (
            <div style={{ margin: '10px 0', fontSize: '10px' }}>
              <div>GENESIS: {parsed.genesisHashB32}</div>
              {parsed.deviceIdB32 && <div>EXISTING DEVICE: {parsed.deviceIdB32}</div>}
            </div>
          )}
          {message && step === 'error' && (
            <div style={{ color: 'var(--error, #c0392b)', fontSize: '10px', margin: '8px 0' }}>{message}</div>
          )}
          <button className="home-brick" disabled={!parsed} onClick={onConfirm}>
            CONTINUE
          </button>
        </>
      )}

      {step === 'confirm' && parsed && (
        <>
          <div style={{ fontSize: '10px', margin: '8px 0' }}>
            Joining identity <strong>{parsed.genesisHashB32}</strong>. The existing authorized
            device must approve this device&apos;s admission. Keep both devices nearby.
          </div>
          <button className="home-brick" onClick={() => void onRequest()}>
            REQUEST ADMISSION
          </button>
          <button className="home-brick" onClick={() => setStep('input')}>
            BACK
          </button>
        </>
      )}

      {step === 'requesting' && (
        <div style={{ fontSize: '11px', margin: '16px 0' }}>
          Requesting admission… approve on the existing device.
        </div>
      )}

      {step === 'done' && (
        <>
          <div style={{ fontSize: '11px', margin: '16px 0' }}>{message}</div>
          <button className="home-brick" onClick={() => onNavigate?.('home')}>
            DONE
          </button>
        </>
      )}

      <button className="home-brick" style={{ marginTop: '16px' }} onClick={() => onNavigate?.('home')}>
        CANCEL
      </button>
    </div>
  );
};

export default AdditionalDeviceScreen;
