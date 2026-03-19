/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// Secondary Device Setup Screen - Scan QR code from root device and bind to existing genesis

import React, { useState } from 'react';
import { addSecondaryDeviceFromQr } from '../../services/genesis/secondaryDeviceSetupService';
import QRCodeScannerPanel from '../qr/QRCodeScannerPanel';

interface SecondaryDeviceSetupScreenProps {
  onComplete?: (deviceIdBase32: string, genesisHashBase32: string) => void;
  onCancel?: () => void;
}

export default function SecondaryDeviceSetupScreen({ 
  onComplete, 
  onCancel 
}: SecondaryDeviceSetupScreenProps) {
  const [step, setStep] = useState<'scan' | 'processing' | 'complete' | 'error'>('scan');
  const [error, setError] = useState<string>('');
  const [deviceIdBase32, setDeviceIdBase32] = useState<string | null>(null);
  const [genesisHashBase32, setGenesisHashBase32] = useState<string | null>(null);

  const handleQRScan = async (scannedData: string) => {
    try {
      setStep('processing');
      setError('');

      const result = await addSecondaryDeviceFromQr(scannedData);
      setDeviceIdBase32(result.deviceIdBase32);
      setGenesisHashBase32(result.genesisHashBase32);
      setStep('complete');

      if (onComplete) {
        onComplete(result.deviceIdBase32, result.genesisHashBase32);
      }
    } catch (err) {
      console.error('FRONTEND: Secondary device setup error:', err);
      setError(err instanceof Error ? err.message : String(err));
      setStep('error');
    }
  };

  if (step === 'scan') {
    return (
      <div className="secondary-device-setup">
        <div className="header">
          <h2>Add Secondary Device</h2>
          <p>Scan the QR code from your primary device</p>
        </div>
        <QRCodeScannerPanel
          onScan={handleQRScan}
          onCancel={onCancel}
        />
      </div>
    );
  }

  if (step === 'processing') {
    return (
      <div className="secondary-device-setup processing">
        <div className="spinner" />
        <p>Binding device to genesis...</p>
      </div>
    );
  }

  if (step === 'error') {
    return (
      <div className="secondary-device-setup error">
        <div className="error-icon" aria-hidden>!</div>
        <h3>Setup Failed</h3>
        <p>{error}</p>
        <button onClick={() => setStep('scan')}>Try Again</button>
        {onCancel && <button onClick={onCancel}>Cancel</button>}
      </div>
    );
  }

  if (step === 'complete' && deviceIdBase32) {
    const deviceIdDisplay = deviceIdBase32;

    return (
      <div className="secondary-device-setup complete">
        <div className="success-icon" aria-hidden>OK</div>
        <h3>Device Added Successfully!</h3>
        <p>Your device ID:</p>
  <code className="device-id">{deviceIdDisplay}</code>
        <p>This device is now bound to the genesis and can be used.</p>
        {onComplete && (
          <button onClick={() => onComplete(deviceIdBase32, genesisHashBase32 || '')}>
            Continue
          </button>
        )}
      </div>
    );
  }

  return null;
}
