/* eslint-disable @typescript-eslint/no-explicit-any */
import React from 'react';
import '../styles/BilateralTransfer.css';

interface ConfirmModalProps {
  visible: boolean;
  title?: string;
  message: string;
  onConfirm: () => void;
  onCancel: () => void;
}

export default function ConfirmModal({ visible, title, message, onConfirm, onCancel }: ConfirmModalProps): JSX.Element | null {
  if (!visible) return null;
  return (
    <div className="bilateral-transfer-overlay" onClick={onCancel}>
      <div className="bilateral-transfer-dialog" onClick={(e) => e.stopPropagation()}>
        <div className="bilateral-transfer-header">
          <h3>{title || 'Confirm'}</h3>
        </div>
        <div className="bilateral-transfer-body">
          <div className="bilateral-transfer-message">{message}</div>
        </div>
        <div className="bilateral-transfer-actions">
          <button className="bilateral-btn bilateral-btn-reject" onClick={onCancel}>Cancel</button>
          <button className="bilateral-btn bilateral-btn-accept" onClick={onConfirm}>Confirm</button>
        </div>
      </div>
    </div>
  );
}
