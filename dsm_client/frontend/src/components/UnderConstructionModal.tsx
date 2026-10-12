// SPDX-License-Identifier: MIT OR Apache-2.0

import React from 'react';
import '../styles/BilateralTransfer.css';

interface UnderConstructionModalProps {
  /** The part of the wallet that is not open yet. */
  title: string;
  /** What to say; the pop-up shows only while there is something to say. */
  message: string | null;
  onClose: () => void;
}

/**
 * A part of the wallet that is not open yet: a short pop-up and an OK, and
 * the wallet stays where it was.
 */
export default function UnderConstructionModal({ title, message, onClose }: UnderConstructionModalProps): React.JSX.Element | null {
  if (message === null) return null;
  return (
    <div className="bilateral-transfer-overlay" onClick={onClose}>
      <div className="bilateral-transfer-dialog" role="alertdialog" aria-label={title} onClick={(e) => e.stopPropagation()}>
        <div className="bilateral-transfer-header">
          <h3>{title}</h3>
        </div>
        <div className="bilateral-transfer-body">
          <div className="bilateral-transfer-message">{message}</div>
        </div>
        <div className="bilateral-transfer-actions">
          <button className="bilateral-btn bilateral-btn-accept" onClick={onClose}>OK</button>
        </div>
      </div>
    </div>
  );
}
