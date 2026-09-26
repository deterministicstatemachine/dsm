// SPDX-License-Identifier: Apache-2.0
// QR Code Scanner Screen wrapper

import React from 'react';
import QRCodeScannerPanel from '../qr/QRCodeScannerPanel';

export default function QRCodeScannerScreen(props: {
  onCancel?: () => void;
  eraTokenSrc?: string;
}): React.JSX.Element {
  return <QRCodeScannerPanel {...props} />;
}
