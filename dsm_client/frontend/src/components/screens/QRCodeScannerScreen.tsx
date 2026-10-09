// SPDX-License-Identifier: Apache-2.0
// The stand-alone Add Contact screen (the `qr` route): the scanner panel on
// the frame, B or the chevron going back to Contacts.

import React from 'react';
import QRCodeScannerPanel from '../qr/QRCodeScannerPanel';
import { ScreenFrame } from '../common/ScreenFrame';

export default function QRCodeScannerScreen(props: {
  onCancel?: () => void;
  eraTokenSrc?: string;
}): React.JSX.Element {
  return (
    <ScreenFrame title="Add Contact" onBack={props.onCancel} className="qr-screen">
      <QRCodeScannerPanel {...props} />
    </ScreenFrame>
  );
}
