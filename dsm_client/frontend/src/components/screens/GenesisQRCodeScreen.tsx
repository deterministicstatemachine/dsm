/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// GenesisQRCodeScreen wrapper

import React from 'react';
import GenesisQrPanel from '../qr/GenesisQrPanel';

interface Props {
  genesisHashBase32: string;
  onClose?: () => void;
}

export default function GenesisQRCodeScreen({ genesisHashBase32, onClose }: Props): JSX.Element {
  return <GenesisQrPanel genesisHashBase32={genesisHashBase32} onClose={onClose} />;
}
