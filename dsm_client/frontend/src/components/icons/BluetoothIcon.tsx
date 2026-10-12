// SPDX-License-Identifier: MIT OR Apache-2.0

import React from 'react';

interface Props {
  size?: number;
  title?: string;
  className?: string;
  color?: string;
}

// Classic Bluetooth "rune" glyph — reads clearly at small sizes (12px) unlike a dense
// satellite icon. Shown next to a contact once it is BLE-paired.
const BluetoothIcon: React.FC<Props> = ({ size = 16, title = 'Bluetooth', className, color }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
    className={className}
    aria-hidden={title ? undefined : 'true'}
    role="img"
    style={{ color }}
  >
    {title && <title>{title}</title>}
    <path
      fill="currentColor"
      d="M17.71 7.71 12 2h-1v7.59L6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 11 14.41V22h1l5.71-5.71-4.3-4.29 4.3-4.29zM13 5.83l1.88 1.88L13 9.59V5.83zm1.88 10.46L13 18.17v-3.76l1.88 1.88z"
    />
  </svg>
);

export default BluetoothIcon;
