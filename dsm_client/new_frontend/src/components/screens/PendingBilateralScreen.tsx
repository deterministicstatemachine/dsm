/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// PendingBilateralScreen wrapper

import React from 'react';
import PendingBilateralPanel from '../relationships/PendingBilateralPanel';

interface Props {
  onNavigate?: (to: string) => void;
}

export default function PendingBilateralScreen({ onNavigate }: Props): JSX.Element {
  return <PendingBilateralPanel onNavigate={onNavigate} />;
}

