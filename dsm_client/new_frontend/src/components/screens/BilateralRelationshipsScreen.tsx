/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// BilateralRelationshipsScreen wrapper

import React from 'react';
import BilateralRelationshipsPanel from '../relationships/BilateralRelationshipsPanel';

interface Props {
  onNavigate?: (to: string) => void;
}

export default function BilateralRelationshipsScreen({ onNavigate }: Props): JSX.Element {
  return <BilateralRelationshipsPanel onNavigate={onNavigate} />;
}
