// SPDX-License-Identifier: Apache-2.0
// The beta agreement: every point is ticked on its own before "I agree" does
// anything, and agreeing keeps it under the current version.

import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import BetaAgreement from '../BetaAgreement';
import { AGREEMENT_POINTS } from '../../domain/betaAgreement';
import { appRuntimeStore } from '../../runtime/appRuntimeStore';

describe('the beta agreement', () => {
  it('asks for every point to be ticked, then keeps the agreement', async () => {
    appRuntimeStore.setAgreement('not_accepted');
    render(<BetaAgreement />);
    expect(screen.getByRole('heading', { name: 'Before you start' })).toBeInTheDocument();
    expect(screen.getByText(/I will not send real Bitcoin, real cryptocurrency/)).toBeInTheDocument();
    const agree = screen.getByRole('button', { name: 'I understand and agree' });
    const boxes = screen.getAllByRole('checkbox');
    expect(boxes).toHaveLength(AGREEMENT_POINTS.length);
    for (const box of boxes.slice(0, -1)) fireEvent.click(box);
    expect(agree).toBeDisabled();
    fireEvent.click(boxes[boxes.length - 1]);
    expect(agree).toBeEnabled();
    await act(async () => {
      fireEvent.click(agree);
    });
    expect(appRuntimeStore.getSnapshot().agreement).toBe('accepted');
  });
});
