// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import DefiHubScreen from '../DefiHubScreen';

describe('DefiHubScreen', () => {
  it('renders LIQUIDITY and MAIL bricks', () => {
    render(<DefiHubScreen />);
    expect(screen.getByRole('menuitem', { name: /LIQUIDITY/ })).toBeInTheDocument();
    expect(screen.getByRole('menuitem', { name: /MAIL/ })).toBeInTheDocument();
  });

  it('clicking LIQUIDITY navigates to liquidity', () => {
    const onNavigate = jest.fn();
    render(<DefiHubScreen onNavigate={onNavigate} />);
    fireEvent.click(screen.getByRole('menuitem', { name: /LIQUIDITY/ }));
    expect(onNavigate).toHaveBeenCalledWith('liquidity');
  });

  it('clicking MAIL navigates to mail', () => {
    const onNavigate = jest.fn();
    render(<DefiHubScreen onNavigate={onNavigate} />);
    fireEvent.click(screen.getByRole('menuitem', { name: /MAIL/ }));
    expect(onNavigate).toHaveBeenCalledWith('mail');
  });

  it('Enter on a brick navigates', () => {
    const onNavigate = jest.fn();
    render(<DefiHubScreen onNavigate={onNavigate} />);
    fireEvent.keyDown(screen.getByRole('menuitem', { name: /LIQUIDITY/ }), { key: 'Enter' });
    expect(onNavigate).toHaveBeenCalledWith('liquidity');
  });

  it('Back button navigates to home', () => {
    const onNavigate = jest.fn();
    render(<DefiHubScreen onNavigate={onNavigate} />);
    fireEvent.click(screen.getByRole('button', { name: /^Back$/ }));
    expect(onNavigate).toHaveBeenCalledWith('home');
  });
});
