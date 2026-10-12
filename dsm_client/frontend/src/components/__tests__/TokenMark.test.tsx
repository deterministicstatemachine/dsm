// SPDX-License-Identifier: Apache-2.0
import React from 'react';
import { render } from '@testing-library/react';
import { TokenMark } from '../TokenMark';

describe('TokenMark', () => {
  it('uses the built-in artwork for ERA and for Bitcoin', () => {
    const era = render(<TokenMark ticker="ERA" />);
    expect(era.container.querySelector('img')?.getAttribute('src')).toMatch(/era_token/);
    era.unmount();

    for (const ticker of ['BTC', 'dBTC']) {
      const btc = render(<TokenMark ticker={ticker} />);
      expect(btc.container.querySelector('img')?.getAttribute('src')).toMatch(/btc-logo/);
      btc.unmount();
    }
  });

  it('draws a created token from its own coin, falling back to the built-in artwork', () => {
    // jsdom has no object URLs, so the coin renderer yields the fallback here.
    const { container } = render(<TokenMark ticker="RIGB" />);
    const img = container.querySelector('img');
    expect(img).toBeInTheDocument();
    expect(img?.getAttribute('src')).toMatch(/era_token/);
  });

  it('renders nothing without a token to name', () => {
    const { container } = render(<TokenMark ticker="  " />);
    expect(container.querySelector('img')).not.toBeInTheDocument();
  });
});
