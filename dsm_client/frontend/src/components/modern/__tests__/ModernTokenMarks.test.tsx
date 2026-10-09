// SPDX-License-Identifier: Apache-2.0
// The Modern skin's token marks are still: no spinning coin anywhere a token
// is named. The DGen Game Boy keeps its coins.

import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { TokenMark } from '../../TokenMark';
import { TokenCoin } from '../../TokenCoin';
import { CoinArt } from '../../CoinArt';
import { appRuntimeStore } from '../../../runtime/appRuntimeStore';

describe('token marks', () => {
  it('are a still letter badge in the Modern skin, or the policy icon when there is one', () => {
    appRuntimeStore.setSkin('modern');
    render(
      <>
        <TokenMark ticker="GOLD" />
        <TokenMark ticker="ERA" />
        <TokenCoin ticker="SILVER" iconUrl="https://example.com/silver.png" />
        <CoinArt src="era.gif" ticker="dBTC" alt="dBTC coin" />
      </>,
    );
    expect(screen.getByRole('img', { name: 'GOLD' })).toHaveTextContent('G');
    expect(screen.getByRole('img', { name: 'ERA' })).toHaveAttribute('data-tone', 'fuchsia');
    expect(screen.getByRole('img', { name: 'SILVER' })).toHaveAttribute('src', 'https://example.com/silver.png');
    expect(screen.getByRole('img', { name: 'dBTC coin' })).toHaveTextContent('₿');
    expect(document.querySelector('img[src$=".gif"]')).toBeNull();
  });

  it('stay the coin artwork on the DGen Game Boy', () => {
    appRuntimeStore.setSkin('dgen');
    render(<CoinArt src="era.gif" ticker="ERA" alt="ERA coin" />);
    expect(screen.getByRole('img', { name: 'ERA coin' })).toHaveAttribute('src', 'era.gif');
  });
});
