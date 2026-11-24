// SPDX-License-Identifier: Apache-2.0
// ERA's mark in the Modern skin is its built-in symbol, the hexagonal E its
// DGen coins are struck from, in its fuchsia badge; other tokens keep their
// own shape or their ticker's first letter.

import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { ERA_MARK_SRC, FlatTokenMark } from '../FlatTokenMark';

test('ERA is drawn with its own symbol, in fuchsia, not a letter', () => {
  const { container } = render(<FlatTokenMark ticker="ERA" />);
  const badge = screen.getByRole('img', { name: 'ERA' });
  expect(badge).toHaveAttribute('data-tone', 'fuchsia');
  const shape = container.querySelector('img.s-token-shape');
  expect(shape).toHaveAttribute('src', ERA_MARK_SRC);
  expect(container.querySelector('.s-token-letter')).toBeNull();
});

test('a token with no artwork of its own keeps its first letter', () => {
  const { container } = render(<FlatTokenMark ticker="GOLD" />);
  expect(container.querySelector('img.s-token-shape')).toBeNull();
  expect(container.querySelector('.s-token-letter')).toHaveTextContent('G');
});
