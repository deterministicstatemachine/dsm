// SPDX-License-Identifier: Apache-2.0
// What the send screen says while an offline step is in flight follows the step's phase as Rust
// lists it, and names the person paid.

import { sendingWords } from '../sendTransfer';

describe('the words for an offline step in flight', () => {
  it('names the person at each phase Rust lists', () => {
    expect(sendingWords(null, 'Ana')).toBe('Sending to Ana…');
    expect(sendingWords('preparing', 'Ana')).toBe('Sending to Ana…');
    expect(sendingWords('prepared', 'Ana')).toBe('Sending to Ana…');
    expect(sendingWords('pending_user_action', 'Ana')).toBe('Waiting for Ana to accept');
    expect(sendingWords('accepted', 'Ana')).toBe('Ana accepted — finishing');
    expect(sendingWords('confirm_pending', 'Ana')).toBe('Finishing…');
    expect(sendingWords('committed', 'Ana')).toBe('Sent');
    expect(sendingWords('rejected', 'Ana')).toBe('Ana declined');
    expect(sendingWords('failed', 'Ana')).toBe('Not sent');
  });
});
