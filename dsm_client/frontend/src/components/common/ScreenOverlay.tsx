// SPDX-License-Identifier: Apache-2.0
// A dialog that covers the whole screen, opened from inside a scrolling body. It
// belongs to the screen, not to the body. WebKit paints such a dialog clipped to
// the scroller it sits in: on iOS the DGen screen's header and tabs hid a wizard's
// title, Close and steps, and Modern's tab bar hid the Cancel of its bottom sheet
// (2026-11-04, the iOS simulator; Android's WebView painted both whole). Mounted
// when the dialog opens, so the screen is already there.

import React, { useState } from 'react';
import { createPortal } from 'react-dom';

export function ScreenOverlay({ on = '.sb-screen', children }: {
  /** The element that is the whole screen: the DGen screen, or Modern's `.s-app`. */
  on?: string;
  children: React.ReactNode;
}): React.JSX.Element {
  const [screen] = useState(() => document.querySelector(on));
  return screen ? createPortal(children, screen) : <>{children}</>;
}
