// SPDX-License-Identifier: Apache-2.0
// The stand-alone My QR screen (the `mycontact` route): this wallet's contact
// code on the frame.

import React from 'react';
import MyContactInfoPanel from '../contacts/MyContactInfoPanel';
import { ScreenFrame } from '../common/ScreenFrame';

export default function MyContactInfoScreen(): React.JSX.Element {
  return (
    <ScreenFrame title="My QR" className="mycontact-screen">
      <MyContactInfoPanel />
    </ScreenFrame>
  );
}
