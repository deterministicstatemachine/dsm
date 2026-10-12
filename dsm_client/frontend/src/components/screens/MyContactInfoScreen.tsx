// SPDX-License-Identifier: Apache-2.0
// The stand-alone My QR screen (the `mycontact` route): this wallet's contact
// code on the frame, and the contact card it carries. Saving the card reads
// the code again, since the code now carries the new card.

import React, { useState } from 'react';
import MyContactInfoPanel from '../contacts/MyContactInfoPanel';
import MyCardPanel from '../contacts/MyCardPanel';
import { ScreenFrame } from '../common/ScreenFrame';

export default function MyContactInfoScreen(): React.JSX.Element {
  const [saves, setSaves] = useState(0);
  return (
    <ScreenFrame title="My QR" className="mycontact-screen">
      <MyContactInfoPanel key={saves} />
      <MyCardPanel onSaved={() => setSaves((n) => n + 1)} />
    </ScreenFrame>
  );
}
