// SPDX-License-Identifier: Apache-2.0
// The one-time choice the app asks for before anything else: Simple or
// Classic. Shown once the preferences are read and none is set, over whatever
// is on the screen (a first launch's intro or setup, or a wallet set up before
// the choice existed); Settings changes it after.

import React, { useState } from 'react';
import { useAppRuntimeStore, type Skin } from '../../runtime/appRuntimeStore';
import { chooseSkin } from '../../runtime/skinPreferences';
import { Sheet } from './parts';

export default function SkinChoice(): React.JSX.Element | null {
  const runtime = useAppRuntimeStore();
  const [problem, setProblem] = useState<string | null>(null);
  if (runtime.skinRead !== 'read' || runtime.skin !== null) return null;

  const pick = (skin: Skin) => {
    chooseSkin(skin).then(
      () => setProblem(null),
      (e: unknown) => setProblem(e instanceof Error ? e.message : String(e)),
    );
  };

  return (
    <Sheet label="Choose your wallet" onClose={() => pick('simple')}>
      <h2>How do you want your wallet?</h2>
      <p>You can change this any time in Settings.</p>
      <div className="s-stack">
        <button type="button" className="s-btn s-btn-primary" onClick={() => pick('simple')}>
          Simple: send, receive, people
        </button>
        <button type="button" className="s-btn s-btn-quiet" onClick={() => pick('classic')}>
          Classic: every DSM feature
        </button>
      </div>
      {problem !== null ? <p>{problem}</p> : null}
    </Sheet>
  );
}
