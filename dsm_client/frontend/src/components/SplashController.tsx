// SPDX-License-Identifier: MIT OR Apache-2.0

/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/components/SplashController.tsx
// Isolates the intro cutscene rendering from App.tsx.
//
// The intro is the StateBoy FX "IT LIVES" scene, drawn edge to edge on the
// screen by the pixel engine. If the engine cannot be loaded (asset missing,
// script blocked) the theme's intro GIF is shown instead, so the boot path
// never lands on a blank screen.

import React, { useEffect, useRef, useState } from 'react';
import { FxCanvas } from './fx/FxCanvas';
import { loadFxEngine } from './fx/fxEngine';

export default function SplashController({
  showIntro,
  introGifSrc,
  onPlayed,
}: {
  showIntro: boolean;
  introGifSrc: string;
  /** Called once the intro's own fade-out has finished. */
  onPlayed: () => void;
}) {
  const [engineReady, setEngineReady] = useState<boolean | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);

  // The intro is over when its fade-out animation ends, on the container itself
  // (animations inside the scene do not count). The screen for the app's phase
  // takes over from there.
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const onEnd = (e: Event) => {
      if (e.target === el && (e as AnimationEvent).animationName === 'introFadeOut') onPlayed();
    };
    el.addEventListener('animationend', onEnd);
    return () => el.removeEventListener('animationend', onEnd);
  }, [onPlayed, showIntro]);

  useEffect(() => {
    let alive = true;
    void loadFxEngine(2500).then((ok) => {
      if (alive) setEngineReady(ok);
    });
    return () => { alive = false; };
  }, []);

  if (!showIntro) return null;
  return (
    <div
      ref={containerRef}
      className="intro-container"
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        height: '100%',
        background: 'var(--stateboy-dark)',
        pointerEvents: 'none',
        padding: 0,
        margin: 0,
        animation: 'introFadeOut 0.8s ease-out 5.2s forwards',
      }}
    >
      {engineReady === false ? (
        <img
          src={introGifSrc}
          alt="StateBoy Intro"
          style={{
            maxWidth: '100%',
            maxHeight: '100%',
            objectFit: 'contain',
            imageRendering: 'pixelated',
            display: 'block',
          }}
        />
      ) : (
        <div className="sb-fx-full" aria-label="StateBoy Intro" role="img">
          {engineReady ? <FxCanvas anim="intro" fit="fill" /> : null}
        </div>
      )}
    </div>
  );
}
