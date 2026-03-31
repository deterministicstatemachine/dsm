/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/components/SplashController.tsx
// Isolates the intro cutscene rendering from App.tsx.

import React from 'react';

export default function SplashController({ showIntro, introGifSrc }: { showIntro: boolean; introGifSrc: string }) {
  if (!showIntro) return null;
  return (
    <div 
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
        animation: 'introFadeOut 0.8s ease-out 5.2s forwards'
      }}
    >
      <img 
        src={introGifSrc}
        alt="StateBoy Intro"
        style={{ 
          maxWidth: '100%',
          maxHeight: '100%',
          objectFit: 'contain',
          imageRendering: 'pixelated',
          display: 'block'
        }}
      />
    </div>
  );
}
