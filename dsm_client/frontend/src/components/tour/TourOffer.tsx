// First-run offer of the guided tour.
//
// Shown once, on the home screen of a ready wallet, to someone who has never
// finished or dismissed the tour. Starting the tour or choosing "Not now" both
// retire the offer for this session at once, before the preference write
// lands, so it can never reappear on the way back home. The tour stays
// replayable from Settings.

import React, { useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import type { AppState } from '../../types/app';
import { useNavigationStore } from '../../runtime/navigationStore';
import { hasSeenTour, markTourSeen, tourStore, useTourStore } from './tourStore';
import './GuidedTour.css';

type Props = {
  appState: AppState;
  showIntro: boolean;
  guideSrc: string;
};

export default function TourOffer({ appState, showIntro, guideSrc }: Props): React.JSX.Element | null {
  const tour = useTourStore();
  const navigation = useNavigationStore();
  const [unseen, setUnseen] = useState(false);
  const [done, setDone] = useState(false);

  const eligible =
    appState === 'wallet_ready' && !showIntro && navigation.currentScreen === 'home' && !tour.active && !done;

  useEffect(() => {
    if (!eligible) return undefined;
    let cancelled = false;
    void hasSeenTour().then((seen) => {
      if (!cancelled) setUnseen(!seen);
    });
    return () => {
      cancelled = true;
    };
  }, [eligible]);

  if (!eligible || !unseen || typeof document === 'undefined') return null;

  const host = document.querySelector('.stateboy-screen-host');
  const frame = host ? host.getBoundingClientRect() : null;
  const style: React.CSSProperties = frame
    ? {
        left: frame.left + 8,
        width: Math.max(frame.width - 16, 200),
        bottom: Math.max(window.innerHeight - frame.bottom + 8, 8),
      }
    : { left: 8, right: 8, bottom: 8 };

  const dismiss = (): void => {
    setDone(true);
    void markTourSeen();
  };

  const start = (): void => {
    setDone(true);
    tourStore.start();
  };

  return createPortal(
    <div className="gt-root" data-testid="tour-offer">
      <div className="gt-dialog" role="dialog" aria-labelledby="gt-offer-title" style={style}>
        <div className="gt-dialog__main">
          <img className="gt-guide" src={guideSrc} alt="" aria-hidden="true" />
          <div className="gt-copy">
            <div id="gt-offer-title" className="gt-title">New here?</div>
            <p className="gt-body">
              Take a quick tour. It runs in practice mode, so nothing you do in it is real. You can replay it from
              Settings any time.
            </p>
          </div>
        </div>
        <div className="gt-controls">
          <button type="button" className="gt-btn gt-btn--ghost" onClick={dismiss}>
            Not now
          </button>
          <button type="button" className="gt-btn gt-btn--primary" onClick={start}>
            Start tour
          </button>
        </div>
      </div>
    </div>,
    document.body,
  );
}
