// SPDX-License-Identifier: Apache-2.0
//
// The guided tour overlay. It opens each step's real screen, finds the real
// element the step is about, dims everything else, points at it, and explains
// it in a dialogue box. On hands-on steps the element stays live so the user
// does the thing themselves; the tour moves on when it sees it done.

import React, { useCallback, useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import type { AppState } from '../../types/app';
import { navigationStore, useNavigationStore } from '../../runtime/navigationStore';
import { buildHomeMenuItems } from '../../viewmodels/homeViewModel';
import { AudioManager } from '../../utils/audio';
import { practiceMode } from './practiceMode';
import { TOUR_STEPS, type TourStep } from './tourSteps';
import { tourStore, useTourStore } from './tourStore';
import './GuidedTour.css';

export type Box = { top: number; left: number; width: number; height: number };

const RING_PAD = 6;
const TYPE_INTERVAL_MS = 16;
const VALUE_SETTLE_MS = 900;
const CELEBRATE_MS = 1800;
const HOME_MENU = buildHomeMenuItems('wallet_ready', 'home');
const HARDWARE =
  '#button-a, #button-b, #button-start, #button-select, #dpad-up, #dpad-down, #dpad-left, #dpad-right';

function prefersReducedMotion(): boolean {
  try {
    return typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  } catch {
    return false;
  }
}

function find(selector: string | undefined): HTMLElement | null {
  if (!selector) return null;
  try {
    return document.querySelector(selector) as HTMLElement | null;
  } catch {
    return null;
  }
}

function toBox(rect: DOMRect, pad: number): Box | null {
  if (rect.width <= 0 || rect.height <= 0) return null;
  return { top: rect.top - pad, left: rect.left - pad, width: rect.width + pad * 2, height: rect.height + pad * 2 };
}

function sameBox(a: Box | null, b: Box | null): boolean {
  if (a === b) return true;
  if (!a || !b) return false;
  return (
    Math.abs(a.top - b.top) < 0.5 &&
    Math.abs(a.left - b.left) < 0.5 &&
    Math.abs(a.width - b.width) < 0.5 &&
    Math.abs(a.height - b.height) < 0.5
  );
}

function valueIsReady(value: string, positive: boolean | undefined): boolean {
  if (value.trim() === '') return false;
  if (!positive) return true;
  const n = Number(value);
  return Number.isFinite(n) && n > 0;
}

const schedule = (fn: () => void): number =>
  typeof window.requestAnimationFrame === 'function' ? window.requestAnimationFrame(fn) : window.setTimeout(fn, 16);
const unschedule = (id: number): void => {
  if (typeof window.cancelAnimationFrame === 'function') window.cancelAnimationFrame(id);
  window.clearTimeout(id);
};

function play(sound: 'tick' | 'boop' | 'confirm' | 'bleep'): void {
  try {
    AudioManager.unlock();
    AudioManager.play(sound);
  } catch {
    // sound is decoration
  }
}

/** The dialogue sits on the opposite half of the screen from what it points at. */
export function placeDialog(target: Box | null, screen: Box | null): 'top' | 'bottom' | 'middle' {
  if (!target) return 'middle';
  const top = screen ? screen.top : 0;
  const height = screen ? screen.height : window.innerHeight;
  return target.top + target.height / 2 > top + height / 2 ? 'top' : 'bottom';
}

type Props = {
  appState: AppState;
  guideSrc: string;
};

export default function GuidedTour({ appState, guideSrc }: Props): React.JSX.Element | null {
  const tour = useTourStore();
  const navigation = useNavigationStore();
  const step: TourStep | undefined = tour.active ? TOUR_STEPS[tour.index] : undefined;
  const [target, setTarget] = useState<Box | null>(null);
  const [screen, setScreen] = useState<Box | null>(null);
  const [shown, setShown] = useState(0);
  const [celebrating, setCelebrating] = useState(false);
  const armed = useRef(false);
  const lastValue = useRef<{ value: string; since: number } | null>(null);

  const text = step?.body ?? '';
  const typing = shown < text.length;
  const isLast = tour.index === TOUR_STEPS.length - 1;

  // The tour only runs on a ready wallet; locking or an error ends it.
  useEffect(() => {
    if (tour.active && appState !== 'wallet_ready') tourStore.end();
  }, [appState, tour.active]);

  // Open the step's screen.
  useEffect(() => {
    armed.current = false;
    lastValue.current = null;
    if (!step) return;
    if (navigationStore.getSnapshot().currentScreen !== step.screen) navigationStore.navigate(step.screen);
  }, [step]);

  // Highlight the brick a menu step asks for, so pressing A opens it. The app
  // resets the menu index whenever home opens, so this waits a tick.
  useEffect(() => {
    if (!step?.menuItem || navigation.currentScreen !== 'home') return undefined;
    const index = HOME_MENU.indexOf(step.menuItem);
    if (index < 0) return undefined;
    const timer = window.setTimeout(() => navigationStore.setCurrentMenuIndex(index), 0);
    return () => window.clearTimeout(timer);
  }, [step, navigation.currentScreen]);

  // Type the guide's words out, like a game does.
  useEffect(() => {
    if (prefersReducedMotion()) {
      setShown(text.length);
      return undefined;
    }
    setShown(0);
    const timer = window.setInterval(() => {
      setShown((n) => {
        if (n >= text.length) {
          window.clearInterval(timer);
          return n;
        }
        return n + 1;
      });
    }, TYPE_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [text]);

  // Follow the target every frame and watch for hands-on steps being done.
  useEffect(() => {
    if (!step || celebrating) return undefined;
    let frame = 0;
    let lastTarget: Box | null = null;
    let lastScreen: Box | null = null;
    let scrolled = false;
    const loop = (): void => {
      const here = navigationStore.getSnapshot().currentScreen === step.screen;
      if (here) armed.current = true;
      const element = here ? find(step.target) : null;
      if (element && !scrolled) {
        scrolled = true;
        try {
          element.scrollIntoView({ block: 'center', inline: 'nearest' });
        } catch {
          // older WebViews
        }
      }
      const box = element ? toBox(element.getBoundingClientRect(), RING_PAD) : null;
      if (!sameBox(box, lastTarget)) {
        lastTarget = box;
        setTarget(box);
      }
      const host = document.querySelector('.stateboy-screen-host');
      const screenBox = host ? toBox(host.getBoundingClientRect(), 0) : null;
      if (!sameBox(screenBox, lastScreen)) {
        lastScreen = screenBox;
        setScreen(screenBox);
      }
      const wait = step.wait;
      if (wait && armed.current) {
        if (wait.kind === 'screen' && navigationStore.getSnapshot().currentScreen === wait.screen) {
          play('tick');
          tourStore.next();
          return;
        }
        if (wait.kind === 'selector' && here && find(wait.selector)) {
          play('tick');
          tourStore.next();
          return;
        }
        if (wait.kind === 'value' && here) {
          const field = find(wait.selector) as HTMLInputElement | HTMLSelectElement | null;
          const value = field ? field.value : '';
          const now = Date.now();
          if (!lastValue.current || lastValue.current.value !== value) lastValue.current = { value, since: now };
          if (valueIsReady(value, wait.positive) && now - lastValue.current.since >= VALUE_SETTLE_MS) {
            play('tick');
            tourStore.next();
            return;
          }
        }
      }
      frame = schedule(loop);
    };
    frame = schedule(loop);
    return () => unschedule(frame);
  }, [step, celebrating]);

  // Steps that wait for a practice action: let its own animation play, then move on.
  useEffect(() => {
    if (step?.wait?.kind !== 'event') return undefined;
    const expected = step.wait.event;
    let timer = 0;
    const off = practiceMode.onEvent((event) => {
      if (event !== expected) return;
      setCelebrating(true);
      timer = window.setTimeout(() => {
        setCelebrating(false);
        tourStore.next();
      }, CELEBRATE_MS);
    });
    return () => {
      off();
      window.clearTimeout(timer);
      setCelebrating(false);
    };
  }, [step]);

  const advance = useCallback((): void => {
    if (!step) return;
    if (typing) {
      setShown(text.length);
      return;
    }
    if (step.wait) return;
    if (isLast) {
      play('confirm');
      tourStore.end();
      return;
    }
    play('tick');
    tourStore.next();
  }, [isLast, step, text.length, typing]);

  const back = useCallback((): void => {
    play('boop');
    tourStore.back();
  }, []);

  // The tour owns the hardware buttons and keys while it runs. On a menu step,
  // A and Enter still reach the app so they open the highlighted brick.
  useEffect(() => {
    if (!step) return undefined;
    const typingInField = (): boolean => {
      const el = document.activeElement;
      return !!el && (el.tagName === 'INPUT' || el.tagName === 'SELECT' || el.tagName === 'TEXTAREA');
    };
    const onKey = (event: KeyboardEvent): void => {
      if (typingInField() && event.key !== 'Escape') return;
      const passToMenu = Boolean(step.menuItem) && (event.key === 'Enter' || event.key === ' ');
      if (passToMenu) return;
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        event.stopImmediatePropagation();
        advance();
      } else if (event.key === 'Escape') {
        event.preventDefault();
        event.stopImmediatePropagation();
        back();
      } else if (event.key.startsWith('Arrow') || event.key === 'Tab' || event.key === 'Shift') {
        event.preventDefault();
        event.stopImmediatePropagation();
      }
    };
    const onClick = (event: MouseEvent): void => {
      const origin = event.target as Element | null;
      if (step.backOn && origin?.closest?.(step.backOn)) {
        window.setTimeout(back, 0);
        return;
      }
      const button = origin?.closest?.(HARDWARE);
      if (!button) return;
      if (button.id === 'button-a' && step.menuItem) return;
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();
      if (button.id === 'button-a') advance();
      else if (button.id === 'button-b') back();
    };
    window.addEventListener('keydown', onKey, true);
    window.addEventListener('click', onClick, true);
    return () => {
      window.removeEventListener('keydown', onKey, true);
      window.removeEventListener('click', onClick, true);
    };
  }, [advance, back, step]);

  if (!step || celebrating || typeof document === 'undefined') return null;

  const handsOn = Boolean(step.wait);
  const placement = placeDialog(target, screen);
  const frame = screen ?? { top: 0, left: 0, width: window.innerWidth, height: window.innerHeight };
  const dialogStyle: React.CSSProperties = { left: frame.left + 8, width: Math.max(frame.width - 16, 200) };
  if (placement === 'top') dialogStyle.top = frame.top + 8;
  else if (placement === 'bottom') dialogStyle.bottom = Math.max(window.innerHeight - (frame.top + frame.height) + 8, 8);
  else dialogStyle.top = frame.top + frame.height / 2;

  let arrowStyle: React.CSSProperties | null = null;
  let arrowDown = true;
  if (target) {
    // The arrow sits between the dialogue and the thing it points at.
    const roomAbove = target.top - 22 > 0;
    const roomBelow = target.top + target.height + 28 < window.innerHeight;
    arrowDown = placement === 'bottom' ? !roomBelow && roomAbove : roomAbove || !roomBelow;
    const left = target.left + target.width / 2 - 9;
    arrowStyle = arrowDown ? { left, top: target.top - 22 } : { left, top: target.top + target.height + 6 };
  }

  return createPortal(
    <div className="gt-root" data-testid="guided-tour">
      {target ? (
        <>
          <div className="gt-shade" style={{ top: 0, left: 0, right: 0, height: Math.max(target.top, 0) }} />
          <div className="gt-shade" style={{ top: target.top + target.height, left: 0, right: 0, bottom: 0 }} />
          <div className="gt-shade" style={{ top: target.top, left: 0, width: Math.max(target.left, 0), height: target.height }} />
          <div className="gt-shade" style={{ top: target.top, left: target.left + target.width, right: 0, height: target.height }} />
          {handsOn ? null : <div className="gt-guard" style={target} />}
          <div className={`gt-ring${handsOn ? ' gt-ring--live' : ''}`} style={target} aria-hidden="true" />
          {arrowStyle ? <div className={`gt-arrow ${arrowDown ? 'gt-arrow--down' : 'gt-arrow--up'}`} style={arrowStyle} aria-hidden="true" /> : null}
        </>
      ) : (
        <div className="gt-shade gt-shade--full" />
      )}
      <div
        className={`gt-dialog gt-dialog--${placement}`}
        style={dialogStyle}
        role="dialog"
        aria-labelledby="gt-title"
        aria-describedby="gt-body"
        onClick={advance}
      >
        <div className="gt-dialog__top">
          <span className="gt-badge">PRACTICE</span>
          <span className="gt-count">
            {tour.index + 1}/{TOUR_STEPS.length}
          </span>
        </div>
        <div className="gt-dialog__main">
          <img className="gt-guide" src={guideSrc} alt="" aria-hidden="true" />
          <div className="gt-copy">
            <div id="gt-title" className="gt-title">{step.title}</div>
            <p className="gt-body" aria-hidden="true">
              {text.slice(0, shown)}
              {typing ? <span className="gt-caret">▌</span> : null}
            </p>
            <p id="gt-body" className="gt-sr">{text}</p>
          </div>
        </div>
        <div className="gt-controls">
          <button
            type="button"
            className="gt-btn gt-btn--ghost"
            onClick={(event) => {
              event.stopPropagation();
              play('boop');
              tourStore.end();
            }}
          >
            Skip
          </button>
          <button
            type="button"
            className="gt-btn"
            disabled={tour.index === 0}
            onClick={(event) => {
              event.stopPropagation();
              back();
            }}
          >
            Back
          </button>
          {handsOn ? (
            <span className="gt-todo" role="status">{step.prompt ?? 'Your turn'}</span>
          ) : (
            <button
              type="button"
              className="gt-btn gt-btn--primary"
              onClick={(event) => {
                event.stopPropagation();
                advance();
              }}
            >
              {isLast ? 'Finish' : 'Next'}
            </button>
          )}
        </div>
      </div>
    </div>,
    document.body,
  );
}
