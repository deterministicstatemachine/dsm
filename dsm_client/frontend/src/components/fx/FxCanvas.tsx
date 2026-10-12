// SPDX-License-Identifier: Apache-2.0
import React, { useEffect, useLayoutEffect, useRef } from 'react';
import { loadFxEngine, type FxAnim } from './fxEngine';

export interface FxCanvasProps {
  anim: FxAnim;
  /** Bump to replay the scene from frame 0. */
  seq?: number;
  fps?: number;
  muted?: boolean;
  /** `fill` stretches to the host width (edge to edge); `integer` keeps whole CSS pixels. */
  fit?: 'fill' | 'integer';
  /** Amount caption for the confirm/fail scenes, e.g. "+12.5 ERA". */
  amount?: string;
  className?: string;
  /** Fires once when the scene's last frame has been drawn. */
  onEnd?: () => void;
}

/**
 * Thin React wrapper around the `<fx-canvas>` web component. The engine script
 * is loaded on first use; the element upgrades in place when it lands.
 *
 * The engine is configured through attributes set imperatively, never through
 * JSX props: React 19 writes a prop onto a custom element as a *property* when
 * one by that name exists, which would shadow the engine's own methods (`fps`
 * is both an attribute and a method on the element).
 */
export function FxCanvas({ anim, seq = 0, fps = 10, muted = false, fit = 'fill', amount, className, onEnd }: FxCanvasProps) {
  const ref = useRef<HTMLElement>(null);
  const onEndRef = useRef(onEnd);
  onEndRef.current = onEnd;

  useEffect(() => {
    void loadFxEngine();
  }, []);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const handler = () => onEndRef.current?.();
    el.addEventListener('fx-end', handler);
    return () => el.removeEventListener('fx-end', handler);
  }, []);

  // Before paint, so the element starts on the scene we asked for rather than
  // on the engine's default. `amount` is set ahead of `anim`: the scene reads
  // it while drawing, and `anim`/`seq` are what start or restart it.
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (amount === undefined) el.removeAttribute('amount');
    else el.setAttribute('amount', amount);
    el.setAttribute('fps', String(fps));
    el.setAttribute('muted', muted ? '1' : '0');
    el.setAttribute('fit', fit);
    el.setAttribute('anim', anim);
    el.setAttribute('seq', String(seq));
  }, [anim, seq, fps, muted, fit, amount]);

  return <fx-canvas ref={ref} class={className} data-anim={anim} />;
}

export default FxCanvas;
