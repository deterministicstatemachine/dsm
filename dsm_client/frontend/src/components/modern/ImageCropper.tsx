// SPDX-License-Identifier: Apache-2.0
// Framing a chosen picture before it is kept: the picture under a frame of
// the shape it is shown in (a circle for the photo, a 3:1 band for the
// banner). Drag to move it; pinch, the slider, or a mouse wheel to zoom in
// and out. The picture always covers the frame. Save cuts out what the frame
// shows at the size the picture is kept at.

import React, { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { cropRegion } from '../../utils/imageCrop';

/** How far in the slider and a pinch can zoom, from the picture just covering the frame. */
const MAX_ZOOM = 5;

type Props = {
  image: HTMLImageElement;
  shape: 'circle' | 'banner';
  /** The size the cut-out is kept at. */
  width: number;
  height: number;
  onSave: (picture: string) => void;
  onCancel: () => void;
};

/** Where the picture sits under the frame: its zoom, and its top-left corner in frame pixels. */
type View = { zoom: number; x: number; y: number };

type Frame = { w: number; h: number };

/** The picture's scale at `zoom`: 1 is the smallest scale that still covers the frame. */
function scaleAt(image: HTMLImageElement, frame: Frame, zoom: number): number {
  return Math.max(frame.w / image.naturalWidth, frame.h / image.naturalHeight) * zoom;
}

/** The view moved back so the picture covers the whole frame. */
function covered(image: HTMLImageElement, frame: Frame, view: View): View {
  const zoom = Math.min(MAX_ZOOM, Math.max(1, view.zoom));
  const scale = scaleAt(image, frame, zoom);
  const minX = frame.w - image.naturalWidth * scale;
  const minY = frame.h - image.naturalHeight * scale;
  return { zoom, x: Math.min(0, Math.max(minX, view.x)), y: Math.min(0, Math.max(minY, view.y)) };
}

/** The view zoomed to `zoom`, keeping the picture's point under (px, py) where it is. */
function zoomedAbout(image: HTMLImageElement, frame: Frame, view: View, zoom: number, px: number, py: number): View {
  const before = scaleAt(image, frame, view.zoom);
  const after = scaleAt(image, frame, Math.min(MAX_ZOOM, Math.max(1, zoom)));
  const ix = (px - view.x) / before;
  const iy = (py - view.y) / before;
  return covered(image, frame, { zoom, x: px - ix * after, y: py - iy * after });
}

export default function ImageCropper({ image, shape, width, height, onSave, onCancel }: Props): React.JSX.Element {
  const frameRef = useRef<HTMLDivElement>(null);
  const [frame, setFrame] = useState<Frame | null>(null);
  const [view, setView] = useState<View>({ zoom: 1, x: 0, y: 0 });
  const pointers = useRef(new Map<number, { x: number; y: number }>());
  const [problem, setProblem] = useState<string | null>(null);

  // The frame's size on screen; the picture starts centred, just covering it.
  useLayoutEffect(() => {
    const measure = () => {
      const el = frameRef.current;
      if (el === null) return;
      const next = { w: el.clientWidth, h: el.clientHeight };
      setFrame(next);
      const scale = scaleAt(image, next, 1);
      setView(covered(image, next, {
        zoom: 1,
        x: (next.w - image.naturalWidth * scale) / 2,
        y: (next.h - image.naturalHeight * scale) / 2,
      }));
    };
    measure();
    window.addEventListener('resize', measure);
    return () => window.removeEventListener('resize', measure);
  }, [image]);

  const local = useCallback((clientX: number, clientY: number) => {
    const rect = frameRef.current?.getBoundingClientRect();
    return rect ? { x: clientX - rect.left, y: clientY - rect.top } : { x: clientX, y: clientY };
  }, []);

  const onPointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
    e.currentTarget.setPointerCapture(e.pointerId);
    pointers.current.set(e.pointerId, local(e.clientX, e.clientY));
  };

  const onPointerMove = (e: React.PointerEvent<HTMLDivElement>) => {
    const was = pointers.current.get(e.pointerId);
    if (was === undefined || frame === null) return;
    const now = local(e.clientX, e.clientY);
    const others = [...pointers.current.entries()].filter(([id]) => id !== e.pointerId).map(([, p]) => p);
    if (others.length === 0) {
      // One finger: move the picture.
      setView((v) => covered(image, frame, { ...v, x: v.x + now.x - was.x, y: v.y + now.y - was.y }));
    } else {
      // Two fingers: zoom by how far apart they are, about the point between them, and move with it.
      const other = others[0];
      const apartBefore = Math.hypot(was.x - other.x, was.y - other.y);
      const apartNow = Math.hypot(now.x - other.x, now.y - other.y);
      const midBefore = { x: (was.x + other.x) / 2, y: (was.y + other.y) / 2 };
      const midNow = { x: (now.x + other.x) / 2, y: (now.y + other.y) / 2 };
      setView((v) => {
        const zoomed = apartBefore > 0 ? zoomedAbout(image, frame, v, v.zoom * (apartNow / apartBefore), midBefore.x, midBefore.y) : v;
        return covered(image, frame, { ...zoomed, x: zoomed.x + midNow.x - midBefore.x, y: zoomed.y + midNow.y - midBefore.y });
      });
    }
    pointers.current.set(e.pointerId, now);
  };

  const onPointerUp = (e: React.PointerEvent<HTMLDivElement>) => {
    pointers.current.delete(e.pointerId);
  };

  // A mouse wheel zooms about the pointer.
  useEffect(() => {
    const el = frameRef.current;
    if (el === null || frame === null) return undefined;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const at = local(e.clientX, e.clientY);
      setView((v) => zoomedAbout(image, frame, v, v.zoom * Math.exp(-e.deltaY / 400), at.x, at.y));
    };
    // On an element (not the window) a wheel listener is not passive by default, so it can keep the page still.
    el.addEventListener('wheel', onWheel);
    return () => el.removeEventListener('wheel', onWheel);
  }, [frame, image, local]);

  const save = () => {
    if (frame === null) return;
    const scale = scaleAt(image, frame, view.zoom);
    try {
      onSave(cropRegion(image, { sx: -view.x / scale, sy: -view.y / scale, sw: frame.w / scale, sh: frame.h / scale }, width, height));
    } catch (e: unknown) {
      setProblem(e instanceof Error ? e.message : String(e));
    }
  };

  const scale = frame !== null ? scaleAt(image, frame, view.zoom) : 0;

  return createPortal(
    <div className="s-crop" role="dialog" aria-label={shape === 'circle' ? 'Frame your photo' : 'Frame your banner'}>
      <h2 className="s-crop-title">{shape === 'circle' ? 'Frame your photo' : 'Frame your banner'}</h2>
      <p className="s-hint" style={{ textAlign: 'center' }}>Drag to move it. Pinch or use the slider to zoom.</p>
      <div
        ref={frameRef}
        className={`s-crop-frame s-crop-${shape}`}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerUp}
      >
        {frame !== null ? (
          <img
            src={image.src}
            alt=""
            onDragStart={(e) => e.preventDefault()}
            style={{ left: view.x, top: view.y, width: image.naturalWidth * scale, height: image.naturalHeight * scale }}
          />
        ) : null}
        {shape === 'circle' ? <span className="s-crop-ring" aria-hidden /> : null}
      </div>
      <label className="s-crop-zoom">
        <span>Zoom</span>
        <input
          type="range"
          min={1}
          max={MAX_ZOOM}
          step={0.01}
          value={view.zoom}
          aria-label="Zoom"
          onChange={(e) => {
            if (frame === null) return;
            const zoom = Number(e.target.value);
            setView((v) => zoomedAbout(image, frame, v, zoom, frame.w / 2, frame.h / 2));
          }}
        />
      </label>
      {problem !== null ? <div className="s-notice s-error">{problem}</div> : null}
      <div className="s-actions">
        <button type="button" className="s-btn s-btn-quiet" onClick={onCancel}>Cancel</button>
        <button type="button" className="s-btn s-btn-primary" onClick={save}>Save</button>
      </div>
    </div>,
    document.body,
  );
}
