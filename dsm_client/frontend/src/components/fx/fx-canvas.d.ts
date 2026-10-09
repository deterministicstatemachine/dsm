// SPDX-License-Identifier: Apache-2.0
// JSX typing for the StateBoy FX web component
// (public/images/animations/animations/fx-canvas.js).
//
// Only `ref`, `class` and data attributes are declared: every engine attribute
// (anim, seq, fps, muted, fit, amount) is set imperatively, because React 19
// writes a JSX prop onto a custom element as a property when the element has
// one by that name, which shadows the engine's methods.
import 'react';

declare module 'react' {
  namespace JSX {
    interface IntrinsicElements {
      'fx-canvas': {
        ref?: React.Ref<HTMLElement>;
        class?: string;
        key?: React.Key;
        'data-anim'?: string;
      };
    }
  }
}
