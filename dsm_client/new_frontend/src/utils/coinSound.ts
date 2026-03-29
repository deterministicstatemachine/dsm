/**
 * Global coin sound player — plays the retro coin.mp3 whenever the user
 * receives tokens (BLE bilateral or online inbox).
 *
 * Uses a shared HTMLAudioElement so multiple rapid calls don't stack.
 * Restart-from-zero on rapid replay (Game Boy style).
 *
 * Respects the global soundEnabled flag from appRuntimeStore — when the
 * user mutes via Start button on the home screen, this stays silent too.
 */

import { appRuntimeStore } from '@/runtime/appRuntimeStore';

let audio: HTMLAudioElement | null = null;

function getAudio(): HTMLAudioElement {
  if (!audio) {
    audio = new Audio('sounds/coin.mp3');
    audio.volume = 0.7;
  }
  return audio;
}

/** Play the coin sound. Respects global mute. Safe to call rapidly. */
export function playCoinSound(): void {
  try {
    if (!appRuntimeStore.getSnapshot().soundEnabled) return;
    const a = getAudio();
    a.currentTime = 0;
    a.play().catch(() => {
      // Autoplay blocked by browser policy — silent fail.
      // On Android WebView this is generally allowed after first user gesture.
    });
  } catch {
    // Audio not available (e.g. SSR, test env) — ignore.
  }
}
