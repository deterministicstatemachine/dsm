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
let lastPlayAttemptAt = 0;

const COIN_SOUND_URL = 'sounds/coin.mp3';
const COIN_SOUND_MIN_INTERVAL_MS = 900;

function createAudio(): HTMLAudioElement {
  const nextAudio = new Audio(COIN_SOUND_URL);
  nextAudio.volume = 0.7;
  nextAudio.preload = 'auto';
  nextAudio.setAttribute('playsinline', 'true');
  nextAudio.load();
  return nextAudio;
}

function getAudio(): HTMLAudioElement {
  if (!audio) {
    audio = createAudio();
  }
  return audio;
}

function resetAudio(): HTMLAudioElement {
  try {
    audio?.pause();
  } catch {
    // Ignore stale audio state.
  }
  audio = createAudio();
  return audio;
}

function playWithRetry(target: HTMLAudioElement, attempt: number): void {
  try {
    target.pause();
    target.currentTime = 0;
    const playPromise = target.play();
    if (playPromise && typeof playPromise.catch === 'function') {
      playPromise.catch((error) => {
        if (attempt === 0) {
          const retriedAudio = resetAudio();
          setTimeout(() => {
            playWithRetry(retriedAudio, 1);
          }, 60);
          return;
        }
        console.warn('[coinSound] play() rejected:', error);
      });
    }
  } catch (error) {
    if (attempt === 0) {
      const retriedAudio = resetAudio();
      setTimeout(() => {
        playWithRetry(retriedAudio, 1);
      }, 60);
      return;
    }
    console.warn('[coinSound] playback failed:', error);
  }
}

/** Play the coin sound. Respects global mute. Safe to call rapidly. */
export function playCoinSound(): void {
  try {
    const snapshot = appRuntimeStore.getSnapshot();
    if (!snapshot.soundEnabled) {
      console.log('[coinSound] muted — skipping');
      return;
    }
    const now = Date.now();
    if ((now - lastPlayAttemptAt) < COIN_SOUND_MIN_INTERVAL_MS) {
      return;
    }
    lastPlayAttemptAt = now;
    console.log('[coinSound] playing coin.mp3');
    const nextAudio = getAudio();
    playWithRetry(nextAudio, 0);
  } catch {
    // Audio not available (e.g. SSR, test env) — ignore.
  }
}
