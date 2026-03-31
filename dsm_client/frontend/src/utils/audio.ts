/* eslint-disable security/detect-object-injection */
/* eslint-disable @typescript-eslint/no-explicit-any */
// Audio Manager supporting file-based SFX with graceful WebAudio synth path

export type SfxKey =
  | 'bleep' | 'boop' | 'tick' | 'confirm' | 'deny'
  | 'dpad-up' | 'dpad-down' | 'dpad-left' | 'dpad-right'
  | 'button-a' | 'button-b' | 'start' | 'select';

// Filename mapping (filenames tell the mapping). Place files in ./sounds relative to index.html
// Prefer .mp3 or .ogg on Android WebView; wav also supported but larger.
export const SFX_FILE_MAP: Partial<Record<SfxKey, string>> = {
  'dpad-up': 'dpad_up.mp3',
  'dpad-down': 'dpad_down.mp3',
  'dpad-left': 'dpad_left.mp3',
  'dpad-right': 'dpad_right.mp3',
  'button-a': 'button_a.mp3',
  'button-b': 'button_b.mp3',
  'start': 'start.mp3',
  'select': 'select.mp3',
  'confirm': 'confirm.mp3',
  'deny': 'deny.mp3',
  // Logical cues (kept for existing calls)
  'bleep': 'bleep.mp3',
  'boop': 'boop.mp3',
  'tick': 'tick.mp3',
};

// Runtime candidates to match existing filenames in the repo. We try these in order until one fetches.
// Filenames tell the mapping; we include both snake_case and hyphenated variants plus generic SFX candidates.
const SFX_FILE_CANDIDATES: Partial<Record<SfxKey, string[]>> = {
  'dpad-up': ['up-dpad.mp3', 'dpad_up.mp3'],
  'dpad-down': ['down-dpad.mp3', 'dpad_down.mp3'],
  'dpad-left': ['left-dpad.mp3', 'dpad_left.mp3'],
  'dpad-right': ['right-dpad.mp3', 'dpad_right.mp3'],
  'button-a': ['a-button.mp3', 'button_a.mp3'],
  'button-b': ['b-button.mp3', 'button_b.mp3'],
  // For these cues we intentionally avoid a shared file candidate to keep sounds distinct.
  // Let the synth path produce unique tones until dedicated files are added.
  'start': [],
  'select': [],
  'confirm': [],
  'deny': [],
  'bleep': [],
  'boop': [],
  'tick': [],
};

class AudioManagerImpl {
  private ctx: AudioContext | null = null;
  private _enabled = true;
  private unlocked = false;
  private decoded: Map<SfxKey, AudioBuffer> = new Map();
  private triedFetch: Set<SfxKey> = new Set();
  private resolvedFile: Map<SfxKey, string> = new Map();

  get enabled() { return this._enabled; }
  set enabled(v: boolean) { this._enabled = v; }

  /** Must be called from a user gesture to comply with autoplay policies. Also triggers lazy preload. */
  unlock() {
    if (!this.ctx) {
      try {
        this.ctx = new (window.AudioContext || (window as any).webkitAudioContext)();
      } catch {}
    }
    if (this.ctx?.state === 'suspended') {
      void this.ctx.resume();
    }
    if (!this.unlocked) {
      this.unlocked = true;
      // Kick off lazy preload of known SFX; non-blocking
      this.preload(Object.keys(SFX_FILE_MAP) as SfxKey[]).catch(() => {});
    }
  }

  /** Explicit preload for a set of keys. Will skip already-decoded entries. */
  async preload(keys: SfxKey[]) {
    if (!this.ctx) return; // create on unlock
    const ctx = this.ctx;
    await Promise.all(keys.map(async (k) => {
      if (this.decoded.has(k) || this.triedFetch.has(k)) return;
      const candidates = (SFX_FILE_CANDIDATES[k] ?? [SFX_FILE_MAP[k]!]).filter(Boolean) as string[];
      for (const file of candidates) {
        try {
          const url = new URL(`./sounds/${file}`, window.location.href).toString();
          const res = await fetch(url);
          if (!res.ok) continue;
          const buf = await res.arrayBuffer();
          const audioBuf = await ctx.decodeAudioData(buf.slice(0));
          this.decoded.set(k, audioBuf);
          this.resolvedFile.set(k, file);
          return;
        } catch {
          // try next candidate
        }
      }
      // Mark as tried to avoid refetch storms; route to synth path
      this.triedFetch.add(k as SfxKey);
    }));
  }

  play(key: SfxKey = 'bleep') {
    if (!this._enabled) return;
    if (!this.ctx) {
      try { this.ctx = new (window.AudioContext || (window as any).webkitAudioContext)(); }
      catch { /* no audio available */ }
    }
    const ctx = this.ctx;
    if (!ctx) return;

    // If we have a decoded file, play it. Otherwise use the synth path.
    const decoded = this.decoded.get(key);
    if (decoded) {
      try {
        const src = ctx.createBufferSource();
        src.buffer = decoded;
        const gain = ctx.createGain();
        gain.gain.value = 0.6; // gentle gain to avoid clipping
        src.connect(gain);
        gain.connect(ctx.destination);
        src.start();
        return;
      } catch {
        // fall through to synth
      }
    } else if (!this.triedFetch.has(key)) {
      // Opportunistic lazy fetch using candidates
      void this.preload([key]);
    }

    // --- Synth path (retro tones) ---
    const now = ctx.currentTime;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);

    const dur = 0.08; // short retro clicky
    const startGain = 0.15;
    gain.gain.setValueAtTime(0, now);
    gain.gain.linearRampToValueAtTime(startGain, now + 0.002);
    gain.gain.exponentialRampToValueAtTime(0.0001, now + dur);

    switch (key) {
      case 'bleep':
      case 'button-a':
        osc.type = 'square';
        osc.frequency.setValueAtTime(880, now);
        osc.frequency.exponentialRampToValueAtTime(660, now + dur);
        break;
      case 'boop':
      case 'button-b':
        osc.type = 'square';
        osc.frequency.setValueAtTime(330, now);
        osc.frequency.exponentialRampToValueAtTime(220, now + dur);
        break;
      case 'tick':
      case 'dpad-up':
      case 'dpad-down':
      case 'dpad-left':
      case 'dpad-right':
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(1200, now);
        break;
      case 'confirm':
      case 'start':
        osc.type = 'square';
        osc.frequency.setValueAtTime(523.25, now);
        osc.frequency.exponentialRampToValueAtTime(659.25, now + dur);
        break;
      case 'deny':
      case 'select':
        osc.type = 'square';
        osc.frequency.setValueAtTime(196, now);
        break;
      default:
        osc.type = 'square';
        osc.frequency.setValueAtTime(440, now);
        break;
    }

    osc.start(now);
    osc.stop(now + dur);
  }
}

export const AudioManager = new AudioManagerImpl();
