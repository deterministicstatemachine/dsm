/* StateBoy FX engine v3 — live-realm web component.
   Logical width fixed at 160px; logical HEIGHT adapts to the host element
   (144 minimum, up to 288) so elongated phone screens are filled edge-to-edge
   with zero distortion: art band stays centered, dialog box pins to the
   bottom, pixels always integer-scaled.
   Attributes: anim, seq (bump to replay), fps, muted ("1"/"0").
   window.StateBoyFX = { play(name), list(), mute(bool) }.
   window.STATEBOY_MUTED === true silences all SFX. */
(function () {
  if (customElements.get('fx-canvas')) return;

  // 3x5 pixel font for digits & symbols
  const TINY = {
    '0': ['111', '101', '101', '101', '111'],
    '1': ['010', '110', '010', '010', '111'],
    '2': ['111', '001', '111', '100', '111'],
    '3': ['111', '001', '111', '001', '111'],
    '4': ['101', '101', '111', '001', '001'],
    '5': ['111', '100', '111', '001', '111'],
    '6': ['111', '100', '111', '101', '111'],
    '7': ['111', '001', '001', '010', '010'],
    '8': ['111', '101', '111', '101', '111'],
    '9': ['111', '101', '111', '001', '111'],
    '.': ['000', '000', '000', '000', '010'],
    '+': ['000', '010', '111', '010', '000'],
    '?': ['111', '001', '010', '000', '010'],
    '!': ['010', '010', '010', '000', '010']
  };

  const SPR = {
    sci: [
      ".................................33.....................",
      "................................3303....................",
      "..................................3033..................",
      "...............333333.......333...30033.................",
      "..............33303333.....3030....33033................",
      "......33.....300000003333...3300333030033...............",
      "......33......3330000000033...33003330003...............",
      "......30.........3300000000333033003330003..............",
      "......3303.........300000000033330003300003..3..........",
      "......30003....3...3330000030003330003300003.33.........",
      "........003....330000033000003003300033000033333...3....",
      "........000033...3300000000000000000003000030303...33...",
      "........0000033.33333000000000000030000000003303...03...",
      ".......3000000....3033000300000000300000000033033.303...",
      "........300000000000000003300003303000000000030033..3...",
      "........3300030000000000003000033030000000000300330.....",
      "....3....300000330000003330000003000000000000300330.....",
      "....03....30000033300000033000000300300000000300330.....",
      "...3003....3000000003333033330000300000030000000300033..",
      "...3300333..3000000000330000330003303000303030000003303.",
      "...3300030330333000000033300333003033300003030033003303.",
      "...3330000003333030003300330033033030303303330030003303.",
      "...303000000000000000003003303333333330300333003003303..",
      "...300330000000000333330030300333003333030330033033003..",
      "....30000300000000003303303333330000000333300330330033..",
      "....33000000003333000303300000003300000003333330300033..",
      ".....30000000000033330300000333300300000033000330030333.",
      "..333333000000000003333030030330300300033300000033030303",
      "..303333300003000003330300300033030030030003333003303303",
      "...3003333000003333330030300000330303330303003033033303.",
      "...3300000000000333330300300000330330330000000300300333.",
      "....30000000030300333030033300333303033003000033030333..",
      "....3330003000003333303303333300033303330033333333033...",
      "...30333300333330333303303000000033303030300000033033...",
      "...330000000033330003333003000000330000333000000330333..",
      "....3300000033303000003330300000303033333030000303003...",
      "......3303333333033300030303300303003033300300333033....",
      ".......3330033030003300030300333300300333300033303......",
      "..........330033003033000033000003300000333300003.......",
      "...........333..30003300000333330000000000333333........",
      ".................3000000000000000033330000003...........",
      "..................333330000000000300030000003......33...",
      "............3....3330333000000000300030000003.....3003..",
      "..3333....3303333300333333000000303330000033...30300003.",
      "..300033330000000000030303300000033300000......003333303",
      "..333000330300030000000333333000000000333.....3003000003",
      "..300000000030003030000330303333003033330333333003000003",
      "33003000000030003303003300033033033333300030003003300033",
      ".3333333000030303.3330030000300033030030030003033300003.",
      ".33303.3300030333.3330003300330303030333000003033333003.",
      "..3003.330003333..3300003000033333300300000003030300003.",
      "...33..30003......330003300003330330030000000303003003..",
      ".......3033.......33000003000033030000333333003033333...",
      "........33........300000003300333000333...333333300.....",
      "................33300000300030033003303.........33......",
      "...............300000000033003033030003.................",
      "......333333333000003330000000303300003.................",
      "...33300000000000000000033300000300000033...............",
      ".33000000000000000000000000333000300000033..............",
      ".333....00000000000000000000030.000000000033............",
      "..........333000000000000333003.3033000000003...........",
      "..............3330000000000003...3000000000003..........",
      "............3303033300000000......3000000033333.........",
      "............3030333033000003333...3300033333333.........",
      "...........300333333...3333.30033..333.300000033........",
      "..........33033003003.......33333.......300000003.......",
      ".........33333000003....................3000333333......",
      "........33003033003.....................30330030303.....",
      ".......33333333333......................333333333333....",
      ".......3333333333........................33333333333....",
      ".........3333333............................3.3333......"
    ],
    star: ['..3..', '.333.', '33333', '.333.', '..3..'],
    twinkle: ['.3.', '333', '.3.'],
    skull: ['.0000000.', '000000000', '003303300', '000030000', '.0000000.', '.0.0.0.0.'],
    packet: ['33333333', '33000033', '30300303', '30033003', '30000003', '33333333'],
    note: ['...33', '...3.', '...3.', '...3.', '.333.', '3333.', '.33..'],
    dust: ['.2.2.', '2.2.2', '.2.2.'],
    bt: [
      '....3....',
      '....33...',
      '....3.3..',
      '3...3..3.',
      '.3..3.3..',
      '..3.33...',
      '...33....',
      '...33....',
      '..3.33...',
      '.3..3.3..',
      '3...3..3.',
      '....3.3..',
      '....33...',
      '....3....'
    ],
    lock: [
      '...3333333...',
      '..333333333..',
      '..33.....33..',
      '..33.....33..',
      '..33.....33..',
      '3333333333333',
      '3000000000003',
      '3111111111113',
      '3111133311113',
      '3111133311113',
      '3111113111113',
      '3111113111113',
      '3111111111113',
      '3222222222223',
      '.33333333333.'
    ],
    fragA: ['.333333.', '31111113', '31111213', '31121113', '31111123', '31211113', '31111113', '.333333.'],
    fragB: ['..3333..', '.311113.', '31111113', '31112113', '31121113', '31111113', '.311113.', '..3333..']
  };

  class FxCanvas extends HTMLElement {
    static get observedAttributes() { return ['anim', 'seq', 'fps', 'muted']; }

    connectedCallback() {
      if (!this._cv) {
        this._cv = document.createElement('canvas');
        this._cv.width = 160; this._cv.height = 144;
        this._cv.style.display = 'block';
        this._cv.style.imageRendering = 'pixelated';
        this._cv.style.background = '#9bbc0f';
        this._cv.style.margin = '0 auto';
        this.appendChild(this._cv);
      }
      this.style.display = 'block';
      this.style.height = '100%';
      this._connected = true;
      try {
        this._ro = new ResizeObserver(() => this.fitScale());
        this._ro.observe(this);
      } catch (e) {}
      this.fitScale();
      if (!this._sciImgStarted) {
        this._sciImgStarted = true;
        const im = new Image();
        im.onload = () => {
          try {
            const oc = document.createElement('canvas');
            oc.width = im.width; oc.height = im.height;
            const octx = oc.getContext('2d');
            octx.drawImage(im, 0, 0);
            const d = octx.getImageData(0, 0, oc.width, oc.height);
            const px = d.data, Wd = oc.width, Hd = oc.height;
            const mark = new Uint8Array(Wd * Hd);
            const isBgAt = (p) => {
              const i = p * 4;
              return px[i + 3] < 128 || (px[i] > 195 && px[i + 1] > 195 && px[i + 2] > 195);
            };
            const st = [];
            for (let y = 0; y < Hd; y++) for (let x = 0; x < Wd; x++) {
              if (x < 6 || y < 6 || x >= Wd - 6 || y >= Hd - 6) { const p = y * Wd + x; if (!mark[p]) { mark[p] = 1; st.push(p); } }
            }
            while (st.length) {
              const p = st.pop();
              const x = p % Wd, y = (p / Wd) | 0;
              [[1, 0], [-1, 0], [0, 1], [0, -1]].forEach(([ddx, ddy]) => {
                const nx = x + ddx, ny = y + ddy;
                if (nx < 0 || nx >= Wd || ny < 0 || ny >= Hd) return;
                const np = ny * Wd + nx;
                if (!mark[np] && isBgAt(np)) { mark[np] = 1; st.push(np); }
              });
            }
            for (let p = 0; p < Wd * Hd; p++) if (mark[p]) px[p * 4 + 3] = 0;
            // keep only the largest connected piece (drop stray artifacts)
            const lab = new Int32Array(Wd * Hd).fill(-1);
            const comps = [];
            for (let p0 = 0; p0 < Wd * Hd; p0++) {
              if (lab[p0] >= 0 || px[p0 * 4 + 3] < 128) continue;
              const id = comps.length;
              const comp = { n: 0, mnX: 1e9, mxX: -1, mnY: 1e9, mxY: -1, id };
              const s2 = [p0]; lab[p0] = id;
              while (s2.length) {
                const p = s2.pop();
                const x = p % Wd, y = (p / Wd) | 0;
                comp.n++;
                if (x < comp.mnX) comp.mnX = x; if (x > comp.mxX) comp.mxX = x;
                if (y < comp.mnY) comp.mnY = y; if (y > comp.mxY) comp.mxY = y;
                [[1, 0], [-1, 0], [0, 1], [0, -1], [1, 1], [1, -1], [-1, 1], [-1, -1]].forEach(([ddx, ddy]) => {
                  const nx = x + ddx, ny = y + ddy;
                  if (nx < 0 || nx >= Wd || ny < 0 || ny >= Hd) return;
                  const np = ny * Wd + nx;
                  if (lab[np] < 0 && px[np * 4 + 3] >= 128) { lab[np] = id; s2.push(np); }
                });
              }
              comps.push(comp);
            }
            comps.sort((a, b) => b.n - a.n);
            const main = comps[0];
            for (let p = 0; p < Wd * Hd; p++) {
              if (px[p * 4 + 3] >= 128 && lab[p] !== main.id) px[p * 4 + 3] = 0;
            }
            const mnX = main.mnX, mxX = main.mxX, mnY = main.mnY, mxY = main.mxY;
            octx.putImageData(d, 0, 0);
            if (mxX > mnX && mxY > mnY) this._sciImg = { cv: oc, x: mnX, y: mnY, w: mxX - mnX + 1, h: mxY - mnY + 1 };
          } catch (e) {}
        };
        im.src = 'sci-guy.png';
      }
      window.StateBoyFX = {
        play: (n, o) => { if (o && o.amount != null) this.setAttribute('amount', String(o.amount)); this.play(n); },
        list: () => Object.keys(this.ANIMS()),
        mute: (v) => { this._muteOverride = !!v; }
      };
      this.readPalette();
      const start = () => { if (this._connected) this.play(this.getAttribute('anim') || 'intro'); };
      try {
        if (document.fonts && document.fonts.load) {
          Promise.race([document.fonts.load('8px "Press Start 2P"'), new Promise(r => setTimeout(r, 1500))]).then(start, start);
        } else start();
      } catch (e) { start(); }
    }

    disconnectedCallback() {
      this._connected = false;
      if (this._ro) { try { this._ro.disconnect(); } catch (e) {} }
      if (this._raf) { cancelAnimationFrame(this._raf); this._raf = null; }
    }

    fitScale() {
      if (!this._cv) return;
      const w = this.clientWidth || 320;
      const s = Math.max(1, Math.floor(w / 160));
      const hostH = Math.max(this.clientHeight || 0, this.parentElement ? (this.parentElement.clientHeight || 0) : 0);
      let H = 144;
      // Only grow when the host is explicitly taller than the classic canvas
      if (hostH > 144 * s + 6) H = Math.max(144, Math.min(288, Math.floor(hostH / s)));
      if (this._cv.width !== 160) this._cv.width = 160;
      if (this._cv.height !== H) { this._cv.height = H; this._lastF = -1; }
      this._cv.style.width = (160 * s) + 'px';
      this._cv.style.height = (H * s) + 'px';
      if (this._cur && !this._raf && this._connected) this._raf = requestAnimationFrame(this._step);
    }

    attributeChangedCallback(name, oldV, newV) {
      if (!this._connected || oldV === newV) return;
      if (name === 'anim' && newV) this.play(newV);
      else if (name === 'seq') this.play(this.getAttribute('anim') || this._cur || 'intro');
    }

    isMuted() {
      return this._muteOverride === true || this.getAttribute('muted') === '1' || window.STATEBOY_MUTED === true;
    }

    fps() {
      const v = Number(this.getAttribute('fps'));
      return Math.max(4, Math.min(20, v || 10));
    }

    readPalette() {
      try {
        const cs = getComputedStyle(this);
        const get = (n, fb) => { const v = cs.getPropertyValue(n).trim(); return v || fb; };
        this.pal = [get('--bg', '#9bbc0f'), get('--bg-secondary', '#8bac0f'), get('--border', '#306230'), get('--text', '#0f380f')];
      } catch (e) {
        this.pal = ['#9bbc0f', '#8bac0f', '#306230', '#0f380f'];
      }
    }

    // ---------- audio ----------
    audio() {
      if (!this._ac) {
        try { this._ac = new (window.AudioContext || window.webkitAudioContext)(); } catch (e) { return null; }
      }
      if (this._ac.state === 'suspended') { this._ac.resume().catch(() => {}); }
      return this._ac;
    }

    tone(freq, dur, type, vol, slideTo, delay) {
      if (this.isMuted()) return;
      const ac = this.audio();
      if (!ac || ac.state !== 'running') return;
      type = type || 'square'; vol = vol == null ? 0.12 : vol; slideTo = slideTo || 1; delay = delay || 0;
      const t0 = ac.currentTime + delay;
      const osc = ac.createOscillator(); const g = ac.createGain();
      osc.type = type;
      osc.frequency.setValueAtTime(freq, t0);
      if (slideTo !== 1) osc.frequency.exponentialRampToValueAtTime(Math.max(30, freq * slideTo), t0 + dur);
      g.gain.setValueAtTime(vol, t0);
      g.gain.exponentialRampToValueAtTime(0.001, t0 + dur);
      osc.connect(g); g.connect(ac.destination);
      osc.start(t0); osc.stop(t0 + dur + 0.02);
    }

    playSfx(name) {
      const T = (f, d, ty, v, s, dl) => this.tone(f, d, ty, v, s, dl);
      const M = {
        blip: () => T(760, 0.06),
        blipHi: () => T(1150, 0.05),
        blipLo: () => T(420, 0.08),
        tick: () => T(1500, 0.03, 'square', 0.07),
        key: () => T(1900, 0.02, 'square', 0.045),
        thunk: () => T(150, 0.12, 'square', 0.22, 0.35),
        clunk: () => T(95, 0.16, 'square', 0.25, 0.4),
        buzz: () => T(110, 0.28, 'sawtooth', 0.15, 0.6),
        alarmA: () => T(720, 0.12, 'square', 0.15),
        alarmB: () => T(510, 0.12, 'square', 0.15),
        chirp: () => { T(900, 0.05); T(1350, 0.07, 'square', 0.12, 1, 0.06); },
        plink: () => T(980, 0.05, 'square', 0.1, 1.3),
        win: () => { T(523, 0.09); T(659, 0.09, 'square', 0.12, 1, 0.1); T(784, 0.16, 'square', 0.12, 1, 0.2); },
        t1: () => T(523, 0.08), t2: () => T(659, 0.08), t3: () => T(784, 0.14)
      };
      if (M[name]) M[name]();
    }

    // ---------- drawing surface ----------
    mkS(ctx, cv) {
      const pal = this.pal || ['#9bbc0f', '#8bac0f', '#306230', '#0f380f'];
      const H = cv.height;
      const dy = Math.max(0, Math.floor((H - 40 - 104) / 2)); // center 104px art band above 40px dialog
      let inv = false;
      const C = (i) => pal[Math.max(0, Math.min(3, inv ? 3 - i : i))];
      const S = {
        dy: dy,
        ty: H - 40 - dy, // dialog top, in art coords
        inv(v) { inv = v; },
        clear(i) { ctx.fillStyle = C(i || 0); ctx.fillRect(-8, -8 - dy, 176, H + 16); },
        px(x, y, w, h, i) { ctx.fillStyle = C(i == null ? 3 : i); ctx.fillRect(Math.round(x), Math.round(y), w || 1, h || 1); },
        frame(x, y, w, h, i, t) {
          t = t || 2; i = i == null ? 3 : i;
          S.px(x, y, w, t, i); S.px(x, y + h - t, w, t, i); S.px(x, y, t, h, i); S.px(x + w - t, y, t, h, i);
        },
        dashFrame(x, y, w, h, i) {
          for (let k = 0; k < w; k += 4) { S.px(x + k, y, 2, 1, i); S.px(x + k, y + h - 1, 2, 1, i); }
          for (let k = 0; k < h; k += 4) { S.px(x, y + k, 1, 2, i); S.px(x + w - 1, y + k, 1, 2, i); }
        },
        dither(x, y, w, h, iA, iB) {
          for (let yy = 0; yy < h; yy++) for (let xx = 0; xx < w; xx++) {
            ctx.fillStyle = C(((xx + yy) & 1) ? (iB == null ? 0 : iB) : (iA == null ? 1 : iA));
            ctx.fillRect(x + xx, y + yy, 1, 1);
          }
        },
        speckle(x, y, w, h, i, mod) {
          mod = mod || 3;
          for (let yy = 0; yy < h; yy++) for (let xx = 0; xx < w; xx++) {
            if ((xx * 3 + yy * 7) % mod === 0) S.px(x + xx, y + yy, 1, 1, i);
          }
        },
        line(x0, y0, x1, y1, t, i) {
          t = t || 2;
          const n = Math.max(Math.abs(x1 - x0), Math.abs(y1 - y0), 1);
          for (let k = 0; k <= n; k++) {
            S.px(Math.round(x0 + (x1 - x0) * k / n - t / 2), Math.round(y0 + (y1 - y0) * k / n - t / 2), t, t, i);
          }
        },
        circle(cx, cy, r, i, t, a0, a1) {
          t = t || 1; a0 = a0 == null ? 0 : a0; a1 = a1 == null ? Math.PI * 2 : a1;
          const n = Math.max(10, Math.round(r * 7 * Math.abs(a1 - a0) / (Math.PI * 2)));
          for (let k = 0; k <= n; k++) {
            const th = a0 + (a1 - a0) * k / n;
            S.px(Math.round(cx + Math.cos(th) * r) - Math.floor(t / 2), Math.round(cy + Math.sin(th) * r) - Math.floor(t / 2), t, t, i);
          }
        },
        disc(cx, cy, r, i) {
          for (let dyy = -r; dyy <= r; dyy++) {
            const w = Math.floor(Math.sqrt(r * r - dyy * dyy));
            S.px(cx - w, cy + dyy, w * 2 + 1, 1, i);
          }
        },
        ellipse(cx, cy, rx, ry, fill, rim) {
          for (let dyy = -ry; dyy <= ry; dyy++) {
            const w = Math.max(0, Math.floor(rx * Math.sqrt(Math.max(0, 1 - (dyy / ry) * (dyy / ry)))));
            S.px(cx - w, cy + dyy, w * 2 + 1, 1, fill);
          }
          S.circleE(cx, cy, rx, ry, rim);
        },
        circleE(cx, cy, rx, ry, i) {
          const n = Math.max(12, (rx + ry) * 4);
          for (let k = 0; k <= n; k++) {
            const th = k / n * Math.PI * 2;
            S.px(Math.round(cx + Math.cos(th) * rx), Math.round(cy + Math.sin(th) * ry), 1, 1, i);
          }
        },
        text(s, x, y, i, center) {
          ctx.font = '8px "Press Start 2P"'; ctx.textBaseline = 'top';
          ctx.fillStyle = C(i == null ? 3 : i);
          ctx.fillText(s, center ? Math.round(x - s.length * 4) : x, y);
        },
        tiny(s, x, y, i, sc) {
          sc = sc || 1;
          let cx = x;
          for (const ch of s) {
            const m = TINY[ch];
            if (m) {
              for (let r = 0; r < 5; r++) for (let c = 0; c < 3; c++) {
                if (m[r][c] === '1') S.px(cx + c * sc, y + r * sc, sc, sc, i);
              }
            }
            cx += 4 * sc;
          }
        },
        sprite(map, x, y) {
          for (let r = 0; r < map.length; r++) {
            const row = map[r];
            for (let c = 0; c < row.length; c++) {
              const ch = row[c];
              if (ch !== '.') S.px(x + c, y + r, 1, 1, +ch);
            }
          }
        },
        spriteS(map, x, y, sc) {
          sc = sc || 1;
          for (let r = 0; r < map.length; r++) {
            const row = map[r];
            for (let c = 0; c < row.length; c++) {
              const ch = row[c];
              if (ch !== '.') S.px(x + c * sc, y + r * sc, sc, sc, +ch);
            }
          }
        },
        brickBG() {
          const top = -dy, bot = S.ty;
          let course = 0;
          for (let y = top; y < bot; y += 12) {
            S.px(0, y, 160, 1, 1);
            const off = (course % 2) ? 10 : 0;
            for (let x = off; x < 160; x += 20) S.px(x, y + 1, 1, Math.min(11, bot - y - 1), 1);
            course++;
          }
          S.speckle(0, top, 160, bot - top, 1, 53);
        },
        bevel(x, y, w, h, fill) {
          S.px(x, y, w, h, 3);
          S.px(x + 1, y + 1, w - 2, h - 2, fill == null ? 1 : fill);
          S.px(x + 1, y + 1, w - 2, 1, 0);
          S.px(x + 1, y + 1, 1, h - 2, 0);
          S.px(x + 1, y + h - 2, w - 2, 1, 2);
          S.px(x + w - 2, y + 2, 1, h - 3, 2);
        },
        shadow(cx, cy, rx) {
          for (let dx = -rx; dx <= rx; dx++) {
            if ((dx + cx) % 2 === 0) S.px(cx + dx, cy, 1, 1, 2);
            if (Math.abs(dx) < rx - 3 && (dx + cx) % 2 === 1) S.px(cx + dx, cy + 1, 1, 1, 2);
          }
        },
        spark(cx, cy, s, i) {
          S.line(cx - s, cy, cx + s, cy, 1, i == null ? 3 : i);
          S.line(cx, cy - s, cx, cy + s, 1, i == null ? 3 : i);
        },
        burst(cx, cy, r0, r1, i) {
          for (let k = 0; k < 8; k++) {
            const a = k * Math.PI / 4 + Math.PI / 8;
            S.line(cx + Math.cos(a) * r0, cy + Math.sin(a) * r0, cx + Math.cos(a) * r1, cy + Math.sin(a) * r1, 1, i == null ? 3 : i);
          }
        },
        shake(dx, dyy) { ctx.translate(dx, dyy); },
        drawImg(img, dx2, dy2, dw, dh, flip) {
          ctx.save();
          ctx.imageSmoothingEnabled = false;
          if (flip) {
            ctx.translate(dx2 + dw, dy2); ctx.scale(-1, 1);
            ctx.drawImage(img.cv, img.x, img.y, img.w, img.h, 0, 0, dw, dh);
          } else {
            ctx.drawImage(img.cv, img.x, img.y, img.w, img.h, dx2, dy2, dw, dh);
          }
          ctx.restore();
        },
        blit(sy, h, dx) { ctx.drawImage(cv, 0, sy + dy, 160, h, dx, sy, 160, h); },
        floor(topY, iA, iB) {
          S.px(0, topY, 160, 1, 2);
          S.dither(0, topY + 1, 160, Math.max(5, S.ty - topY - 1), iA == null ? 1 : iA, iB == null ? 0 : iB);
        },
        // dialog box with typewriter text + blinking advance cursor
        textBox(l1, l2, f, start) {
          if (f < start) return;
          const ty = S.ty;
          S.px(6, ty, 148, 36, 0);
          S.frame(6, ty, 148, 36, 3, 2);
          S.px(9, ty + 3, 142, 30, 0);
          const shown = Math.max(0, (f - start) * 2);
          S.text(l1.substring(0, shown), 13, ty + 7, 3);
          if (l2 && shown > l1.length) S.text(l2.substring(0, shown - l1.length), 13, ty + 19, 3);
          const total = l1.length + (l2 ? l2.length : 0);
          if (shown >= total && (f % 4) < 2) {
            S.px(141, ty + 28, 7, 1, 3); S.px(142, ty + 29, 5, 1, 3); S.px(143, ty + 30, 3, 1, 3); S.px(144, ty + 31, 1, 1, 3);
          }
        },
        // ---- rich props ----
        gbDevice(x, y, screenFill) {
          S.bevel(x, y, 26, 46, 1);
          S.px(x + 3, y + 3, 20, 19, 2);
          S.frame(x + 4, y + 4, 18, 17, 3, 1);
          S.px(x + 5, y + 5, 16, 15, screenFill == null ? 0 : screenFill);
          if (screenFill == null) {
            S.px(x + 7, y + 8, 8, 2, 3);
            S.px(x + 7, y + 12, 12, 2, 2);
            S.px(x + 7, y + 16, 5, 2, 2);
          }
          S.px(x + 6, y + 26, 3, 9, 3); S.px(x + 3, y + 29, 9, 3, 3);
          S.px(x + 7, y + 27, 1, 1, 1);
          S.px(x + 14, y + 31, 4, 4, 3); S.px(x + 15, y + 32, 1, 1, 1);
          S.px(x + 19, y + 27, 4, 4, 3); S.px(x + 20, y + 28, 1, 1, 1);
          S.px(x + 8, y + 40, 5, 2, 3); S.px(x + 15, y + 40, 5, 2, 3);
          for (let k = 0; k < 3; k++) S.px(x + 18 + k * 2, y + 43, 1, 2, 2);
        },
        pico(x, y, ledOn) {
          S.px(x - 5, y + 9, 5, 7, 2); S.frame(x - 5, y + 9, 5, 7, 3, 1); S.px(x - 4, y + 12, 3, 1, 0);
          S.bevel(x, y, 40, 24, 2);
          [[2, 2], [36, 2], [2, 20], [36, 20]].forEach(p => { S.px(x + p[0], y + p[1], 2, 2, 0); S.px(x + p[0], y + p[1], 1, 1, 3); });
          for (let k = 0; k < 12; k++) { S.px(x + 7 + k * 2, y + 1, 1, 1, 0); S.px(x + 7 + k * 2, y + 22, 1, 1, 0); }
          S.px(x + 14, y + 8, 13, 9, 3);
          S.px(x + 15, y + 9, 1, 1, 0);
          S.px(x + 12, y + 10, 2, 1, 0); S.px(x + 12, y + 13, 2, 1, 0);
          S.px(x + 27, y + 10, 2, 1, 0); S.px(x + 27, y + 13, 2, 1, 0);
          S.px(x + 8, y + 5, 2, 2, ledOn ? 0 : 3);
        },
        chipBig(x, y, w, h, label, mode, dx) {
          dx = dx || 0; x += dx;
          const pinI = mode === 'ghost' ? 2 : 3;
          const step = Math.floor((h - 6) / 4);
          for (let k = 0; k < 5; k++) {
            const py = y + 2 + k * step;
            S.px(x - 5, py, 5, 3, pinI); S.px(x - 6, py + 1, 2, 2, 2);
            S.px(x + w, py, 5, 3, pinI); S.px(x + w + 4, py + 1, 2, 2, 2);
          }
          if (mode === 'g25') { S.speckle(x, y, w, h, 2, 4); S.dashFrame(x, y, w, h, 2); return; }
          if (mode === 'g50') { S.dither(x, y, w, h, 2, 0); S.frame(x, y, w, h, 2, 1); return; }
          S.px(x + 2, y + h, w - 2, 2, 2);
          S.px(x, y, w, h, 3);
          S.px(x + 1, y + 1, w - 2, 1, 2);
          S.px(x + 1, y + 1, 1, h - 2, 2);
          S.frame(x + 4, y + 4, w - 8, h - 8, 2, 1);
          S.px(x + 3, y + 3, 2, 2, 0);
          const nx = x + Math.floor(w / 2);
          S.px(nx - 3, y, 6, 3, 1); S.px(nx - 2, y + 1, 4, 2, 2);
          if (mode === 'skull') S.sprite(SPR.skull, nx - 4, y + Math.floor(h / 2) - 4);
          else if (label) S.text(label, nx, y + Math.floor(h / 2) - 4, 0, true);
        },
        miniLock(cx, cy, i) {
          i = i == null ? 0 : i;
          S.px(cx - 4, cy, 9, 7, i);
          S.frame(cx - 3, cy - 4, 7, 5, i, 1);
          S.px(cx, cy + 2, 1, 3, i === 0 ? 3 : 0);
        },
        hazardBorder(f) {
          const topY = -dy, botY = H - 7 - dy;
          for (let x = -8; x < 168; x += 2) {
            const on = (((x + f * 2) % 12) + 12) % 12 < 6;
            S.px(x, topY, 2, 7, on ? 3 : 0);
            S.px(x, topY, 2, 1, 3); S.px(x, topY + 6, 2, 1, 3);
            S.px(x, botY, 2, 7, on ? 3 : 0);
            S.px(x, botY, 2, 1, 3); S.px(x, botY + 6, 2, 1, 3);
          }
        },
        rssi(x, y, n) {
          for (let k = 0; k < 4; k++) {
            const h = 2 + k * 2;
            if (k < n) S.px(x + k * 4, y + 8 - h, 3, h, 3);
            else S.px(x + k * 4, y + 7, 3, 1, 2);
          }
        },
        coin(cx, cy, rx, ry) {
          if (rx <= 1) { S.px(cx - 1, cy - ry, 2, ry * 2, 3); return; }
          S.ellipse(cx, cy, rx, ry, 1, 3);
          if (rx >= 8) {
            S.circleE(cx, cy, rx - 3, ry - 3, 2);
            S.sprite(SPR.star, cx - 2, cy - 2);
          } else if (rx >= 4) {
            S.px(cx - 1, cy - 3, 2, 6, 2);
          }
        },
        coinS(cx, cy, mode) { // small coin — mode: 0 normal, 1 flash, 2 dark
          const fillI = mode === 1 ? 0 : mode === 2 ? 2 : 1;
          S.disc(cx, cy, 5, fillI);
          S.circle(cx, cy, 5, 3, 1);
          if (mode !== 1) S.circle(cx, cy, 3, 2, 1);
          S.px(cx - 2, cy - 3, 1, 1, 0);
          if (mode === 1) S.circle(cx, cy, 7, 0, 1);
        },
        coinSpin(cx, cy, ph) {
          const rxs = [5, 3, 1, 3][((ph % 4) + 4) % 4];
          if (rxs <= 1) { S.px(cx - 1, cy - 5, 2, 10, 3); return; }
          S.ellipse(cx, cy, rxs, 5, 1, 3);
          if (rxs >= 4) S.circle(cx, cy, 3, 2, 1);
        },
        text16(s, x, y, i, center) {
          ctx.font = '16px "Press Start 2P"'; ctx.textBaseline = 'top';
          ctx.fillStyle = C(i == null ? 3 : i);
          ctx.fillText(s, center ? Math.round(x - s.length * 8) : x, y);
        },
        bag(cx, mode, bulge, squash) { // classic cinched money sack
          bulge = bulge || 0;
          const bot = 93;
          const ry = 14 + bulge - (squash ? 2 : 0);
          const rx = 16 + bulge + (squash ? 3 : 0);
          const cy = bot - ry;
          S.shadow(cx, bot + 2, rx + 2);
          const rowW = (dyy) => {
            let w = rx * Math.sqrt(Math.max(0, 1 - (dyy / ry) * (dyy / ry)));
            if (dyy > 0) w *= 1 + 0.14 * dyy / ry;
            if (dyy >= ry - 1) w *= 0.85;
            if (dyy < 0) {
              const t = -dyy / ry;
              w = w * (1 - 0.10 * t);
              if (w < 5) w = 5;
            }
            return Math.floor(Math.min(w, rx + 3));
          };
          for (let dyy = -ry; dyy <= ry; dyy++) S.px(cx - rowW(dyy), cy + dyy, rowW(dyy) * 2 + 1, 1, 1);
          // shade lower-right
          for (let dyy = 0; dyy <= ry - 1; dyy++) {
            const w = rowW(dyy) - 1;
            for (let xx = Math.floor(w * 0.25); xx < w; xx++) {
              if ((xx + dyy) % 2 === 0) S.px(cx + xx, cy + dyy, 1, 1, 2);
            }
          }
          // outline
          for (let dyy = -ry; dyy <= ry; dyy++) {
            const w = rowW(dyy);
            S.px(cx - w, cy + dyy, 1, 1, 3); S.px(cx + w, cy + dyy, 1, 1, 3);
            const wn = dyy < ry ? rowW(dyy + 1) : 0;
            if (wn > w + 1) { S.px(cx - wn, cy + dyy + 1, wn - w, 1, 3); S.px(cx + w + 1, cy + dyy + 1, wn - w, 1, 3); }
          }
          S.px(cx - rowW(ry), bot, rowW(ry) * 2 + 1, 1, 3);
          // highlight top-left
          for (let k = 0; k < 6; k++) {
            const a = Math.PI * (1.12 + k * 0.05);
            S.px(Math.round(cx + Math.cos(a) * (rx - 3)), Math.round(cy + Math.sin(a) * (ry - 3)), 1, 1, 0);
          }
          // gather creases fanning out from the neck
          S.line(cx - 4, cy - ry + 2, cx - 8, cy - ry + 9, 1, 2);
          S.line(cx + 4, cy - ry + 2, cx + 8, cy - ry + 9, 1, 2);
          S.px(cx, cy - ry + 2, 1, 5, 2);
          // $ on the belly
          S.text16('$', cx + 1, cy - 5, 3, true);
          const nb = cy - ry;
          if (mode === 'open') {
            const ws = [7, 9, 11];
            for (let k = 0; k < 3; k++) {
              const w = ws[k], yy = nb - 2 - k * 2;
              S.px(cx - w, yy, w * 2, 2, 1);
              S.px(cx - w - 1, yy, 1, 2, 3); S.px(cx + w, yy, 1, 2, 3);
            }
            S.ellipse(cx, nb - 8, 10, 3, 3, 3);
            S.px(cx - 6, nb - 9, 4, 1, 2);
          } else {
            // pinched neck cloth
            for (let k = 1; k <= 3; k++) {
              const hw = k === 1 ? 5 : 4;
              S.px(cx - hw, nb - k, hw * 2, 1, 1);
              S.px(cx - hw - 1, nb - k, 1, 1, 3); S.px(cx + hw, nb - k, 1, 1, 3);
            }
            S.px(cx - 1, nb - 3, 1, 3, 2);
            // gathered cloth puff above the tie
            const PUFF = [[13, 3], [12, 5], [11, 6], [10, 7], [9, 7], [8, 6], [7, 5]];
            PUFF.forEach(pr => {
              S.px(cx - pr[1], nb - pr[0], pr[1] * 2, 1, 1);
              S.px(cx - pr[1] - 1, nb - pr[0], 1, 1, 3); S.px(cx + pr[1], nb - pr[0], 1, 1, 3);
            });
            S.px(cx - 3, nb - 14, 6, 1, 3);
            S.px(cx - 2, nb - 11, 1, 4, 2); S.px(cx + 2, nb - 11, 1, 4, 2);
            S.px(cx - 4, nb - 12, 1, 1, 0); S.px(cx - 5, nb - 10, 1, 1, 0);
            if (mode === 'tied') {
              // rope wound around the pinch + knot + dangling ends
              S.px(cx - 5, nb - 6, 10, 3, 3);
              S.px(cx - 4, nb - 6, 8, 1, 2);
              S.px(cx + 3, nb - 7, 3, 2, 3);
              S.line(cx + 5, nb - 4, cx + 8, nb - 1, 1, 3);
              S.line(cx + 4, nb - 4, cx + 5, nb, 1, 3);
              S.px(cx + 8, nb - 1, 1, 2, 3);
            } else {
              // untied: band slipping loose
              S.px(cx - 5, nb - 5, 10, 2, 2);
              S.line(cx + 4, nb - 3, cx + 7, nb + 2, 1, 3);
            }
          }
        }
      };
      return S;
    }

    // ---------- animations ----------
    ANIMS() {
      const TAU = Math.PI * 2;
      const AMT = (this.getAttribute('amount') || '').trim();
      // Irrefutable Labs mascot — wild hair, giant goggles, magnifying glass, lab coat
      const docSci = (S, cx, fy, pose, f) => {
        if (pose === 'shock') cx += (f % 2) ? 1 : -1;
        let yo = 0;
        if (pose === 'walk0') yo = -1;
        if (pose === 'cheer' && f % 4 < 2) yo = -2;
        const IM = this._sciImg;
        if (IM) {
          const dh = 71, dw = Math.round(IM.w * dh / IM.h);
          S.drawImg(IM, cx - (dw >> 1), fy - dh + yo, dw, dh, true);
        } else {
          S.sprite(SPR.sci, cx - 28, fy - 71 + yo);
        }

        if (pose === 'shock') {
          // hair stands further on end + stray sparks
          const SPKE = [[-0.9, -0.4], [-0.55, -0.8], [0, -1], [0.5, -0.85], [0.9, -0.3]];
          for (let i = 0; i < SPKE.length; i++) {
            const dx = SPKE[i][0], dy = SPKE[i][1];
            const bx = cx + dx * 17, by = fy - 50 + dy * 14;
            S.line(bx, by, bx + dx * (6 + ((f + i) % 2) * 2), by + dy * 6, 2, 0);
          }
          S.spark(cx - 17, fy - 63, 2, 3);
          S.spark(cx + 12, fy - 64, 2, 3);
        }
      };
      const zig = (S, x0, y0, x1, y1, seed) => {
        const j = (k, m) => ((seed * 13 + k * 7 + 5) % (2 * m + 1)) - m;
        const m1x = x0 + (x1 - x0) * 0.33 + j(1, 4);
        const m1y = y0 + (y1 - y0) * 0.33 + j(2, 3);
        const m2x = x0 + (x1 - x0) * 0.66 + j(3, 4);
        const m2y = y0 + (y1 - y0) * 0.66 + j(4, 3);
        // thick dark bolt with a bright core so it reads at display scale
        S.line(x0, y0, m1x, m1y, 2, 3);
        S.line(m1x, m1y, m2x, m2y, 2, 3);
        S.line(m2x, m2y, x1, y1, 2, 3);
        S.line(x0, y0, m1x, m1y, 1, 0);
        S.line(m1x, m1y, m2x, m2y, 1, 0);
        S.line(m2x, m2y, x1, y1, 1, 0);
        // branch fork off the first elbow
        const bx = m1x + j(5, 6), by = m1y + Math.abs(j(6, 4)) + 3;
        S.line(m1x, m1y, bx, by, 1, 3);
      };
      const bagScene = (ok) => ({
        frames: 58, holdBlink: true,
        title: ok ? 'TX CONFIRMED · COIN BAG' : 'TX FAILED · BAG SHUT',
        sfx: ok
          ? { 1: 'blipLo', 3: 'thunk', 4: 'tick', 5: ['clunk', 'chirp'], 6: 'tick', 7: 't3', 8: 'tick', 9: 't2', 11: 't3', 13: 't2', 15: 'blip', 17: 'blip', 19: 'blip', 22: 'tick', 24: 'chirp', 26: 't2', 27: 'plink', 28: 'plink', 29: 'thunk', 31: 'win', 34: 'key', 36: 'key', 38: 'key', 40: 'key' }
          : { 1: 'blipLo', 3: 'thunk', 4: 'tick', 5: ['clunk', 'chirp'], 6: 'tick', 7: 't3', 8: 'tick', 9: 't2', 11: 't3', 13: 't2', 15: 'blip', 17: 'blip', 19: 'blip', 22: 'tick', 24: 'chirp', 26: 'blipLo', 28: 'chirp', 29: ['plink', 'blipHi'], 30: 'plink', 31: 'clunk', 33: 'blipLo', 34: 'key', 36: 'key', 38: 'key', 40: 'key' },
        draw: (S, f) => {
          S.clear(0);
          if (f === 3) S.shake(1, 0);
          if (f === 29) S.shake(ok ? 0 : 2, 1);
          S.brickBG();
          S.floor(95, 1, 0);
          const CS = [[78, 40], [92, 32], [106, 42], [120, 34], [132, 46]];
          const bagX = 104;
          // ---- brick block rattles, hops, bursts — releasing the coins ----
          const brick = (x, y, sq) => {
            const w = 24, h = sq ? 22 : 24;
            S.px(x, y, w, h, 3);
            S.px(x + 1, y + 1, w - 2, h - 2, 1);
            S.px(x + 1, y + 1, w - 2, 1, 0);
            S.px(x + 1, y + 1, 1, h - 2, 0);
            S.px(x + 1, y + Math.floor(h / 2) - 1, w - 2, 2, 3);
            S.px(x + 11, y + 1, 2, Math.floor(h / 2) - 2, 3);
            S.px(x + 5, y + Math.floor(h / 2) + 1, 2, Math.floor(h / 2) - 2, 3);
            S.px(x + 17, y + Math.floor(h / 2) + 1, 2, Math.floor(h / 2) - 2, 3);
            S.px(x + 3, y + h - 3, 2, 1, 2); S.px(x + 15, y + 4, 2, 1, 2);
          };
          if (f < 1) brick(26, 32, false);
          else if (f < 3) brick(26 + (f % 2 ? 1 : -1), 32, false);
          else if (f === 3) brick(26, 25, true);
          else if (f === 4) {
            brick(26, 30, false);
            S.line(32, 34, 38, 42, 1, 3); S.line(38, 42, 34, 50, 1, 3);
            S.line(42, 32, 46, 44, 1, 3);
          } else if (f === 5) {
            S.burst(38, 42, 6, 15, 3);
            S.px(34, 38, 8, 8, 0);
          }
          if (f >= 5 && f <= 12) {
            const t = f - 5;
            const DIRS = [[-1, -1], [1, -1], [-1, 1], [1, 1]];
            for (let k = 0; k < 4; k++) {
              const d = DIRS[k];
              const fx = 34 + d[0] * (5 + t * 6);
              let fy;
              if (d[1] < 0) fy = 38 - 8 * t + 2 * t * t;
              else fy = 42 + 4 * t + t * t;
              if (fy < 86 && fx > -8 && fx < 76) S.sprite((t + k) % 2 ? SPR.fragA : SPR.fragB, fx, fy);
            }
          }
          // on fail the bag sits tied the whole time, drawn behind the coins
          if (!ok) S.bag(bagX, 'tied', 0, false);
          // ---- coins: fly out, hover, freeze in unison, magic flash... then diverge ----
          for (let i = 0; i < 5; i++) {
            const st = 5 + i * 2;
            if (f < st) continue;
            const sl = CS[i];
            if (f < st + 6) {
              const t = (f - st) / 6;
              const x = Math.round(38 + (sl[0] - 38) * t);
              const y = Math.round(42 + (sl[1] - 42) * t - Math.sin(Math.PI * t) * 14);
              S.coinSpin(x, y, f + i);
            } else if (f < 22) {
              S.coinS(sl[0], sl[1] + (((f + i) % 4 < 2) ? 0 : 1), 0);
            } else if (f < 26) {
              S.coinS(sl[0], sl[1], f === 25 ? 1 : 0); // frozen in unison + magic flash
              if (f === 24) S.sprite(SPR.twinkle, sl[0] - 1, sl[1] - 12);
            } else if (ok) {
              // pour into the open bag
              if (f <= 29) {
                const t = f - 25;
                const x = Math.round(sl[0] + (bagX - sl[0]) * (t / 3));
                const y = sl[1] + t * 12;
                if (y < 58) S.coinS(x, y, 0);
              }
            } else {
              // gather over the shut bag...
              if (f <= 27) {
                const t = f - 25;
                const x = Math.round(sl[0] + ((bagX + (i - 2) * 5) - sl[0]) * (t / 2));
                const y = Math.round(sl[1] + ((40 + (i % 2) * 3) - sl[1]) * (t / 2));
                S.coinS(x, y, 0);
              } else {
                // ...the bag throws up a force field: coins slam into it,
                // bounce back, and tumble away off the bottom of the screen
                const x0 = bagX + (i - 2) * 5;
                const y0 = 40 + (i % 2) * 3;
                const dxs = x0 - bagX;
                const ys = 74 - Math.sqrt(Math.max(1, 484 - dxs * dxs));
                if (f === 28) S.coinS(x0, y0 + 3, 0);
                else if (f === 29) S.coinS(x0, Math.round(ys), 0);
                else {
                  const t = f - 29;
                  const vx = ((i - 2) * 5) || ((i % 2) ? 3 : -3);
                  const x = Math.round(x0 + vx * t);
                  const y = Math.round(ys - 7 * t + 3.2 * t * t);
                  if (y < S.ty + 46 && x > -10 && x < 170) S.coinS(x, y, 0);
                }
              }
            }
          }
          if (ok) {
            const mode = f < 6 ? 'tied' : f < 8 ? 'untied' : f < 30 ? 'open' : 'tied';
            S.bag(bagX, mode, f >= 29 ? 2 : 0, f === 29);
            if (f >= 29 && f <= 31) { S.sprite(SPR.dust, bagX - 26, 80); S.sprite(SPR.dust, bagX + 20, 80); }
            if (f >= 32) {
              if (f % 4 < 2) S.sprite(SPR.star, 62, 50); else S.sprite(SPR.twinkle, 128, 52);
            }
          } else {
            // force-field dome flashes as the coins strike it
            if (f >= 28 && f <= 34) {
              const bright = f === 29 || f === 30;
              S.circle(bagX, 74, 22, bright ? 3 : 2, 1, Math.PI * 0.92, Math.PI * 2.08);
              if (bright) {
                S.circle(bagX, 74, 25, 2, 1, Math.PI * 1.08, Math.PI * 1.92);
                for (let ii = 0; ii < 5; ii++) {
                  const ddx = (ii - 2) * 5;
                  S.spark(bagX + ddx, Math.round(74 - Math.sqrt(484 - ddx * ddx)) - 2, 3, 3);
                }
              }
            }
            // X stamp over the bag
            if (f >= 31) {
              const st2 = Math.min(f - 31, 2);
              const hl = [16, 13, 11][st2];
              const i2 = st2 === 2 ? 3 : 2;
              S.line(bagX - hl, 28 - hl, bagX + hl, 28 + hl, 5, i2);
              S.line(bagX + hl, 28 - hl, bagX - hl, 28 + hl, 5, i2);
              if (st2 === 2) {
                S.line(bagX - 10, 18, bagX + 10, 38, 2, 0);
                S.line(bagX + 10, 18, bagX - 10, 38, 2, 0);
              }
            }
          }
          let l2 = ok ? (AMT ? '+' + AMT : 'BALANCE UPDATED') : (AMT ? AMT + ' DENIED' : 'PRESS B: RETRY');
          if (l2.length > 17) l2 = AMT;
          S.textBox(ok ? 'TX CONFIRMED' : 'TX FAILED', l2, f, 33);
        }
      });
      return {
        // ============ INTRO · IRREFUTABLE LABS ============
        intro: {
          frames: 66, holdBlink: true, title: 'INTRO · IT LIVES',
          sfx: { 2: 'key', 4: 'key', 5: 'blip', 6: 'key', 8: 'key', 10: 'tick', 11: 'clunk', 13: 'buzz', 15: 'alarmA', 17: 'alarmB', 19: 'alarmA', 21: 'alarmB', 23: 'buzz', 25: 'blipLo', 27: 'chirp', 28: 't1', 29: 't2', 30: ['t3', 'thunk'], 32: 'win', 34: 'key', 36: 'key', 38: 'key', 40: 'key' },
          draw: (S, f) => {
            S.inv(f === 15 || f === 19);
            S.clear(0);
            S.brickBG();
            S.floor(94, 1, 0);
            const zap = f >= 13 && f <= 23;
            // gantry beam + electrode rig (kept clear of the title)
            S.px(88, 16, 80, 3, 3);
            S.px(88, 19, 80, 1, 2);
            S.px(107, 19, 2, 5, 3);
            S.px(131, 19, 2, 5, 3);
            S.bevel(100, 24, 44, 8, 2);
            S.px(106, 32, 4, 6, 3); S.px(130, 32, 4, 6, 3);
            S.disc(108, 40, 3, zap && f % 2 ? 0 : 3); S.circle(108, 40, 3, 3, 1);
            S.disc(132, 40, 3, zap && f % 2 === 0 ? 0 : 3); S.circle(132, 40, 3, 3, 1);
            // slab legs
            S.px(96, 78, 4, 16, 3); S.px(140, 78, 4, 16, 3);
            S.px(96, 84, 4, 1, 2); S.px(140, 84, 4, 1, 2);
            // the creation
            if (f < 27) {
              // sheet-covered mound (jolts under the lightning)
              const hop = zap ? ((f % 2) ? -2 : 0) - (f === 16 || f === 20 ? 2 : 0) : 0;
              const HW = [4, 7, 9, 11, 12, 13, 14, 15, 15, 16, 16, 17, 17, 17];
              for (let r = 0; r < HW.length; r++) {
                const y = 58 + r + hop;
                S.px(120 - HW[r], y, HW[r] * 2, 1, 0);
                S.px(120 - HW[r], y, 1, 1, 3); S.px(120 + HW[r] - 1, y, 1, 1, 3);
              }
              S.px(116, 58 + hop, 8, 1, 3);
              S.line(112, 62 + hop, 108, 68 + hop, 1, 2);
              S.line(126, 61 + hop, 130, 67 + hop, 1, 2);
            } else {
              // DSM monolith rises
              const top = f === 27 ? 66 : f === 28 ? 58 : 52;
              if (f >= 31 && f % 4 < 2) S.frame(101, top - 2, 38, 24, 0, 1);
              S.bevel(103, top, 34, 20, 1);
              S.text('DSM', 120, top + 6, 3, true);
              // crumpled sheet flies off
              if (f <= 29) {
                const sp = [[100, 44, 5], [80, 32, 4], [60, 24, 3]][f - 27];
                S.disc(sp[0], sp[1], sp[2], 0); S.circle(sp[0], sp[1], sp[2], 3, 1);
              }
            }
            // slab tabletop (masks the monolith's base)
            S.bevel(92, 72, 56, 7, 2);
            // knife switch
            S.px(64, 90, 16, 4, 3);
            S.px(66, 91, 12, 1, 2);
            const lv = f <= 10 ? [76, 63] : f === 11 ? [66, 61] : [60, 66];
            S.line(72, 91, lv[0], lv[1], 2, 3);
            S.px(70, 88, 5, 4, 3);
            S.px(71, 89, 3, 1, 2);
            S.disc(lv[0], lv[1], 2, f >= 12 ? 3 : 1);
            S.circle(lv[0], lv[1], 2, 3, 1);
            // lightning storm
            if (zap) {
              zig(S, 108, 40, 132, 40, f * 3 + 1);
              if (f % 2 === 0) zig(S, 108, 42, 115, 57, f * 5 + 2);
              else zig(S, 132, 42, 125, 57, f * 7 + 3);
              if (f % 3 === 0) zig(S, 120, 40, 120, 56, f * 11 + 5);
            }
            // smoke after the storm
            if (f >= 24 && f <= 27) {
              const k = f - 24;
              S.sprite(SPR.dust, 112 - k * 2, 52 - k * 4);
              S.sprite(SPR.dust, 128 + k * 2, 50 - k * 4);
            }
            if (f === 30 || f === 31) S.burst(120, 50, 20, 27, 3);
            // end-card sparkles + idle arcs
            if (f >= 32) {
              if (f % 4 < 2) S.sprite(SPR.star, 98, 42); else S.sprite(SPR.twinkle, 141, 46);
              if (f % 8 < 2) zig(S, 108, 40, 132, 40, f);
            }
            // the scientist
            if (f <= 8) docSci(S, Math.round(4 + 4.5 * f), 94, f % 2 ? 'walk1' : 'walk0', f);
            else if (f <= 10) docSci(S, 40, 94, 'stand', f);
            else if (f <= 12) docSci(S, 40, 94, 'lever', f);
            else if (f <= 26) docSci(S, 40, 94, zap ? 'shock' : 'stand', f);
            else if (f <= 29) docSci(S, 40, 94, 'stand', f);
            else docSci(S, 40, 94, 'cheer', f);
            // studio name
            if (f >= 5) {
              const ti = f < 7 ? 2 : 3;
              S.text('IRREFUTABLE LABS', 80, 4, ti, true);
              if (f >= 7) S.px(28, 14, 104, 1, ti);
            }
            S.textBox('IT LIVES!', 'INTRODUCING DSM!', f, 33);
          }
        },

        // ============ SECURE LINK · CHIP TRACE ============
        trace: {
          frames: 52, holdBlink: true, title: 'SECURE LINK · CHIP TRACE',
          sfx: { 4: 'blipLo', 8: 'tick', 12: 'tick', 15: 'tick', 19: 'tick', 21: 'blipHi', 22: 'blip', 24: 'blip', 26: 'blip', 32: 'thunk', 34: 'key', 36: 'key', 38: 'key', 40: 'key', 42: 'key', 46: 'win' },
          draw(S, f) {
            S.clear(0);
            S.brickBG();
            S.floor(94, 1, 0);
            // devices seated on the floor
            S.shadow(21, 96, 15);
            S.shadow(128, 96, 25);
            S.gbDevice(8, 48);
            const flash = f >= 22 && f <= 27 && f % 2 === 0;
            S.chipBig(108, 54, 40, 34, 'T01', flash ? 'ghost' : 'solid');
            // jumper wire arcing up between them
            const PTS = [[36, 68], [58, 68], [58, 44], [86, 44], [86, 68], [104, 68]];
            for (let k = 0; k < PTS.length - 1; k++) S.line(PTS[k][0], PTS[k][1], PTS[k + 1][0], PTS[k + 1][1], 3, 2);
            PTS.forEach(p => { S.px(p[0] - 2, p[1] - 2, 5, 5, 2); S.px(p[0] - 1, p[1] - 1, 3, 3, 0); });
            // pulse — live wire: energized trace + marching current + electric arcs
            const TOTAL = 116;
            const pathPt = (d) => {
              let rem = Math.max(0, Math.min(d, TOTAL));
              for (let k = 0; k < PTS.length - 1; k++) {
                const a = PTS[k], b = PTS[k + 1];
                const len = Math.abs(b[0] - a[0]) + Math.abs(b[1] - a[1]);
                if (rem <= len) {
                  const t = rem / len;
                  return [Math.round(a[0] + (b[0] - a[0]) * t), Math.round(a[1] + (b[1] - a[1]) * t), a[1] === b[1]];
                }
                rem -= len;
              }
              const e = PTS[PTS.length - 1];
              return [e[0], e[1], true];
            };
            if (f >= 6) {
              const dist = Math.min((f - 5) * 8, TOTAL);
              // energized wire body
              for (let d = 0; d <= dist; d++) {
                const p = pathPt(d);
                if (p[2]) S.px(p[0], p[1] - 1, 1, 3, 3); else S.px(p[0] - 1, p[1], 3, 1, 3);
              }
              // marching bright current inside the wire
              for (let d = 0; d <= dist; d++) {
                if ((((d - f * 5) % 12) + 12) % 12 < 5) {
                  const p = pathPt(d);
                  S.px(p[0], p[1], 1, 1, 0);
                }
              }
              // electric zigzag arcs crawling off the live wire
              const bolt = (x, y, hor, side, ph) => {
                if (hor) {
                  S.px(x, y - side * 4, 1, 2, 3);
                  S.px(x + 1, y - side * 6, 1, 2, 3);
                  S.px(x + 2 - (ph % 2) * 3, y - side * 8, 1, 2, 3);
                } else {
                  S.px(x + side * 4, y, 2, 1, 3);
                  S.px(x + side * 6, y + 1, 2, 1, 3);
                  S.px(x + side * 8, y + 2 - (ph % 2) * 3, 2, 1, 3);
                }
              };
              for (let d = 10; d < dist - 2; d += 22) {
                const idx = Math.floor(d / 22);
                if ((f + idx) % 3 === 0) continue;
                const p = pathPt(d + ((f * 3 + idx * 7) % 6));
                bolt(p[0], p[1], p[2], (idx + f) % 2 ? 1 : -1, f + idx);
              }
              // crackling head while the pulse travels
              if (dist < TOTAL) {
                const hp = pathPt(dist);
                S.px(hp[0] - 2, hp[1] - 2, 5, 5, 3);
                S.px(hp[0] - 1, hp[1] - 1, 3, 3, 0);
                S.spark(hp[0], hp[1], f % 2 ? 6 : 4, 3);
              }
            }
            // echo rings from chip
            if (f >= 26 && f <= 29) {
              const k = f - 25;
              S.frame(108 - k * 5, 54 - k * 5, 40 + k * 10, 34 + k * 10, k > 2 ? 1 : 2, 1);
            }
            // padlock stamp (hand-drawn sprite, 2x)
            if (f >= 30) {
              const ly = f === 30 ? 1 : 5;
              S.spriteS(SPR.lock, 65, ly, 2);
              if (f >= 31 && f <= 33) S.burst(78, 19, 19, 25, 3);
            }
            S.textBox('SECURE LINK OK', 'DSM ANCHOR SET', f, 33);
            if (f <= 3) S.px(0, (f + 1) * 36, 160, 300, 0);
          }
        },

        // ============ SECURE LINK · PADLOCK ============
        lock: {
          frames: 52, holdBlink: true, title: 'SECURE LINK · PADLOCK',
          sfx: { 3: 'thunk', 6: 'tick', 8: 'tick', 10: 'tick', 12: 'blip', 14: 'tick', 16: 'blip', 18: 'tick', 20: 'blip', 24: 'tick', 25: 'clunk', 30: 'blipHi', 32: 'key', 34: 'key', 36: 'key', 38: 'key', 44: 'win' },
          draw(S, f) {
            S.clear(0);
            if (f === 25) S.shake(0, 2);
            S.brickBG();
            S.floor(94, 1, 0);
            const drop = [-34, 10, 40, 56, 53, 56];
            const by = f < 6 ? drop[Math.min(f, 5)] : 56;
            const squash = (f === 3 || f === 25);
            S.shadow(80, 97, f < 3 ? 12 : 26);
            // shackle (behind body)
            let shTop, legBot;
            if (f < 24) { shTop = by - 34; legBot = by - 10; }
            else if (f === 24) { shTop = by - 28; legBot = by - 2; }
            else { shTop = by - 24; legBot = by + 6; }
            S.px(60, shTop, 7, legBot - shTop, 3);
            S.px(93, shTop, 7, legBot - shTop, 3);
            S.px(60, shTop, 40, 7, 3);
            S.px(62, shTop + 2, 36, 2, 2);
            // body
            const bx = squash ? 54 : 56, bw = squash ? 52 : 48, bh = squash ? 30 : 32, byy = squash ? by + 2 : by;
            S.bevel(bx, byy, bw, bh, 1);
            [[3, 3], [bw - 5, 3], [3, bh - 5], [bw - 5, bh - 5]].forEach(p => { S.px(bx + p[0], byy + p[1], 2, 2, 3); S.px(bx + p[0], byy + p[1], 1, 1, 0); });
            // combination window: 3 wheels
            S.px(bx + 8, byy + 8, bw - 16, 16, 3);
            S.px(bx + 9, byy + 9, bw - 18, 14, 0);
            const stops = [12, 16, 20];
            const digits = ['0', '0', '1'];
            for (let w = 0; w < 3; w++) {
              const wx = bx + 11 + w * 11, wy = byy + 10;
              if (f >= 6 && f < stops[w]) {
                S.dither(wx, wy, 8, 12, 1, 0);
                S.tiny(String((f + w * 3) % 10), wx + 1, wy + (f % 2), 2, 2);
              } else if (f >= stops[w]) {
                S.tiny(digits[w], wx + 1, wy + 1, 3, 2);
                S.px(wx, wy + 11, 8, 1, 2);
              } else {
                S.tiny(String((7 + w * 4) % 10), wx + 1, wy + 1, 2, 2);
              }
            }
            if (f >= 3 && f <= 5) { S.sprite(SPR.dust, 44 - (f - 3) * 3, 88 - (f - 3) * 2); S.sprite(SPR.dust, 112 + (f - 3) * 3, 88 - (f - 3) * 2); }
            if (f >= 25 && f <= 27) { S.sprite(SPR.dust, 46 - (f - 25) * 4, 54); S.sprite(SPR.dust, 110 + (f - 25) * 4, 54); }
            // shine sweep
            if (f >= 28 && f <= 34) {
              const sx = bx + 4 + (f - 28) * 7;
              for (let k = 0; k < bh - 4; k++) {
                const xx = sx - k;
                if (xx > bx + 1 && xx < bx + bw - 2) S.px(xx, byy + 2 + k, 2, 1, 0);
              }
            }
            if (f >= 30) {
              if (f % 4 < 2) S.sprite(SPR.star, 40, 36); else S.sprite(SPR.twinkle, 41, 37);
              if ((f + 2) % 4 < 2) S.sprite(SPR.star, 114, 30); else S.sprite(SPR.twinkle, 115, 31);
            }
            S.textBox('LOCKED!', 'HW ANCHOR SET', f, 31);
          }
        },

        // ============ SECURE LINK · VAULT ============
        vault: {
          frames: 52, holdBlink: true, title: 'SECURE LINK · VAULT',
          sfx: { 3: 'tick', 4: 'tick', 5: 'tick', 6: 'tick', 7: 'tick', 8: 'tick', 10: 'tick', 11: 'tick', 12: 'tick', 13: 'tick', 14: 'tick', 15: 'tick', 16: 'thunk', 17: 'thunk', 18: 'thunk', 19: 'thunk', 20: 'clunk', 22: 'blipHi', 26: 'key', 28: 'key', 30: 'key', 32: 'key', 40: 'win' },
          draw(S, f) {
            S.clear(0);
            if (f === 20) S.shake(1, 1);
            S.brickBG();
            const cx = 80, cy = 54;
            const nB = Math.max(0, Math.min(4, f - 15));
            const bolt = (x, y, w, h) => { S.px(x, y, w, h, 3); S.px(x + 1, y + 1, w - 2, 1, 1); };
            if (nB >= 1) bolt(116, 50, 12, 8);
            if (nB >= 2) bolt(76, 90, 8, 12);
            if (nB >= 3) bolt(32, 50, 12, 8);
            if (nB >= 4) bolt(76, 8, 8, 12);
            S.disc(cx, cy, 34, 1);
            S.circle(cx, cy, 36, 3, 2); S.circle(cx, cy, 34, 3, 1);
            S.circle(cx, cy, 33, 0, 1, Math.PI * 0.9, Math.PI * 1.6);
            S.circle(cx, cy, 33, 2, 1, Math.PI * 0.05, Math.PI * 0.55);
            S.circle(cx, cy, 24, 2, 1);
            for (let k = 0; k < 8; k++) {
              const a = k * TAU / 8 + TAU / 16;
              const rx = Math.round(cx + Math.cos(a) * 29), ry = Math.round(cy + Math.sin(a) * 29);
              S.px(rx - 1, ry - 1, 3, 3, 3); S.px(rx - 1, ry - 1, 1, 1, 0);
            }
            const ANG = [0, 30, 60, 90, 120, 150, 180, 150, 120, 90, 120, 150, 180];
            const deg = f < 3 ? 0 : ANG[Math.min(f - 3, ANG.length - 1)];
            const th = deg * Math.PI / 180;
            S.circle(cx, cy, 16, 3, 3);
            for (let k = 0; k < 3; k++) {
              const a = th + k * TAU / 3;
              S.line(cx + Math.cos(a) * 4, cy + Math.sin(a) * 4, cx + Math.cos(a) * 15, cy + Math.sin(a) * 15, 3, 3);
              S.px(Math.round(cx + Math.cos(a) * 14) - 1, Math.round(cy + Math.sin(a) * 14) - 1, 3, 3, 0);
            }
            S.disc(cx, cy, 5, 3);
            S.px(cx - 1, cy - 1, 2, 2, (f >= 21 && f % 4 < 2) ? 0 : 2);
            if (f >= 21 && f <= 24 && f % 2 === 1) S.circle(cx, cy, 38, 2, 1);
            S.textBox('VAULT SEALED', 'ANCHORED: T01', f, 25);
          }
        },

        // ============ BT PAIRING ============
        pair: {
          frames: 52, holdBlink: true, title: 'BT PAIRING · PICO LINK',
          sfx: { 1: 'blipLo', 4: 'blip', 6: 'blip', 8: 'blipHi', 9: 'blip', 11: 'blip', 13: 'blipHi', 14: 'blip', 15: 'blip', 16: 'blipHi', 17: 'blipHi', 18: 'tick', 19: 'tick', 20: 'chirp', 22: 'blip', 24: 'win', 28: 'key', 30: 'key', 32: 'key', 34: 'key' },
          draw(S, f) {
            S.clear(0);
            S.brickBG();
            S.floor(92, 1, 0);
            const gbX = [-30, -10, 4, 12][Math.min(f, 3)];
            const picoX = [162, 142, 124, 112][Math.min(f, 3)];
            S.shadow(gbX + 13, 90, 15);
            S.shadow(picoX + 20, 90, 22);
            const flashGB = f >= 22 && f <= 25 && f % 2 === 0;
            S.gbDevice(gbX, 42, flashGB ? 3 : null);
            S.pico(picoX, 64, f >= 20 ? true : (f % 4 < 2));
            for (let x = 44; x <= 104; x += 6) S.px(x, 63, 2, 1, 2);
            const pk = (px, py) => S.sprite(SPR.packet, px, py);
            if (f >= 4 && f <= 8) pk(42 + (f - 4) * 15, 56);
            if (f >= 9 && f <= 13) pk(102 - (f - 9) * 15, 56);
            if (f >= 14 && f <= 17) { pk(48 + (f - 14) * 18, 48); pk(96 - (f - 14) * 18, 66); }
            const nGB = f >= 22 ? 4 : f >= 16 ? 3 : f >= 13 ? 2 : f >= 8 ? 1 : 0;
            S.rssi(14, 28, nGB);
            S.rssi(126, 48, nGB);
            // Bluetooth rune: blinks while searching, locks solid on link
            if (f >= 18) {
              S.spriteS(SPR.bt, 71, 18, 2);
              if (f <= 20) S.burst(80, 32, 18, 24, 3);
            } else if (f >= 4) {
              if (f % 2 === 0) S.spriteS(SPR.bt, 71, 18, 2);
            }
            if (f >= 22 && f <= 30) {
              const rise = (f - 22) * 3;
              S.sprite(SPR.note, 30 + (f % 2), 30 - rise);
              S.sprite(SPR.note, 122 - (f % 2), 44 - rise);
            }
            S.textBox('PAIRED!', 'LINK QUALITY OK', f, 27);
          }
        },

        // ============ TX CONFIRMED / FAILED · shared choreography ============
        confirm: bagScene(true),
        fail: bagScene(false),

        // ============ TAMPER / CLONE ============
        tamper: {
          frames: 52, holdBlink: true, title: 'TAMPER · CLONE DETECT',
          sfx: { 2: 'tick', 4: 'tick', 6: 'tick', 8: 'tick', 9: 'blipLo', 10: 'blipLo', 12: 'alarmA', 14: 'alarmB', 16: 'alarmA', 18: 'alarmB', 20: 'buzz', 23: 'key', 25: 'key', 27: 'key', 29: 'key', 31: 'key' },
          draw(S, f) {
            S.inv(f >= 12 && f <= 19 && f % 2 === 1);
            S.clear(0);
            const shk = (f >= 12 && f <= 19) ? (f % 2 ? 1 : -1) : 0;
            S.dashFrame(20, 36, 48, 40, 2);
            S.dashFrame(92, 36, 48, 40, 2);
            S.chipBig(24, 40, 40, 32, 'T01', 'solid', shk);
            if (f >= 2 && f <= 8) {
              const bx = 94 + (f - 2) * 6;
              S.px(bx, 34, 2, 44, 3);
              S.speckle(96, 36, bx - 96, 40, 2, 5);
            }
            if (f === 8) S.chipBig(96, 40, 40, 32, null, 'g25', shk);
            else if (f === 9) S.chipBig(96, 40, 40, 32, null, 'g50', shk);
            else if (f >= 10) S.chipBig(96, 40, 40, 32, null, 'skull', shk);
            if (f >= 12) {
              const ty = f === 12 ? -8 : f === 13 ? 8 : 4;
              S.line(80, ty, 94, ty + 22, 2, 3);
              S.line(80, ty, 66, ty + 22, 2, 3);
              S.line(66, ty + 22, 94, ty + 22, 2, 3);
              if (f % 4 < 2 || f < 20) S.text('!', 80, ty + 9, 3, true);
            }
            if (f >= 20) {
              S.line(94, 38, 138, 74, 6, 3);
              S.line(138, 38, 94, 74, 6, 3);
              S.line(94, 38, 138, 74, 2, 0);
              S.line(138, 38, 94, 74, 2, 0);
            }
            if (f >= 12) S.hazardBorder(f);
            S.textBox('CLONE DETECTED', 'LINK REFUSED', f, 22);
          }
        },

        // ============ OFFLINE TX · SEALED ============
        seal: {
          frames: 54, holdBlink: true, title: 'OFFLINE TX · SEALED',
          sfx: { 1: 'key', 3: 'key', 5: 'key', 7: 'key', 9: 'key', 11: 'key', 13: 'key', 14: 'blipLo', 16: 'tick', 17: 'tick', 18: 'clunk', 22: 'blipHi', 26: 'key', 28: 'key', 30: 'key', 32: 'key', 38: 'win' },
          draw(S, f) {
            S.clear(0);
            if (f === 18) S.shake(0, 2);
            const ph = Math.min(74, Math.max(0, f) * 6);
            const pTop = 20, pBot = pTop + ph;
            if (ph > 2) {
              S.px(48, pTop, 64, ph, 0);
              S.px(48, pTop, 1, ph, 3); S.px(111, pTop, 1, ph, 3);
              for (let k = 0; k < ph; k += 4) { S.px(46, pTop + k, 2, 2, 2); S.px(112, pTop + k, 2, 2, 2); }
              if (f < 13) { for (let x = 50; x < 110; x += 4) S.px(x, pBot - 1, 2, 1, 3); }
              else S.px(48, pBot, 64, 1, 3);
              const ROWS = [[40, 2], [52, 2], [30, 2], ['1', 0], [46, 2], [24, 2]];
              for (let j = 0; j < 6; j++) {
                const ry = pBot - 8 - j * 10;
                if (ry > pTop + 3) {
                  const rw = ROWS[j][0];
                  if (rw === '1') S.tiny('+12.50', 56, ry - 2, 3, 1);
                  else S.px(54, ry, rw, 2, 2);
                }
              }
            }
            S.bevel(28, 6, 104, 16, 2);
            S.px(40, 19, 80, 3, 3);
            S.px(34, 10, 3, 3, (f < 14 && f % 2 === 0) ? 0 : 3);
            S.px(120, 10, 6, 2, 1); S.px(120, 14, 6, 2, 1);
            if (f >= 15 && f <= 21) {
              const sy = [-20, 4, 24, 40, 40, 24, -2][f - 15];
              S.px(76, sy - 14, 8, 16, 3);
              S.px(77, sy - 12, 2, 12, 2);
              S.bevel(64, sy, 32, 12, 2);
              if (f === 18) {
                S.sprite(SPR.star, 56, 60); S.sprite(SPR.star, 100, 60);
                S.sprite(SPR.twinkle, 60, 78); S.sprite(SPR.twinkle, 98, 78);
              }
            }
            if (f >= 19) {
              S.disc(80, 66, 13, 3);
              S.circle(80, 66, 10, 0, 1);
              S.miniLock(80, 63, 0);
              if (f >= 22) {
                if (f % 4 < 2) S.sprite(SPR.twinkle, 92, 56); else S.sprite(SPR.twinkle, 66, 74);
              }
            }
            S.textBox('SIGNED+SEALED', 'OFFLINE READY', f, 25);
          }
        }
      };
    }

    // ---------- player ----------
    play(name) {
      const anims = this.ANIMS();
      if (!anims[name]) return;
      this._cur = name;
      this._t0 = performance.now();
      this._lastF = -1;
      if (!this._raf) this._raf = requestAnimationFrame(this._step);
    }

    _step = () => {
      this._raf = null;
      if (!this._connected) return;
      const a = this.ANIMS()[this._cur];
      if (!a || !this._cv) return;
      let f = Math.floor((performance.now() - this._t0) / 1000 * this.fps());
      const last = a.frames - 1;
      const df = a.holdBlink ? f : Math.min(f, last);
      if (df !== this._lastF) {
        this._lastF = df;
        const s = a.sfx && a.sfx[df];
        if (s) (Array.isArray(s) ? s : [s]).forEach(n => this.playSfx(n));
        const ctx = this._cv.getContext('2d');
        ctx.save();
        ctx.imageSmoothingEnabled = false;
        const S = this.mkS(ctx, this._cv);
        ctx.translate(0, S.dy);
        try { a.draw(S, df); } catch (e) {}
        ctx.restore();
      }
      if (f < last || a.holdBlink) this._raf = requestAnimationFrame(this._step);
    };
  }

  customElements.define('fx-canvas', FxCanvas);
})();
