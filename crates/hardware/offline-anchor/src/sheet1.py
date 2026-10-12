# SPDX-License-Identifier: MIT OR Apache-2.0
"""Sheet 1 — wiring & pinout. No dependencies.   Run: python3 sheet1.py"""
import os

from common import *

S = 8.0  # px per mm for the board drawings

PICO_LEFT = ["GP0", "GP1", "GND", "GP2", "GP3", "GP4", "GP5", "GND", "GP6", "GP7",
             "GP8", "GP9", "GND", "GP10", "GP11", "GP12", "GP13", "GND", "GP14", "GP15"]  # pins 1..20
PICO_RIGHT = ["VBUS", "VSYS", "GND", "3V3_EN", "3V3(OUT)", "ADC_VREF", "GP28", "AGND", "GP27", "GP26",
              "RUN", "GP22", "GND", "GP21", "GP20", "GP19", "GP18", "GND", "GP17", "GP16"]  # pins 40..21

# net: (id, signal, pico pin number, click left-header index, colour, short tag)
WIRES = [
    ("W1", "SPI SCK", 24, 3, "#ffd23f", "SCK"),
    ("W2", "SPI MOSI", 25, 5, "#3ddc84", "SDI"),
    ("W3", "SPI MISO", 21, 4, "#f4f4f4", "SDO"),
    ("W4", "CHIP SELECT", 22, 2, "#ff9f1c", "CS"),
    ("W5", "+3.3 V", 36, 6, "#ff5d5d", "3V3"),
    ("W6", "GROUND", 23, 7, "#1b1b1b", "GND"),
]
USED_PICO = {w[2] for w in WIRES}

CLICK_LEFT = ["NC", "NC", "CS", "SCK", "SDO", "SDI", "3V3", "GND"]
CLICK_LEFT_BUS = ["AN", "RST", "CS", "SCK", "MISO", "MOSI", "3.3V", "GND"]
CLICK_RIGHT = ["NC", "GPO", "NC", "NC", "NC", "NC", "NC", "GND"]


def pico_pin_xy(px, py, pin):
    if pin <= 20:
        i = pin - 1
        x = px + 1.61 * S
    else:
        i = 40 - pin
        x = px + (21 - 1.61) * S
    return x, py + (1.37 + i * 2.54) * S


def draw_pico(s, px, py):
    w, h = 21 * S, 51 * S
    # USB connector (protrudes 1.3 mm past the board edge)
    s.rect(px + (21 - 8) / 2 * S, py - 1.3 * S, 8 * S, 5.6 * S, sw=1.2, fill=BG)
    s.text(px + w / 2, py - 1.3 * S - 10, "micro-USB → phone (OTG) / host", size=10, fill=INK_DIM, anchor="middle")
    s.rect(px, py, w, h, sw=1.8, rx=4)
    s.rect(px + (21 - 8) / 2 * S, py - 1.3 * S, 8 * S, 5.6 * S, sw=1.2, fill=BG)
    # mounting holes Ø2.1 at 11.4 x 47
    for hx in (4.8, 16.2):
        for hy in (2.0, 49.0):
            s.circle(px + hx * S, py + hy * S, 1.05 * S, sw=1)
    # BOOTSEL (2.5 mm left of centre, 14.5 mm from USB edge), LED near USB, RP2350, radio module
    s.rect(px + (8.0 - 1.5) * S, py + (14.5 - 2.0) * S, 3 * S, 4 * S, sw=1, rx=2)
    s.circle(px + 8.0 * S, py + 14.5 * S, 0.9 * S, sw=1, fill=INK_DIM)
    s.rect(px + 7.0 * S, py + 21.0 * S, 7 * S, 7 * S, sw=1, rx=2)
    s.text(px + 10.5 * S, py + 25.2 * S, "RP2350", size=10, anchor="middle")
    s.rect(px + 6.0 * S, py + 33.0 * S, 9 * S, 8.5 * S, sw=0.9, dash="3 2")
    s.text(px + 10.5 * S, py + 37.4 * S, "CYW43439", size=9, fill=INK_DIM, anchor="middle")
    s.text(px + 10.5 * S, py + 39.0 * S, "(radio unused)", size=8, fill=INK_DIM, anchor="middle")
    for k in range(3):  # SWD pads at the far end
        s.circle(px + (8.0 + k * 2.54) * S, py + 44.4 * S, 0.45 * S, sw=0.9)
    s.text(px + 10.5 * S, py + 43.0 * S, "SWD", size=8, fill=INK_DIM, anchor="middle")
    # pins
    for pin in range(1, 41):
        x, y = pico_pin_xy(px, py, pin)
        used = pin in USED_PICO
        edge = px if pin <= 20 else px + w
        pw = 1.6 * S
        rx0 = edge if pin <= 20 else edge - pw
        s.rect(rx0, y - 0.8 * S, pw, 1.6 * S, sw=0.8, fill=ACCENT if used else "none",
               stroke=ACCENT if used else INK_DIM)
        s.circle(x, y, 0.5 * S, sw=0.8, fill=BG if used else "none", stroke=ACCENT if used else INK)
        name = PICO_LEFT[pin - 1] if pin <= 20 else PICO_RIGHT[40 - pin]
        col = ACCENT if used else (INK if "GND" not in name else INK_DIM)
        near_hole = pin in (19, 20, 21, 22)
        backed = pin in (1, 2, 39, 40)
        if backed:
            bw = len(name) * 6.2 + 4
            bx = x + 0.9 * S - 2 if pin <= 20 else x - 0.9 * S - bw + 2
            s.rect(bx, y - 6, bw, 12, fill=BG, stroke=BG, sw=0)
        if pin <= 20:
            s.text(x + (4.6 if near_hole else 0.9) * S, y + 3.5, name, size=10, fill=col)
            s.text(px - 6, y + 3.5, str(pin), size=9, fill=INK_DIM, anchor="end")
        else:
            lx = x - (4.6 if near_hole else 0.9) * S
            s.text(lx, y + 3.5, name, size=10, fill=col, anchor="end",
                   weight="bold" if used else "normal")
            s.text(lx - len(name) * 6.3 - 4, y + 3.5, str(pin), size=8, fill=INK_DIM, anchor="end")
    s.text(px + w / 2, py + h + 22, "RASPBERRY PI PICO 2 W", size=13, anchor="middle", weight="bold", spacing=1)
    s.text(px + w / 2, py + h + 38, "component side up · USB toward top", size=10, fill=INK_DIM, anchor="middle")
    s.text(px - 6, py + 2, "PIN", size=9, fill=INK_DIM, anchor="end")
    # dims
    s.hdim(px, px + w, py + h + 62, py + h, "21.0")
    s.vdim(py, py + h, px - 46, px, "51.0")


def click_pad_xy(cx, cy, side, k):
    x = cx + (1.27 if side == "L" else 25.4 - 1.27) * S
    return x, cy + (21.0 + k * 2.54) * S


def draw_click(s, cx, cy):
    w, h = 25.4 * S, 42.9 * S
    c = 3.2 * S
    s.path(f"M{cx},{cy+2*S} Q{cx},{cy} {cx+2*S},{cy} L{cx+w-2*S},{cy} Q{cx+w},{cy} {cx+w},{cy+2*S} "
           f"L{cx+w},{cy+h-c} L{cx+w-c},{cy+h} L{cx},{cy+h} Z", sw=1.8)
    # Click Snap section (stays attached)
    mx, my, mw, mh = cx + 5.2 * S, cy + 0.8 * S, 15.0 * S, 12.6 * S
    s.path(f"M{mx-1*S},{cy} L{mx-1*S},{my+mh+1*S} L{mx+mw+1*S},{my+mh+1*S} L{mx+mw+1*S},{cy}",
           stroke=INK_DIM, sw=0.8, dash="4 3")
    s.rect(mx, my, mw, mh, sw=1, rx=3)
    for hx, hy in ((1.6, 1.7), (13.4, 1.7), (1.6, 7.6), (13.4, 7.6)):
        s.circle(mx + hx * S, my + hy * S, 1.0 * S, sw=0.9)
    s.rect(cx + (12.7 - 2) * S, cy + 3.0 * S, 4 * S, 4 * S, sw=1.2, fill="#173f69")
    s.text(cx + 12.7 * S, cy + 5.4 * S, "U1", size=9, anchor="middle", weight="bold")
    s.text(cx + 12.7 * S, cy + 8.6 * S, "TROPIC01", size=10, fill=ACCENT, anchor="middle", weight="bold")
    for row_y in (11.6, 15.8):
        for k in range(8):
            s.circle(cx + (7.4 + k * 1.52) * S, cy + row_y * S, 0.4 * S, sw=0.7, stroke=INK_DIM)
    s.text(cx + 12.7 * S, cy + 18.3 * S, "Snap pads — leave unused", size=8, fill=INK_DIM, anchor="middle")
    # headers
    for side, names in (("L", CLICK_LEFT), ("R", CLICK_RIGHT)):
        for k, nm in enumerate(names):
            x, y = click_pad_xy(cx, cy, side, k)
            used = side == "L" and nm != "NC"
            s.circle(x, y, 0.85 * S, sw=1, fill=ACCENT if used else "none", stroke=ACCENT if used else INK_DIM)
            s.circle(x, y, 0.42 * S, sw=0.7, fill=BG, stroke=BG if used else INK_DIM)
            if side == "L":
                s.rect(x + 1.3 * S, y - 1.0 * S, 5.6 * S, 2.0 * S, sw=0.7, stroke=ACCENT if used else INK_DIM)
                s.text(x + 4.1 * S, y + 3.5, nm, size=10, anchor="middle", fill=ACCENT if used else INK_DIM,
                       weight="bold" if used else "normal")
            else:
                s.rect(x - 6.9 * S, y - 1.0 * S, 5.6 * S, 2.0 * S, sw=0.7, stroke=INK_DIM)
                s.text(x - 4.1 * S, y + 3.5, nm, size=10, anchor="middle", fill=INK_DIM)
    s.rect(cx + 15.6 * S, cy + 40.4 * S, 2.0 * S, 1.0 * S, sw=0.8)
    s.text(cx + 16.6 * S, cy + 39.6 * S, "PWR", size=8, fill=INK_DIM, anchor="middle")
    s.text(cx + 12.7 * S, cy + 27.0 * S, "Secure", size=10, anchor="middle", fill=INK_DIM)
    s.text(cx + 12.7 * S, cy + 28.8 * S, "Tropic", size=10, anchor="middle", fill=INK_DIM)
    s.text(cx + 12.7 * S, cy + 30.6 * S, "Click", size=10, anchor="middle", fill=INK_DIM)
    s.text(cx + w / 2, cy + h + 22, "MIKROE SECURE TROPIC CLICK", size=13, anchor="middle", weight="bold", spacing=1)
    s.text(cx + w / 2, cy + h + 38, "MIKROE-6559 · component side up", size=10, fill=INK_DIM, anchor="middle")
    s.hdim(cx, cx + w, cy + h + 62, cy + h, "25.4")
    s.vdim(cy, cy + h, cx + w + 40, cx + w, "42.9", left=False)
    for k, nm in enumerate(CLICK_LEFT_BUS):  # bus names outside, left of the pads (small)
        pass


def draw_detail(s, x0, y0):
    """Detail A: wire entry through plated holes, scale 10:1."""
    K = 18.0
    s.text(x0, y0, "DETAIL A · WIRE ENTRY (section, 10:1 approx.)", size=14, weight="bold", spacing=1)
    def board(bx, by, thick, name):
        wlen = 9 * K
        s.rect(bx, by, wlen, thick * K, fill="url(#hatch)", sw=1.2)
        # plated hole
        hx = bx + wlen / 2
        s.rect(hx - 0.55 * K, by - 0.5, 1.1 * K, thick * K + 1, fill=BG, stroke=BG, sw=0)
        s.line(hx - 0.55 * K, by, hx - 0.55 * K, by + thick * K, stroke=ACCENT, w=2)
        s.line(hx + 0.55 * K, by, hx + 0.55 * K, by + thick * K, stroke=ACCENT, w=2)
        s.text(bx + wlen + 8, by + thick * K / 2 + 4, name, size=11, fill=INK_DIM)
        return hx
    # Pico: wire comes up from below, joint on top, trimmed flush
    bx, by = x0 + 10, y0 + 60
    hx = board(bx, by, 1.0, "Pico 2 W, 1.0 thk")
    s.path(f"M{hx-0.9*K},{by} Q{hx},{by-0.9*K} {hx+0.9*K},{by}", stroke=ACCENT, sw=1.6, fill=ACCENT)
    s.rect(hx - 0.3 * K, by - 0.15 * K, 0.6 * K, 1.0 * K + 0.15 * K + 3.2 * K, fill="#ffd23f", stroke=INK, sw=0.8)
    s.leader(hx + 0.6 * K, by - 0.45 * K, hx + 3.2 * K, by - 1.6 * K, "solder on top, trim flush", size=11)
    s.text(hx, by + 4.9 * K, "↓ to Click", size=11, fill=INK_DIM, anchor="middle")
    s.text(bx, by + 5.9 * K, "PICO: insert from the UNDERSIDE", size=11)
    # Click: wire comes down from above, joint underneath, short trim (sits on ledges)
    bx2, by2 = x0 + 400, y0 + 60 + 3.2 * K
    hx2 = board(bx2, by2, 1.6, "Click, 1.6 thk")
    s.rect(hx2 - 0.3 * K, by2 - 3.2 * K, 0.6 * K, 3.2 * K + 1.6 * K + 0.15 * K, fill="#ffd23f", stroke=INK, sw=0.8)
    yb = by2 + 1.6 * K
    s.path(f"M{hx2-0.9*K},{yb} Q{hx2},{yb+0.9*K} {hx2+0.9*K},{yb}", stroke=ACCENT, sw=1.6, fill=ACCENT)
    s.text(hx2, by2 - 3.6 * K, "↓ from Pico", size=11, fill=INK_DIM, anchor="middle")
    s.leader(hx2 + 0.6 * K, yb + 0.45 * K, hx2 + 5.6 * K, yb + 0.45 * K, "solder underneath, trim ≤ 1 mm", size=11)
    s.text(bx2, by2 + 4.2 * K, "CLICK: insert from the COMPONENT SIDE", size=11)
    s.text(bx2, by2 + 4.2 * K + 17, "The Click rests on 3.5 mm ledges (1.9 mm above the floor).", size=10, fill=INK_DIM)


def bez(p0, p1, p2, p3, t):
    u = 1 - t
    return (u**3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t**3 * p3[0],
            u**3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t**3 * p3[1])


def build():
    s = Svg()
    sheet_open(s, "DSM Offline Anchor — Sheet 1 — Wiring & Pinout")
    s.text(52, 66, "SHEET 1 · WIRING & PINOUT", size=22, weight="bold", spacing=2)
    s.text(52, 88, "Six wires, soldered directly into the plated holes. No headers, no other parts.",
           size=12, fill=INK_DIM)

    px, py = 150, 160
    cx, cy = 740, 175
    draw_pico(s, px, py)
    draw_click(s, cx, cy)

    # harness
    mids = []
    order = [4, 3, 0, 1, 2, 5]  # draw 3V3 first so it sits beneath the bus
    for idx in order:
        wid, sig, pin, k, colr, tag = WIRES[idx]
        x0, y0 = pico_pin_xy(px, py, pin)
        x0 = px + 21 * S  # leave from the castellated edge
        x3, y3 = click_pad_xy(cx, cy, "L", k)
        x3 -= 0.85 * S
        p0, p3 = (x0, y0), (x3, y3)
        p1, p2 = (x0 + 170, y0), (x3 - 170, y3)
        d = f"M{x0:.1f},{y0:.1f} C{p1[0]:.1f},{p1[1]:.1f} {p2[0]:.1f},{p2[1]:.1f} {x3:.1f},{y3:.1f}"
        s.path(d, stroke=BG, sw=9)
        s.path(d, stroke=INK, sw=6)
        s.path(d, stroke=colr, sw=4)
        tpos = {"W1": 0.80, "W2": 0.30, "W3": 0.12, "W4": 0.93, "W5": 0.38, "W6": 0.55}[wid]
        mids.append((wid, bez(p0, p1, p2, p3, tpos)))
    for wid, (mx, my) in mids:
        s.balloon(mx, my, wid, r=13)

    # ---- net table -----------------------------------------------------------------------------
    tx, ty = 1046, 120
    cols = [("WIRE", 46), ("SIGNAL", 104), ("PICO 2 W", 86), ("PIN", 76), ("CLICK", 56), ("DIR", 80),
            ("COLOUR*", 0)]
    widths = [c[1] for c in cols]
    tw = 512
    s.text(tx, ty - 12, "HARNESS / NET LIST", size=14, weight="bold", spacing=1)
    s.rect(tx, ty, tw, 28 + 30 * len(WIRES), sw=1.4, fill=BG)
    xx = tx
    for (name, wd) in cols:
        s.text(xx + 8, ty + 19, name, size=10, fill=INK_DIM)
        xx += wd
    s.line(tx, ty + 28, tx + tw, ty + 28, w=1)
    gpio = {24: "GP18", 25: "GP19", 21: "GP16", 22: "GP17", 36: "3V3(OUT)", 23: "GND"}
    dirs = {"SCK": "Pico → SE", "SDI": "Pico → SE", "SDO": "SE → Pico", "CS": "Pico → SE", "3V3": "supply",
            "GND": "return"}
    cname = {"#ffd23f": "yellow", "#3ddc84": "green", "#f4f4f4": "white", "#ff9f1c": "orange",
             "#ff5d5d": "red", "#1b1b1b": "black"}
    for r, (wid, sig, pin, k, colr, tag) in enumerate(WIRES):
        yy = ty + 28 + r * 30
        if r:
            s.line(tx, yy, tx + tw, yy, w=0.5, stroke=INK_DIM)
        vals = [wid, sig, gpio[pin], str(pin) + (" / 38" if pin == 23 else ""), tag, dirs[tag], cname[colr]]
        xx = tx
        for i, v in enumerate(vals):
            fill = ACCENT if i in (2, 4) else INK
            if i == 6:
                s.rect(xx + 6, yy + 10, 12, 12, sw=0.8, fill=colr, stroke=INK)
                s.text(xx + 24, yy + 20, v, size=10)
                break
            s.text(xx + 8, yy + 20, v, size=11, fill=fill, weight="bold" if i == 0 else "normal")
            xx += widths[i]

    # ---- SPI parameters box --------------------------------------------------------------------
    by = ty + 28 + 30 * len(WIRES) + 44
    s.text(tx, by - 10, "BUS PARAMETERS (fixed in firmware)", size=14, weight="bold", spacing=1)
    s.rect(tx, by, tw, 128, sw=1.4, fill=BG)
    rows = [("Peripheral", "RP2350 SPI0 · 8-bit frames"),
            ("Mode / clock", "MODE 0 (CPOL 0, CPHA 0) · 1 MHz"),
            ("Chip select", "GP17 as push-pull GPIO, driven by firmware"),
            ("Logic / supply", "3.3 V only · Pico 3V3(OUT) pin 36"),
            ("Source of truth", "crates/dsm-anchor-pico/src/main.rs"),
            ("", "crates/dsm-anchor-secure-monitor/src/tropic.rs")]
    for i, (k, v) in enumerate(rows):
        s.text(tx + 10, by + 22 + i * 19, k, size=10, fill=INK_DIM)
        s.text(tx + 150, by + 22 + i * 19, v, size=11)

    # ---- notes ---------------------------------------------------------------------------------
    ny = by + 128 + 34
    s.text(tx, ny - 10, "NOTES", size=14, weight="bold", spacing=1)
    notes = [
        ("1", "3.3 V ONLY. Never connect VBUS or VSYS (5 V) to the Click."),
        ("2", "No pin headers. Solder each wire straight into the plated"),
        ("", "hole on both boards — headers will not fit the pocket case."),
        ("3", "Leave GPO, every NC pad and the Snap pads unconnected."),
        ("4", "Do not snap off the Click Snap module; the case is sized"),
        ("", "for the whole Click."),
        ("5", "28–30 AWG stranded silicone wire, 60–80 mm per lead."),
        ("6", "*Colours are a suggestion; signal names govern."),
        ("7", "Boards are drawn side by side for clarity. Installed, the"),
        ("", "Click lies under the Pico (see Sheet 2)."),
    ]
    for i, (n, t) in enumerate(notes):
        yy = ny + 8 + i * 18
        if n:
            s.text(tx + 4, yy, n + ".", size=11, fill=ACCENT, weight="bold")
        s.text(tx + 26, yy, t, size=11)

    draw_detail(s, 110, 690)

    # legend
    lx, ly = 150, 1000
    s.text(lx, ly - 14, "LEGEND", size=12, weight="bold", spacing=1)
    s.rect(lx, ly - 6, 14, 10, fill=ACCENT, stroke=ACCENT, sw=0.8)
    s.text(lx + 22, ly + 3, "pad used by the harness", size=11)
    s.rect(lx, ly + 14, 14, 10, stroke=INK_DIM, sw=0.8)
    s.text(lx + 22, ly + 23, "pad left unconnected", size=11)
    s.balloon(lx + 7, ly + 44, "W", r=9)
    s.text(lx + 22, ly + 48, "wire number (see net list)", size=11)
    s.text(lx + 300, ly + 3, "SE = secure element (TROPIC01)", size=11, fill=INK_DIM)
    s.text(lx + 300, ly + 23, "Component outlines on both boards are indicative.", size=11, fill=INK_DIM)
    s.text(lx + 300, ly + 43, "Pin names and pad positions are exact.", size=11, fill=INK_DIM)

    title_block(s, "SHEET 1 — WIRING & PINOUT", "1 / 2")
    return sheet_close(s)


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    open(os.path.join(here, "..", "sheet-1-wiring.svg"), "w").write(build())
