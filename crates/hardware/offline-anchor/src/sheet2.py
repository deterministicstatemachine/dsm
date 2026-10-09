# SPDX-License-Identifier: MIT OR Apache-2.0
"""Sheet 2 — enclosure (REV E) & stack-up. Geometry is traced from ../enclosure/{base,lid}.stl.

Requires: pip install trimesh numpy   ·   Run: python3 sheet2.py
"""
import os

import numpy as np
import trimesh
from common import *

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = trimesh.load(os.path.join(HERE, "..", "enclosure", "base.stl"))
LID = trimesh.load(os.path.join(HERE, "..", "enclosure", "lid.stl"))
LID_PLATE = 2.0
WALL_TOP = 13.8


def zloops(mesh, z):
    sec = mesh.section(plane_origin=[0, 0, z], plane_normal=[0, 0, 1])
    return [] if sec is None else [e[:, :2] for e in sec.discrete]


def poly_d(pts, tx):
    p = [tx(x, y) for x, y in pts]
    return "M" + " L".join(f"{a:.2f},{b:.2f}" for a, b in p) + " Z"


def bbox(e):
    return e[:, 0].min(), e[:, 0].max(), e[:, 1].min(), e[:, 1].max()


# --------------------------------------------------------------------------------------------------
def view_base(s, ox, oy, K):
    """Top view of the base, looking down. ox,oy = SVG position of model origin."""
    tx = lambda x, y: (ox + x * K, oy - y * K)
    outer = max(zloops(BASE, 0.3), key=lambda e: np.ptp(e[:, 0]) * np.ptp(e[:, 1]))
    s.path(poly_d(outer, tx), sw=2.0, fill="#123f6e")
    # inner wall line (cavity) at mid-height
    for e in zloops(BASE, 7.0):
        x0, x1, y0, y1 = bbox(e)
        if x1 - x0 > 20:
            if x1 - x0 < 30:
                s.path(poly_d(e, tx), sw=1.4, fill=BG)
    # lanyard hole
    for e in zloops(BASE, 1.0):
        x0, x1, y0, y1 = bbox(e)
        if x1 - x0 < 5:
            s.path(poly_d(e, tx), sw=1.2, fill=BG)
    # floor features at z=2.5 (ribs, far-end bar, USB-end bridge) — draw cavity loop with ribs
    for e in zloops(BASE, 2.5):
        x0, x1, y0, y1 = bbox(e)
        if 20 < x1 - x0 < 30:
            s.path(poly_d(e, tx), sw=0.9, stroke=INK_DIM, dash="5 3")
        elif x1 - x0 < 19 and y1 - y0 < 6 and abs(x0 + x1) < 1:
            s.path(poly_d(e, tx), sw=1.0, fill="url(#hatch)")
    # standoffs + pilots (z=6)
    for e in zloops(BASE, 6.0):
        x0, x1, y0, y1 = bbox(e)
        if 4 < x1 - x0 < 5.5 and abs(abs((x0 + x1) / 2) - 5.7) < 0.3:
            s.path(poly_d(e, tx), sw=1.3, fill="#123f6e")
        if x1 - x0 < 2 and abs(abs((x0 + x1) / 2) - 5.7) < 0.3:
            s.path(poly_d(e, tx), sw=1.0, fill=BG)
    # lid-screw bosses (moved outward with the walls in REV E)
    for sx in (-1, 1):
        a, b = tx(sx * 11.95, 22.0)
        c, d = tx(sx * 13.85, 17.0)
        s.rect(min(a, c), b, abs(c - a), d - b, stroke=ACCENT, sw=1.2, fill="url(#hatchA)")
    # lid screw pilots in the wall (z=12)
    for e in zloops(BASE, 12.0):
        x0, x1, y0, y1 = bbox(e)
        if x1 - x0 < 2:
            s.path(poly_d(e, tx), sw=1.0, fill=BG)
    # phantom components
    x, y = tx(-10.5, 25.65)
    s.rect(x, y, 21 * K, 51 * K, stroke=ACCENT, sw=1.0, dash="10 4 2 4")
    x, y = tx(-12.7, 24.15)
    s.rect(x, y, 25.4 * K, 42.9 * K, stroke="#7fd1ff", sw=1.0, dash="6 4")
    # centre lines
    a, b = tx(0, -30.5)
    c, d = tx(0, 33.5)
    s.line(a, b, c, d, stroke=INK_DIM, w=0.6, dash="14 4 3 4")
    a, b = tx(-18.5, 0)
    c, d = tx(16.5, 0)
    s.line(a, b, c, d, stroke=INK_DIM, w=0.6, dash="14 4 3 4")
    # USB opening marker
    a, b = tx(-4.8, 28.05)
    c, d = tx(4.8, 28.05)
    s.line(a, b - 0, c, d, stroke=BG, w=3)
    s.line(a, b, a, b + 1.8 * K, w=1.2)
    s.line(c, d, c, d + 1.8 * K, w=1.2)
    return tx


def view_lid(s, ox, oy, K):
    """Lid seen from above as installed (lid STL is printed upside-down → mirror Y)."""
    tx = lambda x, y: (ox + x * K, oy + y * K)  # lid frame y = -base y
    outer = max(zloops(LID, 0.2), key=lambda e: np.ptp(e[:, 0]) * np.ptp(e[:, 1]))
    s.path(poly_d(outer, tx), sw=2.0, fill="#123f6e")
    for e in zloops(LID, 0.15):
        x0, x1, y0, y1 = bbox(e)
        if x1 - x0 < 8:
            s.path(poly_d(e, tx), sw=1.0, fill=BG)
    for e in zloops(LID, 1.6):
        x0, x1, y0, y1 = bbox(e)
        if x1 - x0 < 8:
            s.path(poly_d(e, tx), sw=1.0, stroke=INK_DIM, fill=BG)
    # hidden: skirt + clamp tabs
    for e in zloops(LID, 2.6):
        s.path(poly_d(e, tx), sw=0.8, stroke=INK_DIM, dash="4 3")
    for e in zloops(LID, 6.0):
        s.path(poly_d(e, tx), sw=0.8, stroke=INK_DIM, dash="4 3")
    a, b = tx(0, -34)
    c, d = tx(0, 30)
    s.line(a, b, c, d, stroke=INK_DIM, w=0.6, dash="14 4 3 4")
    return tx


def section_view(s, ox, oy, K, cut_x=-5.7):
    """Section through the base + lid along the long axis at x = cut_x (standoff line).
    Horizontal = base y (USB end to the right), vertical = z (up)."""
    tx = lambda y, z: (ox + y * K, oy - z * K)
    sec = BASE.section(plane_origin=[cut_x, 0, 0], plane_normal=[1, 0, 0])
    for e in sec.discrete:
        p = [tx(y, z) for _, y, z in e]
        d = "M" + " L".join(f"{a:.2f},{b:.2f}" for a, b in p) + " Z"
        s.path(d, sw=1.4, fill="url(#hatch)")
    secl = LID.section(plane_origin=[cut_x, 0, 0], plane_normal=[1, 0, 0])
    for e in secl.discrete:
        p = [tx(-y, WALL_TOP + LID_PLATE - z) for _, y, z in e]
        d = "M" + " L".join(f"{a:.2f},{b:.2f}" for a, b in p) + " Z"
        s.path(d, sw=1.4, fill="url(#hatch)")
    # far-end retaining lip (at x = 0, beyond the cut plane) shown hidden
    lip = [(-19.55, 1.6), (-17.8, 1.6), (-17.8, 3.5), (-18.75, 3.5), (-18.75, 5.6), (-16.75, 5.6),
           (-16.75, 6.7), (-19.55, 6.7)]
    p = [tx(y, z) for y, z in lip]
    s.path("M" + " L".join(f"{a:.2f},{b:.2f}" for a, b in p) + " Z", stroke=INK, sw=1.0, dash="4 3")
    # clamp tab (beyond the cut plane, x = ±12.2) shown hidden
    a, b = tx(21.9, WALL_TOP)
    c, d = tx(25.9, WALL_TOP + LID_PLATE - 10.35)
    s.rect(a, b, c - a, d - b, stroke=INK_DIM, sw=0.9, dash="4 3")
    # USB opening (hidden, beyond)
    a, b = tx(26.25, 13.4)
    c, d = tx(28.05, 8.8)
    s.rect(a, b, c - a, d - b, stroke=INK_DIM, sw=0.9, dash="4 3")
    # components
    a, b = tx(-25.35, 9.0)
    c, d = tx(25.65, 8.0)
    s.rect(a, b, c - a, d - b, stroke=ACCENT, sw=1.2, fill="#5a4a1f")
    a, b = tx(22.0, 11.6)
    c, d = tx(25.65 + 1.3, 9.0)
    s.rect(a, b, c - a, d - b, stroke=ACCENT, sw=1.0)
    a, b = tx(-18.75, 5.1)
    c, d = tx(24.15, 3.5)
    s.rect(a, b, c - a, d - b, stroke="#7fd1ff", sw=1.2, fill="#1d5a7a")
    a, b = tx(18.0, 6.0)
    c, d = tx(22.0, 5.1)
    s.rect(a, b, c - a, d - b, stroke="#7fd1ff", sw=1.0)
    return tx


# --------------------------------------------------------------------------------------------------
def build():
    s = Svg()
    sheet_open(s, "DSM Offline Anchor — Sheet 2 — Enclosure & Stack-up")
    s.text(52, 66, "SHEET 2 · ENCLOSURE & STACK-UP", size=22, weight="bold", spacing=2)
    s.text(52, 88, "Pocket case REV E. Geometry traced from base.stl / lid.stl. Dimensions in mm.",
           size=12, fill=INK_DIM)

    # ---------------- VIEW A : BASE ----------------
    K = 7.0
    ox, oy = 245, 400
    tx = view_base(s, ox, oy, K)
    s.text(ox - 1 * K, oy + 28.05 * K + 92, "VIEW A · BASE, TOP", size=13, weight="bold", anchor="middle", spacing=1)
    s.text(ox - 1 * K, oy + 28.05 * K + 108, "phantom: Pico (yellow), Click (blue)", size=10, fill=INK_DIM, anchor="middle")
    # dims
    x0, _ = tx(-15.65, 0); x1, _ = tx(15.65, 0); _, yb = tx(0, -28.05)
    s.hdim(x0, x1, yb + 30, yb, "31.3")
    xl, _ = tx(-17.95, 0)
    s.hdim(xl, x1, yb + 58, yb, "33.6")
    _, yt = tx(0, 28.05); _, ytt = tx(0, 32.4); xr, _ = tx(15.65, 0)
    s.vdim(yt, yb, xr + 34, xr, "56.1", left=False)
    s.vdim(ytt, yb, xr + 62, xr, "60.45", left=False)
    a, b = tx(-5.7, 23.65); c, d = tx(5.7, 23.65)
    s.hdim(a, c, tx(0, 30.9)[1], b, "11.4")
    a, b = tx(-5.7, 23.65); c, d = tx(-5.7, -23.35)
    s.vdim(b, d, a - 1.2 * K - 46, a, "47.0")
    a, b = tx(-4.8, 28.05); c, _ = tx(4.8, 28.05)
    s.hdim(a, c, tx(0, 35.2)[1], b, "9.6 USB")
    # leaders + balloons
    s.leader(*tx(13.3, 19.5), *tx(23, 16), "M2 pilot Ø1.7 (lid screw)", size=10)
    s.leader(*tx(12.4, 21.5), *tx(23, 31), "lid-screw boss (moved out)", size=10, fill=ACCENT)
    s.leader(*tx(-12.2, 10.9), *tx(-24, 4), "rib", size=10, anchor="end")
    s.leader(*tx(0, -18.6), *tx(-24, -14), "lip", size=10, anchor="end")
    s.leader(*tx(-14.15, 28.6), *tx(-21, 36), "lanyard Ø3.4", size=10, anchor="end")
    s.leader(*tx(12.7, 0), *tx(23, -3), "Click (phantom)", size=10, fill="#7fd1ff")
    s.leader(*tx(10.5, -10), *tx(23, -12), "Pico (phantom)", size=10, fill=ACCENT)

    # ---------------- VIEW B : LID ----------------
    ox2, oy2 = 690, 400
    t2 = view_lid(s, ox2, oy2, K)
    s.text(ox2 - 1 * K, oy2 + 28.05 * K + 92, "VIEW B · LID, TOP (as installed)", size=13, weight="bold",
           anchor="middle", spacing=1)
    s.text(ox2 - 1 * K, oy2 + 28.05 * K + 108, "hidden lines: skirt, clamp tabs", size=10, fill=INK_DIM,
           anchor="middle")
    s.leader(*t2(-2.5, -11.15), *t2(20, -8), "BOOTSEL pinhole Ø1.8", size=10)
    s.leader(*t2(-5.8, -21.6), *t2(20, -19.5), "LED slot 2.4 × 5.0", size=10)
    s.leader(*t2(12.9, -19.5), *t2(20, -27), "M2 countersink ×2", size=10)
    s.leader(*t2(12.2, -23.9), *t2(20, 2), "clamp tab ×2 (hidden)", size=10)
    a, b = t2(-2.5, -11.15)
    c, d = t2(-2.5, -25.65)
    s.vdim(d, b, a - 40, a, "14.5")
    s.text(*t2(0, -30.6), "USB end", size=10, anchor="middle")

    # ---------------- SECTION ----------------
    KS = 11.0
    sx, sy = 500, 925
    t3 = section_view(s, sx, sy, KS)
    s.text(sx - 8 * KS, sy + 52, "SECTION C–C · through the standoffs (x = −5.7), USB end right",
           size=13, weight="bold", anchor="middle", spacing=1)
    # z dimension ladder on the right
    xr = sx + 31.5 * KS
    for z, lab in ((0, "0"), (1.6, "1.6 floor"), (3.5, "3.5 Click seat"), (5.1, "5.1 Click top"),
                   (8.0, "8.0 Pico seat"), (9.0, "9.0 Pico top"), (13.8, "13.8 wall / lid seat"),
                   (15.8, "15.8 overall")):
        _, yy = t3(0, z)
        s.line(xr - 6, yy, xr + 14, yy, stroke=INK_DIM, w=0.7)
        dy = {8.0: 8, 9.0: -1}.get(z, 4)
        s.text(xr + 18, yy + dy, lab, size=10, fill=ACCENT if "Click" in lab or "Pico" in lab else INK)
    s.leader(*t3(-12, 4.3), *t3(-31, 4.3), "Click 1.6 thk", size=10, fill="#7fd1ff", anchor="end")
    s.leader(*t3(-12, 8.5), *t3(-31, 8.5), "Pico 1.0 thk", size=10, fill=ACCENT, anchor="end")
    s.leader(*t3(-17.2, 6.2), *t3(-29, 12.5), "retaining lip (hidden)", size=10, anchor="end")
    s.leader(*t3(23.9, 6.0), *t3(24.5, 19.0), "clamp tab, tip at 5.45 (hidden)", size=10, anchor="end")

    # ---------------- right column: BOM / fasteners / print / sequence ----------------
    rx, ry = 1012, 112
    s.text(rx, ry, "BILL OF MATERIALS", size=14, weight="bold", spacing=1)
    bom = [("1", "1", "Raspberry Pi Pico 2 W (RP2350), no headers"),
           ("2", "1", "MIKROE-6559 Secure Tropic Click (TROPIC01)"),
           ("3", "6", "Wire, 28–30 AWG stranded silicone, 60–80 mm"),
           ("4", "4", "Screw M2 × 5, self-tapping (Pico → standoffs)"),
           ("5", "2", "Screw M2 × 6, countersunk self-tapping (lid)"),
           ("6", "1", "base.stl — PETG (PLA ok)"),
           ("7", "1", "lid.stl — PETG (PLA ok)"),
           ("8", "1", "USB cable: micro-USB to phone (OTG) or host")]
    s.rect(rx, ry + 10, 548, 24 + 22 * len(bom), sw=1.4, fill=BG)
    s.text(rx + 10, ry + 27, "ITEM", size=10, fill=INK_DIM)
    s.text(rx + 56, ry + 27, "QTY", size=10, fill=INK_DIM)
    s.text(rx + 100, ry + 27, "DESCRIPTION", size=10, fill=INK_DIM)
    s.line(rx, ry + 34, rx + 548, ry + 34, w=1)
    for i, (it, q, dsc) in enumerate(bom):
        yy = ry + 34 + i * 22
        s.text(rx + 16, yy + 16, it, size=11, fill=ACCENT, weight="bold")
        s.text(rx + 62, yy + 16, q, size=11)
        s.text(rx + 100, yy + 16, dsc, size=11)

    py0 = ry + 34 + 22 * len(bom) + 40
    s.text(rx, py0, "PRINT SETTINGS", size=14, weight="bold", spacing=1)
    prt = ["PETG preferred, PLA fine · 0.2 mm layers · 3 perimeters",
           "25 % infill · NO supports · no brim · ~35 g total",
           "Both parts print flat face down, already oriented",
           "base ≈ 2 h · lid ≈ 1 h"]
    for i, t in enumerate(prt):
        s.text(rx + 10, py0 + 22 + i * 18, t, size=11)

    ay = py0 + 22 + 18 * len(prt) + 30
    s.text(rx, ay, "ASSEMBLY SEQUENCE", size=14, weight="bold", spacing=1)
    seq = [
        "Print base + lid. Test-fit the bare Pico on the four standoffs.",
        "Wire the Click: six leads in from the component side,",
        "  solder underneath, trim ≤ 1 mm (Sheet 1, Detail A).",
        "Lay the Click component-up on the ribs, TROPIC01 end",
        "  toward USB, far end tucked under the retaining lip.",
        "Pass the leads up; solder them into the Pico from the",
        "  underside (pins 21, 22, 23, 24, 25, 36). Trim flush.",
        "Seat the Pico, USB into the opening. Screw down (4× M2×5).",
        "Flash + self-test (README) BEFORE closing the lid.",
        "Fit the lid: the tabs clamp the Click. 2× M2×6 countersunk.",
    ]
    n = 0
    for i, t in enumerate(seq):
        yy = ay + 24 + i * 18
        if not t.startswith("  "):
            n += 1
            s.balloon(rx + 10, yy - 4, str(n), r=9)
        s.text(rx + 28, yy, t.strip(), size=11)

    # notes
    ny = ay + 24 + 18 * len(seq) + 28
    s.text(rx, ny, "NOTES", size=14, weight="bold", spacing=1)
    notes = ["1. Pico sits component side UP on the standoffs (seat z = 8.0).",
             "2. The Click lies in the 6.4 mm bay under the Pico (seat z = 3.5).",
             "3. REV E: side walls, lid-screw bosses and lid countersinks moved",
             "   out 0.75 mm per side so the Pico clears the bosses (view A).",
             "4. Section C–C is traced from the STLs; components are phantoms."]
    for i, t in enumerate(notes):
        s.text(rx + 10, ny + 22 + i * 17, t, size=11, fill=ACCENT if t.startswith(("3", "   out")) else INK)

    title_block(s, "SHEET 2 — ENCLOSURE & STACK-UP", "2 / 2")
    return sheet_close(s)


if __name__ == "__main__":
    open(os.path.join(HERE, "..", "sheet-2-enclosure.svg"), "w").write(build())
