# SPDX-License-Identifier: MIT OR Apache-2.0
"""Shared blueprint drawing helpers (plain SVG, no dependencies)."""
from xml.sax.saxutils import escape

W, H = 1600, 1131
BG = "#0d3763"
GRID_MINOR = "#164675"
GRID_MAJOR = "#1f5486"
INK = "#e9f2fb"
INK_DIM = "#a9c8e8"
ACCENT = "#ffd166"
FONT = "'DejaVu Sans Mono','Menlo','Consolas','Liberation Mono',monospace"


class Svg:
    def __init__(self):
        self.out = []

    def add(self, s):
        self.out.append(s)

    def line(self, x1, y1, x2, y2, stroke=INK, w=1.2, dash=None, cap="butt", extra=""):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        self.add(f'<line x1="{x1:.2f}" y1="{y1:.2f}" x2="{x2:.2f}" y2="{y2:.2f}" stroke="{stroke}" '
                 f'stroke-width="{w}" stroke-linecap="{cap}"{d} {extra}/>')

    def rect(self, x, y, w, h, stroke=INK, sw=1.2, fill="none", rx=0, dash=None, extra=""):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        self.add(f'<rect x="{x:.2f}" y="{y:.2f}" width="{w:.2f}" height="{h:.2f}" rx="{rx}" '
                 f'fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{d} {extra}/>')

    def circle(self, cx, cy, r, stroke=INK, sw=1.2, fill="none", dash=None):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        self.add(f'<circle cx="{cx:.2f}" cy="{cy:.2f}" r="{r:.2f}" fill="{fill}" stroke="{stroke}" '
                 f'stroke-width="{sw}"{d}/>')

    def path(self, d, stroke=INK, sw=1.2, fill="none", dash=None, extra=""):
        da = f' stroke-dasharray="{dash}"' if dash else ""
        self.add(f'<path d="{d}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{da} '
                 f'stroke-linejoin="round" stroke-linecap="round" {extra}/>')

    def text(self, x, y, s, size=12, fill=INK, anchor="start", weight="normal", rot=None,
             spacing=None, style=""):
        r = f' transform="rotate({rot} {x:.2f} {y:.2f})"' if rot is not None else ""
        ls = f' letter-spacing="{spacing}"' if spacing is not None else ""
        st = f' font-style="{style}"' if style else ""
        self.add(f'<text x="{x:.2f}" y="{y:.2f}" font-size="{size}" fill="{fill}" '
                 f'text-anchor="{anchor}" font-weight="{weight}"{ls}{st}{r}>{escape(str(s))}</text>')

    # ---- drafting conventions -------------------------------------------------
    def arrow(self, x, y, ang_deg, size=7, fill=INK_DIM):
        import math
        a = math.radians(ang_deg)
        p1 = (x - size * math.cos(a) + size * 0.35 * math.sin(a), y - size * math.sin(a) - size * 0.35 * math.cos(a))
        p2 = (x - size * math.cos(a) - size * 0.35 * math.sin(a), y - size * math.sin(a) + size * 0.35 * math.cos(a))
        self.add(f'<path d="M{x:.2f},{y:.2f} L{p1[0]:.2f},{p1[1]:.2f} L{p2[0]:.2f},{p2[1]:.2f} Z" fill="{fill}"/>')

    def hdim(self, x1, x2, y, ref_y, label, size=11, above=True):
        """Horizontal dimension between x1,x2 drawn at y, extension lines from ref_y."""
        c = INK_DIM
        ext = 4 if y < ref_y else -4
        self.line(x1, ref_y - (2 if y < ref_y else -2), x1, y - ext, stroke=c, w=0.7)
        self.line(x2, ref_y - (2 if y < ref_y else -2), x2, y - ext, stroke=c, w=0.7)
        self.line(x1, y, x2, y, stroke=c, w=0.8)
        self.arrow(x1, y, 180, fill=c)
        self.arrow(x2, y, 0, fill=c)
        ty = y - 5 if above else y + size + 3
        self.add(f'<rect x="{(x1+x2)/2 - len(label)*size*0.31:.2f}" y="{ty - size + 1:.2f}" '
                 f'width="{len(label)*size*0.62:.2f}" height="{size+2}" fill="{BG}"/>')
        self.text((x1 + x2) / 2, ty, label, size=size, fill=INK, anchor="middle")

    def vdim(self, y1, y2, x, ref_x, label, size=11, left=True):
        c = INK_DIM
        ext = 4 if x < ref_x else -4
        self.line(ref_x - (2 if x < ref_x else -2), y1, x - ext, y1, stroke=c, w=0.7)
        self.line(ref_x - (2 if x < ref_x else -2), y2, x - ext, y2, stroke=c, w=0.7)
        self.line(x, y1, x, y2, stroke=c, w=0.8)
        self.arrow(x, y1, -90, fill=c)
        self.arrow(x, y2, 90, fill=c)
        tx = x - 5 if left else x + 5
        cy = (y1 + y2) / 2
        self.add(f'<rect x="{(tx - size - 1) if left else tx - 1:.2f}" y="{cy - len(label)*size*0.31:.2f}" '
                 f'width="{size+2}" height="{len(label)*size*0.62:.2f}" fill="{BG}"/>')
        self.text(tx - (2 if left else -size + 2), cy, label, size=size, fill=INK, anchor="middle", rot=-90)

    def leader(self, x1, y1, x2, y2, label, size=11, anchor="start", fill=INK):
        self.line(x1, y1, x2, y2, stroke=INK_DIM, w=0.8)
        self.circle(x1, y1, 1.8, stroke=INK_DIM, fill=INK_DIM, sw=0.5)
        off = 4 if anchor == "start" else -4
        self.text(x2 + off, y2 + size * 0.35, label, size=size, anchor=anchor, fill=fill)

    def balloon(self, x, y, n, r=11):
        self.circle(x, y, r, stroke=ACCENT, sw=1.4, fill=BG)
        self.text(x, y + 4.5, n, size=13, fill=ACCENT, anchor="middle", weight="bold")


def sheet_open(s: Svg, title: str):
    s.add(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
          f'font-family="{FONT}">')
    s.add(f'<title>{escape(title)}</title>')
    s.add(f'<rect width="{W}" height="{H}" fill="{BG}"/>')
    # drafting grid: 10 px minor, 50 px major
    s.add('<defs><pattern id="g10" width="10" height="10" patternUnits="userSpaceOnUse">'
          f'<path d="M10 0H0V10" fill="none" stroke="{GRID_MINOR}" stroke-width="0.6"/></pattern>'
          '<pattern id="g50" width="50" height="50" patternUnits="userSpaceOnUse">'
          f'<rect width="50" height="50" fill="url(#g10)"/>'
          f'<path d="M50 0H0V50" fill="none" stroke="{GRID_MAJOR}" stroke-width="0.9"/></pattern>'
          '<pattern id="hatch" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">'
          f'<line x1="0" y1="0" x2="0" y2="6" stroke="{INK_DIM}" stroke-width="1"/></pattern>'
          '<pattern id="hatchA" width="5" height="5" patternUnits="userSpaceOnUse" patternTransform="rotate(-45)">'
          f'<line x1="0" y1="0" x2="0" y2="5" stroke="{ACCENT}" stroke-width="1.2"/></pattern>'
          '</defs>')
    s.add(f'<rect x="20" y="20" width="{W-40}" height="{H-40}" fill="url(#g50)"/>')
    s.rect(20, 20, W - 40, H - 40, sw=2.2)
    s.rect(28, 28, W - 56, H - 56, sw=0.8)
    # zone markers
    for i in range(8):
        x = 28 + (W - 56) * (i + 0.5) / 8
        s.text(x, 25.5, str(i + 1), size=9, fill=INK_DIM, anchor="middle")
        s.text(x, H - 21.5, str(i + 1), size=9, fill=INK_DIM, anchor="middle")
    for i, L in enumerate("ABCDEF"):
        y = 28 + (H - 56) * (i + 0.5) / 6
        s.text(24, y + 3, L, size=9, fill=INK_DIM, anchor="middle")
        s.text(W - 24, y + 3, L, size=9, fill=INK_DIM, anchor="middle")


def title_block(s: Svg, sheet_title: str, sheet_no: str, extra_rows=()):
    x, y, w, h = W - 28 - 600, H - 28 - 150, 600, 150
    s.rect(x, y, w, h, sw=1.8, fill=BG)
    s.line(x, y + 44, x + w, y + 44, w=1)
    s.text(x + 14, y + 20, "DSM · OFFLINE ANCHOR APPLIANCE", size=15, weight="bold", spacing=1)
    s.text(x + 14, y + 37, sheet_title, size=12, fill=ACCENT, spacing=0.5)
    rows = [
        ("PROJECT", "deterministicstatemachine/dsm"),
        ("ASSEMBLY", "Pico 2 W (RP2350) + Secure Tropic Click (TROPIC01)"),
        ("ENCLOSURE", "Pocket case REV E · base.stl / lid.stl"),
        ("UNITS", "mm · drawings not to scale unless noted"),
    ] + list(extra_rows)
    for i, (k, v) in enumerate(rows):
        yy = y + 62 + i * 17
        s.text(x + 14, yy, k, size=10, fill=INK_DIM)
        s.text(x + 104, yy, v, size=11)
    # right column
    cx = x + w - 118
    s.line(cx, y + 44, cx, y + h, w=1)
    for i, (k, v) in enumerate([("SHEET", sheet_no), ("REV", "E"), ("DATE", "2026-10-02"),
                                ("LICENSE", "MIT/Apache-2.0")]):
        yy = y + 44 + i * 26.5
        if i:
            s.line(cx, yy, x + w, yy, w=0.6)
        s.text(cx + 8, yy + 11, k, size=9, fill=INK_DIM)
        s.text(cx + 8, yy + 23, v, size=12, weight="bold" if k in ("SHEET", "REV") else "normal")


def sheet_close(s: Svg):
    s.add('</svg>')
    return "\n".join(s.out)
