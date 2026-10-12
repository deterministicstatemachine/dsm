# SPDX-License-Identifier: MIT OR Apache-2.0
"""Rev D -> Rev E (kept for provenance; the Rev D STLs are not in the repo): widen the pocket case so the Pico clears the lid-screw bosses.

Only the side walls move. Each side wall moves outward by D mm, taking the two lid-screw
bosses (and their M2 pilots) and the matching lid countersinks with it. Everything on the
centre line stays exactly where it was: the Pico standoffs, USB opening, BOOTSEL pinhole,
LED slot and the far-end lip. The inner faces of the Click ribs and the lid clamp tabs are
also pinned, so the Click is supported and clamped exactly as in Rev D. Wall material between
the pinned faces and the moved walls is stretched, not cut.

    python3 widen.py rev_d/base.stl rev_d/lid.stl out_dir/ [D]
"""
import sys

import numpy as np
import trimesh

D = 0.75                  # mm added per side (total width grows by 2*D)
PIN = 11.45               # |x| at or below this never moves (ribs 11.4, clamp tabs 11.3, Pico 10.5)
WALL = 13.05              # |x| at or above this moves by the full D (cavity wall 13.1, outer 14.9)
RIGID = 9.2               # inside a boss/countersink region, everything beyond this moves rigidly


def zone(x):
    """Continuous piecewise map: fixed below PIN, full shift beyond WALL, stretch between."""
    ax = np.abs(x)
    sh = np.where(ax <= PIN, 0.0,
                  np.where(ax >= WALL, D, (ax - PIN) / (WALL - PIN) * D))
    return x + np.sign(x) * sh


def widen(mesh, rigid_mask):
    v = mesh.vertices.copy()
    x = v[:, 0]
    nx = zone(x)
    r = rigid_mask(v) & (np.abs(x) > RIGID)
    nx[r] = x[r] + np.sign(x[r]) * D
    v[:, 0] = nx
    out = mesh.copy()
    out.vertices = v
    return out


def base_rigid(v):
    bosses = (v[:, 1] > 16.9) & (v[:, 1] < 22.7) & (v[:, 2] > 8.5)      # lid-screw bosses + pilots
    lanyard = (v[:, 1] > 26.4) & (v[:, 0] < 0)                           # keep the lanyard hole round
    return bosses | lanyard


def lid_rigid(v):    # the lid is modelled upside-down, so its y axis is mirrored
    countersinks = (v[:, 1] > -21.85) & (v[:, 1] < -17.15) & (v[:, 2] <= 2.0 + 1e-6)
    lanyard = (v[:, 1] < -26.4) & (v[:, 0] < 0)
    return countersinks | lanyard


if __name__ == "__main__":
    base_in, lid_in, out_dir = sys.argv[1:4]
    if len(sys.argv) > 4:
        D = float(sys.argv[4])
    b = widen(trimesh.load(base_in), base_rigid)
    l = widen(trimesh.load(lid_in), lid_rigid)
    b.export(f"{out_dir}/base.stl")
    l.export(f"{out_dir}/lid.stl")
    print(f"widened by {D} mm per side -> base {b.extents.round(2)}, lid {l.extents.round(2)}")
