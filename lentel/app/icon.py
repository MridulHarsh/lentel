"""
Procedurally generated tray icon.

We draw the icon from code so the package has no binary assets and the same
source ships on both platforms. A coloured rounded square with a stylized
"L" in the middle. The colour changes when a transfer is active so the
user can tell at a glance.
"""
from __future__ import annotations

from PIL import Image, ImageDraw


def make_icon(size: int = 64, active: bool = False) -> Image.Image:
    im = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)

    bg = (30, 144, 255, 255) if active else (48, 48, 52, 255)
    fg = (255, 255, 255, 240)

    pad = max(1, size // 10)
    radius = max(2, size // 5)
    d.rounded_rectangle([pad, pad, size - pad, size - pad],
                        radius=radius, fill=bg)

    # Letter "L" from two rectangles.
    inset = size // 4
    stroke = max(2, size // 9)
    # Vertical stroke
    d.rectangle([inset, inset, inset + stroke, size - inset], fill=fg)
    # Horizontal stroke
    d.rectangle([inset, size - inset - stroke, size - inset, size - inset], fill=fg)

    # A small dot above the L to represent a packet in flight when active.
    if active:
        r = max(2, size // 12)
        cx, cy = size - inset - r, inset + r
        d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=fg)

    return im
