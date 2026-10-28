"""Generate the Unfilter .ico files from the logo geometry (stdlib only).

Usage (from the repository root):  python -I assets/icons/gen_icons.py

The mark (see assets/logo/unfilter.svg) is a stroked centre-line with round
caps, so it is rendered analytically as a signed distance field: two "J"
strokes (stem + arc) with half-width 5 and a dot, in a 64x64 design space.
Output (PNG-compressed ICO entries, Windows Vista+):

  unfilter.ico          app icon (tile + mark)       16..256 px
  tray-<state>.ico      tray glyph per ConnState     16..48 px
"""

import math
import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))

# ---- geometry (64-unit design space, y down) --------------------------------
C = (32.0, 34.0)  # arc centre
R = 13.0  # centre-line radius
HW = 5.0  # stroke half-width
STEM_TOP = 12.0
GAP_DEG = 32.0  # arc stops this far short of the bottom (90 deg) on each side
DOT = (32.0, 56.5, 4.0)


def _seg_dist(px, py, ax, ay, bx, by):
    vx, vy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((px - ax) * vx + (py - ay) * vy) / (vx * vx + vy * vy)))
    return math.hypot(px - ax - t * vx, py - ay - t * vy)


def _arc_dist(px, py, a0, a1):
    """Distance to the centre-line arc between screen angles a0 < a1 (deg)."""
    dx, dy = px - C[0], py - C[1]
    ang = math.degrees(math.atan2(dy, dx)) % 360.0
    if a0 <= ang <= a1:
        return abs(math.hypot(dx, dy) - R)
    best = float("inf")
    for a in (a0, a1):
        ex = C[0] + R * math.cos(math.radians(a))
        ey = C[1] + R * math.sin(math.radians(a))
        best = min(best, math.hypot(px - ex, py - ey))
    return best


def sdf_u(px, py):
    left = min(
        _seg_dist(px, py, C[0] - R, STEM_TOP, C[0] - R, C[1]),
        _arc_dist(px, py, 90.0 + GAP_DEG, 180.0),
    )
    right = min(
        _seg_dist(px, py, C[0] + R, STEM_TOP, C[0] + R, C[1]),
        _arc_dist(px, py, 0.0, 90.0 - GAP_DEG),
    )
    return min(left, right) - HW


def sdf_dot(px, py):
    return math.hypot(px - DOT[0], py - DOT[1]) - DOT[2]


def sdf_round_rect(px, py, cx, cy, half, radius):
    qx = abs(px - cx) - (half - radius)
    qy = abs(py - cy) - (half - radius)
    out = math.hypot(max(qx, 0.0), max(qy, 0.0))
    return out + min(max(qx, qy), 0.0) - radius


# ---- raster helpers ----------------------------------------------------------
def hex_rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i : i + 2], 16) / 255.0 for i in (0, 2, 4))


def cov(d, px_per_unit):
    return max(0.0, min(1.0, 0.5 - d * px_per_unit))


def over(dst, rgb, a):
    """Composite straight-alpha colour `rgb`/`a` over straight-alpha `dst`."""
    r, g, b, da = dst
    oa = a + da * (1.0 - a)
    if oa <= 0.0:
        return (0.0, 0.0, 0.0, 0.0)
    f = lambda s, d: (s * a + d * da * (1.0 - a)) / oa
    return (f(rgb[0], r), f(rgb[1], g), f(rgb[2], b), oa)


def png(size, pixels):
    raw = bytearray()
    for y in range(size):
        raw.append(0)
        for x in range(size):
            r, g, b, a = pixels[y * size + x]
            raw += bytes(int(round(max(0.0, min(1.0, v)) * 255)) for v in (r, g, b, a))

    def chunk(tag, data):
        c = tag + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + chunk(b"IEND", b"")
    )


def ico(images):
    """images: list of (size, png_bytes)."""
    out = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    body = b""
    for size, data in images:
        dim = 0 if size >= 256 else size
        out += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
        body += data
    return out + body


def render(size, shade):
    """shade(u, v, px_per_unit) -> rgba for design-space point (u, v)."""
    ppu = size / 64.0
    pix = []
    for y in range(size):
        for x in range(size):
            u = (x + 0.5) / ppu
            v = (y + 0.5) / ppu
            pix.append(shade(u, v, ppu))
    return pix


# ---- the two icon styles -----------------------------------------------------
def app_shade(u, v, ppu):
    tile_d = sdf_round_rect(u, v, 32.0, 32.0, 30.0, 13.5)
    a = cov(tile_d, ppu)
    px = (0.0, 0.0, 0.0, 0.0)
    if a > 0.0:
        t = v / 64.0
        top, bot = hex_rgb("#252a35"), hex_rgb("#111317")
        base = tuple(top[i] * (1 - t) + bot[i] * t for i in range(3))
        px = over(px, base, a)
        # 1-unit rim, slightly brighter at the top (glass edge)
        rim = cov(abs(tile_d + 0.6) - 0.6, ppu) * a
        px = over(px, hex_rgb("#3a4150"), rim * (0.9 - 0.5 * t))
    # mark, scaled 0.86 about the design centre so it sits inside the tile
    s = 0.86
    gu = 32.0 + (u - 32.0) / s
    gv = 34.0 + (v - 33.0) / s
    px = over(px, hex_rgb("#eef0f3"), cov(sdf_u(gu, gv) * s, ppu))
    px = over(px, hex_rgb("#4ade80"), cov(sdf_dot(gu, gv) * s, ppu))
    return px


def tray_shade(color, dot_color):
    rgb, dot_rgb = hex_rgb(color), hex_rgb(dot_color)

    def shade(u, v, ppu):
        s = 1.14
        gu = 32.0 + (u - 32.0) / s
        gv = 33.75 + (v - 32.0) / s
        du = sdf_u(gu, gv) * s
        dd = sdf_dot(gu, gv) * s
        # soft dark halo keeps the glyph readable on light taskbars
        halo = cov(min(du, dd) - 1.0 / ppu, ppu) * 0.45
        px = over((0.0, 0.0, 0.0, 0.0), (0.0, 0.0, 0.0), halo)
        px = over(px, rgb, cov(du, ppu))
        px = over(px, dot_rgb, cov(dd, ppu))
        return px

    return shade


TRAY_STATES = {
    # state: (glyph colour, dot colour)
    "offline": ("#7b828c", "#7b828c"),
    "ready": ("#d4d8de", "#d4d8de"),
    "scanning": ("#f5b942", "#f5b942"),
    "connected": ("#e6e8eb", "#4ade80"),
    "fault": ("#f06b6b", "#f06b6b"),
}


def main():
    app = [(n, png(n, render(n, app_shade))) for n in (16, 20, 24, 32, 40, 48, 64, 256)]
    with open(os.path.join(HERE, "unfilter.ico"), "wb") as f:
        f.write(ico(app))
    with open(os.path.join(HERE, "unfilter-256.png"), "wb") as f:
        f.write(app[-1][1])
    for state, (c, d) in TRAY_STATES.items():
        imgs = [(n, png(n, render(n, tray_shade(c, d)))) for n in (16, 20, 24, 32, 48)]
        with open(os.path.join(HERE, f"tray-{state}.ico"), "wb") as f:
            f.write(ico(imgs))
    print("icons written to", HERE)


if __name__ == "__main__":
    main()
