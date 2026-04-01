#!/usr/bin/env python3
"""Generate NexGuard app icon PNG files for .icns creation."""
import struct, zlib, math, os, sys

def make_png(size):
    pixels = []
    cx, cy = size / 2, size / 2
    r = size * 0.45
    corner = size * 0.15

    shield = [
        (cx, cy - r * 0.72), (cx + r * 0.6, cy - r * 0.2),
        (cx + r * 0.44, cy + r * 0.36), (cx, cy + r * 0.8),
        (cx - r * 0.44, cy + r * 0.36), (cx - r * 0.6, cy - r * 0.2),
    ]

    def in_rounded_rect(x, y):
        dx, dy = abs(x - cx), abs(y - cy)
        if dx > cx - corner and dy > cy - corner:
            a, b = dx - (cx - corner), dy - (cy - corner)
            return a * a + b * b <= corner * corner
        return dx <= cx and dy <= cy

    def in_polygon(px, py, pts):
        inside = False
        n = len(pts)
        j = n - 1
        for i in range(n):
            xi, yi = pts[i]
            xj, yj = pts[j]
            if ((yi > py) != (yj > py)) and (px < (xj - xi) * (py - yi) / (yj - yi) + xi):
                inside = not inside
            j = i
        return inside

    lock_w = r * 0.32
    lock_h = r * 0.26
    lock_cy = cy + r * 0.16
    arc_r = r * 0.55 * 0.25
    arc_cy = lock_cy - r * 0.55 * 0.12

    for y in range(size):
        row = []
        for x in range(size):
            if not in_rounded_rect(x, y):
                row.extend([0, 0, 0, 0])
                continue

            in_shield = in_polygon(x, y, shield)
            in_lock_body = abs(x - cx) <= lock_w / 2 and lock_cy <= y <= lock_cy + lock_h
            dist = math.sqrt((x - cx) ** 2 + (y - arc_cy) ** 2)
            in_arc = y <= arc_cy and abs(dist - arc_r) <= max(3.5 * size / 128, 2)

            if in_shield and not in_lock_body and not in_arc:
                row.extend([6, 182, 212, 255])
            elif in_lock_body or in_arc:
                row.extend([15, 23, 42, 255])
            else:
                # border glow
                min_d = size
                for px, py in shield:
                    d = math.sqrt((x - px) ** 2 + (y - py) ** 2)
                    min_d = min(min_d, d)
                if min_d < 3 * size / 128:
                    row.extend([6, 182, 212, 80])
                else:
                    row.extend([15, 23, 42, 255])
        pixels.append(bytes(row))

    raw = b''
    for row in pixels:
        raw += b'\x00' + row

    def deflate(data):
        c = zlib.compressobj()
        return c.compress(data) + c.flush()

    def chunk(ctype, data):
        c = struct.pack('>I', len(data)) + ctype + data
        return c + struct.pack('>I', zlib.crc32(ctype + data) & 0xffffffff)

    sig = b'\x89PNG\r\n\x1a\n'
    ihdr = struct.pack('>IIBBBBB', size, size, 8, 6, 0, 0, 0)
    return sig + chunk(b'IHDR', ihdr) + chunk(b'IDAT', deflate(raw)) + chunk(b'IEND', b'')

out = sys.argv[1] if len(sys.argv) > 1 else 'icon'
os.makedirs(out, exist_ok=True)
for s in [16, 32, 64, 128, 256, 512, 1024]:
    with open(f'{out}/icon_{s}x{s}.png', 'wb') as f:
        f.write(make_png(s))
    print(f'  {s}x{s}')
print(f'Icons saved to {out}/')
