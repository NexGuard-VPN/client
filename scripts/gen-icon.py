#!/usr/bin/env python3
"""Generate NexGuard app icon PNG files from source logo."""
import subprocess, os, sys, shutil

SRC = os.path.join(os.path.dirname(__file__), '..', 'assets', 'logo-128.png')
out = sys.argv[1] if len(sys.argv) > 1 else 'icon'
os.makedirs(out, exist_ok=True)

for s in [16, 32, 64, 128, 256, 512, 1024]:
    dst = f'{out}/icon_{s}x{s}.png'
    subprocess.run(['sips', '-z', str(s), str(s), SRC, '--out', dst],
                   capture_output=True)
    print(f'  {s}x{s}')

print(f'Icons saved to {out}/')
