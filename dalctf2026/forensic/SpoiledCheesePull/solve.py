#!/usr/bin/env python3
from pathlib import Path
import sys, struct, zlib

PNG_SIG = b'\x89PNG\r\n\x1a\n'

def repair_png(inp: Path, out: Path) -> bytes:
    b = inp.read_bytes()
    # The image is a valid PNG with a fake JPEG/JFIF start and chunk type names altered:
    # IHET -> IHDR, ISAD -> IDAT, SEND -> IEND. CRCs still match the real PNG chunk names.
    png = bytearray()
    png += PNG_SIG
    png += (13).to_bytes(4, 'big') + b'IHDR' + b[16:33]

    pos = 33
    length = int.from_bytes(b[pos:pos+4], 'big')
    png += b[pos:pos+4] + b'IDAT' + b[pos+8:pos+8+length] + b[pos+8+length:pos+12+length]

    pos += 12 + length
    length = int.from_bytes(b[pos:pos+4], 'big')
    png += b[pos:pos+4] + b'IEND' + b[pos+8:pos+8+length] + b[pos+8+length:pos+12+length]
    out.write_bytes(png)
    return bytes(png)

def read_grid_from_png(path: Path):
    try:
        from PIL import Image
    except ImportError:
        raise SystemExit('Pillow is required: pip install pillow')
    im = Image.open(path).convert('L')
    w, h = im.size
    pix = im.load()
    xs, ys = [], []
    for y in range(h):
        for x in range(w):
            if pix[x, y] < 128:
                xs.append(x); ys.append(y)
    x0, x1, y0, y1 = min(xs), max(xs), min(ys), max(ys)
    # This rMQR symbol is R7x77 and rendered at 10 px/module.
    module = (y1 - y0 + 1) // 7
    grid = []
    for r in range(7):
        row = []
        for c in range(77):
            black = 0
            for yy in range(y0 + r*module, y0 + (r+1)*module):
                for xx in range(x0 + c*module, x0 + (c+1)*module):
                    black += pix[xx, yy] < 128
            row.append(1 if black > (module*module)//2 else 0)
        grid.append(row)
    return grid

def mask(x, y):
    return (y // 2 + x // 3) % 2 == 0

def reserved_modules(width=77, height=7):
    # Recreate the reserved areas for rMQR R7x77: finder, sub-finder, corner finder,
    # alignment/timing, and format information. Only data cells remain unreserved.
    r = [[False]*width for _ in range(height)]
    def mark(x,y):
        if 0 <= x < width and 0 <= y < height:
            r[y][x] = True
    # left 7x7 finder + separator column 7
    for y in range(7):
        for x in range(7): mark(x,y)
        mark(7,y)
    # right bottom 5x5 sub finder
    for i in range(5):
        for j in range(5): mark(width-1-j, height-1-i)
    # corner finder bits
    for x in [0,1,2]: mark(x,height-1)
    mark(width-1,0); mark(width-2,0); mark(width-1,1); mark(width-2,1)
    # alignment patterns for width 77 (from ISO rMQR placement; centers at x=25 and x=51)
    for cx in [25, 51]:
        for j in range(cx-1, cx+2):
            for y in [0,1,2,height-3,height-2,height-1]: mark(j,y)
    # timing rows top/bottom and timing columns at x=0,width-1,alignment centers
    for x in range(width): mark(x,0); mark(x,height-1)
    for x in [0,width-1,25,51]:
        for y in range(height): mark(x,y)
    # format info near both finder patterns
    for n in range(18):
        x = 8 + n//5; y = 1 + n%5; mark(x,y)
    for n in range(15):
        x = width-1-7 + n//5; y = height-1-5 + n%5; mark(x,y)
    for x,y in [(width-1-4, height-1-5), (width-1-3, height-1-5), (width-1-2, height-1-5)]: mark(x,y)
    return r

def extract_codewords(grid):
    width, height = 77, 7
    res = reserved_modules(width, height)
    bits = []
    dy = -1
    cx, cy = width - 2, height - 6
    total_bits = 32 * 8
    remainder_bits = 5
    while True:
        for x in (cx, cx-1):
            if not res[cy][x]:
                if len(bits) < total_bits:
                    bits.append(grid[cy][x] ^ (1 if mask(x, cy) else 0))
                else:
                    remainder_bits -= 1
                if len(bits) == total_bits and remainder_bits == 0:
                    break
        if len(bits) == total_bits and remainder_bits == 0:
            break
        if dy < 0 and cy == 1:
            cx -= 2; dy = 1
        elif dy > 0 and cy == height - 2:
            cx -= 2; dy = -1
        else:
            cy += dy
    return [int(''.join(map(str, bits[i:i+8])), 2) for i in range(0, total_bits, 8)]

def decode_payload(codewords):
    bits = ''.join(f'{b:08b}' for b in codewords)
    mode = bits[:3]
    if mode != '011':
        raise ValueError(f'unexpected rMQR mode {mode}, expected byte mode 011')
    count = int(bits[3:8], 2)  # R7x77 byte mode count indicator is 5 bits
    idx = 8
    data = bytes(int(bits[idx+i:idx+i+8], 2) for i in range(0, count*8, 8))
    return data.decode('utf-8')

def main():
    inp = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('chall.png')
    fixed = Path('fixed.png')
    repair_png(inp, fixed)
    grid = read_grid_from_png(fixed)
    codewords = extract_codewords(grid)
    flag = decode_payload(codewords)
    print(flag)

if __name__ == '__main__':
    main()
