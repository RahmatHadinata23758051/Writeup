#!/usr/bin/env python3
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile
import sys

try:
    import numpy as np
    from PIL import Image
except ImportError:
    print('Missing dependency: install pillow numpy', file=sys.stderr)
    sys.exit(1)

FLAG = 'scriptCTF{w@t_4_cu71e_p@too1$}'
TILE = 60
GRID = 6

# Final grid order + number of de-scramble rounds for each tile.
# The two numbers in the filename are used as the generalized Arnold Cat Map parameters.
LAYOUT = [
    [('43_37.png', 56), ('17_11.png',  9), ('1_1.png',   9), ('19_29.png', 0), ('8_5.png',   0), ('3_5.png',   0)],
    [('41_31.png',  0), ('61_53.png',  4), ('41_59.png', 0), ('9_13.png',  1), ('13_9.png',  1), ('2_3.png',   3)],
    [('23_31.png',  0), ('7_4.png',    2), ('5_3.png',  16), ('13_19.png', 4), ('59_41.png', 6), ('23_17.png', 33)],
    [('19_13.png',  9), ('3_2.png',   16), ('53_61.png', 1), ('2_1.png',   6), ('31_23.png', 1), ('29_19.png',  4)],
    [('7_11.png',   5), ('1_2.png',    4), ('5_8.png',   0), ('29_37.png',11), ('31_41.png',13), ('37_43.png', 53)],
    [('4_7.png',    3), ('11_7.png',   0), ('37_29.png', 5), ('17_23.png',47), ('11_17.png',11), ('73_97.png', 10)],
]


def arnold_decode_step(arr: np.ndarray, a: int, b: int) -> np.ndarray:
    """One generalized Arnold Cat Map recovery step for a 60x60 RGB tile.

    Coordinates use x=column, y=row:
        x' = x + a*y
        y' = b*x + (a*b + 1)*y        (mod N)

    Recovery samples the current scrambled tile at (x', y') for each output (x, y).
    """
    n = arr.shape[0]
    rows, cols = np.indices((n, n))
    x = cols
    y = rows
    nx = (x + a * y) % n
    ny = (b * x + (a * b + 1) * y) % n
    return arr[ny, nx]


def recover_tile(tile_path: Path, rounds: int) -> Image.Image:
    a, b = map(int, tile_path.stem.split('_'))
    arr = np.array(Image.open(tile_path).convert('RGB'))
    for _ in range(rounds):
        arr = arnold_decode_step(arr, a, b)
    return Image.fromarray(arr)


def recover(zip_path: Path, out_dir: Path) -> Image.Image:
    with TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        with ZipFile(zip_path) as zf:
            zf.extractall(tmp)

        missing = [name for row in LAYOUT for name, _ in row if not (tmp / name).exists()]
        if missing:
            raise FileNotFoundError('Missing tile(s): ' + ', '.join(missing))

        canvas = Image.new('RGB', (GRID * TILE, GRID * TILE))
        for r, row in enumerate(LAYOUT):
            for c, (name, rounds) in enumerate(row):
                tile = recover_tile(tmp / name, rounds)
                canvas.paste(tile, (c * TILE, r * TILE))

    out_dir.mkdir(parents=True, exist_ok=True)
    canvas.save(out_dir / 'recovered_pet.png')
    canvas.resize((canvas.width * 4, canvas.height * 4), Image.Resampling.NEAREST).save(out_dir / 'recovered_pet_4x.png')
    canvas.crop((0, 0, canvas.width, 240)).resize((canvas.width * 4, 240 * 4), Image.Resampling.NEAREST).save(out_dir / 'recovered_pet_flag_area_4x.png')
    return canvas


def main() -> None:
    zip_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('images.zip')
    if not zip_path.exists():
        print(f'Usage: {sys.argv[0]} /path/to/images.zip', file=sys.stderr)
        print(f'Error: {zip_path} not found', file=sys.stderr)
        sys.exit(1)

    out_dir = Path('.')
    recover(zip_path, out_dir)
    print('[+] wrote recovered_pet.png')
    print('[+] wrote recovered_pet_4x.png')
    print('[+] wrote recovered_pet_flag_area_4x.png')
    print(FLAG)


if __name__ == '__main__':
    main()

