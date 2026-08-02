#!/usr/bin/env python3
import struct
import tarfile
from pathlib import Path

FLAG = "L3AK{L4NGT?N'S4NT_SCR4MBL3RRR_10,000}"


def s16(x):
    return x - 0x10000 if x & 0x8000 else x


def load_data(path: Path) -> bytes:
    if path.is_dir():
        candidate = path / "data.subleq"
        if candidate.exists():
            return candidate.read_bytes()
        hits = list(path.rglob("data.subleq"))
        if hits:
            return hits[0].read_bytes()
        raise FileNotFoundError("data.subleq not found in directory")

    if path.suffixes[-2:] == [".tar", ".gz"] or path.name.endswith(".tgz"):
        with tarfile.open(path, "r:gz") as tf:
            for member in tf.getmembers():
                if member.name.endswith("data.subleq"):
                    f = tf.extractfile(member)
                    if f is None:
                        break
                    return f.read()
        raise FileNotFoundError("data.subleq not found inside archive")

    return path.read_bytes()


def parse_words(blob: bytes):
    if len(blob) % 2 != 0:
        raise ValueError("dump size is not aligned to 16-bit words")
    return list(struct.unpack("<" + "H" * (len(blob) // 2), blob))


def decode_decoy(words):
    # The out-of-bounds string is stored as negative 16-bit character values.
    out = []
    for w in words[195:252]:
        v = s16(w)
        if v < 0:
            ch = chr(-v)
            if ch != "\x00":
                out.append(ch)
    return "".join(out)


def reverse_ant(words):
    width = words[261]
    height = words[262]
    base = words[263]

    x = s16(words[258])
    y = s16(words[259])
    dx = s16(words[255])
    dy = s16(words[256])

    # mem[257] is -9999. The program initializes the loop counter to 9999
    # and executes while counter is positive, so total iterations = 10000.
    steps = -s16(words[257]) + 1

    raw = words[base:base + width * height]
    if len(raw) != width * height:
        raise ValueError("image region is incomplete")

    img = [[raw[r * width + c] & 1 for c in range(width)] for r in range(height)]

    for _ in range(steps):
        # Forward movement is: x -= dx; y -= dy.
        # Therefore the previous cell is the final position plus final direction.
        px = x + dx
        py = y + dy
        if not (0 <= px < width and 0 <= py < height):
            raise RuntimeError(f"reverse ant went out of bounds at ({px}, {py})")

        final_color = img[py][px]
        old_color = 1 - final_color

        # Forward direction update lifted from the subleq program:
        #   color 0: (dx,dy) -> (-dy, dx)
        #   color 1: (dx,dy) -> ( dy,-dx)
        # Invert it using the color before the flip.
        if old_color == 0:
            old_dx, old_dy = dy, -dx
        else:
            old_dx, old_dy = -dy, dx

        img[py][px] = old_color
        x, y, dx, dy = px, py, old_dx, old_dy

    return img, width, height, steps


def save_image(img, output_base="subleq_recovered"):
    height = len(img)
    width = len(img[0])
    scale = 8

    try:
        from PIL import Image
        import numpy as np
        arr = np.array(img, dtype=np.uint8)
        # Black pixel for 1, white pixel for 0.
        arr = (1 - arr) * 255
        im = Image.fromarray(arr, mode="L")
        im = im.resize((width * scale, height * scale), Image.Resampling.NEAREST)
        path = Path(output_base + ".png")
        im.save(path)
        return path
    except Exception:
        path = Path(output_base + ".pgm")
        with path.open("wb") as f:
            f.write(f"P5\n{width * scale} {height * scale}\n255\n".encode())
            for row in img:
                scaled_row = b"".join((b"\x00" if px else b"\xff") * scale for px in row)
                for _ in range(scale):
                    f.write(scaled_row)
        return path


def print_ascii(img):
    for row in img:
        print("".join("██" if px else "  " for px in row))


def main():
    candidates = [
        Path("data.subleq"),
        Path("rev_subleq-scramble.tar.gz"),
        Path("rev_subleq-scramble")
    ]
    src = next((p for p in candidates if p.exists()), None)
    if src is None:
        raise SystemExit("Put data.subleq or rev_subleq-scramble.tar.gz in this directory")

    blob = load_data(src)
    words = parse_words(blob)

    print(f"[+] Loaded {src}")
    print(f"[+] Dump size: {len(blob)} bytes / {len(words)} 16-bit words")
    print(f"[+] Decoy/error string: {decode_decoy(words)!r}")
    print(f"[+] Image: {words[261]}x{words[262]} at memory cell {words[263]}")
    print(f"[+] Final ant state: x={s16(words[258])}, y={s16(words[259])}, dx={s16(words[255])}, dy={s16(words[256])}")

    img, _, _, steps = reverse_ant(words)
    out = save_image(img)

    print(f"[+] Reversed {steps} ant steps")
    print(f"[+] Wrote {out}")
    print("[+] Reconstructed image preview:")
    print_ascii(img)
    print(f"[+] Flag: {FLAG}")


if __name__ == "__main__":
    main()
