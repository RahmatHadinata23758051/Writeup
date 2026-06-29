#!/usr/bin/env python3
import io
import re
import struct
import sys
import tarfile
import zipfile
from pathlib import Path

TARGET_PHRASE = "Specialist formats handled cleanly."
FLAG_PREFIX = "SEKAI"


def uleb(data: bytes, off: int):
    value = 0
    shift = 0
    while True:
        b = data[off]
        off += 1
        value |= (b & 0x7F) << shift
        if b < 0x80:
            return value, off
        shift += 7


def dex_strings(dex: bytes):
    if dex[:4] != b"dex\n":
        return []
    string_ids_size = struct.unpack_from("<I", dex, 0x38)[0]
    string_ids_off = struct.unpack_from("<I", dex, 0x3C)[0]
    out = []
    for i in range(string_ids_size):
        off = struct.unpack_from("<I", dex, string_ids_off + 4 * i)[0]
        _, off = uleb(dex, off)
        end = dex.index(0, off)
        out.append(dex[off:end].decode("utf-8", "replace"))
    return out


def apk_bytes_from_arg(path: Path):
    if path.suffix == ".apk":
        return path.read_bytes()
    if path.suffixes[-2:] == [".tar", ".gz"] or path.name.endswith(".tgz"):
        with tarfile.open(path, "r:gz") as tf:
            for member in tf.getmembers():
                if member.name.endswith(".apk"):
                    return tf.extractfile(member).read()
        raise FileNotFoundError("no APK inside tar.gz")
    raise ValueError("give an APK or tar.gz")


def normalize_flag_body(s: str) -> str:
    s = s.lower()
    s = re.sub(r"[^a-z0-9]+", "_", s).strip("_")
    return s


def main():
    default = Path(__file__).with_name("misc_ufo") / "app-release.apk"
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else default
    apk_data = apk_bytes_from_arg(src)

    found = False
    evidence = []
    with zipfile.ZipFile(io.BytesIO(apk_data)) as zf:
        for name in zf.namelist():
            if name.endswith(".dex"):
                strings = dex_strings(zf.read(name))
                if TARGET_PHRASE in strings:
                    found = True
                    evidence.append(f"{name}: string index {strings.index(TARGET_PHRASE)}")

    if not found:
        raise SystemExit("target phrase not found")

    flag = f"{FLAG_PREFIX}{{{normalize_flag_body(TARGET_PHRASE)}}}"
    print("\n".join(evidence))
    print(flag)


if __name__ == "__main__":
    main()
