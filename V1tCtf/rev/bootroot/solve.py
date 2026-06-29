#!/usr/bin/env python3
import subprocess
import sys
import tempfile
from pathlib import Path


QCOW_PATH = Path("V1t_win2k_disk.qcow2")
EXE_PATH = Path("eEyeBootRoot2005.exe")
MARKER = b"Bo may de dia chi lai roi, co gioi thi tim toi va chan bo may de"


def extract_exe_from_qcow() -> bytes:
    if not QCOW_PATH.exists():
        raise FileNotFoundError("missing eEyeBootRoot2005.exe and V1t_win2k_disk.qcow2")

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        subprocess.run(
            ["7z", "x", "-y", str(QCOW_PATH)],
            cwd=tmpdir,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        ntfs = tmpdir / "0.ntfs"
        if not ntfs.exists():
            raise RuntimeError("failed to extract NTFS image from qcow2")

        subprocess.run(
            ["7z", "x", "-y", str(ntfs), "Documents and Settings/test/Desktop/eEyeBootRoot2005.exe"],
            cwd=tmpdir,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        exe = tmpdir / "Documents and Settings/test/Desktop/eEyeBootRoot2005.exe"
        if not exe.exists():
            raise RuntimeError("failed to extract eEyeBootRoot2005.exe from NTFS image")
        return exe.read_bytes()


def load_exe() -> bytes:
    if EXE_PATH.exists():
        return EXE_PATH.read_bytes()
    return extract_exe_from_qcow()


def recover_flag(exe_bytes: bytes) -> str:
    marker_off = exe_bytes.find(MARKER)
    if marker_off < 0:
        raise RuntimeError("malicious MBR marker string not found")

    mbr_off = marker_off - 0x34
    mbr = exe_bytes[mbr_off : mbr_off + 0x200]
    if len(mbr) != 0x200 or mbr[-2:] != b"\x55\xaa":
        raise RuntimeError("failed to locate embedded MBR payload")

    tail = mbr[0x1BE:0x1FE].lstrip(b"\x00")
    if not tail:
        raise RuntimeError("encoded tail not found in MBR partition table area")

    return bytes((byte - 13) & 0xFF for byte in tail).decode()


def main() -> int:
    flag = recover_flag(load_exe())
    print(flag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
