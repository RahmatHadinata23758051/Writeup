#!/usr/bin/env python3

import base64
import gzip
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
WORK = ROOT / "solve_work"


def run(cmd, *, input_text=None, text_output=True):
    result = subprocess.run(
        cmd,
        input=input_text,
        text=True if input_text is not None else False,
        capture_output=True,
        cwd=ROOT,
        check=True,
    )
    if text_output:
        return result.stdout.decode() if isinstance(result.stdout, bytes) else result.stdout
    return result.stdout if isinstance(result.stdout, bytes) else result.stdout.encode()


def extract_with_7z(archive: Path, outdir: Path, password: str | None = None):
    outdir.mkdir(parents=True, exist_ok=True)
    cmd = ["7z", "x", "-y", str(archive), f"-o{outdir}"]
    if password is not None:
        cmd.insert(2, f"-p{password}")
    run(cmd)


def main():
    zip_path = ROOT / "layers.zip"
    if not zip_path.exists():
        print("layers.zip not found", file=sys.stderr)
        sys.exit(1)

    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir()

    extract_with_7z(zip_path, WORK / "top")

    layer1_zip = WORK / "top" / "layers" / "layer1.zip"
    extract_with_7z(layer1_zip, WORK / "layer1")

    dmg_path = WORK / "layer1" / "layer1" / "layer1.dmg"
    extract_with_7z(dmg_path, WORK / "layer1_contents")

    clue = (WORK / "layer1_contents" / "clue.txt").read_text()
    l2_password = clue.split("L2_PASSWORD=", 1)[1].splitlines()[0].strip()

    layer2_zip = WORK / "top" / "layers" / "layer2.zip"
    extract_with_7z(layer2_zip, WORK / "layer2", l2_password)

    vhdx_path = WORK / "layer2" / "evidence.vhdx"
    extract_with_7z(vhdx_path, WORK / "layer2_contents")

    secret_b64 = (WORK / "layer2_contents" / "report.txt:secret.bin").read_text().strip()
    l3_line = base64.b64decode(secret_b64).decode().strip()
    l3_password = l3_line.split("=", 1)[1]

    layer3_zip = WORK / "top" / "layers" / "layer3.zip"
    extract_with_7z(layer3_zip, WORK / "layer3", l3_password)

    ext4_img = WORK / "layer3" / "ext4.img"
    unalloc = run(["blkls", "-f", "ext4", str(ext4_img)], text_output=False)
    flag = gzip.decompress(unalloc).decode("utf-8", errors="ignore").split("\x00", 1)[0]

    print(flag)


if __name__ == "__main__":
    main()
