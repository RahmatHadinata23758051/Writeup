#!/usr/bin/env python3
import io
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path

import msoffcrypto
from PIL import Image, ImageOps
import pytesseract

CHAL_FILE = Path("file")
JTR_RUN = Path("/home/nata/ctf/darma/misc/3/Kampus_Biru-ForensicCTF/JohnTheRipper/run")
OFFICE2JOHN = JTR_RUN / "office2john.py"
JOHN = JTR_RUN / "john"
PASSWORD_LST = JTR_RUN / "password.lst"


def crack_password(target: Path) -> str:
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        hash_file = td / "hash.txt"
        pot_file = td / "local.pot"

        r = subprocess.run(
            [str(OFFICE2JOHN), str(target)],
            capture_output=True,
            text=True,
            check=True,
        )
        hash_file.write_text(r.stdout)

        subprocess.run(
            [
                str(JOHN),
                "--format=office",
                f"--wordlist={PASSWORD_LST}",
                f"--pot={pot_file}",
                str(hash_file),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        show = subprocess.run(
            [str(JOHN), "--show", f"--pot={pot_file}", str(hash_file)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout

    # format: file:password
    m = re.search(r"^[^:\n]+:([^:\n]+)$", show, re.M)
    if not m:
        raise RuntimeError("Password tidak ditemukan")
    return m.group(1)


def decrypt_office(target: Path, password: str) -> bytes:
    out = io.BytesIO()
    with target.open("rb") as f:
        doc = msoffcrypto.OfficeFile(f)
        doc.load_key(password=password)
        doc.decrypt(out)
    return out.getvalue()


def extract_flag_from_png(png_data: bytes) -> str:
    img = Image.open(io.BytesIO(png_data)).convert("RGB")
    candidates = []

    # Pakai channel biru + threshold karena paling bersih untuk teks flag di challenge ini.
    b = img.split()[2]
    candidates.append(b)
    candidates.append(b.point(lambda p: 255 if p > 80 else 0))
    candidates.append(ImageOps.autocontrast(b))

    for cand in candidates:
        txt = pytesseract.image_to_string(cand, config="--psm 3")
        m = re.search(r"CIT\{[A-Za-z0-9_]+\}", txt, re.I)
        if m:
            raw = m.group(0)
            # normalisasi OCR ambigu O/0 pada token w0rd
            return raw.replace("wOrd", "w0rd").replace("WOrd", "W0rd").upper().replace("{BIRD", "{bird").replace("_1S_", "_1s_").replace("_TH3_", "_th3_").replace("_W0RD", "_w0rd")

    raise RuntimeError("Flag tidak ditemukan via OCR")


def main():
    password = crack_password(CHAL_FILE)
    decrypted = decrypt_office(CHAL_FILE, password)

    with zipfile.ZipFile(io.BytesIO(decrypted)) as zf:
        png = zf.read("word/media/image1.png")

    flag = extract_flag_from_png(png)
    print(f"password: {password}")
    print(flag)


if __name__ == "__main__":
    main()
