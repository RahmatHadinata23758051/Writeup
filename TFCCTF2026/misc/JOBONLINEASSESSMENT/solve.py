#!/usr/bin/env python3

"""Complete the supplied Packet Tracer activity and optionally submit it."""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_URL = (
    "https://j-b-online-assessment-5600642a6c9c6e06.challs.ctf.thefewchosen.com"
)


def load_codec():
    tool_dir = BASE_DIR / "pka-tools"
    if not (tool_dir / "pka2xml" / "libtwofish.so").exists():
        raise RuntimeError(
            "missing pka-tools codec; clone cisco-pka-to-xml into pka-tools "
            "and run: python3 pka-tools/build_libtwofish.py"
        )
    sys.path.insert(0, str(tool_dir))
    from pka2xml import PkaError, decrypt_pka, encrypt_pka  # type: ignore

    return PkaError, decrypt_pka, encrypt_pka


def complete_activity(source: Path, output: Path) -> tuple[int, int]:
    PkaError, decrypt_pka, encrypt_pka = load_codec()
    try:
        xml = decrypt_pka(source.read_bytes())
    except PkaError as exc:
        raise RuntimeError(f"cannot decrypt {source.name}: {exc}") from exc

    root = ET.fromstring(xml)
    snapshots = root.findall("PACKETTRACER5")
    if len(snapshots) < 3:
        raise RuntimeError(f"expected at least 3 Packet Tracer snapshots, found {len(snapshots)}")

    active = snapshots[0]
    target = snapshots[2]
    active_network = active.find("NETWORK")
    target_network = target.find("NETWORK")
    if active_network is None or target_network is None:
        raise RuntimeError("activity snapshots do not contain NETWORK sections")

    position = list(active).index(active_network)
    active.remove(active_network)
    active.insert(position, copy.deepcopy(target_network))

    rebuilt_xml = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    output.write_bytes(encrypt_pka(rebuilt_xml))

    return len(root.findall("COMPARISONS/NODE/NODE")), len(
        target_network.findall("DEVICES/DEVICE")
    )


def submit(path: Path, url: str) -> dict:
    request = urllib.request.Request(
        url.rstrip("/") + "/api/submit",
        data=path.read_bytes(),
        headers={"content-type": "application/octet-stream"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=180) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-i", "--input", type=Path, default=BASE_DIR / "job-oa.pka")
    parser.add_argument("-o", "--output", type=Path, default=BASE_DIR / "completed.pka")
    parser.add_argument("--submit", action="store_true", help="submit the rebuilt file")
    parser.add_argument("--url", default=os.environ.get("HOST_URL", DEFAULT_URL))
    args = parser.parse_args()

    comparison_nodes, devices = complete_activity(args.input, args.output)
    print(f"[+] rebuilt {args.output.name}: target snapshot has {devices} devices")
    print(f"[+] comparison tree loaded: {comparison_nodes} top-level nodes")

    if args.submit:
        result = submit(args.output, args.url)
        print(json.dumps(result, indent=2))
        if result.get("flag"):
            print(f"<FLAG>{result['flag']}</FLAG>")


if __name__ == "__main__":
    main()
