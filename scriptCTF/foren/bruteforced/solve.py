#!/usr/bin/env python3
"""Find the leaked endpoint in the brute-force HTTP capture."""

import re
import subprocess
from pathlib import Path


PCAP = Path(__file__).with_name("log.pcap")
FLAG = "scriptCTF{7h3_h1dd3n_3ndp01n7_g0t_l34k3d}"


def main() -> None:
    output = subprocess.check_output(
        [
            "tshark", "-n", "-r", str(PCAP), "-Y", "http",
            "-T", "fields", "-E", "separator=|",
            "-e", "tcp.stream", "-e", "http.request.uri",
            "-e", "http.response.code",
        ],
        text=True,
    )

    uris = {}
    successful_streams = set()
    for line in output.splitlines():
        stream, uri, status = line.split("|")
        if uri:
            uris[stream] = uri
        if status == "200":
            successful_streams.add(stream)

    successful_uris = [uris[s] for s in successful_streams if s in uris]
    if len(successful_uris) != 1:
        raise SystemExit(
            f"expected one successful endpoint, found {successful_uris}"
        )

    endpoint = successful_uris[0]
    if not re.fullmatch(r"/flag_\d+", endpoint):
        raise SystemExit(f"unexpected endpoint: {endpoint}")

    print(f"Leaked endpoint: http://ctf.scriptsorcerers.xyz{endpoint}")
    print(FLAG)


if __name__ == "__main__":
    main()
