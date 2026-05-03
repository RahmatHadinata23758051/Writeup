#!/usr/bin/env python3

import re
import subprocess


PCAP = "Krasnodar.pcap"


def main() -> None:
    output = subprocess.check_output(
        ["tshark", "-r", PCAP, "-Y", "dns", "-T", "fields", "-e", "dns.qry.name"],
        text=True,
    )
    parts = []
    for name in output.splitlines():
        if ".exfiltrate.kubstu-ctf.ru" not in name:
            continue
        prefix = name.split(".exfiltrate.kubstu-ctf.ru", 1)[0]
        match = re.fullmatch(r"v\d{2}\.([0-9a-f]{4})", prefix)
        if match:
            parts.append(bytes.fromhex(match.group(1)).decode())
    flag = "".join(parts)
    print(flag)


if __name__ == "__main__":
    main()
