#!/usr/bin/env python3
import subprocess
import sys


def run(cmd):
    return subprocess.check_output(cmd, text=True)


def main():
    pcap = sys.argv[1] if len(sys.argv) > 1 else "nmap12.pcapng"
    cmd = [
        "tshark", "-r", pcap,
        "-Y", "http.request && (http.request.uri contains \"/api?data=\" || http.request.uri contains \"/track?info=\" || http.request.uri contains \"/debug?log=\")",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "http.request.uri",
    ]
    out = run(cmd).strip().splitlines()

    parts = {"api": "", "track": "", "debug": ""}
    for line in out:
        cols = line.split("\t")
        if len(cols) < 2:
            continue
        uri = cols[1]
        if uri.startswith("/api?data="):
            parts["api"] = uri.split("=", 1)[1]
        elif uri.startswith("/track?info="):
            parts["track"] = uri.split("=", 1)[1]
        elif uri.startswith("/debug?log="):
            parts["debug"] = uri.split("=", 1)[1]

    flag = parts["api"] + parts["track"] + parts["debug"]
    if not flag:
        raise SystemExit("Flag parts not found")
    print(flag)


if __name__ == "__main__":
    main()
