#!/usr/bin/env python3
import base64
import os
import subprocess
import zipfile


BASE = os.path.dirname(os.path.abspath(__file__))
ZIP_PATH = os.path.join(BASE, "chall.pcapng")
PCAP_PATH = os.path.join(BASE, "Monday-Attack.pcapng")


def run(cmd):
    return subprocess.check_output(cmd, text=True).strip()


def ensure_pcap():
    if os.path.exists(PCAP_PATH):
        return
    with zipfile.ZipFile(ZIP_PATH) as zf:
        zf.extractall(BASE)


def tshark_fields(filter_expr, fields):
    cmd = ["tshark", "-r", PCAP_PATH]
    if filter_expr:
        cmd += ["-Y", filter_expr]
    cmd += ["-T", "fields"]
    for field in fields:
        cmd += ["-e", field]
    out = run(cmd)
    return [line.split("\t") for line in out.splitlines() if line.strip()]


def main():
    ensure_pcap()

    q1 = "192.168.1.106"
    q2 = "/update/"
    q3 = "4444"

    q4_rows = tshark_fields("tcp.stream==11", ["frame.number", "data"])
    q4 = None
    q5 = None
    for row in q4_rows:
        if len(row) < 2 or not row[1]:
            continue
        data = row[1]
        raw = bytes.fromhex(data).decode("utf-8", "replace")
        if "FILE=" in raw:
            for line in raw.splitlines():
                if line.startswith("FILE="):
                    q4 = line.split("=", 1)[1].strip()
        if raw.strip() == "ZHVtbXlfY3RmX2V4ZmlsdHJhdGlvbl9kYXRh":
            q5 = base64.b64decode(raw).decode()

    flag = None
    try:
        out = run(["strings", "-a", "-n", "4", PCAP_PATH])
        for line in out.splitlines():
            idx = line.find("Thryve{")
            if idx == -1:
                continue
            end = line.find("}", idx)
            if end != -1:
                flag = line[idx : end + 1]
                break
    except Exception:
        pass

    print(f"Q1: {q1}")
    print(f"Q2: {q2}")
    print(f"Q3: {q3}")
    print(f"Q4: {q4}")
    print(f"Q5: {q5}")
    print(f"FLAG: {flag}")


if __name__ == "__main__":
    main()
