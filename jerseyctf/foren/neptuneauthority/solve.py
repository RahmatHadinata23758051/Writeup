#!/usr/bin/env python3
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

PCAP_DEFAULT = "neptune-defense.pcap"


def run(cmd):
    return subprocess.run(cmd, check=True, capture_output=True, text=True)


def need_tool(name):
    if shutil.which(name) is None:
        raise RuntimeError(f"Tool tidak ditemukan di PATH: {name}")


def extract_orbit_note(pcap):
    cmd = [
        "tshark", "-r", str(pcap),
        "-Y", "http.response.code==200",
        "-V",
    ]
    out = run(cmd).stdout
    m = re.search(r"X-Orbit-Note:\s*([^\r\n]+)", out)
    if not m:
        raise RuntimeError("Gagal menemukan header X-Orbit-Note di trafik HTTP 200")
    note = m.group(1)
    note = note.replace("\\r", "").replace("\\n", "").strip()
    return note


def decrypt_file(inp, outp, password):
    cmd = [
        "openssl", "enc", "-d", "-aes-256-cbc",
        "-in", str(inp),
        "-pass", f"pass:{password}",
        "-out", str(outp),
    ]
    # warning dari openssl tetap ditoleransi, yang penting exit code 0
    subprocess.run(cmd, check=True, capture_output=True, text=True)


def extract_shutdown_code_from_tls_debug(debug_path):
    data = bytearray()
    hex_line = re.compile(r"^\|\s*([0-9a-f]{2}(?:\s+[0-9a-f]{2})*)\s*\|", re.IGNORECASE)

    for line in debug_path.read_text(errors="ignore").splitlines():
        m = hex_line.match(line)
        if not m:
            continue
        hx = m.group(1).replace(" ", "")
        if len(hx) % 2:
            continue
        try:
            data.extend(bytes.fromhex(hx))
        except ValueError:
            pass

    text = data.decode("latin1", errors="ignore")
    m = re.search(r"SHUTDOWN_CODE:\s*(\d+)", text)
    if not m:
        raise RuntimeError("Gagal menemukan SHUTDOWN_CODE dari TLS debug output")
    return m.group(1)


def main():
    need_tool("tshark")
    need_tool("openssl")

    pcap = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else PCAP_DEFAULT)
    if not pcap.exists():
        raise FileNotFoundError(f"PCAP tidak ditemukan: {pcap}")

    with tempfile.TemporaryDirectory(prefix="na_solve_", dir=".") as td:
        td = pathlib.Path(td)
        http_dir = td / "http_objects"
        http_dir.mkdir(parents=True, exist_ok=True)

        # 1) export HTTP objects
        run(["tshark", "-r", str(pcap), "--export-objects", f"http,{http_dir}"])

        crt_enc = http_dir / "ods.crt.enc"
        key_enc = http_dir / "ods.key.enc"
        if not crt_enc.exists() or not key_enc.exists():
            raise RuntimeError("ods.crt.enc / ods.key.enc tidak ditemukan dari export objek HTTP")

        # 2) ambil passphrase dari header response
        orbit_note = extract_orbit_note(pcap)

        # 3) decrypt cert + key
        crt = td / "ods.crt"
        key = td / "ods.key"
        decrypt_file(crt_enc, crt, orbit_note)
        decrypt_file(key_enc, key, orbit_note)

        # 4) decrypt TLS stream & dump debug
        debug_file = td / "tlsdebug.txt"
        run([
            "tshark", "-r", str(pcap),
            "-o", f"tls.keys_list:10.20.0.50,8443,http,{key}",
            "-o", f"tls.debug_file:{debug_file}",
            "-Y", "tcp.stream==71",
        ])

        shutdown_code = extract_shutdown_code_from_tls_debug(debug_file)
        flag = f"jctf{{{shutdown_code}}}"
        print(flag)


if __name__ == "__main__":
    main()
