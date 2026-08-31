#!/usr/bin/env python3
import argparse
import hashlib
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

HOST_DEFAULT = "34.2.22.80"
PORT_DEFAULT = 30096
DEFAULT_CTFD_TOKEN = "ctfd_fbee761c64f386754e6a81f5b33dea580f61385c934ba9987349716ce6441f7e"

DEBUG = os.environ.get("BQ_DEBUG", "") not in ("", "0", "false", "False")
PROMPT_MARKERS = [b"Masukkan pilihan", b"masukkan pilihan"]
FLAG_RE = re.compile(r"COMPFEST18\{[^}\r\n]+\}")

JAVA_SRC = r'''
import java.util.*;

public class BQCalc {
    static int[] invTable(int[] tab) {
        int[] inv = new int[tab.length];
        for (int i = 0; i < tab.length; i++) inv[tab[i]] = i;
        return inv;
    }

    static int[] invOp(int op, int[] arr) {
        int n = arr.length;
        int[] out = new int[n];
        switch (op) {
            case 0:
                return arr.clone();
            case 1:
                for (int i = 0; i < n; i++) out[n - 1 - i] = arr[i];
                return out;
            case 2:
                for (int i = 0; i < n; i++) out[i] = 31 - arr[i];
                return out;
            case 3:
                for (int i = 0; i < n; i++) {
                    int v = arr[i], r = 0;
                    for (int b = 0; b < 5; b++) r = (r << 1) | ((v >> b) & 1);
                    out[i] = r & 31;
                }
                return out;
            case 4: {
                int[] f = new int[] {
                    0,1,3,2,6,7,5,4,12,13,15,14,10,11,9,8,
                    24,25,27,26,30,31,29,28,20,21,23,22,18,19,17,16
                };
                int[] inv = invTable(f);
                for (int i = 0; i < n; i++) out[i] = inv[arr[i] & 31];
                return out;
            }
            case 5:
                for (int i = 0; i < n; i++) out[i] = ((arr[i] >> 1) | ((arr[i] & 1) << 4)) & 31;
                return out;
            case 6:
                for (int i = 0; i < n; i++) out[i] = ((arr[i] >> 2) | ((arr[i] & 3) << 3)) & 31;
                return out;
            case 7:
                for (int i = 0; i < n; i++) out[i] = (arr[i] - i) & 31;
                return out;
            case 8:
                for (int i = 0; i < n; i++) out[i] = (arr[i] * 23) & 31;
                return out;
            case 9:
                for (int i = 0; i < n; i++) out[i] = (arr[i] * 11) & 31;
                return out;
            case 10:
                out[0] = arr[0];
                for (int i = 1; i < n; i++) out[i] = (arr[i] ^ arr[i - 1]) & 31;
                return out;
            case 11:
                for (int i = 0; i < n; i++) out[(i + 2) % n] = arr[i];
                return out;
            case 12:
                out[0] = arr[0];
                for (int i = 1; i < n; i++) out[i] = (arr[i] - arr[i - 1]) & 31;
                return out;
            case 13:
                out[0] = arr[0];
                for (int i = 1; i < n; i++) out[i] = (arr[i] - out[i - 1]) & 31;
                return out;
            case 14:
                for (int i = 0; i < n; i++) out[i] = (11 * ((arr[i] - i) & 31)) & 31;
                return out;
            case 15:
                for (int i = 0; i < n; i++) {
                    int y = arr[i];
                    int x = (y == 31) ? 31 : ((16 * y) % 31);
                    out[n - 1 - i] = x;
                }
                return out;
            case 16: {
                int half = (n + 1) / 2;
                for (int i = 0; i < half; i++) out[2 * i] = arr[i];
                for (int i = half; i < n; i++) out[2 * (i - half) + 1] = arr[i];
                return out;
            }
            case 17:
                for (int i = 0; i < n; i++) out[(i + 1) % n] = arr[i];
                return out;
            default:
                throw new RuntimeException("bad op " + op);
        }
    }

    static String password(int h, int g, int bp, String cpHex, int bq, String dqHex, int br, String crHex, int s) throws Exception {
        byte[][] item = new byte[][] {
            p.a(h),
            p.a(g),
            p.a(bp),
            p.b(cpHex),
            p.a(bq),
            p.b(dqHex),
            p.a(br),
            p.b(crHex),
            p.a(s)
        };

        byte[] concat = new byte[0];
        for (byte[] x : item) concat = p.a(concat, x);
        long t = p.b(p.a(concat)) % 17643225600L;
        int[] u = p.a(t, 18, 9);

        byte[] gh = p.a(p.a(g), p.a(h));
        long v = p.b(p.a(gh)) % 362880L;
        int[] w = p.a(v, 9, 9);

        byte[][] perm = new byte[item.length][];
        for (int i = 0; i < item.length; i++) perm[i] = item[w[i]];

        byte[] state = p.a(p.a(u[0], perm[0]));
        for (int i = 1; i < perm.length; i++) state = p.b(state, p.a(u[i], perm[i]));
        int[] y = p.a(state, 16);

        int[] cur = y.clone();
        for (int i = u.length - 1; i >= 0; i--) cur = invOp(u[i], cur);

        String alphabet = p.b((int)(t % 32L));
        StringBuilder sb = new StringBuilder();
        for (int idx : cur) sb.append(alphabet.charAt(idx));
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 9) throw new RuntimeException("args: h g bp cpHex bq dqHex br crHex s");
        System.out.println(password(
            Integer.parseInt(args[0]), Integer.parseInt(args[1]),
            Integer.parseInt(args[2]), args[3],
            Integer.parseInt(args[4]), args[5],
            Integer.parseInt(args[6]), args[7],
            Integer.parseInt(args[8])
        ));
    }
}
'''

def dbg(data: bytes):
    if DEBUG and data:
        sys.stderr.write(data.decode("utf-8", "replace"))
        sys.stderr.flush()

def has_any(data: bytes, markers) -> bool:
    low = data.lower()
    for marker in markers:
        m = marker if isinstance(marker, bytes) else marker.encode()
        if m in data or m.lower() in low:
            return True
    return False

def recv_some(sock: socket.socket, total=2.0, idle=0.35) -> bytes:
    data = b""
    deadline = time.time() + total
    last = None
    sock.settimeout(0.12)

    while time.time() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            if data and last is not None and time.time() - last >= idle:
                break
            continue

        if not chunk:
            break

        data += chunk
        last = time.time()
        dbg(chunk)

    return data

def recv_until(sock: socket.socket, markers, timeout=12.0, idle=0.60) -> bytes:
    if isinstance(markers, (bytes, str)):
        markers = [markers]

    data = b""
    deadline = time.time() + timeout
    last = None
    sock.settimeout(0.15)

    while time.time() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            if data and last is not None and time.time() - last >= idle:
                break
            continue

        if not chunk:
            break

        data += chunk
        last = time.time()
        dbg(chunk)

        if has_any(data, markers):
            break

    return data

def sendline(sock: socket.socket, s: str):
    if DEBUG:
        sys.stderr.write(f"\n>>> {s}\n")
        sys.stderr.flush()
    sock.sendall(s.encode() + b"\n")

def to_text(data: bytes) -> str:
    return data.decode("utf-8", "ignore")

def die_dump(msg: str, blob: str):
    raise RuntimeError(f"{msg}\n--- dump terakhir ---\n{blob[-2000:]!r}")

def pick_int(pattern: str, blob: str, name: str) -> int:
    m = re.findall(pattern, blob, flags=re.I)
    if not m:
        die_dump(f"gagal parse {name}", blob)
    return int(m[-1])

def pick_hex(pattern: str, blob: str, name: str) -> str:
    m = re.findall(pattern, blob, flags=re.I)
    if not m:
        die_dump(f"gagal parse {name}", blob)
    return m[-1]

def sync_initial_menu(sock: socket.socket, token: str | None):
    data = recv_until(sock, PROMPT_MARKERS, timeout=20.0, idle=0.8)
    low = data.lower()

    # Kadang remote cuma nge-print token:
    # CTFd access token: ctfd_xxx
    # Kalau begitu jangan kirim token, lanjut baca menu.
    if not has_any(data, PROMPT_MARKERS) and b"access token" in low:
        if b"ctfd_" in low:
            data += recv_until(sock, PROMPT_MARKERS, timeout=20.0, idle=0.8)
        else:
            if not token:
                raise RuntimeError("remote minta CTFd token, tapi token kosong")
            print("[+] sent CTFd token")
            sendline(sock, token)
            data += recv_until(sock, PROMPT_MARKERS, timeout=20.0, idle=0.8)

    if not has_any(data, PROMPT_MARKERS):
        data += recv_some(sock, total=3.0, idle=0.8)

    if not has_any(data, PROMPT_MARKERS):
        die_dump("menu awal tidak kebaca", to_text(data))

    return to_text(data)

def menu(sock: socket.socket, opt: str, timeout=12.0) -> str:
    sendline(sock, opt)
    data = recv_until(sock, PROMPT_MARKERS, timeout=timeout, idle=0.8)

    if not data or len(data.strip()) < 5:
        data += recv_some(sock, total=4.0, idle=0.8)

    return to_text(data)

def login(sock: socket.socket, username: str, password: str) -> str:
    sendline(sock, "1")

    got = recv_until(sock, [b"username", b"Username"], timeout=8.0, idle=0.8)
    if b"username" not in got.lower():
        die_dump("prompt username tidak kebaca", to_text(got))

    sendline(sock, username)

    got = recv_until(sock, [b"password", b"Password"], timeout=8.0, idle=0.8)
    if b"password" not in got.lower():
        die_dump("prompt password tidak kebaca", to_text(got))

    sendline(sock, password)

    out = recv_until(sock, PROMPT_MARKERS, timeout=15.0, idle=0.8)
    if not out:
        out += recv_some(sock, total=5.0, idle=0.8)

    return to_text(out)

def u32be(x: int) -> bytes:
    return int(x).to_bytes(4, "big", signed=False)

def longhash(data: bytes) -> int:
    d = hashlib.sha256(data).digest()
    return int.from_bytes(d[:8], "big") & 0x7FFFFFFFFFFFFFFF

def kperm(num: int, maxn: int, count: int):
    pool = list(range(maxn))
    out = []

    for i in range(count):
        radix = maxn - i
        rest = 1

        for j in range(i + 1, count):
            rest *= maxn - j

        idx = (num // rest) % radix
        out.append(pool.pop(idx))

    return out

def quest_path(level: int, coins: int):
    # Ini bug solver lama: jangan double sha256.
    # l.<init>() pakai sha256(u32(level)||u32(coins)) % 4896.
    n = longhash(u32be(level) + u32be(coins)) % 4896
    return [f"Q{x + 1}" for x in kperm(n, 18, 3)]

def ensure_java_helper(base: Path, jar: Path):
    src = base / "BQCalc.java"
    cls = base / "BQCalc.class"

    if not src.exists() or src.read_text(errors="ignore") != JAVA_SRC:
        src.write_text(JAVA_SRC)
        if cls.exists():
            cls.unlink()

    if not cls.exists():
        cp = f".{os.pathsep}{jar.name}"
        r = subprocess.run(
            ["javac", "-cp", cp, src.name],
            cwd=base,
            text=True,
            capture_output=True,
        )

        if r.returncode != 0:
            raise RuntimeError(
                "javac gagal. Pastikan JDK ada dan burhanquest.jar satu folder dengan solve.py\n"
                + r.stderr
            )

def calc_admin_password(base: Path, jar: Path, h, g, bp, cp_hex, bq, dq_hex, br, cr_hex, s) -> str:
    ensure_java_helper(base, jar)

    cp = f".{os.pathsep}{jar.name}"
    args = [str(x) for x in [h, g, bp, cp_hex, bq, dq_hex, br, cr_hex, s]]

    r = subprocess.run(
        ["java", "-cp", cp, "BQCalc", *args],
        cwd=base,
        text=True,
        capture_output=True,
    )

    if r.returncode != 0:
        raise RuntimeError("java helper gagal\n" + r.stderr)

    return r.stdout.strip().splitlines()[-1]

def do_quest(sock: socket.socket, qid: str) -> int:
    sendline(sock, "5")

    out = recv_until(sock, [b"ID Quest", b"Quest"], timeout=8.0, idle=0.8)

    sendline(sock, qid)

    out += recv_until(sock, PROMPT_MARKERS, timeout=18.0, idle=0.8)
    blob = to_text(out)

    return pick_int(
        r"sigil-pertempuran\s*\[[^\]]+\]\s*:\s*(\d+)",
        blob,
        f"battle sigil {qid}",
    )
def rol(x, r):
    return ((x << r) | (x >> (8 - r))) & 255

def ror(x, r):
    return ((x >> r) | ((x << (8 - r)) & 255)) & 255

def ungray(g):
    x = g
    x ^= x >> 1
    x ^= x >> 2
    x ^= x >> 4
    return x & 255

def inv_byte_op(op, arr):
    n = len(arr)
    y = list(arr)
    x = [0] * n

    if op == 0:
        return y[:]
    if op == 1:
        return y[::-1]
    if op == 2:
        return [255 - v for v in y]
    if op == 3:
        out = []
        for v in y:
            r = 0
            for i in range(8):
                r = (r << 1) | ((v >> i) & 1)
            out.append(r)
        return out
    if op == 4:
        return [ror(v, 3) for v in y]
    if op == 5:
        return [ungray(v) for v in y]
    if op == 6:
        return [ror(v, 2) for v in y]
    if op == 7:
        return [(v - i) & 255 for i, v in enumerate(y)]
    if op == 8:
        return [(v * 183) & 255 for v in y]
    if op == 9:
        x[0] = y[0]
        for i in range(1, n):
            x[i] = y[i] ^ y[i - 1]
        return x
    if op == 10:
        return [y[(i - 2) % n] for i in range(n)]
    if op == 11:
        return [(v * 171) & 255 for v in y]
    if op == 12:
        return [((v - i) * 171) & 255 for i, v in enumerate(y)]
    if op == 14:
        half = (n + 1) // 2
        for i in range(half):
            x[2 * i] = y[i]
        for j in range(n - half):
            x[2 * j + 1] = y[half + j]
        return x
    if op == 15:
        return [y[(i - 1) % n] for i in range(n)]
    if op == 16:
        x[0] = y[0]
        for i in range(1, n):
            x[i] = (y[i] - x[i - 1]) & 255
        return x
    if op == 17:
        x[0] = y[0]
        for i in range(1, n):
            x[i] = (y[i] - y[i - 1]) & 255
        return x

    raise ValueError(f"unsupported byte op {op}")

def decode_sealed_archive(hex_blob, ops):
    cur = list(bytes.fromhex(hex_blob))
    for op in reversed(ops):
        cur = inv_byte_op(op, cur)
    return bytes(cur).decode("utf-8", "replace")


def archive_ops(h, g, bp, cp_hex, bq, dq_hex, br, cr_hex, s):
    # Sama kayak admin password: t = sha256(all sigil/state) % 17643225600
    items = [
        u32be(h),
        u32be(g),
        u32be(bp),
        bytes.fromhex(cp_hex),
        u32be(bq),
        bytes.fromhex(dq_hex),
        u32be(br),
        bytes.fromhex(cr_hex),
        u32be(s),
    ]
    t = longhash(b"".join(items)) % 17643225600
    return kperm(t, 18, 9)

def solve(host: str, port: int, jar: Path, token: str | None):
    base = Path.cwd()

    print(f"[+] connect {host}:{port}")

    with socket.create_connection((host, port), timeout=12.0) as sock:
        sync_initial_menu(sock, token)

        out = login(sock, "frieren", "frieren")
        if "Login berhasil" not in out and "Menu Pengembara" not in out:
            die_dump("login frieren kemungkinan gagal", out)

        print("[+] logged in as frieren")

        info = ""
        for _ in range(3):
            info += menu(sock, "1", timeout=15.0)

            if re.search(r"Level\s+Pengembara\s*:\s*\d+", info, re.I):
                break

            info += to_text(recv_some(sock, total=3.0, idle=0.8))

        h = pick_int(r"Level\s+Pengembara\s*:\s*(\d+)", info, "level")
        g = pick_int(r"Koin\s+Didapatkan\s*:\s*(\d+)", info, "coins")

        qs = quest_path(h, g)
        print(f"[+] level={h} coins={g} path={' > '.join(qs)}")

        bp = do_quest(sock, qs[0])
        arch1 = menu(sock, "7", timeout=10.0)
        cp_hex = pick_hex(r"sigil-arsip\s*:\s*([0-9a-fA-F]+)", arch1, "archive sigil 1")
        print(f"[+] {qs[0]} battle={bp} archive={cp_hex}")

        bq = do_quest(sock, qs[1])
        exp = menu(sock, "6", timeout=10.0)
        dq_hex = pick_hex(r"sigil-ekspor\s*:\s*([0-9a-fA-F]+)", exp, "export sigil")
        print(f"[+] {qs[1]} battle={bq} export={dq_hex}")

        br = do_quest(sock, qs[2])
        arch3 = menu(sock, "7", timeout=10.0)
        cr_hex = pick_hex(r"sigil-arsip\s*:\s*([0-9a-fA-F]+)", arch3, "archive sigil 3")

        info2 = menu(sock, "1", timeout=10.0)
        s = pick_int(r"Koin\s+Didapatkan\s*:\s*(\d+)", info2, "final coins")

        print(f"[+] {qs[2]} battle={br} archive={cr_hex} final_coins={s}")

        pw = calc_admin_password(base, jar, h, g, bp, cp_hex, bq, dq_hex, br, cr_hex, s)
        print(f"[+] admin password = {pw}")

        # Logout dari wanderer.
        menu(sock, "0", timeout=8.0)

        out = login(sock, "burhan", pw)
        if "Admin" not in out and "Menu" not in out:
            die_dump("login admin gagal", out)

        print("[+] logged in as burhan")

        sendline(sock, "13")

        final = recv_until(sock, PROMPT_MARKERS, timeout=10.0, idle=0.8)
        final += recv_some(sock, total=2.0, idle=0.8)

        txt = to_text(final)
        m = FLAG_RE.search(txt)
        if m:
            print(f"<FLAG>{m.group(0)}</FLAG>")
            return

        hm = re.search(r"\b[0-9a-fA-F]{40,}\b", txt)
        if not hm:
            print("[!] flag regex belum ketemu, dump output akhir:")
            print(txt)
            return

        sealed_hex = hm.group(0)
        ops = archive_ops(h, g, bp, cp_hex, bq, dq_hex, br, cr_hex, s)
        print(f"[+] archive ops = {ops}")

        decoded = decode_sealed_archive(sealed_hex, ops)
        m2 = FLAG_RE.search(decoded)

        if not m2:
            print("[!] decode archive belum menghasilkan flag. Dump decoded:")
            print(decoded)
            return

        print(f"<FLAG>{m2.group(0)}</FLAG>")
        return

def main():
    ap = argparse.ArgumentParser(description="BurhanQuest remote solver")
    ap.add_argument("host", nargs="?", default=HOST_DEFAULT)
    ap.add_argument("port", nargs="?", default=PORT_DEFAULT, type=int)
    ap.add_argument("--jar", default="burhanquest.jar")
    ap.add_argument("--token", default=os.environ.get("BQ_TOKEN", DEFAULT_CTFD_TOKEN))
    ap.add_argument("--offline-test", action="store_true")
    args = ap.parse_args()

    jar = Path(args.jar).resolve()

    if not jar.exists():
        print(f"[-] jar tidak ketemu: {jar}", file=sys.stderr)
        sys.exit(1)

    if args.offline_test:
        pw = calc_admin_password(
            Path.cwd(), jar,
            8, 3042,
            45461, "e6b5534db151",
            47556, "04ead7b47299",
            25080, "acfe2181f761",
            4041,
        )
        print(pw)
        return

    solve(args.host, args.port, jar, args.token)

if __name__ == "__main__":
    main()
