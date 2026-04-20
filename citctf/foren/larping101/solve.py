#!/usr/bin/env python3
import re
import sys
import zipfile

FLAG_RE = re.compile(r"CIT\{[^\r\n\t\f\v\}]+\}")


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else "challenge.pptx"

    try:
        with zipfile.ZipFile(target, "r") as zf:
            hits = []
            for name in zf.namelist():
                try:
                    data = zf.read(name)
                except Exception:
                    continue

                text = data.decode("utf-8", errors="ignore")
                for m in FLAG_RE.findall(text):
                    hits.append((name, m))

            if not hits:
                print("Flag not found")
                return 1

            # Deduplicate while preserving order
            seen = set()
            unique = []
            for src, flag in hits:
                key = (src, flag)
                if key not in seen:
                    seen.add(key)
                    unique.append((src, flag))

            for src, flag in unique:
                print(f"[+] {src}: {flag}")

            # Print main flag only (first hit) for quick use
            print(unique[0][1])
            return 0

    except FileNotFoundError:
        print(f"File not found: {target}")
        return 1
    except zipfile.BadZipFile:
        print(f"Not a valid PPTX/ZIP file: {target}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
