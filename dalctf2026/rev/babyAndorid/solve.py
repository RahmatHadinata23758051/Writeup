#!/usr/bin/env python3
from pathlib import Path
import re


BASE = Path(__file__).resolve().parent / "apkout"


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def extract(pattern: str, text: str, label: str) -> str:
    match = re.search(pattern, text)
    if not match:
        raise SystemExit(f"missing {label}")
    return match.group(1)


def main() -> None:
    flag1 = extract(
        r'const-string v0, "([^"]+)"',
        read_text(BASE / "smali_classes4/com/example/babyandroid/MainActivity.smali"),
        "flag1",
    )
    flag2 = extract(
        r'<string name="flag2">(.*?)</string>',
        read_text(BASE / "res/values/strings.xml"),
        "flag2",
    )
    flag3 = extract(
        r'const-string v0, "([^"]+)"',
        read_text(BASE / "smali_classes3/com/example/babyandroid/ui/theme/ColorKt.smali"),
        "flag3",
    )
    print(flag1 + flag2 + flag3)


if __name__ == "__main__":
    main()
