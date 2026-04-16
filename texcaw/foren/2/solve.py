#!/usr/bin/env python3
from pathlib import Path
import mmap


IMG = Path("evidence.001")


def has_utf16(mm: mmap.mmap, text: str) -> bool:
    return mm.find(text.encode("utf-16le")) != -1


def main():
    seg_journal = None
    seg_files = None
    seg_ads = None
    seg_altered = None
    seg_uncovers = None

    with IMG.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        if has_utf16(mm, "flagsegment_u5njOurn@l"):
            seg_journal = "u5njOurn@l"
        if has_utf16(mm, "flagsegment_f1les.txt"):
            seg_files = "f1les"
        if mm.find(b"flagsegment_3fd19982505363d0") != -1:
            seg_ads = "3fd19982505363d0"
        if has_utf16(mm, "flagsegment_4lter3d"):
            seg_altered = "4lter3d"
        if has_utf16(mm, "flagsegment_unc0v3rs.txt"):
            seg_uncovers = "unc0v3rs"

    parts = [seg_journal, seg_uncovers, seg_altered, seg_files, seg_ads]
    if not all(parts):
        missing = [name for name, value in [
            ("journal", seg_journal),
            ("uncovers", seg_uncovers),
            ("altered", seg_altered),
            ("files", seg_files),
            ("ads", seg_ads),
        ] if not value]
        raise SystemExit(f"missing segments: {', '.join(missing)}")

    flag = "texsaw{" + "_".join(parts) + "}"
    print(flag)


if __name__ == "__main__":
    main()
