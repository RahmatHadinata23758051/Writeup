from pathlib import Path


def extract_flag(path: str = "ancient_note.txt") -> str:
    text = Path(path).read_text(encoding="utf-8")
    hidden = [ch for ch in text if ch in ("\u200b", "\u200c")]
    bits = "".join("0" if ch == "\u200b" else "1" for ch in hidden)
    return "".join(chr(int(bits[i : i + 8], 2)) for i in range(0, len(bits), 8))


if __name__ == "__main__":
    print(extract_flag())
