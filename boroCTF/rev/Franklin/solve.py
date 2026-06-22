#!/usr/bin/env python3
from fontTools.ttLib import TTFont


GLYPH_TEXT = {
    "braceleft": "{",
    "braceright": "}",
    "underscore": "_",
    "zero": "0",
    "one": "1",
    "four": "4",
    "seven": "7",
}


def glyph_to_text(name: str) -> str:
    if len(name) == 1:
        return name
    if name in GLYPH_TEXT:
        return GLYPH_TEXT[name]
    raise ValueError(f"Unhandled glyph component: {name}")


def extract_flag(path: str = "chall") -> str:
    font = TTFont(path)
    lookup = font["GSUB"].table.LookupList.Lookup[0]
    subtable = lookup.SubTable[0]

    for first, ligatures in subtable.ligatures.items():
        for ligature in ligatures:
            if ligature.LigGlyph != "asterisk":
                continue
            parts = [first, *ligature.Component]
            return "".join(glyph_to_text(part) for part in parts)

    raise RuntimeError("Flag ligature not found")


if __name__ == "__main__":
    print(extract_flag())
