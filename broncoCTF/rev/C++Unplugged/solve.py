#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

# Judul lagu -> token C++.
# Replacement dilakukan dari string terpanjang agar token yang menempel,
# seperti SmallerThanThisThisIsMe, berubah menjadi <= dengan benar.
REPLACEMENTS: dict[str, str] = {
    "BreakUpWithYourGirlfriendImBored": "/",
    "FreshOutTheSlammer": "]",
    "PleasePleasePlease": "if",
    "SmallerThanThis": "<",
    "CallItWhatYouWant": "string",
    "YouBrokeMeFirst": "break",
    "ShouldveSaidNo": "else",
    "ComeBackBeHere": "return",
    "PieceByPiece": "[",
    "CountingStars": "int",
    "FromTheStart": "(",
    "IsItOverNow": ")",
    "BeginAgain": "{",
    "EndOfTime": "}",
    "BadIdeaRight": "bool",
    "TruthHurts": "true",
    "ThisOrThat": "||",
    "SameOldLove": "==",
    "WithoutMe": "-",
    "FalseGod": "false",
    "Positions": "switch",
    "CaseClosed": "case",
    "AsItWas": "default",
    "GoodForYou": "for",
    "DejaVu": "while",
    "OnMyWay": "continue",
    "Abcdefu": "char",
    "ThisIsMe": "=",
    "PartOfMe": "%",
    "Starboy": "*",
    "Greedy": "&&",
    "Higher": ">",
    "EndGame": ";",
    "Mine": "+=",
    "More": "++",
}


def extract_cpp(text: str) -> str:
    """Ambil source C++ dari file asli atau hasil copy-paste terminal."""
    include_pos = text.find("#include")
    if include_pos == -1:
        raise ValueError("Tidak menemukan awal source C++ (#include)")

    source = text[include_pos:]

    # Buang prompt terminal yang ikut tersalin setelah source.
    prompt_match = re.search(r"\nnata in .+?➜\s*$", source)
    if prompt_match:
        source = source[:prompt_match.start()]

    return source


def restore_source(obfuscated: str) -> str:
    restored = obfuscated

    # Tiga placeholder operator berada di dalam character literal dengan spasi.
    # Hilangkan spasinya supaya hasil menjadi '*', '{', dan '}'.
    restored = restored.replace("' Starboy '", "'*'")
    restored = restored.replace("' BeginAgain '", "'{'")
    restored = restored.replace("' EndOfTime '", "'}'")

    for title in sorted(REPLACEMENTS, key=len, reverse=True):
        restored = restored.replace(title, REPLACEMENTS[title])

    return restored


def compile_and_run(source: str) -> str:
    # Temporary directory tetap dibuat di folder kerja saat solver dijalankan.
    with tempfile.TemporaryDirectory(prefix=".cpp-unplugged-", dir=Path.cwd()) as tmp:
        tmp_dir = Path(tmp)
        source_path = tmp_dir / "restored.cpp"
        binary_path = tmp_dir / "restored"

        source_path.write_text(source, encoding="utf-8")

        compile_result = subprocess.run(
            ["g++", "-std=c++17", "-O2", str(source_path), "-o", str(binary_path)],
            capture_output=True,
            text=True,
        )
        if compile_result.returncode != 0:
            raise RuntimeError(
                "Kompilasi gagal:\n"
                + compile_result.stdout
                + compile_result.stderr
            )

        run_result = subprocess.run(
            [str(binary_path)],
            capture_output=True,
            text=True,
        )
        if run_result.returncode != 0:
            raise RuntimeError(
                f"Program berhenti dengan kode {run_result.returncode}:\n"
                + run_result.stdout
                + run_result.stderr
            )

        return run_result.stdout.strip()


def main() -> None:
    input_path = Path(
        sys.argv[1] if len(sys.argv) > 1 else "totallynormalcode.cpp"
    )

    raw_text = input_path.read_text(encoding="utf-8")
    restored = restore_source(extract_cpp(raw_text))
    output = compile_and_run(restored)

    match = re.search(r"bronco\{[^}\n]+\}", output)
    if not match:
        raise ValueError(f"Flag tidak ditemukan pada output: {output!r}")

    print(output)
    print(f"[+] Flag: {match.group(0)}")


if __name__ == "__main__":
    main()
