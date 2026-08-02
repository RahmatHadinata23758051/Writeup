#!/usr/bin/env python3

import re
from pathlib import Path

import matplotlib.pyplot as plt


PGN_FILE = Path("games.pgn")


def extract_queen_paths(pgn_text: str):
    games = [
        game
        for game in re.split(r"(?=\[Event )", pgn_text)
        if game.strip()
    ]

    paths = []

    for game in games:
        movetext = " ".join(
            line.strip()
            for line in game.splitlines()
            if line.strip() and not line.startswith("[")
        )

        # Posisi awal menteri putih adalah d1.
        queen_path = [(3, 0)]
        white_to_move = True

        for token in movetext.split():
            # Abaikan nomor langkah.
            if re.fullmatch(r"\d+\.(?:\.\.)?", token):
                continue

            # Abaikan hasil pertandingan.
            if token in {"1-0", "0-1", "1/2-1/2", "*"}:
                continue

            # Ambil petak tujuan setiap langkah menteri putih.
            if white_to_move and token.startswith("Q"):
                match = re.search(
                    r"([a-h])([1-8])(?:=[QRBN])?[+#]?$",
                    token,
                )

                if match:
                    file_index = ord(match.group(1)) - ord("a")
                    rank_index = int(match.group(2)) - 1
                    queen_path.append((file_index, rank_index))

            white_to_move = not white_to_move

        paths.append(queen_path)

    return paths


def main():
    pgn_text = PGN_FILE.read_text(encoding="utf-8")
    paths = extract_queen_paths(pgn_text)

    print(f"[+] Total games: {len(paths)}")

    fig, axes = plt.subplots(4, 6, figsize=(15, 10))

    for game_number, (axis, path) in enumerate(
        zip(axes.flat, paths),
        start=1,
    ):
        x_coordinates = [point[0] for point in path]
        y_coordinates = [point[1] for point in path]

        axis.plot(
            x_coordinates,
            y_coordinates,
            marker="o",
            markersize=3,
        )

        axis.set_xlim(-0.5, 7.5)
        axis.set_ylim(-0.5, 7.5)
        axis.set_xticks(range(8), labels=list("abcdefgh"))
        axis.set_yticks(range(8), labels=range(1, 9))
        axis.grid(alpha=0.3)
        axis.set_aspect("equal")
        axis.set_title(f"Game {game_number}")

    plt.tight_layout()
    plt.savefig("queen_paths.png", dpi=200)

    print("[+] Saved: queen_paths.png")
    print("[+] Message: HARD TO KEEP UP WITH THE QUEEN")
    print("[+] Flag: L3AK{HARD_TO_KEEP_UP_WITH_THE_QUEEN}")


if __name__ == "__main__":
    main()
