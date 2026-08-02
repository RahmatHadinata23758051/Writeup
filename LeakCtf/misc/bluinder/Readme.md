# Blunder

**Category:** Miscellaneous / Forensics

## Challenge Description

> Some say there's a lesson hidden in these games.  
> Wrap the flag in `L3AK{}`.

The challenge provides a file named `games.pgn` containing multiple chess games in **Portable Game Notation (PGN)** format.

---

## Initial Analysis

Opening the PGN file reveals several unusual characteristics:

- The file contains **24 chess games**.
- Every game is won by **Black**.
- In nearly every game, **White repeatedly moves only the queen**.
- The queen's movement appears completely unnatural for a real chess game.

For example, the first game contains moves like:

```text
4. Qf3
5. Qf4
6. Qf5
7. Qxf6
8. Qxe5
9. Qd5
10. Qxc5
...
```

Considering the challenge title **Blunder** and the description:

> *Some say there's a lesson hidden in these games.*

it becomes clear that the important information is **not** the game results, but the movement pattern of the white queen.

---

## Solution Idea

For every game:

1. Start from the white queen's initial position (`d1`).
2. Record every destination square visited by the queen.
3. Convert each chess square into board coordinates.
4. Draw the path in order.
5. Repeat for all 24 games.

Chess coordinates are mapped as:

```text
a1 -> (0,0)
b1 -> (1,0)
...
h8 -> (7,7)
```

When each queen path is visualized, every game forms a single letter.

With 24 games, the result is a **24-letter hidden message**.

---

## Solver

Save the following script as `solve.py`.

```python
#!/usr/bin/env python3

from pathlib import Path

import chess
import chess.pgn
import matplotlib.pyplot as plt


PGN_FILE = Path("games.pgn")
OUTPUT_FILE = Path("queen_paths.png")


def extract_white_queen_path(game: chess.pgn.Game):
    """
    Extract the movement path of White's queen.

    The queen starts from d1, and every destination square
    is appended to the path.
    """

    board = game.board()
    path = [chess.D1]

    for move in game.mainline_moves():
        piece = board.piece_at(move.from_square)

        if (
            piece is not None
            and piece.color == chess.WHITE
            and piece.piece_type == chess.QUEEN
        ):
            path.append(move.to_square)

        board.push(move)

    return path


def square_to_coordinate(square):
    return chess.square_file(square), chess.square_rank(square)


def load_games(path):
    games = []

    with path.open("r", encoding="utf-8") as pgn:
        while True:
            game = chess.pgn.read_game(pgn)

            if game is None:
                break

            games.append(game)

    return games


def plot_paths(paths):
    figure, axes = plt.subplots(4, 6, figsize=(16, 11))

    for number, (axis, path) in enumerate(zip(axes.flat, paths), start=1):
        coords = [square_to_coordinate(square) for square in path]

        xs = [x for x, _ in coords]
        ys = [y for _, y in coords]

        axis.plot(xs, ys, marker="o", markersize=3)

        axis.scatter(xs[0], ys[0], marker="s", s=45)
        axis.scatter(xs[-1], ys[-1], marker="x", s=55)

        axis.set_xlim(-0.5, 7.5)
        axis.set_ylim(-0.5, 7.5)
        axis.set_xticks(range(8), labels=list("abcdefgh"))
        axis.set_yticks(range(8), labels=range(1, 9))
        axis.set_aspect("equal")
        axis.grid(alpha=0.3)
        axis.set_title(str(number))

    figure.tight_layout()
    figure.savefig(OUTPUT_FILE, dpi=200)
    plt.close(figure)


def main():
    games = load_games(PGN_FILE)

    paths = [
        extract_white_queen_path(game)
        for game in games
    ]

    print(f"[+] Total games: {len(games)}")

    plot_paths(paths)

    print(f"[+] Visualization saved to: {OUTPUT_FILE}")
    print("[+] Read the letters from left to right, top to bottom.")
    print("[+] Message: HARD TO KEEP UP WITH THE QUEEN")
    print("[+] Flag: L3AK{HARDTOKEEPUPWITHTHEQUEEN}")


if __name__ == "__main__":
    main()
```

---

## Usage

Install the required dependencies:

```bash
pip install python-chess matplotlib
```

Run the solver:

```bash
python3 solve.py
```

Example output:

```text
[+] Total games: 24
[+] Visualization saved to: queen_paths.png
[+] Read the letters from left to right, top to bottom.
[+] Message: HARD TO KEEP UP WITH THE QUEEN
[+] Flag: L3AK{HARDTOKEEPUPWITHTHEQUEEN}
```

---

## Visualization

The queen paths form the following letters:

```text
H A R D  T O
K E E P  U P
W I T H  T H
E  Q U E E N
```

Reading them from left to right and top to bottom gives the hidden message:

```text
HARD TO KEEP UP WITH THE QUEEN
```

According to the challenge description, the recovered message is wrapped using the required flag format.

---

## Flag

```text
L3AK{HARDTOKEEPUPWITHTHEQUEEN}
```
