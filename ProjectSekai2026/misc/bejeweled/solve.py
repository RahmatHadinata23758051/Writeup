#!/usr/bin/env python3
from __future__ import annotations

import codecs
import re
import sys
import time
import socket
from dataclasses import dataclass

import pyte
from pwn import context, remote

HOST = "bejeweled.chals.sekai.team"
PORT = 1337

ROWS = 12
COLS = 7

TERM_WIDTH = 80
TERM_HEIGHT = 25

GEMS = {
    "♣": "C",
    "♧": "C",

    "●": "O",
    "○": "O",
    "•": "O",

    "♦": "D",
    "♢": "D",
    "◆": "D",
    "◇": "D",
    "◊": "D",

    "♥": "H",
    "♡": "H",

    "♠": "S",
    "♤": "S",

    "▲": "T",
    "△": "T",

    "■": "Q",
    "□": "Q",
    "▪": "Q",
    "▫": "Q",
    "⬛": "Q",
    "⬜": "Q",
    "◼": "Q",
}

FLAG_RE = re.compile(r"(?:SEKAI|sekai)\{[^}\r\n]+\}")

ANSI_RE = re.compile(
    r"(?:\x1b\][^\x07]*(?:\x07|\x1b\\))|"
    r"(?:\x1b[P^_].*?\x1b\\)|"
    r"(?:\x1b\[[0-?]*[ -/]*[@-~])",
    re.DOTALL,
)


@dataclass(frozen=True)
class BoardState:
    board: tuple[tuple[str, ...], ...]
    coords: tuple[tuple[tuple[int, int], ...], ...]

    @property
    def signature(self) -> str:
        return "".join("".join(row) for row in self.board)


class Game:
    def __init__(self):
        context.log_level = "error"

        ip = socket.gethostbyname(HOST)
        print(f"[*] Connecting to {HOST} ({ip}):{PORT}")
        self.io = remote(ip, PORT, timeout=8)
        self.screen = pyte.Screen(
            TERM_WIDTH,
            TERM_HEIGHT,
        )

        self.stream = pyte.Stream(self.screen)

        self.decoder = codecs.getincrementaldecoder(
            "utf-8"
        )("ignore")

        self.raw = bytearray()
        self.transcript = ""
        self._line_cache = [
            " " * TERM_WIDTH
            for _ in range(TERM_HEIGHT)
        ]

    def close(self):
        self.io.close()

    def answer_terminal_queries(self, data: bytes):
        if b"\x1b[6n" in data:
            self.io.send(b"\x1b[1;1R")

        if b"\x1b[c" in data:
            self.io.send(b"\x1b[?1;2c")

        if b"\x1b[18t" in data:
            response = (
                f"\x1b[8;"
                f"{TERM_HEIGHT};"
                f"{TERM_WIDTH}t"
            ).encode()

            self.io.send(response)

        if b"\x1b[14t" in data:
            self.io.send(
                b"\x1b[4;900;1600t"
            )

        if b"\x1b]11;?" in data:
            self.io.send(
                b"\x1b]11;"
                b"rgb:0000/0000/0000"
                b"\x07"
            )

    def pump(self, duration=0.05):
        end_time = time.monotonic() + duration

        while time.monotonic() < end_time:
            try:
                if not self.io.can_recv(timeout=0.01):
                    continue

                data = self.io.recv(timeout=0.01)

            except EOFError:
                return

            if not data:
                continue

            self.answer_terminal_queries(data)

            self.raw.extend(data)

            if len(self.raw) > 300_000:
                del self.raw[:-300_000]

            decoded = self.decoder.decode(data)

            self.transcript = (
                self.transcript + decoded
            )[-300_000:]

            self.stream.feed(decoded)

    def lines(self) -> list[str]:
        dirty = set(getattr(self.screen, "dirty", set()))

        if not dirty and not any(
            line.strip() for line in self._line_cache
        ):
            dirty = set(range(TERM_HEIGHT))

        for y in dirty:
            if not 0 <= y < TERM_HEIGHT:
                continue

            terminal_line = self.screen.buffer[y]
            rendered = []

            for x in range(TERM_WIDTH):
                data = terminal_line[x].data
                rendered.append(data if data else " ")

            self._line_cache[y] = "".join(rendered)

        if hasattr(self.screen, "dirty"):
            self.screen.dirty.clear()

        return self._line_cache

    def visible_text(self) -> str:
        return "\n".join(self.lines())

    def find_flag(self) -> str | None:
        sources = (
            self.visible_text(),
            ANSI_RE.sub("", self.transcript),
        )

        for source in sources:
            match = FLAG_RE.search(source)

            if match:
                return match.group(0)

        return None

    def find_text(
        self,
        text: str,
    ) -> tuple[int, int] | None:

        for y, line in enumerate(
            self.lines(),
            start=1,
        ):
            position = line.find(text)

            if position >= 0:
                x = (
                    position
                    + len(text) // 2
                    + 1
                )

                return x, y

        return None

    def click_sgr(self, x: int, y: int):
        self.io.send(
            f"\x1b[<0;{x};{y}M".encode()
        )

        time.sleep(0.002)

        self.io.send(
            f"\x1b[<0;{x};{y}m".encode()
        )

    def click_x10(self, x: int, y: int):
        press = (
            b"\x1b[M"
            + bytes((
                32,
                x + 32,
                y + 32,
            ))
        )

        release = (
            b"\x1b[M"
            + bytes((
                35,
                x + 32,
                y + 32,
            ))
        )

        self.io.send(press)
        time.sleep(0.002)
        self.io.send(release)

    def click_urxvt(self, x: int, y: int):
        self.io.send(
            f"\x1b[32;{x};{y}M".encode()
        )

        time.sleep(0.002)

        self.io.send(
            f"\x1b[35;{x};{y}M".encode()
        )

    def click(
        self,
        x: int,
        y: int,
        protocol: str | None = None,
    ):
        raw = bytes(self.raw)

        if protocol is None:
            if b"\x1b[?1006h" in raw:
                protocol = "sgr"
            elif b"\x1b[?1015h" in raw:
                protocol = "urxvt"
            else:
                protocol = "x10"

        if protocol == "sgr":
            self.click_sgr(x, y)

        elif protocol == "x10":
            self.click_x10(x, y)

        elif protocol == "urxvt":
            self.click_urxvt(x, y)

        else:
            raise ValueError(
                f"Unknown mouse protocol: {protocol}"
            )


def parse_board(
    lines: list[str],
) -> BoardState | None:

    candidate_rows = []

    for y, line in enumerate(lines):
        hits = []

        for x, character in enumerate(line):
            if character in GEMS:
                hits.append((
                    x,
                    GEMS[character],
                ))

        if len(hits) == COLS:
            candidate_rows.append((
                y,
                hits,
            ))

    for start in range(
        len(candidate_rows) - ROWS + 1
    ):
        chunk = candidate_rows[
            start:start + ROWS
        ]

        ys = [
            y
            for y, _ in chunk
        ]

        gaps = [
            next_y - current_y
            for current_y, next_y
            in zip(ys, ys[1:])
        ]

        if not gaps:
            continue

        if min(gaps) < 1:
            continue

        if max(gaps) > 3:
            continue

        if max(gaps) - min(gaps) > 1:
            continue

        base_xs = [
            x
            for x, _ in chunk[0][1]
        ]

        aligned = True

        for _, hits in chunk[1:]:
            current_xs = [
                x
                for x, _ in hits
            ]

            for base_x, current_x in zip(
                base_xs,
                current_xs,
            ):
                if abs(base_x - current_x) > 1:
                    aligned = False
                    break

            if not aligned:
                break

        if not aligned:
            continue

        board = tuple(
            tuple(
                gem
                for _, gem in hits
            )
            for _, hits in chunk
        )

        coords = tuple(
            tuple(
                (
                    x + 1,
                    y + 1,
                )
                for x, _ in hits
            )
            for y, hits in chunk
        )

        return BoardState(
            board=board,
            coords=coords,
        )

    return None


def matched_cells(
    board: list[list[str]],
) -> set[tuple[int, int]]:

    found = set()

    for row in range(ROWS):
        column = 0

        while column < COLS:
            end = column + 1

            while (
                end < COLS
                and board[row][end]
                == board[row][column]
            ):
                end += 1

            if end - column >= 3:
                for current in range(
                    column,
                    end,
                ):
                    found.add((
                        row,
                        current,
                    ))

            column = end

    for column in range(COLS):
        row = 0

        while row < ROWS:
            end = row + 1

            while (
                end < ROWS
                and board[end][column]
                == board[row][column]
            ):
                end += 1

            if end - row >= 3:
                for current in range(
                    row,
                    end,
                ):
                    found.add((
                        current,
                        column,
                    ))

            row = end

    return found



def estimate_cascade(
    board: list[list[str]],
) -> int:
    sim = [row[:] for row in board]
    total = 0
    wave = 0

    while wave < 8:
        cells = matched_cells(sim)

        if not cells:
            break

        wave += 1

        # Utamakan banyak sel dan cascade bertingkat.
        total += len(cells) * 100
        total += (wave - 1) * 250

        for row, column in cells:
            sim[row][column] = None

        # Terapkan gravity. Slot baru dibuat unik agar tidak
        # mengasumsikan warna gem random dari server.
        for column in range(COLS):
            remaining = [
                sim[row][column]
                for row in range(ROWS)
                if sim[row][column] is not None
            ]

            missing = ROWS - len(remaining)

            replacement = [
                f"?{wave}:{column}:{index}"
                for index in range(missing)
            ] + remaining

            for row, value in enumerate(replacement):
                sim[row][column] = value

    return total

def find_moves(
    state: BoardState,
):
    board = [
        list(row)
        for row in state.board
    ]

    legal_moves = []

    for row in range(ROWS):
        for column in range(COLS):
            neighbours = (
                (row, column + 1),
                (row + 1, column),
            )

            for next_row, next_column in neighbours:
                if next_row >= ROWS:
                    continue

                if next_column >= COLS:
                    continue

                if (
                    board[row][column]
                    == board[next_row][next_column]
                ):
                    continue

                board[row][column], board[next_row][next_column] = (
                    board[next_row][next_column],
                    board[row][column],
                )

                cells = matched_cells(board)

                is_legal = (
                    (row, column) in cells
                    or (
                        next_row,
                        next_column,
                    ) in cells
                )

                score = estimate_cascade(board)

                for matched_row, matched_column in cells:
                    horizontal = (
                        0 < matched_column < COLS - 1
                        and board[matched_row][matched_column - 1]
                        == board[matched_row][matched_column]
                        == board[matched_row][matched_column + 1]
                    )

                    vertical = (
                        0 < matched_row < ROWS - 1
                        and board[matched_row - 1][matched_column]
                        == board[matched_row][matched_column]
                        == board[matched_row + 1][matched_column]
                    )

                    if horizontal and vertical:
                        score += 500

                board[row][column], board[next_row][next_column] = (
                    board[next_row][next_column],
                    board[row][column],
                )

                if is_legal:
                    legal_moves.append((
                        score,
                        (row, column),
                        (
                            next_row,
                            next_column,
                        ),
                    ))

    legal_moves.sort(
        reverse=True
    )

    return legal_moves


def wait_for_board(
    game: Game,
    timeout=3.0,
) -> BoardState | None:

    end_time = (
        time.monotonic()
        + timeout
    )

    last_state = None
    stable_since = None

    while time.monotonic() < end_time:
        game.pump(0.012)

        current = parse_board(
            game.lines()
        )

        if current is None:
            last_state = None
            stable_since = None
            continue

        if (
            last_state is not None
            and current.signature
            == last_state.signature
        ):
            if stable_since is None:
                stable_since = (
                    time.monotonic()
                )

            elif (
                time.monotonic()
                - stable_since
                >= 0.025
            ):
                return current

        else:
            last_state = current
            stable_since = None

    return last_state


def wait_for_change(
    game: Game,
    old_signature: str,
    timeout=0.7,
):
    end_time = (
        time.monotonic()
        + timeout
    )

    last_state = None
    stable_since = None

    while time.monotonic() < end_time:
        game.pump(0.008)

        flag = game.find_flag()

        if flag:
            return flag

        current = parse_board(
            game.lines()
        )

        if current is None:
            continue

        if current.signature == old_signature:
            continue

        if (
            last_state is not None
            and current.signature
            == last_state.signature
        ):
            if stable_since is None:
                stable_since = (
                    time.monotonic()
                )

            elif (
                time.monotonic()
                - stable_since
                >= 0.015
            ):
                return current

        else:
            last_state = current
            stable_since = None

    return last_state


def read_number(
    game: Game,
    label: str,
) -> int | None:

    match = re.search(
        rf"{re.escape(label)}\s*:\s*(\d+)",
        game.visible_text(),
    )

    if match:
        return int(match.group(1))

    return None


def start_game(
    game: Game,
) -> BoardState | None:

    game.pump(1.0)

    keyboard_inputs = (
        b"\r",
        b" ",
        b"\t\r",
    )

    for key in keyboard_inputs:
        game.io.send(key)

        state = wait_for_board(
            game,
            timeout=0.5,
        )

        if state:
            return state

    start_position = game.find_text(
        "Start"
    )

    if start_position is None:
        return None

    x, y = start_position

    click_points = (
        (x, y),
        (x - 1, y),
        (x + 1, y),
        (x, y - 1),
        (x, y + 1),
    )

    protocols = (
        "sgr",
        "x10",
        "urxvt",
    )

    for protocol in protocols:
        for click_x, click_y in click_points:
            game.click(
                click_x,
                click_y,
                protocol=protocol,
            )

            state = wait_for_board(
                game,
                timeout=0.45,
            )

            if state:
                return state

    return None


def solve_once() -> str | None:
    game = Game()

    try:
        state = start_game(game)

        if state is None:
            print(
                "[-] Tombol Start tidak berhasil ditekan."
            )

            print(
                "[-] Posisi Start:",
                game.find_text("Start"),
            )

            enabled_modes = []

            raw = bytes(game.raw)

            for mode in (
                1000,
                1002,
                1003,
                1006,
                1015,
            ):
                sequence = (
                    f"\x1b[?{mode}h"
                ).encode()

                if sequence in raw:
                    enabled_modes.append(mode)

            print(
                "[-] Mouse modes:",
                enabled_modes,
            )

            print(
                "[-] Tampilan non-kosong:"
            )

            for line_number, line in enumerate(
                game.lines(),
                start=1,
            ):
                if line.strip():
                    print(
                        f"{line_number:02d}: "
                        f"{line.rstrip()}"
                    )

            return None

        move_number = 0

        while True:
            flag = game.find_flag()

            if flag:
                return flag

            moves = find_moves(state)

            if not moves:
                updated = wait_for_board(
                    game,
                    timeout=1.0,
                )

                if updated is not None:
                    state = updated

                moves = find_moves(state)

                if not moves:
                    print(
                        "[-] Tidak ada move valid."
                    )
                    return None

            _, first, second = moves[0]

            first_x, first_y = (
                state.coords[
                    first[0]
                ][
                    first[1]
                ]
            )

            second_x, second_y = (
                state.coords[
                    second[0]
                ][
                    second[1]
                ]
            )

            move_number += 1

            level = read_number(
                game,
                "Level",
            )

            score = read_number(
                game,
                "Score",
            )

            timer = read_number(
                game,
                "Time",
            )

            print(
                f"[+] move={move_number:03d} "
                f"level={level} "
                f"score={score} "
                f"time={timer} "
                f"R{first[0] + 1}"
                f"C{first[1] + 1}"
                f"<->"
                f"R{second[0] + 1}"
                f"C{second[1] + 1}",
                flush=True,
            )

            old_signature = (
                state.signature
            )

            game.click(
                first_x,
                first_y,
            )

            time.sleep(0.002)

            game.click(
                second_x,
                second_y,
            )

            result = wait_for_change(
                game,
                old_signature,
            )

            if isinstance(result, str):
                return result

            if result is None:
                game.pump(0.2)

                flag = game.find_flag()

                if flag:
                    return flag

                print(
                    "[-] Board tidak berubah."
                )

                return None

            state = result

    except EOFError:
        print("[-] Server menutup koneksi (EOF).")
        flag = game.find_flag()
        if not flag:
            print("[-] Tampilan terakhir:")
            for no, line in enumerate(game.lines(), 1):
                if line.strip():
                    print(f"{no:02d}: {line.rstrip()}")
        return flag

    finally:
        game.close()

def main():
    for attempt in range(1, 21):
        print(f"[*] Attempt {attempt}/20: {HOST}:{PORT}")

        try:
            flag = solve_once()

        except KeyboardInterrupt:
            raise

        except Exception as error:
            print(f"[-] Connection/solver error: {type(error).__name__}: {error}")
            flag = None

        if flag:
            print(f"\n[+] FLAG: {flag}")
            return

        print("[*] Menunggu 12 detik sebelum mencoba lagi...")
        time.sleep(12)

    print("[-] Belum berhasil setelah 20 percobaan.")
    sys.exit(1)


if __name__ == "__main__":
    main()
