#!/usr/bin/env python3
import re
import socket
import sys
import time
from collections import deque


HOST = sys.argv[1] if len(sys.argv) > 1 else "10.42.5.10"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9998

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
FRAME_RE = re.compile(
    r"--- Level (\d+)/(\d+) \| Time Left: (\d+)s ---\n((?:[ #XE]+\n){21})Move\(s\): ",
    re.S,
)
FLAG_RE = re.compile(r"(?:RAM|RMCTF)\{[^}\n]+\}")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def recv_until(sock: socket.socket, want: tuple[str, ...], timeout: float = 10.0) -> str:
    buf = ""
    end = time.time() + timeout
    while time.time() < end:
        clean = strip_ansi(buf)
        if any(token in clean for token in want):
            return clean
        try:
            chunk = sock.recv(16384)
        except socket.timeout:
            continue
        if not chunk:
            return clean
        buf += chunk.decode("utf-8", "replace")
    raise TimeoutError(f"timed out waiting for one of: {want}")


def bfs(grid: list[str]) -> str:
    start = None
    end = None
    for y, row in enumerate(grid):
        for x, cell in enumerate(row):
            if cell == "X":
                start = (x, y)
            elif cell == "E":
                end = (x, y)
    if start is None or end is None:
        raise ValueError("grid missing X or E")

    q = deque([start])
    prev: dict[tuple[int, int], tuple[tuple[int, int] | None, str | None]] = {
        start: (None, None)
    }
    moves = [("W", (0, -1)), ("A", (-1, 0)), ("S", (0, 1)), ("D", (1, 0))]
    height = len(grid)
    width = len(grid[0])

    while q:
        x, y = q.popleft()
        if (x, y) == end:
            break
        for step, (dx, dy) in moves:
            nx, ny = x + dx, y + dy
            if not (0 <= nx < width and 0 <= ny < height):
                continue
            if grid[ny][nx] == "#" or (nx, ny) in prev:
                continue
            prev[(nx, ny)] = ((x, y), step)
            q.append((nx, ny))

    if end not in prev:
        raise RuntimeError("no path to exit")

    path: list[str] = []
    cur = end
    while prev[cur][0] is not None:
        parent, step = prev[cur]
        path.append(step)  # type: ignore[arg-type]
        cur = parent  # type: ignore[assignment]
    path.reverse()
    return "".join(path)


def parse_frame(text: str) -> tuple[int, int, int, list[str]]:
    matches = list(FRAME_RE.finditer(text))
    if not matches:
        raise RuntimeError("no complete frame found")
    level_s, total_s, time_s, grid_s = matches[-1].groups()
    return int(level_s), int(total_s), int(time_s), grid_s.strip().splitlines()


def main() -> None:
    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        sock.settimeout(0.5)

        banner = recv_until(sock, ("Press Enter to start...",), timeout=5)
        if "Press Enter to start..." not in banner:
            raise RuntimeError("unexpected banner")
        sock.sendall(b"\n")

        while True:
            screen = recv_until(sock, ("Move(s): ", "Flag:", "RAM{", "RMCTF{"))
            flag = FLAG_RE.search(screen)
            if flag:
                print(flag.group(0))
                return

            level, total, time_left, grid = parse_frame(screen)
            path = bfs(grid)
            print(f"[+] Level {level}/{total} | t={time_left}s | path={len(path)}", file=sys.stderr)
            sock.sendall(path.encode() + b"\n")


if __name__ == "__main__":
    main()
