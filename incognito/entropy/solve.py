#!/usr/bin/env python3
import re
import socket
import time
from collections import deque

HOST = "34.131.216.230"
PORT = 1340

DELIM = b"\x1b[2J\x1b[H"
FLAG_RE = re.compile(r"IIITL\{[^}]+\}")
ANSI_RE = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]")
CELL_RE = re.compile(rb"\x1b\[48;5;(\d+)m(?:\x1b\[[0-9;]*m)*(.*?)\x1b\[0m")

# Empirically passable backgrounds from successful runs.
PASSABLE_BG = {
    46, 190, 191, 214, 215, 216, 226, 227, 228, 229, 230, 231, 250, 251, 252,
}

DIRS = [
    (1, 0, b"S"),
    (-1, 0, b"W"),
    (0, 1, b"D"),
    (0, -1, b"A"),
]


def parse_frame(frame_bytes):
    rows = []
    warning = None

    for line in frame_bytes.splitlines():
        if b"WARNING" in line:
            m = re.search(rb"IN (\d)s", line)
            if m:
                warning = int(m.group(1))

        cells = CELL_RE.findall(line)
        if len(cells) >= 40:
            rows.append([(int(bg), tok.decode("utf-8", "ignore")) for bg, tok in cells])

    player = None
    goal = None
    for r, row in enumerate(rows):
        for c, (_, tok) in enumerate(row):
            if tok == "><":
                player = (r, c)
            elif tok == "▓▓":
                goal = (r, c)

    return rows, player, goal, warning


def bfs_path(rows, start, target=None):
    rmax, cmax = len(rows), len(rows[0])
    q = deque([start])
    prev = {start: None}
    via = {}

    while q:
        r, c = q.popleft()
        for dr, dc, key in DIRS:
            nr, nc = r + dr, c + dc
            if not (0 <= nr < rmax and 0 <= nc < cmax):
                continue
            if (nr, nc) in prev:
                continue

            bg, tok = rows[nr][nc]
            if (nr, nc) == target or tok in ("><", "▓▓") or bg in PASSABLE_BG:
                prev[(nr, nc)] = (r, c)
                via[(nr, nc)] = key
                q.append((nr, nc))

    if target is not None and target not in prev:
        return None, prev

    if target is not None:
        path = []
        cur = target
        while prev[cur] is not None:
            path.append(via[cur])
            cur = prev[cur]
        path.reverse()
        return path, prev

    return None, prev


def reconstruct_path(prev, start, end):
    if end == start:
        return []
    path = []
    cur = end
    while prev[cur] is not None:
        pr = prev[cur]
        dr, dc = cur[0] - pr[0], cur[1] - pr[1]
        for ddr, ddc, key in DIRS:
            if (dr, dc) == (ddr, ddc):
                path.append(key)
                break
        cur = pr
    path.reverse()
    return path


def attempt_once(timeout_sec=45):
    s = socket.create_connection((HOST, PORT), timeout=6)
    s.settimeout(0.002)

    buf = b""
    last_delim_count = 0
    last_warning = None
    start = time.time()

    try:
        while time.time() - start < timeout_sec:
            try:
                d = s.recv(65535)
                if not d:
                    break
                buf += d
            except Exception:
                pass

            # Bound memory while keeping enough history for full frames.
            if len(buf) > 8_000_000:
                buf = buf[-4_000_000:]

            # Fast flag check on cleaned stream.
            cleaned = ANSI_RE.sub(b"", buf).decode("utf-8", "ignore")
            m = FLAG_RE.search(cleaned)
            if m:
                return m.group(0)

            delim_count = buf.count(DELIM)
            if delim_count < 2 or delim_count == last_delim_count:
                continue

            frame = buf.split(DELIM)[-2]
            rows, player, goal, warning = parse_frame(frame)
            last_delim_count = delim_count

            if not rows or not player:
                continue

            if player == goal and goal is not None:
                m = FLAG_RE.search(cleaned)
                if m:
                    return m.group(0)

            # Replan once each warning tick.
            if warning != last_warning:
                path_to_goal, prev = bfs_path(rows, player, goal)

                if path_to_goal:
                    s.sendall(b"".join(path_to_goal))
                else:
                    # Move toward farthest reachable cell by progress score.
                    _, prev = bfs_path(rows, player, None)
                    best = max(
                        prev.keys(),
                        key=lambda p: (p[0] + p[1], -abs(49 - p[0]) - abs(49 - p[1])),
                    )
                    if best != player:
                        fallback_path = reconstruct_path(prev, player, best)
                        if fallback_path:
                            s.sendall(b"".join(fallback_path))

                last_warning = warning
    finally:
        try:
            s.sendall(b"q")
        except Exception:
            pass
        s.close()

    return None


def main():
    while True:
        flag = attempt_once(timeout_sec=45)
        if flag:
            print(flag)
            return


if __name__ == "__main__":
    main()
