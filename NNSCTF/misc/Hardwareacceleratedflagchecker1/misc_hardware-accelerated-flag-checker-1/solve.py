#!/usr/bin/env python3
import re
from collections import deque
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
NETLIST = BASE_DIR / "netlist.v"
TARGET_STATE = 31
PRINTABLE = range(32, 127)


def load_assigns(path: Path):
    text = path.read_text()
    assigns = []
    for m in re.finditer(r"assign\s+([^=]+?)\s*=\s*(.*?);", text):
        lhs = m.group(1).strip()
        rhs = m.group(2).strip()
        rhs = rhs.replace("~", " not ").replace("&", " and ").replace("|", " or ")
        assigns.append((lhs, rhs))
    if not assigns:
        raise RuntimeError("no assign statements found")
    return assigns


ASSIGNS = load_assigns(NETLIST)


def step(state: int, ch: int) -> int:
    s = [bool((state >> i) & 1) for i in range(5)]
    character = [bool((ch >> i) & 1) for i in range(7)]
    env = {
        "s": s,
        "character": character,
        "reset_n": True,
    }
    values = {}

    for lhs, rhs in ASSIGNS:
        values[lhs] = bool(eval(rhs, {"__builtins__": {}}, env))
        if "[" not in lhs:
            env[lhs] = values[lhs]

    # The synthesized logic resets the FSM if reset is low or found_flag is already high.
    if values.get("_000_", False):
        return 0

    return sum(1 << i for i in range(5) if values.get(f"_289_[{i}]", False))


def recover_flag() -> str:
    queue = deque([(0, "")])
    seen = {0}

    while queue:
        state, prefix = queue.popleft()
        if state == TARGET_STATE:
            return prefix

        for ch in PRINTABLE:
            nxt = step(state, ch)
            if nxt not in seen:
                seen.add(nxt)
                queue.append((nxt, prefix + chr(ch)))

    raise RuntimeError("target state is not reachable with printable ASCII")


def main():
    flag = recover_flag()
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
