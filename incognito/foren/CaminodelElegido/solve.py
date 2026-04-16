#!/usr/bin/env python3
import json
from collections import defaultdict


def extract_flag(path: str = "nodes.json") -> str:
    with open(path, "r", encoding="utf-8") as f:
        nodes = json.load(f)

    int_edges = []
    for node in nodes:
        src = node["id"]
        for edge in node["neighbors"]:
            w = edge["weight"]
            if abs(w - round(w)) < 1e-12:
                int_edges.append((src, edge["to"], int(round(w))))

    out = defaultdict(list)
    indeg = defaultdict(int)
    all_nodes = set()

    for a, b, w in int_edges:
        out[a].append((b, w))
        indeg[b] += 1
        all_nodes.add(a)
        all_nodes.add(b)

    starts = [n for n in all_nodes if indeg[n] == 0]
    if len(starts) != 1:
        raise RuntimeError(f"Expected exactly 1 start node, got {len(starts)}: {starts}")

    cur = starts[0]
    seen = set()
    chars = []

    while True:
        if cur in seen:
            raise RuntimeError("Cycle detected in extracted integer-edge path")
        seen.add(cur)

        nxt = out[cur]
        if not nxt:
            break
        if len(nxt) != 1:
            raise RuntimeError(f"Branch detected at node {cur}: {nxt}")

        cur, w = nxt[0]
        chars.append(chr(w))

    return "".join(chars)


def main() -> None:
    flag = extract_flag("nodes.json")
    print(flag)


if __name__ == "__main__":
    main()
