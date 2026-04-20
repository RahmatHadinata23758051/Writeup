#!/usr/bin/env python3
import argparse
import random
import sys
from typing import List, Tuple

import requests


def clip_vec(v: List[float], lo: List[float], hi: List[float]) -> List[float]:
    return [max(lo[i], min(hi[i], float(v[i]))) for i in range(len(v))]


def score(url: str, u: List[float], timeout: float = 30.0) -> Tuple[float, bool, str]:
    r = requests.post(
        f"{url}/submit-u",
        json={"u": u, "include_image": False},
        timeout=timeout,
    )
    r.raise_for_status()
    data = r.json()
    return float(data.get("tom_score", 0.0)), bool(data.get("success", False)), str(data.get("flag", ""))


def main() -> int:
    ap = argparse.ArgumentParser(description="Soulmate solver")
    ap.add_argument("url", help="Base URL target, ex: http://127.0.0.1:8000")
    ap.add_argument("--iters", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--sigma", type=float, default=0.35)
    ap.add_argument("--batch", type=int, default=40)
    args = ap.parse_args()

    random.seed(args.seed)
    url = args.url.rstrip("/")

    h = requests.get(f"{url}/health", timeout=20).json()
    d = int(h["control_dim"])
    lo = list(map(float, h["u_lower"]))
    hi = list(map(float, h["u_upper"]))
    threshold = float(h["tom_score_threshold"])

    # Start from center of bounds
    cur = [(lo[i] + hi[i]) * 0.5 for i in range(d)]
    cur_s, cur_ok, cur_flag = score(url, cur)
    print(f"[*] init tom_score={cur_s:.6f} threshold={threshold:.6f}")
    if cur_ok and cur_flag:
        print(cur_flag)
        return 0

    best = cur[:]
    best_s = cur_s

    for it in range(1, args.iters + 1):
        improved = False

        # local random search around current best
        for _ in range(args.batch):
            cand = [best[i] + random.gauss(0.0, args.sigma) * (hi[i] - lo[i]) for i in range(d)]
            cand = clip_vec(cand, lo, hi)
            s, ok, flag = score(url, cand)
            if ok and flag:
                print(flag)
                return 0
            if s > best_s:
                best_s = s
                best = cand
                improved = True

        if improved:
            cur = best[:]
        else:
            # occasional global restart to avoid local optima
            cur = [random.uniform(lo[i], hi[i]) for i in range(d)]
            s, ok, flag = score(url, cur)
            if ok and flag:
                print(flag)
                return 0
            if s > best_s:
                best_s = s
                best = cur[:]

        if it % 20 == 0:
            print(f"[*] iter={it} best_tom={best_s:.6f}")

    print(f"[!] not solved yet, best_tom={best_s:.6f} (< {threshold:.6f})", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
