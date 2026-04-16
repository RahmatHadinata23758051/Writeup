#!/usr/bin/env python3
import hashlib
import itertools
import sys

TARGET = "3f07b8c8867988ac4670e29e0f66a25e1772ed21ac13d6554e4d6948347f2e5c"

words = [
    "ouroboros", "serpent", "snake", "tail", "eats", "eat", "its", "vm",
    "rewrites", "rewrite", "itself", "self", "name", "accepts", "accept",
    "the", "loop", "cycle", "bytecode", "runtime", "hash", "web", "reverse",
]
styles = ["lower", "title", "upper"]
subs = {
    "a": ["a", "4"],
    "e": ["e", "3"],
    "i": ["i", "1"],
    "o": ["o", "0"],
    "s": ["s", "5"],
}


def mutate(word: str):
    opts = [""]
    for ch in word:
        reps = subs.get(ch, [ch])
        opts = [p + r for p in opts for r in reps]
        if len(opts) > 64:
            opts = opts[:64]
    return opts


def stylize(s: str, style: str):
    if style == "lower":
        return s
    if style == "upper":
        return s.upper()
    return s[:1].upper() + s[1:]


mut = {w: mutate(w) for w in words}

for r in [2, 3, 4]:
    for comb in itertools.product(words, repeat=r):
        for sep in ["_", "-", ""]:
            base = sep.join(comb)
            if len(base) != 21:
                continue

            token_lists = [mut[w] for w in comb]
            for toks in itertools.product(*token_lists):
                inner = sep.join(toks)
                if len(inner) != 21:
                    continue

                for st in styles:
                    cand = "uni6{" + stylize(inner, st) + "}"
                    if hashlib.sha256(cand.encode()).hexdigest() == TARGET:
                        print(cand)
                        sys.exit(0)

print("not found")
