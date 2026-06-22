#!/usr/bin/env python3

SYMBOLS = ['A', 'L', 'N', 'Q', 'R', 'S', 'T', '@', '1']
GRID = [
    ['.', '@', '.', '1', '.', '.', '.', '.', '.'],
    ['1', '.', 'R', '.', '.', 'A', 'L', '.', 'N'],
    ['.', 'Q', '.', 'L', '.', '.', '.', '.', 'S'],
    ['.', '.', '.', '.', '.', '.', 'N', 'Q', '.'],
    ['S', 'R', 'N', '.', 'T', '.', '.', '.', '@'],
    ['.', '.', '.', '@', '.', '.', '.', 'R', '.'],
    ['T', '.', '.', '.', '.', 'Q', '.', '.', '.'],
    ['.', 'L', '.', 'N', '.', '.', '.', 'S', 'Q'],
    ['R', '.', '.', '.', '.', '@', '1', '.', '.'],
]


def solve(grid):
    rows = [set() for _ in range(9)]
    cols = [set() for _ in range(9)]
    boxes = [set() for _ in range(9)]

    for r in range(9):
        for c in range(9):
            v = grid[r][c]
            if v == '.':
                continue
            b = (r // 3) * 3 + (c // 3)
            if v in rows[r] or v in cols[c] or v in boxes[b]:
                raise ValueError(f"invalid clue {v!r} at row {r + 1}, col {c + 1}")
            rows[r].add(v)
            cols[c].add(v)
            boxes[b].add(v)

    def dfs():
        target = None
        choices = None

        for r in range(9):
            for c in range(9):
                if grid[r][c] != '.':
                    continue
                b = (r // 3) * 3 + (c // 3)
                cand = set(SYMBOLS) - rows[r] - cols[c] - boxes[b]
                if not cand:
                    return False
                if choices is None or len(cand) < len(choices):
                    target = (r, c)
                    choices = cand

        if target is None:
            return True

        r, c = target
        b = (r // 3) * 3 + (c // 3)
        for v in sorted(choices):
            grid[r][c] = v
            rows[r].add(v)
            cols[c].add(v)
            boxes[b].add(v)

            if dfs():
                return True

            rows[r].remove(v)
            cols[c].remove(v)
            boxes[b].remove(v)
            grid[r][c] = '.'

        return False

    if not dfs():
        raise RuntimeError("no solution found")
    return grid


def main():
    solved = solve([row[:] for row in GRID])
    for row in solved:
        print(' '.join(row))
    top_row = ''.join(solved[0])
    print(f"flag: boroCTF{{{top_row}}}")


if __name__ == "__main__":
    main()
