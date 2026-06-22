# Efficient Encryption

Category: Crypto  
Flag: `boroCTF{L@T1NSQAR}`

## Ringkas

Gambar berisi puzzle Sudoku 9x9 dengan 9 simbol: `A L N Q R S T @ 1`. Clue `top shelf` mengarah ke baris paling atas setelah puzzle selesai. Isi baris atas adalah `L@T1NSQAR`, jadi flag finalnya `boroCTF{L@T1NSQAR}`.

## Analisis

Grid di gambar ditranskrip sebagai berikut. Tanda `.` berarti sel kosong.

```text
. @ . 1 . . . . .
1 . R . . A L . N
. Q . L . . . . S
. . . . . . N Q .
S R N . T . . . @
. . . @ . . . R .
T . . . . Q . . .
. L . N . . . S Q
R . . . . @ 1 . .
```

Aturannya sama seperti Sudoku biasa:

- tiap baris harus berisi semua simbol sekali,
- tiap kolom harus berisi semua simbol sekali,
- tiap kotak 3x3 harus berisi semua simbol sekali.

Karena simbolnya bukan angka 1-9, solver dibuat dengan set simbol manual. Backtracking memakai heuristic minimum remaining values supaya cepat: pilih sel kosong dengan kandidat paling sedikit, isi, lalu mundur kalau dead-end.

## Solver

```python
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
        raise RuntimeError('no solution found')
    return grid


solved = solve([row[:] for row in GRID])
for row in solved:
    print(' '.join(row))
print('flag:', f"boroCTF{{{''.join(solved[0])}}}")
```

## Output

```text
L @ T 1 N S Q A R
1 S R T Q A L @ N
N Q A L @ R T 1 S
@ A 1 R S L N Q T
S R N Q T 1 A L @
Q T L @ A N S R 1
T 1 S A R Q @ N L
A L @ N 1 T R S Q
R N Q S L @ 1 T A
flag: boroCTF{L@T1NSQAR}
```
