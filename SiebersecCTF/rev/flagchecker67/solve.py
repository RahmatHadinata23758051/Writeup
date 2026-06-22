import random
from collections import deque

six = "sctf{sixsevenSIXSEVEN6767}"
seven = sorted(set(six))
random.seed(67)
random.shuffle(seven)

def solve():
    with open("sixseven.txt") as f:
        grid = [line.strip() for line in f if line.strip()]

    target_x, target_y = 247, 219
    start_x, start_y = 1, 1

    # queue: (x, y, is_horizontal, path)
    queue = deque([(start_x, start_y, True, "")])
    visited = set([(start_x, start_y, True)])

    while queue:
        x, y, is_horizontal, path = queue.popleft()

        if x == target_x and y == target_y:
            print(f"<FLAG>{path}</FLAG>")
            return

        for dist_minus_1, char in enumerate(seven):
            dist = dist_minus_1 + 1
            new_x, new_y = x, y
            possible = True
            
            if is_horizontal:
                for _ in range(dist):
                    if new_x + 1 >= len(grid[0]) or grid[new_y][new_x + 1] == '7':
                        possible = False
                        break
                    new_x += 2
            else:
                for _ in range(dist):
                    if new_y + 1 >= len(grid) or grid[new_y + 1][new_x] == '7':
                        possible = False
                        break
                    new_y += 2

            if possible:
                if (new_x, new_y, not is_horizontal) not in visited:
                    visited.add((new_x, new_y, not is_horizontal))
                    queue.append((new_x, new_y, not is_horizontal, path + char))

if __name__ == "__main__":
    solve()
