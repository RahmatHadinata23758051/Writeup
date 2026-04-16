def solve_rubics_cube():
    # 1. MEMBACA FILE FLAG
    try:
        with open('flag.txt', 'r') as f:
            # Kita pecah jadi list of lists (grid 2D)
            grid = [list(line.rstrip('\n')) for line in f.readlines()]
    except FileNotFoundError:
        print("Error: File flag.txt tidak ditemukan!")
        return

    # 2. NORMALISASI GRID
    # Penting: ASCII art seringkali kehilangan spasi di akhir baris.
    # Kita harus buat semua baris punya panjang yang sama agar pergeseran kolom akurat.
    height = len(grid)
    width = max(len(row) for row in grid)
    for row in grid:
        while len(row) < width:
            row.append(' ')

    # 3. MEMBACA URUTAN PENGACAKAN (SEQUENCE)
    try:
        with open('sequence.txt', 'r') as f:
            steps = f.read().strip().split('\n')
    except FileNotFoundError:
        print("Error: File sequence.txt tidak ditemukan!")
        return

    # 4. PROSES INVERSE (MUNDUR)
    # Kita balik urutan instruksinya: dari langkah terakhir ke langkah pertama
    for step in reversed(steps):
        parts = step.split()
        if not parts: continue
        
        direction = parts[0]
        idx = int(parts[1])
        amount = int(parts[2])

        # LOGIKA KEBALIKAN:
        # Jika aslinya geser KIRI (l), maka untuk memperbaikinya kita geser KANAN.
        # Jika aslinya geser ATAS (u), maka kita geser BAWAH, dst.

        if direction == 'l': # Kebalikan Left adalah Right
            shift = amount % width
            grid[idx] = grid[idx][-shift:] + grid[idx][:-shift]

        elif direction == 'r': # Kebalikan Right adalah Left
            shift = amount % width
            grid[idx] = grid[idx][shift:] + grid[idx][:shift]

        elif direction == 'u': # Kebalikan Up adalah Down
            shift = amount % height
            # Ambil kolom, geser, masukkan lagi
            col = [grid[r][idx] for r in range(height)]
            new_col = col[-shift:] + col[:-shift]
            for r in range(height):
                grid[r][idx] = new_col[r]

        elif direction == 'd': # Kebalikan Down adalah Up
            shift = amount % height
            col = [grid[r][idx] for r in range(height)]
            new_col = col[shift:] + col[:shift]
            for r in range(height):
                grid[r][idx] = new_col[r]

    # 5. CETAK HASIL AKHIR
    print("\n--- FLAG RECOVERED ---\n")
    for row in grid:
        print("".join(row))
    print("\n----------------------")

if __name__ == "__main__":
    solve_rubics_cube()
