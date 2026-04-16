from pwn import *
import re
from z3 import *

def main():
    context.log_level = 'info'
    io = remote('chals2.apoorvctf.xyz', 14001)

    log.info("Menerima data dari server...")
    # Terima semua data sampai disuruh submit
    data = io.recvuntil(b"Submit your answer:").decode()

    # Bersihkan karakter warna (ANSI escape sequences) dari output server
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    clean_data = ansi_escape.sub('', data)

    # Parsing jumlah node dan edge
    graph_section = clean_data.split('Graph:\n')[1].split('Submit')[0].strip()
    lines = graph_section.split('\n')
    num_nodes, num_edges = map(int, lines[0].strip().split())
    log.info(f"Total Nodes: {num_nodes}, Total Edges: {num_edges}")

    # Parsing semua edge
    edges = []
    for line in lines[1:]:
        if line.strip():
            u, v = map(int, line.strip().split())
            edges.append((u, v))

    log.info("Menghitung Minimum Vertex Cover dengan Z3...")
    solver = Optimize()
    
    # Buat variabel untuk tiap node (0 = tidak diambil, 1 = diambil)
    nodes = {i: Int(f"n_{i}") for i in range(1, num_nodes + 1)}
    for i in range(1, num_nodes + 1):
        solver.add(Or(nodes[i] == 0, nodes[i] == 1))

    # Syarat MVC: Setiap edge (u, v) minimal salah satu ujungnya harus diambil
    for u, v in edges:
        solver.add(nodes[u] + nodes[v] >= 1)

    # Tujuan: Minimalkan jumlah node yang diambil
    solver.minimize(Sum([nodes[i] for i in range(1, num_nodes + 1)]))

    # Eksekusi Z3
    solver.check()
    model = solver.model()

    # Ambil node-node yang bernilai 1
    mvc = [i for i in range(1, num_nodes + 1) if model[nodes[i]].as_long() == 1]
    
    jawaban = " ".join(map(str, mvc))
    log.info(f"Ditemukan MVC dengan size {len(mvc)}")
    
    # Kirim jawaban
    io.sendline(jawaban.encode())
    
    # Masuk mode interaktif buat lihat flag-nya
    io.interactive()

if __name__ == '__main__':
    main()
